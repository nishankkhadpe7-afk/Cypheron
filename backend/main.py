"""Cypheron API.

    uvicorn main:app --reload --port 8000

REST
  POST /api/scan            {url, active_checks, consent} → full report
  GET  /api/scans           recent scan history
  GET  /api/scans/{id}      one saved report
  GET  /api/health
WebSocket
  /api/ws/scan              send {url, active_checks, consent}; receive live events:
                            start → check_start / check_done … → complete (or error)
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from scanner import ScanError, analyst_summary, run_scan

DB_PATH = os.getenv("CYPHERON_DB", "cypheron.db")

app = FastAPI(title="Cypheron", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CYPHERON_FRONTEND", "http://localhost:5173,http://127.0.0.1:5173").split(","),
    allow_methods=["*"], allow_headers=["*"])


# ------------------------------------------------------------------ storage
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


with closing(db()) as c:
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL, host TEXT NOT NULL,
        score INTEGER, grade TEXT, risk TEXT,
        active_checks INTEGER, created_at TEXT, report TEXT)""")
    c.commit()


def save(report: dict) -> int:
    with closing(db()) as c:
        cur = c.execute(
            "INSERT INTO scans (url, host, score, grade, risk, active_checks, created_at, report) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (report["url"], report["host"], report["score"], report["grade"], report["risk"],
             int(report["active_checks"]), report["scanned_at"], json.dumps(report)))
        c.commit()
        return cur.lastrowid


def previous_score(host: str, exclude_id: int) -> int | None:
    with closing(db()) as c:
        row = c.execute("SELECT score FROM scans WHERE host=? AND id<>? ORDER BY id DESC LIMIT 1",
                        (host, exclude_id)).fetchone()
        return row["score"] if row else None


# ------------------------------------------------------------------ scanning
class ScanRequest(BaseModel):
    url: str
    active_checks: bool = False
    consent: bool = False   # user confirms they own / may test the target


def validate(req: ScanRequest) -> None:
    if req.active_checks and not req.consent:
        raise ScanError("Active checks request extra paths on the server. "
                        "Confirm you own or are authorised to test this site.")


async def full_scan(req: ScanRequest, emit=None) -> dict:
    validate(req)
    report = await run_scan(req.url, active=req.active_checks, emit=emit)
    report["analyst"] = await analyst_summary(report)
    report["id"] = save(report)
    report["previous_score"] = previous_score(report["host"], report["id"])
    return report


@app.get("/api/health")
def health():
    return {"status": "ok", "ai": bool(os.getenv("ANTHROPIC_API_KEY"))}


@app.post("/api/scan")
async def scan(req: ScanRequest):
    try:
        return await full_scan(req)
    except ScanError as e:
        raise HTTPException(400, str(e))


@app.get("/api/scans")
def list_scans(limit: int = 20):
    with closing(db()) as c:
        rows = c.execute("SELECT id, url, host, score, grade, risk, active_checks, created_at "
                         "FROM scans ORDER BY id DESC LIMIT ?", (min(limit, 100),)).fetchall()
        return [dict(r) for r in rows]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):
    with closing(db()) as c:
        row = c.execute("SELECT id, report FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Scan not found")
    report = json.loads(row["report"])
    report["id"] = row["id"]
    report["previous_score"] = previous_score(report["host"], row["id"])
    return report


@app.websocket("/api/ws/scan")
async def ws_scan(ws: WebSocket):
    await ws.accept()
    try:
        req = ScanRequest(**await ws.receive_json())
        report = await full_scan(req, emit=ws.send_json)
        await ws.send_json({"type": "complete", "report": report})
    except ScanError as e:
        await ws.send_json({"type": "error", "error": str(e)})
    except WebSocketDisconnect:
        return
    except Exception as e:
        await ws.send_json({"type": "error", "error": f"Scan failed: {e}"})
    await ws.close()


# ------------------------------------------- serve the built React app (optional)
# After `npm run build` in ../frontend, the whole app runs from this one server
# at http://localhost:8000 — handy for the demo and for deployment.
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")
