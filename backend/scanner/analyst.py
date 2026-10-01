"""'AI Security Analyst' summary.

Uses Claude if ANTHROPIC_API_KEY is set; otherwise falls back to a
rule-based summary so the demo always works offline.
"""
from __future__ import annotations

import json
import os

import httpx

MODEL = os.getenv("CYPHERON_MODEL", "claude-haiku-4-5-20251001")


def rule_based_summary(report: dict) -> str:
    c = report["counts"]
    issues = [f for f in report["findings"] if f["severity"] in ("critical", "high", "medium", "low")]
    host = report["host"]
    if not issues:
        return (f"{host} passed every check Cypheron ran. HTTPS, headers and cookies are configured well. "
                "Keep dependencies patched and re-scan after major changes.")

    parts = [f"{host} scored {report['score']}/100 (grade {report['grade']}, {report['risk'].lower()} risk)."]
    strengths = [f["title"] for f in report["findings"] if f["severity"] == "pass"][:2]
    if strengths:
        parts.append("Strengths: " + "; ".join(s.lower() for s in strengths) + ".")
    serious = c["critical"] + c["high"]
    if serious:
        parts.append(f"There {'is' if serious == 1 else 'are'} {serious} critical/high issue"
                     f"{'' if serious == 1 else 's'} to fix first.")
    top = issues[0]
    parts.append(f"The most important fix: {top['title']}. {top['recommendation']}")
    if len(issues) == 2:
        parts.append(f"Then fix: {issues[1]['title'].lower()}.")
    elif len(issues) > 2:
        parts.append(f"After that, work through the other {len(issues) - 1} findings, "
                     f"starting with {issues[1]['title'].lower()}.")
    return " ".join(parts)


async def analyst_summary(report: dict) -> dict:
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        return {"source": "rules", "text": rule_based_summary(report)}

    compact = {k: report[k] for k in ("host", "score", "grade", "risk", "counts")}
    compact["findings"] = [{k: f[k] for k in ("title", "severity", "evidence")}
                           for f in report["findings"] if f["severity"] != "pass"][:25]
    prompt = (
        "You are a web security analyst. Write a 3-4 sentence plain-English summary of this scan "
        "for a non-expert site owner: overall posture, the single most important fix and why, "
        "and one positive point if any. Do not invent findings. Scan JSON:\n" + json.dumps(compact))
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json={"model": MODEL, "max_tokens": 300, "messages": [{"role": "user", "content": prompt}]})
            r.raise_for_status()
            text = "".join(b.get("text", "") for b in r.json()["content"])
            return {"source": "ai", "text": text.strip()}
    except Exception:
        return {"source": "rules", "text": rule_based_summary(report)}
