"""Scan orchestration, risk scoring and report building."""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional
from urllib.parse import urlparse

import httpx

from .checks import ACTIVE_CHECKS, PASSIVE_CHECKS, ScanContext
from .findings import PENALTY, SEVERITIES, Finding

USER_AGENT = "Cypheron/1.0 (security assessment; +https://github.com/)"
Emit = Callable[[dict], Awaitable[None]]

# Set CYPHERON_ALLOW_PRIVATE=0 when you deploy publicly, so nobody can use your
# server to scan your internal network (SSRF). Local demos need it on.
ALLOW_PRIVATE = os.getenv("CYPHERON_ALLOW_PRIVATE", "1") == "1"

CATEGORY_LABELS = {
    "headers": "Security Headers",
    "transport": "SSL/TLS & HTTPS",
    "cookies": "Cookies",
    "cors": "CORS",
    "content": "Forms & Content",
    "disclosure": "Information Disclosure",
    "exposure": "Exposed Files",
}


class ScanError(Exception):
    pass


def normalise_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ScanError("Please enter a URL.")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ScanError("Only http:// and https:// URLs are supported.")
    return raw


def _assert_public(host: str) -> None:
    if ALLOW_PRIVATE:
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ScanError(f"Could not resolve {host}.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ScanError("Scanning private or internal addresses is disabled on this server.")


def score_findings(findings: list[Finding]) -> dict:
    counts = Counter(f.severity for f in findings)
    score = max(0, 100 - sum(PENALTY[f.severity] for f in findings))
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    if counts["critical"]:
        risk = "CRITICAL"
    elif counts["high"] or score < 60:
        risk = "HIGH"
    elif score < 80:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    categories = []
    for key, label in CATEGORY_LABELS.items():
        items = [f for f in findings if f.category == key and f.severity != "info"]
        if not items:
            continue
        passed = sum(1 for f in items if f.severity == "pass")
        categories.append({"key": key, "label": label, "passed": passed,
                           "total": len(items), "percent": round(100 * passed / len(items))})

    return {"score": score, "grade": grade, "risk": risk,
            "counts": {s: counts.get(s, 0) for s in SEVERITIES}, "categories": categories}


async def run_scan(url: str, active: bool = False, emit: Optional[Emit] = None) -> dict:
    """Scan `url` and return a report dict. `emit` receives live progress events."""
    async def send(evt: dict):
        if emit:
            await emit(evt)

    url = normalise_url(url)
    host = urlparse(url).hostname
    await asyncio.to_thread(_assert_public, host)

    checks = list(PASSIVE_CHECKS) + (list(ACTIVE_CHECKS) if active else [])
    started = time.perf_counter()
    await send({"type": "start", "url": url, "checks": [name for name, _ in checks]})

    async with httpx.AsyncClient(timeout=10, headers={"User-Agent": USER_AGENT},
                                 follow_redirects=True, verify=True) as client:
        try:
            resp = await client.get(url)
        except httpx.ConnectError as e:
            # A bad certificate is itself a finding; retry without verification to keep scanning.
            if "CERTIFICATE_VERIFY_FAILED" in str(e):
                async with httpx.AsyncClient(timeout=10, headers={"User-Agent": USER_AGENT},
                                             follow_redirects=True, verify=False) as insecure:
                    resp = await insecure.get(url)
            else:
                raise ScanError(f"Could not connect to {host}: {e}") from e
        except httpx.HTTPError as e:
            raise ScanError(f"Request to {url} failed: {e}") from e

        ctx = ScanContext(url=url, response=resp, client=client,
                          html=resp.text if "html" in resp.headers.get("content-type", "") else "")

        findings: list[Finding] = []
        for name, fn in checks:
            await send({"type": "check_start", "check": name})
            try:
                result = await fn(ctx)
            except Exception as e:  # one broken check must not kill the scan
                result = []
                await send({"type": "check_error", "check": name, "error": str(e)})
            findings.extend(result)
            await send({"type": "check_done", "check": name,
                        "findings": [f.to_dict() for f in result]})

    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: order[f.severity])
    summary = score_findings(findings)

    warnings = []
    if resp.status_code >= 400:
        warnings.append(f"The target answered with HTTP {resp.status_code}, so header results describe "
                        "that error response and may not reflect the real site.")
    if not ctx.html:
        warnings.append("The page is not HTML, so form and content checks were skipped.")

    return {
        "url": url,
        "final_url": ctx.final_url,
        "host": host,
        "status_code": resp.status_code,
        "active_checks": active,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": round((time.perf_counter() - started) * 1000),
        **summary,
        "warnings": warnings,
        "findings": [f.to_dict() for f in findings],
    }
