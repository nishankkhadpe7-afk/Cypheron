# Cypheron — Web Security Scanner (backend)

Enter a URL, get a security score, graded findings, and a plain-English analyst summary.
Checks are OWASP-aligned and **detection-only**: nothing is exploited.

## Run it

```bash
cd backend
python -m venv venv && venv\Scripts\activate      # Windows  (Linux/mac: source venv/bin/activate)
pip install -r requirements.txt

python demo_target.py                 # terminal 1: vulnerable demo site on :8081
uvicorn main:app --reload --port 8000 # terminal 2: API on :8000  → docs at http://localhost:8000/docs
python -m scanner.cli http://localhost:8081 --active   # or scan from the terminal
python test_api.py                    # end-to-end tests (needs demo_target running)
```

Optional: set `ANTHROPIC_API_KEY` to make the analyst summary AI-written. Without it, a
rule-based summary is used, so the demo never depends on internet or an API key.

## What it checks

| Module | Checks | Mode |
|---|---|---|
| Security headers | CSP (missing / unsafe-inline), HSTS (missing / short), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | passive |
| HTTPS & TLS | HTTPS available, HTTP→HTTPS redirect, certificate trust & expiry, TLS version, legacy TLS 1.0/1.1 | passive |
| Cookies | Secure, HttpOnly, SameSite (stricter for session cookies) | passive |
| CORS | Reflected origin with credentials, reflected origin, wildcard | passive |
| Forms & content | Password over HTTP, password via GET, missing CSRF token, mixed content | passive |
| Disclosure | Versions in Server / X-Powered-By / meta generator, tech fingerprint | passive |
| Exposed files | `.git`, `.env`, `.htpasswd`, `phpinfo.php`, `server-status`, backups, directory listing | **active — needs consent** |

**Scoring:** start at 100; subtract critical 25, high 15, medium 8, low 3.
Grade A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, else F. Any critical → CRITICAL risk.

## Safety built in

- Active probes run only when the user ticks "I own or am authorised to test this site".
- `CYPHERON_ALLOW_PRIVATE=0` blocks scanning localhost/private/cloud-metadata IPs.
  Set it whenever the app is deployed publicly (SSRF protection). It defaults to on for local demos.
- Warns when the target returns an error page, instead of silently grading the error page.

## API (for the React frontend)

| | |
|---|---|
| `POST /api/scan` | body `{url, active_checks, consent}` → report |
| `GET /api/scans` | history: `[{id, url, host, score, grade, risk, created_at}]` |
| `GET /api/scans/{id}` | saved report |
| `WS /api/ws/scan` | send the same body; receive `start`, then `check_start`/`check_done` per module, then `complete` with the report (or `error`) |

Report shape (abridged):
```json
{
  "id": 3, "url": "...", "host": "...", "score": 78, "grade": "C", "risk": "MEDIUM",
  "previous_score": 62,
  "counts": {"critical":0,"high":1,"medium":4,"low":3,"info":1,"pass":6},
  "categories": [{"key":"headers","label":"Security Headers","passed":4,"total":5,"percent":80}],
  "findings": [{"id":"header.csp.missing","title":"...","category":"headers","severity":"medium",
                "description":"...","impact":"...","recommendation":"...","evidence":null,"references":[]}],
  "analyst": {"source":"ai|rules","text":"..."},
  "warnings": [], "duration_ms": 1170
}
```

## Demo script (≈4 minutes)

1. Start `python demo_target.py`. Scan `http://localhost:8081` with active checks ticked.
   Checks tick off live; the result is **F, CRITICAL** with exposed `.git` and `.env`, CORS misconfiguration, and more.
2. Open "Environment file exposed" and show impact, recommendation and evidence.
3. Read the AI analyst summary.
4. Stop it and run `python demo_target.py --fixed`. Rescan and the score jumps from **0 to 70**, shown against the previous scan.
   The analyst says the last fix is HTTPS.
5. Passive-scan a real public site to show it works on the live web.

## Layout

```
backend/
  main.py              FastAPI app, SQLite history, WebSocket streaming
  demo_target.py       deliberately vulnerable site (and --fixed version)
  test_api.py          end-to-end tests
  scanner/
    checks.py          all security checks
    engine.py          orchestration, SSRF guard, scoring, grades
    analyst.py         AI / rule-based summary
    findings.py        Finding model, severities, penalties
    cli.py             terminal scanner
```

## Next steps

- React + Tailwind dashboard (score gauge, category bars, live checklist, finding drawer, history)
- PDF report export
- CVE lookup for fingerprinted versions (NVD API)
