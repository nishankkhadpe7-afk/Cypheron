# Cypheron

A web security scanner. Enter a URL and Cypheron inspects it live, then returns a grade,
a score, findings with fixes, and an analyst summary.

```
cypheron/
  backend/    FastAPI + Python scanner           (port 8000)
  frontend/   React + Vite + Tailwind dashboard  (port 5173 in development)
```

You need **Python 3.10+** and **Node.js 18+**.

---

## 1. First-time setup

```bash
# backend
cd backend
python -m venv venv
venv\Scripts\activate            # Windows   (macOS/Linux: source venv/bin/activate)
pip install -r requirements.txt

# frontend
cd ../frontend
npm install
```

> `requirements.txt` installs `uvicorn[standard]`. The `[standard]` part matters: it adds WebSocket
> support. With plain `uvicorn`, scans fail with "Cannot reach the backend" and the backend log says
> `Unsupported upgrade request`. Fix: `pip install "uvicorn[standard]"`.

## 2. Run it (development, 3 terminals)

| Terminal | Folder | Command | What it is |
|---|---|---|---|
| 1 | `backend` | `python demo_target.py` | Vulnerable demo site on :8081 |
| 2 | `backend` | `uvicorn main:app --reload --port 8000` | API |
| 3 | `frontend` | `npm run dev` | Dashboard on **http://localhost:5173** |

Open http://localhost:5173. The dot in the top-right corner should say **Scanner online**.
Click **Use the local demo site**, then **Scan site**.

(Activate the venv in terminals 1 and 2.)

---

## 3. How the frontend and backend are connected

The frontend never hard-codes `http://localhost:8000`. It calls relative paths like `/api/scan`,
and something in between routes them to FastAPI. There are three ways to set that up.

### A. Development: the Vite proxy (default)

`frontend/vite.config.js`:

```js
server: {
  proxy: {
    '/api': { target: 'http://localhost:8000', changeOrigin: true, ws: true },
  },
},
```

```
Browser ──► localhost:5173 (Vite) ──/api/*──► localhost:8000 (FastAPI)
                                   └ ws: true also forwards the live-scan WebSocket
```

Because the browser only ever talks to :5173, there is **no CORS problem**. If your backend runs
on another port, start Vite with `CYPHERON_BACKEND=http://localhost:9000 npm run dev`.

### B. Demo day: one server (recommended)

```bash
cd frontend && npm run build      # creates frontend/dist
cd ../backend && uvicorn main:app --port 8000
```

Open **http://localhost:8000**. `main.py` detects `frontend/dist` and serves the dashboard itself,
so you only need one terminal (plus the demo target) and there's no proxy to go wrong.
Rebuild after any frontend change.

### C. Frontend and backend on different hosts (e.g. Vercel + Render)

1. In `frontend/.env`: `VITE_API_URL=https://your-backend.onrender.com`, then `npm run build`.
2. On the backend, allow that frontend origin:
   `CYPHERON_FRONTEND=https://your-frontend.vercel.app`
3. Set `CYPHERON_ALLOW_PRIVATE=0` on any public deployment, so nobody can use your server to
   scan internal networks.

`src/api.js` turns `VITE_API_URL` into the right `ws://` or `wss://` WebSocket address automatically.

---

## 4. What talks to what

All calls live in `frontend/src/api.js`.

| Frontend function | Backend endpoint | Used for |
|---|---|---|
| `getHealth()` | `GET /api/health` | "Scanner online" indicator |
| `streamScan()` | `WS /api/ws/scan` | Running a scan with live progress |
| `getHistory()` | `GET /api/scans` | "Recent scans" list |
| `getScan(id)` | `GET /api/scans/{id}` | Re-opening an old report |

A live scan works like this:

```
frontend sends   {"url": "...", "active_checks": true, "consent": true}
backend sends    {"type": "start", "checks": [8 names]}
                 {"type": "check_start", "check": "Security headers"}   → row shows "checking"
                 {"type": "check_done",  "check": "...", "findings": []} → row shows "3 issues"
                 ... once per check ...
                 {"type": "complete", "report": {...}}                   → grade stamp appears
          or     {"type": "error", "error": "..."}                       → red message under the form
```

`POST /api/scan` returns the same report in one response, without progress. Use it from
Postman or the interactive docs at http://localhost:8000/docs.

---

## 5. Troubleshooting

| Symptom | Fix |
|---|---|
| "Scanner offline" | Backend isn't running on :8000. Start it with `uvicorn main:app --port 8000`. |
| Health works but scans fail instantly | Install WebSocket support: `pip install "uvicorn[standard]"` |
| CORS error in the console | You opened the built files directly or used option C without `CYPHERON_FRONTEND`. Use option A or B. |
| "Could not connect to localhost" when scanning the demo | Start `python demo_target.py` |
| "Scanning private or internal addresses is disabled" | `CYPHERON_ALLOW_PRIVATE=0` is set. Unset it for local demos. |
| Changes don't show at :8000 | Run `npm run build` again (option B serves the last build). |

---

## 6. The 4-minute demo

1. Run `python demo_target.py`, then click **Use the local demo site** and **Scan site**.
   The 8 checks tick off live, and the result is an **F stamp, 0/100, CRITICAL risk**.
2. Open **Environment file (.env) exposed** and walk through why it matters, how to fix it, and the evidence.
3. Read the analyst summary.
4. Stop the demo site and run `python demo_target.py --fixed`, then scan again.
   You get a **C, 70/100, "+70 points since the previous scan"**. The remaining fix is HTTPS.
5. Turn off exposed-file checks and passive-scan a real public site.

Optional: set `ANTHROPIC_API_KEY` before starting the backend to make the analyst summary AI-written.
