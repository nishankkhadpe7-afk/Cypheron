"""End-to-end tests. Start `python demo_target.py` first (port 8081), then: python test_api.py"""
import os

os.environ["CYPHERON_DB"] = "test_cypheron.db"
if os.path.exists("test_cypheron.db"):
    os.remove("test_cypheron.db")

from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402

client = TestClient(app)
TARGET = "http://localhost:8081"


def test_consent_required():
    r = client.post("/api/scan", json={"url": TARGET, "active_checks": True})
    assert r.status_code == 400 and "authorised" in r.json()["detail"]


def test_bad_url():
    r = client.post("/api/scan", json={"url": "ftp://x"})
    assert r.status_code == 400


def test_rest_scan_and_history():
    r = client.post("/api/scan", json={"url": TARGET, "active_checks": True, "consent": True})
    assert r.status_code == 200, r.text
    rep = r.json()
    ids = {f["id"] for f in rep["findings"]}
    for expected in ("exposure/.git/HEAD", "exposure/.env", "cors.reflect.credentials",
                     "header.csp.missing", "transport.https.missing", "exposure.listing/uploads/"):
        assert expected in ids, expected
    assert rep["risk"] == "CRITICAL" and rep["analyst"]["text"]

    hist = client.get("/api/scans").json()
    assert hist[0]["id"] == rep["id"]
    assert client.get(f"/api/scans/{rep['id']}").json()["score"] == rep["score"]
    assert client.get("/api/scans/99999").status_code == 404


def test_passive_skips_active_probes():
    rep = client.post("/api/scan", json={"url": TARGET}).json()
    assert not any(f["category"] == "exposure" for f in rep["findings"])
    assert rep["previous_score"] is not None  # history diff works


def test_websocket_live_events():
    with client.websocket_connect("/api/ws/scan") as ws:
        ws.send_json({"url": TARGET, "active_checks": True, "consent": True})
        types = []
        while True:
            evt = ws.receive_json()
            types.append(evt["type"])
            if evt["type"] in ("complete", "error"):
                break
    assert types[0] == "start" and types[-1] == "complete"
    assert types.count("check_start") == types.count("check_done") == 8


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
    os.remove("test_cypheron.db")
