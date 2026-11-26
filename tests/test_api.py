"""API safety tests. All accounts, logs and records live in pytest temp folders.
No production logs, firewall rules or organisation data are touched.
"""
import importlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient
from rakshak.auth import make_user

PASSWORD = "Only-a-test-password-2026"


@pytest.fixture
def api_module(tmp_path, monkeypatch):
    monkeypatch.setenv("RAKSHAK_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("RAKSHAK_LOGS", str(tmp_path / "missing.log"))
    monkeypatch.setenv("RAKSHAK_ENFORCER", "none")
    monkeypatch.setenv("RAKSHAK_ALLOWED_HOSTS", "testserver")
    monkeypatch.setenv("RAKSHAK_MODE", "recommend")
    sys.modules.pop("rakshak.api", None)
    mod = importlib.import_module("rakshak.api")
    for name, role in (("admin1", "admin"), ("analyst1", "analyst"), ("viewer1", "viewer")):
        mod.engine.store.put_user(make_user(name, PASSWORD, role))
    yield mod
    mod.engine.stop()
    mod.engine.store.conn.close()
    sys.modules.pop("rakshak.api", None)


def signin(mod, username="admin1"):
    c = TestClient(mod.app)
    r = c.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200
    csrf = r.json()["csrf"]
    c.headers.update({"X-RAKSHAK-CSRF": csrf})
    return c


def test_unauthenticated_security_routes_and_foreign_host_are_refused(api_module):
    c = TestClient(api_module.app)
    assert c.get("/api/health").status_code == 200
    for path in ("/api/overview", "/api/incidents", "/api/protection", "/api/plugins", "/api/runs", "/api/audit"):
        assert c.get(path).status_code == 401, path
    assert c.get("/api/memory").status_code == 401
    assert c.get("/api/health", headers={"Host": "evil.example"}).status_code == 400
    assert c.get("/api/unknown").status_code == 404
    assert c.get("/api/docs").status_code == 404


def test_login_me_cookie_security_headers_and_logout(api_module):
    c = signin(api_module)
    assert c.get("/api/auth/me").json()["role"] == "admin"
    h = c.get("/").headers
    assert h["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert c.post("/api/auth/logout").status_code == 200
    assert c.get("/api/overview").status_code == 401


def test_csrf_required_even_for_admin(api_module):
    c = signin(api_module)
    c.headers.pop("X-RAKSHAK-CSRF")
    assert c.post("/api/plugins/website-check/enable").status_code == 403
    assert c.post("/api/settings/mode", json={"mode": "auto"}).status_code == 403
    c.headers.update({"X-RAKSHAK-CSRF": "wrong"})
    assert c.post("/api/auth/logout").status_code == 403


def test_viewer_and_analyst_roles_cannot_enable_or_change_mode(api_module):
    c = signin(api_module, "viewer1")
    assert c.get("/api/plugins").status_code == 200
    assert c.post("/api/plugins/website-check/enable").status_code == 403
    assert c.post("/api/plugins/website-check/runs", json={"target": "http://127.0.0.1", "reason": "testing", "authorised": True}).status_code == 403
    assert c.get("/api/audit").status_code == 403
    c = signin(api_module, "analyst1")
    assert c.get("/api/audit").status_code == 200
    assert c.post("/api/plugins/website-check/enable").status_code == 403
    assert c.post("/api/settings/mode", json={"mode": "auto"}).status_code == 403


def test_empty_scope_disabled_tools_and_no_implicit_approval(api_module):
    c = signin(api_module)
    body = {"target": "http://127.0.0.1", "reason": "owned target", "authorised": True}
    assert c.post("/api/plugins/website-check/runs", json=body).status_code == 400
    assert c.post("/api/plugins/website-check/enable").status_code == 200
    assert c.post("/api/plugins/website-check/runs", json=body).status_code == 400
    body["authorised"] = False
    assert c.post("/api/plugins/website-check/runs", json=body).status_code == 400
    assert all(r["status"] == "refused" for r in c.get("/api/runs").json())


def test_real_http_test_request_approve_validate_report_and_integrity(api_module):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Real HTTP response fixture; non-existent paths must not be counted as leaked files.
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>test-only catchall page</body></html>")
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        (api_module.conf.data_dir / "scope.yml").write_text("networks: [127.0.0.1/32]\nhosts: []\nnever_scan: []\n")
        admin = signin(api_module)
        analyst = signin(api_module, "analyst1")
        assert admin.post("/api/plugins/website-check/enable").status_code == 200
        target = f"http://127.0.0.1:{server.server_port}"
        body = {"target": target, "reason": "authorised isolated HTTP fixture", "authorised": True}
        q = analyst.post("/api/plugins/website-check/runs", json=body)
        assert q.status_code == 200
        run_id = q.json()["id"]
        assert q.json()["status"] == "queued"
        assert not q.json()["started_at"]
        # This plugin needs an admin: a wrong approver must not consume the request.
        assert analyst.post(f"/api/runs/{run_id}/approve").status_code == 403
        assert admin.get(f"/api/runs/{run_id}").json()["status"] == "queued"
        r = admin.post(f"/api/runs/{run_id}/approve")
        assert r.status_code == 200
        assert r.json()["status"] == "completed"
        full = admin.get(f"/api/runs/{run_id}").json()
        assert full["verified"]
        fs = full["findings"]
        assert any(f["status"] == "confirmed" and f["id"].startswith("HDR-") for f in fs)
        assert not any(f["status"] == "confirmed" and f["id"].startswith("FILE-") for f in fs)
        assert admin.post(f"/api/runs/{run_id}/approve").status_code == 400
        report = admin.post(f"/api/runs/{run_id}/report")
        assert report.status_code == 200
        pdf = admin.get(report.json()["url"])
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
        check = admin.get("/api/integrity").json()
        assert check["events"]["ok"] and check["audit"]["ok"]
        assert admin.get("/api/runs/999999").status_code == 404
    finally:
        server.shutdown()
        server.server_close()


def test_login_failure_throttle_and_disabled_account(api_module):
    c = TestClient(api_module.app)
    for _ in range(5):
        assert c.post("/api/auth/login", json={"username": "absent", "password": "wrong"}).status_code == 401
    assert c.post("/api/auth/login", json={"username": "admin1", "password": PASSWORD}).status_code == 429
    api_module.auth.failures.clear()
    c = signin(api_module)
    user = api_module.engine.store.get_user("admin1")
    user["disabled"] = 1
    api_module.engine.store.put_user(user)
    assert c.get("/api/overview").status_code == 401


def test_edited_pending_request_is_refused_before_any_tool_starts(api_module):
    (api_module.conf.data_dir / "scope.yml").write_text("networks: [127.0.0.1/32, 127.0.0.2/32]\nhosts: []\nnever_scan: []\n")
    admin = signin(api_module)
    assert admin.post("/api/plugins/website-check/enable").status_code == 200
    q = admin.post("/api/plugins/website-check/runs",
                   json={"target": "http://127.0.0.1:9", "reason": "tamper check", "authorised": True})
    assert q.status_code == 200
    run_id = q.json()["id"]
    # Someone with database access swaps the approved target behind the approver's back.
    api_module.engine.store.conn.execute("UPDATE plugin_runs SET target='http://127.0.0.2:9' WHERE id=?", (run_id,))
    api_module.engine.store.conn.commit()
    assert admin.get(f"/api/runs/{run_id}").json()["verified"] is False
    r = admin.post(f"/api/runs/{run_id}/approve")
    assert r.status_code == 400 and "signature" in r.json()["detail"]
    run = api_module.engine.store.get_run(run_id)
    assert run["status"] == "queued" and not run["started_at"] and not run["cmd"]


def test_no_readable_logs_means_blind_not_safe(api_module):
    c = signin(api_module)
    ov = c.get("/api/overview").json()
    assert ov["state"] == "blind"
    assert ov["events_total"] == 0
    assert not ov["enforcer"]["ready"]
    assert ov["sources"][0]["state"] == "missing"

def test_memory_timeline_is_computed_from_signed_records(api_module):
    """Memory has no table of its own: it merges the same signed incidents, actions and runs
    the other pages show, newest first, filterable, honest when empty."""
    import time
    c = signin(api_module)
    st = api_module.engine.store
    assert c.get("/api/memory").json() == {"entries": [], "counts": {}, "shown": 0}
    now = time.time()
    iid = st.create_incident({"source_ip": "203.0.113.9", "category": "brute_force", "severity": "high",
                              "status": "contained", "first_seen": now - 300, "last_seen": now - 60,
                              "detected_at": now - 300, "event_count": 9})
    st.add_action({"ts": now - 200, "incident_id": iid, "action": "block_ip", "target": "203.0.113.9",
                   "mode": "recommend", "status": "done", "detail": "approved by analyst1",
                   "signature": "x"})
    st.add_run({"plugin_id": "website-check", "plugin_version": "1", "kind": "active",
                "target": "http://10.0.0.8", "status": "completed", "requested_by": "analyst1",
                "requested_at": now - 100, "approved_by": "admin1", "summary": {"state": "ok"},
                "findings": [], "authorised_statement": "I confirm this asset belongs to our organisation"})
    st.create_incident({"source_ip": "198.51.100.2", "category": "xss", "severity": "medium",
                        "status": "resolved", "first_seen": now - 9 * 86400, "last_seen": now - 9 * 86400,
                        "detected_at": now - 9 * 86400})
    m = c.get("/api/memory").json()
    assert [e["kind"] for e in m["entries"]] == ["test", "action", "alert", "alert"]  # newest first
    assert m["counts"] == {"test": 1, "action": 1, "alert": 2}
    alert = m["entries"][2]
    assert alert["source_ip"] == "203.0.113.9" and alert["event_count"] == 9 and alert["validation"] == "pending"
    act = m["entries"][1]
    assert act["signed"] is True and act["status"] == "done"
    run = m["entries"][0]
    assert run["approved_by"] == "admin1" and "organisation" in run["authorised_statement"]
    assert c.get("/api/memory?kind=alert").json()["counts"] == {"alert": 2}
    assert all(e["kind"] == "test" for e in c.get("/api/memory?kind=test").json()["entries"])
    assert c.get("/api/memory?days=1").json()["counts"] == {"test": 1, "action": 1, "alert": 1}
    assert c.get("/api/memory?kind=bogus").status_code == 400
    viewer = signin(api_module, "viewer1")  # no more sensitive than the pages viewers already see
    assert len(viewer.get("/api/memory").json()["entries"]) == 4
