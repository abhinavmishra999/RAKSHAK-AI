"""Distributed sensor ingestion: the hub endpoint accepts only HMAC-signed, in-clock,
monotonic-sequence batches, records the node, and turns a real attack line into an
incident that carries the sensor's node name. All temp folders; no production state.
"""
import hashlib
import hmac
import importlib
import json
import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

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
    from rakshak.auth import make_user
    for name, role in (("admin1", "admin"), ("analyst1", "analyst")):
        mod.engine.store.put_user(make_user(name, PASSWORD, role))
    yield mod
    mod.engine.stop()
    mod.engine.store.conn.close()
    sys.modules.pop("rakshak.api", None)


def signin(mod, username="admin1"):
    c = TestClient(mod.app)
    r = c.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200
    c.headers.update({"X-RAKSHAK-CSRF": r.json()["csrf"]})
    return c


def sign(secret, node, seq, body, ts=None):
    ts = ts if ts is not None else str(time.time())
    msg = f"{ts}\n{node}\n{seq}\n{hashlib.sha256(body).hexdigest()}".encode()
    return ts, hmac.new(secret, msg, hashlib.sha256).hexdigest()


def hdr(secret, node, seq, body, ts=None, sig_override=None):
    ts2, sig = sign(secret, node, seq, body, ts)
    return {"X-Rakshak-Sensor": node, "X-Rakshak-Seq": str(seq), "X-Rakshak-Timestamp": ts2,
            "X-Rakshak-Sign": sig_override or sig}


ATTACK = {"ts": time.time(), "source_ip": "77.88.9.9", "kind": "http", "method": "GET",
          "path": "/shop.php", "query": "id=1 UNION SELECT username,password FROM users",
          "body": "", "status": 500, "user_agent": "sqlmap/1.7", "raw": "sensor attack line"}
BENIGN = {"ts": time.time(), "source_ip": "10.1.2.3", "kind": "http", "method": "GET",
          "path": "/index.html", "query": "", "body": "", "status": 200,
          "user_agent": "Mozilla/5.0", "raw": "sensor benign line"}


def test_ingest_requires_secret_configured(api_module):
    c = TestClient(api_module.app)
    r = c.post("/api/ingest", content=b"{}", headers={
        "X-Rakshak-Sensor": "n1", "X-Rakshak-Seq": "1",
        "X-Rakshak-Timestamp": str(time.time()), "X-Rakshak-Sign": "0" * 64})
    assert r.status_code == 503                          # no secret file -> refused, honestly


def test_ingest_full_flow_signature_replay_and_node_incident(api_module):
    secret = os.urandom(32)
    os.makedirs(str(api_module.conf.data_dir), exist_ok=True)
    with open(os.path.join(str(api_module.conf.data_dir), "sensor_secret.key"), "wb") as fh:
        fh.write(secret)
    anon = TestClient(api_module.app)
    body = json.dumps({"events": [ATTACK, BENIGN, {**BENIGN, "kind": "host_exec"}]}).encode()

    # 1) bad signature -> 401
    assert anon.post("/api/ingest", content=body,
                     headers=hdr(secret, "web01", 1, body, sig_override="f" * 64)).status_code == 401

    # 2) stale timestamp -> 401
    old_ts = str(time.time() - 600)
    assert anon.post("/api/ingest", content=body,
                     headers=hdr(secret, "web01", 1, body, ts=old_ts)).status_code == 401

    # 3) valid batch -> accepted; host-kind event filtered at the hub
    r = anon.post("/api/ingest", content=body, headers=hdr(secret, "web01", 1, body))
    assert r.status_code == 200 and r.json()["accepted"] == 2

    # 4) exact replay -> 409 (sequence must increase)
    assert anon.post("/api/ingest", content=body, headers=hdr(secret, "web01", 1, body)).status_code == 409

    # 5) the attack produced an incident that names the sensor node
    admin = signin(api_module)
    incs = [i for i in api_module.engine.store.list_incidents(50) if i.get("node") == "web01"]
    assert incs and incs[0]["source_ip"] == "77.88.9.9"
    nodes = admin.get("/api/nodes").json()["nodes"]
    w = next(n for n in nodes if n["name"] == "web01")
    assert w["last_seq"] == 1 and w["events_total"] == 2
    audit = admin.get("/api/audit").json()
    assert any(e["action"] == "sensor.batch" for e in audit)
    assert any(e["action"] == "sensor.bad_signature" for e in audit)


def test_ingest_headers_must_be_wellformed(api_module):
    secret = os.urandom(32)
    os.makedirs(str(api_module.conf.data_dir), exist_ok=True)
    open(os.path.join(str(api_module.conf.data_dir), "sensor_secret.key"), "wb").write(secret)
    anon = TestClient(api_module.app)
    body = json.dumps({"events": [BENIGN]}).encode()
    assert anon.post("/api/ingest", content=body, headers={}).status_code == 401
    ts, sig = sign(secret, "web9", "x1", body)
    assert anon.post("/api/ingest", content=body, headers={
        "X-Rakshak-Sensor": "web9", "X-Rakshak-Seq": "x1",
        "X-Rakshak-Timestamp": ts, "X-Rakshak-Sign": sig}).status_code == 401


def test_overview_reports_ingest_enabled(api_module):
    admin = signin(api_module)
    assert admin.get("/api/overview").json()["ingest_enabled"] is False
    os.makedirs(str(api_module.conf.data_dir), exist_ok=True)
    open(os.path.join(str(api_module.conf.data_dir), "sensor_secret.key"), "wb").write(os.urandom(32))
    assert admin.get("/api/overview").json()["ingest_enabled"] is True
