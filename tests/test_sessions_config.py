"""Restart-proof sessions and rakshak.conf loading.

Sessions live in the database: replacing the in-memory Auth object (what a restart
does) must NOT sign the operator out. The config file closes the 'settings vanish
on restart' gap; explicit environment variables still win over the file.
"""
import os
import subprocess
import sys
import time
import importlib
from pathlib import Path

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
    mod.engine.store.put_user(make_user("admin1", PASSWORD, "admin"))
    yield mod
    mod.engine.stop()
    mod.engine.store.conn.close()
    sys.modules.pop("rakshak.api", None)


def test_session_survives_auth_restart_and_dies_on_logout(api_module):
    from rakshak.auth import Auth, COOKIE
    c = TestClient(api_module.app)
    r = c.post("/api/auth/login", json={"username": "admin1", "password": PASSWORD})
    assert r.status_code == 200
    csrf = r.json()["csrf"]
    token = c.cookies[COOKIE]
    assert api_module.engine.store.get_session(token)["username"] == "admin1"

    # simulate a server restart: brand-new Auth object, same store (same DB file)
    api_module.auth = api_module.engine.auth = Auth(api_module.engine.store, api_module.engine.audit)
    assert token not in api_module.engine.auth.sessions                 # memory really is empty
    c.headers.update({"X-RAKSHAK-CSRF": csrf})
    assert c.get("/api/overview").status_code == 200                    # DB fallback keeps the session
    # the CSRF token came back from the DB too: a write needs it and must pass
    assert c.post("/api/settings/mode", json={"mode": "recommend"}).status_code == 200

    # logout drops it everywhere; a second restart-like swap then refuses again
    assert c.post("/api/auth/logout").status_code == 200
    api_module.auth = api_module.engine.auth = Auth(api_module.engine.store, api_module.engine.audit)
    assert c.get("/api/overview").status_code == 401                    # expired never re-auths
    assert api_module.engine.store.get_session(token) is None


def test_expired_row_is_not_revived(api_module):
    from rakshak.auth import Auth, COOKIE
    c = TestClient(api_module.app)
    r = c.post("/api/auth/login", json={"username": "admin1", "password": PASSWORD})
    assert r.status_code == 200
    token = c.cookies[COOKIE]
    # force the DB row into the past (as if the console were down over the hour)
    api_module.engine.store.conn.execute(
        "UPDATE sessions SET expires=? WHERE token=?", (time.time() - 10, token))
    api_module.engine.store.conn.commit()
    api_module.auth = api_module.engine.auth = Auth(api_module.engine.store, api_module.engine.audit)
    assert c.get("/api/overview").status_code == 401                    # expired session stays dead


def test_rakshak_conf_file_is_loaded_and_env_wins(tmp_path):
    repo = str(Path(__file__).resolve().parents[1])
    conf_file = tmp_path / "rakshak.conf"
    conf_file.write_text("# phase 2 test\nRAKSHAK_ORG=FileOrg\nRAKSHAK_BLOCK_TTL=77\n"
                         "RAKSHAK_NEVER_LOCK=svc_a,svc_b\n")
    code = ("from rakshak.config import Settings; s=Settings();"
            "print(s.org, s.block_ttl, s.never_lock)")
    env = dict(os.environ, RAKSHAK_CONF=str(conf_file))
    env.pop("RAKSHAK_ORG", None)
    env.pop("RAKSHAK_BLOCK_TTL", None)
    out = subprocess.run([sys.executable, "-c", code], cwd=repo, env=env,
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "FileOrg 77 ['svc_a', 'svc_b']" in out.stdout
    # an explicit environment variable overrides the file
    env["RAKSHAK_ORG"] = "EnvOrg"
    out = subprocess.run([sys.executable, "-c", code], cwd=repo, env=env,
                         capture_output=True, text=True)
    assert out.stdout.strip().startswith("EnvOrg 77")
