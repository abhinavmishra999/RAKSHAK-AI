"""Offline adaptation tests: rule-pack gate (schema + sample self-test), live reload,
draft-rule mining from real evidence, payload-entropy feature, ML train gate.
Everything runs in pytest temp folders; nothing is fake - the gate must refuse weak packs.
"""
import base64
import importlib
import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

from rakshak import rulecraft
from rakshak.config import Settings
from rakshak.detect.behaviour import BehaviourDetector
from rakshak.engine import Engine
from rakshak.parsers import parse_line

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
    c.headers.update({"X-RAKSHAK-CSRF": r.json()["csrf"]})
    return c


# ---------------- validate_pack schema gate ----------------

GOOD_PACK = """- id: ADP-TEST-001
  name: Novel exfil token
  category: sql_injection
  severity: high
  patterns:
    - novel_exfil_token
"""

def test_validate_pack_accepts_good_pack():
    rules, errors = rulecraft.validate_pack(GOOD_PACK)
    assert errors == []
    assert rules[0]["id"] == "ADP-TEST-001"


def test_validate_pack_refuses_broken_packs():
    assert rulecraft.validate_pack("not: a: list")[1]                      # mapping, not list
    assert rulecraft.validate_pack("[]")[1]                                 # empty
    rules, errors = rulecraft.validate_pack(
        "- id: lowercase\n  name: x\n  category: nonexistent_cat\n  severity: wow\n  patterns: ['[unclosed']\n")
    joined = " | ".join(errors)
    assert "id" in joined and "category" in joined and "severity" in joined and "compile" in joined
    dup = "- id: ADP-A-1\n  name: a\n  category: xss\n  severity: low\n  patterns: [z]\n" \
          "- id: ADP-A-1\n  name: b\n  category: xss\n  severity: low\n  patterns: [y]\n"
    assert any("duplicate" in e for e in rulecraft.validate_pack(dup)[1])
    assert rulecraft.validate_pack("line" * 40000)[1]                       # junk / oversize input refused


# ---------------- self_test sample gate ----------------

POS = [{"path": "/shop.php", "query": "id=7%20novel_exfil_token%20end", "body": "", "expect": "match"}]
NEG = [{"path": "/shop.php", "query": "id=7&lang=en", "body": "", "expect": "nomatch"}]


def test_self_test_requires_samples_and_firing_rules():
    rules, _ = rulecraft.validate_pack(GOOD_PACK)
    assert rulecraft.self_test(rules, []) != []                             # no samples -> refuse
    assert rulecraft.self_test(rules, POS + NEG) == []
    dead_rules = [{"id": "ADP-DEAD-9", "name": "never fires", "category": "xss",
                   "severity": "low", "patterns": ["zzz_this_matches_nothing_zzz"], "match_on": "path"}]
    gate = rulecraft.self_test(dead_rules, POS + NEG)
    assert any("ADP-DEAD-9" in e for e in gate)
    bad_neg = [{"path": "/x", "query": "contains novel_exfil_token here", "expect": "nomatch"}]
    assert rulecraft.self_test(rules, POS + bad_neg) != []                  # FP on negative -> refuse


# ---------------- reload: imported pack becomes live ----------------

NOVEL = {"ts": time.time(), "source_ip": "10.66.7.7", "kind": "http", "method": "GET",
         "path": "/report.php", "query": "t=1&blob=novel_exfil_token_A7", "body": "",
         "status": 200, "user_agent": "Mozilla/5.0", "raw": "novel line"}


def test_reload_rules_activates_imported_pack(tmp_path):
    conf = Settings(data_dir=tmp_path / "data", logs=[], enforcer="none", trusted=[],
                    hostsec_interval=3600, fim_paths=[],
                    imported_rules_dir=tmp_path / "imp", draft_rules_dir=tmp_path / "dr")
    engine = Engine(conf)
    assert not any("novel_exfil_token" in p for r in engine.rules.rules for p in r["patterns"])
    assert engine.rules.match(NOVEL) == []                                  # not detected yet
    pack_dir = os.path.join(str(conf.imported_rules_dir))
    os.makedirs(pack_dir, exist_ok=True)
    with open(os.path.join(pack_dir, "phase2-pack.yml"), "w") as fh:
        fh.write(GOOD_PACK)
    engine.reload_rules()
    hits = engine.rules.match(NOVEL)
    assert hits and hits[0]["rule_id"] == "ADP-TEST-001"                    # caught after import
    engine.stop()


# ---------------- draft-rule mining from real evidence ----------------

from datetime import datetime, timedelta, timezone


def _log_line(age_s, target, status, size):
    t = (datetime.now(timezone.utc) - timedelta(seconds=age_s)).strftime("%d/%b/%Y:%H:%M:%S")
    return (f'9.4.4.1 - - [{t} +0000] "GET {target} HTTP/1.1" {status} {size} "-" "x"')


# recent timestamps: the incident merge window is 300 s, and these tests exercise it
EV1 = _log_line(40, "/item.php?q=1%27%20UNION%20SELECT%20username%2Cpassword%20"
                     "FROM%20accounts--%20", 500, 900)
EV2 = _log_line(20, "/item.php?page=2%27%20UNION%20SELECT%20username%2Cpassword%20"
                     "FROM%20accounts--%20", 403, 120)


def test_suggest_rule_mines_a_passing_draft_from_evidence():
    inc = {"id": 77, "category": "sql_injection", "severity": "high", "evidence": [EV1, EV2]}
    text, samples, note = rulecraft.suggest_rule(inc, None, parse_line)
    assert "ADP-77-" in text and "NOT active" in note
    rules, errors = rulecraft.validate_pack(text)
    assert errors == [] and rules[0]["category"] == "sql_injection"
    assert rulecraft.self_test(rules, samples) == []                        # draft passes its own gate
    assert parse_line(EV1) is not None


def test_suggest_rule_refuses_host_or_thin_evidence():
    with pytest.raises(ValueError):
        rulecraft.suggest_rule({"id": 1, "category": "new_service", "severity": "high",
                                "evidence": ["process exec /bin/sh -c id"]}, None, parse_line)
    with pytest.raises(ValueError):
        rulecraft.suggest_rule({"id": 2, "category": "sql_injection", "severity": "high",
                                "evidence": [EV1]}, None, parse_line)       # single line: no shared pattern


# ---------------- payload entropy feature ----------------

def _ev(q, ts, ip):
    return {"ts": ts, "source_ip": ip, "kind": "http", "method": "GET", "path": "/p",
            "query": q, "body": "", "status": 200, "user_agent": "ua", "raw": q}


def test_entropy_separates_machine_generated_payloads():
    det = BehaviourDetector()
    base = time.time()
    rnd = [base64.b32encode(os.urandom(15)).decode() for _ in range(4)]
    for i, r in enumerate(rnd):
        det.observe(_ev(f"data={r}junk", base + i, "5.5.5.5"), [{"rule_id": "X"}])
    hi = det.features_for("5.5.5.5")["payload_entropy"]
    det2 = BehaviourDetector()
    for i, q in enumerate(["id=1' or 'a'='a' order by 3--", "name=cat cat cat aaa",
                           "x=aaaa bbbb ccccdddd", "y=eeee ffff gggghhhh"]):
        det2.observe(_ev(q, base + i, "6.6.6.6"), [{"rule_id": "X"}])
    lo = det2.features_for("6.6.6.6")["payload_entropy"]
    assert hi is not None and lo is not None and hi > lo + 0.4             # machine payloads read 'random'


# ---------------- ML training gate ----------------

def test_ml_train_refuses_without_samples_then_trains(tmp_path):
    conf = Settings(data_dir=tmp_path / "data", logs=[], enforcer="none", trusted=[],
                    hostsec_interval=3600, fim_paths=[])
    engine = Engine(conf)
    res = engine.train_anomaly(actor="admin")
    assert res["ok"] is False and "30" in res["reason"]                     # honest refusal
    ts = time.time() - 600
    for i in range(45):                                                     # benign browsing window
        engine.process_event({"ts": ts + i, "source_ip": "10.30.1.9", "kind": "http",
                             "method": "GET", "path": f"/page/{i % 9}", "query": "n=1",
                             "body": "", "status": 200, "user_agent": "Mozilla/5.0",
                             "raw": "benign"})
    res = engine.train_anomaly(actor="admin")
    assert res["ok"] is True and res["samples"] >= 30
    assert engine.anomaly.model is not None
    assert os.path.exists(engine.anomaly.path)                              # persisted for next run
    engine.stop()


# ---------------- API: import gate, live effect, draft endpoint ----------------

def test_api_import_gate_then_live_detection(api_module):
    admin = signin(api_module)
    r = admin.post("/api/rules/import", json={"name": "bad", "rules_yaml": "- just: a string",
                                              "samples": POS})
    assert r.status_code == 400 and "schema" in r.text.lower()
    dead = "- id: ADP-DEAD-9\n  name: never fires\n  category: xss\n  severity: low\n  patterns: [qqzznever]\n"
    r = admin.post("/api/rules/import", json={"name": "dead", "rules_yaml": dead, "samples": POS + NEG})
    assert r.status_code == 400 and "examples" in r.text.lower()           # sample gate refused it
    viewer = signin(api_module, "analyst1")
    r = viewer.post("/api/rules/import", json={"name": "nope", "rules_yaml": GOOD_PACK,
                                               "samples": POS + NEG})
    assert r.status_code == 403                                            # analysts cannot import
    r = admin.post("/api/rules/import", json={"name": "phase2", "rules_yaml": GOOD_PACK,
                                              "samples": POS + NEG})
    assert r.status_code == 200, r.text
    assert r.json()["rules_added"] == 1 and os.path.exists(r.json()["file"])
    assert os.stat(r.json()["file"]).st_mode & 0o077 == 0                  # 0600, private
    listing = admin.get("/api/rules").json()
    row = next(x for x in listing["rules"] if x["id"] == "ADP-TEST-001")
    assert row["imported"] is True
    # the newly imported signature catches the novel attack for real
    ev = {**NOVEL, "ts": time.time(), "raw": "novel attack line observed"}
    api_module.engine.process_event(ev)
    inc = next(i for i in api_module.engine.store.list_incidents(50)
               if i["source_ip"] == NOVEL["source_ip"])
    assert any(d["rule_id"] == "ADP-TEST-001" for d in inc["detections"])
    audit = admin.get("/api/audit").json()
    assert any(e["action"] == "rules.import_refused" for e in audit)
    assert any(e["action"] == "rules.import" for e in audit)


def test_api_suggest_rule_draft_is_not_active_until_imported(api_module):
    admin = signin(api_module)
    for raw in (EV1, EV2):
        api_module.engine.process_event(parse_line(raw))
    inc = next(i for i in api_module.engine.store.list_incidents(50)
               if i["source_ip"] == "9.4.4.1")
    r = admin.post(f"/api/incidents/{inc['id']}/suggest_rule")
    assert r.status_code == 200, r.text
    data = r.json()
    assert "ADP-" in data["yaml"] and data["samples"] and "NOT active" in data["note"]
    import yaml as _y
    draft = _y.safe_load(data["yaml"])
    assert draft[0]["patterns"][0].lower().count("union") + draft[0]["patterns"][0].lower().count("select") >= 1
    # drafts land on disk but are NOT loaded into the engine
    assert os.path.exists(data["file"])
    loaded_ids = {x["id"] for x in admin.get("/api/rules").json()["rules"]}
    assert draft[0]["id"] not in loaded_ids
    assert draft[0]["id"].split("-")[0] == "ADP"
    listing = admin.get("/api/rules").json()
    assert any("draft" in n or data["file"].endswith(n) for n in listing["drafts"])
