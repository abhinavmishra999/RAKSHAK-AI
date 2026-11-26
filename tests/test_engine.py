import json
import os
import time
from pathlib import Path

import pytest

from rakshak.config import Settings
from rakshak.engine import Engine
from rakshak.enforcer import NftEnforcer
from rakshak.report import build_plugin_report



def event(ts=None, ip="198.51.100.10", query=""):
    ts = ts if ts is not None else time.time()
    raw = json.dumps({"ts": ts, "ip": ip, "method": "GET", "path": "/search",
                      "query": query, "status": 200, "ua": "synthetic-test"})
    return {"ts": ts, "source_ip": ip, "kind": "http", "method": "GET", "path": "/search",
            "query": query, "body": "", "status": 200, "user_agent": "synthetic-test", "raw": raw}


def make_engine(tmp_path, logs=(), mode="recommend"):
    conf = Settings(data_dir=tmp_path / "data", logs=[str(x) for x in logs], mode=mode,
                    enforcer="none", trusted=[])
    return Engine(conf)


def test_missing_source_is_not_created_and_status_is_explicit(tmp_path):
    source = tmp_path / "does-not-exist.log"
    engine = make_engine(tmp_path, [source])
    assert not source.exists()
    status = engine.source_status()[0]
    assert status["path"] == str(source)
    assert status["readable"] is False
    assert status["state"] == "missing"
    assert status["bytes"] == 0
    assert status["errors"]
    engine.start()
    try:
        assert not source.exists()
        assert engine.tail_alive()
        assert engine.source_status()[0]["state"] == "missing"
    finally:
        assert engine.stop()


def _line(ip):
    return json.dumps({"ts": time.time(), "ip": ip, "method": "GET", "path": "/", "status": 200}) + "\n"


def _wait(engine, n):
    deadline = time.time() + 2
    while time.time() < deadline and engine.store.count_events() < n:
        time.sleep(0.02)
    return engine.store.count_events()


def test_existing_history_is_not_replayed_by_default_and_rotation_is_tracked(tmp_path, monkeypatch):
    monkeypatch.delenv("RAKSHAK_READ_EXISTING", raising=False)
    source = tmp_path / "events.log"
    source.write_text(_line("198.51.100.1"))  # old history: must NOT be imported
    engine = make_engine(tmp_path, [source])
    engine.start()
    try:
        time.sleep(0.3)
        assert engine.store.count_events() == 0
        with open(source, "a") as fh:
            fh.write(_line("198.51.100.3"))
        assert _wait(engine, 1) == 1
        rotated = tmp_path / "events.log.1"
        source.rename(rotated)
        source.write_text(_line("198.51.100.2"))  # new file after rotation is read from its start
        assert _wait(engine, 2) == 2
    finally:
        engine.stop()


def test_restart_resumes_without_duplicates_or_gaps(tmp_path, monkeypatch):
    monkeypatch.delenv("RAKSHAK_READ_EXISTING", raising=False)
    source = tmp_path / "events.log"
    source.write_text("")
    engine = make_engine(tmp_path, [source])
    engine.start()
    with open(source, "a") as fh:
        fh.write(_line("198.51.100.5"))
    assert _wait(engine, 1) == 1
    assert engine.stop()
    with open(source, "a") as fh:          # written while Rakshak was stopped
        fh.write(_line("198.51.100.6"))
    engine2 = make_engine(tmp_path, [source])
    engine2.start()
    try:
        assert _wait(engine2, 2) == 2       # the missed line is read once, the old one is not repeated
        time.sleep(0.3)
        assert engine2.store.count_events() == 2
    finally:
        engine2.stop()


def test_backfill_requires_explicit_opt_in(tmp_path, monkeypatch):
    monkeypatch.setenv("RAKSHAK_READ_EXISTING", "1")
    source = tmp_path / "events.log"
    source.write_text(_line("198.51.100.7"))
    engine = make_engine(tmp_path, [source])
    engine.start()
    try:
        assert _wait(engine, 1) == 1
    finally:
        engine.stop()


def test_validation_reproduces_stored_rule_evidence_and_detects_tamper(tmp_path):
    engine = make_engine(tmp_path)
    engine.process(event(query="q=union select password"))
    incident = engine.store.list_incidents()[0]
    assert incident["validation"] == "evidence_checked"
    detail = incident["validation_detail"]
    assert detail["matching_event_count"] == 1
    assert detail["observed_flagged_count"] == 1
    assert "Rule reproduction only" in detail["note"]

    engine.store.conn.execute("UPDATE events SET raw=? WHERE id=1", ("tampered",))
    engine.store.conn.commit()
    checked = engine.validate_incident(incident["id"])
    assert checked["validation"] == "invalid_evidence"
    assert checked["validation_detail"]["chain"]["ok"] is False


def test_ml_only_incident_remains_suspected(tmp_path):
    engine = make_engine(tmp_path)
    ev = event()
    engine.store.add_event(ev, flagged=True)
    inc_id = engine.store.create_incident({"source_ip": ev["source_ip"], "category": "anomaly",
                                           "categories": ["anomaly"], "severity": "medium", "status": "open",
                                           "first_seen": ev["ts"], "last_seen": ev["ts"],
                                           "detected_at": time.time(), "event_count": 1, "ai_score": .8,
                                           "ai_reasons": ["heuristic"],
                                           "detections": [{"rule_id": "ML-IFOREST-001", "category": "anomaly",
                                                           "severity": "medium", "name": "anomaly", "matched": ""}],
                                           "evidence": [ev["raw"]]})
    checked = engine.validate_incident(inc_id)
    assert checked["validation"] == "suspected"


def test_no_enforcer_is_recorded_but_never_contained_and_auto_requires_evidence(tmp_path):
    engine = make_engine(tmp_path, mode="auto")
    engine.process(event(query="q=union select password"))
    inc = engine.store.list_incidents()[0]
    assert inc["status"] == "block_recorded"
    assert inc["contained_at"] is None
    assert engine.store.blocklist()[0]["enforced"] == "not_enforced"
    assert engine.responder.enforcer.status()["ready"] is False


def test_recommend_approval_keeps_recorded_state_without_firewall(tmp_path):
    engine = make_engine(tmp_path, mode="recommend")
    engine.process(event(query="q=union select password"))
    inc = engine.store.list_incidents()[0]
    action = engine.store.list_actions(inc["id"])[0]
    assert inc["status"] == "awaiting_approval"
    assert engine.approve(action["id"], actor="operator") == inc["id"]
    assert engine.store.get_incident(inc["id"])["status"] == "block_recorded"
    updated = engine.store.get_action(action["id"])
    assert updated["status"] == "recorded"
    assert engine.responder.verify(updated)


def test_failed_undo_retains_database_block(tmp_path):
    engine = make_engine(tmp_path)

    class FakeEnforcer:
        def block(self, ip, ttl):
            return {"state": "enforced", "detail": "test-only"}
        def unblock(self, ip):
            return {"state": "failed", "detail": "test-only removal failure"}

    engine.responder.enforcer = FakeEnforcer()
    engine.store.block("198.51.100.44", "test", enforced="enforced")
    result = engine.responder.undo("198.51.100.44")
    assert result["state"] == "failed"
    assert engine.store.is_blocked("198.51.100.44")
    assert "retained" in engine.store.list_actions()[0]["detail"]


def test_action_mutation_resigns_and_tampered_action_is_not_verified(tmp_path):
    engine = make_engine(tmp_path)
    engine.process(event(query="q=union select password"))
    inc = engine.store.list_incidents()[0]
    action = engine.store.list_actions(inc["id"])[0]
    assert engine.responder.verify(action)
    engine.store.conn.execute("UPDATE actions SET detail=? WHERE id=?", ("changed", action["id"]))
    engine.store.conn.commit()
    assert not engine.responder.verify(engine.store.get_action(action["id"]))


def test_report_refuses_broken_full_chain(tmp_path):
    engine = make_engine(tmp_path)
    engine.process(event(query="q=union select password"))
    inc = engine.store.list_incidents()[0]
    assert engine.report(inc["id"]).exists()
    engine.store.conn.execute("UPDATE events SET raw=? WHERE id=1", ("tampered",))
    engine.store.conn.commit()
    with pytest.raises(ValueError, match="Evidence chain is broken; report refused"):
        engine.report(inc["id"])


def test_incident_and_plugin_pdfs_escape_untrusted_text(tmp_path):
    engine = make_engine(tmp_path)
    engine.process(event(query="q=union select password"))
    inc = engine.store.list_incidents()[0]
    path = engine.report(inc["id"])
    assert path.exists()
    run = {"id": 17, "plugin_id": "<plugin>", "target": "<target>&", "verified": True, "findings": [
        {"id": "F1", "status": "confirmed", "passed": False, "severity": "high",
         "title": "<script>", "what": "<x>", "evidence": "&", "fix": "fix"},
        {"id": "F2", "status": "observed_pass", "passed": True, "title": "pass",
         "evidence": "ok"},
        {"id": "F3", "status": "inconclusive", "passed": False, "title": "unclear",
         "evidence": "?"},
    ]}
    plugin_path = build_plugin_report(run, tmp_path / "reports", org="<Org>&")
    assert plugin_path.name == "plugin_run_17.pdf"
    assert plugin_path.exists()
    with pytest.raises(ValueError, match="not verified"):
        build_plugin_report({**run, "id": 18, "verified": False}, tmp_path / "reports")
    assert not (tmp_path / "reports" / "plugin_run_18.pdf").exists()


def test_model_pickle_is_not_loaded_without_explicit_trust(tmp_path, monkeypatch):
    model = tmp_path / "data" / "anomaly_model.pkl"
    model.parent.mkdir(parents=True)
    model.write_bytes(b"not a pickle")
    monkeypatch.delenv("RAKSHAK_TRUST_MODEL", raising=False)
    engine = make_engine(tmp_path)
    assert engine.anomaly.status()["trained"] is False
    assert "disabled" in engine.anomaly.status()["persistence"]


def test_nft_exact_match_does_not_accept_substring(tmp_path):
    assert NftEnforcer._contains_exact("10.0.0.10, 2001:db8::2", "10.0.0.1") is False
    assert NftEnforcer._contains_exact("10.0.0.10, 2001:db8::2", "10.0.0.10") is True
