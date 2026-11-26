"""Credential-compromise detection: many failed SSH logins then an accepted one, from
the same address. Deterministic (>=5 failures in 5 min), reproducible from stored rows,
severity critical, and - unlike host findings - it has a real IP so the block pipeline runs."""
import time

from rakshak.config import Settings
from rakshak.engine import Engine
from rakshak.parsers import parse_line


def ssh_ev(ip, ts, ok=False, user="root"):
    return {"ts": ts, "source_ip": ip, "kind": "ssh_login", "method": "SSH", "path": user,
            "query": "", "body": "", "status": 200 if ok else 401, "user_agent": "sshd",
            "raw": f"sshd[1]: {'Accepted' if ok else 'Failed'} password for {user} from {ip} port 22"}


def make_engine(tmp_path):
    conf = Settings(data_dir=tmp_path / "data", logs=[], enforcer="none", trusted=[],
                    hostsec_interval=0)
    return Engine(conf)


def test_accepted_after_failures_becomes_critical_incident_with_block_proposal(tmp_path):
    engine = make_engine(tmp_path)
    t0 = time.time()
    for i in range(6):
        engine.process(ssh_ev("203.0.113.7", t0 + i))
    assert engine.store.list_incidents(10) == []          # 6 failures alone: below every threshold
    engine.process(ssh_ev("203.0.113.7", t0 + 8, ok=True))
    inc = engine.store.list_incidents(10)[0]
    assert inc["category"] == "credential_compromise"
    assert inc["severity"] == "critical"
    assert any(d["rule_id"] == "SSH-CRED-001" for d in inc["detections"])
    # validated from stored rows, then the normal containment proposal for its real IP
    assert inc["validation"] == "evidence_checked"
    acts = engine.store.list_actions(inc["id"])
    assert acts and acts[0]["action"] == "block_ip" and acts[0]["target"] == "203.0.113.7"
    assert inc["status"] == "awaiting_approval"           # recommend mode: human decides


def test_lone_success_is_not_flagged(tmp_path):
    engine = make_engine(tmp_path)
    engine.process(ssh_ev("203.0.113.8", time.time(), ok=True))
    assert engine.store.list_incidents(10) == []


def test_old_failures_outside_window_do_not_count(tmp_path):
    engine = make_engine(tmp_path)
    t0 = time.time() - 400
    for i in range(8):
        engine.process(ssh_ev("203.0.113.9", t0 + i))
    engine.process(ssh_ev("203.0.113.9", t0 + 390, ok=True))
    # 8 failures >60s before: the behaviour window (60 s) never fires, the credential rule must
    # not either - the success is 390 s after the last failure (> 300 s window)
    incs = engine.store.list_incidents(10)
    assert not any(i["category"] == "credential_compromise" for i in incs)


def test_validation_reproduces_the_credential_hit_from_stored_rows(tmp_path):
    engine = make_engine(tmp_path)
    t0 = time.time()
    for i in range(6):
        engine.process(ssh_ev("203.0.113.6", t0 + i))
    engine.process(ssh_ev("203.0.113.6", t0 + 8, ok=True))
    inc = engine.store.list_incidents(10)[0]
    again = engine.validate_incident(inc["id"], actor="tester")
    assert again["validation"] == "evidence_checked"
    d = again["validation_detail"]
    assert d["observed_flagged_count"] == d["reproduced_flagged_count"] == 1
    assert d["matching_event_count"] == 1


def test_publickey_accept_line_parses():
    ev = parse_line("Nov 26 10:00:00 host sshd[99]: Accepted publickey for ubuntu from 10.99.0.6 port 51234 ssh2: ED25519")
    assert ev and ev["kind"] == "ssh_login" and ev["status"] == 200 and ev["source_ip"] == "10.99.0.6"
    assert ev["path"] == "ubuntu"
