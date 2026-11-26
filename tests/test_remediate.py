"""Tests for host remediation: approved, live-verified undo of attacker changes.

Everything here runs in pytest temp folders (and, for the listener test, against a
real socket owned by a real test child process). The console's own files, logs and
firewall are never touched.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from rakshak.config import Settings
from rakshak.engine import Engine
from rakshak.hostsec import listen_snapshot

FAKE_ACCT_HELPER = r'''#!/usr/bin/python3
import json, os, re, sys
from pathlib import Path
P = os.environ["RAK_TEST_PASSWD"]; S = os.environ["RAK_TEST_SHADOW"]
NAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
DENY = {"root", "ubuntu"}
def refuse(why):
    print(f"fake-acct: refused: {why}", file=sys.stderr); sys.exit(2)
def entries(path):
    return [ln.strip().split(":") for ln in Path(path).read_text().splitlines() if ln.strip()]
def find(rows, name):
    return next((r for r in rows if r[0] == name), None)
def status(name):
    pw = find(entries(P), name); sh = find(entries(S), name)
    return {"name": name, "exists": bool(pw), "uid": int(pw[2]) if pw else None,
            "locked": (sh[1].startswith("!") if sh else None)}
args = sys.argv[1:]
if len(args) != 2 or args[0] not in ("status", "lock", "remove"):
    refuse("usage")
name = args[1]
if not NAME_RE.fullmatch(name):
    refuse("bad name")
if args[0] == "status":
    print(json.dumps(status(name))); sys.exit(0)
if name in DENY:
    refuse("protected account")
pw = find(entries(P), name)
if pw is None:
    refuse("does not exist")
if int(pw[2]) < 1000:
    refuse("system account")
if args[0] == "lock":
    rows = entries(S)
    row = find(rows, name)
    if row and row[1].startswith("!"):
        print(json.dumps(status(name))); sys.exit(0)
    if row:
        row[1] = "!" + row[1]
    else:
        rows.append([name, "!x", "0", "", "", "", ""])
    Path(S).write_text("\n".join(":".join(r) for r in rows) + "\n")
    if not status(name)["locked"]:
        refuse("verify failed")
    print(json.dumps(status(name))); sys.exit(0)
# remove
Path(P).write_text("\n".join(":".join(r) for r in entries(P) if r[0] != name) + "\n")
Path(S).write_text("\n".join(":".join(r) for r in entries(S) if r[0] != name) + "\n")
if status(name)["exists"]:
    refuse("still present")
print(json.dumps(status(name))); sys.exit(0)
'''


def tcp_hdr():
    return ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
            "retrnsmt uid timeout inode")


def make_conf(tmp_path, watch=(), passwd=None, group=None, tcp=None, acct=()):
    return Settings(data_dir=tmp_path / "data", logs=[], enforcer="none", trusted=[],
                    hostsec_interval=30, acct_cmd=list(acct),
                    fim_paths=[str(w) for w in watch],
                    passwd_file=str(passwd or tmp_path / "missing-passwd"),
                    group_file=str(group or tmp_path / "missing-group"),
                    proc_net_files=[str(t) for t in (tcp or [tmp_path / "missing-tcp"])])


def find_incident(engine, category):
    return next(i for i in engine.store.list_incidents(100)
                if i["source_ip"] == "system" and i["category"] == category)


def tamper_alert(tmp_path, extra=None):
    """Common setup: baseline -> tamper the watched file -> one open file_integrity alert."""
    watch = tmp_path / "app.conf"
    watch.write_text("original sanctioned content\n")
    conf = make_conf(tmp_path, watch=[watch], **(extra or {}))
    engine = Engine(conf)
    assert engine.hostsec.scan() == []
    time.sleep(0.01)
    watch.write_text("ATTACKER EDITED THIS\n")
    findings = engine.hostsec.scan()
    engine._host_finding(findings[0])
    return engine, watch, find_incident(engine, "file_integrity")


def test_restore_proposal_does_nothing_until_approval_then_verifies(tmp_path):
    engine, watch, inc = tamper_alert(tmp_path)
    assert inc["validation"] == "evidence_checked"

    opts = engine.remediator.possibilities(engine.store.get_incident(inc["id"]))
    restore = next(o for o in opts if o["action"] == "restore_file")
    assert restore["possible"], restore["reason"]

    act, created = engine.remediator.propose(inc["id"], "restore_file", actor="analyst9")
    assert created and act["status"] == "proposed"
    assert watch.read_text() == "ATTACKER EDITED THIS\n"       # a proposal changes NOTHING
    assert engine.store.get_incident(inc["id"])["status"] == "awaiting_approval"

    # approve THROUGH the engine dispatcher (what the API route calls)
    inc_id = engine.approve(act["id"], actor="admin7")
    assert inc_id == inc["id"]
    assert watch.read_text() == "original sanctioned content\n"   # the attacker's change is UNDONE
    action = engine.store.get_action(act["id"])
    assert action["status"] == "done"
    assert engine.responder.verify(action)
    after = engine.store.get_incident(inc["id"])
    assert after["validation"] == "suspected"       # live re-check now says: reverted / restored
    assert any("matches the recorded original" in r for r in after["validation_detail"]["reasons"])
    assert engine.store.verify_chain()["ok"]


def test_restore_when_alert_resolved_is_cancelled_not_executed(tmp_path):
    engine, watch, inc = tamper_alert(tmp_path)
    act, _ = engine.remediator.propose(inc["id"], "restore_file", actor="analyst")
    engine.responder.cancel_pending(inc["id"], "alert resolved by analyst")
    engine.store.update_incident(inc["id"], status="resolved", resolved_at=time.time())
    inc_id, result = engine.remediator.approve(act["id"], actor="admin")
    assert (inc_id, result) == (None, None)
    assert watch.read_text() == "ATTACKER EDITED THIS\n"
    assert engine.store.get_action(act["id"])["status"] == "cancelled"


def test_tampered_restore_proposal_is_refused_without_touching_file(tmp_path):
    engine, watch, inc = tamper_alert(tmp_path)
    act, _ = engine.remediator.propose(inc["id"], "restore_file", actor="analyst")
    engine.store.update_action(act["id"], detail="evil instruction")   # edit outside Rakshak
    inc_id, result = engine.remediator.approve(act["id"], actor="admin")
    assert (inc_id, result) == (None, None)
    assert watch.read_text() == "ATTACKER EDITED THIS\n"
    assert engine.store.get_action(act["id"])["status"] == "proposed"


def test_restore_not_offered_when_original_was_unreadable(tmp_path):
    watch = tmp_path / "secret.conf"
    watch.write_text("root-owned content\n")
    os.chmod(watch, 0o000)
    try:
        conf = make_conf(tmp_path, watch=[watch])
        engine = Engine(conf)
        engine.hostsec.scan()                       # baseline: metadata only, no content hash
        os.chmod(watch, 0o644)
        watch.write_text("tampered now that it is readable\n")
        findings = engine.hostsec.scan()
        assert len(findings) == 1
        engine._host_finding(findings[0])
        inc = find_incident(engine, "file_integrity")
        restore = next(o for o in engine.remediator.possibilities(inc) if o["action"] == "restore_file")
        assert not restore["possible"]
        assert "not readable" in restore["reason"]
        with pytest.raises(ValueError):
            engine.remediator.propose(inc["id"], "restore_file", actor="analyst")
    finally:
        os.chmod(watch, 0o644)


def test_listener_alert_is_attributed_and_stop_is_verified(tmp_path):
    port = 15000 + os.getpid() % 377
    code = (f"import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,"
            f"socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',{port})); s.listen(5); time.sleep(60)")
    key = f"127.0.0.1:{port}"
    conf = Settings(data_dir=tmp_path / "data", logs=[], enforcer="none", trusted=[],
                        hostsec_interval=30, fim_paths=[],
                        passwd_file=str(tmp_path / "none"), group_file=str(tmp_path / "none"),
                        proc_net_files=["/proc/net/tcp", "/proc/net/tcp6"])
    engine = Engine(conf)
    engine.hostsec.scan()                                # baseline FIRST: no attacker socket in it
    child = subprocess.Popen([sys.executable, "-c", code])
    try:
        findings = None
        for _ in range(30):
            findings = engine.hostsec.scan()
            if any(f["category"] == "new_service" and f["object"] == key for f in findings):
                break
            time.sleep(0.2)
        f = next((f for f in findings if f["category"] == "new_service" and f["object"] == key), None)
        assert f is not None, f"listener {key} not detected in {findings}"
        proc = f["observed"]["process"]
        assert proc and proc["pid"] == child.pid and "socket" in proc["cmdline"]
        engine._host_finding(f)
        inc = find_incident(engine, "new_service")
        assert inc["validation"] == "evidence_checked"
        opt = next(o for o in engine.remediator.possibilities(inc) if o["action"] == "stop_process")
        assert opt["possible"], opt["reason"]
        act, _ = engine.remediator.propose(inc["id"], "stop_process", actor="analyst")
        assert engine.approve(act["id"], actor="admin") == inc["id"]   # dispatcher: execute + re-validate
        action = engine.store.get_action(act["id"])
        assert action["status"] == "done", action
        assert child.wait(timeout=10) is not None
        assert key not in listen_snapshot(["/proc/net/tcp", "/proc/net/tcp6"])
        after = engine.store.get_incident(inc["id"])
        assert after["validation"] == "suspected"        # re-observation: no longer listening
    finally:
        child.kill()


def test_backdoor_account_can_be_locked_then_removed_with_verification(tmp_path):
    passwd = tmp_path / "passwd"
    shadow = tmp_path / "shadow"
    passwd.write_text("root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:u:/home/ubuntu:/bin/bash\n")
    shadow.write_text("root:!:0:::::\nubuntu:x:0:::::\n")
    helper = tmp_path / "fake-acct"
    helper.write_text(FAKE_ACCT_HELPER)
    os.chmod(helper, 0o755)
    os.environ["RAK_TEST_PASSWD"] = str(passwd)
    os.environ["RAK_TEST_SHADOW"] = str(shadow)
    try:
        conf = make_conf(tmp_path, passwd=passwd, group=tmp_path / "groups",
                         acct=[sys.executable, str(helper)])
        Path(tmp_path / "groups").write_text("root:x:0:\nsudo:x:27:ubuntu\n")
        engine = Engine(conf)
        engine.hostsec.scan()                             # accounts baseline
        with passwd.open("a") as fh:
            fh.write("invader:x:1500:1500::/home/invader:/bin/bash\n")
        with shadow.open("a") as fh:
            fh.write("invader:hashhash:0:::::\n")
        findings = engine.hostsec.scan()
        acc = next(f for f in findings if f["category"] == "account_change")
        assert acc["detection"]["rule_id"] == "HOST-ACC-001"
        engine._host_finding(acc)
        inc = find_incident(engine, "account_change")
        opts = {o["action"]: o for o in engine.remediator.possibilities(inc)}
        assert opts["lock_account"]["possible"] and opts["remove_account"]["possible"]
        act, _ = engine.remediator.propose(inc["id"], "lock_account", actor="analyst")
        _, result = engine.remediator.approve(act["id"], actor="admin")
        assert result["state"] == "enforced", result
        assert "invader:!" in shadow.read_text()          # password logins disabled, verified
        # removing it entirely also works and is verified absent:
        act2, _ = engine.remediator.propose(inc["id"], "remove_account", actor="analyst")
        _, result2 = engine.remediator.approve(act2["id"], actor="admin")
        assert result2["state"] == "enforced", result2
        assert "invader" not in passwd.read_text()
    finally:
        os.environ.pop("RAK_TEST_PASSWD", None)
        os.environ.pop("RAK_TEST_SHADOW", None)


def test_protected_and_unconfigured_account_helpers_are_refused(tmp_path):
    engine, watch, inc = tamper_alert(tmp_path)
    # a synthetic "new account" incident with no helper configured:
    opts = engine.remediator.possibilities({
        "source_ip": "system", "category": "account_change",
        "detections": [{"matched": "passwd:invader", "name": "HOST-ACC-001 new account",
                        "before": {"absent": True}, "found": {"uid": "1500"}}]})
    lock = next(o for o in opts if o["action"] == "lock_account")
    assert not lock["possible"] and "helper" in lock["reason"]
    # protected account: even with a helper the console's own user is off-limits
    engine.remediator.acct_cmd = [sys.executable, "whatever"]
    opts = engine.remediator.possibilities({
        "source_ip": "system", "category": "account_change",
        "detections": [{"matched": "passwd:root", "name": "HOST-ACC-001 new account",
                        "before": {"absent": True}, "found": {"uid": "0"}}]})
    assert all(not o["possible"] for o in opts)


def test_accept_change_closes_alert_and_cancels_pending_undo(tmp_path):
    engine, watch, inc = tamper_alert(tmp_path)
    act, _ = engine.remediator.propose(inc["id"], "restore_file", actor="analyst")
    out = engine.accept_change(inc["id"], actor="admin2")
    assert out["status"] == "resolved" and out["validation"] == "accepted"
    assert str(watch) in engine.hostsec.state["accepted"]
    assert engine.hostsec.accepted_by(str(watch))["actor"] == "admin2"
    assert engine.store.get_action(act["id"])["status"] == "cancelled"
    records = [a for a in engine.store.list_actions(inc["id"]) if a["action"] == "accept_change"]
    assert records and engine.responder.verify(records[0])
    # and the console refuses to re-run accept/propose on closed alerts
    with pytest.raises(ValueError):
        engine.accept_change(inc["id"], actor="admin2")
    with pytest.raises(ValueError):
        engine.remediator.propose(inc["id"], "restore_file", actor="analyst")
