"""Tests for the system-security sensors (rakshak.hostsec) and their engine pipeline:
baseline first, then every change becomes a chained event, an incident, and an independent
live re-check that can also downgrade the alert when the change was reverted."""
import time
from pathlib import Path

import pytest

from rakshak.config import Settings
from rakshak.engine import Engine


TCP_HDR = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
           "retrnsmt uid timeout inode")


def tcp_line(hex_local, uid="1000"):
    return f"   0: {hex_local} 00000000:0000 0A 00000000:00000000 00:00000000 00000000  {uid}        0 12345 1 0000000000000000 100 0 0 10 0"


def make_conf(tmp_path, watch=(), passwd=None, group=None, tcp=None):
    return Settings(data_dir=tmp_path / "data", logs=[], enforcer="none", trusted=[],
                    hostsec_interval=30,
                    fim_paths=[str(w) for w in watch],
                    passwd_file=str(passwd or tmp_path / "missing-passwd"),
                    group_file=str(group or tmp_path / "missing-group"),
                    proc_net_files=[str(t) for t in (tcp or [tmp_path / "missing-tcp"])])


def find_incident(engine, category):
    return next(i for i in engine.store.list_incidents(100)
                if i["source_ip"] == "system" and i["category"] == category)


def test_file_integrity_baseline_then_change_is_alerted_and_rechecked(tmp_path):
    watch = tmp_path / "app.conf"
    watch.write_text("original content\n")
    engine = Engine(make_conf(tmp_path, watch=[watch]))
    assert engine.hostsec is not None
    assert engine.hostsec.scan() == []          # first pass only records the baseline
    assert engine.store.list_incidents(50) == []  # no alerts from a baseline

    time.sleep(0.01)
    watch.write_text("tampered content here\n")   # attacker edits the file
    findings = engine.hostsec.scan()
    assert len(findings) == 1
    f = findings[0]
    assert f["category"] == "file_integrity"
    assert f["detection"]["rule_id"] == "HOST-FIM-001"
    assert f["previous"].get("sha256") and f["observed"].get("sha256")
    assert f["previous"]["sha256"] != f["observed"]["sha256"]

    engine._host_finding(f)
    inc = find_incident(engine, "file_integrity")
    assert inc["validation"] == "evidence_checked"     # live re-check confirmed the difference
    assert inc["status"] == "open"                      # host finding: never auto-responded
    assert engine.store.list_actions(inc["id"]) == []   # and no block is proposed for "system"
    assert engine.store.verify_chain()["ok"]

    # revert the change -> re-check must downgrade, not keep claiming containment
    watch.write_text("original content\n")
    inc = engine.validate_incident(inc["id"], actor="tester")
    assert inc["validation"] == "suspected"
    assert any("reverted" in r or "no longer" in r for r in inc["validation_detail"]["reasons"])


def test_same_object_updates_one_incident_not_two(tmp_path):
    watch = tmp_path / "keys.conf"
    watch.write_text("a\n")
    engine = Engine(make_conf(tmp_path, watch=[watch]))
    engine.hostsec.scan()
    time.sleep(0.01)
    watch.write_text("b\n")
    (f1,) = engine.hostsec.scan()
    engine._host_finding(f1)
    time.sleep(0.01)
    watch.write_text("c\n")
    (f2,) = engine.hostsec.scan()
    engine._host_finding(f2)
    incs = [i for i in engine.store.list_incidents(50) if i["source_ip"] == "system"]
    assert len(incs) == 1
    assert incs[0]["event_count"] == 2


def test_unreadable_root_only_file_is_watched_by_metadata_only(tmp_path):
    secret = tmp_path / "shadowlike"
    secret.write_bytes(b"x")
    secret.chmod(0o000)
    try:
        engine = Engine(make_conf(tmp_path, watch=[secret]))
        s1 = engine.hostsec.scan()  # baseline
        assert s1 == []
        st = engine.hostsec.state["baseline"][str(secret)]
        assert "sha256" not in st and st["exists"]        # honest: content not readable
        secret.chmod(0o644)                               # permission change is observable
        (f,) = engine.hostsec.scan()
        assert f["category"] == "file_integrity"
        engine._host_finding(f)
        inc = find_incident(engine, "file_integrity")
        assert inc["validation"] == "evidence_checked"
    finally:
        secret.chmod(0o600)


def test_new_listener_is_detected_and_gone_listener_downgrades(tmp_path):
    tcp = tmp_path / "fake_tcp"
    tcp.write_text(TCP_HDR + "\n" + tcp_line("0100007F:1F91") + "\n")   # 127.0.0.1:8081
    engine = Engine(make_conf(tmp_path, tcp=[tcp]))
    assert engine.hostsec.scan() == []                                   # baseline
    assert engine.hostsec.status()["ports_listening"] == 1

    tcp.write_text(TCP_HDR + "\n" + tcp_line("0100007F:1F91") + "\n"
                   + tcp_line("00000000:270F") + "\n")                   # 0.0.0.0:9999 appeared
    (f,) = engine.hostsec.scan()
    assert f["category"] == "new_service"
    assert f["object"] == "0.0.0.0:9999"
    engine._host_finding(f)
    inc = find_incident(engine, "new_service")
    assert inc["severity"] == "high"
    assert inc["validation"] == "evidence_checked"
    assert "still listening" in " ".join(inc["validation_detail"]["reasons"])

    tcp.write_text(TCP_HDR + "\n" + tcp_line("0100007F:1F91") + "\n")    # attacker left
    inc = engine.validate_incident(inc["id"], actor="tester")
    assert inc["validation"] == "suspected"
    assert "no longer listening" in " ".join(inc["validation_detail"]["reasons"])


def test_new_uid0_account_and_sudo_membership_alert(tmp_path):
    passwd = tmp_path / "passwd"
    group = tmp_path / "group"
    passwd.write_text("root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
    group.write_text("sudo:x:27:alice\n")
    engine = Engine(make_conf(tmp_path, passwd=passwd, group=group))
    assert engine.hostsec.scan() == []      # baseline includes alice's sudo membership

    passwd.write_text("root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
                      "svcbackup:x:0:0::/tmp:/bin/bash\n")
    group.write_text("sudo:x:27:alice,bob\n")
    findings = engine.hostsec.scan()
    cats = {(f["category"], f["detection"]["rule_id"]) for f in findings}
    assert ("account_change", "HOST-ACC-001") in cats      # new account
    assert ("account_change", "HOST-ACC-005") in cats      # new sudo member
    uid0 = next(f for f in findings if "svcbackup" in f["object"])
    assert uid0["severity"] == "critical"
    for f in findings:
        engine._host_finding(f)
    incs = [i for i in engine.store.list_incidents(50) if i["category"] == "account_change"]
    assert len(incs) == 2
    assert all(i["validation"] == "evidence_checked" for i in incs)

    # remove the rogue account again -> the re-check sees it gone
    passwd.write_text("root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
    inc_new = next(i for i in engine.store.list_incidents(100)
                   if i["category"] == "account_change"
                   and "svcbackup" in i["detections"][0]["matched"])
    inc_new = engine.validate_incident(inc_new["id"], actor="tester")
    assert inc_new["validation"] == "suspected"


def test_host_findings_survive_restart_without_realerting(tmp_path):
    watch = tmp_path / "cfg.conf"
    watch.write_text("1\n")
    engine = Engine(make_conf(tmp_path, watch=[watch]))
    engine.hostsec.scan()
    time.sleep(0.01)
    watch.write_text("2\n")
    (f,) = engine.hostsec.scan()
    engine._host_finding(f)
    # a second engine on the same data dir (restart) sees no new change
    engine2 = Engine(make_conf(tmp_path, watch=[watch]))
    assert engine2.hostsec.scan() == []
    assert len([i for i in engine2.store.list_incidents(50) if i["source_ip"] == "system"]) == 1


def test_hostsec_disabled_when_interval_zero(tmp_path):
    conf = Settings(data_dir=tmp_path / "d2", logs=[], enforcer="none", hostsec_interval=0)
    engine = Engine(conf)
    assert engine.hostsec is None
    assert engine.host_alive() is False
