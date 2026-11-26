"""Regression tests for issues found in the code review (26 Nov 2026).
Synthetic, test-only events use documentation addresses (198.51.100.0/24); temp folders only.
"""
import time

import pytest

from rakshak.plugins.scope import Scope, TargetError
from tests.test_api import api_module, signin  # noqa: F401  (fixture re-use)


@pytest.mark.parametrize("text", [
    "- 10.0.0.0/8\n",                                   # list root
    "networks: 10.0.0.0/8\n",                           # not a list
    "networks: ['not-a-cidr', '127.0.0.1/32']\n",      # one bad entry poisons the file
    "networks: [127.0.0.1/32]\nhosts: 7\n",
    "networks: [127.0.0.1/32]\nnever_scan: 7\n",
    "networks: [127.0.0.1/32]\nextra: yes\n",            # unknown key
    "networks: [127.0.0.1/32]\nhosts: ['bad host!']\n",
])
def test_malformed_scope_fails_closed_without_crashing(tmp_path, text):
    p = tmp_path / "scope.yml"
    p.write_text(text)
    s = Scope(p)
    assert s.error
    assert not s.networks
    with pytest.raises(TargetError):
        s.check("127.0.0.1")


def test_listed_host_name_still_needs_every_address_in_an_owned_network(tmp_path):
    p = tmp_path / "scope.yml"
    p.write_text("networks: [10.0.0.0/8]\nhosts: [localhost]\n")
    with pytest.raises(TargetError, match="not inside the scope"):
        Scope(p).check("localhost")       # resolves to 127.0.0.1, outside 10.0.0.0/8
    p.write_text("networks: [127.0.0.0/8, '::1/128']\nhosts: []\n")
    with pytest.raises(TargetError, match="not listed under hosts"):
        Scope(p).check("localhost")       # name itself not listed
    p.write_text("networks: [127.0.0.0/8]\nhosts: [localhost]\n")
    if any(":" in str(ip) for ip in Scope(p).resolve("localhost")):
        # localhost also resolves to ::1 here; one address outside scope must refuse the whole name
        with pytest.raises(TargetError, match="::1 is not inside"):
            Scope(p).check("localhost")
    p.write_text("networks: [127.0.0.0/8, '::1/128']\nhosts: [localhost]\n")
    assert Scope(p).check("localhost")


def _make_incident(mod, ip="198.51.100.20"):
    q = "id=1' OR '1'='1"
    raw = f'{ip} - - [26/Nov/2026:08:00:00 +0000] "GET /item?{q} HTTP/1.1" 200 10 "-" "test-only"'
    ev = {"ts": time.time(), "source_ip": ip, "kind": "http", "method": "GET", "path": "/item",
          "query": q, "body": "", "status": 200, "user_agent": "test-only", "raw": raw}
    mod.engine.process(ev)
    inc = next(i for i in mod.engine.store.list_incidents() if i["source_ip"] == ip)
    action = next(a for a in mod.engine.store.list_actions(inc["id"]) if a["action"] == "block_ip")
    return inc, action


def test_resolved_alert_cannot_be_blocked_from_a_stale_page(api_module):
    inc, action = _make_incident(api_module)
    assert inc["status"] == "awaiting_approval" and action["status"] == "proposed"
    c = signin(api_module, "analyst1")
    assert c.post(f"/api/incidents/{inc['id']}/resolve").status_code == 200
    assert c.post(f"/api/actions/{action['id']}/approve").status_code == 400
    assert not api_module.engine.store.blocklist()
    assert api_module.engine.store.get_action(action["id"])["status"] == "cancelled"
    assert api_module.engine.store.get_incident(inc["id"])["status"] == "resolved"


def test_tampered_proposed_action_is_not_applied_and_report_is_refused(api_module):
    inc, action = _make_incident(api_module, "198.51.100.21")
    store = api_module.engine.store
    store.conn.execute("UPDATE actions SET target='198.51.100.99' WHERE id=?", (action["id"],))
    store.conn.commit()
    c = signin(api_module, "analyst1")
    assert c.post(f"/api/actions/{action['id']}/approve").status_code == 400
    assert not store.blocklist()
    r = c.post(f"/api/incidents/{inc['id']}/report")
    assert r.status_code == 400 and "signature" in r.json()["detail"]


def test_untampered_incident_report_is_created_with_evidence_check(api_module):
    inc, _ = _make_incident(api_module, "198.51.100.22")
    c = signin(api_module, "analyst1")
    r = c.post(f"/api/incidents/{inc['id']}/report")
    assert r.status_code == 200
    assert c.get(r.json()["url"]).content.startswith(b"%PDF")
    assert api_module.engine.store.get_incident(inc["id"])["validation"] == "evidence_checked"
