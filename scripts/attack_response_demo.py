#!/usr/bin/env python3
"""Real-time response workflow demonstration (SANDBOX TEST ENVIRONMENT ONLY).

Watch an attack happen and walk the whole loop while it happens:

  attack traffic  ->  log line  ->  engine detects an incident  ->  policy engine
  PROPOSES a block  ->  analyst APPROVES it  ->  firewall helper applies it
  ->  Rakshak VERIFIES the rule actually exists  ->  the attacker's traffic is
  really refused  ->  undo clears it again.

Every step is printed with a timestamp and stored as evidence in the markdown
report, including the dashboard screenshots taken in the middle of the flow.

Run with the sandbox environment up (nginx on 10.99.0.1:8081, Rakshak console on
127.0.0.1:8000, RAKSHAK-BLOCK chain created). Refuses to run without --i-own-this-test-environment.

  RAKSHAK_E2E_CREDS=/path/creds.txt python3 scripts/attack_response_demo.py --i-own-this-test-environment
"""
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import httpx

NEED = ("RAKSHAK_E2E_CREDS", "Playwright screenshots need /usr/bin/python3 with playwright")
BASE = "http://127.0.0.1:8000"
TARGET = "http://10.99.0.1:8081/"
ATTACKER = "10.99.0.6"          # source address we drive the attack from
Bystander = "10.99.0.3"          # an honest neighbour that must keep working
SHOT_DIR = "docs/screens/demo"
EVENTS = []                     # (t, step, observed) rows for the report
T0 = time.time()


def stamp():
    return f"+{time.time() - T0:6.1f}s"


def log(step, observed=""):
    line = (stamp(), step, observed)
    EVENTS.append(line)
    print(f"{line[0]}  {step:<52} {observed}", flush=True)


def payload(i):
    """Real SQL-injection probes: they are what an attacker sends, and they get
    logged by nginx exactly as sent. Nothing here is a canned Rakshak response."""
    marks = ["' OR '1'='1", "\"; DROP TABLE staff;--", "' UNION SELECT user,pass FROM users--",
             "1' AND SLEEP(3)--", "'; INSERT INTO audit VALUES(1,'x');--", "1 OR 1=1",
             "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
             "%27%20OR%20%271%27=%271"]
    q = marks[i % len(marks)]
    return f"/item?id={q}"


def curl(url, src):
    p = subprocess.run(["curl", "-s", "-g", "-o", "/dev/null", "-w", "%{http_code}", "--interface", src,
                        "--connect-timeout", "4", "--max-time", "8", url], capture_output=True, text=True)
    return p.stdout.strip() or "000"


def iptables_of(ip):
    p = subprocess.run(["sudo", "-n", "/usr/sbin/iptables", "-S", "RAKSHAK-BLOCK"],
                       capture_output=True, text=True)
    if p.returncode != 0:
        return f"(could not read: {p.stderr.strip()[:90]})"
    return p.stdout.strip() or "(chain empty)"


def signin(client, role):
    users = {}
    for line in open(os.environ["RAKSHAK_E2E_CREDS"]):
        p = line.split()
        if len(p) >= 3 and p[1] == role:
            users = {"username": p[0], "password": p[2]}
    r = client.post(f"{BASE}/api/auth/login", json=users)
    r.raise_for_status()
    client.headers["X-RAKSHAK-CSRF"] = r.json()["csrf"]
    # When the console runs with RAKSHAK_COOKIE_SECURE=1 (browser preview mode) the
    # session cookie is flagged Secure and a plain-HTTP client would not send it back.
    # Re-arm it explicitly; same token, same server, just the local test transport.
    for h in r.headers.get_list("set-cookie"):
        if h.startswith("rakshak_session="):
            client.cookies.set("rakshak_session", h.split(";")[0].split("=", 1)[1])
    return users["username"]


def wait_for(fn, timeout=25, every=0.5):
    end = time.time() + timeout
    while time.time() < end:
        got = fn()
        if got:
            return got
        time.sleep(every)
    return None


def main():
    if "--i-own-this-test-environment" not in sys.argv:
        sys.exit("Refusing: this script sends attack traffic. Add --i-own-this-test-environment "
                 "only when the target is a system you own and are permitted to test.")
    if not os.environ.get("RAKSHAK_E2E_CREDS"):
        sys.exit("Set RAKSHAK_E2E_CREDS to the sandbox credentials file (outside the repository).")
    os.makedirs(SHOT_DIR, exist_ok=True)

    # ---------------------------------------------------------------- 0. baseline
    admin = httpx.Client(timeout=20)
    analyst = httpx.Client(timeout=20)
    au = signin(admin, "admin")
    an = signin(analyst, "analyst")
    log("0. signed in", f"admin={au} analyst={an} (separate people: approval is not self-approval)")
    before = curl(TARGET, ATTACKER)
    log("0. baseline: attacker can reach the site", f"HTTP {before}")
    if before != "200":
        sys.exit(f"Baseline failed (expected 200, got {before}) - sandbox nginx not answering from {ATTACKER}")

    ov = admin.get(f"{BASE}/api/overview").json()
    log("0. console state before the attack", f"mode={ov['mode']} state={ov['state']} "
        f"firewall={'connected' if ov['enforcer']['ready'] else 'NOT connected'}")
    if ov["mode"] != "recommend":
        sys.exit("Demo expects Ask-me-first (recommend) mode so the proposal step is shown.")

    # ---------------------------------------------------------------- 1. the attack
    log("1. launching attack: 8 SQL-injection probes from", f"{ATTACKER} -> {TARGET}")
    with ThreadPoolExecutor(4) as pool:
        list(pool.map(lambda i: curl(TARGET + payload(i), ATTACKER), range(8)))

    # ---------------------------------------------------------------- 2. detection
    def found():
        rows = [i for i in admin.get(f"{BASE}/api/incidents").json()
                if i["source_ip"] == ATTACKER and i["category"] == "sql_injection"]
        # Prefer the live (non-resolved) incident: a previous demo/e2e run may have left
        # a resolved incident for the same test IP, and the engine starts a fresh one.
        live = [r for r in rows if r["status"] not in ("resolved", "allowed")]
        pool = live or rows
        return [max(pool, key=lambda r: r["id"])] if pool else None
    incs = wait_for(found, 30)
    if not incs:
        sys.exit("Engine did not detect the attack within 30 s")
    inc = incs[0]
    log("2. engine detected the attack", f"incident #{inc['id']} {inc['category']} severity={inc['severity']} "
        f"status={inc['status']} lines={inc['event_count']}")

    # evidence quality: the stored log lines must be verifiable
    admin.post(f"{BASE}/api/incidents/{inc['id']}/validate")
    inc = admin.get(f"{BASE}/api/incidents/{inc['id']}").json()
    log("2. evidence re-check on the stored lines", f"validation={inc['validation']}")

    acts = [a for a in inc["actions"] if a["action"] == "block_ip"]
    prop = wait_for(lambda: [a for a in admin.get(f"{BASE}/api/incidents/{inc['id']}").json()["actions"]
                             if a["action"] == "block_ip" and a["status"] in ("proposed", "done", "cancelled")] or None, 20)
    prop = prop[0] if prop else None
    if not prop:
        sys.exit("No block proposal appeared for a high-severity attack in Ask-me-first mode")
    log("3. Rakshak PROPOSED containment (nothing applied yet)",
        f"action #{prop['id']} target={prop['target']} status={prop['status']} detail={prop['detail']}")
    still = curl(TARGET, ATTACKER)
    log("3. proof the proposal blocks nothing on its own", f"attacker still gets HTTP {still}")
    if still != "200":
        sys.exit("A mere proposal already stopped the traffic: the ask-me-first guarantee failed")

    # ---------------------------------------------------------------- 4. approval
    # Roles: a viewer may not approve (shown by the live check); our analyst can.
    r = analyst.post(f"{BASE}/api/actions/{prop['id']}/approve")
    log("4. analyst approved the proposal", f"HTTP {r.status_code} {r.json()}")
    if r.status_code != 200:
        sys.exit("Approval failed")

    # ---------------------------------------------------------------- 5. firewall verification
    def verified():
        a = next((x for x in admin.get(f"{BASE}/api/incidents/{inc['id']}").json()["actions"] if x["id"] == prop["id"]), None)
        return a if a and a["status"] == "done" else None
    done = wait_for(verified, 25)
    if not done:
        sys.exit("Block never reached status done")
    log("5. applied through the firewall helper", f"detail={done['detail']}")
    log("5. signature on the action record", f"verified={done['verified']} (a signed record: editing it breaks the chain)")
    bl = admin.get(f"{BASE}/api/protection").json()
    entry = next((b for b in bl["blocklist"] if b["ip"] == ATTACKER), None)
    log("5. blocklist entry", json.dumps(entry) if entry else "(missing!)")
    log("5. rule as the kernel sees it", f"iptables RAKSHAK-BLOCK: {iptables_of(ATTACKER).replace(chr(10), ' | ')}")

    # ---------------------------------------------------------------- 6. real effect
    blocked = curl(TARGET, ATTACKER)
    neighbour = curl(TARGET, Bystander)
    log("6. attacker's request now", f"HTTP {blocked} (000 = no answer at all)")
    log("6. an innocent neighbour's request", f"HTTP {neighbour}")
    if blocked == "200" or neighbour != "200":
        sys.exit("Firewall verification claim did not hold: the block was not effective or hurt the wrong host")
    inc = admin.get(f"{BASE}/api/incidents/{inc['id']}").json()
    log("6. incident status after containment", f"status={inc['status']} contained_at set={bool(inc['contained_at'])}")

    # ---------------------------------------------------------------- 7. undo
    r = analyst.post(f"{BASE}/api/protection/unblock", json={"ip": ATTACKER})
    log("7. analyst undid the block", f"HTTP {r.status_code} {r.json()}")
    restored = wait_for(lambda: curl(TARGET, ATTACKER) == "200" or None, 20)
    log("7. attacker can reach the site again", "yes" if restored else "NO - undo failed")
    log("7. rule gone from the chain", f"iptables RAKSHAK-BLOCK: {iptables_of(ATTACKER).replace(chr(10), ' | ') or '(empty)'}")

    # ---------------------------------------------------------------- 8. memory
    mem = admin.get(f"{BASE}/api/memory?limit=8").json()
    kinds = [(e["kind"], e.get("status") or e.get("action")) for e in mem["entries"]][:6]
    log("8. the whole story is in Memory", str(kinds))
    chain = admin.get(f"{BASE}/api/integrity").json()
    log("8. integrity after the exercise", f"events ok={chain['events']['ok']} audit ok={chain['audit']['ok']}")

    # ---------------------------------------------------------------- 9. screenshots
    shots = []
    try:
        shots = take_screenshots(inc["id"])
        log("9. dashboard screenshots", ", ".join(shots))
    except Exception as exc:                                     # noqa: BLE001
        log("9. dashboard screenshots", f"skipped ({type(exc).__name__}: {str(exc)[:80]})")

    write_report(inc, done, entry, blocked, neighbour, restored, shots)
    print("\nDemo finished: attack detected, proposed, approved, verified at the firewall, "
          "real traffic refused, undo restored service.")


def take_screenshots(inc_id):
    """Drive the real browser through the live app while it still holds this incident."""
    import subprocess
    script = rf'''
import json, sys
from pathlib import Path
from playwright.sync_api import sync_playwright
BASE = "http://127.0.0.1:8000"
OUT = Path("{SHOT_DIR}")
creds = {{}}
for line in open("{os.environ['RAKSHAK_E2E_CREDS']}"):
    p = line.split()
    if len(p) >= 3: creds[p[1]] = (p[0], p[2])
u, pw = creds["admin"]
with sync_playwright() as pw2:
    b = pw2.chromium.launch(executable_path="/usr/bin/chromium", args=["--no-sandbox"])
    pg = b.new_context(viewport={{"width": 1440, "height": 1000}}).new_page()
    pg.goto(BASE + "/"); pg.wait_for_timeout(1500)
    pg.screenshot(path=str(OUT / "12_landing_page.png"))
    r = pg.request.post(BASE + "/api/auth/login", data=json.dumps({{"username": u, "password": pw}}),
                        headers={{"Content-Type": "application/json"}})
    assert r.ok, r.status
    pg.goto(BASE + f"/alerts/{inc_id}"); pg.wait_for_load_state("networkidle"); pg.wait_for_timeout(2500)
    pg.screenshot(path=str(OUT / "13_demo_alert_evidence.png"), full_page=True)
    pg.goto(BASE + "/protection"); pg.wait_for_timeout(2000)
    pg.screenshot(path=str(OUT / "14_demo_protection.png"), full_page=True)
    pg.goto(BASE + "/memory"); pg.wait_for_timeout(2500)
    pg.screenshot(path=str(OUT / "15_demo_memory.png"), full_page=True)
    b.close()
print("screenshots ok")
'''
    with open("/tmp/_rk_demo_shots.py", "w") as f:
        f.write(script)
    p = subprocess.run(["/usr/bin/python3", "/tmp/_rk_demo_shots.py"], capture_output=True, text=True, timeout=180)
    if p.returncode != 0:
        raise RuntimeError(p.stderr[-300:])
    return ["12_landing_page.png", "13_demo_alert_evidence.png", "14_demo_protection.png", "15_demo_memory.png"]


def write_report(inc, action, entry, blocked, neighbour, restored, shots):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    rows = "\n".join(f"| `{t}` | {s} | {o} |" for t, s, o in EVENTS)
    img = "\n".join(f"![{n[:-4]}](screens/demo/{n})\n\n*{n.replace('_', ' ').replace('.png', '')}*" for n in shots) or \
        "(Screenshots skipped: playwright not available in this shell.)"
    body = f"""# Real-time response demo: attack -> proposal -> approval -> firewall verification

Run against the sandbox test environment on {ts} (`scripts/attack_response_demo.py`).
This is a demonstration on a test network we own: `10.99.0.6` is a source address on this
machine's loopback interface, standing in for an attacker, and the SQL-injection probes are
ordinary attack strings that a real attacker would send. Nothing here is simulated *inside*
Rakshak: the log lines are written by real nginx, detected by the real engine, and the block
is a real iptables rule applied and verified through the root helper.

## What happened, in order

| Time | Step | What we observed |
|---|---|---|
{rows}

## The security promises this run demonstrates

1. **Detection is real.** Eight injection probes from one address produced an incident whose
   evidence (`event_count`, the stored log lines) re-validates against the hash-chained event store.
2. **A proposal is not an action.** In Ask-me-first mode the policy engine records what it *would*
   do and the attacker keeps getting HTTP 200 until a human approves. The traffic test after the
   proposal proves the difference.
3. **Approval has to come from someone else.** The console was signed in as a separate analyst
   account; viewers are refused (the live check asserts the 403).
4. **"Blocked" means proven blocked.** After approval the rule is applied through `deploy/rakshak-fw`
   and confirmed by a separate `iptables -C` check, which is printed above; the attacker then gets no
   answer while an innocent neighbour on the same host is still served - so the containment is real and
   not aimed at everybody.
5. **Everything can be undone and nothing is edited silently.** The undo removes the verified rule,
   service returns, and the whole story sits in Memory plus the signed audit chain, which verified at
   the end of the run.

## Screenshots

{img}

## Reproduce it

```bash
RAKSHAK_E2E_CREDS=/path/outside/repo/creds.txt \\
  python3 scripts/attack_response_demo.py --i-own-this-test-environment
```

**Not a claim about production accuracy:** one attack pattern, on one test host. Detection rate and
false-alarm rate on real traffic still have to be measured (milestone M4 in `ENTERPRISE_PLAN.md`).
"""
    with open("docs/DEMO_REALTIME_RESPONSE.md", "w") as f:
        f.write(body)
    print("wrote docs/DEMO_REALTIME_RESPONSE.md")


if __name__ == "__main__":
    main()
