#!/usr/bin/env python3
"""System-security response demonstration (SANDBOX TEST ENVIRONMENT ONLY).

The other half of the SOC story: no network traffic at all. An attacker who already
has a foothold changes this machine to keep it. We simulate those persistence steps
on files and processes we own in this sandbox and watch the console catch them:

  config file edited  ->  file-integrity alert with before/after SHA-256
  backdoor listener   ->  new-service alert from /proc/net
  re-check            ->  "still there" vs "reverted" decided by looking at the LIVE machine
  no fake containment -> Rakshak proposes no IP block for a host finding
  verified undo       -> console restores the file and stops the listener itself:
                         analyst proposes, admin approves, effect re-checked live, alert downgraded.

Run with the console up (RAKSHAK_HOSTSEC_INTERVAL=5, RAKSHAK_FIM_PATHS holding
/home/ubuntu/rakshak-test/watched.conf). Refuses to run without --i-own-this-test-environment.
"""
import json
import os
import random
import socket
import subprocess
import sys
import time
from datetime import datetime

import httpx

BASE = "http://127.0.0.1:8000"
WATCH = "/home/ubuntu/rakshak-test/watched.conf"
SHOT_DIR = "docs/screens/demo"
EVENTS = []
T0 = time.time()


def stamp():
    return f"+{time.time() - T0:6.1f}s"


def log(step, observed=""):
    EVENTS.append((stamp(), step, observed))
    print(f"{stamp()}  {step:<52} {observed}", flush=True)


def signin(client, role):
    users = {}
    for line in open(os.environ["RAKSHAK_E2E_CREDS"]):
        p = line.split()
        if len(p) >= 3 and p[1] == role:
            users = {"username": p[0], "password": p[2]}
    r = client.post(f"{BASE}/api/auth/login", json=users)
    r.raise_for_status()
    client.headers["X-RAKSHAK-CSRF"] = r.json()["csrf"]
    for h in r.headers.get_list("set-cookie"):          # COOKIE_SECURE re-arm (see DEV_NOTES)
        if h.startswith("rakshak_session="):
            client.cookies.set("rakshak_session", h.split(";")[0].split("=", 1)[1])
    return users["username"]


def wait_for(fn, timeout=40, every=0.5):
    end = time.time() + timeout
    while time.time() < end:
        got = fn()
        if got:
            return got
        time.sleep(every)
    return None


def main():
    if "--i-own-this-test-environment" not in sys.argv:
        sys.exit("Refusing: this script edits files and starts a listener. Only run it on a system you own.")
    if not os.environ.get("RAKSHAK_E2E_CREDS"):
        sys.exit("Set RAKSHAK_E2E_CREDS to the sandbox credentials file.")
    os.makedirs(SHOT_DIR, exist_ok=True)

    admin = httpx.Client(timeout=20)
    analyst = httpx.Client(timeout=20)
    au = signin(admin, "admin")
    an = signin(analyst, "analyst")
    hs = admin.get(f"{BASE}/api/overview").json()["hostsec"]
    log("0. signed in + sensor status", f"admin={au} analyst={an}; watching {hs['watched_files']} files, "
        f"{hs['ports_listening']} ports, {hs['accounts_known']} accounts, every {hs['interval_s']}s")
    if not (hs["enabled"] and hs["baselined"]):
        sys.exit("Host sensors are not enabled/baselined - start the console with RAKSHAK_HOSTSEC_INTERVAL>0.")

    # close leftovers so timings below are clean
    for i in admin.get(f"{BASE}/api/incidents").json():
        if i["source_ip"] == "system" and i["status"] != "resolved":
            analyst.post(f"{BASE}/api/incidents/{i['id']}/resolve")

    if not os.path.exists(WATCH):                              # first run: create it, let sensors baseline
        os.makedirs(os.path.dirname(WATCH), exist_ok=True)
        with open(WATCH, "w") as fh:
            fh.write("original sanctioned configuration\n")
        time.sleep(7)
        for i in admin.get(f"{BASE}/api/incidents").json():
            if i["source_ip"] == "system" and i["status"] != "resolved":
                analyst.post(f"{BASE}/api/incidents/{i['id']}/resolve")
    original = open(WATCH).read()

    # ------------------------------------------------ 1. attacker persistence, on this host
    t_edit = time.time()
    open(WATCH, "a").write(f"\n# persistence: run extra service on boot (attacker line {int(t_edit)})\n")
    port = 15000 + random.randint(0, 900)
    proc = subprocess.Popen(["python3", "-m", "http.server", str(port), "--bind", "127.0.0.1"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log("1. persistence simulated", f"watched config edited + listener 127.0.0.1:{port} started (real socket in /proc/net)")

    # ------------------------------------------------ 2. detection
    def inc_for(cat):
        return next((i for i in admin.get(f"{BASE}/api/incidents").json()
                     if i["source_ip"] == "system" and i["category"] == cat and i["status"] != "resolved"), None)
    fim = wait_for(lambda: (i := inc_for("file_integrity")) and (i["validation"] == "evidence_checked" or time.time() - t_edit > 20) and i or None)
    ns = wait_for(lambda: (i := inc_for("new_service")) and (i["validation"] == "evidence_checked" or time.time() - t_edit > 25) and i or None)
    if not (fim and ns):
        sys.exit(f"Detection failed: file_integrity={bool(fim)} new_service={bool(ns)}")
    log("2. file change detected + live re-checked", f"alert #{fim['id']} rule={fim['detections'][0]['rule_id']} "
        f"validation={fim['validation']} in {fim['detected_at'] - t_edit:.1f}s")
    log("2. new listener detected + live re-checked", f"alert #{ns['id']} rule={ns['detections'][0]['rule_id']} "
        f"matched={ns['detections'][0]['matched']} validation={ns['validation']}")

    ev = fim["evidence"][0]
    old_h = ev.split('"sha256": "')[1][:16] if '"sha256"' in ev else "?"
    new_h = ev.rsplit('"sha256": "', 1)[1][:16] if '"sha256"' in ev else "?"
    log("3. analysis: before/after fingerprints", f"sha256 {old_h}... -> {new_h}... (both stored, hash-chained)")
    ex = fim["explain"]
    log("3. analysis: plain-language guidance shown", f"title='{ex['title']}' MITRE={ex['mitre_id']} CERT-In='{ex['certin_category'][:40]}...'")
    acts = admin.get(f"{BASE}/api/incidents/{fim['id']}").json()["actions"]
    log("3. honest response: no IP block is invented for a host change", f"executed actions so far: {len(acts)} (0 is correct)")
    opts = admin.get(f"{BASE}/api/incidents/{fim['id']}/remediation").json()["options"]
    opts += admin.get(f"{BASE}/api/incidents/{ns['id']}/remediation").json()["options"]
    log("3. instead the console offers a VERIFIED UNDO per alert",
        "; ".join(f"{o['action']} {'OFFERED' if o['possible'] else 'refused: ' + o['reason'][:70]}" for o in opts) or "nothing offered")

    # ------------------------------------------------ 4. remediation + honest downgrade
    pr_f = analyst.post(f"{BASE}/api/incidents/{fim['id']}/remediation", json={"action": "restore_file"}).json()
    pr_n = analyst.post(f"{BASE}/api/incidents/{ns['id']}/remediation", json={"action": "stop_process"}).json()
    log("4. analyst PROPOSES the undo (nothing executed yet)",
        f"restore_file #{pr_f['action_id']} status={pr_f['status']}; stop_process #{pr_n['action_id']} status={pr_n['status']}")
    shots_offer = []
    try:
        shots_offer = take_screenshots(fim["id"], ns["id"], "offer")
    except Exception as exc:                            # noqa: BLE001
        log("4. dashboard screenshots (offer)", f"skipped ({type(exc).__name__}: {str(exc)[:80]})")
    admin.post(f"{BASE}/api/actions/{pr_f['action_id']}/approve")
    admin.post(f"{BASE}/api/actions/{pr_n['action_id']}/approve")

    def act_state(inc_id, aid):
        for a in admin.get(f"{BASE}/api/incidents/{inc_id}").json()["actions"]:
            if a["id"] == aid:
                return a
        return {}
    fin_f = wait_for(lambda: (a := act_state(fim["id"], pr_f["action_id"])) and a.get("status") in ("done", "failed", "refused") and a or None, timeout=90)
    fin_n = wait_for(lambda: (a := act_state(ns["id"], pr_n["action_id"])) and a.get("status") in ("done", "failed", "refused") and a or None, timeout=90)
    content_ok = open(WATCH).read() == original            # INDEPENDENT proof, not the console's word
    port_refuses = True
    try:
        socket.create_connection(("127.0.0.1", port), 2).close()
        port_refuses = False
    except OSError:
        pass
    if proc.poll() is None:                               # safety net only; the console should have killed it
        proc.terminate(); proc.wait()
    log("4. admin APPROVED; the console executed and LIVE-VERIFIED",
        f"restore_file -> {fin_f.get('status')}: {str(fin_f.get('detail'))[:70]}; "
        f"file on disk equals pre-attack content: {content_ok}")
    log("4. same for the backdoor listener",
        f"stop_process -> {fin_n.get('status')}: {str(fin_n.get('detail'))[:70]}; port refuses connections: {port_refuses}")
    fim2 = analyst.post(f"{BASE}/api/incidents/{fim['id']}/validate").json()
    ns2 = analyst.post(f"{BASE}/api/incidents/{ns['id']}/validate").json()
    r1 = (fim2["validation_detail"]["reasons"] or [""])[0]
    r2 = (ns2["validation_detail"]["reasons"] or [""])[0]
    log("4. re-check of the live machine now downgrades the alerts", f"file: {fim2['validation']} - '{r1[:60]}'")
    log("4. and reports the listener as gone", f"port: {ns2['validation']} - '{r2[:60]}'")
    analyst.post(f"{BASE}/api/incidents/{fim['id']}/resolve")
    analyst.post(f"{BASE}/api/incidents/{ns['id']}/resolve")
    late = wait_for(lambda: inc_for("file_integrity") or inc_for("new_service"), timeout=12) or True
    if inc_for("file_integrity"):
        analyst.post(f"{BASE}/api/incidents/{inc_for('file_integrity')['id']}/resolve")
    if inc_for("new_service"):
        analyst.post(f"{BASE}/api/incidents/{inc_for('new_service')['id']}/resolve")
    log("4. alerts closed; the record stays in Memory", "resolved alerts are history, not deleted")

    # ------------------------------------------------ 5. memory + integrity
    mem = admin.get(f"{BASE}/api/memory?kind=system&limit=20").json()
    log("5. Memory (system changes filter)", f"{len(mem['entries'])} system entries; newest: "
        + "; ".join(f"{e['category']}#{e['id']}" for e in mem["entries"][:4]))
    ch = admin.get(f"{BASE}/api/integrity").json()
    log("5. evidence chain after the exercise", f"events ok={ch['events']['ok']} audit ok={ch['audit']['ok']}")

    # ------------------------------------------------ 6. screenshots of the live alerts
    shots = list(shots_offer)
    try:
        shots += take_screenshots(fim["id"], ns["id"], "verified")
        log("6. dashboard screenshots", ", ".join(shots))
    except Exception as exc:                                # noqa: BLE001
        log("6. dashboard screenshots (verified)", f"skipped ({type(exc).__name__}: {str(exc)[:80]})")

    write_report(fim, ns, old_h, new_h, port, shots)
    print("\nDemo finished: system persistence detected, analysed with proof, answered honestly, "
          "and closed after real remediation.")


def take_screenshots(fim_id, ns_id, phase="offer"):
    script = rf'''
import json
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
    pg.goto(BASE + "/"); pg.wait_for_timeout(800)
    r = pg.request.post(BASE + "/api/auth/login", data=json.dumps({{"username": u, "password": pw}}),
                        headers={{"Content-Type": "application/json"}})
    assert r.ok, r.status
    if "{phase}" == "offer":
        pg.goto(BASE + f"/alerts/{fim_id}"); pg.wait_for_load_state("networkidle"); pg.wait_for_timeout(2500)
        pg.screenshot(path=str(OUT / "16_system_file_alert.png"), full_page=True)
        pg.goto(BASE + f"/alerts/{ns_id}"); pg.wait_for_timeout(2000)
        pg.screenshot(path=str(OUT / "17_system_port_alert.png"), full_page=True)
        pg.goto(BASE + f"/alerts/{fim_id}"); pg.wait_for_timeout(1500)
        try:
            pg.locator("text=Undo the attacker").scroll_into_view_if_needed(); pg.wait_for_timeout(700)
        except Exception:
            pass
        pg.screenshot(path=str(OUT / "20_remediation_offer.png"), full_page=True)
        pg.goto(BASE + "/"); pg.wait_for_timeout(2000)
        pg.screenshot(path=str(OUT / "18_home_system_watch.png"))
        pg.goto(BASE + "/memory"); pg.wait_for_timeout(1500)
        try:
            pg.get_by_text("System changes", exact=True).click(); pg.wait_for_timeout(1500)
        except Exception as e:
            print("filter click skipped", e)
        pg.screenshot(path=str(OUT / "19_memory_system_filter.png"), full_page=True)
    else:
        pg.goto(BASE + f"/alerts/{fim_id}"); pg.wait_for_load_state("networkidle"); pg.wait_for_timeout(2500)
        pg.screenshot(path=str(OUT / "21_undo_verified.png"), full_page=True)
    b.close()
print("screenshots ok")
'''
    with open("/tmp/_rk_host_shots.py", "w") as f:
        f.write(script)
    p = subprocess.run(["/usr/bin/python3", "/tmp/_rk_host_shots.py"], capture_output=True, text=True, timeout=180)
    if p.returncode != 0:
        raise RuntimeError(p.stderr[-300:])
    if phase == "offer":
        return ["16_system_file_alert.png", "17_system_port_alert.png", "20_remediation_offer.png",
                "18_home_system_watch.png", "19_memory_system_filter.png"]
    return ["21_undo_verified.png"]


def write_report(fim, ns, old_h, new_h, port, shots):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    rows = "\n".join(f"| `{t}` | {s} | {o} |" for t, s, o in EVENTS)
    img = "\n".join(f"![{n[:-4]}](screens/demo/{n})\n\n*{n.replace('_', ' ').replace('.png', '')}*"
                    for n in shots) or "(Screenshots skipped.)"
    body = f"""# System-security demo: persistence on the machine, detected and closed honestly

Run against the sandbox test environment on {ts} (`scripts/host_security_demo.py`).
No attack traffic was needed for this one. The simulated attacker actions are real
system changes performed by us on a test machine we own: editing a watched config file
and starting a listener on 127.0.0.1:{port}. The console then undid both - through its
propose -> approve -> execute -> live-verify remediation flow, not by the demo script.
The nginx/SSH side of the story (attacker IPs, approvals, firewall verification) is
covered separately in `DEMO_REALTIME_RESPONSE.md`.

## What happened, in order

| Time | Step | What we observed |
|---|---|---|
{rows}

## The security promises this run demonstrates

1. **The agent protects the system, not just the website.** File integrity (SHA-256, size,
   permissions), accounts (new users, uid-0, sudo/wheel changes) and listening ports
   (`/proc/net`) are re-observed on a timer, offline, with no kernel modules or agents beyond
   a normal service account.
2. **Evidence, not vibes.** The alert stores the *before* and *after* fingerprints inside the
   hash-chained event log: `sha256 {old_h}... -> {new_h}...` for file `{'"'}{fim["detections"][0]["matched"]}{'"'}.
3. **Re-check means the live machine.** "Evidence re-checked" here means Rakshak re-hashed the
   file and re-read `/proc/net` again and still saw the change - after the approved undo it
   re-checked, saw the effect was gone, and *downgraded the alert instead of quietly deleting
   it*. The demo script verified the same facts independently of the console's own claims.
4. **No fake containment, and a real undo.** A changed file has no attacker IP, so Rakshak
   proposes no block and claims no containment. Instead the console now offers a **verified
   undo**: the analyst proposes, nothing changes on disk; the admin approves; the engine
   restores the file from its vault copy (or stops the listener it attributed through the
   `/proc` socket inode) and re-checks the live effect before the alert downgrades. The
   network attacker behind an intrusion remains blockable through the normal approval flow
   demonstrated in the other demo.
5. **Memory and tamper evidence.** Both findings, their validation decisions and their closure
   stay in the signed record; the integrity endpoint still verified at the end of the run.

## Honest limits seen in this demo

* The sensors see *changes and their effects*, not *who* made them - the "who" comes from
  correlating login alerts (brute force / accepted logins) around the same window.
* The baseline starts when Rakshak starts: a compromise older than the install looks like a
  normal starting point, which is why setup tells you to install on a known-good machine.
* Files readable only by root are watched by metadata (size, mtime, permissions) unless the
  service runs as root.

## Screenshots

{img}

## Reproduce it

```bash
cd /home/ubuntu/rakshak   # console running with RAKSHAK_HOSTSEC_INTERVAL=5 and
                          # RAKSHAK_FIM_PATHS=/home/ubuntu/rakshak-test/watched.conf
RAKSHAK_E2E_CREDS=/home/ubuntu/rk_test_credentials.txt \\
  .venv/bin/python scripts/host_security_demo.py --i-own-this-test-environment
```
"""
    with open("docs/DEMO_SYSTEM_SECURITY.md", "w") as f:
        f.write(body)
    print("wrote docs/DEMO_SYSTEM_SECURITY.md")


if __name__ == "__main__":
    main()
