#!/usr/bin/env python3
"""RAKSHAK-AI live end-to-end functional check.

Runs against a REAL, running Rakshak console and REAL software (nginx, OpenSSH, Nmap,
iptables) in an isolated test environment that you own. It generates attack-like traffic
(SQL injection strings, failed SSH logins) from test source addresses, approves blocks,
tampers with records and then restores them. Never point it at production.

This is a FUNCTIONAL test (does each feature behave as specified end to end?).
It is NOT an accuracy measurement: it says nothing about detection rates on real traffic.

Expected test environment (see docs/E2E_LIVE_RESULTS.md for the one used):
  10.99.0.1  server: nginx :8081 plain, :8082 leaky fixture (/.env), :8083 catch-all; sshd :2222
  10.99.0.2  SQL-injection source         10.99.0.3  normal visitor
  10.99.0.4  never_scan in scope.yml      10.99.0.5  SSH brute-force source
  scope.yml networks [10.99.0.0/29], never_scan [10.99.0.4]; RAKSHAK_TRUSTED=10.99.0.1
  RAKSHAK_ENFORCER=iptables with chain RAKSHAK-BLOCK; RAKSHAK_MODE=recommend
  RAKSHAK_PLUGINS_DIR=examples/plugins and RAKSHAK_ALLOW_EXTERNAL_PLUGINS=1 (section 11)

Usage:
  RAKSHAK_E2E_CREDS=/path/outside/repo/creds.txt \\
    .venv/bin/python scripts/e2e_live_check.py --i-own-this-test-environment
  creds file lines: "<username> <role> <password>" for an admin, an analyst and a viewer.
"""
import argparse
import re
import hashlib
import hmac
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("RAKSHAK_E2E_URL", "http://127.0.0.1:8000")
DB = Path(os.environ.get("RAKSHAK_DATA", ROOT / "data")) / "rakshak.db"
SERVER, SQLI_SRC, NORMAL_SRC, NEVER_IP, BRUTE_SRC = "10.99.0.1", "10.99.0.2", "10.99.0.3", "10.99.0.4", "10.99.0.5"
WEB_PLAIN, WEB_LEAKY, WEB_CATCHALL = (f"http://{SERVER}:{p}/" for p in (8081, 8082, 8083))
SSH_PORT = 2222
WRAPPER = ROOT / "rakshak/plugins/builtin/website-check/wrapper.py"
EXAMPLE_WRAPPER = ROOT / "examples/plugins/tcp-connect-check/wrapper.py"
OUT = ROOT / "docs/E2E_LIVE_RESULTS.md"

results = []          # (section, name, ok, observed)
T0 = time.time()


def check(section, name, ok, observed=""):
    results.append((section, name, bool(ok), " ".join(str(observed).split())[:420]))
    print(("PASS " if ok else "FAIL ") + f"[{section}] {name} | {observed}"[:300], flush=True)
    return bool(ok)


def wait_for(fn, timeout=20.0, every=0.5):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(every)
    return fn()


def load_creds(path):
    users = {}
    for line in Path(path).read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3:
            users[parts[1]] = (parts[0], parts[2])     # role -> (username, password)
    for role in ("admin", "analyst", "viewer"):
        if role not in users:
            sys.exit(f"creds file needs an account with role {role}")
    return users


def session(username, password):
    c = httpx.Client(base_url=BASE, timeout=240)
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    r.raise_for_status()
    c.headers["X-RAKSHAK-CSRF"] = r.json()["csrf"]
    # With RAKSHAK_COOKIE_SECURE=1 (browser preview mode) the cookie is flagged Secure and a
    # plain-HTTP httpx client would drop it. Re-arm the same token explicitly. Browsers on
    # http://127.0.0.1 treat it as trustworthy, so the console behaviour being tested is unchanged.
    for h in r.headers.get_list("set-cookie"):
        if h.startswith("rakshak_session="):
            c.cookies.set("rakshak_session", h.split(";")[0].split("=", 1)[1])
    c.user = username
    return c


# ---------- real traffic helpers ----------
def http_from(src, url, timeout=4):
    p = subprocess.run(["curl", "-s", "-g", "-o", "/dev/null", "-w", "%{http_code}", "--interface", src,
                        "--max-time", str(timeout), "-A", "Mozilla/5.0 (X11; Linux x86_64) e2e-check", url],
                       capture_output=True, text=True)
    return p.stdout.strip() or "000"


def tcp_from(src, port, timeout=3):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.bind((src, 0))
        s.connect((SERVER, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def ssh_fail(src):
    cmd = ["sshpass", "-p", "wrong-password-e2e", "ssh", "-b", src, "-p", str(SSH_PORT),
           "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
           "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
           "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=5", f"nosuchuser@{SERVER}", "true"]
    return subprocess.run(cmd, capture_output=True, timeout=40).returncode


def fw_rules():
    p = subprocess.run(["sudo", "-n", "iptables", "-S", "RAKSHAK-BLOCK"], capture_output=True, text=True)
    return p.stdout


def db():
    return sqlite3.connect(DB, timeout=15)


def version(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return (p.stdout + p.stderr).strip().splitlines()[0]
    except Exception as exc:  # noqa: BLE001
        return f"unavailable ({exc.__class__.__name__})"


def pdf_text(client, url):
    r = client.get(url)
    if r.status_code != 200 or not r.content.startswith(b"%PDF"):
        return ""
    tmp = Path("/tmp") / f"e2e_{abs(hash(url))}.pdf"
    tmp.write_bytes(r.content)
    return subprocess.run(["pdftotext", "-layout", str(tmp), "-"], capture_output=True, text=True).stdout


def incidents_from(client, ip):
    return [i for i in client.get("/api/incidents").json()
            if i["source_ip"] == ip and (i["last_seen"] or 0) >= T0 - 5]


def run_test(requester, approver, plugin, target, reason):
    r = requester.post(f"/api/plugins/{plugin}/runs", json={"target": target, "reason": reason, "authorised": True})
    if r.status_code != 200:
        return None, r
    run = r.json()
    a = approver.post(f"/api/runs/{run['id']}/approve")
    return a.json() if a.status_code == 200 else None, a


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--i-own-this-test-environment", action="store_true", required=True)
    ap.parse_args()
    creds = load_creds(os.environ["RAKSHAK_E2E_CREDS"])
    env = {
        "date (UTC)": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "kernel": version(["uname", "-sr"]), "nginx": version(["nginx", "-v"]),
        "OpenSSH": version(["ssh", "-V"]), "Nmap": version(["nmap", "--version"]),
        "iptables": version(["sudo", "-n", "iptables", "--version"]), "Python": sys.version.split()[0],
    }

    # ---------------- 0. preconditions ----------------
    S = "0 Preconditions"
    for extra_ip in ("10.99.0.7", "10.99.0.8", "10.99.0.9"):
        subprocess.run(["sudo", "-n", "ip", "-4", "addr", "replace", f"{extra_ip}/32", "dev", "lo"],
                       capture_output=True)
    check(S, "console health endpoint answers", httpx.get(BASE + "/api/health").json().get("ok"), BASE)
    admin = session(*creds["admin"])
    analyst = session(*creds["analyst"])
    viewer = session(*creds["viewer"])
    ov = admin.get("/api/overview").json()
    srcs = {s["path"]: s["state"] for s in ov["sources"]}
    check(S, "both real log sources are readable", all(s["readable"] for s in ov["sources"]) and len(srcs) == 2, srcs)
    check(S, "enforcer is iptables and ready", ov["enforcer"]["name"] == "iptables" and ov["enforcer"]["ready"],
          ov["enforcer"]["detail"])
    check(S, "mode is recommend (no automatic blocking)", ov["mode"] == "recommend", ov["mode"])
    # Re-runnable: close what a previous run left behind (blocks and unresolved test alerts).
    for ip in (SQLI_SRC, BRUTE_SRC, NORMAL_SRC, "10.99.0.6", "10.99.0.7", "10.99.0.8", "10.99.0.9", "77.99.0.2"):
        if any(b["ip"] == ip for b in admin.get("/api/protection").json()["blocklist"]):
            admin.post("/api/protection/unblock", json={"ip": ip})
    for i in admin.get("/api/incidents").json():
        if i["source_ip"] in (SQLI_SRC, BRUTE_SRC, NORMAL_SRC, "10.99.0.6") and i["status"] != "resolved":
            analyst.post(f"/api/incidents/{i['id']}/resolve")
    for p in admin.get("/api/plugins").json()["plugins"]:
        if p["enabled"]:
            admin.post(f"/api/plugins/{p['id']}/disable")
    check(S, "all tools start disabled", not any(p["enabled"] for p in admin.get("/api/plugins").json()["plugins"]), "disabled")
    check(S, "firewall chain starts empty", "-A RAKSHAK-BLOCK" not in fw_rules(), fw_rules().strip())

    # ---------------- 1. access control ----------------
    S = "1 Access control"
    anon = httpx.Client(base_url=BASE)
    check(S, "no session -> overview refused", anon.get("/api/overview").status_code == 401, "401 expected")
    r = anon.post("/api/auth/login", json={"username": creds["viewer"][0], "password": "definitely-wrong"})
    check(S, "wrong password refused", r.status_code == 401, r.status_code)
    r = viewer.post("/api/plugins/website-check/runs", json={"target": WEB_PLAIN, "reason": "viewer try", "authorised": True})
    check(S, "viewer cannot request a security test", r.status_code == 403, r.status_code)
    r = analyst.post("/api/plugins/website-check/enable")
    check(S, "analyst cannot enable a tool (admin only)", r.status_code == 403, r.status_code)
    r = admin.post("/api/settings/mode", json={"mode": "recommend"}, headers={"X-RAKSHAK-CSRF": ""})
    check(S, "POST without CSRF token refused", r.status_code == 403, f"{r.status_code} {r.text[:80]}")
    r = httpx.get(BASE + "/api/health", headers={"Host": "evil.example"})
    check(S, "unexpected Host header refused", r.status_code == 400, r.status_code)

    # ---------------- 2. tool enable and hash pinning ----------------
    S = "2 Tools"
    for pid in ("website-check", "nmap-ports"):
        r = admin.post(f"/api/plugins/{pid}/enable")
        check(S, f"admin enables {pid}", r.status_code == 200, r.status_code)
    pl = {p["id"]: p for p in admin.get("/api/plugins").json()["plugins"]}
    wrapper_hash = hashlib.sha256(WRAPPER.read_bytes()).hexdigest()
    nmap_path = os.path.realpath(shutil.which("nmap") or "")
    nmap_hash = hashlib.sha256(Path(nmap_path).read_bytes()).hexdigest() if nmap_path else ""
    check(S, "website-check pinned hash equals independently computed sha256",
          pl["website-check"]["enabled"] and pl["website-check"]["trusted_hash"] == wrapper_hash, wrapper_hash[:16])
    check(S, "nmap pinned hash equals sha256 of the system nmap binary",
          pl["nmap-ports"]["enabled"] and pl["nmap-ports"]["trusted_hash"] == nmap_hash, f"{nmap_path} {nmap_hash[:16]}")

    # ---------------- 3. normal traffic -> no alert ----------------
    S = "3 Normal traffic"
    codes = [http_from(NORMAL_SRC, WEB_PLAIN + p) for p in ("", "index.html", "about", "contact", "") * 4]
    time.sleep(4)
    check(S, "20 normal page views from 10.99.0.3 answered by nginx", len(codes) == 20, f"codes {sorted(set(codes))}")
    check(S, "no alert raised for normal visitor", not incidents_from(admin, NORMAL_SRC), "0 incidents expected")

    # ---------------- 4. SQL injection -> alert -> approve -> real firewall block -> undo ----------------
    S = "4 SQL injection + block"
    attack = ["item?id=1%27%20OR%20%271%27%3D%271", "item?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
              "item?id=1%27%3B%20DROP%20TABLE%20users--", "search?q=%27%20or%201%3D1--"]
    for a in attack:
        http_from(SQLI_SRC, WEB_PLAIN + a)
    incs = wait_for(lambda: incidents_from(admin, SQLI_SRC), 15)
    inc = incs[0] if incs else None
    check(S, "incident raised from real nginx log lines", bool(inc),
          f"#{inc['id']} {inc['category']} {inc['status']} events={inc['event_count']}" if inc else "none")
    if inc:
        check(S, "category is sql_injection", inc["category"] == "sql_injection", inc["category"])
        inc2 = wait_for(lambda: next((x for x in incidents_from(admin, SQLI_SRC)
                                     if x["id"] == inc["id"] and x["status"] != "open"), None), timeout=10) or inc
        check(S, "recommend mode waits for approval (not auto-blocked)", inc2["status"] == "awaiting_approval", inc2["status"])
        v = analyst.post(f"/api/incidents/{inc['id']}/validate").json()
        check(S, "evidence re-check against stored rows: evidence_checked", v.get("validation") == "evidence_checked",
              v.get("validation"))
        r = admin.post("/api/plugins/nmap-ports/runs", json={"target": SQLI_SRC, "reason": "scan the attacker?", "authorised": True})
        check(S, "scanning the flagged attacker is refused", r.status_code == 400 and "attack" in r.text, r.json().get("detail", "")[:140])
        act = next((a for a in v.get("actions", []) if a["action"] == "block_ip" and a["status"] == "proposed"), None)
        r = viewer.post(f"/api/actions/{act['id']}/approve") if act else None
        check(S, "viewer cannot approve a block", r is not None and r.status_code == 403, r.status_code if r else "no action")
        r = analyst.post(f"/api/actions/{act['id']}/approve") if act else None
        check(S, "analyst approves the proposed block", r is not None and r.status_code == 200, r.status_code if r else "no action")
        rule = f"-A RAKSHAK-BLOCK -s {SQLI_SRC}/32 -j DROP"
        check(S, "DROP rule present in iptables chain", rule in fw_rules(), rule)
        bl = {b["ip"]: b for b in admin.get("/api/protection").json()["blocklist"]}
        check(S, "blocklist entry says enforced", bl.get(SQLI_SRC, {}).get("enforced") == "enforced", bl.get(SQLI_SRC))
        st = admin.get(f"/api/incidents/{inc['id']}").json()["status"]
        check(S, "incident status contained (firewall verified)", st == "contained", st)
        blocked = http_from(SQLI_SRC, WEB_PLAIN, timeout=3)
        other = http_from(NORMAL_SRC, WEB_PLAIN)
        check(S, "blocked source really cannot reach nginx", blocked == "000", f"10.99.0.2 -> {blocked}")
        check(S, "other source still served", other == "200", f"10.99.0.3 -> {other}")
        r = analyst.post("/api/protection/unblock", json={"ip": SQLI_SRC})
        check(S, "undo removes the block", r.status_code == 200 and r.json().get("ok"), r.text[:120])
        check(S, "DROP rule removed from iptables", rule not in fw_rules(), "rule absent")
        back = http_from(SQLI_SRC, WEB_PLAIN)
        check(S, "access restored after undo", back == "200", f"10.99.0.2 -> {back}")

    # ---------------- 5. SSH brute force -> block -> expiry ----------------
    S = "5 SSH brute force + expiry"
    with ThreadPoolExecutor(4) as pool:
        list(pool.map(lambda _: ssh_fail(BRUTE_SRC), range(10)))
    incs = wait_for(lambda: [i for i in incidents_from(admin, BRUTE_SRC) if i["category"] == "brute_force"], 15)
    inc = incs[0] if incs else None
    check(S, "brute_force incident from real sshd log", bool(inc),
          f"#{inc['id']} {inc['status']} events={inc['event_count']}" if inc else "none")
    if inc:
        act = next((a for a in admin.get(f"/api/incidents/{inc['id']}").json()["actions"]
                    if a["action"] == "block_ip" and a["status"] == "proposed"), None)
        r = analyst.post(f"/api/actions/{act['id']}/approve") if act else None
        check(S, "block approved", r is not None and r.status_code == 200, r.status_code if r else "no action")
        check(S, "SSH port unreachable from blocked source", not tcp_from(BRUTE_SRC, SSH_PORT), "connect timed out")
        check(S, "SSH port reachable from other source", tcp_from(NORMAL_SRC, SSH_PORT), "connected")
        with db() as con:   # SIMULATED TIME: move expiry into the past instead of waiting the 1-hour TTL
            con.execute("UPDATE blocklist SET expires_at=? WHERE ip=?", (time.time() - 1, BRUTE_SRC))
        gone = wait_for(lambda: f"-s {BRUTE_SRC}/32" not in fw_rules()
                        and not any(b["ip"] == BRUTE_SRC for b in admin.get("/api/protection").json()["blocklist"]), 40, 1)
        check(S, "expired block removed by housekeeping (simulated time)", gone, "rule and blocklist entry gone")
        check(S, "SSH reachable again after expiry", tcp_from(BRUTE_SRC, SSH_PORT), "connected")

    # ---------------- 6. scope refusals ----------------
    S = "6 Scope refusals"
    for name, plugin, target in [("public address 8.8.8.8 (not owned)", "nmap-ports", "8.8.8.8"),
                                 ("never_scan address 10.99.0.4", "nmap-ports", NEVER_IP),
                                 ("host-name URL (DNS can change)", "website-check", "http://localhost:8081/"),
                                 ("out-of-scope URL", "website-check", "http://192.168.1.1/")]:
        r = analyst.post(f"/api/plugins/{plugin}/runs", json={"target": target, "reason": "scope refusal check", "authorised": True})
        check(S, f"refused: {name}", r.status_code == 400, r.json().get("detail", "")[:150])
    r = analyst.post("/api/plugins/website-check/runs", json={"target": WEB_PLAIN, "reason": "no authorisation", "authorised": False})
    check(S, "refused: authorisation box not ticked", r.status_code == 400, r.json().get("detail", "")[:100])

    # ---------------- 7. website checks with independent re-checks ----------------
    S = "7 Website check"
    req = analyst.post("/api/plugins/website-check/runs", json={"target": WEB_PLAIN, "reason": "e2e plain site", "authorised": True}).json()
    r = analyst.post(f"/api/runs/{req['id']}/approve")
    still = admin.get(f"/api/runs/{req['id']}").json()["status"]
    check(S, "analyst approval refused for admin-approval tool; request still waiting", r.status_code == 403 and still == "queued",
          f"{r.status_code} {still}")
    run = admin.post(f"/api/runs/{req['id']}/approve").json()
    f = {x["id"]: x for x in run.get("findings", [])}
    check(S, "plain site run completed", run.get("status") == "completed", f"#{run.get('id')} {run.get('status')} {run.get('reason','')}")
    hdrs = [k for k, x in f.items() if k.startswith("HDR-") and not x["passed"]]
    check(S, "missing headers confirmed by re-check", hdrs and all(f[k]["status"] == "confirmed" for k in hdrs), hdrs)
    check(S, "server version disclosure confirmed", f.get("INFO-SERVER", {}).get("status") == "confirmed",
          f.get("INFO-SERVER", {}).get("evidence", "")[:120])
    check(S, "plain HTTP confirmed", f.get("TLS", {}).get("status") == "confirmed", f.get("TLS", {}).get("title"))
    check(S, "no secret file reported on plain site", f.get("FILE-/.env", {}).get("passed", True), f.get("FILE-/.env", {}).get("status"))
    plain_run = run["id"]

    run, _ = run_test(analyst, admin, "website-check", WEB_LEAKY, "e2e leaky fixture")
    f = {x["id"]: x for x in (run or {}).get("findings", [])}
    env_f = f.get("FILE-/.env", {})
    check(S, "leaky fixture: /.env exposure confirmed", env_f.get("passed") is False and env_f.get("status") == "confirmed",
          f"{env_f.get('status')} | {env_f.get('validation_evidence','')[:120]}")
    leaky_run = (run or {}).get("id")

    run, _ = run_test(analyst, admin, "website-check", WEB_CATCHALL, "e2e catch-all site")
    f = {x["id"]: x for x in (run or {}).get("findings", [])}
    confirmed_files = [k for k, x in f.items() if k.startswith("FILE-") and x.get("status") == "confirmed"]
    check(S, "catch-all site: no false 'secret file' confirmed", run and not confirmed_files,
          f"confirmed file findings: {confirmed_files}")

    req = analyst.post("/api/plugins/website-check/runs", json={"target": WEB_PLAIN, "reason": "e2e reject flow", "authorised": True}).json()
    r = admin.post(f"/api/runs/{req['id']}/reject", json={"why": "Not in this change window"}).json()
    check(S, "reject: stored as refused/rejected, tool never launched",
          r.get("status") == "refused" and r["summary"].get("state") == "rejected" and not r.get("started_at"), r.get("status"))

    # ---------------- 8. Nmap with independent TCP re-check ----------------
    S = "8 Nmap"
    run, resp = run_test(analyst, admin, "nmap-ports", SERVER, "e2e port check")
    run = run or {}
    ports = sorted(int(x["recheck"]["port"]) for x in run.get("findings", []) if x.get("recheck", {}).get("port"))
    check(S, "nmap run completed", run.get("status") == "completed", f"#{run.get('id')} {run.get('status')} {run.get('reason','')[:100]}")
    check(S, "every open-port finding re-confirmed by own TCP connect",
          run.get("findings") and all(x["status"] == "confirmed" for x in run["findings"] if not x.get("passed")), f"ports {ports}")
    check(S, "nginx port 8081 found", 8081 in ports, ports)
    ss = subprocess.run(["ss", "-Hltn"], capture_output=True, text=True).stdout
    listening = {int(l.split()[3].rsplit(":", 1)[1]) for l in ss.splitlines()
                 if l.split()[3].rsplit(":", 1)[0] in ("0.0.0.0", "*", "[::]", SERVER)}
    check(S, "every reported port is really listening (ss)", set(ports) <= listening, f"ss listening {sorted(listening)}")

    # ---------------- 9. tamper detection ----------------
    S = "9 Tamper detection"
    sqli_inc = next((i for i in incidents_from(admin, SQLI_SRC)), None)
    check(S, "evidence chain is healthy BEFORE tamper test (no leftover from an interrupted run)",
          admin.get("/api/integrity").json()["events"]["ok"], admin.get("/api/integrity").json()["events"])
    with db() as con:
        eid, path = con.execute("SELECT id, path FROM events WHERE source_ip=? ORDER BY id DESC LIMIT 1", (SQLI_SRC,)).fetchone()
        con.execute("UPDATE events SET path=? WHERE id=?", (path + "-edited", eid))
    ig = admin.get("/api/integrity").json()["events"]
    check(S, "edited event row detected", not ig["ok"], ig)
    r = analyst.post(f"/api/incidents/{sqli_inc['id']}/report") if sqli_inc else None
    check(S, "incident report refused while evidence is broken", r is not None and r.status_code == 400, r.text[:120] if r else "")
    with db() as con:
        con.execute("UPDATE events SET path=? WHERE id=?", (path, eid))
    check(S, "chain verifies again after restore", admin.get("/api/integrity").json()["events"]["ok"], "restored")

    if leaky_run:
        with db() as con:
            tgt = con.execute("SELECT target FROM plugin_runs WHERE id=?", (leaky_run,)).fetchone()[0]
            con.execute("UPDATE plugin_runs SET target=? WHERE id=?", ("http://10.99.0.6/", leaky_run))
        v = admin.get(f"/api/runs/{leaky_run}").json()["verified"]
        r = analyst.post(f"/api/runs/{leaky_run}/report")
        check(S, "edited run record fails signature; report refused", not v and r.status_code == 400, f"verified={v} {r.status_code}")
        with db() as con:
            con.execute("UPDATE plugin_runs SET target=? WHERE id=?", (tgt, leaky_run))
        check(S, "run record verifies after restore", admin.get(f"/api/runs/{leaky_run}").json()["verified"], "restored")

    original = WRAPPER.read_bytes()
    try:
        WRAPPER.write_bytes(original + b"\n# e2e tamper test\n")
        r = analyst.post("/api/plugins/website-check/runs", json={"target": WEB_PLAIN, "reason": "after tamper", "authorised": True})
        check(S, "modified tool file refused before launch", r.status_code == 400 and "hash" in r.text.lower(), r.json().get("detail", "")[:150])
    finally:
        WRAPPER.write_bytes(original)
    r = analyst.post("/api/plugins/website-check/runs", json={"target": WEB_PLAIN, "reason": "after restore", "authorised": True})
    ok = r.status_code == 200
    if ok:
        admin.post(f"/api/runs/{r.json()['id']}/reject", json={"why": "cleanup after tamper test"})
    check(S, "restored tool accepted again", ok, r.status_code)

    with db() as con:
        aid, det = con.execute("SELECT id, detail FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        con.execute("UPDATE audit SET detail=? WHERE id=?", (det.replace("}", ',"x":1}', 1) if det else "{}", aid))
    au = admin.get("/api/integrity").json()["audit"]
    check(S, "edited audit entry detected", not au["ok"], au)
    with db() as con:
        con.execute("UPDATE audit SET detail=? WHERE id=?", (det, aid))
    check(S, "audit chain verifies after restore", admin.get("/api/integrity").json()["audit"]["ok"], "restored")

    # ---------------- 10. reports ----------------
    S = "10 Reports"
    if sqli_inc:
        r = analyst.post(f"/api/incidents/{sqli_inc['id']}/report")
        txt = pdf_text(analyst, r.json()["url"]) if r.status_code == 200 else ""
        check(S, "incident PDF generated", bool(txt), f"{len(txt)} chars")
        check(S, "incident PDF names the real source and category", SQLI_SRC in txt and "sql" in txt.lower(), "10.99.0.2, SQL")
        check(S, "incident PDF states evidence check", "evidence" in txt.lower(), "evidence wording present")
    if leaky_run:
        r = analyst.post(f"/api/runs/{leaky_run}/report")
        txt = pdf_text(analyst, r.json()["url"]) if r.status_code == 200 else ""
        check(S, "test-run PDF generated", bool(txt), f"{len(txt)} chars")
        check(S, "test-run PDF lists the confirmed /.env finding", "/.env" in txt and "onfirmed" in txt, "/.env + Confirmed")
    r = analyst.post(f"/api/runs/{plain_run}/report")
    check(S, "plain-site PDF generated", r.status_code == 200, r.status_code)

    # ---------------- 11. external plugin (the path used for your own / GitHub tools) ----------------
    S = "11 External plugin"
    pl = {p["id"]: p for p in admin.get("/api/plugins").json()["plugins"]}
    ext = pl.get("tcp-connect-check")
    check(S, "example plugin discovered and valid", ext and ext["available"] and not ext["builtin"],
          (ext or {}).get("reason") or "available")
    if ext:
        check(S, "external plugin disabled until an admin enables it", ext["enabled"] is False, ext["reason"][:100])
        r = admin.post("/api/plugins/tcp-connect-check/enable")
        real = hashlib.sha256(EXAMPLE_WRAPPER.read_bytes()).hexdigest()
        pinned = r.json().get("trusted_hash") if r.status_code == 200 else ""
        pinned = pinned or {p["id"]: p for p in admin.get("/api/plugins").json()["plugins"]}["tcp-connect-check"]["trusted_hash"]
        check(S, "enabled; pinned hash = manifest sha256 = file sha256", r.status_code == 200 and pinned == real == ext["sha256"],
              real[:16])
        r = analyst.post("/api/plugins/tcp-connect-check/runs", json={"target": NEVER_IP, "reason": "never_scan check", "authorised": True})
        check(S, "never_scan applies to external tools too", r.status_code == 400, r.json().get("detail", "")[:100])
        run, _ = run_test(analyst, admin, "tcp-connect-check", SERVER, "e2e external plugin")
        run = run or {}
        f = run.get("findings", [])
        conf = sorted(x["port"] for x in f if x["status"] == "confirmed")
        passes = sorted(x["port"] for x in f if x["status"] == "observed_pass")
        check(S, "external run completed", run.get("status") == "completed", f"#{run.get('id')} {run.get('status')} {run.get('reason', '')[:80]}")
        ss = subprocess.run(["ss", "-Hltn"], capture_output=True, text=True).stdout
        listening = {int(l.split()[3].rsplit(":", 1)[1]) for l in ss.splitlines()
                     if l.split()[3].rsplit(":", 1)[0] in ("0.0.0.0", "*", "[::]", SERVER)}
        check(S, "confirmed ports are really listening (ss)", conf and set(conf) <= listening, f"confirmed {conf}")
        check(S, "closed ports reported only as observed passes", passes and not set(passes) & listening, f"passes {passes}")
        check(S, "tool cannot self-confirm: every confirmation has Rakshak's own re-check",
              all("Independent TCP connection" in x.get("validation_evidence", "") for x in f if x["status"] == "confirmed"), "validation_evidence present")

    # ---------------- 12. system security (the machine itself) ----------------
    S = "12 System security"
    hs = admin.get("/api/overview").json()["hostsec"]
    check(S, "system sensors on, baselined, fast scan interval",
          hs.get("enabled") and hs.get("baselined") and 0 < hs.get("interval_s", 99) <= 10, hs)
    for i in admin.get("/api/incidents").json():
        if i["source_ip"] == "system" and i["status"] != "resolved":
            analyst.post(f"/api/incidents/{i['id']}/resolve")   # re-runnable
    watch = Path("/home/ubuntu/rakshak-test/watched.conf")
    if not watch.exists():                                       # first run: create, let sensors see it
        watch.parent.mkdir(parents=True, exist_ok=True)
        watch.write_text("original sanctioned configuration\n")
        time.sleep(8)                                            # baseline/appearance alert
        for i in admin.get("/api/incidents").json():
            if i["source_ip"] == "system" and i["status"] != "resolved":
                analyst.post(f"/api/incidents/{i['id']}/resolve")
    original = watch.read_text()

    def host_inc(cat):
        return next((i for i in admin.get("/api/incidents").json()
                     if i["source_ip"] == "system" and i["category"] == cat
                     and i["status"] != "resolved"), None)

    def fresh(i):
        return next((x for x in admin.get("/api/incidents").json() if x["id"] == i["id"]), None)

    watch.write_text(original + f"\n# unsanctioned edit {int(time.time())}\n")
    inc = wait_for(lambda: host_inc("file_integrity"), timeout=30)
    check(S, "unsanctioned edit of a watched file detected on the live machine", inc is not None,
          (inc or {}).get("id"))
    if inc:
        wait_for(lambda: (fresh(inc) or {}).get("validation") == "evidence_checked", timeout=10)
        inc = fresh(inc)
        check(S, "file change re-checked live: evidence_checked",
              inc["validation"] == "evidence_checked", inc["validation"])
        check(S, "alert carries before/after SHA-256 fingerprints",
              "sha256" in inc["evidence"][0] and "after=" in inc["evidence"][0],
              inc["evidence"][0][:140])
        analyst.post(f"/api/incidents/{inc['id']}/validate")   # re-check while still tampered
        watch.write_text(original)                       # then revert the change
        time.sleep(7)                                    # let the console's own scan observe it
        cur = host_inc("file_integrity")
        check(S, "revert observed: alert now Suspected (change reverted, no fake claim)",
              cur is not None and cur["validation"] == "suspected",
              (cur or {}).get("validation"))
        deadline = time.time() + 20
        while time.time() < deadline:
            late = host_inc("file_integrity")            # drain any late re-alert of the revert
            if not late:
                break
            analyst.post(f"/api/incidents/{late['id']}/resolve")
            time.sleep(6)

    port = 14000 + int(time.time()) % 500                # fresh port on every rerun
    listener = subprocess.Popen(["python3", "-m", "http.server", str(port), "--bind", "127.0.0.1"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    inc = wait_for(lambda: host_inc("new_service"), timeout=30)
    check(S, "new backdoor-style listener detected via /proc/net", inc is not None,
          (inc or {}).get("detections", [{}])[0].get("matched") if inc else None)
    if inc:
        wait_for(lambda: (fresh(inc) or {}).get("validation") == "evidence_checked", timeout=10)
        inc = fresh(inc)
        check(S, "listener still there: evidence_checked + high severity",
              inc["validation"] == "evidence_checked" and inc["severity"] == "high",
              (inc["validation"], inc["severity"]))
        check(S, "alert names the exact socket it found", f"127.0.0.1:{port}" in str(inc["detections"][0]["matched"]),
              inc["detections"][0]["matched"])
        listener.terminate()
        listener.wait()
        time.sleep(1.5)                                  # let /proc settle
        inc2 = analyst.post(f"/api/incidents/{inc['id']}/validate").json()
        check(S, "listener gone: re-check downgrades honestly",
              inc2["validation"] == "suspected",
              (inc2["validation_detail"]["reasons"] or [""])[0][:120])
        analyst.post(f"/api/incidents/{inc['id']}/resolve")

    mem = admin.get("/api/memory?kind=system").json()
    check(S, "system findings visible in Memory (kind=system)",
          mem["entries"] and all(e["source_ip"] == "system" for e in mem["entries"]),
          f"{len(mem['entries'])} entries")
    prot = admin.get("/api/protection").json()
    check(S, "host findings never enter the block pipeline",
          not any(a["target"] == "system" for a in prot["actions"]), "no 'system' blocks")

    # credential compromise: password guessing, then a REAL accepted login from the same address
    cred_src = "10.99.0.6"
    key_path = Path("/home/ubuntu/rakshak-test/e2e_attacker_key")
    if not key_path.exists():
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path), "-C", "rakshak-e2e-temp"],
                       check=True, capture_output=True, timeout=30)
    pubkey = key_path.with_suffix(".pub").read_text().strip() + " rakshak-e2e-temp"
    ak = Path.home() / ".ssh" / "authorized_keys"
    ak.parent.mkdir(mode=0o700, exist_ok=True)
    ak.touch(mode=0o600)
    before_keys = ak.read_text()
    ak.write_text(before_keys + pubkey + "\n")          # the "stolen/added" key - real sshd accepts it now
    for _ in range(6):
        ssh_fail(cred_src)
    r = subprocess.run(["ssh", "-b", cred_src, "-i", str(key_path), "-p", str(SSH_PORT),
                        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                        "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", f"ubuntu@{SERVER}", "true"],
                       capture_output=True, timeout=40)
    ak.write_text(before_keys)                          # cleanup: remove the test key
    inc = wait_for(lambda: next((i for i in admin.get("/api/incidents").json()
                                 if i["source_ip"] == cred_src
                                 and i["category"] == "credential_compromise"
                                 and i["status"] != "resolved"), None), timeout=30)
    check(S, "guessing-then-accepted login detected from real sshd log",
          inc is not None and r.returncode == 0, f"ssh rc={r.returncode} alert={(inc or {}).get('id')}")
    if inc:
        check(S, "critical severity, evidence re-checked from stored rows",
              inc["severity"] == "critical" and inc["validation"] == "evidence_checked",
              (inc["severity"], inc["validation"]))
        acts = admin.get(f"/api/incidents/{inc['id']}").json()["actions"]
        prop = next((a for a in acts if a["action"] == "block_ip" and a["status"] == "proposed"), None)
        ok = analyst.post(f"/api/actions/{prop['id']}/approve").status_code == 200 if prop else False
        time.sleep(1.0)
        rule = f"-A RAKSHAK-BLOCK -s {cred_src}/32 -j DROP"
        check(S, "this host-side attack DOES have an IP: approved block lands in the firewall",
              ok and rule in fw_rules(), rule if ok else "no approved block")
        admin.post("/api/protection/unblock", json={"ip": cred_src})
        analyst.post(f"/api/incidents/{inc['id']}/resolve")

    check(S, "watched file and port state back to normal after cleanup",
          watch.read_text() == original and host_inc("file_integrity") is None
          and host_inc("new_service") is None, "clean")

    # ---------------- 13. undo attacker events (approved, live-verified) ----------------
    S = "13 Verified undo"
    for i in admin.get("/api/incidents").json():
        if i["source_ip"] == "system" and i["status"] != "resolved":
            analyst.post(f"/api/incidents/{i['id']}/resolve")           # re-runnable start state
    time.sleep(6)                                                       # let sensors settle on baseline
    watch.write_text(original + "\n# attacker backdoor line\n")
    inc1 = wait_for(lambda: host_inc("file_integrity"), timeout=30)
    check(S, "tamper #1 detected (alert with vault-backed restore available)", inc1 is not None,
          (inc1 or {}).get("id"))
    if inc1:
        opts = analyst.get(f"/api/incidents/{inc1['id']}/remediation").json()["options"]
        restore = next((o for o in opts if o["action"] == "restore_file"), None)
        check(S, "undo offered: vault holds the exact pre-change content", restore and restore["possible"],
              (restore or {}).get("reason", "no option"))
        r = viewer.post(f"/api/incidents/{inc1['id']}/remediation", json={"action": "restore_file"})
        check(S, "viewer cannot propose an undo", r.status_code == 403, r.status_code)
        r = analyst.post(f"/api/incidents/{inc1['id']}/remediation", json={"action": "restore_file"})
        act_id = r.json().get("action_id") if r.status_code == 200 else None
        check(S, "analyst PROPOSES the undo (signed action record)", r.status_code == 200 and act_id,
              (r.status_code, act_id))
        check(S, "a proposal changes nothing on disk", watch.read_text().endswith("backdoor line\n"),
              watch.read_text()[-40:])
        analyst.post(f"/api/incidents/{inc1['id']}/resolve")            # closing cancels pending work
        time.sleep(1)
        acts = admin.get(f"/api/incidents/{inc1['id']}").json()["actions"]
        a1 = next((a for a in acts if a["id"] == act_id), {})
        check(S, "resolving the alert cancels the unapproved proposal",
              a1.get("status") == "cancelled" and watch.read_text().endswith("backdoor line\n"),
              a1.get("status"))

    tamper2 = original + "\n# attacker backdoor line\n# ops-sanctioned tweak\n"
    watch.write_text(tamper2)                                           # still open object history
    inc2 = wait_for(lambda: host_inc("file_integrity"), timeout=30)
    check(S, "tamper #2 detected as a new alert", inc2 is not None, (inc2 or {}).get("id"))
    if inc2:
        r = analyst.post(f"/api/incidents/{inc2['id']}/accept")
        got = admin.get(f"/api/incidents/{inc2['id']}").json()
        hv = admin.get("/api/overview").json()["hostsec"]
        led = [a for a in got["actions"] if a["action"] == "accept_change"]
        check(S, "'sanctioned change' closes the alert with validation=accepted",
              r.status_code == 200 and got["status"] == "resolved" and got["validation"] == "accepted",
              (r.status_code, got["status"], got["validation"]))
        check(S, "acceptance is ledgered (who + what, signed) and counted on Home",
              led and led[0]["verified"] and led[0]["status"] == "done"
              and hv.get("accepted_changes", 0) >= 1,
              (led[0]["detail"][:70] if led else "no ledger row", hv.get("accepted_changes")))
        check(S, "accepting does NOT silently rewrite the file - it stays as sanctioned",
              watch.read_text() == tamper2, watch.read_text()[-40:])

    tamper3 = tamper2 + "# attacker returns\n"
    watch.write_text(tamper3)
    inc3 = wait_for(lambda: host_inc("file_integrity"), timeout=30)
    check(S, "tamper #3 detected", inc3 is not None, (inc3 or {}).get("id"))
    if inc3:
        r = analyst.post(f"/api/incidents/{inc3['id']}/remediation", json={"action": "restore_file"})
        act_id = r.json().get("action_id") if r.status_code == 200 else None
        r = admin.post(f"/api/actions/{act_id}/approve")
        undone = wait_for(lambda: watch.read_text() == tamper2, timeout=12)
        acts = admin.get(f"/api/incidents/{inc3['id']}").json()["actions"]
        a3 = next((a for a in acts if a["id"] == act_id), {})
        check(S, "admin approval executes the undo and RESTORES the pre-attack state",
              r.status_code == 200 and undone, (r.status_code, watch.read_text()[-40:]))
        check(S, "restore verified against the live hash (not just attempted)",
              a3.get("status") == "done" and a3.get("verified") and "restored" in str(a3.get("detail", "")),
              (a3.get("status"), str(a3.get("detail", ""))[:80]))
        time.sleep(1)
        got = fresh(inc3)
        check(S, "alert downgrades to Suspected once the change is undone",
              got["validation"] == "suspected", got["validation"])
        analyst.post(f"/api/incidents/{inc3['id']}/resolve")

    # ---- unauthorised listener: attribute it to its process, then stop it (verified) ----
    import random
    lport = 15000 + random.randint(0, 399)
    listener = subprocess.Popen(["python3", "-m", "http.server", str(lport), "--bind", "127.0.0.1"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        inc4 = wait_for(lambda: host_inc("new_service"), timeout=30)
        check(S, f"real listener on 127.0.0.1:{lport} detected", inc4 is not None,
              (inc4 or {}).get("detections", [{}])[0].get("matched") if inc4 else None)
        if inc4:
            det0 = inc4["detections"][0]
            proc = (det0.get("found") or {}).get("process") or {}
            check(S, "socket attributed to the exact process (pid + cmdline via /proc)",
                  proc.get("pid") == listener.pid and "http.server" in str(proc.get("cmdline", "")),
                  (proc.get("pid"), str(proc.get("cmdline", ""))[:60]))
            opts = analyst.get(f"/api/incidents/{inc4['id']}/remediation").json()["options"]
            so = next((o for o in opts if o["action"] == "stop_process"), None)
            check(S, "stop-process undo offered for the attributed pid", so and so["possible"],
                  (so or {}).get("reason", "no option"))
            r = analyst.post(f"/api/incidents/{inc4['id']}/remediation", json={"action": "stop_process"})
            act_id = r.json().get("action_id") if r.status_code == 200 else None
            alive_now = listener.poll() is None
            check(S, "proposal alone does NOT kill the process", r.status_code == 200 and alive_now,
                  (r.status_code, "still running"))
            r = admin.post(f"/api/actions/{act_id}/approve")
            gone = wait_for(lambda: listener.poll() is not None, timeout=15)
            refused_conn = False
            if gone:
                try:
                    sk = socket.create_connection(("127.0.0.1", lport), timeout=2); sk.close()
                except OSError:
                    refused_conn = True
            acts = admin.get(f"/api/incidents/{inc4['id']}").json()["actions"]
            a4 = next((a for a in acts if a["id"] == act_id), {})
            check(S, "approved stop actually killed the listener (port refuses connections)",
                  r.status_code == 200 and gone and refused_conn, (r.status_code, gone, refused_conn))
            check(S, "stop verified against the live socket table, action signed done",
                  a4.get("status") == "done" and a4.get("verified"), (a4.get("status"), a4.get("verified")))
            analyst.post(f"/api/incidents/{inc4['id']}/resolve")
    finally:
        listener.kill()

    # ---- backdoor account: lock and remove through the restricted root helper ----
    subprocess.run(["sudo", "-n", "userdel", "-r", "invader_e2e"], capture_output=True)
    r = subprocess.run(["sudo", "-n", "useradd", "-m", "-s", "/bin/bash", "invader_e2e"],
                       capture_output=True, text=True)
    check(S, "backdoor-style account created by the simulated attacker", r.returncode == 0, r.stderr[:80])
    inc5 = wait_for(lambda: host_inc("account_change"), timeout=40)
    check(S, "new account detected from /etc/passwd diff", inc5 is not None,
          (inc5 or {}).get("detections", [{}])[0].get("matched") if inc5 else None)
    if inc5:
        opts = analyst.get(f"/api/incidents/{inc5['id']}/remediation").json()["options"]
        la = next((o for o in opts if o["action"] == "lock_account"), None)
        check(S, "lock-account undo offered (root helper configured, account not protected)",
              la and la["possible"], (la or {}).get("reason", "no option"))
        r = analyst.post(f"/api/incidents/{inc5['id']}/remediation", json={"action": "lock_account"})
        act_id = r.json().get("action_id")
        admin.post(f"/api/actions/{act_id}/approve")
        sh = subprocess.run(["sudo", "-n", "getent", "shadow", "invader_e2e"],
                            capture_output=True, text=True)
        locked = sh.stdout.strip().split(":")[1:2] and sh.stdout.split(":")[1].startswith("!")
        check(S, "approved lock executed AND verified live (shadow hash disabled)",
              r.status_code == 200 and locked, sh.stdout.split(":")[1][:12] if sh.returncode == 0 else "no entry")
        r = analyst.post(f"/api/incidents/{inc5['id']}/remediation", json={"action": "remove_account"})
        act_id = r.json().get("action_id")
        admin.post(f"/api/actions/{act_id}/approve")
        gone = wait_for(lambda: subprocess.run(["getent", "passwd", "invader_e2e"],
                                               capture_output=True).returncode != 0, timeout=15)
        acts = admin.get(f"/api/incidents/{inc5['id']}").json()["actions"]
        a5 = next((a for a in acts if a["id"] == act_id), {})
        check(S, "approved removal deleted the account and helper verified absence",
              r.status_code == 200 and gone and a5.get("status") == "done" and a5.get("verified"),
              (r.status_code, gone, a5.get("status")))
        time.sleep(1)
        got = fresh(inc5)
        check(S, "account alert downgrades honestly after removal",
              got["validation"] == "suspected", got["validation"])
        analyst.post(f"/api/incidents/{inc5['id']}/resolve")
    subprocess.run(["sudo", "-n", "userdel", "-r", "invader_e2e"], capture_output=True)
    watch.write_text(original)                                          # restore the fixture file
    time.sleep(7)
    for i in admin.get("/api/incidents").json():
        if i["source_ip"] == "system" and i["status"] != "resolved":
            analyst.post(f"/api/incidents/{i['id']}/resolve")           # the revert itself alerts: expected

    # ---------------- 14. offline adaptation: rule packs mined and gated ----------------
    S = "14 Adaptation"
    novel_id = "ADP-E2E-NOVEL-1"
    novel_pat = "rk-e2e-novel-7f3c"
    pack = (f"- id: {novel_id}\n  name: E2E novel token\n  category: sql_injection\n"
            f"  severity: high\n  patterns:\n    - {novel_pat}\n")
    r = admin.post("/api/rules/import", json={"name": "e2e-broken", "rules_yaml": "- just: a string",
                                              "samples": []})
    check(S, "malformed rule pack refused by schema gate", r.status_code == 400, r.status_code)
    dead = ("- id: ADP-E2E-DEAD\n  name: Dead rule\n  category: xss\n  severity: low\n"
            "  patterns: [zz-nothing-can-match-this]\n")
    r = admin.post("/api/rules/import", json={"name": "e2e-dead", "rules_yaml": dead,
                                              "samples": [{"path": "/x", "query": "a=1", "expect": "match"}]})
    check(S, "rule that fails its own examples refused by self-test gate",
          r.status_code == 400 and "examples" in r.text.lower(), r.status_code)
    r = analyst.post("/api/rules/import", json={"name": "e2e-x", "rules_yaml": pack, "samples": []})
    check(S, "analyst cannot import rule packs (admin gate)", r.status_code == 403, r.status_code)
    good_samples = [{"path": "/q", "query": f"x=1&blob={novel_pat}", "expect": "match"},
                    {"path": "/q", "query": "x=1&lang=en", "expect": "nomatch"}]
    r = admin.post("/api/rules/import", json={"name": "e2e-novel", "rules_yaml": pack,
                                             "samples": good_samples})
    check(S, "valid pack imported after passing both gates", r.status_code == 200, r.text[:120])
    if r.status_code == 200:
        rules = admin.get("/api/rules").json()["rules"]
        row = next((x for x in rules if x["id"] == novel_id), None)
        check(S, "imported rule listed and flagged as imported", row is not None and row["imported"],
              row)
    # the freshly imported signature catches a REAL request nginx logs
    http_from("10.99.0.7", f"{WEB_CATCHALL}?x=1&blob={novel_pat}")
    inc6 = wait_for(lambda: next((i for i in admin.get("/api/incidents").json()
                                  if i["source_ip"] == "10.99.0.7" and i["status"] != "resolved"), None),
                    timeout=30)
    check(S, "NEW attack pattern detected live by the imported rule (offline learning loop closed)",
          inc6 is not None and any(d["rule_id"] == novel_id for d in inc6["detections"]),
          [d["rule_id"] for d in (inc6 or {}).get("detections", [])])
    # mine a draft from a genuine SQLi alert and take it through the same gate
    frag = "UNION%20SELECT%20login%2Ctoken%20FROM%20sessions7f"
    for p_ in (f"/search.php?q=1'+{frag}", f"/search.php?page=2'+{frag}"):
        http_from("10.99.0.8", WEB_CATCHALL + p_)
    inc7 = wait_for(lambda: next((i for i in admin.get("/api/incidents").json()
                                  if i["source_ip"] == "10.99.0.8" and i["status"] != "resolved"
                                  and len(i.get("evidence", [])) >= 2   # mining needs both lines indexed
                                  ), None), timeout=30)
    check(S, "SQLi incident exists to mine a draft rule from", inc7 is not None, (inc7 or {}).get("id"))
    if inc7:
        r = analyst.post(f"/api/incidents/{inc7['id']}/suggest_rule")
        d = r.json() if r.status_code == 200 else {}
        check(S, "draft rule mined from real evidence (with positive+negative samples)",
              r.status_code == 200 and "ADP-" in d.get("yaml", "") and len(d.get("samples", [])) == 2,
              (r.status_code, str(d.get("note", ""))[:60]))
        m = re.search(r"\bid:\s*([A-Za-z0-9_-]+)", d.get("yaml", ""))
        draft_id = m.group(1) if m else "?"
        loaded_before = {x["id"] for x in admin.get("/api/rules").json()["rules"]}
        check(S, "draft is NOT active before import", draft_id not in loaded_before, draft_id)
        if d.get("yaml"):
            r = admin.post("/api/rules/import", json={"name": f"e2e-draft-{int(time.time()) % 10000}",
                                                      "rules_yaml": d["yaml"], "samples": d["samples"]})
            live = {x["id"] for x in admin.get("/api/rules").json()["rules"]}
            check(S, "draft passes the same gate and goes live on admin import",
                  r.status_code == 200 and draft_id in live, (r.status_code, draft_id in live))
    # machine-generated payloads: entropy signal fires on randomised blobs
    import base64, secrets as _sec
    for _ in range(4):
        blob = base64.b32encode(_sec.token_bytes(18)).decode()
        http_from("10.99.0.9", f"{WEB_CATCHALL}?d={blob}&tag={novel_pat}")
    inc8 = wait_for(lambda: next((i for i in admin.get("/api/incidents").json()
                                  if i["source_ip"] == "10.99.0.9" and i["status"] != "resolved"), None),
                    timeout=30)
    check(S, "AI-payload entropy signal fires on machine-generated variants",
          inc8 is not None and any("machine-generated" in r_ for r_ in inc8["ai_reasons"]),
          str((inc8 or {}).get("ai_reasons", ""))[:120])
    r = admin.post("/api/ml/train")
    check(S, "model training answers honestly (trained or 'not enough samples', never fake)",
          r.status_code in (200, 400) and (r.json().get("ok") or "samples" in r.text.lower()),
          (r.status_code, r.text[:80]))
    for ip_ in ("10.99.0.7", "10.99.0.8", "10.99.0.9"):
        for i in admin.get("/api/incidents").json():
            if i["source_ip"] == ip_ and i["status"] != "resolved":
                analyst.post(f"/api/incidents/{i['id']}/resolve")
        if any(b["ip"] == ip_ for b in admin.get("/api/protection").json()["blocklist"]):
            admin.post("/api/protection/unblock", json={"ip": ip_})

    # ---------------- 15. distributed sensors -> hub (HMAC-gated ingestion) ----------------
    S = "15 Sensors"
    key_path = ROOT / "data" / "sensor_secret.key"
    if not key_path.exists():
        subprocess.run([".venv/bin/python", "-m", "rakshak.admin", "sensor-secret"], cwd=ROOT,
                       capture_output=True, text=True)
    check(S, "hub ingest key exists (rakshak.admin sensor-secret) with 0600 perms",
          key_path.exists() and (key_path.stat().st_mode & 0o077) == 0, str(key_path))
    check(S, "overview reports ingestion armed", admin.get("/api/overview").json()["ingest_enabled"])
    node_log = Path("/home/ubuntu/rakshak-test/node_access.log")
    node_log.parent.mkdir(exist_ok=True)
    node_log.write_text("")
    state = Path("/tmp/rk_e2e_sensor_state.json")
    state.unlink(missing_ok=True)
    with db() as con:
        con.execute("UPDATE nodes SET last_seq=0 WHERE name='testnode-e2e'")
    sensor = subprocess.Popen([".venv/bin/python", "-m", "rakshak.sensor", "--hub", BASE,
                               "--secret", str(key_path), "--name", "testnode-e2e",
                               "--logs", str(node_log), "--state", str(state), "--interval", "1"],
                              cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ts = (datetime.now(timezone.utc) - timedelta(seconds=5)).strftime("%d/%b/%Y:%H:%M:%S")
        with open(node_log, "a") as fh:
            fh.write(f'77.99.0.2 - - [{ts} +0000] "GET /news.php?id=9%20UNION%20SELECT%20u%2Cp%20'
                     f'FROM%20users--%20 HTTP/1.1" 500 33 "-" "e2e-sensor/1.0"\n')
        inc9 = wait_for(lambda: next((i for i in admin.get("/api/incidents").json()
                                      if i.get("node") == "testnode-e2e"
                                      and i["status"] != "resolved"), None), timeout=45)
        check(S, "sensor-batched attack line became a hub alert NAMED FOR ITS MACHINE",
              inc9 is not None and inc9["source_ip"] == "77.99.0.2",
              f'alert={((inc9 or {}).get("id"))} node={((inc9 or {}).get("node"))}')
        nodes = admin.get("/api/nodes").json()["nodes"]
        me = next((n for n in nodes if n["name"] == "testnode-e2e"), None)
        check(S, "node registry shows last sequence and event count",
              me is not None and me["last_seq"] >= 1 and me["events_total"] >= 1, me)
        # a captured batch replayed by an attacker is refused (sequence must increase)
        secret = key_path.read_bytes()
        body = b'{"events": []}'
        tsx = str(time.time())
        sig = hmac.new(secret, f"{tsx}\ntestnode-e2e\n1\n{hashlib.sha256(body).hexdigest()}".encode(),
                       hashlib.sha256).hexdigest()
        rr = anon.post("/api/ingest", content=body, headers={
            "X-Rakshak-Sensor": "testnode-e2e", "X-Rakshak-Seq": "1",
            "X-Rakshak-Timestamp": tsx, "X-Rakshak-Sign": sig}) if (anon := httpx.Client(base_url=BASE)) else None
        check(S, "replayed batch refused (409: sequence must increase)", rr.status_code == 409, rr.status_code)
        tsx = str(time.time())
        seq_next = int(me["last_seq"]) + 1 if me else 9999
        sig = hmac.new(secret, f"{tsx}\ntestnode-e2e\n{seq_next}\n{hashlib.sha256(body).hexdigest()}".encode(),
                       hashlib.sha256).hexdigest()
        rr = anon.post("/api/ingest", content=body, headers={
            "X-Rakshak-Sensor": "testnode-e2e", "X-Rakshak-Seq": str(seq_next),
            "X-Rakshak-Timestamp": tsx, "X-Rakshak-Sign": "0" * 64})
        check(S, "forged batch (bad HMAC) refused (401)", rr.status_code == 401, rr.status_code)
        rr = anon.post("/api/ingest", content=body, headers={
            "X-Rakshak-Sensor": "testnode-e2e", "X-Rakshak-Seq": str(seq_next),
            "X-Rakshak-Timestamp": str(time.time() - 900), "X-Rakshak-Sign": sig})
        check(S, "stale-timestamp batch refused (401, replay window enforced)", rr.status_code == 401,
              rr.status_code)
    finally:
        sensor.terminate()
    con = sqlite3.connect(DB)
    n_sess = con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    con.close()
    check(S, "sign-in sessions persist in the DB (restart no longer signs staff out)", n_sess >= 1, n_sess)
    for i in admin.get("/api/incidents").json():
        if i.get("node") == "testnode-e2e" and i["status"] != "resolved":
            analyst.post(f"/api/incidents/{i['id']}/resolve")

    ig = admin.get("/api/integrity").json()
    check(S, "final integrity: events and audit chains verify", ig["events"]["ok"] and ig["audit"]["ok"], ig)
    write_report(env)
    failed = [x for x in results if not x[2]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


def write_report(env):
    passed = sum(1 for r in results if r[2])
    lines = [
        "# RAKSHAK-AI live end-to-end check (sandbox functional test)", "",
        "> **What this is.** A functional test: real nginx, OpenSSH, Nmap and iptables running in an isolated sandbox, "
        "real log files, real HTTP and SSH traffic from test source addresses, and the real Rakshak console over its API. "
        "**What this is not.** It is not an accuracy measurement and says nothing about detection rates on production traffic. "
        "Items marked *simulated time* move a timestamp instead of waiting.", "",
        f"**Result: {passed} of {len(results)} checks passed.** Generated by `scripts/e2e_live_check.py`.", "",
        "## Environment", "", "| Item | Value |", "|---|---|",
    ]
    lines += [f"| {k} | {v} |" for k, v in env.items()]
    lines += ["| Test network | 10.99.0.0/29 on the loopback interface (sandbox only) |",
              "| Rakshak settings | mode=recommend, enforcer=iptables (chain RAKSHAK-BLOCK), RAKSHAK_TRUSTED=10.99.0.1 |", ""]
    section = None
    for sec, name, ok, obs in results:
        if sec != section:
            lines += ["", f"## {sec}", "", "| Check | Result | Observed |", "|---|---|---|"]
            section = sec
        obs = obs.replace("|", "/")
        lines.append(f"| {name} | {'PASS' if ok else '**FAIL**'} | {obs} |")
    OUT.write_text("\n".join(lines) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    sys.exit(main())
