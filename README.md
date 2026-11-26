# RAKSHAK-AI: offline security console for your own servers

**Team:** The Hopelesss Guys · started at CMR HACKFEST 4.0, Problem Statement 16

RAKSHAK-AI is a system SOC agent for one machine, offline: it covers web security **and** host security together.
It watches the real log files of a Linux server (web server and SSH) **and** the machine itself — protected config
files changing, new or removed user accounts, new processes listening on a port, and a brute-force run that ends in a
successful login — raises an alert when it sees an attack, explains it in plain words, and re-checks the live system
before calling any alert verified. For network attackers it can block the source at the server's firewall after a
person approves, and for what an attacker already *did* on the machine it can **undo it**: restore the tampered file
from its stored copy, kill the backdoor listener it started, lock or remove the account it created — each proposal is
approved by a person, executed, and **verified against the live system afterwards**. When a new attack pattern shows up
that no rule knows, it mines a candidate detection rule from the incident's own evidence and imports it through a
schema + live-sample gate, so detection improves offline. Optional sensor agents on other machines stream signed
events to it, so one console can cover several servers without any cloud service. It also runs
security tests against systems your organisation owns: built-in checks, Nmap, and tools you bring yourself, for example a
tool from GitHub copied to an offline machine. Every finding a tool reports is re-checked independently by Rakshak before
it is called **Confirmed**, and only confirmed findings appear as problems in reports. Everything runs on one machine with
no cloud service and no internet connection while it runs.

There is no demo data in this product. Every number on the dashboard comes from the log files and test runs on the
machine it is installed on.

## What is verified today

| Area | Status | Evidence |
|---|---|---|
| Watching nginx/Apache access logs and OpenSSH logs, alerts, evidence re-check | Working | live run on real nginx 1.24 and OpenSSH 9.6 logs |
| Host sensors: file-integrity watch, account changes, new listening ports, brute-force-then-login (credential compromise), each re-checked against the live system | Working | `docs/DEMO_SYSTEM_SECURITY.md` and section 12 of the live check |
| Sign-in, roles (viewer, analyst, admin), CSRF protection, localhost-only by default | Working | unit tests and live run |
| Blocking at the firewall with iptables, verified, with undo and expiry | Working | live run: blocked source got no answer, others still served |
| Root firewall helper that only allows Rakshak's own chain | Working | `docs/FIREWALL_HELPER_LIVE_TEST.txt` |
| Full response loop on a simulated attack: detect -> propose -> human approval -> firewall verification -> undo | Working | `docs/DEMO_REALTIME_RESPONSE.md` (attack to verified block in under 1 second) |
| Undo what an attacker did: restore tampered files from the content vault, kill the listener they opened, lock or remove the account they made — each with a signed proposal, human approval and a live after-check | Working | section 13 of the live check (restore matched the pre-attack hash, killed port refuses connections, locked account cannot log in) and `docs/DEMO_SYSTEM_SECURITY.md` |
| Adapt to new attack patterns offline: mine a draft rule from an incident's evidence, import rule packs through a schema + positive/negative sample gate, matched variants re-alert immediately | Working | 86% -> 100% detection on a labelled sandbox corpus after **one** imported pack (`docs/ACCURACY_RESULTS.md`) and section 14 of the live check |
| Multi-machine ingestion: sensor agents stream HMAC-signed batches to the hub, replayed/forged/stale batches refused, incidents are node-aware | Working | section 15 of the live check (409 replay, 401 forged, 401 stale, node-named incident) |
| Restart-proof admin sessions and settings from a file (`rakshak.conf`) instead of only environment variables | Working | unit tests and section 15 of the live check |
| Security tests: scope file, tool hash pinning, per-run approval, independent re-checks | Working | live run with website check, Nmap 7.94 and an external example tool |
| Tamper detection for log evidence, audit trail, test records and tool files | Working | live run edits a record, sees the refusal, then restores |
| nftables blocking | Built, unit-tested only | the build sandbox kernel cannot create nftables tables |
| Native Windows / multi-OS collection | Planned | Linux sensors today; see `ENTERPRISE_PLAN.md` |
| Accuracy on real production traffic | **Not measured yet** | needs a pilot (see `ENTERPRISE_PLAN.md`) |
| Single sign-on, MFA, full plugin sandbox, local LLM, many servers | Planned | `ENTERPRISE_PLAN.md` |

Latest results: 117 of 117 automated tests pass (`docs/TEST_RESULTS.txt`). The live end-to-end check — which now includes
a system-security section that tampers with a watched file, opens and closes a real listening port, and forces a
password-guessing run that ends in a real SSH login; a remediation section that restores the file, stops the listener
and locks/removes an attacker account **through the console itself and verifies each undo against the live system**;
an adaptation section that imports rule packs through the gates and catches a new pattern; and a sensor section that
streams signed batches from a second machine — passed 143 of 143 checks (`docs/E2E_LIVE_RESULTS.md`). Its first
run with these checks passed 95 of 96 and found one real bug (a reverted file could not downgrade its own alert
because the file's timestamp alone was treated as evidence); the fix and its regression test are in place. The phase-2
sections' first run passed 131 of 139 and the follow-ups found three more issues (all in the test environment or the
check script itself, one real helper bug fixed); each is documented in `docs/DEV_NOTES.md`. The earliest
run of all passed only 65 of 72 checks and found seven real bugs; that run is kept in
`docs/E2E_LIVE_RESULTS_run1_before_fixes.md`, and each bug now has a regression test.

---

## 1. Install and first start (Linux)

You need Linux (tested on Ubuntu 24.04), Python 3.10 or newer (tested with 3.12) and, optionally, `nmap`. Node.js is only
needed if `frontend/dist` is missing; the dashboard ships pre-built.

```bash
RAKSHAK_LOGS=/var/log/nginx/access.log,/var/log/auth.log ./run.sh
```

On the first start `run.sh` creates the Python environment, creates `data/scope.yml` (empty, so no test can run yet) and
asks you to create the first administrator. Passwords must be 14 to 256 characters. Then open **http://127.0.0.1:8000**
and sign in. The account that runs Rakshak must be able to read the log files; on Ubuntu, add it to the `adm` group.

**Installing on a machine without internet.** On a machine with internet and the same Linux and Python version, run
`pip download -r requirements.txt -d wheelhouse`, then copy the whole folder, including `wheelhouse/`, by USB. `run.sh`
installs from `wheelhouse/` automatically when it exists.

**Using it from another computer.** The dashboard listens only on 127.0.0.1. The safe way in is an SSH tunnel:
`ssh -L 8000:127.0.0.1:8000 you@server`, then open http://127.0.0.1:8000 on your own computer. To serve it on the
network, put a TLS reverse proxy in front and set `RAKSHAK_ALLOW_REMOTE=1`, `RAKSHAK_COOKIE_SECURE=1` and
`RAKSHAK_ALLOWED_HOSTS`.

**More accounts.** `./.venv/bin/python -m rakshak.admin priya --role analyst`. The password is typed at a hidden prompt,
never on the command line. Use `--replace` to reset a password.

| Role | Can do |
|---|---|
| viewer | see everything: alerts, tests, reports, protection, integrity status |
| analyst | everything a viewer can, plus re-check evidence, approve or undo blocks, resolve alerts, request tests, approve tests whose tool allows it, create reports, read the activity log |
| admin | everything an analyst can, plus enable or disable tools, approve tests that need an admin, switch between Ask-me-first and Auto-block |

Sessions last one hour. Five wrong passwords from one address pause sign-in for five minutes.

**Log history.** On its first start Rakshak begins at the *end* of each log file, so old lines do not create a burst of
stale alerts. After that it remembers its position (`data/log_offsets.json`) and continues where it stopped, including
across log rotation. To import existing history once, start with `RAKSHAK_READ_EXISTING=1`.

**Host sensors (system security).** Besides log lines, Rakshak scans the machine itself every
`RAKSHAK_HOSTSEC_INTERVAL` seconds: the fingerprint of each watched file (content hash when readable, otherwise
size + owner + permissions), the user and group tables, and the list of listening ports. The first scan records a
baseline and raises nothing — it will not invent history from before it was installed. A change raises an alert only
when it is still present when re-checked against the live system; a file that was reverted (an authorised admin fixed
it) makes the alert downgrade to *Suspected* with the reason recorded, instead of pretending nothing happened.
Repeated failed logins from one address ending in a **successful** login are treated as a credential compromise
(critical). Host alerts deliberately never propose a firewall block — there is no attacker address to block — the
console explains what changed, shows the before/after fingerprints, and tells a person what to check.

## 2. Tell Rakshak what you own: `data/scope.yml`

No security test can run against anything that is not listed here. An empty or broken file refuses everything and the
Security tests page says why.

```yaml
networks: [10.20.0.0/24, 10.20.1.15/32]   # your own address ranges
hosts: [intranet.example.internal]          # host names you own (each address it resolves to must be inside networks)
never_scan: [10.20.0.1/32]                  # gateways and fragile systems: always refused, even inside networks
```

Rakshak also refuses, at all times, any address it has flagged or blocked as an attacker: it never scans back. Test
targets are resolved when the test is requested and again at approval; if the address changed, the test is refused.
The website check accepts only numeric-IP addresses such as `http://10.20.0.15:8080/`, which prevents DNS tricks.

## 3. The pages

| Page | Question it answers |
|---|---|
| Home | Is anything wrong right now? Can Rakshak read its logs? Is blocking connected to the firewall? If Rakshak cannot read any log it says so and does not show "safe". |
| Alerts | What happened, why it matters, what Rakshak did, what you should do, the exact log lines, and whether the evidence re-check passed. |
| Security tests | The four-step test flow, your scope, the tools, requests waiting for approval, and every result with its re-check. |
| Protection | Ask-me-first or Auto-block, who is blocked now, when blocks expire, and the signed history of every block and undo. |
| Memory | Everything done so far in one timeline: each detected threat, each response (block, refusal, undo, expiry) and each security test, newest first, filterable by type, range or search. Computed live from the same signed records the other pages show - there is no separate memory table that could be edited or drift. |
| Activity log | Who did what, with a check that the record has not been edited. |
| Guide | The full manual inside the app: first-time setup, every option explained, the principles enforced in code, how detection actually works, the validation loop, and the honest limits. |
| Learn | Security words explained for people who are new to them. |

Screenshots taken from the live sandbox run are in `docs/screens/`. Sample reports from the same run are in
`docs/samples/`.

## 4. How a security test runs, and why its results can be trusted

1. **An admin enables a tool.** Rakshak records the exact SHA-256 fingerprint of the tool file and of its `plugin.yml`.
   Every tool starts disabled, and tools you add yourself are not even listed unless `RAKSHAK_ALLOW_EXTERNAL_PLUGINS=1`.
2. **Someone requests a test.** They choose the target, write why it is needed and confirm that the organisation owns it
   and has authorised the test. The target is checked against `scope.yml`, and the request is signed and stored.
3. **An approver approves it.** Rakshak checks again that the request record is unchanged, the tool and manifest
   fingerprints are unchanged, the target still resolves to the same in-scope addresses, and the approver is allowed to
   approve. Tools marked `approval: admin` need an admin. With `RAKSHAK_TWO_PERSON=1`, nobody can approve their own request.
4. **The tool runs.** There is no shell; the argument list is fixed in `plugin.yml`, and only `{target}` is filled in.
   The tool runs with a clean environment, its own working folder, and limits on time, CPU, memory, file size and output.
   Only one test runs against a given machine at a time.
5. **The output is checked.** A strict parser reads the output; anything malformed or oversized is rejected rather than
   guessed at. A tool cannot mark its own findings as confirmed.
6. **Every reported problem is re-checked by Rakshak.** It uses its own new connection or request; for example, it opens
   a fresh TCP connection to each port the tool says is open. The result gets one of these labels:

| Label | Meaning |
|---|---|
| Confirmed | the tool saw it **and** Rakshak's own re-check saw it again; only these appear as problems in the report |
| Not reproduced | the tool reported it but the re-check did not see it; listed for transparency, not counted as a problem |
| Could not check (inconclusive) | no reliable observation was possible, for example the page did not answer or no re-check exists for this kind of finding |
| Looked fine (observed pass) | this specific check looked fine this time; this is never presented as proof that a system is secure |

The full record (who requested and approved it, command, tool fingerprint, output fingerprint, findings) is signed. A
report is refused if the signature no longer matches.

## 5. Connect your own tool (local or from GitHub)

A tool is a folder inside `RAKSHAK_PLUGINS_DIR` (default `./plugins`). The folder name must equal the tool's `id`. A
complete, tested example is in `examples/plugins/tcp-connect-check/`.

1. **Bring the tool to the offline machine.** On a machine with internet, clone the GitHub repository at a specific
   release or commit, build it, compare it with the project's published checksum if there is one, and copy it by USB.
   Write the repository URL and commit into `source:` so reviewers know exactly what it is.
2. **Create the folder** with `plugin.yml` and, usually, a small `wrapper.py` that runs the tool and converts its output
   into Rakshak findings.
3. **Pin the fingerprint.** Run `sha256sum wrapper.py` (or the binary) and put the value in `sha256:`.
4. **Start Rakshak with** `RAKSHAK_PLUGINS_DIR=/path/to/plugins RAKSHAK_ALLOW_EXTERNAL_PLUGINS=1`.
5. **An admin reviews it on the Security tests page** (exact command and fingerprints) and enables it.
6. **Request a test, then approve it.**

`plugin.yml` fields (unknown fields are refused):

| Field | Allowed values and meaning |
|---|---|
| `id` | 2 to 41 characters: lowercase letters, digits and dashes; must equal the folder name |
| `name`, `version`, `description`, `source` | shown to reviewers; `source` should be the repository URL and commit |
| `kind` | `active` (sends traffic to the target; always needs per-run approval) or `passive` |
| `approval` | `admin` (only an admin may approve each run) or `self` (any analyst may) |
| `interpreter` | empty (run `executable` directly) or `python` (run a script inside the tool folder with Rakshak's Python in isolated mode) |
| `executable` | script name in the folder, an absolute path, or a program name found on the system path |
| `sha256` | expected fingerprint of `executable`; if it does not match, the tool is refused |
| `target_type` | `host` (numeric IP or listed host name, inside scope), `url` (numeric-IP URL) or `none` |
| `args` | fixed list of strings; only `{target}` is substituted |
| `timeout_s`, `max_output_kb` | 1 to 3600 seconds; 1 to 8192 KB |
| `parser` | `json_findings`, `nmap_xml` or `text` |
| `validator` | `tcp_open` (Rakshak re-opens the port itself) or `none` |

The tool prints one JSON document on standard output and exits with code 0:

```json
{"findings": [
  {"id": "TCP-8081", "title": "TCP port 8081 accepts connections", "severity": "medium", "passed": false,
   "evidence": "connect to 10.20.0.15:8081 succeeded", "fix": "Close it if not needed",
   "recheck": {"kind": "tcp_open", "port": "8081"}},
  {"id": "TCP-23", "title": "Telnet port closed", "severity": "info", "passed": true}
]}
```

**What can become Confirmed.** In this version, a finding from your own tool can be confirmed only by the `tcp_open`
re-check, as in the example. Findings that no Rakshak re-check covers, such as a vulnerability-scanner match, are shown
as *Could not check*, never as Confirmed. This is deliberate: "validate every result before reporting it" would be
false otherwise. More re-checks (for example repeating a scanner's exact request) are planned in `ENTERPRISE_PLAN.md`.

**Wrapping a separate binary.** Rakshak pins the file named in `executable`. If your wrapper calls another program (for
example a Go tool built from GitHub), check that program's fingerprint inside the wrapper before running it. Template
(not tested; adapt it to your tool):

```python
import hashlib, json, subprocess, sys
from pathlib import Path
TOOL = Path(__file__).with_name("mytool")          # the binary you built and copied
EXPECTED = "paste the sha256 of mytool here"
if hashlib.sha256(TOOL.read_bytes()).hexdigest() != EXPECTED:
    sys.exit("mytool fingerprint changed")           # non-zero exit: Rakshak accepts no findings
raw = subprocess.run([str(TOOL), "--json", sys.argv[1]], capture_output=True, text=True, timeout=300, check=True)
findings = [{"id": f"MYTOOL-{i}", "title": item["name"], "severity": "medium", "passed": False,
             "evidence": item.get("detail", "")} for i, item in enumerate(json.loads(raw.stdout))]
print(json.dumps({"findings": findings}))
```

Two built-in tools ship disabled: **Website safety observations** (security headers, server version, HTTP or HTTPS,
cookie flags, exposed secret files, reflected input, database error text; all requests are harmless and size-limited)
and **Open port check (Nmap)**, which runs `nmap -Pn -sT --top-ports 100 --open -oX - <target>` and re-checks every open
port.

## 6. Blocking attackers at the firewall

Rakshak starts in **Ask me first** mode: it proposes a block, and nothing happens until an analyst approves it. **Auto-block**
(admin only) blocks high or critical alerts by itself, and only when an attack rule or a fixed behaviour limit (such as
8 failed logins in 60 seconds) matched and the evidence re-check passed; it never blocks on the unusual-behaviour model alone. Every block expires (`RAKSHAK_BLOCK_TTL`, default 24 h) and can be
undone. Rakshak never blocks loopback or link-local addresses, `RAKSHAK_NEVER_BLOCK` addresses or `RAKSHAK_TRUSTED`
addresses.

By default (`RAKSHAK_ENFORCER=none`) blocks are only recorded, and the dashboard says so plainly. It never claims a
block it did not apply. To apply blocks with **iptables** (tested live), an administrator does this once as root:

```bash
iptables -N RAKSHAK-BLOCK && iptables -I INPUT 1 -j RAKSHAK-BLOCK          # same with ip6tables for IPv6
install -o root -g root -m 0755 deploy/rakshak-fw /usr/local/sbin/rakshak-fw
echo 'rakshak ALL=(root) NOPASSWD: /usr/local/sbin/rakshak-fw' > /etc/sudoers.d/rakshak
chmod 0440 /etc/sudoers.d/rakshak && visudo -c
```

Then start Rakshak with:

```bash
RAKSHAK_ENFORCER=iptables \
RAKSHAK_IPTABLES_CMD="sudo -n /usr/local/sbin/rakshak-fw 4" \
RAKSHAK_IP6TABLES_CMD="sudo -n /usr/local/sbin/rakshak-fw 6" ./run.sh
```

`rakshak-fw` accepts only listing the chain, checking the jump, and adding, checking or removing a single-address DROP
rule inside `RAKSHAK-BLOCK`. Every add or remove is verified with `iptables -C` before the dashboard shows "Blocked at
firewall". Expiry is done by Rakshak while it runs; blocks stay in place if Rakshak is stopped.

For **nftables**, an administrator creates the table once, using the definition in `rakshak/enforcer.py` (`SETUP`),
then sets `RAKSHAK_ENFORCER=nftables` and `RAKSHAK_NFT_CMD`. This path has unit tests only.

**Important:** put the addresses your own security tests come from into `RAKSHAK_TRUSTED`. Otherwise Rakshak sees its
own website check in the web log, flags that address as an attacker and from then on refuses to test it.

## 7. Settings

All settings are environment variables. A commented example is in `deploy/rakshak.env.example`.

| Variable | Default | Meaning |
|---|---|---|
| `RAKSHAK_DATA` | `./data` | database, signing key, reports, `scope.yml` (keep it mode 700 and back it up) |
| `RAKSHAK_LOGS` | `/var/log/auth.log` | comma-separated log files to watch |
| `RAKSHAK_MODE` | `recommend` | `recommend` (Ask me first) or `auto` |
| `RAKSHAK_HOST`, `RAKSHAK_PORT` | `127.0.0.1`, `8000` | dashboard address |
| `RAKSHAK_ALLOW_REMOTE` | `0` | `1` allows a non-loopback address (TLS proxy first) |
| `RAKSHAK_COOKIE_SECURE` | `0` | `1` when served over HTTPS |
| `RAKSHAK_ALLOWED_HOSTS` | none | extra accepted Host header names |
| `RAKSHAK_TRUSTED` | none | source addresses never treated as attackers (include your scanner) |
| `RAKSHAK_NEVER_BLOCK` | none | addresses or ranges that are never blocked |
| `RAKSHAK_BLOCK_TTL` | `86400` | seconds until a block expires (`0` = never) |
| `RAKSHAK_ENFORCER` | `none` | `none`, `iptables` or `nftables` |
| `RAKSHAK_IPTABLES_CMD`, `RAKSHAK_IP6TABLES_CMD` | `iptables`, `ip6tables` | commands used for blocking (see section 6) |
| `RAKSHAK_NFT_CMD` | `nft` | command used for nftables |
| `RAKSHAK_PLUGINS_DIR` | `./plugins` | folder with your own tools |
| `RAKSHAK_HOSTSEC_INTERVAL` | `30` | seconds between host sensor scans (`0` turns them off) |
| `RAKSHAK_FIM_PATHS` | passwd, shadow, group, sudoers, sshd_config, your `authorized_keys` | comma-separated files or folders watched for changes |
| `RAKSHAK_ALLOW_EXTERNAL_PLUGINS` | `0` | `1` lists and allows your own tools |
| `RAKSHAK_TWO_PERSON` | `0` | `1`: the requester can never approve their own test |
| `RAKSHAK_PLUGIN_USER` | none | run tools as this OS user (only when Rakshak itself runs as root) |
| `RAKSHAK_ORG` | `Your organisation` | name printed on reports |
| `RAKSHAK_READ_EXISTING` | `0` | `1`: on first start read existing log history |
| `RAKSHAK_TRUST_MODEL` | `0` | `1`: load a saved anomaly model file (only one you created yourself) |
| `RAKSHAK_ACCT_CMD` | `usermod`/`userdel` directly | hardened account helper for remediation, e.g. `"sudo -n /usr/local/sbin/rakshak-acct"` (recommended: uid and denylist guards live inside the helper) |
| `RAKSHAK_NEVER_LOCK` | service accounts | extra account names no remediation may ever lock or remove |
| `RAKSHAK_CONF` | `./rakshak.conf` or `data/rakshak.conf` if present | optional `KEY=VALUE` settings file (same names as above; environment still wins) |
| `RAKSHAK_SENSOR_NAME` | hostname | label a sensor agent uses when streaming events to a hub |
| `RAKSHAK_HUB_URL`, `RAKSHAK_SENSOR_SECRET`, `RAKSHAK_SENSOR_INTERVAL` | hub `http://127.0.0.1:8000`, none, `3` | settings of the **sensor agent** (`python -m rakshak.sensor`); the hub key comes from `python -m rakshak.admin sensor-secret` |

Sessions are stored in the database, so restarting the console no longer signs everyone out (logout and expiry still
end them). Imported rule packs live in `data/rules/imported/` (active) and `data/rules/drafts/` (proposals that do
nothing until an admin imports them through the gate); both folders are reloaded without a restart, and the activated
folder is itself watched by the file-integrity sensor.

## 8. Running it as a service

`deploy/rakshak.service` is a systemd unit **template** (it could not be tested in the build sandbox, which has no
systemd). It runs Rakshak as a dedicated `rakshak` user with read-only code, a private data folder in `/var/lib/rakshak`
and settings from `/etc/rakshak/rakshak.env`. The setup commands are listed at the top of the file.

## 9. Check it yourself

```bash
PYTHONPATH=. .venv/bin/python -m pytest -q                 # 117 automated tests
PYTHONPATH=. .venv/bin/python scripts/accuracy_benchmark.py  # regenerates docs/ACCURACY_RESULTS.md
```

`scripts/e2e_live_check.py` repeats the full live check against a running console and real software. It refuses to start
without `--i-own-this-test-environment` because it sends attack-like traffic. The environment it expects (test addresses,
nginx sites, sshd, scope) is described at the top of the script; `scripts/reset_sandbox_data.sh` creates a clean data
folder for it. `scripts/firewall_helper_live_check.sh` repeats the firewall-helper check.
`scripts/attack_response_demo.py` and `scripts/host_security_demo.py` replay the two story demos end to end
(network attack to verified firewall block, and host persistence to verified remediation) and regenerate
`docs/DEMO_REALTIME_RESPONSE.md` and `docs/DEMO_SYSTEM_SECURITY.md` with fresh timings and screenshots.

## 10. Limitations of this version

* **Plugins are limited, not fully sandboxed.** A tool runs with time, CPU, memory, file and output limits and a clean
  environment, but as the same OS user as Rakshak, with normal network and file access. A malicious tool could read
  what that user can read, or call the firewall helper. Only enable tools you have reviewed. Network and filesystem
  isolation is planned.
* **Single server and local accounts only.** There is no SSO or MFA yet. Sessions are stored in the database and
  survive a restart. A sensor
  agent (`python -m rakshak.sensor --hub URL`) can stream events from other machines into one console, which is the
  first form of multi-server coverage - but enforcement (firewall, remediation) still happens only on the hub machine.
  Data is SQLite on the hub.
* **Detection is rules plus behaviour limits.** For example, 8 failed logins from one address within 60 seconds is
  flagged. The unusual-behaviour model is off until trained on your own traffic. Standard access logs do not contain
  POST bodies, so attacks hidden in form bodies are not seen without extra logging. **Detection accuracy on real
  production traffic has not been measured.**
  New patterns can now be added offline (evidence-mined drafts and gated rule-pack imports), but accuracy so far is
  measured only on a labelled sandbox corpus (`docs/ACCURACY_RESULTS.md`), not on production traffic or a public
  dataset such as CIC-IDS2017.
* **The host sensors see changes, not people.** They notice that a watched file, an account table, or the listening-port
  list changed — not who made the change. Process-level attribution (which PID touched which file) needs root and an
  audit subsystem and is planned. Until then the console says so plainly instead of guessing.
  (For network sockets it is now exact: a listener is found through the `/proc` socket inode before it is stopped.)
* **The file-integrity baseline starts when Rakshak first runs**, so tampering done before installation is not caught.
  Root-owned files (for example `/etc/shadow`) are compared by metadata only when Rakshak cannot read them.
* **Undo is possible only where evidence exists to undo with.** A file can be restored only if Rakshak held a readable
  copy of its previous content (the vault); for root-owned or never-readable files the console refuses instead of
  guessing. Killing a process and locking or removing an account are offered only for what this incident created,
  never for pre-existing ones, and root-owned file restore is refused by design unless a helper is configured. The
  account helper enforces uid ranges and a denylist (root and service accounts can never be locked).
* **The "bot or AI" estimate is a behaviour heuristic.** It is not proof of who or what is attacking.
* **The website check is small.** It runs a handful of harmless checks, not a full scanner, and accepts numeric-IP
  targets only. It verifies HTTPS certificates against the system's public trust store, so sites with an internal or
  self-signed certificate show "Could not check".
* **Explanations come from a built-in offline knowledge base.** No language model is connected yet.
* **Reports are drafts for a responsible person to review.** Nothing is sent to CERT-In or anyone else automatically.
* **Linux only.** Native Windows is not supported; use WSL2 or a Linux virtual machine.

## 11. Project layout

```
rakshak/                 Python engine (api.py is the entry point)
  detect/                rules, behaviour limits, anomaly model, automation estimate
  rules/                 YAML attack rules (add your own .yml and restart)
  plugins/               test runner: manifest, scope, executor, parsers, re-checks, built-in tools
  auth.py, admin.py      accounts, sign-in (sessions persist in the DB), sensor-key helper
  engine.py, hostsec.py, responder.py, remediate.py, enforcer.py, store.py, audit.py, report.py
  rulecraft.py           rule-pack validation gate + evidence-mined draft rules
  sensor.py              sensor agent for other machines (streams signed events to the hub)
  config.py              environment + rakshak.conf settings
frontend/                React dashboard (src/ = source, dist/ = built and served by api.py)
examples/plugins/        tested example of an external tool
deploy/                  firewall helper, account helper, systemd template, example settings
scripts/                 live end-to-end check, accuracy benchmark and sandbox helpers
tests/                   automated tests
docs/                    test results, screenshots and sample reports from the sandbox run
ENTERPRISE_PLAN.md       roadmap to multi-server, international deployment
```
