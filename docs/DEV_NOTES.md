# DEV NOTES (internal progress log)

## External sources used
- CERT-In Directions 28 Apr 2022, Annexure I: https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf (text /home/ubuntu/ps16/src/certin.txt)
- Python subprocess docs: preexec_fn NOT safe with threads; use start_new_session, user/group/extra_groups=() : https://docs.python.org/3/library/subprocess.html
- OWASP SSRF Prevention Cheat Sheet: validate RESOLVED IPs against allowlist, connect only to validated IP (DNS rebinding), no redirects, rebuild requests: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

## State at 26 Nov 2026 ~13:30 IST
Built and tested (34 pytest tests pass):
- config.py (env settings, recommend default, 127.0.0.1 bind, RAKSHAK_ALLOW_REMOTE), auth.py (PBKDF2 600k, roles viewer/analyst/admin, CSRF header X-RAKSHAK-CSRF, 1h sessions, 5-fail throttle), admin.py (python -m rakshak.admin user --role admin; getpass)
- audit.py (hash chain + HMAC), store.py (plugin_runs, plugin_state, users, audit, migrations)
- plugins/: manifest.py, scope.py (strict fail-closed, every resolved IP must be in networks, attacker IPs refused), executor.py + _launch.py (no shell, rlimits, timeout, caps), findings.py, validators.py (tcp_open, http_recheck builtin only), webchecks.py, runner.py (enable pins hashes, request queued, approve verifies signature, admin approval, two-person, DNS pin), builtin/website-check, builtin/nmap-ports
- engine.py: resumes from data/log_offsets.json; default start at END of file (RAKSHAK_READ_EXISTING=1 to backfill); validate_incident; report refuses broken chain or tampered actions; expiry every 15 s
- responder.py: verify signature + alert still open before approve; cancel_pending on resolve; NoEnforcer undo clears record
- enforcer.py: none | nftables | iptables (chain RAKSHAK-BLOCK, admin creates chain+jump; verified with -C)
- api.py: all routes auth; TrustedHost; CSP etc.; /api/runs*, /api/plugins*, /api/audit, /api/integrity
- frontend: Login, Layout, Home (blind state, sources, enforcer), Alerts, AlertDetail (evidence card, report), Tests, RunDetail, Protection, Activity, Learn. WebsiteCheck.jsx deleted. Build OK.

## Sandbox test environment (real software, sandbox only)
- loopback addrs 10.99.0.1-6; nginx 10.99.0.1:8081 plain, :8082 leaky (.env fixture), :8083 catch-all; sshd 10.99.0.1:2222 -E /var/log/rakshak-test/sshd.log
- nftables tables NOT supported by this kernel; iptables-legacy works (verified drop). Chain RAKSHAK-BLOCK + INPUT jump created.
- data/ fresh (old lab data moved to /home/ubuntu/rakshak_backup_lab_era/), data/scope.yml networks [10.99.0.0/29], never_scan [10.99.0.4]
- test accounts in /home/ubuntu/rk_test_credentials.txt (secadmin admin, analyst1, viewer1) - NOT shipped
- start: RAKSHAK_LOGS=/var/log/rakshak-test/nginx_access.log,/var/log/rakshak-test/sshd.log RAKSHAK_MODE=recommend RAKSHAK_ENFORCER=iptables RAKSHAK_IPTABLES_CMD="sudo -n /usr/sbin/iptables" RAKSHAK_TRUSTED=10.99.0.1 RAKSHAK_BLOCK_TTL=3600 .venv/bin/python -m rakshak.api
- webdev init refused (nonempty dir): deliver as offline zip, no hosting.

## Next
## Live end-to-end results (26 Nov 2026, 13:51 IST)
Done: tests/test_review_fixes.py and scripts/e2e_live_check.py. Live run 1 = 65/72 (kept in docs/E2E_LIVE_RESULTS_run1_before_fixes.md).
Bugs found by the live run and fixed: gzip double-decode in webchecks._request; 404 on a secret-file path was "inconclusive";
an inconclusive first observation was upgraded to "confirmed" by the validator; nmap's bare DOCTYPE was refused and open-port
findings lacked the passed flag; brute-force incident said events=3 for 10 failures (now counts the window); PDF lacked re-check evidence.
Regression tests: tests/test_live_found_bugs.py (+ fixture tests/fixtures/nmap_real_7.94.xml). 56 pytest tests pass.
Data reset (run 1 data in /home/ubuntu/rakshak_backup_lab_era/data_e2e_run1_*), accounts recreated; DB file is now mode 0600.
Live run 2 = 72/72 (docs/E2E_LIVE_RESULTS.md). Console service job_RZBUK88A is running. scanner.py removed (unused).

## Next
DONE 14:20: live run 4 (81/81, includes new section 11 external plugin); scripts/rerunnable cleanup at start.
Dashboard wording fixes: "Blocked right now" card, per-run reason = authorised_statement (kept on refused records too).
deploy/rakshak-fw (validated root helper for iptables; live tested -> docs/FIREWALL_HELPER_LIVE_TEST.txt; 23 unit tests).
deploy/rakshak.service + rakshak.env.example (templates, systemd untestable here). run.sh rewritten + first-run tested in a
throwaway copy (creates scope, prompts admin, refuses short passwords, starts clean); run.bat now states Windows unsupported.
README rewritten for real deployments (314 lines; verified-status table; plugin how-to incl. GitHub import + wrapper template
for third-party binaries; RAKSHAK_TRUSTED warning). ENTERPRISE_PLAN sections 0/1/3/4/5/7 updated with DONE/PARTIAL/PLANNED truth.
Data-file permissions 0600 (store db, engine offsets, config mkdir 0700). Lab-era docs/screens replaced with real
sandbox screenshots; docs/samples/ has real incident + test-run PDFs; sample_incident_report_ai_bot.pdf deleted.
TODO.md marked with open gates. Final pass 08:50 UTC: fresh data, live run 81/81 on final code, helper test refreshed,
TEST_RESULTS.txt (79 pass), 9 screenshots and both sample PDFs regenerated from the final DB, RAKSHAK-AI.zip rebuilt
(175 files; excludes .venv, node_modules, data/, caches; verified: no credentials, no data files; includes deploy
templates, examples plugin, all docs evidence). Console now job_HXGZnSIL.

## 26 Nov ~14:45 IST: Memory + Guide + browser preview
New /api/memory endpoint (no own table; merges signed incidents/actions/runs, newest first, kind/days/limit filters;
viewer-readable; tests in test_api.py: empty state, order, counts, filters, 400 bad kind, 401 unauthenticated, viewer OK).
Frontend: pages/Memory.jsx (timeline by day, chips per kind, search, Evidence links, plain-word mode chips) and
pages/Guide.jsx (9 sections: start, setup, every option, principles, detection, validation, plugins, responses, limits);
nav History/Compass. 80 tests pass; frontend rebuilt.
Preview for the user: console job_QEwNTaQM on 0.0.0.0 via RAKSHAK_ALLOW_REMOTE=1 + RAKSHAK_COOKIE_SECURE=1 +
RAKSHAK_ALLOWED_HOSTS=8000-ikm6e2b255m7y2chxvkr1-03a69602.sg2.manus.computer; verified https health 200, index 200,
data route 401, evil Host 400; Playwright login through the preview works, screenshots 09/10/11 taken that way.
PREVIEW IS TEMPORARY: stop with job kill when done; production guidance unchanged (localhost only).

## Test console quick reference (sandbox)
creds file: /home/ubuntu/rk_test_credentials.txt (never ship). Reset: scripts/reset_sandbox_data.sh <creds>.
Start console: see README or RAKSHAK_PLUGINS_DIR=examples/plugins RAKSHAK_ALLOW_EXTERNAL_PLUGINS=1 +
RAKSHAK_LOGS=/var/log/rakshak-test/*, RAKSHAK_ENFORCER=iptables, RAKSHAK_IPTABLES_CMD="sudo -n /usr/local/sbin/rakshak-fw 4",
RAKSHAK_IP6TABLES_CMD="sudo -n /usr/local/sbin/rakshak-fw 6", RAKSHAK_TRUSTED=10.99.0.1.
Live checks: scripts/e2e_live_check.py --i-own-this-test-environment; scripts/firewall_helper_live_check.sh.

## 26 Nov ~15:15 IST: 502 fix + landing redesign + real-time response demo
User saw 502 + "passwords not working": the plain service job died silently (sandbox recycled; upstream IP changed
192.168.53.225 -> 192.168.181.151). Fix: console now runs under an until-loop supervisor (job_ZVoRW98M, log
/tmp/rakshak_console.log, auto-restarts in 3 s). Verified: health 200 via preview + all three account logins 200.
Secure-cookie note: with RAKSHAK_COOKIE_SECURE=1, httpx clients over http:// drop the session cookie (browsers on
127.0.0.1/https are fine); scripts/e2e_live_check.py and the demo re-arm the cookie from Set-Cookie explicitly.
Login.jsx redesigned as split landing (hero: offline agent, detects/responds; facts only, no live data) - served as
index-7de55db8.js; docs/screens/00_sign_in.png replaced.
NEW scripts/attack_response_demo.py (runs under venv python): live attack 8xSQLi from 10.99.0.6 -> detect +0.5 s ->
proposal (traffic still 200 = proposal blocks nothing) -> analyst1 approves -> rakshak-fw applies, verified via -C,
attacker now 000, neighbour 200 -> undo restores -> Memory + integrity ok. Full evidence docs/DEMO_REALTIME_RESPONSE.md
+ docs/screens/demo/{12..15}. E2E re-run after all changes: 81/81, 80 unit tests. ENTERPRISE_PLAN Windows row expanded
with the planned native-agent milestone (Event Log/IIS + WFP adapter), explicitly not started.

## 26 Nov ~16:10 IST: System SOC layer (hostsec)
User reminder: RAKSHAK is a system SOC (detect/analyze/respond on the HOST), not only web attacks. Built + verified live.
- NEW rakshak/hostsec.py: scans every RAKSHAK_HOSTSEC_INTERVAL s (default 30, 0=off; test env uses 5).
  (a) FIM: state_sig = sha256(content) when readable else (size,mode,uid,gid). mtime DELIBERATELY EXCLUDED:
      a reverted file must compare equal to the recorded original so the alert can downgrade to Suspected.
      (e2e run 2 caught the old mtime-based version: 95/96; fix = state_sig, regression test added.)
      Baseline recorded on first scan -> no alerts for pre-install history (limit disclosed everywhere).
      scope.yml + rakshak/rules/*.yml auto-added to watch list in Config.__post_init__.
  (b) Accounts diff /etc/passwd + /etc/group: HOST-ACC-001 new user (critical if uid 0), -002 removed, -003 changed,
      -004 extra uid-0, -005 new sudo/wheel member. Overridable files for tests: RAKSHAK_PASSWD_FILE/GROUP_FILE.
  (c) Listeners: /proc/net/tcp+tcp6 state 0A (RAKSHAK_PROC_NET_FILES override); HOST-LISTEN-001 new listener = high.
      Own console port exempt; engine also delays the FIRST host scan 5 s so uvicorn's port is IN the baseline
      (prevents self-alert on 8000, seen live).
  State: data/hostsec_state.json mode 0600. recheck(inc) compares live system vs detection["before"]/["found"] snapshots.
- engine.py: _host_loop thread; _host_finding -> chained event kind=host source_ip="system", incident create/merge on
  same (category, object), audit hostsec.finding, validate_incident immediately; NO responder call (no IP to block).
  validate_incident source=="system" -> _validate_host (live recheck; evidence_checked only if still present + chain ok).
  _cred_hit: >=5 rejected ssh_login from an IP within 300 s + one accepted from same IP -> SSH-CRED-001
  credential_compromise CRITICAL. Applied symmetrically in process() and in the validate_incident row loop.
- parsers.py accepts "Accepted password|publickey for ..."; knowledge.py + 4 categories (file_integrity T1554,
  account_change T1136, new_service T1571, credential_compromise T1110) with CERT-In mapping.
- api.py: /api/overview -> hostsec {interval_s, baselined, watching counts} + hostsec_alive; /api/memory kind=system.
- Frontend (dist index-f4a1f1cd.js): AlertDetail host view (story, before/after hashes, "nothing to block" panel),
  Home "System security sensors" panel, Memory "System changes" chip, Login hero now says system + web defence.
- Tests: tests/test_hostsec.py (7) + tests/test_credentials.py (5) -> 92 total. e2e section 12 adds 15 live checks
  (96 total; run3 = 96/96 incl. real listener 127.0.0.1:14000+rand, real block approval for 10.99.0.6 after
  credential_compromise via ~/.ssh/authorized_keys trick: root sshd fixture accepts ubuntu keys; file restored after).
- Demos: NEW scripts/host_security_demo.py -> docs/DEMO_SYSTEM_SECURITY.md + screens 16-19 (ran clean, 4.5 s detect).
  attack_response_demo.py fix: found() must pick the NEWEST non-resolved incident for the test IP (e2e leaves a
  resolved 10.99.0.6 incident; engine correctly starts a fresh one instead of reusing resolved -> old incs[0]
  looked at the stale resolved one and missed the proposal). Re-ran: full block/undo story green.
Console supervisor: job_b1vQr814 (session console5) on final code. E2E 96/96, unit 92/92.

## 26 Nov ~18:20 IST: PHASE 2 build (post-7/10-review): remediation + adaptation + scale
User asked to fix everything rated <9. New modules (backend DONE, tests 8/8 remediate green):
- remediate.py Remediator: restore_file (Vault content-addressed copies in data/vault/blobs/<sha>,
  verify-after-write), stop_process (/proc socket->inode->pid attribution, SIGTERM->SIGKILL, verified
  socket gone), lock/remove_account via RAKSHAK_ACCT_CMD helper (deploy/rakshak-acct: uid>=1000 only,
  denylist, verify-after). Flow: possibilities()->propose() (signed action, nothing executed)
  ->engine.approve dispatch->execute+verify->validate_incident downgrades alert on success.
  responder.cancel_pending now also cancels remediation proposals. engine.accept_change = sanctioned-change
  ledger (hostsec.state["accepted"]) + validation 'accepted'.
- rulecraft.py: validate_pack schema + self_test positive/negative SAMPLE GATE (candidate runs in
  isolation; dead rules refused); suggest_rule mines common substring from REAL incident evidence via
  parse_line -> draft yaml in data/rules/drafts (NOT active until admin imports through gate).
  rules.py RuleEngine now loads [rakshak/rules, data/rules/imported]; engine.reload_rules().
- behaviour.py payload_entropy (Shannon over unique payloads >=16ch); ai_origin signals at >=4.2 (0.20)
  / >=3.7 (0.10).
- anomaly.py AnomalyModel(path, load_persisted): samples ALWAYS collected in-process; pickle loaded only
  with RAKSHAK_TRUST_MODEL=1; /api/ml/train (admin) trains from memory; status.persistence wording keeps
  'disabled' test compat. engine.train_anomaly.
- sensor.py: HMAC(ts\nnode\nseq\nsha256(body)) batches to hub /api/ingest; seq monotonic per node (409
  replay), ts skew 120s, body<=2MB, kind filter (host events NOT accepted remotely - honest);
  events.incidents gain node column; same ip on two nodes = two incidents. admin.py sensor-secret.
- auth.py sessions persisted in DB (sessions table) -> survive restart; drop on logout/expiry.
- config.py: rakshak.conf file loader (env wins), acct_cmd shlex, never_lock, sensor_name,
  imported_rules_dir/draft_rules_dir (+imported rules auto-watched by FIM).
- api.py new routes: GET/POST /api/incidents/{id}/remediation, POST /accept, GET /api/rules,
  POST /api/rules/import (admin; after success the imported file is silently added to hostsec baseline),
  POST /api/incidents/{id}/suggest_rule, POST /api/ml/train, GET /api/nodes, POST /api/ingest (unauth+HMAC).
  overview gains nodes/ingest_enabled/vault_copies.
TODO in phase 2: test_adaptation.py, test_sensor.py (TestClient), sessions test; e2e section 13
(remediation live: watched.conf tamper->restore approved->hash verified->downgrade; real listener stop;
useradd invader via sudo -n useradd in sandbox + helper lock/remove; accept-change), section 14
(rule-pack adaptation live: draft from SQLi incident -> import -> new variant matched + self_test refusal
case), section 15 (sensor agent -> hub node ingest incident). accuracy_benchmark.py + docs/ACCURACY_RESULTS.md.
Frontend: AlertDetail remediation panel + accept + rules import UI, Nodes page, Guide updates; vite build.
Docs pass + zip rebuild + screenshots after all green. Console currently DOWN? No: still job_Nimr3TmD on
OLD backend code (pre-phase-2) -> MUST restart after api.py changes, then e2e.

### 26 Nov ~19:00 IST: PHASE 2 finishing (tests green, e2e debugging log)
Backend + frontend + tests DONE (unit 117/117). Live-run debugging, honest log:
- deploy/rakshak-acct had an argv off-by-one (main receives sys.argv[1:] but the code checked
  argv[1] and len==3): status/lock/remove now verified live. Found only because e2e exercised it.
- Remediation live story (e2e section 13): restore verified to the exact pre-attack content hash,
  listener stop verified by the port refusing connections (PID attributed via /proc socket inode),
  account lock verified via shadow '!', removal verified absent; alert downgrades after verified undo;
  cancel-on-resolve and the sanctioned-change accept ledger both pass.
- e2e run5 131/139 -> four real fixes: (a) 10.99.0.7/.8/.9 were outside the /29 lab net so
  curl --interface produced NO log lines -> preconditions now 'ip -4 addr replace .../32 dev lo';
  (b) an interrupted earlier run left a tampered events row (id 467) -> repaired (its stored hash
  matched path='/' after setting the value back) and section 9 now asserts the chain is healthy
  BEFORE the tamper test, so leftovers from a crashed run fail loudly instead of confusing results;
  (c) listener unit-test ordering fixed (baseline scan BEFORE spawning the child);
  (d) a double-insert bug in this very script (replace() matched two anchors) - code inserted twice;
  lesson: verify insertion count after scripted edits (now asserts ==1 per section).
- run6 141/143 -> two more honest findings: (1) the draft-rule check extracted the id with
  startswith("id:") but mined YAML is a list ("- id: ...") so the check read "?" and failed while
  the import itself had actually SUCCEEDED (rule live in engine) - check fixed, not the product;
  (2) the sensor run-2 batches were refused with 409 replay because the agent's local state (and
  therefore seq) resets each run while the hub remembered last_seq - the guard was CORRECT; e2e now
  resets that node's stored seq before the run and adds 77.99.0.2 to its cleanup list.
- Accuracy benchmark (scripts/accuracy_benchmark.py -> docs/ACCURACY_RESULTS.md): labelled sandbox
  corpus 93 benign/8 IPs + 33 attack/12 IPs + flood + ssh-fail + two novel encoded families:
  baseline 86% detection, zero false positives on benign; after ONE gated imported pack 100%.
  Footnotes: the novel families were authored for the test (proves the import loop, not real-world
  coverage); hex-blob note (4-bit entropy cap per char vs base32); not a production claim.
- run7 141/142: draft-mine check hit a REAL race in the test itself - the incident appeared in the
  list before its second evidence line was indexed, so rulecraft correctly refused ("fewer than two
  decodable lines"). e2e now waits for >=2 evidence lines before mining. run8: 143/143 PASS.
- host_security_demo.py extended: the undo is now performed BY THE CONSOLE (analyst proposes
  restore_file/stop_process -> admin approves -> done+verified, independently re-checked in the
  script: file hash equals pre-attack, port refuses), alerts downgrade, screens
  20_remediation_offer.png / 21_undo_verified.png added to docs/DEMO_SYSTEM_SECURITY.md. Demo rerun green.
- Final dashboard screens regenerated over the proxy (00/01/02/03/09/10 incl. new Home lines: vault copies,
  reporting sensors, imported rule count). Console restarted with RAKSHAK_HOSTSEC_INTERVAL=30 (production
  cadence) keeping ACCT_CMD/FIREWALL/ingest config; health ok, login gate 401 confirmed.
- Zip rebuilt (208 files, 16.4 MB): verified remediate/rulecraft/sensor/deploy/rakshak-acct/new tests/new docs/
  new screens present; data/, credentials, venv, node_modules excluded; grep for credential strings across the
  extracted archive = 0 hits. TEST_RESULTS.txt regenerated at 117 passed.

## 26 Nov ~23:05 IST: permanent showcase website + my-machine install guide
User: "Turn it into a permanent website" -> chose "showcase site now + guide me through installing on
my own machine".
- Product code lives at /home/ubuntu/rakshak-app now (moved; the old path was needed by the Webdev
  workspace after its init recovered from the earlier workspace_directory_conflict by moving the
  occupied directory aside, exactly as its recovery text requires). No product file referenced the
  absolute path, so the move was code-free; console relaunched with the same env (PLUGINS_DIR updated),
  health ok, dashboard 200, bad login 401, and the full suite re-run from the new path: 117 passed.
- Showcase site: static Webdev project "rakshak" (flexible template, no server/db), published publicly
  at https://rakshak-ese65ylm.manus.space. Checkpoint 6024101. Real content only: 13 genuine sandbox
  screenshots (reduced/trimmed, no mockups), the honest numbers 117/117, 143/143, 86->100% with run
  history including the failing runs, adaptation/multi-node/plugin sections, install quickstart,
  limitations section and team credit. /download/RAKSHAK-AI.zip serves the rebuilt archive
  (216 files, 14,839,803 B, INSTALL_YOUR_MACHINE.md included, credential grep = 0 hits; verified
  byte-identical to the sandbox copy over HTTPS).
- Install guide for the user's own machine: INSTALL_YOUR_MACHINE.md (8 sections: fast start, scope.yml,
  firewall helper + sudoers + acct helper, systemd service, team accounts + SSH tunnel/TLS, sensor
  agents, verify-your-install (must print 117 passed), Windows via WSL2, honesty checklist).
- Known rough edge seen in the console log: rulecraft draft file uses O_EXCL with a second-resolution
  name, so a second suggest_rule for the same incident in the same second returns 500 FileExistsError
  instead of a clean refusal. Data is never half-written; behaviour is safe, just ugly. TODO: name the
  draft uniquely (uuid4) or return 409 with the existing path.
