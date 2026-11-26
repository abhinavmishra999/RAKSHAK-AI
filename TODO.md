# RAKSHAK-AI implementation outcomes

Verified 26 Nov 2026 by 117 automated tests (`docs/TEST_RESULTS.txt`), a live end-to-end check against real nginx,
OpenSSH, Nmap and iptables passing 143 of 143 checks including the system-security, verified-undo remediation,
offline rule-pack adaptation and sensor-ingestion sections
(`docs/E2E_LIVE_RESULTS.md`; its first run with these checks passed 95 of 96, found one real bug in the file-integrity
logic, and that fix now has a regression test), and a separate firewall-helper test
(`docs/FIREWALL_HELPER_LIVE_TEST.txt`).

- [x] Offline plugins: reviewed copies of local/GitHub tools run without internet at runtime. Tools start disabled and
  external tools need `RAKSHAK_ALLOW_EXTERNAL_PLUGINS=1`; manifest + executable hash pinning at enable; explicit asset
  scope (`scope.yml`, fail-closed, never_scan wins, attacker addresses never scanned); separate per-run approval with
  admin/two-person rules and signature + DNS-drift re-checks at approval; no shell, scrubbed environment, timeout,
  output cap, rlimits, process-group kill, one run per target; signed run records and audit entries. The tested example
  tool in `examples/plugins/` proves the path end to end.
- [x] No dummy results: independent rechecks separate Confirmed / Not reproduced / Inconclusive / Observed pass; a
  plugin can never mark itself Confirmed; an inconclusive first observation is never upgraded; catch-all pages cannot
  fake a pass; failed requests are not passes; reports contain only confirmed findings in the main section and
  recompute from stored evidence; reports are refused when the evidence chain or a record signature is broken.
- [x] Local protection: localhost-only bind (refuses remote bind without opt-in), offline local accounts (PBKDF2
  600k, 14+ characters, no default password), viewer/analyst/admin roles, CSRF header on every change, sessions 1 h,
  5-fail lockout, TrustedHost + CSP + security headers, honest blind/attention/no-active-alerts states, recommend
  mode by default, blocks only counted as contained when the firewall verified them, expiry + undo + never-block list,
  root firewall helper allowing only Rakshak's own chain.
- [x] Beginner dashboard: sign-in, Home, Alerts (+evidence card), Security tests (four-step flow, scope card, tool
  review, request with authorisation, approve/reject, results by validation status), Protection, Memory (timeline of
  every detection, response and test, computed live from the signed records - no separate table to drift or be
  edited), Activity (audit + chain check), Guide (in-app manual: setup, every option, principles enforced in code,
  how detection works, validation loop, honest limits), Learn; visible error banners; screenshots in `docs/screens/`.
- [x] System security (host SOC, not only web): offline host sensors - file-integrity watch (content fingerprint when
  readable, metadata fingerprint otherwise; a reverted change downgrades the alert to Suspected with the reason instead
  of vanishing), new or removed user accounts, extra uid-0 accounts, new sudo group members, new listening ports read
  from `/proc/net`, and credential compromise when repeated failed logins from one address end in a successful login
  (critical). Every host alert is re-checked against the live system before it is called verified; host alerts never
  enter the IP-block pipeline (there is no address to block) and the console says so. Dashboard: Home sensor status,
  Memory System-changes filter, AlertDetail host view, Guide updated; 12 dedicated unit tests and 15 live checks;
  story demo in `docs/DEMO_SYSTEM_SECURITY.md` (re-runnable via `scripts/host_security_demo.py`).
- [x] Delivery: current README with deployment truth, plugin integration guide with example manifest and wrapper,
  systemd/env templates, reproducible live-check scripts, source archive without credentials or runtime data, honest
  enterprise roadmap (`ENTERPRISE_PLAN.md` status columns).

Open gates (do not claim these as done): detection accuracy on real production traffic is unmeasured (M4); plugin OS
isolation beyond process limits (namespaces/seccomp/dedicated user exercised in production); nftables enforcement never
tested live; human sign-off on reports; accepted-risk list; SSO/MFA; process-level attribution for host changes
(which command touched the file) and root-mode collection; native
Windows sensors; baseline-before-install (today the host baseline starts at first run); local LLM (M5); multi-server sensors
full form - mTLS, signed rule push, PostgreSQL (M6: signed sensor-to-hub event streaming is DONE and tested live);
pilot (M7); external penetration test, SBOM, signed releases (M8). Restoring a file whose previous content Rakshak
never held (root-owned, unreadable) is refused by design. No public publication is authorised.

Done 26 Nov phase 2 (the fixes for everything previously rated below 9):
- [x] Response depth - undo what an attacker did: `remediate.py` offers, per incident, restore of a tampered file
  from the content-addressed vault, stop of a backdoor listener (PID attributed exactly through the `/proc` socket
  inode), lock/remove of an attacker-created account via the hardened `deploy/rakshak-acct` helper (uid-range and
  denylist guards live in the root helper). Nothing executes until a person approves a signed proposal; every
  executed step is re-checked against the live system and only then does the alert downgrade; refusals state the
  reason. Sanctioned changes can be accepted into a ledger so they stop alerting. Verified live end to end.
- [x] Detection coverage + offline adaptation: `rulecraft.py` mines a draft rule from an incident's own decoded
  evidence (drafts are inert until imported); imported rule packs must pass a schema gate AND a live positive/negative
  sample gate before activation; rules hot-reload without restart and the imported folder is file-integrity watched;
  payload-entropy and high-encoding detectors flag machine-generated variants. Measured on a labelled sandbox
  corpus: 86% -> 100% detection after one imported pack, zero benign false positives (`docs/ACCURACY_RESULTS.md`).
- [x] Scalable architecture: sensor agents on other machines stream HMAC-signed batches (replay, forged and stale
  batches refused: 409/401/401) to the hub; incidents are node-aware; `rakshak.conf` settings file; sessions persist
  in the DB across restarts. First form of multi-SIEM-node coverage without any cloud service.

Also done 26 Nov later: split-screen landing page; real-time response demonstration on a simulated attack, from
detection through proposal, approval, firewall verification and undo, in `docs/DEMO_REALTIME_RESPONSE.md`
(re-runnable via `scripts/attack_response_demo.py`), plus the system-security demonstration (file tampering detected
and re-checked live, a real listener caught, remediation confirmed, credential-compromise story) in
`docs/DEMO_SYSTEM_SECURITY.md` (re-runnable via `scripts/host_security_demo.py`). Windows: native service remains a
planned milestone; today it runs on Windows only through WSL2 or a Linux VM.
