# RAKSHAK-AI: Enterprise Plan

**Goal:** turn RAKSHAK-AI into an autonomous security agent that organisations can trust on real production
systems, offline, at international scale, without ever showing unverified or fake results.

**Status legend used below:** DONE = built and tested in this repo · PARTIAL = exists but not production-ready ·
PLANNED = not built yet.

---

## 0. Where we are today (honest status, 26 Nov 2026)

Evidence for every DONE item: 117 automated tests (`docs/TEST_RESULTS.txt`) and a live end-to-end check against real
nginx 1.24, OpenSSH 9.6, Nmap 7.94 and iptables 1.8.10 in an isolated sandbox (`docs/E2E_LIVE_RESULTS.md`, all checks
passing including the system-security, verified-undo remediation, offline-adaptation and sensor-ingestion sections; the web-only suite previously passed 81 of 81 twice). The system section's first
run passed 95 of 96 and exposed one real bug in the file-integrity logic (fixed, regression test added); the earliest run
of the web suite passed 65 of 72 and exposed seven bugs, which were fixed and now have regression tests. The phase-2
sections' first live run passed 131 of 139 and exposed four real issues (lab addresses outside the test /29 producing
no log lines, an interrupted-run leftover in the evidence fixture, an account-helper argv off-by-one, a double insert
in the check script itself) - all fixed and re-verified; their second run also caught a draft-mining race and a
correct-by-design sensor replay refusal on a reset sequence number, both handled honestly (see docs/DEV_NOTES.md).
"Tested live" below always means that sandbox, never a customer's production network.

| Area | Status | Notes |
|---|---|---|
| Log ingestion (nginx/Apache combined, OpenSSH, JSON) | DONE | resumes from its saved position, follows rotation, starts at end of file on first run; tested live |
| Signature rules and behaviour limits | DONE | tested live on sandbox traffic only; accuracy on production traffic not measured |
| Isolation Forest anomaly model | PARTIAL | off until trained on the organisation's own traffic; saved model files are not loaded unless explicitly trusted |
| AI-origin estimate | DONE (estimate) | behaviour heuristic, labelled as such everywhere; not proof |
| Alert evidence validation | DONE | re-runs rules on the stored, hash-checked log rows (including the 60 s before the alert) |
| Host security sensors (system SOC layer) | DONE (single Linux machine) | file-integrity watch (content fingerprint when readable, metadata otherwise; a reverted change downgrades the alert to Suspected with the reason), new/removed accounts, extra uid-0, new sudo members, new listening ports from `/proc/net`; every alert re-checked against the live system before `verified`; tested live (tamper + real listener + real OpenSSH) |
| Response depth: undo what the attacker did | DONE (single Linux machine) | propose -> human approve -> execute -> **verify the effect against the live system** -> downgrade the alert, or refuse with the reason: restore tampered files from the content-addressed vault, stop backdoor listeners (PID attributed exactly through the `/proc` socket inode), lock/remove attacker-created accounts through the hardened `deploy/rakshak-acct` helper (uid range + denylist); signed undo records in Memory; a sanctioned change can be accepted so it stops alerting; tested live (restore matched the pre-attack hash, the killed port refuses connections, the locked account cannot log in, the removed account is absent) |
| Adaptation to new attack patterns, offline | DONE (rule packs) | candidate rules mined from an incident's own decoded evidence (drafts are inert until imported), imported rule packs pass a schema gate **and** a live positive/negative sample gate before activation, hot reload without restart, the imported folder is itself file-integrity watched; payload-entropy and high-encoding detectors flag machine-generated variants; measured on a labelled sandbox corpus: 86% -> 100% detection after **one** imported pack with zero benign false positives (`docs/ACCURACY_RESULTS.md`) |
| Credential-compromise detection | DONE | repeated failed logins from one address ending in a successful login = critical incident; block proposal goes through the same two-person approval; tested live against real sshd |
| Host response policy | DONE | host alerts never propose an IP block (no attacker address to block) and the console says so; instead they offer **verified remediation** (restore / stop / lock / remove above) or plainly refuse with guidance when undo is impossible; zero fake actions |
| Hash-chained event store and signed audit log | DONE | live tamper tests: edit detected, report refused, verifies again after restore |
| Firewall enforcement | DONE for iptables, PARTIAL for nftables | iptables tested live (blocked source dropped, others served, undo restores); every change verified; root helper `deploy/rakshak-fw` allows only Rakshak's own chain; nftables unit-tested only (sandbox kernel lacks support) |
| Block expiry, never-block list, undo, stale-approval guards | DONE | expiry tested live with simulated time |
| Local accounts, roles, CSRF, sign-in throttling, localhost-only binding | DONE | no SSO or MFA yet; sessions persist in the DB across restarts |
| Operator experience for new staff | DONE | in-app **Guide** (setup, every option, principles, detection, limits) and **Memory** timeline (all detections, responses and tests, computed live from the signed records); tested live through the browser |
| Plugin runner (scope, hash pinning, per-run approval, two-person rule, DNS pinning, no shell, resource limits, signed records) | DONE (core) | tested live with the website check, Nmap and an external example tool |
| Plugin OS isolation (separate user, network namespace, seccomp, read-only filesystem) | PLANNED | today: process limits and a clean environment only |
| Validation of test findings | PARTIAL | independent TCP and HTTP re-checks exist; findings no re-check covers stay "Could not check", never Confirmed |
| Human sign-off on reports | PLANNED | reports are drafts; no approval step is recorded yet |
| Demo portal, attack simulator, Test Lab | REMOVED | no demo data in the product |
| Local LLM reasoning | PLANNED | explanations come from an offline knowledge base |
| Distributed sensors, central server, PostgreSQL | PARTIAL | signed sensor-to-hub event streaming (HMAC, replay/staleness guards, node-aware incidents) DONE and tested live; mTLS, signed rule push and PostgreSQL still PLANNED |
| Accuracy measurement on production traffic | PARTIAL | labelled sandbox corpus measured (86% baseline -> 100% after one gated imported pack, 0 benign false positives, `docs/ACCURACY_RESULTS.md`); production traffic and public datasets (CIC-IDS2017) not run yet (M4) |
| Windows | NOT SUPPORTED today | Today: run on Windows via WSL2 or a Linux VM (all features work there, including firewall blocking and the host sensors on the Linux side). Planned as its own milestone: native Windows service - Event Log (Security channel: logon and account-change events) + IIS log ingestion, file-integrity and listener equivalents via Windows APIs, Windows Firewall (WFP) enforcement adapter behind the same proposal/approval/verification flow. Not started; nothing may be claimed for it until tested live. |

**Rule for everyone on the team:** only items marked DONE may be described as working in demos, decks or sales material.

---

## 1. Safety principles (non-negotiable)

An autonomous agent that can block traffic and launch security tools is itself a high-value target and a
potential source of outages. These principles come before features:

1. **Scope is explicit.** Rakshak may only test assets listed in a signed `scope.yml` (the organisation's own
   CIDRs/hostnames). Anything else is refused, including requests from the LLM.
2. **Never attack back.** Rakshak never scans, probes or "validates" an attacker's IP or any third-party system.
   Validation means checking *our own* asset ("is this endpoint actually vulnerable?"), never the source.
3. **Passive by default, active only with approval.** Active tests (port scans, vulnerability scans, exploit
   checks) require a named operator's approval per run, inside an approved maintenance window.
4. **Least privilege.** Rakshak runs as a dedicated non-root user. Containment uses narrowly scoped helpers
   (DONE for iptables: `deploy/rakshak-fw` accepts only single-address DROP rules in the `RAKSHAK-BLOCK` chain).
5. **Everything reversible and logged.** Every action is signed, has an undo, and expires by default (DONE: blocks
   expire after `RAKSHAK_BLOCK_TTL`, 24 h by default).
6. **The LLM advises; code decides.** The LLM never executes commands directly. It can only *request* a
   registered, approved plugin action, which the policy engine checks against scope, risk and mode.
7. **No unverified claims.** A finding is shown as **Confirmed** only after validation (Section 4); otherwise it is
   shown as **Suspected**, with its reasons. Reports include only confirmed findings in the main section.
8. **Fail safe.** If Rakshak cannot read its logs, the dashboard shows that it is blind instead of "safe" (DONE). A
   second alert channel is PLANNED. It never fails into a state that blocks everything.

---

## 2. Target architecture

```
  Edge sensors (each server)            Central node (on-prem, air-gapped)
  ┌──────────────────────┐   mTLS      ┌─────────────────────────────────────────────┐
  │ log tailer + parser  │ ──────────► │ ingest ─► detect ─► reason (local LLM)       │
  │ local shield/nft     │ ◄────────── │          policy engine ─► plugin runner      │
  │ (applies signed      │  signed     │          (scope, approval, sandbox)          │
  │  block rules)        │  rules      │ store (append-only, hash-chained, backed up) │
  └──────────────────────┘             │ dashboard + API (SSO, RBAC, audit)           │
                                       └─────────────────────────────────────────────┘
```

* **Edge sensor:** small static binary (Go or Rust), reads logs, normalises and hash-chains events, sends them over
  mutual TLS, applies only block rules signed by the central node.
* **Central node:** the current Python engine grows into this. PostgreSQL replaces SQLite (with the same hash chain
  plus periodic signed checkpoints written to WORM storage or an offline disk).
* **Local LLM:** e.g. Foundation-sec-8B or a Llama-class model served by llama.cpp/Ollama on the central node's GPU.
  Pinned model hash; prompts and outputs logged for audit.

---

## 3. Plugin system (safe design)

Purpose: let organisations connect their own offline copies of tools (from GitHub or internal) such as Nmap,
Nuclei, OWASP ZAP, Trivy, osquery, or custom scripts, and run them from the same platform.

### 3.1 Plugin package

```
plugins/nuclei/
  plugin.yml        manifest (required)
  wrapper.py        optional: converts tool output to Rakshak findings
```

`plugin.yml` declares (all fields are implemented and strictly validated; unknown fields are refused):

| Field | Meaning |
|---|---|
| `id`, `name`, `version`, `source` | identity; `source` = GitHub URL + commit the binary was built from |
| `executable` + `sha256` | exact binary path and hash; Rakshak refuses to run if the hash differs |
| `kind` | `passive` (reads data, no network to targets) or `active` (sends traffic to targets) |
| `approval` | `admin` (only an admin may approve each run) or `self` |
| `target_type` | `host`, `url` or `none` |
| `args` | fixed argument list; only `{target}` is substituted; no shell, no free-form arguments |
| `timeout_s`, `max_output_kb` | hard limits |
| `parser` | how to turn output into findings: `json_findings`, `nmap_xml` or `text` |
| `validator` | Rakshak's own re-check: `tcp_open`, `none` (the built-in website check additionally uses `http_recheck`) |

### 3.2 Lifecycle

1. **Import offline:** copy the tool + manifest from a USB or internal mirror. Rakshak computes hashes.
2. **Review and enable:** an Admin role reviews the manifest and the exact command in the dashboard and enables it.
   Every tool starts disabled; external tools are not even listed without `RAKSHAK_ALLOW_EXTERNAL_PLUGINS=1`.
   Enabling pins the SHA-256 of both the manifest and the executable (DONE).
3. **Request and approve:** the target is checked against `scope.yml` (plus never_scan and never-scan-attackers) and
   its resolved addresses are pinned at request time; approval re-checks the signature of the stored request, the pinned
   hashes, and re-resolves the target, refusing on any drift. Admin-approval tools and the two-person rule are enforced (DONE).
4. **Run:** the tool starts as a separate process, without a shell, with a scrubbed environment, its own workdir,
   timeout, output cap and rlimits (CPU, address space, file size, descriptors); the process group is killed on timeout;
   one concurrent run per target node (DONE). Optional drop to a dedicated plugin user when Rakshak runs as root (PARTIAL:
   `RAKSHAK_PLUGIN_USER` exists; not exercised live). OS-level isolation - network namespace, read-only filesystem,
   seccomp - is PLANNED; until then only reviewed tools should be enabled.
5. **Record:** command, hashes, requester, approver, times, exit code, output digest and findings are stored in a
   signed run record (DONE).
6. **Parse and validate:** output is parsed strictly; findings stay *Suspected* until an independent re-check makes
   them Confirmed or Not reproduced, or mark them Inconclusive (DONE for tcp_open and the built-in HTTP checks;
   PLANNED for more finding types).

### 3.3 First plugins to build

| Plugin | Kind | Status |
|---|---|---|
| Built-in Website Check | active (own assets) | DONE, tested live against three real nginx sites incl. catch-all false-positive guard |
| Nmap (top-100 ports) | active | DONE, tested live; every open port re-confirmed by an independent TCP connect |
| Example external tool (tcp-connect-check) | active | DONE in `examples/plugins/`; proves the external-tool path end to end |
| Nuclei (offline template pack) | active | PLANNED - needs a finding re-check before matches can be Confirmed |
| Trivy (offline DB) | passive | PLANNED |
| osquery | passive | PLANNED |

---

## 4. Validation: no fake or unverified results

Every finding passes these checks before it is shown as **Confirmed**:

1. **Provenance (DONE):** the signed run record names the tool, its pinned hashes, requester and approver; findings
   carry the tool's raw evidence plus the re-check's own evidence. Alert reports recompute everything from stored,
   hash-verified log rows and refuse if the chain or any action signature is broken.
2. **Reproduction (PARTIAL):** ports are re-confirmed by an independent TCP connect; the built-in website check
   repeats its own HTTP observation (including against catch-all pages, which cannot fake a pass). Findings with no
   re-check available are labelled Inconclusive, never Confirmed. Scanner-specific reproduction (e.g. replaying a
   Nuclei request) is PLANNED.
3. **Context (PARTIAL):** scope is enforced at request and approval time; an accepted-risk list is PLANNED.
4. **Consistency (DONE):** severities come from validated rule/plugin definitions; report numbers are recomputed
   from stored evidence at report time, never copied from UI state.
5. **Human sign-off (PLANNED):** reports are clearly marked drafts ("a responsible person must review before
   anything is sent"); an explicit recorded sign-off step is not built yet.

Findings that fail any step are shown as Suspected / Not reproduced / Inconclusive with the failed step named. Nothing
is invented to fill a gap: with no readable logs the dashboard says Rakshak is blind; with no data a panel says so.

**Accuracy measurement before any "auto" deployment:**
* Replay public labelled datasets offline (CIC-IDS2017, CSE-CIC-IDS2018) and the org's own red-team exercises
  (MITRE CALDERA, Atomic Red Team) against a staging copy.
* Publish detection rate, false-alarm rate and time-to-contain per attack type, with dataset versions.
* Shadow mode in production: 2-4 weeks in "Ask me first", comparing Rakshak's suggestions with the SOC's decisions.
  Auto mode is enabled per attack category only after it meets the agreed false-alarm threshold.

---

## 5. Protecting Rakshak itself

| Threat | Control | Status |
|---|---|---|
| Someone logs into the dashboard | SSO (SAML/OIDC) or local accounts with MFA; roles Viewer/Analyst/Admin | PARTIAL: local PBKDF2 accounts + roles DONE; no SSO/MFA yet |
| Stolen API access | Short-lived tokens, rate limits, CSRF protection; mTLS between components | PARTIAL: 1-hour sessions, 5-fail lockout, CSRF header, localhost-only binding DONE; mTLS is multi-node (PLANNED) |
| Malicious or tampered plugin | Manifest + hash pinning, admin enablement, per-run approval, no shell, resource limits | DONE, tested live (edited tool file refused before launch); OS-level isolation PLANNED |
| Stale or tampered approval | Approve re-verifies the signed request; resolved alerts cancel pending proposals; edited records refused | DONE, tested live |
| Prompt injection via logs | LLM output advisory only; policy engine enforces scope; log content quoted | N/A yet (no LLM wired); the scope/approval gates that would contain it are DONE |
| Attacker gets a legitimate user blocked (IP spoofing) | Source IPs come only from server-side logs (X-Forwarded-For is never trusted); blocks expire; never-block/allowlist; scanner source in TRUSTED | DONE |
| Log tampering | Hash chain + HMAC-signed audit, verified in the UI and before reports | DONE; signed checkpoints copied to offline/WORM storage PLANNED |
| Attacker persists on the host without sending attack traffic (edited config, backdoor account, opened port, guessed password) | Host sensors: file-integrity fingerprints, passwd/group differ, `/proc/net` listener watch, failed-logins-then-success rule; alerts re-observed against the live system before `verified`; guidance instead of pretend-blocking | DONE for one Linux machine, tested live (`docs/DEMO_SYSTEM_SECURITY.md`); process-level attribution (which command did it) and root-mode collection PLANNED |
| Supply chain | Offline wheelhouse install documented; pinned dependency versions with hashes, SBOM, signed releases | PARTIAL: wheelhouse path DONE (untested at scale); SBOM/signed releases PLANNED |
| Rakshak outage | Health endpoint, dashboard shows when blind (never "safe" without logs), fail-open: blocks expire, nothing is blocked on Rakshak's failure | DONE; second-channel alerting PLANNED |
| Host sensors blind to tampering done before install | Baseline is recorded at first run and the console/docs state this limit plainly; install guidance requires a known-clean machine | PARTIAL: honest disclosure DONE; baseline-before-install tooling and signed baseline export PLANNED |

---

## 6. Compliance and international readiness

* **India:** CERT-In 6-hour reporting and 180-day log retention (report generator DONE; retention policy PLANNED);
  DPDP Act 2023: mask personal data in stored payloads (PLANNED).
* **EU:** GDPR data minimisation and retention limits; NIS2 incident-reporting timelines as a report template.
* **US/global:** map controls to NIST CSF 2.0 and ISO/IEC 27001 Annex A; alerts already carry MITRE ATT&CK IDs.
* **Threat intel offline:** import STIX 2.1 bundles from USB; signed rule packs.
* **Languages:** UI strings externalised for translation (English, Hindi first).

---

## 7. Milestones

Durations are estimates for a small team; each milestone ends with tests that pass before moving on.

| # | Milestone | Done when | Status (26 Nov 2026) |
|---|---|---|---|
| M1 | **Hardening the current node** | login + roles, CSRF, localhost-only by default, block expiry, critical-IP allowlist, config file instead of env vars | PARTIAL: config file (rakshak.conf), DB-persisted sessions and never-lock/never-block lists DONE; remaining: MFA and a second alert channel |
| M2 | **Safe plugin runner** | manifest + hash check, scope.yml, approval flow, sandboxed subprocess, audit log; Website Check and Nmap as first plugins | DONE (core). Remaining: OS-level isolation of plugins (separate user, network namespace, seccomp) |
| M3 | **Validation layer** | Confirmed vs Suspected states end-to-end; reports recompute from evidence; human sign-off | PARTIAL: statuses, TCP/HTTP re-checks and evidence-recomputing reports done; human sign-off and more re-check types (e.g. repeating a scanner's exact request) planned |
| M3.5 | **System SOC layer** | Host sensors (file integrity, accounts, listening ports), credential-compromise rule, live re-observation before verified, host-aware dashboard/Memory/Guide | DONE (single Linux machine, tested live), and extended: verified remediation undo (restore/stop/lock/remove), sanctioned-change ledger, offline rule-pack adaptation with sample gate. Remaining: auditd/eBPF attribution of *which command* touched a file, root-mode collection, Windows event sources, deeper directory-tree watching |
| M4 | **Accuracy baseline** | CIC-IDS2017 replay + CALDERA runs with published metrics | PARTIAL: first metrics on a labelled sandbox corpus, baseline vs after-one-imported-pack (`docs/ACCURACY_RESULTS.md`); public datasets and CALDERA runs still PLANNED |
| M5 | **Local LLM (advisory)** | LLM explanations and plugin suggestions, policy-checked, with prompt-injection tests | PLANNED |
| M6 | **Distributed sensors** | edge sensor binary, mTLS, signed rule push, PostgreSQL | PARTIAL: sensor agent with HMAC-signed batches, replay/staleness guards and node-aware incidents DONE and tested live; mTLS, signed rule push, static binary and PostgreSQL still PLANNED |
| M7 | **Pilot** | one organisation, shadow mode 2-4 weeks, then per-category auto mode | PLANNED |
| M8 | **Certification path** | external penetration test of Rakshak itself, ISO 27001-aligned controls, SBOM and signed releases | PLANNED |

**Before any production use**, an organisation should at least complete M1, the plugin isolation part of M2 (or enable
only fully reviewed tools), and a shadow-mode pilot from M7 in "Ask me first" mode.
