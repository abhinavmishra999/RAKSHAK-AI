"""The Rakshak engine: SENSE -> DETECT -> SPOT AI -> EXPLAIN -> CONTAIN -> REPORT.

The engine is deliberately conservative: configured log sources are observed, never
created; evidence is recomputed from stored rows before response/reporting; and the
default enforcer only records proposed blocks.
"""
import json
import os
import threading
import time
from pathlib import Path

from .audit import AuditLog, load_key
from .config import Settings
from .detect import ai_origin
from .detect.anomaly import AnomalyModel
from .detect.behaviour import BehaviourDetector
from .detect.rules import RuleEngine
from .enforcer import make_enforcer
from .knowledge import PRIORITY, SEVERITY_ORDER
from .hostsec import HostSecurity, Vault
from .parsers import parse_line
from .report import build_report
from .responder import Responder
from .remediate import REMEDIATION_ACTIONS, Remediator
from .store import Store


class _DisabledAnomaly:
    """Safe no-pickle fallback used unless the operator explicitly trusts a model."""

    def collect(self, _features):
        return None

    def train(self):
        return {"ok": False, "reason": "Model persistence is disabled; set RAKSHAK_TRUST_MODEL=1 explicitly."}

    def is_anomalous(self, _features):
        return False, 0.0

    def status(self):
        return {"trained": False, "trained_on": 0, "pending_samples": 0,
                "persistence": "disabled (set RAKSHAK_TRUST_MODEL=1 to load/train)"}


class Engine:
    def __init__(self, conf: Settings):
        self.conf = conf
        self.store = Store(Path(conf.data_dir) / "rakshak.db")
        self.audit = AuditLog(self.store, load_key(Path(conf.data_dir) / "signing.key"))
        # built-in rules plus operator-imported offline packs (data/rules/imported)
        self.rules = RuleEngine([Path(conf.rules_dir), Path(getattr(conf, "imported_rules_dir", conf.rules_dir))])
        self.behaviour = BehaviourDetector()
        model_path = Path(conf.data_dir) / "anomaly_model.pkl"
        # samples are ALWAYS collected (no code execution involved); the trained model
        # is only LOADED from disk (pickle) when explicitly trusted. Training itself
        # happens in-process via /api/ml/train.
        self.anomaly = AnomalyModel(model_path, load_persisted=os.environ.get("RAKSHAK_TRUST_MODEL") == "1")
        self.responder = Responder(self.store, self.audit, conf, make_enforcer(conf),
                                   never_block_extra=getattr(conf, "trusted", ()))
        self.vault = Vault(conf.data_dir)
        # System-security sensors: file integrity, accounts, listening services.
        self.hostsec = (HostSecurity(conf, self.store, self.audit)
                        if getattr(conf, "hostsec_interval", 0) else None)
        # Host remediation: approved, live-verified undo of attacker changes.
        self.remediator = Remediator(conf, self.store, self.audit, self.hostsec, self.vault, self.responder)
        self.reports_dir = Path(conf.data_dir) / "reports"
        raw_logs = conf.logs
        if isinstance(raw_logs, (str, Path)):
            raw_logs = str(raw_logs).split(",")
        self.log_files = [Path(f) for f in raw_logs]
        self.allowlist = set(getattr(conf, "trusted", ()))
        self.started_at = time.time()
        self.counters = {"sensed": 0, "detections": 0, "ai_flagged": 0, "explained": 0,
                         "contained": 0, "reported": 0, "host_findings": 0}
        self.errors = []
        self._offsets = {}
        self._inodes = {}
        self._source_states = {}
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._load_counters()

    def _load_counters(self):
        """Rebuild pipeline counters from stored data, so they survive a restart."""
        try:
            incs = self.store.list_incidents(100000)
            self.counters.update({
                "sensed": self.store.count_events(),
                "detections": self.store.count_flagged(),
                "ai_flagged": sum(1 for i in incs if i["ai_score"] >= 0.7),
                "explained": len(incs),
                "contained": sum(1 for i in incs if i["contained_at"]),
                "reported": len(list(self.reports_dir.glob("incident_*.pdf"))) if self.reports_dir.exists() else 0,
                "host_findings": sum(i["event_count"] for i in incs if i["source_ip"] == "system"),
            })
        except Exception:
            pass

    # ---------------- SENSE ----------------
    def _record_error(self, message):
        self.errors.append(f"{time.strftime('%H:%M:%S')} {message}")
        self.errors = self.errors[-20:]

    def _inspect_source(self, f):
        state = {"path": str(f), "readable": False, "bytes": 0,
                 "state": "missing", "errors": []}
        try:
            st = f.stat()
            state["bytes"] = st.st_size
            state["inode"] = getattr(st, "st_ino", None)
            try:
                with f.open("rb"):
                    pass
                state["readable"] = True
                state["state"] = "healthy"
            except OSError as exc:
                state["state"] = "unreadable"
                state["errors"].append(f"{type(exc).__name__}: {exc}")
        except FileNotFoundError:
            state["errors"].append("source is missing")
        except OSError as exc:
            state["state"] = "unreadable"
            state["errors"].append(f"{type(exc).__name__}: {exc}")
        self._source_states[f] = state
        return state

    def source_status(self):
        """Return source health; a live tail thread is not evidence that sources are healthy."""
        with self._lock:
            return [{key: state.get(key) for key in ("path", "readable", "state", "bytes", "errors")}
                    for f in self.log_files for state in [self._inspect_source(f)]]

    def start(self):
        self._stop.clear()
        saved = self._load_offsets()
        backfill = os.environ.get("RAKSHAK_READ_EXISTING") == "1"
        for f in self.log_files:
            status = self._inspect_source(f)
            self._inodes[f] = status.get("inode")
            prev = saved.get(str(f), {})
            size = status.get("bytes") or 0
            if prev.get("inode") == status.get("inode") and 0 <= prev.get("offset", -1) <= size:
                self._offsets[f] = prev["offset"]          # resume exactly where we stopped
            elif backfill:
                self._offsets[f] = 0                       # explicit opt-in: import existing history
            else:
                self._offsets[f] = size                    # default: only lines written from now on
            if not status["readable"]:
                self._record_error(f"source {f}: {', '.join(status['errors']) or status['state']}")
        self._thread = threading.Thread(target=self._tail_loop, daemon=True, name="rakshak-tail")
        self._thread.start()
        if self.hostsec:
            self._host_thread = threading.Thread(target=self._host_loop, daemon=True,
                                                 name="rakshak-hostsec")
            self._host_thread.start()

    def _offsets_file(self):
        return self.conf.data_dir / "log_offsets.json"

    def _load_offsets(self):
        try:
            return json.loads(self._offsets_file().read_text())
        except (OSError, ValueError):
            return {}

    def _save_offsets(self):
        data = {str(f): {"inode": self._inodes.get(f), "offset": self._offsets.get(f, 0)} for f in self.log_files}
        tmp = self._offsets_file().with_suffix(".tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(json.dumps(data))
            tmp.replace(self._offsets_file())
        except OSError as exc:
            self._record_error(f"could not save log positions: {exc}")

    def stop(self, timeout=5):
        self._stop.set()
        thread = getattr(self, "_thread", None)
        if thread and thread.is_alive():
            thread.join(timeout=timeout)
        hthread = getattr(self, "_host_thread", None)
        if hthread and hthread.is_alive():
            hthread.join(timeout=min(2, timeout))
        self._save_offsets()
        return not self.tail_alive()

    def tail_alive(self):
        thread = getattr(self, "_thread", None)
        return bool(thread and thread.is_alive())

    def host_alive(self):
        if not self.hostsec:
            return False
        thread = getattr(self, "_host_thread", None)
        return bool(thread and thread.is_alive())

    def _host_loop(self):
        # Give uvicorn a moment to bind its own port before the baseline is recorded,
        # so the sensors never raise an alert about the console starting up.
        if self._stop.wait(5.0):
            return
        while not self._stop.is_set():
            try:
                for f in self.hostsec.scan():
                    self._host_finding(f)
            except Exception as exc:
                self._record_error(f"hostsec scan: {type(exc).__name__}: {exc}")
            self._stop.wait(max(5, self.conf.hostsec_interval))

    def _host_finding(self, f):
        """Turn one sensor finding into a chained event, an incident, and an immediate re-check."""
        with self._lock:
            self.counters["sensed"] += 1
            self.counters["detections"] += 1
            self.counters["host_findings"] += 1
            self.hostsec.findings_total += 1
            ts = time.time()
            raw = f["evidence"][0][:400]
            ev = {"ts": ts, "source_ip": "system", "kind": "host", "method": "HOST",
                  "path": f["object"], "query": "", "body": "", "status": 0,
                  "user_agent": "rakshak-hostsec", "raw": raw}
            self.store.add_event(ev, flagged=True)
            target = None
            for i in self.store.list_incidents(300):
                if (i["source_ip"] == "system" and i["status"] != "resolved"
                        and i["category"] == f["category"] and i["detections"]
                        and i["detections"][0].get("matched") == f["object"]):
                    target = i
                    break
            if target:
                self.store.update_incident(target["id"], last_seen=ts,
                                           event_count=target["event_count"] + 1,
                                           evidence=(target["evidence"] + [raw])[-12:])
                inc_id = target["id"]
            else:
                inc_id = self.store.create_incident({
                    "source_ip": "system", "category": f["category"],
                    "categories": [f["category"]], "severity": f["severity"], "status": "open",
                    "first_seen": ts, "last_seen": ts, "detected_at": ts, "event_count": 1,
                    "ai_score": 0.0,
                    "ai_reasons": ["host finding: change observed on this machine; "
                                   "no network origin to attribute"],
                    "detections": [f["detection"]], "evidence": [raw]})
                self.counters["explained"] += 1
            self.audit.write("system", "hostsec.finding", str(inc_id), category=f["category"],
                             object=f["object"], severity=f["severity"])
        # No responder call: a host finding has no attacker IP to contain. The alert's
        # response is the immediate independent re-check below plus guidance in the UI/report.
        self.validate_incident(inc_id, actor="system")

    def _tail_loop(self):
        last_housekeeping = 0.0
        while not self._stop.is_set():
            if time.time() - last_housekeeping > 15:
                last_housekeeping = time.time()
                try:
                    self.responder.expire()
                except Exception as exc:
                    self._record_error(f"block expiry: {type(exc).__name__}: {exc}")
                self._save_offsets()
            for f in self.log_files:
                try:
                    status = self._inspect_source(f)
                    if not status["readable"]:
                        continue
                    inode = status.get("inode")
                    if self._inodes.get(f) != inode:
                        self._inodes[f] = inode
                        self._offsets[f] = 0
                    size = status["bytes"]
                    if size < self._offsets.get(f, 0):
                        self._offsets[f] = 0
                    if size == self._offsets.get(f, 0):
                        continue
                    with open(f, "r", errors="replace") as fh:
                        fh.seek(self._offsets.get(f, 0))
                        while True:
                            line = fh.readline()
                            if not line or not line.endswith("\n"):
                                break
                            self._offsets[f] = fh.tell()
                            ev = parse_line(line, source=str(f))
                            if ev:
                                try:
                                    self.process(ev)
                                except Exception as exc:
                                    self._record_error(f"{type(exc).__name__}: {exc}")
                except FileNotFoundError:
                    self._inspect_source(f)
                except Exception as exc:
                    self._record_error(f"tail {f.name}: {type(exc).__name__}: {exc}")
            self._stop.wait(0.1)

    # ---------------- DETECT / SPOT AI / EXPLAIN / CONTAIN ----------------
    def process(self, ev):
        self.process_event(ev)

    def process_event(self, ev, node=None):
        if node:
            ev = {**ev, "node": node}
        with self._lock:
            self.counters["sensed"] += 1
            ip = ev.get("source_ip") or "unknown"
            trusted = ip in self.allowlist
            hits = [] if trusted else self.rules.match(ev)
            beh, features = self.behaviour.observe(ev, hits)
            if trusted:
                beh = []
            cred = None
            if not trusted and ev.get("kind") == "ssh_login" and (ev.get("status") or 0) == 200:
                # A login accepted from an address that just guessed at the door is the classic
                # credential-compromise signal - and this one DOES have an IP to contain.
                cred = self._cred_hit(ev, self.store.events_for(ip, ev["ts"] - 300.0, ev["ts"]))
            if not hits and not beh:
                self.anomaly.collect(features)
                anomalous, score = (False, 0) if trusted else self.anomaly.is_anomalous(features)
                if anomalous and not self.store.open_incident_for_ip(ip):
                    beh = [{"rule_id": "ML-IFOREST-001", "category": "anomaly", "severity": "medium",
                            "name": f"Isolation Forest anomaly (score {score})", "matched": ""}]
            all_hits = hits + beh + ([cred] if cred else [])
            self.store.add_event(ev, flagged=bool(all_hits))
            if not all_hits:
                return
            self.counters["detections"] += 1
            self._update_incident(ip, ev, all_hits, features)

    @staticmethod
    def _cred_hit(ev, rows):
        """Deterministic: >=5 failed ssh logins from the same address in the 5 minutes before
        an accepted one. Reproducible from stored rows, so validation re-derives it the same way."""
        if ev.get("kind") != "ssh_login" or (ev.get("status") or 0) != 200:
            return None
        ev_ts = float(ev.get("ts") or 0)
        fails = [r for r in rows
                 if r.get("kind") == "ssh_login" and (r.get("status") or 0) in (401, 403)
                 and float(r.get("ts") or 0) <= ev_ts and ev_ts - float(r.get("ts") or 0) <= 300]
        if len(fails) < 5:
            return None
        return {"rule_id": "SSH-CRED-001", "category": "credential_compromise", "severity": "critical",
                "name": f"SSH login accepted after {len(fails)} failed attempts from this address",
                "matched": str(ev.get("path") or ev.get("source_ip") or "")[:120]}

    # ---------------- distributed ingestion (sensor agents -> hub) ----------------
    KNOWN_KINDS = {"http", "ssh_login", "ssh_session", "json"}

    def ingest_node_events(self, node: str, events):
        """Accept parsed log events streamed by a sensor agent. Only known fields and
        types are kept; the hub re-runs its own detection over them like on any line."""
        if not isinstance(events, list) or not 0 < len(events) <= 500:
            raise ValueError("events must be a list of 1-500 entries")
        accepted = 0
        for ev in events:
            if not isinstance(ev, dict):
                continue
            clean = {"ts": float(ev.get("ts") or 0),
                     "source_ip": str(ev.get("source_ip") or "")[:64],
                     "kind": str(ev.get("kind") or "")[:20],
                     "method": str(ev.get("method") or "")[:10],
                     "path": str(ev.get("path") or "")[:1000],
                     "query": str(ev.get("query") or "")[:2000],
                     "body": str(ev.get("body") or "")[:2000],
                     "status": int(ev.get("status") or 0),
                     "user_agent": str(ev.get("user_agent") or "")[:300],
                     "raw": str(ev.get("raw") or "")[:2000]}
            if clean["kind"] not in self.KNOWN_KINDS:
                continue        # host findings are re-observable only on the machine itself
            if not clean["raw"] or not clean["ts"]:
                continue
            self.process_event(clean, node=node)
            accepted += 1
        return accepted


    def _update_incident(self, ip, ev, hits, features):
        now = time.time()
        node = str(ev.get("node") or "")
        inc = self.store.open_incident_for_ip(ip)
        if inc is not None and str(inc.get("node") or "") != node:
            inc = None      # same address seen on two different machines: two separate incidents
        score, reasons = ai_origin.score(features)
        evidence_line = ev.get("raw", "")[:400]
        if inc is None:
            cats = sorted({h["category"] for h in hits}, key=PRIORITY.index)
            sev = max((h["severity"] for h in hits), key=SEVERITY_ORDER.get)
            first_seen, count, evidence = ev["ts"], 1, [evidence_line]
            if any(str(h.get("rule_id", "")).startswith("BEH-") for h in hits):
                # Behaviour detections (e.g. 8 failed logins in 60 s) are made of the whole window,
                # not only the line that crossed the threshold: count and show those stored rows.
                window = self.store.events_for(ip, ev["ts"] - 60.0, ev["ts"])
                if window:
                    first_seen = min(first_seen, min(r["ts"] for r in window))
                    count = len(window)
                    evidence = [str(r.get("raw") or "")[:400] for r in window][-12:]
            inc_id = self.store.create_incident({
                "source_ip": ip, "category": cats[0], "categories": cats, "severity": sev, "status": "open",
                "first_seen": first_seen, "last_seen": ev["ts"], "detected_at": now, "event_count": count,
                "ai_score": score, "ai_reasons": reasons, "detections": self._dedupe(hits),
                "evidence": evidence, "node": node})
            self.counters["explained"] += 1
            if score >= 0.7:
                self.counters["ai_flagged"] += 1
            inc = self.store.get_incident(inc_id)
            escalated = True
        else:
            cats = sorted(set(inc["categories"]) | {h["category"] for h in hits}, key=PRIORITY.index)
            sev = max([inc["severity"]] + [h["severity"] for h in hits], key=SEVERITY_ORDER.get)
            escalated = SEVERITY_ORDER[sev] > SEVERITY_ORDER[inc["severity"]]
            if score >= 0.7 > inc["ai_score"]:
                self.counters["ai_flagged"] += 1
            evidence = (inc["evidence"] + [evidence_line])[-12:]
            self.store.update_incident(
                inc["id"], category=cats[0], categories=cats, severity=sev, last_seen=ev["ts"],
                event_count=inc["event_count"] + 1, ai_score=max(score, inc["ai_score"]),
                ai_reasons=reasons if score >= inc["ai_score"] else inc["ai_reasons"],
                detections=self._dedupe(inc["detections"] + hits), evidence=evidence)
            inc = self.store.get_incident(inc["id"])

        # Validate the actual stored rows before any response decision.
        inc = self.validate_incident(inc["id"], actor="system")
        act = self.responder.handle(inc) if (escalated or not self.store.is_blocked(ip)) else None
        if act and act.get("status") == "proposed":
            self.store.update_incident(inc["id"], status="awaiting_approval")
        elif act and act.get("enforcement_state") == "enforced":
            self._mark_contained(inc["id"], act)
        elif act and act.get("enforcement_state") == "not_enforced":
            self.store.update_incident(inc["id"], status="block_recorded")
        elif act and act.get("enforcement_state") == "failed":
            self.store.update_incident(inc["id"], status="enforcement_failed")

    def _mark_contained(self, inc_id, action=None):
        """Mark contained only after the enforcer reports a verified enforcement."""
        inc = self.store.get_incident(inc_id)
        block = next((b for b in self.store.blocklist() if b.get("incident_id") == inc_id), None)
        actually_enforced = (action or {}).get("enforcement_state") == "enforced" or \
            (block and block.get("enforced") == "enforced")
        if inc and not inc["contained_at"] and actually_enforced:
            self.store.update_incident(inc_id, status="contained", contained_at=time.time())
            self.counters["contained"] += 1
            return True
        return False

    @staticmethod
    def _dedupe(hits):
        seen, out = set(), []
        for hit in hits:
            key = (hit["rule_id"], hit.get("matched", ""))
            if key not in seen:
                seen.add(key)
                out.append(hit)
        return out[-30:]

    # ---------------- evidence validation ----------------
    def validate_incident(self, inc_id, actor="system"):
        inc = self.store.get_incident(inc_id)
        if not inc:
            return None
        if inc["source_ip"] == "system":
            return self._validate_host(inc, actor)
        first = float(inc.get("first_seen") or 0)
        last = float(inc.get("last_seen") or first)
        rows = self.store.events_for(inc["source_ip"], first - 60.0, last)
        chain = self.store.verify_event_rows(rows)
        detector = BehaviourDetector()
        reproduced_ids = []
        for row in rows:
            rule_hits = self.rules.match(row)
            behaviour_hits, _ = detector.observe(row, rule_hits)
            cred_hits = [self._cred_hit(row, rows)] if (row.get("kind") == "ssh_login"
                                                        and (row.get("status") or 0) == 200) else []
            if rule_hits or behaviour_hits or cred_hits:
                reproduced_ids.append(row["id"])
        stored_ids = [row["id"] for row in rows if row.get("flagged")]
        matching_ids = sorted(set(stored_ids) & set(reproduced_ids))
        deterministic = any(not d.get("rule_id", "").startswith("ML-") for d in inc["detections"])
        reasons = []
        if not rows:
            reasons.append("No stored event rows cover the incident period.")
        if not chain["ok"]:
            reasons.append(f"Event-chain verification failed at event IDs {chain.get('bad_ids') or chain.get('broken_at')}.")
        if stored_ids != reproduced_ids:
            reasons.append("Stored flagged-event IDs do not match deterministic rule/behaviour reproduction.")
        if not deterministic:
            reasons.append("Detection is ML-only; it remains suspected and is not proof of exploit or attacker intent.")
        if not rows or not chain["ok"]:
            status = "invalid_evidence"
        elif not deterministic:
            # ML-only alerts remain suspected; deterministic reproduction is not
            # an appropriate test for an anomaly-model-only claim.
            status = "suspected"
        elif stored_ids != reproduced_ids:
            status = "invalid_evidence"
        else:
            status = "evidence_checked"
        if status == "evidence_checked":
            reasons.append("Rules and behaviour were reproduced from stored rows; this is not proof of exploit or attacker intent.")
        detail = {
            "status": status, "actor": actor, "source_ip": inc["source_ip"],
            "period": {"from": first - 60.0, "to": last},
            "event_ids": [row["id"] for row in rows],
            "matching_event_ids": matching_ids, "matching_event_count": len(matching_ids),
            "observed_flagged_count": len(stored_ids), "reproduced_flagged_count": len(reproduced_ids),
            "reproduced_event_ids": reproduced_ids, "chain": chain, "reasons": reasons,
            "note": "Rule reproduction only; no outbound traffic, exploit confirmation, or AI/attacker attribution proof.",
        }
        self.store.update_incident(inc_id, validation=status, validation_detail=detail)
        self.audit.write(actor, "incident_validation", str(inc_id), status=status,
                         matching_event_count=len(matching_ids), observed_flagged_count=len(stored_ids),
                         reasons=reasons)
        return self.store.get_incident(inc_id)

    def _validate_host(self, inc, actor):
        """Host findings are validated by re-observing the live system, not by re-running web rules."""
        first = float(inc.get("first_seen") or 0)
        last = float(inc.get("last_seen") or first)
        rows = self.store.events_for("system", first - 60.0, last)
        chain = self.store.verify_event_rows(rows)
        stored_ids = [row["id"] for row in rows if row.get("flagged")]
        ok, why = (self.hostsec.recheck(inc) if self.hostsec
                   else (False, "host sensors are disabled on this engine"))
        reasons = []
        reasons.append(f"Live re-observation: {why}.")
        if not rows:
            reasons.append("No stored event rows cover the incident period.")
        if rows and not chain["ok"]:
            reasons.append("Event-chain verification failed.")
        if not rows or not chain["ok"]:
            status = "invalid_evidence"
        elif ok:
            status = "evidence_checked"
            reasons.append("The change is still observable on the live system; "
                           "this is not proof of attacker intent or how it happened.")
        else:
            status = "suspected"
            reasons.append("The live system no longer shows the reported state; recorded as reverted or unconfirmed.")
        detail = {
            "status": status, "actor": actor, "source_ip": inc["source_ip"],
            "period": {"from": first - 60.0, "to": last},
            "event_ids": stored_ids,
            "matching_event_ids": stored_ids if ok else [], "matching_event_count": len(stored_ids) if ok else 0,
            "observed_flagged_count": len(stored_ids),
            "reproduced_flagged_count": len(stored_ids) if ok else 0,
            "reproduced_event_ids": stored_ids if ok else [],
            "chain": chain, "reasons": reasons,
            "note": "Host finding re-checked against the live system; host findings are never network-blocked.",
        }
        self.store.update_incident(inc["id"], validation=status, validation_detail=detail)
        self.audit.write(actor, "incident_validation", str(inc["id"]), status=status,
                         matching_event_count=detail["matching_event_count"],
                         observed_flagged_count=len(stored_ids), reasons=reasons)
        return self.store.get_incident(inc["id"])

    # ---------------- operator actions ----------------
    def approve(self, action_id, actor="operator"):
        action = self.store.get_action(action_id)
        if action and action["action"] in REMEDIATION_ACTIONS:
            # host remediation pipeline: guard re-check, execute, verify the effect live
            inc_id, result = self.remediator.approve(action_id, actor=actor)
            if inc_id:
                self.validate_incident(inc_id, actor=actor)  # alert downgrades if the undo worked
            return inc_id
        inc_id = self.responder.approve(action_id, actor=actor)
        if inc_id:
            inc = self.store.get_incident(inc_id)
            action = self.store.get_action(action_id)
            block = next((b for b in self.store.blocklist() if b.get("incident_id") == inc_id), None)
            enforcement_state = block.get("enforced") if block else None
            if enforcement_state == "enforced":
                self._mark_contained(inc_id, {"enforcement_state": enforcement_state})
            elif inc and enforcement_state == "not_enforced":
                self.store.update_incident(inc_id, status="block_recorded")
            elif inc and enforcement_state == "failed":
                self.store.update_incident(inc_id, status="enforcement_failed")
        return inc_id

    def accept_change(self, inc_id, actor="operator"):
        """Mark a host change as sanctioned: who accepted what is ledgered, the alert is
        closed, and the sensor baseline stays at the approved current state."""
        inc = self.store.get_incident(inc_id)
        if not inc or inc["source_ip"] != "system":
            raise ValueError("only host (system) alerts can be accepted as sanctioned changes")
        if inc["status"] in ("resolved", "allowed"):
            raise ValueError("alert is already closed")
        if self.hostsec is None:
            raise ValueError("host sensors are disabled on this engine")
        obj = str((inc.get("detections") or [{}])[0].get("matched") or inc["category"])
        self.hostsec.accept(obj, actor)
        self.responder.cancel_pending(inc_id, f"change accepted as sanctioned by {actor}")
        self.audit.write(actor, "incident.accept_change", obj, incident=inc_id)
        self.responder._record({"ts": time.time(), "incident_id": inc_id, "action": "accept_change",
                                "target": obj, "mode": "manual", "status": "done",
                                "detail": f"Change accepted as sanctioned by {actor}; baseline updated."})
        self.store.update_incident(inc_id, status="resolved", resolved_at=time.time(),
                                   validation="accepted")
        return self.store.get_incident(inc_id)

    # ---------------- offline adaptation ----------------
    def reload_rules(self):
        return self.rules.reload()

    def train_anomaly(self, actor="operator"):
        result = self.anomaly.train()
        self.audit.write(actor, "ml.train", "anomaly_model", **{k: v for k, v in result.items()})
        return result

    def report(self, inc_id):
        inc = self.store.get_incident(inc_id)
        if not inc:
            return None
        inc = self.validate_incident(inc_id, actor="system:report")
        chain = self.store.verify_chain()
        if not chain["ok"]:
            self._record_error(f"refused report for incident {inc_id}: event chain broken at {chain.get('broken_at')}")
            raise ValueError("Evidence chain is broken; report refused.")
        actions = self.store.list_actions(inc_id)
        bad = [a["id"] for a in actions if not self.responder.verify(a)]
        if bad:
            self._record_error(f"refused report for incident {inc_id}: action records {bad} fail signature check")
            raise ValueError(f"Action record(s) {bad} were changed outside Rakshak (signature check failed); report refused.")
        path = build_report(inc, actions, self.reports_dir,
                            org=getattr(self.conf, "org", "Enterprise Deployment"))
        self.counters["reported"] += 1
        return path
