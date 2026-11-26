"""Secure reviewed-plugin lifecycle.

Plugins are data until enabled by an administrator. Active requests are always
queued and require a separate ``approve`` call. This module intentionally does
not import Rakshak's API or engine.

The process boundary is deliberately described honestly: argv is shell-free,
resource-limited and hash-pinned, but this is not a full filesystem or packet
sandbox. External plugins stay disabled unless ``RAKSHAK_ALLOW_EXTERNAL_PLUGINS=1``.
"""
import hashlib
import hmac
import ipaddress
import json
import os
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import executor, findings, validators
from .manifest import load_manifest, resolve_executable
from .scope import Scope, TargetError


class PluginRunner:
    def __init__(self, conf, store, audit):
        self.conf = conf
        self.store = store
        self.audit = audit
        self.scope = Scope(Path(conf.data_dir) / "scope.yml", store.attacker_ips)
        self._lock = threading.RLock()
        self._sems = {}
        self.plugins = {}
        self.reload()

    def reload(self):
        found = {}
        builtin_root = Path(self.conf.builtin_plugins)
        external_root = Path(self.conf.plugins_dir)
        for root, builtin in ((builtin_root, True), (external_root, False)):
            if not root.is_dir():
                continue
            try:
                folders = sorted(p for p in root.iterdir() if p.is_dir())
            except OSError:
                folders = []
            for folder in folders:
                if not (folder / "plugin.yml").is_file():
                    continue
                try:
                    plugin = load_manifest(folder, builtin=builtin)
                except (OSError, ValueError) as exc:
                    # Keep a visible, unavailable entry rather than silently loading it.
                    continue
                # A built-in cannot be shadowed by an external folder of the same ID.
                if plugin.id and plugin.id not in found:
                    found[plugin.id] = plugin
        self.plugins = found
        return self.plugins

    def _plugin(self, plugin_id):
        self.reload()
        p = self.plugins.get(str(plugin_id))
        if p is None:
            raise ValueError(f"Unknown plugin: {plugin_id}")
        return p

    @staticmethod
    def _allow_external():
        return os.environ.get("RAKSHAK_ALLOW_EXTERNAL_PLUGINS") == "1"

    def _inspect(self, p, require_enabled=False):
        """Reload manifest, resolve executable, and return current trust metadata."""
        try:
            current = load_manifest(p.folder, builtin=p.builtin)
        except (OSError, ValueError) as exc:
            raise ValueError(f"Plugin {p.id} manifest cannot be read: {exc}") from exc
        if current.problems:
            raise ValueError("; ".join(current.problems))
        if not current.builtin and not self._allow_external():
            raise ValueError("External plugins are disabled; set RAKSHAK_ALLOW_EXTERNAL_PLUGINS=1 only after review.")
        argv, executable, error = resolve_executable(current)
        if error:
            raise ValueError(error)
        actual_hash = self._file_hash(executable)
        if current.sha256 and not hmac.compare_digest(actual_hash, current.sha256):
            raise ValueError(f"Executable hash mismatch: manifest pins {current.sha256}, observed {actual_hash}.")
        state = self.store.get_plugin_state(current.id)
        if require_enabled and not state or (require_enabled and not int(state.get("enabled", 0))):
            raise ValueError(f"Plugin '{current.id}' is not enabled.")
        if state and state.get("enabled"):
            if state.get("exec_sha256") != actual_hash:
                raise ValueError("Refused: enabled plugin executable changed after it was pinned.")
            if state.get("manifest_sha256") != current.manifest_sha256:
                raise ValueError("Refused: enabled plugin manifest changed after it was pinned.")
        return current, argv, executable, actual_hash, state

    @staticmethod
    def _file_hash(path):
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()

    def _public(self, p):
        d = p.public()
        d.update({"available": False, "enabled": False, "trusted_hash": "", "trusted_hashes": [], "reason": ""})
        if not p.builtin and not self._allow_external():
            d["reason"] = "External plugin disabled by default; explicit RAKSHAK_ALLOW_EXTERNAL_PLUGINS=1 is required."
            return d
        try:
            _, _, executable, actual_hash, state = self._inspect(p)
            d["available"] = True
            if state:
                d["enabled"] = bool(state.get("enabled"))
                d["trusted_hash"] = state.get("exec_sha256") or ""
                d["trusted_hashes"] = [x for x in (state.get("exec_sha256"), state.get("manifest_sha256")) if x]
            else:
                d["reason"] = "Available but disabled; an administrator must enable and pin its executable."
            if state and state.get("enabled") and state.get("exec_sha256") != actual_hash:
                d["available"] = False
                d["reason"] = "Executable changed after enable; re-enable is required."
        except ValueError as exc:
            d["reason"] = str(exc)
        return d

    def list(self):
        self.reload()
        return [self._public(p) for p in sorted(self.plugins.values(), key=lambda x: x.id)]

    def enable(self, plugin_id, actor):
        p = self._plugin(plugin_id)
        if not actor:
            raise ValueError("An actor is required to enable a plugin.")
        current, _, executable, actual_hash, _ = self._inspect(p)
        now = time.time()
        self.store.put_plugin_state({"plugin_id": current.id, "enabled": True,
                                     "exec_path": str(executable), "exec_sha256": actual_hash,
                                     "manifest_sha256": current.manifest_sha256,
                                     "enabled_by": str(actor), "enabled_at": now})
        self._audit(actor, "plugin_enable", current.id, executable=str(executable),
                    exec_sha256=actual_hash, manifest_sha256=current.manifest_sha256)
        return self._public(current)

    def disable(self, plugin_id, actor):
        p = self._plugin(plugin_id)
        if not actor:
            raise ValueError("An actor is required to disable a plugin.")
        state = self.store.get_plugin_state(p.id) or {}
        self.store.put_plugin_state({"plugin_id": p.id, "enabled": False,
                                     "exec_path": state.get("exec_path"),
                                     "exec_sha256": state.get("exec_sha256"),
                                     "manifest_sha256": state.get("manifest_sha256"),
                                     "enabled_by": actor, "enabled_at": time.time()})
        self._audit(actor, "plugin_disable", p.id)
        return self._public(p)

    def _audit(self, actor, action, obj, **detail):
        return self.audit.write(str(actor or "system"), action, str(obj), **detail)

    @staticmethod
    def _payload(run):
        fields = ("id", "plugin_id", "plugin_version", "kind", "target", "status", "reason",
                  "requested_by", "requested_at", "authorised_statement", "approved_by", "approved_at",
                  "started_at", "finished_at", "cmd", "file_hashes", "exit_code", "stdout_sha256",
                  "stdout_bytes", "stderr_tail", "findings", "summary")
        return json.dumps({k: run.get(k) for k in fields}, sort_keys=True, separators=(",", ":"), default=str)

    def _sign_run(self, run_id):
        run = self.store.get_run(run_id)
        if not run:
            return None
        sig = self.audit.sign(self._payload(run))
        self.store.update_run(run_id, signature=sig)
        return sig

    def _refuse(self, p, actor, target, reason, requested_by=None, summary=None, statement=""):
        now = time.time()
        d = {"plugin_id": p.id, "plugin_version": getattr(p, "version", ""), "kind": getattr(p, "kind", "active"),
             "target": str(target or ""), "status": "refused", "reason": str(reason),
             "requested_by": str(requested_by or actor or ""), "requested_at": now,
             "authorised_statement": str(statement or "")[:500], "file_hashes": {}, "findings": [],
             "summary": summary or {"reason": str(reason)}}
        run_id = self.store.add_run(d)
        self._sign_run(run_id)
        self._audit(actor, "plugin_refused", p.id, run_id=run_id, target=str(target or ""), reason=str(reason))
        return self.store.get_run(run_id)

    def _target(self, p, target):
        if p.id == "website-check" and p.target_type == "url" and "://" not in str(target):
            raise TargetError("Refused: website-check requires a URL with an explicit http:// or https:// scheme.")
        host, normal = Scope.parse_target(target, p.target_type)
        if p.target_type == "url":
            try:
                ipaddress.ip_address(host)
            except ValueError as exc:
                raise TargetError("Refused: web checks require a numeric-IP URL in this version to prevent DNS rebinding.") from exc
            u = urlsplit(normal)
            if p.id == "website-check":
                if u.path not in ("", "/") or u.query or u.fragment:
                    raise TargetError("Refused: website-check accepts only scheme://IP[:port], without a path or query.")
                # Rebuild the origin from the validated literal. Fixed probe paths
                # are selected by webchecks; user input never becomes a request path.
                literal = f"[{host}]" if ":" in host else host
                normal = f"{u.scheme}://{literal}{f':{u.port}' if u.port else ''}"
        ips = self.scope.check(host)
        # Stable sorted resolution is pinned into the approval record.
        if p.id == "website-check" and p.target_type == "url":
            u = urlsplit(normal)
            first_ip = str(ips[0])
            literal = f"[{first_ip}]" if ":" in first_ip else first_ip
            normal = f"{u.scheme}://{literal}{f':{u.port}' if u.port else ''}"
        return host, normal, [str(x) for x in ips]

    def request(self, plugin_id, target, actor, reason, authorised: bool):
        p = self._plugin(plugin_id)
        if not actor or not reason:
            raise ValueError("An actor and a plain-language reason are required.")
        if not isinstance(authorised, bool):
            raise ValueError("authorised must be a boolean.")
        try:
            current, _, executable, actual_hash, state = self._inspect(p, require_enabled=True)
            if current.kind != "active":
                raise ValueError("Only active plugins use target approval requests.")
            if not authorised:
                raise ValueError("The requester must explicitly attest authorisation before an active request is queued.")
            host, normal, ips = self._target(current, target)
        except (ValueError, TargetError) as exc:
            self._refuse(p, actor, target, str(exc), requested_by=actor, statement=reason)
            raise ValueError(str(exc)) from exc
        now = time.time()
        summary = {"state": "pending_approval", "resolved_ips": ips, "approved_target_ips": ips,
                   "host": host, "target_type": current.target_type,
                   "note": "Addresses are pinned at request time and rechecked at approval."}
        run_id = self.store.add_run({
            "plugin_id": current.id, "plugin_version": current.version, "kind": current.kind,
            "target": normal, "status": "queued", "reason": reason, "requested_by": actor,
            "requested_at": now, "authorised_statement": reason, "cmd": [],
            "file_hashes": {"executable": actual_hash, "manifest": current.manifest_sha256},
            "findings": [], "summary": summary,
        })
        self._sign_run(run_id)
        self._audit(actor, "plugin_request", current.id, run_id=run_id, target=normal,
                    reason=reason, resolved_ips=ips, authorised=True)
        return self.store.get_run(run_id)

    def _refuse_existing(self, run, actor, reason):
        self.store.update_run(run["id"], status="refused", reason=str(reason), finished_at=time.time(),
                              summary={**(run.get("summary") or {}), "reason": str(reason)})
        self._sign_run(run["id"])
        self._audit(actor, "plugin_refused", run["plugin_id"], run_id=run["id"], reason=str(reason))
        return self.store.get_run(run["id"])

    def approve(self, run_id, actor, approver_role):
        run = self.store.get_run(int(run_id))
        if not run:
            raise ValueError("Plugin run does not exist.")
        if not self._verified(run):
            self._audit(actor, "plugin_tamper_refused", run["plugin_id"], run_id=run["id"])
            raise ValueError("Refused: the request record signature does not verify. No tool will be launched.")
        if run.get("status") != "queued":
            raise ValueError("Only a pending plugin request can be approved.")
        if not actor:
            raise ValueError("An approving actor is required.")
        if not approver_role:
            raise ValueError("An approver role is required.")
        p = self._plugin(run["plugin_id"])
        try:
            current, argv_prefix, executable, actual_hash, state = self._inspect(p, require_enabled=True)
            if current.approval == "admin" and approver_role != "admin":
                raise ValueError("Refused: this plugin requires an admin approver.")
            if getattr(self.conf, "two_person", False) and str(actor) == str(run.get("requested_by")):
                raise ValueError("Refused: two-person approval requires a different approver.")
            if current.manifest_sha256 != (run.get("file_hashes") or {}).get("manifest"):
                raise ValueError("Refused: manifest changed after request.")
            if actual_hash != (run.get("file_hashes") or {}).get("executable"):
                raise ValueError("Refused: executable changed after request.")
            host, normal, ips = self._target(current, run.get("target", ""))
            pinned = (run.get("summary") or {}).get("approved_target_ips") or (run.get("summary") or {}).get("resolved_ips")
            if ips != pinned:
                raise ValueError("Refused: target DNS/address resolution changed after request.")
        except (ValueError, TargetError) as exc:
            return self._refuse_existing(run, actor, str(exc))

        node = ips[0] if ips else host
        with self._lock:
            sem = self._sems.setdefault(node, threading.Semaphore(1))
        if not sem.acquire(blocking=False):
            return self._refuse_existing(run, actor, "Refused: another plugin execution is already active for this target node.")
        started = time.time()
        try:
            target_arg = node if current.target_type == "host" else normal
            cmd = [x.replace("{target}", target_arg) for x in current.args]
            cmd = argv_prefix + cmd
            self.store.update_run(run["id"], status="running", approved_by=str(actor), approved_at=started,
                                  started_at=started, cmd=cmd,
                                  file_hashes={"executable": actual_hash, "manifest": current.manifest_sha256,
                                               "target_ips": ips})
            self._sign_run(run["id"])
            self._audit(actor, "plugin_approve", current.id, run_id=run["id"], target=normal, resolved_ips=ips)
            workdir = Path(self.conf.data_dir) / "plugin-runs" / str(run["id"])
            result = executor.execute(cmd, workdir, current.timeout_s, current.max_output_kb,
                                      plugin_user=getattr(self.conf, "plugin_user", ""))
            fields = {"exit_code": result.get("exit_code"), "stdout_sha256": result.get("stdout_sha256"),
                      "stdout_bytes": result.get("stdout_bytes", 0), "stderr_tail": result.get("stderr_tail", "")}
            reason = result.get("error", "")
            parse_error = ""
            parsed = []
            if not reason and (result.get("timed_out") or result.get("truncated")):
                reason = "Plugin timed out or exceeded its output cap; no output was parsed."
            if not reason and result.get("exit_code") != 0:
                reason = f"Plugin exited with code {result.get('exit_code')}; no findings were accepted."
            if not reason:
                try:
                    parsed = findings.PARSERS[current.parser](result.get("stdout", ""))
                    # Connect the validator to the same numeric-IP target that the tool used.
                    parsed = validators.validate_findings(current, target_arg, parsed)
                except (ValueError, TypeError, KeyError) as exc:
                    parse_error = str(exc)
                    reason = f"Plugin output was rejected: {parse_error}"
            status = "completed" if not reason else "failed"
            summary = {"status": status, "duration_s": result.get("duration_s"),
                       "finding_count": len(parsed), "failed_findings": sum(1 for f in parsed if not f.get("passed")),
                       "observed_passes": sum(1 for f in parsed if f.get("status") == "observed_pass"),
                       "note": "Observed passes are not proof of security."}
            if reason:
                summary["reason"] = reason
            self.store.update_run(run["id"], status=status, reason=reason, finished_at=time.time(),
                                  **fields, findings=parsed, summary=summary)
            self._sign_run(run["id"])
            self._audit(actor, "plugin_result", current.id, run_id=run["id"], status=status,
                        finding_count=len(parsed), reason=reason)
            return self.store.get_run(run["id"])
        finally:
            sem.release()

    def reject(self, run_id, actor, why):
        run = self.store.get_run(int(run_id))
        if not run:
            raise ValueError("Plugin run does not exist.")
        if not self._verified(run):
            self._audit(actor, "plugin_tamper_refused", run["plugin_id"], run_id=run["id"])
            raise ValueError("Refused: the request record signature does not verify.")
        if run.get("status") != "queued":
            raise ValueError("Only a pending plugin request can be rejected.")
        if not actor or not why:
            raise ValueError("A rejecting actor and reason are required.")
        self.store.update_run(run["id"], status="refused", reason=str(why), finished_at=time.time(),
                              summary={**(run.get("summary") or {}), "state": "rejected", "reason": str(why)})
        self._sign_run(run["id"])
        self._audit(actor, "plugin_reject", run["plugin_id"], run_id=run["id"], reason=str(why))
        return self.store.get_run(run["id"])

    def _verified(self, run):
        if not run or not run.get("signature"):
            return False
        try:
            expected = self.audit.sign(self._payload(run))
            return hmac.compare_digest(expected, run.get("signature") or "")
        except Exception:
            return False

    def view(self, run_id):
        run = self.store.get_run(int(run_id))
        if not run:
            raise ValueError("Plugin run does not exist.")
        run["verified"] = self._verified(run)
        return run

    def list_runs(self, limit=100):
        return [{**run, "verified": self._verified(run)} for run in self.store.list_runs(limit=int(limit))]


# Compatibility name for callers that only need scope parsing. The runner itself
# deliberately owns a Scope instance and does not depend on API/engine modules.
ScopeManager = Scope
