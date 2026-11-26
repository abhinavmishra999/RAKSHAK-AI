"""Host remediation: undo what the attacker changed - only after a person approves it.

The same discipline as network containment, applied to the machine itself:

  1. The sensor's finding is already re-checked live (engine validation).
  2. An analyst PROPOSES one concrete remediation for that alert (restore file,
     stop process, lock or remove account). Proposal does nothing except create a
     signed record and move the alert to awaiting approval.
  3. A second look happens at approval time: signature valid, alert still open,
     target state re-observed, every safety guard re-confirmed. Stale or edited
     proposals are refused, never executed.
  4. The action then runs and its EFFECT is verified against the live system
     (hash match, socket gone, account state from the account helper). Only a
     verified effect is recorded as done/enforced; anything else is failed or
     refused - with the reason kept in the record and in the audit trail.
  5. After execution the incident is re-validated, so the alert visibly downgrades
     ("reverted") when the remediation worked - the attacker's change is undone and
     the console proves it instead of claiming it.

Safety: root-owned files are NOT written directly (no hidden path to root); those
alerts keep guidance. Account changes go through the hardened rakshak-acct helper
(see deploy/rakshak-acct), never an ad-hoc command line.
"""
import json
import os
import re
import secrets
import signal
import subprocess
import time
from pathlib import Path

from .hostsec import file_state, listen_snapshot, port_line, proc_for_inode, state_sig

REMEDIATION_ACTIONS = ("restore_file", "stop_process", "lock_account", "remove_account")
ACCOUNT_NAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class Remediator:
    def __init__(self, conf, store, audit, hostsec, vault, responder):
        self.conf, self.store, self.audit = conf, store, audit
        self.hostsec = hostsec
        self.vault = vault
        self.responder = responder     # reuses the signed action-record pipeline
        self.acct_cmd = list(getattr(conf, "acct_cmd", ()) or ())
        own_user = "root"
        try:
            import pwd
            own_user = pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            pass
        self.protected_accounts = {"root", own_user} | set(getattr(conf, "never_lock", ()))

    # ---------- what could be done ----------
    def possibilities(self, inc):
        out = []
        if inc["source_ip"] != "system" or not inc.get("detections"):
            return out
        det = inc["detections"][0]
        cat, obj = inc["category"], str(det.get("matched") or "")
        if cat == "file_integrity":
            before, can = det.get("before") or {}, []
            sha = before.get("sha256")
            label = "Restore the file to its recorded original content"
            if not sha:
                can = ["the original content was not readable when recorded (root-owned file): "
                       "restore it from your change-management source instead"]
            elif not (self.vault and self.vault.has(sha)):
                can = ["no vault copy of the recorded hash exists on disk"]
            elif not (os.access(obj, os.W_OK) if Path(obj).exists() else os.access(str(Path(obj).parent), os.W_OK)):
                can = ["the file is not writable by the service user (root-owned): "
                       "restore manually; this console will never ask for hidden root file writes"]
            out.append({"action": "restore_file", "label": label, "target": obj,
                        "possible": not can, "reason": "; ".join(can) or "verified copy available"})
        elif cat == "new_service":
            found = det.get("found") or {}
            proc = found.get("process") if isinstance(found, dict) else None
            label = "Stop the process holding this socket"
            can = []
            if not proc:
                can = ["the owning process is not visible to the service user (different uid); "
                       "investigate with ss/lsof as root"]
            elif proc.get("uid") not in (None, os.getuid()) and os.getuid() != 0:
                can = [f"the process runs as uid {proc.get('uid')}; the agent cannot signal it "
                       "(run the service as root to gain this capability)"]
            out.append({"action": "stop_process", "label": label, "target": obj,
                        "possible": not can,
                        "reason": "; ".join(can) or ("process: " + (proc or {}).get("cmdline", "")[:80]
                                                     if proc else "no attribution")})
        elif cat == "account_change" and ("new account" in str(det.get("name")) or "extra uid-0" in str(det.get("name"))):
            name = obj.split(":")[-1]
            for act, label in (("lock_account", "Lock this account (disable its password logins)"),
                               ("remove_account", "Remove this account and its home directory")):
                can = []
                if not ACCOUNT_NAME_RE.fullmatch(name):
                    can = ["account name is not a safe single identifier"]
                elif name in self.protected_accounts:
                    can = ["this account is protected (the console or its own user)"]
                elif not self.acct_cmd:
                    can = ["no account helper is configured (RAKSHAK_ACCT_CMD); "
                           "see deploy/rakshak-acct for the hardened helper"]
                out.append({"action": act, "label": label, "target": name,
                            "possible": not can, "reason": "; ".join(can) or "helper configured"})
        return out

    def _find(self, inc_id, action):
        inc = self.store.get_incident(inc_id)
        for p in self.possibilities(inc or {}):
            if p["action"] == action:
                return inc, p
        return inc, None

    # ---------- proposal (does nothing to the machine) ----------
    def propose(self, inc_id, action, actor="operator"):
        inc, p = self._find(inc_id, action)
        if inc is None:
            raise ValueError("incident not found")
        if action not in REMEDIATION_ACTIONS or p is None:
            raise ValueError("no such remediation is offered for this alert")
        if inc["status"] not in ("open", "awaiting_approval"):
            raise ValueError(f"alert is {inc['status']}; remediation needs a live alert")
        if not p["possible"]:
            raise ValueError(f"refused: {p['reason']}")
        for a in self.store.list_actions(inc_id):
            if a["action"] == action and a["status"] == "proposed":
                return a, False
        rec = {"ts": time.time(), "incident_id": inc_id, "action": action,
               "target": str(p["target"]), "mode": "recommend", "status": "proposed",
               "detail": f"Remediation proposed by {actor}: {p['label']}. Nothing has been changed yet."}
        act = self.responder._record(rec)
        self.audit.write(actor, "remediation_proposed", str(p["target"]),
                         incident=inc_id, remediation=action)
        self.store.update_incident(inc_id, status="awaiting_approval")
        return act, True

    # ---------- approval: re-check everything, then execute, then verify ----------
    def approve(self, action_id, actor="operator"):
        action = self.store.get_action(action_id)
        if not action or action["action"] not in REMEDIATION_ACTIONS or action["status"] != "proposed":
            return None, None
        if not self.responder.verify(action):
            self.audit.write(actor, "remediation_tamper_refused", action.get("target", ""),
                             action_id=action_id)
            return None, None
        inc = self.store.get_incident(action["incident_id"]) if action["incident_id"] else None
        if inc is None or inc["status"] not in ("open", "awaiting_approval"):
            self.responder._update_action(action_id, status="cancelled",
                                          detail=f"Not applied: alert is {inc['status'] if inc else 'missing'}")
            self.audit.write(actor, "remediation_stale_refused", action["target"], action_id=action_id)
            return None, None
        det = (inc.get("detections") or [{}])[0]
        guards = [p for p in self.possibilities(inc) if p["action"] == action["action"]]
        if not guards or not guards[0]["possible"]:
            why = guards[0]["reason"] if guards else "remediation no longer offered"
            self.responder._update_action(action_id, status="refused", detail=f"Not applied: {why}")
            self.audit.write(actor, "remediation_refused", action["target"], action_id=action_id, reason=why)
            return action["incident_id"], {"state": "refused", "detail": why}
        executors = {"restore_file": self._restore_file, "stop_process": self._stop_process,
                     "lock_account": self._account("lock"), "remove_account": self._account("remove")}
        try:
            result = executors[action["action"]](det, action)
        except Exception as exc:
            result = {"state": "failed", "detail": f"executor error: {type(exc).__name__}: {exc}"}
        status = {"enforced": "done", "not_enforced": "recorded"}.get(result["state"], result["state"])
        if status not in ("done", "recorded", "failed", "refused"):
            status = "failed"
        self.responder._update_action(
            action_id, status=status,
            detail=f"Approved by {actor}. {result['detail']}")
        self.audit.write(actor, "remediation_applied", action["target"],
                         incident=action["incident_id"], remediation=action["action"], result=result)
        return action["incident_id"], result

    def cancel_pending(self, incident_id, why):
        for a in self.store.list_actions(incident_id):
            if a["action"] in REMEDIATION_ACTIONS and a["status"] == "proposed":
                self.responder._update_action(a["id"], status="cancelled", detail=f"Not applied: {why}")

    # ---------- executors (each returns enforced ONLY on live verification) ----------
    def _restore_file(self, det, action):
        path, before = str(det.get("matched") or ""), det.get("before") or {}
        sha = before.get("sha256")
        if not sha or not self.vault.has(sha):
            return {"state": "refused", "detail": "no verified vault copy of the recorded hash"}
        cur = file_state(path)
        if state_sig(cur) == state_sig(before):
            return {"state": "enforced", "detail": f"file already matches the recorded original ({sha[:16]}…)"}
        data = self.vault.load(sha)
        if data is None:
            return {"state": "failed", "detail": "vault copy failed its own hash check; nothing was written"}
        # keep the tampered content too, so the incident can still be studied afterwards
        if cur.get("sha256"):
            self.vault.ensure(path, cur)
        if not (os.access(path, os.W_OK) if Path(path).exists() else os.access(str(Path(path).parent), os.W_OK)):
            return {"state": "refused", "detail": "path is not writable by the service user (root-owned file)"}
        tmp = Path(f"{path}.rakshak-restore.{os.getpid()}.{secrets.token_hex(4)}.tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            try:
                os.chmod(tmp, int(str(before.get("mode") or "0o644"), 8))
            except (OSError, ValueError):
                pass
            os.replace(tmp, path)
        except OSError as exc:
            try:
                tmp.unlink()
            except OSError:
                pass
            return {"state": "failed", "detail": f"restore write failed: {exc}"}
        after = file_state(path)
        if after.get("sha256") == sha:
            return {"state": "enforced", "detail": f"restored; live hash now equals the recorded original ({sha[:16]}…)"}
        return {"state": "failed", "detail": f"restored but live hash differs ({after.get('sha256') or 'gone'}); investigate"}

    def _stop_process(self, det, action):
        obj = str(det.get("matched") or "")
        ports = listen_snapshot(self.conf.proc_net_files)
        if obj not in ports:
            return {"state": "enforced", "detail": f"{obj} is not listening anymore"}
        entry = ports[obj]
        inode = entry.get("inode") if isinstance(entry, dict) else None
        proc = proc_for_inode(inode)          # resolve NOW, not from the stale stored pid
        if not proc:
            return {"state": "refused", "detail": "owning process is not visible to this user; nothing was killed"}
        pid = proc["pid"]
        if os.getuid() != 0 and proc["uid"] != os.getuid():
            return {"state": "refused", "detail": f"process {pid} runs as uid {proc['uid']}; cannot signal"}
        gone = self._terminate(pid, obj, ports)
        if gone:
            return {"state": "enforced",
                    "detail": f"stopped process {pid} ({proc['name']}: {proc['cmdline'][:80]}); "
                              f"verified {obj} is no longer listening"}
        return {"state": "failed",
                "detail": f"signalled process {pid} ({proc['name']}: {proc['cmdline'][:80]}) but {obj} is still listening"}

    def _terminate(self, pid, obj, ports):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            return obj not in listen_snapshot(self.conf.proc_net_files)
        for _ in range(10):
            time.sleep(0.4)
            if obj not in listen_snapshot(self.conf.proc_net_files):
                return True
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        for _ in range(5):
            time.sleep(0.4)
            if obj not in listen_snapshot(self.conf.proc_net_files):
                return True
        return obj not in listen_snapshot(self.conf.proc_net_files)

    def _account(self, mode):
        def run(det, action):
            name = str(action["target"])
            if not ACCOUNT_NAME_RE.fullmatch(name) or name in self.protected_accounts:
                return {"state": "refused", "detail": "account is protected or malformed"}
            if not self.acct_cmd:
                return {"state": "refused", "detail": "no account helper configured"}
            try:
                res = subprocess.run(self.acct_cmd + [mode, name], capture_output=True,
                                     text=True, timeout=15)
            except (OSError, subprocess.TimeoutExpired) as exc:
                return {"state": "failed", "detail": f"account helper error: {exc}"}
            if res.returncode == 2:
                return {"state": "refused", "detail": f"helper refused: {res.stderr.strip()[:160]}"}
            if res.returncode != 0:
                return {"state": "failed", "detail": f"helper error: {res.stderr.strip()[:160]}"}
            # independent second observation via helper 'status' (helper runs as root)
            st = subprocess.run(self.acct_cmd + ["status", name], capture_output=True,
                                text=True, timeout=15)
            try:
                info = json.loads(st.stdout)
            except ValueError:
                return {"state": "failed", "detail": "helper status output was not parseable; state unknown"}
            if mode == "lock" and info.get("locked") is True:
                return {"state": "enforced", "detail": f"account {name} password login locked (verified: {info})"}
            if mode == "remove" and info.get("exists") is False:
                return {"state": "enforced", "detail": f"account {name} removed (verified absent)"}
            return {"state": "failed", "detail": f"helper ran but live state did not match ({info})"}
        return run
