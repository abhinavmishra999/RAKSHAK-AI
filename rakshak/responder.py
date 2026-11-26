"""Containment playbooks.

The default mode records a proposed block only. Network enforcement is considered
successful only when the selected enforcer verifies it; recorded or failed actions
never make an incident look contained.
"""
import hashlib
import hmac
import ipaddress
import json
import time

SIGNED = ("ts", "incident_id", "action", "target", "mode", "status", "detail")


class Responder:
    def __init__(self, store, audit, conf, enforcer, never_block_extra=()):
        self.store = store
        self.audit = audit
        self.conf = conf
        self.enforcer = enforcer
        self.mode = conf.mode
        self.never_block = []
        for item in list(getattr(conf, "never_block", ())) + list(never_block_extra):
            try:
                self.never_block.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                pass
        self._expiry_attempted = set()

    # ---------- signatures ----------
    def _sign(self, rec):
        msg = json.dumps({key: rec.get(key) for key in SIGNED}, sort_keys=True, default=str)
        return hmac.new(self.audit.key, msg.encode(), hashlib.sha256).hexdigest()

    def verify(self, rec):
        """Verify the current action record; callers must not assume old verification."""
        return bool(rec and rec.get("signature") and
                    hmac.compare_digest(self._sign(rec), rec.get("signature")))

    def _record(self, rec):
        rec = dict(rec)
        rec["signature"] = self._sign(rec)
        rec["id"] = self.store.add_action(rec)
        return rec

    def _update_action(self, action_id, **fields):
        """Update and re-sign a mutable action record."""
        self.store.update_action(action_id, **fields)
        rec = self.store.get_action(action_id)
        if rec:
            signature = self._sign(rec)
            self.store.update_action(action_id, signature=signature)
            rec["signature"] = signature
        return rec

    # ---------- safety ----------
    def protected_reason(self, ip: str):
        """Return why this address must never be blocked, or None if allowed."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "not a valid IP address"
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            return "loopback / link-local / multicast address"
        for net in self.never_block:
            if addr in net:
                return f"listed in never-block ({net})"
        return None

    # ---------- main entry ----------
    def handle(self, incident):
        """Called when an incident is created or escalates."""
        ip = incident["source_ip"]
        if self.store.is_blocked(ip) or incident["status"] == "allowed":
            return None
        reason = self.protected_reason(ip)
        if reason:
            already = [a for a in self.store.list_actions(incident["id"])
                       if a["action"] == "block_refused"]
            if not already:
                self._record({"ts": time.time(), "incident_id": incident["id"], "action": "block_refused",
                              "target": ip, "mode": self.mode, "status": "refused",
                              "detail": f"Not blocked: {reason}. Investigate manually."})
                self.audit.write("system", "block_refused", ip, incident=incident["id"], reason=reason)
            return None
        deterministic = any(not d.get("rule_id", "").startswith("ML-")
                            for d in incident.get("detections", []))
        auto = (self.mode == "auto" and incident["severity"] in ("high", "critical")
                and deterministic and incident.get("validation") == "evidence_checked")
        pending = [a for a in self.store.list_actions(incident["id"])
                   if a["action"] == "block_ip" and a["status"] == "proposed"]
        if pending:
            if not auto:
                return None
            result = self._apply_block(ip, incident["category"], incident["id"], actor="system:auto")
            status = "done" if result["state"] == "enforced" else (
                "recorded" if result["state"] == "not_enforced" else "failed")
            updated = self._update_action(
                pending[0]["id"], status=status,
                detail=f"Auto-approved after escalation to {incident['severity']}. {result['detail']}")
            updated["enforcement_state"] = result["state"]
            return updated
        status = "done" if auto else "proposed"
        rec = {"ts": time.time(), "incident_id": incident["id"], "action": "block_ip", "target": ip,
               "mode": self.mode, "status": status, "detail": "Waiting for approval"}
        if auto:
            result = self._apply_block(ip, incident["category"], incident["id"], actor="system:auto")
            rec["status"] = "done" if result["state"] == "enforced" else (
                "recorded" if result["state"] == "not_enforced" else "failed")
            rec["detail"] = result["detail"]
            rec["enforcement_state"] = result["state"]
        action = self._record(rec)
        if not auto:
            self.audit.write("system", "block_proposed", ip, incident=incident["id"], severity=incident["severity"])
        return action

    def _apply_block(self, ip, reason, incident_id, actor):
        expires = time.time() + self.conf.block_ttl if self.conf.block_ttl > 0 else None
        result = self.enforcer.block(ip, self.conf.block_ttl)
        # A database record is intentional even for no-enforcer/failed states: this
        # is a recorded containment decision, not a claim that traffic was blocked.
        self.store.block(ip, reason, incident_id, expires_at=expires, enforced=result["state"])
        self.audit.write(actor, "block_ip", ip, incident=incident_id, reason=reason,
                         expires_at=expires, enforcement=result)
        ttl = f"expires in {self.conf.block_ttl // 3600} h" if expires else "no expiry"
        return {"state": result["state"],
                "detail": f"Added to blocklist ({ttl}). Enforcement: {result['detail']}"}

    def approve(self, action_id, actor="operator"):
        action = self.store.get_action(action_id)
        if not action or action["status"] != "proposed":
            return None
        if not self.verify(action):
            # Edited outside Rakshak: do nothing to the network, keep the evidence as it is.
            self.audit.write(actor, "block_tamper_refused", action.get("target", ""), action_id=action_id)
            return None
        inc = self.store.get_incident(action["incident_id"]) if action["incident_id"] else None
        if inc is None or inc["status"] not in ("open", "awaiting_approval"):
            # The alert was resolved/allowed meanwhile: a stale page must not block anyone.
            self._update_action(action_id, status="cancelled",
                                detail=f"Not applied: alert is {inc['status'] if inc else 'missing'}")
            self.audit.write(actor, "block_stale_refused", action["target"], action_id=action_id,
                             incident_status=inc["status"] if inc else None)
            return None
        reason = self.protected_reason(action["target"])
        if reason:
            self._update_action(action_id, status="refused", detail=f"Not blocked: {reason}")
            return None
        result = self._apply_block(action["target"], inc["category"],
                                   action["incident_id"], actor=actor)
        status = "done" if result["state"] == "enforced" else (
            "recorded" if result["state"] == "not_enforced" else "failed")
        self._update_action(action_id, status=status,
                            detail=f"Approved by {actor}. {result['detail']}")
        return action["incident_id"]

    def cancel_pending(self, incident_id, why):
        """Cancel proposals when an alert is closed, so they cannot be approved later."""
        pending = ("block_ip", "restore_file", "stop_process", "lock_account", "remove_account")
        for a in self.store.list_actions(incident_id):
            if a["action"] in pending and a["status"] == "proposed":
                self._update_action(a["id"], status="cancelled", detail=f"Not applied: {why}")

    def undo(self, ip, actor="operator", why="Undone by operator"):
        result = self.enforcer.unblock(ip)
        # "not_enforced": no firewall is connected, so nothing exists on the network to remove;
        # the recorded block can be cleared. Only a FAILED firewall removal keeps the record.
        removed = result.get("state") in ("removed", "not_enforced")
        state = "done" if removed else "failed"
        detail = f"{why}. Enforcement: {result['detail']}"
        if not removed:
            detail += " Database block retained because removal was not verified."
        self._record({"ts": time.time(), "incident_id": None, "action": "unblock_ip", "target": ip,
                      "mode": "manual" if actor != "system:expiry" else "expiry", "status": state,
                      "detail": detail, "enforcement_state": result.get("state")})
        self.audit.write(actor, "unblock_ip", ip, why=why, enforcement=result,
                         database_block_retained=not removed)
        if removed:
            self.store.unblock(ip)
            for action in self.store.list_actions():
                if action["target"] == ip and action["action"] == "block_ip" and action["status"] in ("done", "recorded"):
                    self._update_action(action["id"], status="undone" if actor != "system:expiry" else "expired",
                                        detail=action.get("detail", ""))
        return result

    def expire(self, now=None):
        n = 0
        for block in self.store.expired_blocks(now or time.time()):
            ip = block["ip"]
            if ip in self._expiry_attempted:
                continue
            self._expiry_attempted.add(ip)
            result = self.undo(ip, actor="system:expiry", why="Block expired")
            n += 1
            if result.get("state") == "removed":
                self._expiry_attempted.discard(ip)
        return n

    def export_rules(self):
        ips = [b["ip"] for b in self.store.blocklist()]
        v4 = [ip for ip in ips if ":" not in ip]
        v6 = [ip for ip in ips if ":" in ip]
        nft = []
        if v4:
            nft.append(f"nft add element inet rakshak blocklist4 {{ {', '.join(v4)} }}")
        if v6:
            nft.append(f"nft add element inet rakshak blocklist6 {{ {', '.join(v6)} }}")
        nginx = "\n".join(f"deny {ip};" for ip in ips)
        return {"nftables": "\n".join(nft), "nginx": nginx, "count": len(ips),
                "note": "Export is advisory; recorded or failed blocks are not proof of firewall enforcement."}
