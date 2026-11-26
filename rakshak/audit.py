"""Signed, hash-chained audit trail.

Every security-relevant decision (logins, plugin trust/enable, test requests,
approvals, refusals, blocks, unblocks, mode changes, validation results) is
written here. Each row contains:
  * hash      = SHA-256(prev_hash + canonical row)   -> deleting/reordering rows breaks the chain
  * signature = HMAC-SHA256(local key, hash)         -> rewriting the whole chain needs the key
The key lives in data/signing.key (chmod 600). Protect the data folder; for
stronger guarantees export the audit log regularly to write-once storage.
"""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path

FIELDS = ("ts", "actor", "action", "object", "detail")


def load_key(path: Path) -> bytes:
    if not path.exists():
        path.write_text(secrets.token_hex(32))
        os.chmod(path, 0o600)
    return path.read_text().strip().encode()


def _canon(row) -> str:
    return json.dumps({k: row[k] for k in FIELDS}, sort_keys=True, default=str)


class AuditLog:
    def __init__(self, store, key: bytes):
        self.store = store
        self.key = key
        self._lock = threading.Lock()

    def sign(self, data: str) -> str:
        return hmac.new(self.key, data.encode(), hashlib.sha256).hexdigest()

    def write(self, actor: str, action: str, obj: str = "", **detail) -> int:
        with self._lock:
            row = {"ts": round(time.time(), 6), "actor": actor or "system", "action": action,
                   "object": str(obj), "detail": json.dumps(detail, sort_keys=True, default=str)}
            prev = self.store.last_audit_hash()
            row["prev_hash"] = prev
            row["hash"] = hashlib.sha256((prev + _canon(row)).encode()).hexdigest()
            row["signature"] = self.sign(row["hash"])
            return self.store.add_audit(row)

    def verify(self) -> dict:
        prev, n = "GENESIS", 0
        for row in self.store.all_audit():
            h = hashlib.sha256((prev + _canon(row)).encode()).hexdigest()
            if row["prev_hash"] != prev or row["hash"] != h:
                return {"ok": False, "checked": n, "broken_at": row["id"], "reason": "hash chain broken"}
            if not hmac.compare_digest(self.sign(h), row["signature"] or ""):
                return {"ok": False, "checked": n, "broken_at": row["id"], "reason": "bad signature"}
            prev, n = h, n + 1
        return {"ok": True, "checked": n}

    def list(self, limit=200, prefix=None):
        out = []
        for r in self.store.list_audit(limit, prefix):
            r["detail"] = json.loads(r["detail"] or "{}")
            out.append(r)
        return out
