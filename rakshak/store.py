"""Local SQLite storage for events, incidents, actions, blocklist, audit trail,
plugin runs and dashboard users.

Tamper evidence:
  * every event row stores a SHA-256 hash chained to the previous row;
  * every audit row is chained the same way AND signed with the local HMAC key
    (see audit.py), so edits or deletions are detectable.
All access goes through one re-entrant lock so the engine, workers and API threads
can share a single connection safely.
"""
import hashlib
import json
import os
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, source_ip TEXT, kind TEXT,
    method TEXT, path TEXT, query TEXT, body TEXT, status INTEGER, user_agent TEXT,
    raw TEXT, flagged INTEGER DEFAULT 0, prev_hash TEXT, hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip, ts);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT, source_ip TEXT, category TEXT, severity TEXT, status TEXT,
    first_seen REAL, last_seen REAL, detected_at REAL, contained_at REAL, resolved_at REAL,
    event_count INTEGER DEFAULT 0, ai_score REAL DEFAULT 0, ai_reasons TEXT, detections TEXT,
    evidence TEXT, categories TEXT, validation TEXT DEFAULT 'pending', validation_detail TEXT
);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, incident_id INTEGER, action TEXT, target TEXT,
    mode TEXT, status TEXT, detail TEXT, signature TEXT
);
CREATE TABLE IF NOT EXISTS blocklist (
    ip TEXT PRIMARY KEY, reason TEXT, incident_id INTEGER, added_at REAL, expires_at REAL,
    enforced TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT, object TEXT,
    detail TEXT, prev_hash TEXT, hash TEXT, signature TEXT
);
CREATE TABLE IF NOT EXISTS plugin_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, plugin_id TEXT, plugin_version TEXT, kind TEXT,
    target TEXT, status TEXT, reason TEXT,
    requested_by TEXT, requested_at REAL, authorised_statement TEXT,
    approved_by TEXT, approved_at REAL, started_at REAL, finished_at REAL,
    cmd TEXT, file_hashes TEXT, exit_code INTEGER, stdout_sha256 TEXT, stdout_bytes INTEGER,
    stderr_tail TEXT, findings TEXT, summary TEXT, signature TEXT
);
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, role TEXT, salt TEXT, pw_hash TEXT, iterations INTEGER,
    created_at REAL, disabled INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS plugin_state (
    plugin_id TEXT PRIMARY KEY, enabled INTEGER DEFAULT 0, exec_path TEXT, exec_sha256 TEXT,
    manifest_sha256 TEXT, enabled_by TEXT, enabled_at REAL
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, username TEXT NOT NULL, csrf TEXT NOT NULL, expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
    name TEXT PRIMARY KEY, added_at REAL, last_seen REAL, events_total INTEGER DEFAULT 0,
    last_seq INTEGER DEFAULT 0
);
"""
# columns added after the first release; added to old databases on start-up
MIGRATIONS = {
    "blocklist": {"expires_at": "REAL", "enforced": "TEXT"},
    "events": {"node": "TEXT DEFAULT ''"},
    "incidents": {"validation": "TEXT DEFAULT 'pending'", "validation_detail": "TEXT",
                  "node": "TEXT DEFAULT ''"},
}
JSON_COLS = ("ai_reasons", "detections", "evidence", "categories", "validation_detail")
RUN_JSON = ("cmd", "file_hashes", "findings", "summary")
HASHED = ("ts", "source_ip", "kind", "method", "path", "query", "body", "status", "user_agent", "raw")


def event_digest(prev, ev):
    payload = json.dumps({k: ev.get(k) for k in HASHED}, sort_keys=True, default=str)
    return hashlib.sha256((prev + payload).encode()).hexdigest()


class Store:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not db_path.exists():
            os.close(os.open(db_path, os.O_CREAT | os.O_WRONLY, 0o600))   # holds password hashes and evidence
        self.path = db_path
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            for extra in (db_path, Path(f"{db_path}-wal"), Path(f"{db_path}-shm")):
                try:
                    if extra.exists() and extra.stat().st_uid == os.getuid():
                        os.chmod(extra, 0o600)
                except OSError:
                    pass
            self.conn.executescript(SCHEMA)
            for table, cols in MIGRATIONS.items():
                have = {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}
                for col, decl in cols.items():
                    if col not in have:
                        self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
            self.conn.commit()
        row = self._one("SELECT hash FROM events ORDER BY id DESC LIMIT 1")
        self._last_hash = row["hash"] if row else "GENESIS"
        self._blocked = {b["ip"] for b in self.blocklist()}

    # ---------- helpers ----------
    def _all(self, sql, params=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def _one(self, sql, params=()):
        with self.lock:
            r = self.conn.execute(sql, params).fetchone()
            return dict(r) if r else None

    def _write(self, sql, params=()):
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur.lastrowid

    # ---------- events (hash-chained) ----------
    def add_event(self, ev: dict, flagged: bool) -> int:
        with self.lock:
            h = event_digest(self._last_hash, ev)
            rid = self._write(
                "INSERT INTO events(ts,source_ip,kind,method,path,query,body,status,user_agent,raw,flagged,prev_hash,hash,node)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (*[ev.get(k) for k in HASHED], int(flagged), self._last_hash, h,
                 str(ev.get("node") or "")[:64]))
            self._last_hash = h
            return rid

    def verify_chain(self) -> dict:
        prev, n = "GENESIS", 0
        with self.lock:
            cur = self.conn.execute("SELECT * FROM events ORDER BY id")
            for r in cur:
                row = dict(r)
                if row["prev_hash"] != prev or row["hash"] != event_digest(prev, row):
                    return {"ok": False, "broken_at": row["id"], "checked": n}
                prev, n = row["hash"], n + 1
        return {"ok": True, "checked": n}

    def verify_event_rows(self, rows) -> dict:
        """Check a subset of events: each row's own hash and its link to the row before it."""
        bad = []
        for row in rows:
            if row["hash"] != event_digest(row["prev_hash"], row):
                bad.append(row["id"])
                continue
            before = self._one("SELECT hash FROM events WHERE id < ? ORDER BY id DESC LIMIT 1", (row["id"],))
            expected_prev = before["hash"] if before else "GENESIS"
            if row["prev_hash"] != expected_prev:
                bad.append(row["id"])
        return {"ok": not bad, "checked": len(rows), "bad_ids": bad[:20]}

    def events_for(self, ip: str, t0: float, t1: float, limit: int = 5000):
        return self._all("SELECT * FROM events WHERE source_ip=? AND ts>=? AND ts<=? ORDER BY id LIMIT ?",
                         (ip, t0, t1, limit))

    def count_events(self, since: float = 0) -> int:
        return self._one("SELECT COUNT(*) c FROM events WHERE ts >= ?", (since,))["c"]

    def count_flagged(self) -> int:
        return self._one("SELECT COUNT(*) c FROM events WHERE flagged=1")["c"]

    def source_share(self, ips, since: float) -> dict:
        tot = self.count_events(since)
        if not ips or not tot:
            return {"total": tot, "share": 0.0}
        q = ",".join("?" * len(ips))
        n = self._one(f"SELECT COUNT(*) c FROM events WHERE ts>=? AND source_ip IN ({q})", (since, *ips))["c"]
        return {"total": tot, "share": n / tot}

    def traffic(self, window: int = 120):
        now = int(time.time())
        rows = self._all("SELECT CAST(ts AS INTEGER) s, COUNT(*) c, SUM(flagged) f FROM events "
                         "WHERE ts >= ? GROUP BY s", (now - window,))
        by = {r["s"]: r for r in rows}
        return [{"t": s, "total": by.get(s, {}).get("c", 0) or 0, "attack": by.get(s, {}).get("f", 0) or 0}
                for s in range(now - window + 1, now + 1)]

    def recent_events(self, limit: int = 40):
        return self._all("SELECT id,ts,source_ip,kind,method,path,query,status,flagged FROM events "
                         "ORDER BY id DESC LIMIT ?", (limit,))

    # ---------- incidents ----------
    def open_incident_for_ip(self, ip: str, within: float = 300):
        r = self._one("SELECT * FROM incidents WHERE source_ip=? AND status != 'resolved' AND last_seen >= ? "
                      "ORDER BY id DESC LIMIT 1", (ip, time.time() - within))
        return self._inc(r) if r else None

    def create_incident(self, d: dict) -> int:
        return self._write(
            "INSERT INTO incidents(source_ip,category,severity,status,first_seen,last_seen,detected_at,"
            "event_count,ai_score,ai_reasons,detections,evidence,categories,validation,validation_detail,node)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (d["source_ip"], d["category"], d["severity"], d["status"], d["first_seen"], d["last_seen"],
             d["detected_at"], d.get("event_count", 1), d.get("ai_score", 0),
             *[json.dumps(d.get(k, [])) for k in JSON_COLS[:4]], "pending", json.dumps({}),
              str(d.get("node") or "")[:64]))

    def update_incident(self, inc_id: int, **fields):
        if not fields:
            return
        for k in JSON_COLS:
            if k in fields:
                fields[k] = json.dumps(fields[k])
        cols = ", ".join(f"{k}=?" for k in fields)
        self._write(f"UPDATE incidents SET {cols} WHERE id=?", (*fields.values(), inc_id))

    def get_incident(self, inc_id: int):
        r = self._one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        return self._inc(r) if r else None

    def list_incidents(self, limit: int = 200):
        return [self._inc(r) for r in self._all("SELECT * FROM incidents ORDER BY last_seen DESC LIMIT ?", (limit,))]

    @staticmethod
    def _inc(d):
        for k in JSON_COLS:
            default = {} if k == "validation_detail" else []
            d[k] = json.loads(d[k]) if d.get(k) else default
        return d

    # ---------- actions & blocklist ----------
    def add_action(self, d: dict) -> int:
        return self._write("INSERT INTO actions(ts,incident_id,action,target,mode,status,detail,signature) "
                           "VALUES(?,?,?,?,?,?,?,?)",
                           (d["ts"], d.get("incident_id"), d["action"], d["target"], d["mode"], d["status"],
                            d.get("detail", ""), d.get("signature", "")))

    def list_actions(self, incident_id: int = None, limit: int = 300):
        if incident_id is None:
            return self._all("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,))
        return self._all("SELECT * FROM actions WHERE incident_id=? ORDER BY id", (incident_id,))

    def get_action(self, action_id: int):
        return self._one("SELECT * FROM actions WHERE id=?", (action_id,))

    def update_action(self, action_id: int, **fields):
        cols = ", ".join(f"{k}=?" for k in fields)
        self._write(f"UPDATE actions SET {cols} WHERE id=?", (*fields.values(), action_id))

    def block(self, ip: str, reason: str, incident_id: int = None, expires_at: float = None, enforced: str = ""):
        self._write("INSERT OR REPLACE INTO blocklist(ip,reason,incident_id,added_at,expires_at,enforced) "
                    "VALUES(?,?,?,?,?,?)", (ip, reason, incident_id, time.time(), expires_at, enforced))
        self._blocked.add(ip)

    def set_block_enforced(self, ip: str, enforced: str):
        self._write("UPDATE blocklist SET enforced=? WHERE ip=?", (enforced, ip))

    def unblock(self, ip: str):
        self._write("DELETE FROM blocklist WHERE ip=?", (ip,))
        self._blocked.discard(ip)

    def blocklist(self):
        return self._all("SELECT * FROM blocklist ORDER BY added_at DESC")

    def expired_blocks(self, now: float):
        return self._all("SELECT * FROM blocklist WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,))

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    # ---------- audit (rows are signed by audit.AuditLog) ----------
    def last_audit_hash(self):
        r = self._one("SELECT hash FROM audit ORDER BY id DESC LIMIT 1")
        return r["hash"] if r else "GENESIS"

    def add_audit(self, row: dict) -> int:
        return self._write("INSERT INTO audit(ts,actor,action,object,detail,prev_hash,hash,signature) "
                           "VALUES(?,?,?,?,?,?,?,?)",
                           (row["ts"], row["actor"], row["action"], row["object"], row["detail"],
                            row["prev_hash"], row["hash"], row["signature"]))

    def list_audit(self, limit: int = 200, action_prefix: str = None):
        if action_prefix:
            return self._all("SELECT * FROM audit WHERE action LIKE ? ORDER BY id DESC LIMIT ?",
                             (action_prefix + "%", limit))
        return self._all("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))

    def all_audit(self):
        return self._all("SELECT * FROM audit ORDER BY id")

    # ---------- plugin runs ----------
    def add_run(self, d: dict) -> int:
        cols = list(d.keys())
        vals = [json.dumps(d[c]) if c in RUN_JSON else d[c] for c in cols]
        return self._write(f"INSERT INTO plugin_runs({','.join(cols)}) VALUES({','.join('?' * len(cols))})", vals)

    def update_run(self, run_id: int, **fields):
        for k in RUN_JSON:
            if k in fields:
                fields[k] = json.dumps(fields[k])
        cols = ", ".join(f"{k}=?" for k in fields)
        self._write(f"UPDATE plugin_runs SET {cols} WHERE id=?", (*fields.values(), run_id))

    def get_run(self, run_id: int):
        r = self._one("SELECT * FROM plugin_runs WHERE id=?", (run_id,))
        return self._run(r) if r else None

    def list_runs(self, limit: int = 100, plugin_id: str = None):
        if plugin_id:
            rows = self._all("SELECT * FROM plugin_runs WHERE plugin_id=? ORDER BY id DESC LIMIT ?", (plugin_id, limit))
        else:
            rows = self._all("SELECT * FROM plugin_runs ORDER BY id DESC LIMIT ?", (limit,))
        return [self._run(r) for r in rows]

    @staticmethod
    def _run(d):
        for k in RUN_JSON:
            d[k] = json.loads(d[k]) if d.get(k) else ([] if k == "findings" else {})
        return d

    # ---------- users ----------
    def get_user(self, username: str):
        return self._one("SELECT * FROM users WHERE username=?", (username,))

    # ---------- sessions (persisted: a restart no longer signs everyone out) ----------
    def put_session(self, token, username, csrf, expires):
        self._write("INSERT OR REPLACE INTO sessions(token,username,csrf,expires) VALUES(?,?,?,?)",
                    (token, username, csrf, expires))

    def get_session(self, token):
        return self._one("SELECT * FROM sessions WHERE token=?", (token,))

    def drop_session(self, token):
        self._write("DELETE FROM sessions WHERE token=?", (token,))

    def active_sessions(self, now=None):
        return self._all("SELECT * FROM sessions WHERE expires>?", (now or time.time(),))

    def prune_sessions(self, now=None):
        self._write("DELETE FROM sessions WHERE expires<=?", (now or time.time(),))

    # ---------- distributed sensor nodes ----------
    def upsert_node(self, name, seq, events, now=None):
        now = now or time.time()
        self._write(
            "INSERT INTO nodes(name,added_at,last_seen,events_total,last_seq) VALUES(?,?,?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET last_seen=?, events_total=events_total+?, last_seq=?",
            (name, now, now, events, seq, now, events, seq))

    def get_node(self, name):
        return self._one("SELECT * FROM nodes WHERE name=?", (name,))

    def list_nodes(self):
        return self._all("SELECT * FROM nodes ORDER BY last_seen DESC")

    def list_users(self):
        return self._all("SELECT username, role, created_at, disabled FROM users ORDER BY username")

    def put_user(self, u: dict):
        self._write("INSERT OR REPLACE INTO users(username,role,salt,pw_hash,iterations,created_at,disabled) "
                    "VALUES(?,?,?,?,?,?,?)", (u["username"], u["role"], u["salt"], u["pw_hash"],
                                              u["iterations"], u.get("created_at", time.time()),
                                              int(u.get("disabled", 0))))

    def user_count(self) -> int:
        return self._one("SELECT COUNT(*) c FROM users WHERE disabled=0")["c"]

    # ---------- plugin trust state ----------
    def get_plugin_state(self, plugin_id: str):
        return self._one("SELECT * FROM plugin_state WHERE plugin_id=?", (plugin_id,))

    def put_plugin_state(self, s: dict):
        self._write("INSERT OR REPLACE INTO plugin_state(plugin_id,enabled,exec_path,exec_sha256,manifest_sha256,"
                    "enabled_by,enabled_at) VALUES(?,?,?,?,?,?,?)",
                    (s["plugin_id"], int(s["enabled"]), s.get("exec_path"), s.get("exec_sha256"),
                     s.get("manifest_sha256"), s.get("enabled_by"), s.get("enabled_at")))

    def pending_runs(self):
        return self._all("SELECT id FROM plugin_runs WHERE status IN ('queued','running')")

    def attacker_ips(self) -> set:
        """Every source address Rakshak has ever flagged or blocked: these are never scanned."""
        ips = {r["source_ip"] for r in self._all("SELECT DISTINCT source_ip FROM incidents")}
        ips |= {r["ip"] for r in self._all("SELECT ip FROM blocklist")}
        return {i for i in ips if i}
