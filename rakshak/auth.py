"""Offline local accounts. No default password, signup or cloud authentication.
Provision users with python -m rakshak.admin. Sessions expire after one hour,
are persisted in the local encrypted-at-rest-by-permissions database (a restart keeps
you signed in until the hour expires) and always recheck the DB role on every request.
This is a single-node foundation: SSO/MFA and distributed sessions remain planned.
"""
import hashlib
import hmac
import re
import secrets
import threading
import time
from fastapi import HTTPException, Request

ROLES = {"viewer": 0, "analyst": 1, "admin": 2}
COOKIE = "rakshak_session"
ITERATIONS = 600000


def make_user(username, password, role="admin"):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username):
        raise ValueError("Username must be 3-40 letters, numbers, dots, dashes or underscores.")
    if role not in ROLES:
        raise ValueError("Role must be viewer, analyst or admin.")
    if not 14 <= len(password) <= 256:
        raise ValueError("Use a password of 14-256 characters.")
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS).hex()
    return {"username": username, "role": role, "salt": salt, "pw_hash": digest,
            "iterations": ITERATIONS, "created_at": time.time()}


class Auth:
    def __init__(self, store, audit):
        self.store, self.audit = store, audit
        self.sessions, self.failures = {}, {}
        self.lock = threading.RLock()

    def login(self, username, password, ip="local"):
        now = time.time()
        with self.lock:
            self.failures = {k: v for k, v in self.failures.items() if v["until"] > now}
            fail = self.failures.get(ip)
            if fail and fail["count"] >= 5:
                raise HTTPException(429, "Too many login attempts. Wait 5 minutes.")
            user = self.store.get_user(username)
            # Equal KDF work for absent accounts; no account enumeration via response text.
            salt = bytes.fromhex(user["salt"]) if user else bytes(16)
            iters = user["iterations"] if user else ITERATIONS
            digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters).hex()
            good = user and not user["disabled"] and hmac.compare_digest(digest, user["pw_hash"])
            if not good:
                f = self.failures.setdefault(ip, {"count": 0, "until": now + 300})
                f["count"] += 1
                self.audit.write("anonymous", "auth.failed", "login", source=ip)
                raise HTTPException(401, "Invalid username or password.")
            self.failures.pop(ip, None)
            self.sessions = {k: v for k, v in self.sessions.items() if v["expires"] > now}
            if len(self.sessions) >= 256:
                raise HTTPException(429, "Session capacity reached. Log out an existing session.")
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.sessions[token] = {"username": username, "csrf": csrf, "expires": now + 3600}
            try:
                self.store.prune_sessions(now)
                self.store.put_session(token, username, csrf, now + 3600)
            except Exception:
                pass         # persistence is a convenience; an in-memory session still works
            self.audit.write(username, "auth.login", "session", role=user["role"])
            return token, {"username": username, "role": user["role"], "csrf": csrf, "expires": now + 3600}

    def require(self, request: Request, role="viewer"):
        token = request.cookies.get(COOKIE, "")
        with self.lock:
            sess = self.sessions.get(token)
            if not sess:
                # memory cache miss: consult the DB (this is what makes sessions survive a restart)
                row = None
                try:
                    row = self.store.get_session(token)
                except Exception:
                    row = None
                if row and row["expires"] > time.time():
                    sess = {"username": row["username"], "csrf": row["csrf"], "expires": row["expires"]}
                    self.sessions[token] = sess
            if not sess or sess["expires"] <= time.time():
                self.sessions.pop(token, None)
                try:
                    self.store.drop_session(token)
                except Exception:
                    pass
                raise HTTPException(401, "Sign in to the local security console.")
            user = self.store.get_user(sess["username"])
            if not user or user["disabled"] or user["role"] not in ROLES:
                self.sessions.pop(token, None)
                try:
                    self.store.drop_session(token)
                except Exception:
                    pass
                raise HTTPException(401, "Account is no longer active.")
            if ROLES[user["role"]] < ROLES[role]:
                raise HTTPException(403, f"This operation requires the {role} role.")
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                supplied = request.headers.get("X-RAKSHAK-CSRF", "")
                if not supplied or not hmac.compare_digest(supplied, sess["csrf"]):
                    raise HTTPException(403, "Missing or invalid CSRF token.")
            return {"username": user["username"], "role": user["role"],
                    "csrf": sess["csrf"], "expires": sess["expires"]}

    def logout(self, request):
        user = self.require(request)
        with self.lock:
            self.sessions.pop(request.cookies.get(COOKIE, ""), None)
            try:
                self.store.drop_session(request.cookies.get(COOKIE, ""))
            except Exception:
                pass
        self.audit.write(user["username"], "auth.logout", "session")
