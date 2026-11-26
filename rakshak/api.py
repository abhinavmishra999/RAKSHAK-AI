"""RAKSHAK-AI local server (offline).

Run from the project folder:   python -m rakshak.api
  * create the first account first:   python -m rakshak.admin <username> --role admin
  * binds to 127.0.0.1 by default; a non-loopback bind needs RAKSHAK_ALLOW_REMOTE=1
Every /api route except /api/health requires a signed-in user. State-changing routes
also need the CSRF header and the right role (viewer < analyst < admin).
"""
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from rakshak.auth import COOKIE, Auth
from rakshak.config import Settings
from rakshak.detect import ai_origin
from rakshak.engine import Engine
from rakshak.hostsec import file_state
from rakshak.knowledge import explain
from rakshak.plugins.runner import PluginRunner
from rakshak.parsers import parse_line
from rakshak import rulecraft

conf = Settings()
engine = Engine(conf)
auth = Auth(engine.store, engine.audit)
plugins = PluginRunner(conf, engine.store, engine.audit)

app = FastAPI(title="RAKSHAK-AI", docs_url=None, redoc_url=None, openapi_url=None)
_hosts = ["127.0.0.1", "localhost", "[::1]", "::1"] + conf.allowed_hosts
if conf.host not in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "::"):
    _hosts.append(conf.host)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=_hosts)

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                               "font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        if k == "Cache-Control" and request.url.path.startswith("/assets/"):
            continue
        resp.headers.setdefault(k, v)
    return resp


def viewer(request: Request):
    return auth.require(request, "viewer")


def analyst(request: Request):
    return auth.require(request, "analyst")


def admin(request: Request):
    return auth.require(request, "admin")


def _client_ip(request: Request):
    return request.client.host if request.client else "unknown"


def _bad(exc):
    raise HTTPException(400, str(exc))


# ---------------- health and auth ----------------
@app.get("/api/health")
def health():
    """Unauthenticated liveness only; reveals no security data."""
    return {"ok": True}


class Login(BaseModel):
    username: str = Field(max_length=40)
    password: str = Field(max_length=256)


@app.get("/api/auth/state")
def auth_state():
    return {"has_users": engine.store.user_count() > 0}


@app.post("/api/auth/login")
def login(body: Login, request: Request, response: Response):
    token, info = auth.login(body.username, body.password, _client_ip(request))
    response.set_cookie(COOKIE, token, max_age=3600, httponly=True, samesite="strict",
                        secure=conf.cookie_secure, path="/")
    return info


@app.get("/api/auth/me")
def me(user=Depends(viewer)):
    return user


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    auth.logout(request)
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


# ---------------- overview ----------------
def _incident_view(inc):
    acts = engine.store.list_actions(inc["id"])
    for a in acts:
        a["verified"] = engine.responder.verify(a)
    return {**inc, "explain": explain(inc["category"]), "ai_label": ai_origin.label(inc["ai_score"]),
            "actions": acts, "report_due": (inc["detected_at"] or time.time()) + 6 * 3600,
            "report_ready": (engine.reports_dir / f"incident_{inc['id']}.pdf").exists()}


@app.get("/api/overview")
def overview(user=Depends(viewer)):
    incs = engine.store.list_incidents(200)
    now = time.time()
    sources = engine.source_status()
    readable = [s for s in sources if s.get("readable")]
    awaiting = [i for i in incs if i["status"] == "awaiting_approval"]
    active = [i for i in incs if i["status"] in ("open", "awaiting_approval", "block_recorded",
                                                 "enforcement_failed") and now - i["last_seen"] < 600]
    if not engine.tail_alive() or not readable:
        state = "blind"           # we cannot honestly say anything is safe
    elif active or awaiting:
        state = "attention"
    else:
        state = "no_active_alerts"
    runs = engine.store.list_runs(200)
    return {
        "state": state, "mode": engine.responder.mode, "user": user,
        "uptime": int(now - engine.started_at),
        "sources": sources,
        "enforcer": engine.responder.enforcer.status(),
        "events_total": engine.store.count_events(),
        "events_5min": engine.store.count_events(now - 300),
        "incidents_total": len(incs),
        "contained": sum(1 for i in incs if i["contained_at"]),
        "awaiting": len(awaiting),
        "ai_driven": sum(1 for i in incs if i["ai_score"] >= 0.7),
        "evidence_checked": sum(1 for i in incs if i.get("validation") == "evidence_checked"),
        "pipeline": engine.counters,
        "anomaly_model": engine.anomaly.status(),
        "rules_loaded": len(engine.rules.rules),
        "blocked_count": len(engine.store.blocklist()),
        "engine_alive": engine.tail_alive(),
        "hostsec": (engine.hostsec.status() if getattr(engine, "hostsec", None)
                    else {"enabled": False}),
        "hostsec_alive": engine.host_alive(),
        "nodes": len(engine.store.list_nodes()),
        "ingest_enabled": _sensor_secret_path().exists(),
        "vault_copies": engine.vault.count(),
        "rules_imported": len(list(Path(conf.imported_rules_dir).glob("*.yml"))),
        "errors": engine.errors[-5:],
        "recent": [_incident_view(i) for i in incs[:5]],
        "tests_waiting": sum(1 for r in runs if r["status"] == "queued"),
        "tests_total": len(runs),
    }


@app.get("/api/traffic")
def traffic(window: int = 120, user=Depends(viewer)):
    return engine.store.traffic(min(max(window, 30), 600))


@app.get("/api/events/recent")
def recent_events(limit: int = 40, user=Depends(viewer)):
    return engine.store.recent_events(min(max(limit, 1), 200))


# ---------------- incidents ----------------
@app.get("/api/incidents")
def list_incidents(user=Depends(viewer)):
    return [_incident_view(i) for i in engine.store.list_incidents(200)]


@app.get("/api/incidents/{inc_id}")
def get_incident(inc_id: int, user=Depends(viewer)):
    inc = engine.store.get_incident(inc_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    return _incident_view(inc)


@app.post("/api/incidents/{inc_id}/validate")
def validate_incident(inc_id: int, user=Depends(analyst)):
    if not engine.store.get_incident(inc_id):
        raise HTTPException(404, "Incident not found")
    engine.validate_incident(inc_id, actor=user["username"])
    return _incident_view(engine.store.get_incident(inc_id))


@app.post("/api/incidents/{inc_id}/resolve")
def resolve(inc_id: int, user=Depends(analyst)):
    if not engine.store.get_incident(inc_id):
        raise HTTPException(404, "Incident not found")
    engine.responder.cancel_pending(inc_id, f"alert resolved by {user['username']}")
    engine.store.update_incident(inc_id, status="resolved", resolved_at=time.time())
    engine.audit.write(user["username"], "incident.resolve", inc_id)
    return {"ok": True}


@app.post("/api/incidents/{inc_id}/report")
def make_report(inc_id: int, user=Depends(analyst)):
    try:
        path = engine.report(inc_id)
    except ValueError as exc:
        _bad(exc)
    if not path:
        raise HTTPException(404, "Incident not found")
    engine.audit.write(user["username"], "incident.report", inc_id)
    return {"ok": True, "url": f"/api/incidents/{inc_id}/report.pdf"}


@app.get("/api/incidents/{inc_id}/report.pdf")
def get_report(inc_id: int, user=Depends(viewer)):
    p = engine.reports_dir / f"incident_{inc_id}.pdf"
    if not p.exists():
        raise HTTPException(404, "No report has been generated for this incident yet.")
    return FileResponse(p, media_type="application/pdf", filename=f"RAKSHAK_incident_{inc_id}.pdf")


# ---------------- protection ----------------
@app.get("/api/protection")
def protection(user=Depends(viewer)):
    acts = engine.store.list_actions(limit=100)
    for a in acts:
        a["verified"] = engine.responder.verify(a)
    return {"mode": engine.responder.mode, "blocklist": engine.store.blocklist(), "actions": acts,
            "enforcer": engine.responder.enforcer.status(), "export": engine.responder.export_rules(),
            "never_block": [str(n) for n in engine.responder.never_block], "block_ttl": conf.block_ttl}


@app.post("/api/actions/{action_id}/approve")
def approve(action_id: int, user=Depends(analyst)):
    if not engine.approve(action_id, actor=user["username"]):
        raise HTTPException(400, "This action is not waiting for approval, or the address is protected.")
    return {"ok": True}


class IP(BaseModel):
    ip: str = Field(max_length=64)


@app.post("/api/protection/unblock")
def unblock(body: IP, user=Depends(analyst)):
    try:
        ipaddress.ip_address(body.ip)
    except ValueError:
        raise HTTPException(400, "Not a valid IP address.")
    if not engine.store.is_blocked(body.ip):
        raise HTTPException(404, "That address is not on the blocklist.")
    engine.responder.undo(body.ip, actor=user["username"])
    still = engine.store.is_blocked(body.ip)
    if not still:
        for inc in engine.store.list_incidents(500):  # operator says this source is OK: don't re-block it
            if inc["source_ip"] == body.ip and inc["status"] != "resolved":
                engine.store.update_incident(inc["id"], status="allowed")
    return {"ok": not still, "still_blocked": still}


class Mode(BaseModel):
    mode: str


@app.post("/api/settings/mode")
def set_mode(body: Mode, user=Depends(admin)):
    if body.mode not in ("auto", "recommend"):
        raise HTTPException(400, "Mode must be 'auto' or 'recommend'.")
    old = engine.responder.mode
    engine.responder.mode = body.mode
    engine.audit.write(user["username"], "settings.mode", body.mode, previous=old)
    return {"ok": True, "mode": body.mode}


# ---------------- host remediation: approved, live-verified undo ----------------
@app.get("/api/incidents/{inc_id}/remediation")
def remediation_options(inc_id: int, user=Depends(viewer)):
    inc = engine.store.get_incident(inc_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    opts = engine.remediator.possibilities(inc)
    for o in opts:
        pend = [a for a in engine.store.list_actions(inc_id)
                if a["action"] == o["action"] and a["status"] == "proposed"]
        o["proposed"] = bool(pend)
        o["action_id"] = pend[0]["id"] if pend else None
    return {"options": opts}


class Remediation(BaseModel):
    action: str = Field(max_length=30)


@app.post("/api/incidents/{inc_id}/remediation")
def propose_remediation(inc_id: int, body: Remediation, user=Depends(analyst)):
    try:
        act, created = engine.remediator.propose(inc_id, body.action, actor=user["username"])
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True, "action_id": act["id"], "status": act["status"],
            "detail": act["detail"], "already": not created}


@app.post("/api/incidents/{inc_id}/accept")
def accept_change(inc_id: int, user=Depends(analyst)):
    try:
        inc = engine.accept_change(inc_id, actor=user["username"])
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return _incident_view(inc)


# ---------------- offline adaptation: rule packs and drafts ----------------
@app.get("/api/rules")
def list_rules(user=Depends(viewer)):
    return {"rules": [{"id": r["id"], "name": r["name"], "category": r["category"],
                       "severity": r["severity"], "file": r["file"],
                       "imported": r["file"] not in [p.name for p in Path(conf.rules_dir).glob("*.yml")]}
                      for r in engine.rules.rules],
            "imported_dir": str(conf.imported_rules_dir),
            "drafts": sorted(p.name for p in Path(conf.draft_rules_dir).glob("*.yml"))}


class RulePack(BaseModel):
    name: str = Field(max_length=60)
    rules_yaml: str = Field(max_length=200000)
    samples: list = Field(default_factory=list)


@app.post("/api/rules/import")
def import_rules(body: RulePack, user=Depends(admin)):
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,60}", body.name):
        raise HTTPException(400, "Pack name must be 3-60 chars of letters, numbers, dot, dash, underscore.")
    rules, errors = rulecraft.validate_pack(body.rules_yaml)
    if errors:
        engine.audit.write(user["username"], "rules.import_refused", body.name, errors=errors[:6])
        raise HTTPException(400, "Rule pack failed schema checks: " + " | ".join(errors[:6]))
    gate = rulecraft.self_test(rules, body.samples[:200])
    if gate:
        engine.audit.write(user["username"], "rules.import_refused", body.name, gate=gate[:6])
        raise HTTPException(400, "Rule pack failed its own examples: " + " | ".join(gate[:6]))
    conf.imported_rules_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = conf.imported_rules_dir / f"{body.name}-{int(time.time())}.yml"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(body.rules_yaml)
    count = engine.reload_rules()
    # rule files are themselves watched; take the new state into the baseline silently
    if engine.hostsec:
        engine.hostsec.state["baseline"][str(target)] = file_state(str(target))
        engine.hostsec._save()
    engine.audit.write(user["username"], "rules.import", str(target), rules=len(rules),
                       samples_passed=len(body.samples), total_loaded=count)
    return {"ok": True, "file": str(target), "rules_added": len(rules), "total_rules": count,
            "note": "Imported after passing its own positive and negative examples; live now."}


@app.post("/api/incidents/{inc_id}/suggest_rule")
def suggest_rule(inc_id: int, user=Depends(analyst)):
    inc = engine.store.get_incident(inc_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    try:
        text, samples, note = rulecraft.suggest_rule(inc, engine.store, parse_line)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    conf.draft_rules_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    dpath = conf.draft_rules_dir / f"draft_incident_{inc_id}_{int(time.time())}.yml"
    fd = os.open(dpath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    engine.audit.write(user["username"], "rules.draft", str(dpath), incident=inc_id)
    return {"yaml": text, "samples": samples, "note": note, "file": str(dpath)}


@app.post("/api/ml/train")
def train_model(user=Depends(admin)):
    result = engine.train_anomaly(actor=user["username"])
    if not result.get("ok"):
        raise HTTPException(400, result.get("reason", "training did not run"))
    return {"ok": True, **result}


# ---------------- distributed sensor ingestion ----------------
def _sensor_secret_path():
    return Path(conf.data_dir) / "sensor_secret.key"


@app.get("/api/nodes")
def list_nodes(user=Depends(viewer)):
    return {"nodes": engine.store.list_nodes(), "note":
            "Sensor agents stream parsed log events here over the local network; each batch is HMAC-signed "
            "and numbered, so replays and edits are refused. Host sensors still run per machine."}


@app.post("/api/ingest")
async def ingest(request: Request):
    secret_path = _sensor_secret_path()
    if not secret_path.exists():
        raise HTTPException(503, "Ingestion is not configured on this hub (no sensor secret file).")
    body = await request.body()
    if len(body) > 2_000_000:
        raise HTTPException(413, "Batch too large.")
    ts = request.headers.get("X-Rakshak-Timestamp", "")
    node = request.headers.get("X-Rakshak-Sensor", "")[:64]
    seq = request.headers.get("X-Rakshak-Seq", "")
    sign = request.headers.get("X-Rakshak-Sign", "")
    if not ts or not node or not seq.isdigit() or not re.fullmatch(r"[0-9a-f]{64}", sign or ""):
        raise HTTPException(401, "Missing or malformed sensor headers.")
    try:
        skew = abs(time.time() - float(ts))
    except ValueError:
        skew = 9e9
    if skew > 120:
        raise HTTPException(401, "Sensor timestamp is too far from the hub clock.")
    secret = secret_path.read_bytes()
    msg = f"{ts}\n{node}\n{seq}\n{hashlib.sha256(body).hexdigest()}".encode()
    if not hmac.compare_digest(hmac.new(secret, msg, hashlib.sha256).hexdigest(), sign):
        engine.audit.write("ingest", "sensor.bad_signature", node, seq=seq)
        raise HTTPException(401, "Signature check failed for this batch.")
    known = engine.store.get_node(node)
    if known and int(seq) <= int(known["last_seq"]):
        raise HTTPException(409, "Replayed or out-of-order sequence number.")
    try:
        payload = json.loads(body)
        events = payload.get("events", [])
    except ValueError:
        raise HTTPException(400, "Body is not JSON.")
    accepted = engine.ingest_node_events(node, events)
    engine.store.upsert_node(node, int(seq), accepted)
    engine.audit.write("ingest", "sensor.batch", node, seq=seq, accepted=accepted)
    return {"ok": True, "accepted": accepted}


# ---------------- integrity and audit ----------------
@app.get("/api/integrity")
def integrity(user=Depends(viewer)):
    return {"events": engine.store.verify_chain(), "audit": engine.audit.verify()}


@app.get("/api/audit")
def audit_list(limit: int = 200, user=Depends(analyst)):
    return engine.audit.list(min(max(limit, 1), 1000))


# ---------------- memory: everything done so far ----------------
@app.get("/api/memory")
def memory(kind: str = "all", days: float = 0, limit: int = 100, user=Depends(viewer)):
    """One timeline of everything that has happened so far. Computed on the fly from the
    already-signed records (detected alerts, response actions, security-test runs) - there is
    no separate memory store that could drift, disagree with the evidence pages, or be tampered
    with. Anyone with dashboard access may read it; changing things still needs roles + CSRF."""
    if kind not in ("all", "alert", "system", "action", "test"):
        raise HTTPException(400, "kind must be all, alert, system, action or test")
    limit = max(1, min(int(limit), 500))
    cut = time.time() - days * 86400 if days > 0 else 0
    entries = []
    if kind in ("all", "alert", "system"):
        for inc in engine.store.list_incidents(1000):
            if kind == "system" and inc["source_ip"] != "system":
                continue
            if (inc["detected_at"] or 0) >= cut:
                entries.append({"ts": inc["detected_at"], "kind": "alert", "id": inc["id"],
                                "category": inc["category"], "severity": inc["severity"],
                                "status": inc["status"], "source_ip": inc["source_ip"],
                                "event_count": inc["event_count"], "validation": inc["validation"]})
    if kind in ("all", "action"):
        for a in engine.store.list_actions(limit=1000):
            if (a["ts"] or 0) >= cut:
                entries.append({"ts": a["ts"], "kind": "action", "id": a["id"], "action": a["action"],
                                "target": a["target"], "mode": a["mode"], "status": a["status"],
                                "detail": a["detail"], "incident_id": a["incident_id"],
                                "signed": bool(a.get("signature"))})
    if kind in ("all", "test"):
        for r in engine.store.list_runs(limit=1000):
            ts = r["requested_at"] or r["started_at"] or 0
            if ts >= cut:
                summary = r.get("summary") or {}
                entries.append({"ts": ts, "kind": "test", "id": r["id"], "tool": r["plugin_id"],
                                "target": r["target"], "status": r["status"], "state": summary.get("state"),
                                "requested_by": r["requested_by"], "approved_by": r["approved_by"],
                                "authorised_statement": r.get("authorised_statement")})
    entries.sort(key=lambda e: e["ts"] or 0, reverse=True)
    counts = {}
    for e in entries:
        counts[e["kind"]] = counts.get(e["kind"], 0) + 1
    return {"entries": entries[:limit], "counts": counts, "shown": min(limit, len(entries))}


# ---------------- plugins (security tests) ----------------
@app.get("/api/plugins")
def list_plugins(user=Depends(viewer)):
    return {"plugins": plugins.list(), "scope": plugins.scope.info(), "two_person": conf.two_person}


@app.post("/api/plugins/{plugin_id}/enable")
def enable_plugin(plugin_id: str, user=Depends(admin)):
    try:
        return plugins.enable(plugin_id, user["username"])
    except ValueError as exc:
        _bad(exc)


@app.post("/api/plugins/{plugin_id}/disable")
def disable_plugin(plugin_id: str, user=Depends(admin)):
    try:
        return plugins.disable(plugin_id, user["username"])
    except ValueError as exc:
        _bad(exc)


class RunRequest(BaseModel):
    target: str = Field(default="", max_length=300)
    reason: str = Field(min_length=5, max_length=500)
    authorised: bool = False


@app.post("/api/plugins/{plugin_id}/runs")
def request_run(plugin_id: str, body: RunRequest, user=Depends(analyst)):
    if not body.authorised:
        raise HTTPException(400, "Confirm that your organisation owns this asset and has authorised this test.")
    try:
        return plugins.request(plugin_id, body.target, user["username"], body.reason, body.authorised)
    except ValueError as exc:
        _bad(exc)


@app.get("/api/runs")
def list_runs(limit: int = 100, user=Depends(viewer)):
    return plugins.list_runs(min(max(limit, 1), 500))


@app.get("/api/runs/{run_id}")
def get_run(run_id: int, user=Depends(viewer)):
    try:
        return plugins.view(run_id)
    except ValueError:
        raise HTTPException(404, "Test run not found")


@app.post("/api/runs/{run_id}/approve")
def approve_run(run_id: int, user=Depends(analyst)):
    run = engine.store.get_run(run_id)
    if not run:
        raise HTTPException(404, "Test run not found")
    manifest = next((p for p in plugins.list() if p["id"] == run["plugin_id"]), None)
    # Wrong approver: say so, but leave the request waiting for the right person.
    if run["status"] == "queued" and manifest and manifest.get("approval") == "admin" and user["role"] != "admin":
        raise HTTPException(403, "This tool needs an admin to approve each run. The request is still waiting.")
    if run["status"] == "queued" and conf.two_person and run.get("requested_by") == user["username"]:
        raise HTTPException(403, "Two-person rule: someone other than the requester must approve. The request is still waiting.")
    try:
        return plugins.approve(run_id, user["username"], user["role"])
    except ValueError as exc:
        _bad(exc)


class Reject(BaseModel):
    why: str = Field(default="Rejected by reviewer", max_length=300)


@app.post("/api/runs/{run_id}/reject")
def reject_run(run_id: int, body: Reject, user=Depends(analyst)):
    try:
        return plugins.reject(run_id, user["username"], body.why)
    except ValueError as exc:
        _bad(exc)


@app.post("/api/runs/{run_id}/report")
def run_report(run_id: int, user=Depends(analyst)):
    from rakshak.report import build_plugin_report
    try:
        r = plugins.view(run_id)
    except ValueError:
        raise HTTPException(404, "Test run not found")
    if not r.get("verified"):
        raise HTTPException(400, "The signature of this run record does not verify. No report is produced.")
    if r["status"] not in ("completed", "failed"):
        raise HTTPException(400, "Only finished runs can be reported.")
    build_plugin_report(r, engine.reports_dir, conf.org)
    engine.audit.write(user["username"], "run.report", run_id)
    return {"ok": True, "url": f"/api/runs/{run_id}/report.pdf"}


@app.get("/api/runs/{run_id}/report.pdf")
def get_run_report(run_id: int, user=Depends(viewer)):
    p = engine.reports_dir / f"plugin_run_{run_id}.pdf"
    if not p.exists():
        raise HTTPException(404, "No report has been generated for this test run yet.")
    return FileResponse(p, media_type="application/pdf", filename=f"RAKSHAK_test_run_{run_id}.pdf")


@app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def api_404(rest: str):
    return JSONResponse({"detail": "Not found"}, status_code=404)


# ---------------- dashboard (built React app) ----------------
if conf.dist.exists():
    app.mount("/assets", StaticFiles(directory=conf.dist / "assets"), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        f = (conf.dist / full_path).resolve()
        if full_path and f.is_file() and conf.dist.resolve() in f.parents:
            return FileResponse(f)
        return FileResponse(conf.dist / "index.html")


def main():
    try:
        loopback = ipaddress.ip_address(conf.host).is_loopback
    except ValueError:
        loopback = conf.host == "localhost"
    if not loopback and not conf.allow_remote:
        sys.exit(f"Refusing to listen on {conf.host}. The console must stay on this machine unless you put "
                 "TLS and a firewall in front of it and set RAKSHAK_ALLOW_REMOTE=1.")
    if engine.store.user_count() == 0:
        print("No accounts exist yet. Create one first:  python -m rakshak.admin <username> --role admin")
    engine.start()
    print(f"RAKSHAK-AI console: http://{conf.host}:{conf.port}   (data: {conf.data_dir})")
    for s in engine.source_status():
        print(f"  log source {s.get('path')}: {s.get('state')}")
    print(f"  response mode: {engine.responder.mode}   enforcement: {engine.responder.enforcer.status()['detail']}")
    uvicorn.run(app, host=conf.host, port=conf.port, log_level="warning", server_header=False)


if __name__ == "__main__":
    main()
