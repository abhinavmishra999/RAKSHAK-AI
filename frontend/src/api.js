import { useCallback, useEffect, useRef, useState } from "react";

let csrfToken = "";
export const setCsrf = (t) => { csrfToken = t || ""; };

/** Calls the local Rakshak API. Throws Error(message) with .status on failure. */
export async function api(path, opts = {}) {
  const method = opts.method || "GET";
  const headers = { "Content-Type": "application/json" };
  if (method !== "GET") headers["X-RAKSHAK-CSRF"] = csrfToken;
  const res = await fetch(`/api${path}`, {
    method, headers, credentials: "same-origin",
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join("; ") : data.detail;
    const err = new Error(detail || `Request failed (${res.status})`);
    err.status = res.status;
    if (res.status === 401) window.dispatchEvent(new Event("rakshak:signed-out"));
    throw err;
  }
  return data;
}

/** Fetches `path` now and every `ms` milliseconds. Returns { data, error, reload, updatedAt }. */
export function usePoll(path, ms = 2000) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [updatedAt, setUpdatedAt] = useState(null);
  const alive = useRef(true);
  const reload = useCallback(async () => {
    if (!path) return;
    try {
      const d = await api(path);
      if (alive.current) { setData(d); setError(null); setUpdatedAt(Date.now()); }
    } catch (e) {
      if (alive.current) setError(e.message);
    }
  }, [path]);
  useEffect(() => {
    alive.current = true;
    reload();
    const t = ms ? setInterval(reload, ms) : null;
    return () => { alive.current = false; if (t) clearInterval(t); };
  }, [reload, ms]);
  return { data, error, reload, updatedAt };
}

export function ago(ts) {
  if (!ts) return "-";
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (s < 5) return "just now";
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(ts * 1000).toLocaleDateString();
}

export const clock = (ts) => (ts ? new Date(ts * 1000).toLocaleTimeString() : "-");
export const dateTime = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "-");

export function countdown(ts) {
  const s = Math.round(ts - Date.now() / 1000);
  if (s <= 0) return "overdue";
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h ? `${h} h ${m} min` : `${m} min`;
}

export const ROLE_RANK = { viewer: 0, analyst: 1, admin: 2 };
export const can = (user, role) => !!user && ROLE_RANK[user.role] >= ROLE_RANK[role];

/** Plain-language words for internal states, shown to non-experts. */
export const STATUS = {
  open: { text: "Needs review", tone: "warn" },
  awaiting_approval: { text: "Waiting for your OK", tone: "warn" },
  block_recorded: { text: "Block recorded, not enforced", tone: "warn" },
  enforcement_failed: { text: "Block failed", tone: "danger" },
  contained: { text: "Blocked at firewall", tone: "safe" },
  allowed: { text: "Allowed by you", tone: "info" },
  unblocked: { text: "Allowed by you", tone: "info" },
  resolved: { text: "Resolved", tone: "muted" },
};

export const VALIDATION = {
  evidence_checked: { text: "Evidence re-checked", tone: "safe",
    help: "For log alerts: Rakshak re-ran its rules on the stored, untampered log lines and got the same result. For system alerts: it looked at the live machine again and still sees the change. This proves the evidence, not that the attack succeeded." },
  suspected: { text: "Suspected", tone: "warn",
    help: "Only behaviour or the anomaly model points to this. Treat it as a lead to investigate." },
  invalid_evidence: { text: "Evidence problem", tone: "danger",
    help: "The stored log lines could not be verified (tampered, missing, or the rules no longer match)." },
  pending: { text: "Not re-checked yet", tone: "muted", help: "The evidence has not been re-checked yet." },
  accepted: { text: "Accepted as sanctioned", tone: "info",
    help: "A person with access confirmed this change was allowed. Who accepted it, when, and on what target is written in the signed ledger; the sensor baseline now includes it." },
};

export const FINDING = {
  confirmed: { text: "Confirmed", tone: "danger",
    help: "Reported by the tool AND reproduced by a separate, independent re-check by Rakshak." },
  suspected: { text: "Suspected", tone: "warn", help: "Reported by the tool but not independently re-checked." },
  not_reproduced: { text: "Not reproduced", tone: "muted",
    help: "The tool reported it but Rakshak's independent re-check did not see it. Not counted as a problem." },
  inconclusive: { text: "Could not check", tone: "info",
    help: "The check could not be completed (no answer, error or unsupported). This is NOT a pass." },
  observed_pass: { text: "Looked fine", tone: "safe",
    help: "This one check saw no problem. It does not prove the system is secure." },
  info: { text: "Information", tone: "muted", help: "Raw tool output that cannot be validated automatically." },
};

export const RUN_STATUS = {
  queued: { text: "Waiting for approval", tone: "warn" },
  running: { text: "Running", tone: "info" },
  completed: { text: "Finished", tone: "safe" },
  failed: { text: "Failed: no findings accepted", tone: "danger" },
  refused: { text: "Refused", tone: "danger" },
  rejected: { text: "Rejected", tone: "muted" },
};

/** Rejected requests are stored as status "refused" with summary.state "rejected". */
export const runState = (r) => (r.status === "refused" && r.summary?.state === "rejected" ? "rejected" : r.status);

export const SEVERITY = {
  low: { text: "Low", tone: "info", help: "Worth knowing, unlikely to cause harm on its own." },
  medium: { text: "Medium", tone: "warn", help: "Could lead to harm. Rakshak asks you before blocking." },
  high: { text: "High", tone: "danger", help: "Likely to cause harm. In Auto mode it can be blocked automatically, if a firewall is connected." },
  critical: { text: "Critical", tone: "danger", help: "Could give full control of a server. Act now." },
};

export const CATEGORY = {
  sql_injection: "Database break-in attempt",
  xss: "Malicious script attempt",
  path_traversal: "Secret file read attempt",
  command_injection: "Server command attempt",
  sensitive_probe: "Looking for secret files",
  recon_scan: "Website mapping / scanning",
  brute_force: "Password guessing",
  flood: "Request flood",
  scanner_tool: "Hacking tool detected",
  anomaly: "Unusual behaviour",
  credential_compromise: "Login likely compromised",
  file_integrity: "Protected file changed",
  account_change: "System account changed",
  new_service: "New listening service",
};

export const aiTone = (score) => (score >= 0.7 ? "danger" : score >= 0.4 ? "warn" : "safe");
// Host findings have no attacker IP; show them as coming from the machine itself.
export const srcLabel = (ip) => (ip === "system" ? "this machine" : ip);
