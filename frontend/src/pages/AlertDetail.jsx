import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { AlertTriangle, ArrowLeft, BadgeCheck, Bot, CheckCircle2, ChevronDown, Clock, Download, FileText, Hand, Lightbulb,
         ListChecks, Loader2, Lock, RotateCcw, SearchCheck, ShieldCheck, Terminal, Undo2, User, Zap } from "lucide-react";
import { api, ago, can, CATEGORY, clock, countdown, srcLabel, usePoll, VALIDATION } from "../api";
import { useOverview } from "../components/Layout";
import { AiChip, Banner, InfoTip, SeverityChip, StatusChip, ValidationChip } from "../components/ui";

function Box({ icon: Icon, title, tone = "brand", children }) {
  const c = { brand: "bg-brand-50 text-brand-700", warn: "bg-warn-bg text-warn", safe: "bg-safe-bg text-safe",
              info: "bg-info-bg text-info" }[tone];
  return (
    <div className="card p-5">
      <div className="flex items-center gap-2.5">
        <span className={`grid h-8 w-8 place-items-center rounded-lg ${c}`}><Icon size={17} /></span>
        <h3 className="font-bold">{title}</h3>
      </div>
      <div className="mt-3 text-[15px] leading-relaxed text-ink-500">{children}</div>
    </div>
  );
}

function whatRakshakDid(inc) {
  if (inc.source_ip === "system") {
    return "Rakshak watched this machine's own configuration (files, accounts, listening ports), caught the change as it happened, stored the before/after fingerprints in the tamper-evident log, and looked at the live system again to re-check it. There is no attacker IP to block here - the alert is about the machine itself.";
  }
  if (inc.status === "contained" && inc.contained_at) {
    const gap = inc.contained_at - inc.detected_at;
    return `Blocked ${inc.source_ip} at this server's firewall ${gap.toFixed(2)} s after detecting it, and checked that the firewall really holds the block.`;
  }
  if (inc.status === "block_recorded")
    return `${inc.source_ip} was added to Rakshak's blocklist, but no firewall is connected, so it can still reach your systems. Copy the rules from Protection to your firewall.`;
  if (inc.status === "enforcement_failed")
    return `Rakshak tried to block ${inc.source_ip} at the firewall but could not confirm it. Treat this source as NOT blocked.`;
  if (inc.status === "awaiting_approval")
    return `It suggests blocking ${inc.source_ip} and is waiting for a decision (see the right panel). Nothing has been blocked.`;
  if (["allowed", "unblocked"].includes(inc.status))
    return `${inc.source_ip} was allowed. Rakshak will not block it again for this alert, but keeps recording its activity.`;
  if (inc.status === "resolved") return "This alert was marked as resolved.";
  return "Rakshak is recording this source's activity. No block has been made.";
}

function EvidenceCard({ inc, onDone }) {
  const { user } = useOverview() || {};
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [draft, setDraft] = useState(null);
  const suggest = async () => {
    setBusy(true); setErr("");
    try { setDraft(await api(`/incidents/${inc.id}/suggest_rule`, { method: "POST" })); }
    catch (e) { setErr(e.message); }
    setBusy(false);
  };
  const v = VALIDATION[inc.validation] || VALIDATION.pending;
  const d = inc.validation_detail || {};
  const isHost = inc.source_ip === "system";
  const recheck = async () => {
    setBusy(true); setErr("");
    try { await api(`/incidents/${inc.id}/validate`, { method: "POST" }); await onDone(); } catch (e) { setErr(e.message); }
    setBusy(false);
  };
  return (
    <div className="card p-5">
      <div className="flex items-center gap-2">
        <SearchCheck size={18} className="text-brand-700" />
        <h3 className="font-bold">Is the evidence solid?</h3>
        <InfoTip wide text={isHost
          ? "For alerts about this machine, Rakshak looks at the live system again - re-hashes the file, re-lists the ports, re-reads the accounts - and compares against what it recorded. That proves the change is real and still there (or shows it was reverted). It does not prove who made the change or why."
          : "Rakshak reads the stored log lines again, checks their fingerprints, and re-runs its rules on them. If it gets the same result, the alert is 'Evidence re-checked'. This proves the log evidence. It does not prove the attack succeeded or who was behind it."} />
      </div>
      <div className="mt-3"><ValidationChip value={inc.validation} /></div>
      <p className="mt-2 text-sm text-ink-500">{v.help}</p>
      {Array.isArray(d.reasons) && d.reasons.length > 0 && (
        <ul className="mt-2 space-y-1 text-xs text-ink-500">{d.reasons.slice(0, 6).map((r) => <li key={r}>· {r}</li>)}</ul>
      )}
      {can(user, "analyst") && (
        <button className="btn-ghost mt-3 w-full" disabled={busy} onClick={recheck}>
          {busy ? <Loader2 size={15} className="animate-spin" /> : <SearchCheck size={15} />} Re-check evidence now</button>
      )}
      {!isHost && can(user, "analyst") && (
        <>
          <button className="btn-ghost mt-2 w-full" disabled={busy} onClick={suggest}>
            <RotateCcw size={15} /> Suggest a new rule from this evidence</button>
          <p className="mt-1.5 text-xs text-ink-400">Mines the shared attack fragment from these stored lines and writes a DRAFT rule pack. A draft does nothing until an admin imports it through the schema + self-test gate - this is how Rakshak learns new patterns offline.</p>
          {draft && (
            <div className="mt-3 rounded-xl border border-info-line bg-info-bg p-3">
              <p className="text-xs font-semibold text-info">{draft.note}</p>
              <pre className="mono mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-ink p-3 text-[11px] leading-relaxed text-slate-200">{draft.yaml}</pre>
              <p className="mt-1.5 text-[11px] text-ink-400">Saved to <span className="mono">{draft.file}</span> - review, then import on the same machine.</p>
            </div>
          )}
        </>
      )}
      {err && <p className="mt-2 text-sm text-danger">{err}</p>}
    </div>
  );
}

function Timeline({ inc }) {
  const d = (t) => (t && inc.first_seen ? `+${(t - inc.first_seen).toFixed(2)} s` : "");
  if (inc.source_ip === "system") {
    const hostItems = [
      { t: inc.first_seen, label: "Change observed on this machine", icon: Zap, done: true },
      { t: inc.detected_at, label: "Detected and recorded by Rakshak", icon: ShieldCheck, done: true },
      { t: null, label: "No IP to block - this is a system change; fix it on the machine", icon: AlertTriangle, done: true },
      { t: null, label: inc.report_ready ? "Report created" : "Report not created yet", icon: FileText, done: inc.report_ready },
    ];
    return (
      <ol className="relative ml-3 border-l-2 border-line">
        {hostItems.map((it) => (
          <li key={it.label} className="mb-5 ml-6 last:mb-0">
            <span className={`absolute -left-[13px] grid h-6 w-6 place-items-center rounded-full ring-4 ring-white ${it.done ? "bg-brand-700 text-white" : "bg-slate-200 text-ink-400"}`}>
              <it.icon size={12} />
            </span>
            <p className={`font-semibold ${it.done ? "" : "text-ink-400"}`}>{it.label}</p>
            {it.t && <p className="text-xs text-ink-400">{clock(it.t)} <span className="font-semibold text-brand-700">{d(it.t)}</span></p>}
          </li>
        ))}
      </ol>
    );
  }
  const items = [
    { t: inc.first_seen, label: "First suspicious request", icon: Zap, done: true },
    { t: inc.detected_at, label: "Detected by Rakshak", icon: ShieldCheck, done: true },
    { t: inc.contained_at, label: inc.contained_at ? "Blocked at firewall (verified)" : "Not blocked at a firewall", icon: Hand, done: !!inc.contained_at },
    { t: null, label: inc.report_ready ? "Report created" : "Report not created yet", icon: FileText, done: inc.report_ready },
  ];
  return (
    <ol className="relative ml-3 border-l-2 border-line">
      {items.map((it) => (
        <li key={it.label} className="mb-5 ml-6 last:mb-0">
          <span className={`absolute -left-[13px] grid h-6 w-6 place-items-center rounded-full ring-4 ring-white ${it.done ? "bg-brand-700 text-white" : "bg-slate-200 text-ink-400"}`}>
            <it.icon size={12} />
          </span>
          <p className={`font-semibold ${it.done ? "" : "text-ink-400"}`}>{it.label}</p>
          {it.t && <p className="text-xs text-ink-400">{clock(it.t)} <span className="font-semibold text-brand-700">{d(it.t)}</span></p>}
        </li>
      ))}
    </ol>
  );
}

function AiCard({ inc }) {
  if (inc.source_ip === "system") {
    return (
      <div className="card p-5">
        <div className="flex items-center gap-2">
          <User size={18} className="text-ink-400" />
          <h3 className="font-bold">Who made this change?</h3>
          <InfoTip wide text="Bot/AI scoring works on network behaviour (speed, retries, payload rewriting). A change written into this machine's files has no network behaviour to measure, so Rakshak says 'unknown' instead of guessing." />
        </div>
        <p className="mt-3 text-2xl font-bold">Unknown</p>
        <p className="mt-2 text-sm text-ink-500">Anyone with a shell on this machine - a person, a script, or an intruder - can make this kind of change. Cross-check who was logged in around this time (see the login alerts and the Memory page) before deciding.</p>
      </div>
    );
  }
  const pct = Math.round(inc.ai_score * 100);
  const color = inc.ai_score >= 0.7 ? "bg-danger" : inc.ai_score >= 0.4 ? "bg-warn" : "bg-safe";
  return (
    <div className="card p-5">
      <div className="flex items-center gap-2">
        {inc.ai_score >= 0.4 ? <Bot size={18} className="text-danger" /> : <User size={18} className="text-safe" />}
        <h3 className="font-bold">Is a bot or AI behind this?</h3>
        <InfoTip wide text="Rakshak looks at HOW the source behaves: speed, timing, many rewritten attack variants, retrying after a block, switching identities. Each signal adds points. It is a rule-of-thumb score, not a probability and never proof." />
      </div>
      <p className="mt-3 text-2xl font-bold">{inc.ai_label}</p>
      <div className="mt-2 h-2.5 overflow-hidden rounded-full bg-slate-100">
        <div className={`h-full rounded-full ${color} transition-all`} style={{ width: `${Math.max(pct, 4)}%` }} />
      </div>
      <div className="mt-1 flex justify-between text-[11px] font-medium text-ink-400"><span>Person</span><span>{pct}%</span><span>AI / bot</span></div>
      <p className="label mt-4">Why Rakshak thinks so</p>
      {inc.ai_reasons.length ? (
        <ul className="mt-2 space-y-2 text-sm">
          {inc.ai_reasons.map((r) => (
            <li key={r} className="flex gap-2"><CheckCircle2 size={16} className="mt-0.5 shrink-0 text-brand-700" />{r}</li>
          ))}
        </ul>
      ) : <p className="mt-2 text-sm text-ink-500">No bot-like signals: slow, few attempts, human-like timing.</p>}
      <p className="mt-4 text-xs text-ink-400">Rule-of-thumb from behaviour, not proof. Accuracy on your traffic has not been measured.</p>
    </div>
  );
}

const REM = ["restore_file", "stop_process", "lock_account", "remove_account"];
const REM_LABEL = { restore_file: "Restore the file to the exact content recorded before the change",
                    stop_process: "Stop the process that opened this port",
                    lock_account: "Lock this account's password login",
                    remove_account: "Remove this account (and home directory)" };

function RemediationCard({ inc, onDone }) {
  const isHost = inc.source_ip === "system";
  const { user } = useOverview() || {};
  const [opts, setOpts] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");
  const load = () => api(`/incidents/${inc.id}/remediation`).then((d) => setOpts(d.options)).catch(() => setOpts([]));
  useEffect(() => { if (isHost) load(); }, [inc.id, inc.status, inc.actions.length, isHost]);  // eslint-disable-line
  if (!isHost) return null;
  const run = async (fn, ok = "") => {
    setBusy(true); setErr(""); setNote("");
    try { await fn(); if (ok) setNote(ok); await load(); await onDone(); }
    catch (e) { setErr(e.message); }
    setBusy(false);
  };
  const det = (inc.detections || [])[0] || {};
  const found = (det.found && typeof det.found === "object") ? det.found : {};
  const proc = found.process;
  const past = inc.actions.filter((a) => REM.includes(a.action) || a.action === "accept_change");
  const open = inc.status !== "resolved" && inc.status !== "allowed";
  return (
    <div className="card p-5">
      <div className="flex items-center gap-2">
        <RotateCcw size={18} className="text-brand-700" />
        <h3 className="font-bold">Undo what the attacker changed</h3>
        <InfoTip wide text="Rakshak keeps a private copy (the vault) of every watched file's content, knows which process opened a new port, and can lock or remove accounts through a restricted root helper. Each fix is PROPOSED first - a proposal changes nothing. An admin approval runs it, and Rakshak then re-checks the live system: only a verified result is recorded as done." />
      </div>
      {inc.category === "new_service" && proc && (
        <p className="mt-3 flex items-start gap-2 rounded-lg bg-canvas px-3 py-2 text-xs">
          <Terminal size={14} className="mt-0.5 shrink-0 text-ink-400" />
          <span>Opened by <span className="mono font-semibold">PID {proc.pid}</span> · {proc.name}<br />
            <span className="mono break-all text-ink-400">{(proc.cmdline || "").slice(0, 140)}</span></span>
        </p>
      )}
      {inc.category === "file_integrity" && det.before && det.before.sha256 && (
        <p className="mt-3 text-xs text-ink-500">Recorded original <span className="mono">{String(det.before.sha256).slice(0, 12)}…</span> → now <span className="mono">{String(found.sha256 || "gone").slice(0, 12)}…</span></p>
      )}
      <div className="mt-3 space-y-2">
        {!opts && <div className="h-16 animate-pulse rounded-lg bg-canvas" />}
        {opts && opts.length === 0 && <p className="text-sm text-ink-500">No undo options for this kind of change (or the alert is closed). Check "What you should do" and resolve when fixed.</p>}
        {opts && opts.map((o) => !o.possible ? (
          <div key={o.action} className="rounded-xl border border-line px-3 py-2.5">
            <p className="flex items-center gap-2 text-sm font-semibold text-ink-400"><Lock size={14} /> {REM_LABEL[o.action] || o.label}</p>
            <p className="mt-0.5 text-xs text-ink-400">{o.reason}</p>
          </div>
        ) : o.proposed ? (
          <div key={o.action} className="rounded-xl border border-warn-line bg-warn-bg px-3 py-2.5">
            <p className="text-sm font-semibold text-warn">Proposed · awaiting admin approval — nothing has been executed</p>
            {can(user, "admin") && (
              <button disabled={busy} className="btn-primary mt-2 w-full" onClick={() => run(() => api(`/actions/${o.action_id}/approve`, { method: "POST" }), "Executed and verified against the live system.")}>
                {busy ? <Loader2 size={15} className="animate-spin" /> : <ShieldCheck size={15} />} Approve: execute &amp; verify</button>
            )}
            <p className="mt-1.5 text-xs text-ink-400">Resolving this alert cancels the proposal automatically.</p>
          </div>
        ) : (
          <div key={o.action} className="rounded-xl border border-line px-3 py-2.5">
            <p className="text-sm font-semibold">{o.label || REM_LABEL[o.action]}</p>
            <p className="mono mt-0.5 truncate text-xs text-ink-400" title={o.target}>{o.target}</p>
            {can(user, "analyst") && open && (
              <button disabled={busy} className="btn-ghost mt-2 w-full" onClick={() => run(() => api(`/incidents/${inc.id}/remediation`, { method: "POST", body: { action: o.action } }), "Proposal recorded and signed. Nothing has changed yet.")}>
                <RotateCcw size={15} /> Propose undo (no effect yet)</button>
            )}
          </div>
        ))}
      </div>
      {past.length > 0 && (
        <>
          <p className="label mt-4">Undo ledger (signed)</p>
          <ul className="mt-1 space-y-1 text-xs text-ink-500">
            {past.slice(-6).map((a) => (
              <li key={a.id} className="flex items-start gap-1.5">
                <BadgeCheck size={13} className={`mt-0.5 shrink-0 ${a.verified ? "text-safe" : "text-danger"}`} />
                <span>{clock(a.ts)} · <span className="mono">{a.action}</span> · <b>{a.status}</b>{a.detail ? ` · ${a.detail}` : ""}</span>
              </li>
            ))}
          </ul>
        </>
      )}
      {note && <p className="mt-3 flex items-center gap-1.5 text-sm font-semibold text-safe"><CheckCircle2 size={15} /> {note}</p>}
      {err && <p className="mt-3 text-sm text-danger">{err}</p>}
      {can(user, "analyst") && open && (
        <>
          <button disabled={busy} className="btn-ghost mt-4 w-full" onClick={() => run(() => api(`/incidents/${inc.id}/accept`, { method: "POST" }), "Recorded: you confirmed this change was sanctioned. The alert is closed and the baseline now includes it.")}>
            <BadgeCheck size={15} /> This was a sanctioned change</button>
          <p className="mt-1.5 text-xs text-ink-400">Use this when someone on your team made the change on purpose. Who accepted it is written in the signed ledger - it is not a silent ignore.</p>
        </>
      )}
    </div>
  );
}

function Decide({ inc, onDone }) {
  const { user } = useOverview() || {};
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const proposed = inc.actions.find((a) => a.status === "proposed");
  const run = async (fn) => { setBusy(true); setErr(null); try { await fn(); await onDone(); } catch (e) { setErr(e.message); } setBusy(false); };
  if (inc.source_ip === "system") {
    return (
      <div className="card p-5">
        <h3 className="font-bold">Your decision</h3>
        <p className="mt-2 text-sm text-ink-500">This alert is a change on the machine itself, not traffic from an address - there is nothing to block. Use the panel above to undo the change, or follow the steps under "What you should do" and close the alert.</p>
        {can(user, "analyst") && inc.status !== "resolved" && (
          <button disabled={busy} className="btn-ghost mt-3 w-full" onClick={() => run(() => api(`/incidents/${inc.id}/resolve`, { method: "POST" }))}>
            <CheckCircle2 size={16} /> Mark as resolved</button>
        )}
        {err && <p className="mt-2 text-sm text-danger">{err}</p>}
      </div>
    );
  }
  if (!can(user, "analyst")) return <div className="card p-5"><h3 className="font-bold">Your decision</h3><p className="mt-2 text-sm text-ink-500">Viewers can read alerts. An analyst or admin decides on blocks.</p></div>;
  const blocked = ["contained", "block_recorded", "enforcement_failed"].includes(inc.status);
  return (
    <div className="card p-5">
      <h3 className="font-bold">Your decision</h3>
      {inc.status === "awaiting_approval" && proposed && (
        <>
          <p className="mt-2 text-sm text-ink-500">Rakshak suggests blocking <span className="mono font-semibold text-ink">{inc.source_ip}</span>. Nothing happens until you choose.</p>
          <div className="mt-4 grid gap-2">
            <button disabled={busy} className="btn-primary" onClick={() => run(() => api(`/actions/${proposed.id}/approve`, { method: "POST" }))}>
              {busy ? <Loader2 size={16} className="animate-spin" /> : <Hand size={16} />} Yes, block it</button>
            <button disabled={busy} className="btn-ghost" onClick={() => run(() => api(`/incidents/${inc.id}/resolve`, { method: "POST" }))}>
              No, close it as a false alarm</button>
          </div>
        </>
      )}
      {blocked && (
        <>
          {inc.status === "contained"
            ? <p className="mt-2 flex items-center gap-2 text-sm font-semibold text-safe"><ShieldCheck size={16} /> {inc.source_ip} is blocked at the firewall.</p>
            : <p className="mt-2 flex items-center gap-2 text-sm font-semibold text-warn"><AlertTriangle size={16} /> {inc.source_ip} is on the blocklist but NOT blocked at a firewall.</p>}
          <p className="mt-1 text-sm text-ink-500">If this was a mistake (a real user), you can remove it.</p>
          <button disabled={busy} className="btn-danger mt-4 w-full" onClick={() => run(() => api("/protection/unblock", { method: "POST", body: { ip: inc.source_ip } }))}>
            <Undo2 size={16} /> Undo block</button>
        </>
      )}
      {["allowed", "unblocked"].includes(inc.status) && <p className="mt-2 text-sm text-ink-500">You allowed this source.</p>}
      {inc.status !== "resolved" && (
        <button disabled={busy} className="btn-ghost mt-2 w-full" onClick={() => run(() => api(`/incidents/${inc.id}/resolve`, { method: "POST" }))}>
          <CheckCircle2 size={16} /> Mark as resolved</button>
      )}
      {err && <p className="mt-2 text-sm text-danger">{err}</p>}
    </div>
  );
}

export default function AlertDetail() {
  const { id } = useParams();
  const { data: inc, error, reload } = usePoll(`/incidents/${id}`, 2500);
  const { reload: reloadOv } = useOverview() || {};
  const [tech, setTech] = useState(false);
  if (error) return <Banner tone="danger">Could not load this alert: {error}</Banner>;
  if (!inc) return <div className="card h-64 animate-pulse" />;
  const refresh = async () => { await reload(); reloadOv?.(); };
  return (
    <div className="space-y-5 animate-fadeUp">
      <Link to="/alerts" className="inline-flex items-center gap-1.5 text-sm font-semibold text-ink-500 hover:text-ink"><ArrowLeft size={16} /> All alerts</Link>

      <div className="card flex flex-wrap items-start justify-between gap-4 p-6">
        <div>
          <p className="label">Alert #{inc.id} · {CATEGORY[inc.category]}</p>
          <h2 className="mt-1 text-2xl font-bold tracking-tight">{inc.explain.title}</h2>
          <div className="mt-3 flex flex-wrap items-center gap-2 text-sm text-ink-500">
            <SeverityChip level={inc.severity} /><StatusChip status={inc.status} /><AiChip score={inc.ai_score} label={inc.ai_label} />
            <ValidationChip value={inc.validation} />
            <span>{inc.source_ip === "system" ? "on" : "from"} <span className="mono font-semibold text-ink">{srcLabel(inc.source_ip)}</span> · {inc.event_count} events · last seen {ago(inc.last_seen)}</span>
          </div>
        </div>
        <div className="rounded-xl border border-info-line bg-info-bg px-4 py-3 text-sm">
          <p className="flex items-center gap-1.5 font-semibold text-info"><Clock size={15} /> CERT-In report due in {countdown(inc.report_due)}
            <InfoTip text="Indian rules (CERT-In Directions, April 2022) require organisations to report cyber incidents within 6 hours of noticing them." /></p>
          <p className="mt-0.5 text-xs text-ink-500">6 hours from detection</p>
        </div>
      </div>

      <div className="grid gap-5 lg:grid-cols-3">
        <div className="space-y-5 lg:col-span-2">
          <div className="grid gap-4 md:grid-cols-2">
            <Box icon={Zap} title="What happened" tone="warn">{inc.explain.what}</Box>
            <Box icon={Lightbulb} title="Why it matters" tone="info">{inc.explain.why}</Box>
            <Box icon={ShieldCheck} title="What Rakshak did" tone="safe">{whatRakshakDid(inc)}</Box>
            <Box icon={ListChecks} title="What you should do">
              <ul className="space-y-1.5">{inc.explain.todo.map((t) => <li key={t} className="flex gap-2"><span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-brand-700" />{t}</li>)}</ul>
            </Box>
          </div>

          <div className="card p-6">
            <h3 className="mb-4 font-bold">Timeline</h3>
            <Timeline inc={inc} />
          </div>

          <div className="card p-6">
            <h3 className="flex items-center gap-2 font-bold">Evidence <InfoTip text="The exact rules that matched and sample log lines. This is what you would show an expert or attach to a report." /></h3>
            <p className="label mt-4">Rules that matched</p>
            <ul className="mt-2 divide-y divide-line rounded-xl border border-line">
              {inc.detections.slice(0, 8).map((d, i) => (
                <li key={i} className="flex flex-wrap items-center gap-3 px-4 py-2.5 text-sm">
                  <span className="mono rounded bg-canvas px-1.5 py-0.5 text-xs font-semibold">{d.rule_id}</span>
                  <span className="flex-1">{d.name}</span>
                  {d.matched && <code className="mono max-w-[260px] truncate rounded bg-danger-bg px-2 py-0.5 text-xs text-danger" title={d.matched}>{d.matched}</code>}
                </li>
              ))}
            </ul>
            <p className="label mt-5">Sample log lines</p>
            <pre className="mono mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-xl bg-ink p-4 text-[11.5px] leading-relaxed text-slate-200">
              {inc.evidence.slice(-6).join("\n")}
            </pre>
          </div>

          <div className="card">
            <button onClick={() => setTech((t) => !t)} className="flex w-full items-center justify-between px-6 py-4 font-bold">
              Technical details (for experts) <ChevronDown size={18} className={`transition ${tech ? "rotate-180" : ""}`} />
            </button>
            {tech && (
              <dl className="grid gap-x-6 gap-y-3 border-t border-line px-6 py-5 text-sm md:grid-cols-2">
                <div><dt className="label">MITRE ATT&CK technique</dt><dd className="mt-1 font-semibold">{inc.explain.mitre_id} · {inc.explain.mitre_name}</dd></div>
                <div><dt className="label">CERT-In category (Annexure I)</dt><dd className="mt-1">{inc.explain.certin_category}</dd></div>
                <div><dt className="label">All categories seen</dt><dd className="mt-1">{inc.categories.map((c) => CATEGORY[c]).join(", ")}</dd></div>
                <div><dt className="label">Detected at</dt><dd className="mt-1">{clock(inc.detected_at)} ({(inc.detected_at - inc.first_seen).toFixed(2)} s after first request)</dd></div>
                <div className="md:col-span-2"><dt className="label">Action log (signed)</dt>
                  <dd className="mt-1 space-y-1">{inc.actions.map((a) => (
                    <p key={a.id} className="flex items-center gap-2"><BadgeCheck size={15} className={a.verified ? "text-safe" : "text-danger"} />
                      {clock(a.ts)} · {a.action} {a.target} · {a.status} · {a.verified ? "signature verified" : "SIGNATURE INVALID"}</p>))}
                    {!inc.actions.length && "No actions yet."}</dd></div>
              </dl>
            )}
          </div>
        </div>

        <div className="space-y-5">
          <RemediationCard inc={inc} onDone={refresh} />
          <Decide inc={inc} onDone={refresh} />
          <EvidenceCard inc={inc} onDone={refresh} />
          <AiCard inc={inc} />
          <ReportCard inc={inc} onDone={refresh} />
        </div>
      </div>
    </div>
  );
}

function ReportCard({ inc, onDone }) {
  const { user } = useOverview() || {};
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const make = async () => {
    setBusy(true); setErr("");
    try { await api(`/incidents/${inc.id}/report`, { method: "POST" }); window.open(`/api/incidents/${inc.id}/report.pdf`, "_blank"); await onDone(); }
    catch (e) { setErr(e.message); }
    setBusy(false);
  };
  return (
    <div className="card p-5">
      <h3 className="flex items-center gap-2 font-bold"><FileText size={18} className="text-brand-700" /> Incident report (draft)</h3>
      <p className="mt-2 text-sm text-ink-500">A PDF draft in a CERT-In-style layout. Numbers are recomputed from the stored evidence, and the whole log chain is checked first.</p>
      {can(user, "analyst") && (
        <button className="btn-brand mt-4 w-full" disabled={busy} onClick={make}>
          {busy ? <Loader2 size={16} className="animate-spin" /> : <FileText size={16} />} Create PDF draft</button>
      )}
      {inc.report_ready && <a href={`/api/incidents/${inc.id}/report.pdf`} target="_blank" rel="noreferrer" className="btn-ghost mt-2 w-full"><Download size={16} /> Download last draft</a>}
      {err && <p className="mt-2 text-sm text-danger">{err}</p>}
      <p className="mt-2 text-xs text-ink-400">A responsible person must review it before anything is sent to incident@cert-in.org.in.</p>
    </div>
  );
}
