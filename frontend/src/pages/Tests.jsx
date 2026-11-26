import { useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, ArrowRight, CheckCircle2, ChevronDown, ClipboardCheck, Fingerprint, Loader2, Lock,
         Power, PowerOff, Radar, Send, ShieldOff, Target, XCircle } from "lucide-react";
import { RUN_STATUS, ago, api, can, runState, usePoll } from "../api";
import { useOverview } from "../components/Layout";
import { Banner, Chip, Empty, InfoTip, SectionTitle } from "../components/ui";

const STEPS = [
  { n: 1, title: "Admin reviews a tool", text: "Read what it does and its exact command, then enable it. Rakshak pins its fingerprint." },
  { n: 2, title: "Someone requests a test", text: "Pick the tool, the target and the reason. Only assets in scope.yml are accepted." },
  { n: 3, title: "An admin approves", text: "Nothing is sent to the target before approval. Then the tool runs with time and output limits." },
  { n: 4, title: "Rakshak re-checks", text: "Every problem the tool reports is tested again separately before it is called Confirmed." },
];

function ScopeCard({ scope }) {
  const empty = !scope.networks.length;
  return (
    <div className="card p-6">
      <SectionTitle title="What may be tested (scope)"
        hint="Scope is the list of systems your organisation owns and has allowed Rakshak to test. It is a file (scope.yml) on the server that only a person can edit, never this website. Anything outside it is refused, and Rakshak never tests addresses it has seen attacking you."
        sub={<span className="mono text-xs">{scope.file}</span>} />
      {scope.error || empty ? (
        <Banner tone="warn" icon={Lock}>
          <b>No test can run yet.</b> {scope.error || "scope.yml lists no networks."} Ask your administrator to add
          the address ranges your organisation owns to <span className="mono">scope.yml</span> on the server (see scope.example.yml).
        </Banner>
      ) : (
        <div className="grid gap-4 md:grid-cols-3">
          {[["Allowed networks", scope.networks, "safe"], ["Allowed host names", scope.hosts, "safe"],
            ["Never test", scope.never_scan, "danger"]].map(([label, items, tone]) => (
            <div key={label}>
              <p className="label">{label}</p>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {items.length ? items.map((x) => <Chip key={x} tone={tone}><span className="mono">{x}</span></Chip>)
                  : <span className="text-sm text-ink-400">none</span>}
              </div>
            </div>
          ))}
        </div>
      )}
      <p className="mt-4 flex items-center gap-1.5 text-xs text-ink-400"><ShieldOff size={13} />
        Addresses Rakshak has flagged or blocked as attackers are always refused, even if they are inside scope.</p>
    </div>
  );
}

function ToolCard({ p, user, onChange }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const toggle = async () => {
    setBusy(true); setErr("");
    try { await api(`/plugins/${p.id}/${p.enabled ? "disable" : "enable"}`, { method: "POST" }); await onChange(); }
    catch (e) { setErr(e.message); }
    setBusy(false);
  };
  const tone = p.enabled ? "safe" : p.available ? "muted" : "danger";
  return (
    <div className="card p-5">
      <div className="flex flex-wrap items-start gap-3">
        <span className={`grid h-10 w-10 shrink-0 place-items-center rounded-xl ${p.enabled ? "bg-brand-50 text-brand-700" : "bg-canvas text-ink-400"}`}><Radar size={19} /></span>
        <div className="min-w-[200px] flex-1">
          <p className="font-bold">{p.name} <span className="text-xs font-normal text-ink-400">v{p.version}</span></p>
          <p className="mt-0.5 text-sm text-ink-500">{p.description}</p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            <Chip tone={tone}>{p.enabled ? "Enabled" : p.available ? "Disabled" : "Unavailable"}</Chip>
            <Chip tone={p.kind === "active" ? "warn" : "info"} title={p.kind === "active" ? "Sends traffic to the target" : "Only reads local data"}>
              {p.kind === "active" ? "Sends traffic to target" : "Reads local data only"}</Chip>
            <Chip tone="muted">{p.approval === "admin" ? "Admin approval per run" : "Requester confirms"}</Chip>
            {p.builtin && <Chip tone="brand">Built in</Chip>}
          </div>
        </div>
        {can(user, "admin") && (p.available || p.enabled) && (
          <button className={p.enabled ? "btn-ghost" : "btn-brand"} disabled={busy} onClick={toggle}>
            {busy ? <Loader2 size={15} className="animate-spin" /> : p.enabled ? <PowerOff size={15} /> : <Power size={15} />}
            {p.enabled ? "Disable" : "Review done: enable"}</button>
        )}
      </div>
      {p.reason && <p className="mt-3 text-sm text-warn">{p.reason}</p>}
      {err && <p className="mt-3 text-sm text-danger">{err}</p>}
      <button onClick={() => setOpen((o) => !o)} className="mt-3 flex items-center gap-1 text-sm font-semibold text-brand-700">
        <ChevronDown size={15} className={open ? "rotate-180 transition" : "transition"} /> {open ? "Hide" : "Review"} exact command and fingerprints</button>
      {open && (
        <dl className="mt-3 grid gap-3 rounded-xl bg-canvas p-4 text-sm md:grid-cols-2">
          <div><dt className="label">Program</dt><dd className="mono mt-1 break-all text-xs">{p.interpreter ? `${p.interpreter} ` : ""}{p.executable}</dd></div>
          <div><dt className="label">Arguments (no shell)</dt><dd className="mono mt-1 break-all text-xs">{p.args.join(" ")}</dd></div>
          <div><dt className="label">Limits</dt><dd className="mt-1">{p.timeout_s} s, {p.max_output_kb} KB output</dd></div>
          <div><dt className="label">Results checked by</dt><dd className="mt-1">{p.validator === "none" ? "No independent re-check (results stay Suspected)" : p.validator}</dd></div>
          <div><dt className="label">Source</dt><dd className="mt-1 break-all">{p.source || "not stated"}</dd></div>
          <div><dt className="label">Pinned fingerprints (SHA-256)</dt>
            <dd className="mono mt-1 break-all text-[11px]">{p.trusted_hashes?.length ? p.trusted_hashes.map((h) => <span key={h} className="block">{h}</span>) : "not pinned yet (pinned when enabled)"}</dd></div>
        </dl>
      )}
    </div>
  );
}

function RequestForm({ plugins, scopeOk, onDone }) {
  const usable = plugins.filter((p) => p.enabled && p.available && p.kind === "active");
  const [pid, setPid] = useState("");
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("");
  const [ok, setOk] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);
  const plugin = usable.find((p) => p.id === pid) || usable[0];
  const placeholder = plugin?.target_type === "url" ? "http://10.20.0.15:8080" : "10.20.0.15";
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setMsg(null);
    try {
      const r = await api(`/plugins/${plugin.id}/runs`, { method: "POST", body: { target, reason, authorised: ok } });
      setMsg({ tone: "safe", text: `Request #${r.id} saved. It waits for an admin to approve it on the list below.` });
      setTarget(""); setReason(""); setOk(false);
      await onDone();
    } catch (ex) { setMsg({ tone: "danger", text: ex.message }); }
    setBusy(false);
  };
  if (!usable.length) return <Empty icon={Radar} title="No tool is enabled yet" text="An admin must review and enable a tool above before tests can be requested." />;
  return (
    <form onSubmit={submit} className="space-y-4">
      {!scopeOk && <Banner tone="warn" icon={Lock}>Scope is empty, so every request will be refused until scope.yml is filled in.</Banner>}
      <div className="grid gap-4 md:grid-cols-2">
        <label className="block"><span className="label">Tool</span>
          <select className="mt-1 w-full rounded-xl border border-line bg-white px-3 py-2.5 text-sm" value={plugin?.id || ""} onChange={(e) => setPid(e.target.value)}>
            {usable.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select></label>
        <label className="block"><span className="label flex items-center gap-1">Target
          <InfoTip text={plugin?.target_type === "url" ? "A web address using a numeric IP, like http://10.20.0.15:8080. Host names are refused in this version so the address cannot be switched after approval." : "One IP address or host name inside your scope."} /></span>
          <input className="mono mt-1 w-full rounded-xl border border-line px-3 py-2.5 text-sm" placeholder={placeholder}
            value={target} onChange={(e) => setTarget(e.target.value)} required maxLength={300} /></label>
      </div>
      <label className="block"><span className="label">Why is this test needed?</span>
        <input className="mt-1 w-full rounded-xl border border-line px-3 py-2.5 text-sm" placeholder="e.g. Monthly check of the staff portal, change ticket CHG-1234"
          value={reason} onChange={(e) => setReason(e.target.value)} required minLength={5} maxLength={500} /></label>
      <label className="flex items-start gap-3 rounded-xl border border-line bg-canvas p-3 text-sm">
        <input type="checkbox" className="mt-1" checked={ok} onChange={(e) => setOk(e.target.checked)} />
        <span>I confirm my organisation owns this system and has authorised this test. I understand the tool will send real network traffic to it.</span>
      </label>
      {msg && <Banner tone={msg.tone}>{msg.text}</Banner>}
      <button className="btn-primary" disabled={busy || !ok || !target || reason.length < 5}>
        {busy ? <Loader2 size={15} className="animate-spin" /> : <Send size={15} />} Request test</button>
    </form>
  );
}

function RunRow({ r, user, onChange }) {
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState("");
  const st = RUN_STATUS[runState(r)] || { text: r.status, tone: "muted" };
  const act = async (kind) => {
    setBusy(kind); setErr("");
    try {
      if (kind === "approve") await api(`/runs/${r.id}/approve`, { method: "POST" });
      else await api(`/runs/${r.id}/reject`, { method: "POST", body: { why: "Rejected by reviewer" } });
      await onChange();
    } catch (e) { setErr(e.message); }
    setBusy(null);
  };
  const s = r.summary || {};
  return (
    <li className="py-3.5">
      <div className="flex flex-wrap items-center gap-3">
        <span className="w-12 text-xs font-semibold text-ink-400">#{r.id}</span>
        <div className="min-w-[220px] flex-1">
          <p className="font-semibold">{r.plugin_id} <span className="mono font-normal text-ink-500">{r.target || "-"}</span></p>
          <p className="text-xs text-ink-400">requested by {r.requested_by || "?"} {ago(r.requested_at)}{r.approved_by ? ` · approved by ${r.approved_by}` : ""}
            {r.status === "completed" && ` · ${s.finding_count ?? 0} observations`}</p>
          {r.authorised_statement && <p className="text-xs text-ink-500">Why: {r.authorised_statement}</p>}
          {["refused", "failed"].includes(r.status) && r.reason && <p className="mt-1 text-xs text-danger">{r.reason}</p>}
        </div>
        <Chip tone={st.tone}>{st.text}</Chip>
        <span title={r.verified ? "Record signature verified" : "Record signature does NOT verify"}>
          <Fingerprint size={16} className={r.verified ? "text-safe" : "text-danger"} /></span>
        {r.status === "queued" && can(user, "analyst") && (
          <>
            <button className="btn-brand px-3 py-1.5" disabled={!!busy} onClick={() => act("approve")}>
              {busy === "approve" ? <Loader2 size={14} className="animate-spin" /> : <ClipboardCheck size={14} />} Approve and run</button>
            <button className="btn-ghost px-3 py-1.5" disabled={!!busy} onClick={() => act("reject")}><XCircle size={14} /> Reject</button>
          </>
        )}
        {["completed", "failed"].includes(r.status) && (
          <Link to={`/tests/${r.id}`} className="btn-ghost px-3 py-1.5">Results <ArrowRight size={14} /></Link>
        )}
      </div>
      {busy === "approve" && <p className="mt-2 text-xs text-info">The tool is running. This can take up to its time limit.</p>}
      {err && <p className="mt-2 text-xs text-danger">{err}</p>}
    </li>
  );
}

export default function Tests() {
  const { user } = useOverview() || {};
  const { data, reload, error } = usePoll("/plugins", 10000);
  const { data: runs, reload: reloadRuns, error: runsError } = usePoll("/runs?limit=50", 5000);
  const refresh = async () => { await reload(); await reloadRuns(); };
  if (error) return <Banner tone="danger" icon={AlertTriangle}>Could not load tools: {error}</Banner>;
  if (!data) return <div className="card h-64 animate-pulse" />;
  const scopeOk = !data.scope.error && data.scope.networks.length > 0;
  return (
    <div className="space-y-6">
      <div className="card p-6">
        <SectionTitle title="How a security test works" sub="Four steps. Nothing touches a system until step 3." />
        <ol className="grid gap-3 md:grid-cols-4">
          {STEPS.map((s) => (
            <li key={s.n} className="rounded-xl border border-line bg-canvas/60 p-4">
              <span className="grid h-7 w-7 place-items-center rounded-full bg-ink text-xs font-bold text-white">{s.n}</span>
              <p className="mt-2 font-bold">{s.title}</p>
              <p className="mt-1 text-xs leading-relaxed text-ink-500">{s.text}</p>
            </li>
          ))}
        </ol>
        {data.two_person && <p className="mt-3 text-xs text-ink-500"><CheckCircle2 size={13} className="mr-1 inline text-safe" />Two-person rule is on: the approver must be a different person from the requester.</p>}
      </div>
      <ScopeCard scope={data.scope} />
      <div>
        <SectionTitle title="Tools" hint="Tools are added by placing a folder with a plugin.yml file on the server (for example a copy of a GitHub tool brought in on USB). Tools from outside Rakshak stay switched off unless the server is started with RAKSHAK_ALLOW_EXTERNAL_PLUGINS=1."
          sub={can(user, "admin") ? "Review each tool before enabling it" : "Only an admin can enable or disable tools"} />
        <div className="grid gap-4 lg:grid-cols-2">
          {data.plugins.map((p) => <ToolCard key={p.id} p={p} user={user} onChange={refresh} />)}
        </div>
        {!data.plugins.length && <Empty icon={Radar} title="No tools found" />}
      </div>
      {can(user, "analyst") && (
        <div className="card p-6">
          <SectionTitle title="Request a test" icon={Target} sub="The request is checked against scope now and again at approval." />
          <RequestForm plugins={data.plugins} scopeOk={scopeOk} onDone={refresh} />
        </div>
      )}
      <div className="card p-6">
        <SectionTitle title="Test requests and results" sub="Newest first. Each record is signed so later edits are detectable." />
        {runsError && <div className="mb-3"><Banner tone="danger">Could not load test records: {runsError}</Banner></div>}
        {!runs && !runsError ? <div className="h-24 animate-pulse rounded-xl bg-canvas" /> : runs?.length ? <ul className="divide-y divide-line">{runs.map((r) => <RunRow key={r.id} r={r} user={user} onChange={refresh} />)}</ul>
          : <Empty icon={ClipboardCheck} title="No tests yet" text="Requested, refused and finished tests all appear here." />}
      </div>
    </div>
  );
}
