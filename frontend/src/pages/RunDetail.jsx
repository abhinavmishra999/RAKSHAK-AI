import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, ChevronDown, Download, FileText, Fingerprint, Loader2 } from "lucide-react";
import { FINDING, RUN_STATUS, api, can, dateTime, runState, usePoll } from "../api";
import { useOverview } from "../components/Layout";
import { Banner, Chip, InfoTip, SeverityChip } from "../components/ui";

const GROUPS = [
  { key: "confirmed", title: "Confirmed problems", sub: "The tool reported it and Rakshak reproduced it separately." },
  { key: "suspected", title: "Suspected (not re-checked)", sub: "Reported by the tool, no independent re-check exists." },
  { key: "inconclusive", title: "Could not be checked", sub: "Errors, no answer or unsupported. This is not a pass." },
  { key: "not_reproduced", title: "Not reproduced", sub: "Reported by the tool, but Rakshak's re-check did not see it." },
  { key: "observed_pass", title: "Checks that looked fine", sub: "Only these exact checks. Not proof the system is secure." },
  { key: "info", title: "Other tool output", sub: "Raw output that cannot be validated." },
];

function Finding({ f }) {
  const [open, setOpen] = useState(f.status === "confirmed");
  const st = FINDING[f.status] || FINDING.info;
  return (
    <li className="rounded-xl border border-line bg-white">
      <button onClick={() => setOpen((o) => !o)} className="flex w-full flex-wrap items-center gap-3 px-4 py-3 text-left">
        <span className="min-w-[200px] flex-1 font-semibold">{f.title}</span>
        {f.severity && f.severity !== "pass" && <SeverityChip level={f.severity === "info" ? "low" : f.severity} />}
        <Chip tone={st.tone} title={st.help}>{st.text}</Chip>
        <ChevronDown size={16} className={`text-ink-400 transition ${open ? "rotate-180" : ""}`} />
      </button>
      {open && (
        <div className="space-y-2 border-t border-line px-4 py-3 text-sm text-ink-500">
          {f.what && <p><b className="text-ink">What it means:</b> {f.what}</p>}
          {f.fix && <p><b className="text-ink">How to fix:</b> {f.fix}</p>}
          {f.evidence && <p><b className="text-ink">Tool saw:</b> <span className="mono text-xs">{f.evidence}</span></p>}
          {f.validation_evidence && <p><b className="text-ink">Rakshak re-check:</b> <span className="mono text-xs">{f.validation_evidence}</span></p>}
        </div>
      )}
    </li>
  );
}

export default function RunDetail() {
  const { id } = useParams();
  const { user } = useOverview() || {};
  const { data: r, error, reload } = usePoll(`/runs/${id}`, 0);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [raw, setRaw] = useState(false);
  if (error) return <Banner tone="danger">Could not load this test: {error}</Banner>;
  if (!r) return <div className="card h-64 animate-pulse" />;
  const findings = r.findings || [];
  const count = (k) => findings.filter((f) => f.status === k).length;
  const st = RUN_STATUS[runState(r)] || { text: r.status, tone: "muted" };
  const makeReport = async () => {
    setBusy(true); setErr("");
    try { await api(`/runs/${r.id}/report`, { method: "POST" }); window.open(`/api/runs/${r.id}/report.pdf`, "_blank"); await reload(); }
    catch (e) { setErr(e.message); }
    setBusy(false);
  };
  return (
    <div className="space-y-5 animate-fadeUp">
      <Link to="/tests" className="inline-flex items-center gap-1.5 text-sm font-semibold text-ink-500 hover:text-ink"><ArrowLeft size={16} /> All tests</Link>
      <div className="card flex flex-wrap items-start justify-between gap-4 p-6">
        <div>
          <p className="label">Test #{r.id} · {r.plugin_id} v{r.plugin_version}</p>
          <h2 className="mono mt-1 text-xl font-bold">{r.target}</h2>
          <div className="mt-3 flex flex-wrap items-center gap-2 text-sm text-ink-500">
            <Chip tone={st.tone}>{st.text}</Chip>
            <Chip tone={r.verified ? "safe" : "danger"} icon={Fingerprint}>{r.verified ? "Record signature verified" : "Signature does NOT verify"}</Chip>
            <span>requested by {r.requested_by}, approved by {r.approved_by || "-"} · {dateTime(r.started_at)} · {r.summary?.duration_s ?? "-"} s</span>
          </div>
          <p className="mt-2 text-sm text-ink-500"><b className="text-ink">Why it was requested:</b> {r.authorised_statement || "-"}</p>
          {["refused", "failed"].includes(r.status) && r.reason && (
            <p className="mt-1 text-sm text-danger"><b>Result note:</b> {r.reason}</p>)}
        </div>
        {can(user, "analyst") && ["completed", "failed"].includes(r.status) && (
          <button className="btn-brand" disabled={busy || !r.verified} onClick={makeReport}>
            {busy ? <Loader2 size={15} className="animate-spin" /> : <FileText size={15} />} Create PDF report</button>
        )}
      </div>
      {err && <Banner tone="danger">{err}</Banner>}
      {r.status === "failed" && <Banner tone="danger">The test did not finish correctly, so no findings were accepted: {r.reason}</Banner>}

      {r.status === "completed" && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          {["confirmed", "suspected", "inconclusive", "not_reproduced", "observed_pass"].map((k) => (
            <div key={k} className="card p-4">
              <p className="flex items-center gap-1 text-xs font-semibold text-ink-500">{FINDING[k].text}<InfoTip text={FINDING[k].help} /></p>
              <p className="mt-1 text-2xl font-bold">{count(k)}</p>
            </div>
          ))}
        </div>
      )}

      {GROUPS.filter((g) => count(g.key)).map((g) => (
        <div key={g.key} className="card p-6">
          <h3 className="font-bold">{g.title} ({count(g.key)})</h3>
          <p className="mb-3 text-sm text-ink-500">{g.sub}</p>
          <ul className="space-y-2">{findings.filter((f) => f.status === g.key).map((f, i) => <Finding key={`${f.id}-${i}`} f={f} />)}</ul>
        </div>
      ))}
      {r.status === "completed" && !findings.length && <Banner tone="info">The tool finished but reported nothing. That is not proof that the target is secure.</Banner>}

      <div className="card">
        <button onClick={() => setRaw((x) => !x)} className="flex w-full items-center justify-between px-6 py-4 font-bold">
          Technical record (for auditors) <ChevronDown size={18} className={`transition ${raw ? "rotate-180" : ""}`} /></button>
        {raw && (
          <dl className="grid gap-4 border-t border-line px-6 py-5 text-sm md:grid-cols-2">
            <div className="md:col-span-2"><dt className="label">Exact command (run without a shell)</dt><dd className="mono mt-1 break-all text-xs">{(r.cmd || []).join(" ") || "-"}</dd></div>
            <div><dt className="label">Executable SHA-256</dt><dd className="mono mt-1 break-all text-xs">{r.file_hashes?.executable}</dd></div>
            <div><dt className="label">Manifest SHA-256</dt><dd className="mono mt-1 break-all text-xs">{r.file_hashes?.manifest}</dd></div>
            <div><dt className="label">Pinned target addresses</dt><dd className="mono mt-1 text-xs">{(r.file_hashes?.target_ips || r.summary?.approved_target_ips || []).join(", ")}</dd></div>
            <div><dt className="label">Exit code · output size</dt><dd className="mt-1">{r.exit_code ?? "-"} · {r.stdout_bytes ?? 0} bytes</dd></div>
            <div className="md:col-span-2"><dt className="label">Raw output SHA-256</dt><dd className="mono mt-1 break-all text-xs">{r.stdout_sha256 || "-"}</dd></div>
            {r.stderr_tail && <div className="md:col-span-2"><dt className="label">Tool messages (stderr, last part)</dt>
              <dd><pre className="mono mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded-xl bg-ink p-3 text-[11px] text-slate-200">{r.stderr_tail}</pre></dd></div>}
          </dl>
        )}
      </div>
      {["completed", "failed"].includes(r.status) && (
        <a href={`/api/runs/${r.id}/report.pdf`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-sm font-semibold text-brand-700">
          <Download size={15} /> Download the last generated report (if one exists)</a>
      )}
    </div>
  );
}
