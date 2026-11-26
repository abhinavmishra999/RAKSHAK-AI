import { useState } from "react";
import { AlertTriangle, BadgeCheck, Ban, CheckCircle2, Copy, Hand, Loader2, Lock, ShieldCheck, Undo2, XCircle, Zap } from "lucide-react";
import { Link } from "react-router-dom";
import { api, ago, can, CATEGORY, clock, usePoll } from "../api";
import { useOverview } from "../components/Layout";
import { Banner, Chip, Empty, InfoTip, SectionTitle } from "../components/ui";

const MODES = [
  { id: "recommend", icon: Hand, title: "Ask me first", tag: "Default. Use this first",
    text: "Rakshak never blocks on its own. It suggests a block, and nothing happens until an analyst or admin approves it." },
  { id: "auto", icon: Zap, title: "Auto-block", tag: "Only after a trial period",
    text: "Rakshak blocks high and critical alerts by itself, only when an attack rule or a fixed limit (like 8 failed logins in 60 s) matched and the evidence was re-checked. Never for 'unusual behaviour' alone. Every block expires and can be undone." },
];

function actionText(a) {
  if (a.action === "unblock_ip") return "Unblocked";
  if (a.action === "block_refused") return "Refused to block";
  if (a.status === "proposed") return "Suggested blocking";
  if (a.status === "undone") return "Blocked (later undone)";
  return "Blocked";
}
function whoText(a) {
  if (a.mode === "manual") return "by you";
  if (a.status === "proposed") return "suggested by Rakshak";
  if (/approved/i.test(a.detail || "")) return "approved by you";
  return "automatic";
}
const STATE = { done: ["Done", "safe"], proposed: ["Waiting for you", "warn"], undone: ["Undone", "muted"], expired: ["Expired", "muted"], refused: ["Refused", "danger"] };

export default function Protection() {
  const { data, reload, error } = usePoll("/protection", 2500);
  const [actErr, setActErr] = useState("");
  const { reload: reloadOv, user } = useOverview() || {};
  const [busy, setBusy] = useState(null);
  const [fmt, setFmt] = useState("nftables");
  const [copied, setCopied] = useState(false);
  const act = async (key, fn) => { setBusy(key); setActErr(""); try { await fn(); } catch (e) { setActErr(e.message); } finally { await reload(); reloadOv?.(); setBusy(null); } };
  const copy = async () => { await navigator.clipboard?.writeText(data?.export?.[fmt] || ""); setCopied(true); setTimeout(() => setCopied(false), 1500); };
  if (error && !data) return <Banner tone="danger" icon={XCircle}>Could not load protection status: {error}</Banner>;
  if (!data) return <div className="card h-64 animate-pulse" />;
  return (
    <div className="space-y-6">
      {actErr && <Banner tone="danger" icon={XCircle}>{actErr}</Banner>}
      {error && <Banner tone="danger" icon={XCircle}>Refresh failed, showing last loaded data: {error}</Banner>}
      <div className="card p-6">
        <SectionTitle title="How should Rakshak respond?" sub={can(user, "admin") ? "Only admins can change this. It applies to new alerts." : "Only an admin can change this setting."}
          hint="Start with 'Ask me first' for several weeks and check that alerts are correct on your own traffic before allowing Auto-block. Rakshak's accuracy on your traffic has not been measured yet." />
        <div className="mb-4"><Banner tone={data.enforcer.ready ? "safe" : "warn"} icon={data.enforcer.ready ? ShieldCheck : AlertTriangle}>
          <b>{data.enforcer.ready ? "Connected to the firewall." : "Not connected to any firewall."}</b> {data.enforcer.detail}</Banner></div>
        <div className="grid gap-4 md:grid-cols-2">
          {MODES.map((m) => {
            const on = data.mode === m.id;
            return (
              <button key={m.id} disabled={!!busy || !can(user, "admin")} onClick={() => act("mode", () => api("/settings/mode", { method: "POST", body: { mode: m.id } }))}
                className={`rounded-2xl border-2 p-5 text-left transition ${on ? "border-brand-700 bg-brand-50" : "border-line bg-white hover:border-brand-100"}`}>
                <div className="flex items-center gap-3">
                  <span className={`grid h-10 w-10 place-items-center rounded-xl ${on ? "bg-brand-700 text-white" : "bg-canvas text-ink-500"}`}><m.icon size={19} /></span>
                  <div className="flex-1"><p className="font-bold">{m.title}</p><p className="text-xs text-ink-400">{m.tag}</p></div>
                  <span className={`grid h-6 w-6 place-items-center rounded-full border-2 ${on ? "border-brand-700 bg-brand-700 text-white" : "border-line"}`}>
                    {on && <CheckCircle2 size={14} />}</span>
                </div>
                <p className="mt-3 text-sm text-ink-500">{m.text}</p>
              </button>
            );
          })}
        </div>
      </div>

      <div className="card p-6">
        <SectionTitle title={`Blocked right now (${data.blocklist.length})`}
          hint="'Enforced' means the firewall confirmed the block. 'Recorded only' means it is on Rakshak's list but traffic is NOT stopped until you apply the rules below. Undo if a real user was blocked by mistake."
          sub={`Blocks expire automatically after ${Math.round(data.block_ttl / 3600)} h`} />
        {data.blocklist.length ? (
          <div className="overflow-hidden rounded-xl border border-line">
            <table className="w-full text-sm">
              <thead className="bg-canvas text-left text-xs uppercase tracking-wider text-ink-400">
                <tr><th className="px-4 py-2.5">Source</th><th className="px-4 py-2.5">Why</th><th className="px-4 py-2.5">Firewall</th><th className="px-4 py-2.5">Since</th><th className="px-4 py-2.5">Expires</th><th /></tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data.blocklist.map((b) => (
                  <tr key={b.ip}>
                    <td className="mono px-4 py-3 font-semibold"><Ban size={14} className="mr-2 inline text-danger" />{b.ip}</td>
                    <td className="px-4 py-3 text-ink-500">{CATEGORY[b.reason] || b.reason}</td>
                    <td className="px-4 py-3">{b.enforced === "enforced" ? <Chip tone="safe">Enforced</Chip> : b.enforced === "failed" ? <Chip tone="danger">Failed</Chip> : <Chip tone="warn">Recorded only</Chip>}</td>
                    <td className="px-4 py-3 text-ink-500">{ago(b.added_at)}</td>
                    <td className="px-4 py-3 text-ink-500">{b.expires_at ? new Date(b.expires_at * 1000).toLocaleString() : "never"}</td>
                    <td className="px-4 py-3 text-right">
                      <button className="btn-ghost px-3 py-1.5" disabled={!!busy || !can(user, "analyst")}
                        onClick={() => act(b.ip, () => api("/protection/unblock", { method: "POST", body: { ip: b.ip } }))}>
                        {busy === b.ip ? <Loader2 size={14} className="animate-spin" /> : <Undo2 size={14} />} Undo</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty icon={ShieldCheck} title="Nobody is blocked" text="When a block is approved or made automatically, it appears here." />}
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="card p-6 lg:col-span-3">
          <SectionTitle title="Action history"
            hint="Every action is signed with a secret key stored only on this computer. 'Signature verified' proves the record wasn't changed later."
            sub="Everything Rakshak did, newest first" />
          {data.actions.length ? (
            <ul className="max-h-[420px] divide-y divide-line overflow-auto">
              {data.actions.map((a) => {
                const [txt, tone] = STATE[a.status] || [a.status, "muted"];
                return (
                  <li key={a.id} className="flex flex-wrap items-center gap-3 py-3 text-sm">
                    <span className="w-20 text-xs text-ink-400">{clock(a.ts)}</span>
                    <span className="flex-1"><b>{actionText(a)}</b> <span className="mono">{a.target}</span>
                      <span className="block text-xs text-ink-400">{a.detail} · {whoText(a)}</span></span>
                    <Chip tone={tone}>{txt}</Chip>
                    <span title={a.verified ? "Signature verified" : "Signature invalid"}>
                      {a.verified ? <BadgeCheck size={17} className="text-safe" /> : <XCircle size={17} className="text-danger" />}</span>
                  </li>
                );
              })}
            </ul>
          ) : <Empty icon={Lock} title="No actions yet" />}
        </div>

        <div className="space-y-6 lg:col-span-2">
          <div className="card p-6">
            <h3 className="font-bold">Is the record untouched?</h3>
            <p className="mt-2 text-sm text-ink-500">Every action above is signed. Check the full log and activity chain on the Activity log page.</p>
            <Link to="/activity" className="btn-ghost mt-4 w-full">Open the Activity log</Link>
          </div>
          <div className="card p-6">
            <h3 className="flex items-center gap-2 font-bold">Rules for your firewall team
              <InfoTip wide text="These are suggestions for your network team. Review them before applying them to a production firewall or nginx; Rakshak does not apply them for you unless the nftables connector is enabled." /></h3>
            <div className="mt-3 flex gap-2">
              {["nftables", "nginx"].map((f) => (
                <button key={f} onClick={() => setFmt(f)} className={`chip px-3 py-1 ${fmt === f ? "border-ink bg-ink text-white" : "border-line bg-white text-ink-500"}`}>{f}</button>))}
            </div>
            <pre className="mono mt-3 max-h-40 overflow-auto rounded-xl bg-ink p-3 text-[11px] text-slate-200">{data.export[fmt] || "# nothing blocked yet"}</pre>
            <button onClick={copy} className="btn-ghost mt-3 w-full" disabled={!data.export.count}><Copy size={15} /> {copied ? "Copied" : "Copy"}</button>
          </div>
        </div>
      </div>
    </div>
  );
}
