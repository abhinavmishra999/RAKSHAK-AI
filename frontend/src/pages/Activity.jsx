import { useState } from "react";
import { CheckCircle2, Fingerprint, ListChecks, Loader2, XCircle } from "lucide-react";
import { api, can, dateTime, usePoll } from "../api";
import { useOverview } from "../components/Layout";
import { Banner, Empty, InfoTip, SectionTitle } from "../components/ui";

const LABEL = {
  "auth.login": "Signed in", "auth.logout": "Signed out", "auth.failed": "Failed sign-in", "auth.provision": "Account created/reset",
  plugin_enable: "Enabled tool", plugin_disable: "Disabled tool", plugin_request: "Requested test", plugin_approve: "Approved test",
  plugin_reject: "Rejected test", plugin_refused: "Test refused", plugin_result: "Test finished",
  block_ip: "Blocked address", block_proposed: "Suggested block", block_refused: "Refused to block", unblock_ip: "Unblocked address",
  approve_block: "Approved block", "settings.mode": "Changed response mode", "incident.resolve": "Resolved alert",
  "incident.report": "Created alert report", "run.report": "Created test report",
};

export default function Activity() {
  const { user } = useOverview() || {};
  const allowed = can(user, "analyst");
  const { data, error } = usePoll(allowed ? "/audit?limit=300" : null, 5000);
  const [check, setCheck] = useState(null);
  const [busy, setBusy] = useState(false);
  const [vErr, setVErr] = useState("");
  const verify = async () => { setBusy(true); setVErr(""); try { setCheck(await api("/integrity")); } catch (e) { setVErr(e.message); } finally { setBusy(false); } };
  if (!allowed) return <Banner tone="info">The activity log is visible to analysts and admins.</Banner>;
  return (
    <div className="space-y-6">
      <div className="card flex flex-wrap items-center gap-4 p-6">
        <span className="grid h-11 w-11 place-items-center rounded-xl bg-brand-50 text-brand-700"><Fingerprint size={22} /></span>
        <div className="min-w-[260px] flex-1">
          <h2 className="flex items-center gap-2 font-bold">Has anything been edited or deleted?
            <InfoTip wide text="Every entry carries a fingerprint of the entry before it and a signature made with a key stored only on this server. Changing or removing an entry breaks the chain. Someone who has the key and full server access could still rewrite everything, so also copy the log to separate storage regularly." /></h2>
          <p className="text-sm text-ink-500">Checks every stored log event and every activity entry.</p>
        </div>
        <button className="btn-ghost" onClick={verify} disabled={busy}>
          {busy ? <Loader2 size={15} className="animate-spin" /> : <Fingerprint size={15} />} Check now</button>
        {vErr && <div className="w-full"><Banner tone="danger">Check could not run: {vErr}</Banner></div>}
        {check && (
          <div className="grid w-full gap-2 md:grid-cols-2">
            {[["Log events", check.events], ["Activity entries", check.audit]].map(([name, c]) => (
              <Banner key={name} tone={c.ok ? "safe" : "danger"} icon={c.ok ? CheckCircle2 : XCircle}>
                {c.ok ? `${name}: all ${c.checked.toLocaleString()} intact.` : `${name}: problem at entry #${c.broken_at}${c.reason ? ` (${c.reason})` : ""}.`}
              </Banner>
            ))}
          </div>
        )}
      </div>
      <div className="card p-6">
        <SectionTitle title="Activity" sub="Newest first. Times are this computer's local time." />
        {error && <Banner tone="danger">{error}</Banner>}
        {!data && !error ? <div className="h-24 animate-pulse rounded-xl bg-canvas" /> : data?.length ? (
          <div className="overflow-hidden rounded-xl border border-line">
            <table className="w-full text-sm">
              <thead className="bg-canvas text-left text-xs uppercase tracking-wider text-ink-400">
                <tr><th className="px-4 py-2.5">When</th><th className="px-4 py-2.5">Who</th><th className="px-4 py-2.5">What</th><th className="px-4 py-2.5">On</th><th className="px-4 py-2.5">Details</th></tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data.map((a) => (
                  <tr key={a.id} className="align-top">
                    <td className="whitespace-nowrap px-4 py-2.5 text-xs text-ink-500">{dateTime(a.ts)}</td>
                    <td className="px-4 py-2.5 font-semibold">{a.actor}</td>
                    <td className="px-4 py-2.5">{LABEL[a.action] || a.action}</td>
                    <td className="mono px-4 py-2.5 text-xs">{a.object}</td>
                    <td className="mono max-w-[360px] px-4 py-2.5 text-[11px] text-ink-500">
                      <span className="line-clamp-2 break-all">{Object.entries(a.detail || {}).map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join("  ")}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty icon={ListChecks} title="No activity yet" />}
      </div>
    </div>
  );
}
