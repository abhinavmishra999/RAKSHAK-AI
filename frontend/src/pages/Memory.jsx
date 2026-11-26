import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, Brain, Radar, Search, ShieldAlert, ShieldCheck } from "lucide-react";
import { ago, CATEGORY, dateTime, RUN_STATUS, runState, SEVERITY, STATUS, usePoll, VALIDATION } from "../api";
import { Chip, Empty, InfoTip, SectionTitle } from "../components/ui";

const KINDS = [
  { id: "all", label: "Everything" },
  { id: "alert", label: "Detected threats" },
  { id: "system", label: "System changes" },
  { id: "action", label: "Responses" },
  { id: "test", label: "Security tests" },
];
const RANGES = [
  { days: 1, label: "Today" },
  { days: 7, label: "7 days" },
  { days: 30, label: "30 days" },
  { days: 0, label: "All time" },
];
const TOOL = { "website-check": "Website check", "nmap-ports": "Port scan (Nmap)" };
const MODE = { recommend: "Ask me first", auto: "Auto-block", manual: "unblocked by you", expiry: "expired automatically" };

function title(e) {
  if (e.kind === "alert") return `${CATEGORY[e.category] || e.category} ${e.source_ip === "system" ? "on this machine" : `from ${e.source_ip}`}`;
  if (e.kind === "action") {
    if (e.action === "unblock_ip") return `Unblocked ${e.target}`;
    if (e.status === "proposed") return `Suggested blocking ${e.target}`;
    if (e.action === "block_refused" || e.status === "refused") return `Refused to block ${e.target}`;
    if (e.status === "cancelled") return `Block of ${e.target} cancelled`;
    if (e.status === "undone") return `Blocked, then unblocked ${e.target}`;
    if (["restore_file", "stop_process", "lock_account", "remove_account"].includes(e.action)) {
      if (e.status === "proposed") return `Proposed undo (${e.action.replace("_", " ")}) of ${e.target}`;
      if (e.status === "cancelled") return `Undo proposal cancelled: ${e.target}`;
      if (e.status === "refused") return `Undo refused (guard): ${e.target}`;
      if (e.status === "failed") return `Undo attempted, NOT verified: ${e.target}`;
      return `Undid attacker change: ${e.action.replace("_", " ")} ${e.target}`;
    }
    if (e.action === "accept_change") return `Accepted as sanctioned: ${e.target}`;
    return `Blocked ${e.target}`;
  }
  return `${TOOL[e.tool] || e.tool} on ${e.target}`;
}

function toText(e) {
  return [title(e), e.target, e.source_ip, e.tool, e.detail, e.requested_by, e.approved_by,
    e.authorised_statement].filter(Boolean).join(" ").toLowerCase();
}

function Chips({ e }) {
  if (e.kind === "alert") return (
    <>
      <Chip tone={SEVERITY[e.severity]?.tone}>{SEVERITY[e.severity]?.text || e.severity}</Chip>
      <Chip tone={(STATUS[e.status] || {}).tone || "muted"}>{(STATUS[e.status] || {}).text || e.status}</Chip>
      <Chip tone={(VALIDATION[e.validation] || {}).tone || "muted"}
        title={(VALIDATION[e.validation] || {}).help}>{(VALIDATION[e.validation] || {}).text || "Not re-checked yet"}</Chip>
    </>
  );
  if (e.kind === "action") return (
    <>
      {e.mode && <Chip tone="muted">{MODE[e.mode] || e.mode}</Chip>}
      {e.signed && <Chip tone="safe" icon={ShieldCheck} title="This record carries a signature; if it were edited, the signature check would fail and reports would be refused.">Record signed</Chip>}
    </>
  );
  const st = runState({ status: e.status, summary: { state: e.state } });
  return (
    <>
      <Chip tone={(RUN_STATUS[st] || {}).tone || "muted"}>{(RUN_STATUS[st] || {}).text || st}</Chip>
      {e.requested_by && <Chip tone="muted">asked by {e.requested_by}</Chip>}
      {e.approved_by && <Chip tone="muted">approved by {e.approved_by}</Chip>}
    </>
  );
}

export default function Memory() {
  const [kind, setKind] = useState("all");
  const [days, setDays] = useState(0);
  const [q, setQ] = useState("");
  const [limit, setLimit] = useState(100);
  const { data, error } = usePoll(`/memory?kind=${kind}&days=${days}&limit=${limit}`, 10000);

  const entries = useMemo(() => {
    let list = data?.entries || [];
    if (q.trim()) list = list.filter((e) => toText(e).includes(q.trim().toLowerCase()));
    return list;
  }, [data, q]);

  const days_label = (ts) => {
    if (!ts) return "Unknown time";
    const d = new Date(ts * 1000);
    const today = new Date();
    if (d.toDateString() === today.toDateString()) return "Today";
    const y = new Date(today.getTime() - 86400000);
    if (d.toDateString() === y.toDateString()) return "Yesterday";
    return d.toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short", year: "numeric" });
  };

  const grouped = useMemo(() => {
    const g = [];
    for (const e of entries) {
      const key = days_label(e.ts);
      if (!g.length || g[g.length - 1].key !== key) g.push({ key, items: [] });
      g[g.length - 1].items.push(e);
    }
    return g;
  }, [entries]);

  const iconFor = (e) => (
    e.kind === "alert" ? <ShieldAlert size={16} />
      : e.kind === "test" ? <Radar size={16} />
        : <ShieldCheck size={16} />
  );
  const bgFor = (e) => (
    e.kind === "alert" ? "bg-amber-50 text-amber-600"
      : e.kind === "test" ? "bg-sky-50 text-sky-600"
        : e.status === "refused" || e.status === "cancelled" || e.status === "failed"
          ? "bg-rose-50 text-rose-600" : "bg-emerald-50 text-emerald-600"
  );
  const linkTo = (e) => (e.kind === "alert" ? `/alerts/${e.id}`
    : e.kind === "test" ? `/tests/${e.id}` : e.incident_id ? `/alerts/${e.incident_id}` : null);

  return (
    <div className="space-y-6">
      <div className="card p-6">
        <div className="flex flex-wrap items-start gap-4">
          <span className="grid h-11 w-11 place-items-center rounded-xl bg-brand-50 text-brand-700"><Brain size={22} /></span>
          <div className="min-w-[280px] flex-1">
            <h2 className="flex items-center gap-2 text-lg font-bold">What Rakshak remembers
              <InfoTip text="Nothing extra is stored here. This timeline is built each time you open it, from the same signed records that the Alerts, Protection and Security tests pages show - so it cannot disagree with them or quietly be edited." /></h2>
            <p className="mt-1 text-sm text-ink-500">
              Every detected threat, every response (block, refusal, undo) and every security test your team ran, newest first.
              {data ? ` ${data.counts.alert || 0} threat${(data.counts.alert || 0) === 1 ? "" : "s"}, ${data.counts.action || 0} response${(data.counts.action || 0) === 1 ? "" : "s"}, ${data.counts.test || 0} test${(data.counts.test || 0) === 1 ? "" : "s"} on record.` : ""}
            </p>
          </div>
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          {KINDS.map((k) => (
            <button key={k.id} onClick={() => setKind(k.id)}
              className={`chip px-3.5 py-1.5 text-sm ${kind === k.id ? "border-ink bg-ink text-white" : "border-line bg-white text-ink-500 hover:text-ink"}`}>
              {k.label}{data && k.id !== "all" && data.counts[k.id] ? ` (${data.counts[k.id]})` : ""}
            </button>
          ))}
          <span className="mx-1 hidden md:block h-5 w-px bg-line" />
          {RANGES.map((r) => (
            <button key={r.label} onClick={() => setDays(r.days)}
              className={`chip px-3 py-1 text-xs ${days === r.days ? "border-brand bg-brand-50 text-brand-700" : "border-line bg-white text-ink-400 hover:text-ink"}`}>
              {r.label}
            </button>
          ))}
          <span className="relative ml-auto">
            <Search size={14} className="absolute left-2.5 top-2 text-ink-400" />
            <input value={q} onChange={(ev) => setQ(ev.target.value)} placeholder="Search address, tool, person..."
              className="w-52 rounded-xl border border-line bg-white py-1.5 pl-8 pr-2 text-sm" />
          </span>
        </div>
        {error && <p className="mt-3 text-sm text-rose-600">Could not read the memory: {error}</p>}
      </div>

      {!data && !error && <Empty icon={Brain} title="Reading the record..." text="Loading everything Rakshak has done so far." />}
      {data && !entries.length && (
        <Empty icon={Brain} title={q ? "Nothing matches your search" : "Nothing recorded yet"}
          text={q ? "Try a shorter search - an IP address, a tool name or a person."
            : "Memory fills itself: detected threats, blocks and approvals, and security-test runs appear here as they happen. Until then this page is honestly empty - Rakshak never adds example or placeholder entries."} />
      )}

      {grouped.map((g) => (
        <div key={g.key} className="space-y-2">
          <SectionTitle title={g.key} sub={`${g.items.length} entr${g.items.length === 1 ? "y" : "ies"}`} />
          <div className="card divide-y divide-line">
            {g.items.map((e) => (
              <div key={`${e.kind}-${e.id}`} className="flex items-center gap-3.5 px-5 py-3.5">
                <span className={`grid h-8 w-8 shrink-0 place-items-center rounded-lg ${bgFor(e)}`}>{iconFor(e)}</span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-semibold text-ink" title={title(e)}>{title(e)}</p>
                  <p className="truncate text-xs text-ink-400">
                    {dateTime(e.ts).split(",")[1]?.trim() || ago(e.ts)}
                    {e.kind === "alert" && e.event_count ? ` · ${e.event_count} matching log line${e.event_count === 1 ? "" : "s"}` : ""}
                    {e.kind === "action" && e.detail ? ` · ${e.detail}` : ""}
                    {e.kind === "test" && e.authorised_statement ? ` · ${e.authorised_statement}` : ""}
                  </p>
                </div>
                <span className="hidden shrink-0 items-center gap-1.5 md:flex"><Chips e={e} /></span>
                {linkTo(e) && (
                  <Link to={linkTo(e)} className="btn-ghost shrink-0 px-2.5 py-1 text-xs" title="Open the full evidence">
                    Evidence <ArrowRight size={13} />
                  </Link>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}

      {data && data.shown >= limit && (
        <button className="btn-ghost w-full py-2 text-sm" onClick={() => setLimit((l) => Math.min(l + 200, 500))}>
          Show more ({data.shown} of {Object.values(data.counts).reduce((a, b) => a + b, 0)} shown)
        </button>
      )}

      <p className="px-1 text-xs text-ink-400">
        Older entries are never deleted automatically here, but your retention policy decides how long the signed database
        itself is kept. The full who-did-what trail with tamper evidence is on the Activity log page.
      </p>
    </div>
  );
}
