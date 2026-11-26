import { Link } from "react-router-dom";
import { Activity, AlertTriangle, ArrowRight, Bot, Brain, CheckCircle2, EyeOff, FileText, Radar, ScanLine,
         ShieldAlert, ShieldCheck, Siren, XCircle } from "lucide-react";
import { ago, srcLabel, usePoll } from "../api";
import { useOverview } from "../components/Layout";
import TrafficChart from "../components/TrafficChart";
import { AiChip, Banner, Empty, InfoTip, SectionTitle, SeverityChip, StatCard, StatusChip, ValidationChip } from "../components/ui";

function Hero({ ov }) {
  if (!ov) return <div className="card h-36 animate-pulse" />;
  const waiting = ov.recent.find((i) => i.status === "awaiting_approval");
  const v = ov.state === "blind"
    ? { tone: "danger", icon: EyeOff, title: "Rakshak cannot see your logs",
        text: !ov.engine_alive ? "The log reader has stopped. Restart Rakshak on the server."
          : "None of the configured log files can be read, so Rakshak cannot tell you whether anything is happening. Check the log sources below.",
        cta: null }
    : ov.state === "attention"
    ? { tone: "warn", icon: AlertTriangle, title: "Needs your attention",
        text: waiting ? `Rakshak found "${waiting.explain.title.toLowerCase()}" and is waiting for your decision.`
          : "There is recent suspicious activity that has not been resolved.",
        cta: waiting ? { to: `/alerts/${waiting.id}`, label: "Review and decide" } : { to: "/alerts", label: "See alerts" } }
    : { tone: "safe", icon: ShieldCheck, title: "No active alerts",
        text: ov.events_total
          ? `Nothing suspicious in the last 10 minutes of the logs Rakshak can read (${ov.events_total.toLocaleString()} events checked so far). This only covers those logs.`
          : "The log sources are readable but no new lines have arrived since Rakshak started.",
        cta: null };
  const tones = { safe: "bg-safe text-white", warn: "bg-warn text-white", danger: "bg-danger text-white" };
  const bg = { safe: "from-safe-bg", warn: "from-warn-bg", danger: "from-danger-bg" };
  return (
    <div className={`card flex flex-wrap items-center gap-5 bg-gradient-to-r ${bg[v.tone]} to-white p-6 animate-fadeUp`}>
      <span className={`grid h-14 w-14 shrink-0 place-items-center rounded-2xl ${tones[v.tone]}`}><v.icon size={28} /></span>
      <div className="min-w-[260px] flex-1">
        <h2 className="text-2xl font-bold tracking-tight">{v.title}</h2>
        <p className="mt-1 text-[15px] text-ink-500">{v.text}</p>
      </div>
      {v.cta && <Link to={v.cta.to} className="btn-primary">{v.cta.label} <ArrowRight size={16} /></Link>}
    </div>
  );
}

function Sources({ ov }) {
  const hs = ov.hostsec || {};
  return (
    <div className="card p-6">
      <SectionTitle title="What Rakshak is watching"
        hint="Web attacks leave lines in these log files; system attacks leave traces on the machine itself. Rakshak watches both. If a file is missing or unreadable, attacks recorded there are invisible to it."
        sub="This machine (files, accounts, ports) + log files on this server, and whether blocks reach the firewall" />
      <div className="mb-4 rounded-xl border border-line bg-canvas/60 p-4 text-sm">
        <p className="flex items-center gap-2 font-semibold">
          {hs.enabled && ov.hostsec_alive
            ? <CheckCircle2 size={17} className="text-safe" />
            : <XCircle size={17} className={hs.enabled ? "text-danger" : "text-ink-400"} />}
          System security sensors (this machine)
        </p>
        {hs.enabled ? (
          <>
          <p className="mt-1 text-ink-500">
            File integrity on {hs.watched_files || 0} critical files · {hs.accounts_known || 0} accounts tracked · {hs.ports_listening || 0} listening ports baselined.
            Scans every {hs.interval_s}s{hs.last_scan ? ` · last scan ${ago(hs.last_scan)}` : " · starting up"}.
            {ov.pipeline?.host_findings ? ` ${ov.pipeline.host_findings} system finding${ov.pipeline.host_findings === 1 ? "" : "s"} so far.` : " No system findings so far."}
            {hs.vault_copies ? ` ${hs.vault_copies} private vault copy${hs.vault_copies === 1 ? "" : "ies"} kept for verified undo.` : ""}
            {hs.accepted_changes ? ` ${hs.accepted_changes} change${hs.accepted_changes === 1 ? "" : "s"} accepted as sanctioned by your team.` : ""}
          </p>
          {hs.enabled && (ov.nodes || ov.ingest_enabled) && (
            <p className="mt-1 text-xs text-ink-400">
              {ov.nodes ? `Reporting sensors: ${ov.nodes} machine${ov.nodes === 1 ? "" : "s"}.`
                        : (ov.ingest_enabled ? "Sensor intake is armed (secret configured) - no other machine has reported yet." : "")}
              {hs.vault_copies ? ` Undo copies live only in this server's private vault (${ov.vault_copies ?? hs.vault_copies} blobs).` : ""}
            </p>
          )}
          </>
        ) : (
          <p className="mt-1 text-ink-500">Off on this install (RAKSHAK_HOSTSEC_INTERVAL=0). The log sources below are still watched.</p>
        )}
      </div>
      <ul className="divide-y divide-line rounded-xl border border-line">
        {ov.sources.map((s) => (
          <li key={s.path} className="flex flex-wrap items-center gap-3 px-4 py-3 text-sm">
            {s.readable ? <CheckCircle2 size={17} className="text-safe" /> : <XCircle size={17} className="text-danger" />}
            <span className="mono flex-1 break-all">{s.path}</span>
            <span className={s.readable ? "text-ink-500" : "font-semibold text-danger"}>
              {s.readable ? `readable · ${(s.bytes / 1024).toFixed(1)} KB` : (s.errors?.[0] || s.state)}</span>
          </li>
        ))}
      </ul>
      <div className="mt-4">
        <Banner tone={ov.enforcer.ready ? "safe" : "warn"} icon={ov.enforcer.ready ? ShieldCheck : AlertTriangle}>
          <b>Blocking: {ov.enforcer.ready ? "connected to the firewall." : "not connected to any firewall."}</b> {ov.enforcer.detail}
        </Banner>
      </div>
      {ov.errors?.length > 0 && (
        <div className="mt-3"><Banner tone="danger" icon={XCircle}>
          <b>Recent engine errors:</b>{ov.errors.map((e) => <span key={e} className="mono block text-xs">{e}</span>)}</Banner></div>
      )}
    </div>
  );
}

const STEPS = [
  { key: "sensed", icon: Activity, name: "Read", text: "New log lines read and stored with a fingerprint" },
  { key: "detections", icon: Radar, name: "Detect", text: "Lines that matched an attack rule or behaviour" },
  { key: "ai_flagged", icon: Bot, name: "Spot automation", text: "Alerts whose behaviour looked machine-driven (estimate)" },
  { key: "explained", icon: Brain, name: "Explain", text: "Alerts written up in plain words" },
  { key: "contained", icon: ShieldCheck, name: "Block", text: "Alerts blocked AND verified at the firewall" },
  { key: "reported", icon: FileText, name: "Report", text: "PDF reports prepared for review" },
];

function Pipeline({ counters }) {
  return (
    <div className="card p-6">
      <SectionTitle title="How Rakshak works on your logs"
        hint="Counts come from the stored data, so they survive a restart. 'Block' only counts blocks that the firewall confirmed."
        sub="Six steps, all on this server" />
      <ol className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {STEPS.map((s, i) => (
          <li key={s.key} className="flex flex-col rounded-xl border border-line bg-canvas/60 p-4">
            <div className="flex items-center justify-between">
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-white text-brand-700 shadow-card"><s.icon size={18} /></span>
              <span className="text-xs font-bold text-ink-400">STEP {i + 1}</span>
            </div>
            <p className="mt-3 font-bold">{s.name}</p>
            <p className="mt-0.5 text-xs leading-relaxed text-ink-500">{s.text}</p>
            <p className="mt-auto pt-3 text-2xl font-bold tracking-tight">{(counters?.[s.key] ?? 0).toLocaleString()}</p>
          </li>
        ))}
      </ol>
    </div>
  );
}

export function IncidentRow({ inc }) {
  const bar = { critical: "bg-danger", high: "bg-danger", medium: "bg-warn", low: "bg-info" }[inc.severity];
  return (
    <Link to={`/alerts/${inc.id}`}
      className="group flex items-center gap-4 rounded-xl border border-line bg-white p-4 transition hover:border-brand-100 hover:shadow-card">
      <span className={`h-12 w-1.5 shrink-0 rounded-full ${bar}`} />
      <div className="min-w-0 flex-1">
        <p className="truncate font-semibold">{inc.explain.title}</p>
        <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-ink-500">
          <SeverityChip level={inc.severity} />
          <ValidationChip value={inc.validation} />
          <AiChip score={inc.ai_score} label={inc.ai_label} />
          <span>{inc.source_ip === "system" ? "on" : "from"} <span className="mono font-semibold text-ink">{srcLabel(inc.source_ip)}</span></span>
          <span>· {inc.event_count} events · {ago(inc.last_seen)}</span>
        </div>
      </div>
      <StatusChip status={inc.status} />
      <ArrowRight size={18} className="text-ink-400 transition group-hover:translate-x-0.5 group-hover:text-brand-700" />
    </Link>
  );
}

export default function Home() {
  const { ov } = useOverview() || {};
  const { data: traffic } = usePoll("/traffic?window=120", 3000);
  return (
    <div className="space-y-6">
      <Hero ov={ov} />
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatCard icon={ScanLine} label="Events checked" value={(ov?.events_total ?? 0).toLocaleString()}
          hint="Each log line Rakshak understood (a web request or a login attempt) is one event."
          sub={`${(ov?.events_5min ?? 0).toLocaleString()} in the last 5 minutes`} />
        <StatCard icon={Siren} tone="warn" label="Alerts" value={ov?.incidents_total ?? 0}
          hint="Suspicious events from the same source are grouped into one alert."
          sub={ov?.awaiting ? `${ov.awaiting} waiting for your decision` : "none waiting for you"} />
        <StatCard icon={ShieldCheck} tone="safe" label="Blocked right now" value={ov?.blocked_count ?? 0}
          hint="Addresses on the blocklist at this moment. 'Applied so far' counts alerts whose block the firewall confirmed, including blocks that were later undone or expired."
          sub={`${ov?.contained ?? 0} block(s) applied and verified so far`} />
        <StatCard icon={Radar} tone="info" label="Security tests" value={ov?.tests_total ?? 0}
          hint="Approved tool runs against your own systems (see Security tests)."
          sub={ov?.tests_waiting ? `${ov.tests_waiting} waiting for approval` : "none waiting"} />
      </div>
      {ov && <Sources ov={ov} />}
      <div className="card p-6">
        <SectionTitle title="Activity in the logs"
          hint="Each bar is one second. Teal bars are normal events. Red bars are events Rakshak flagged."
          sub="Events per second, last 2 minutes"
          right={<div className="flex items-center gap-4 text-xs font-medium text-ink-500">
            <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm bg-brand opacity-75" />Normal</span>
            <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm bg-danger" />Flagged</span>
          </div>} />
        <TrafficChart series={traffic || []} />
      </div>
      <Pipeline counters={ov?.pipeline} />
      <div className="card p-6">
        <SectionTitle title="Latest alerts" sub="Click any alert to see what happened and what to do"
          right={<Link to="/alerts" className="btn-ghost">All alerts <ArrowRight size={15} /></Link>} />
        {ov?.recent?.length ? (
          <div className="space-y-2.5">{ov.recent.map((i) => <IncidentRow key={i.id} inc={i} />)}</div>
        ) : (
          <Empty icon={ShieldAlert} title="No alerts yet"
            text="When Rakshak finds suspicious activity in your logs, it appears here with a plain-language explanation." />
        )}
      </div>
      <p className="flex items-center gap-1.5 text-xs text-ink-400">
        <InfoTip text="Attack rules are YAML files. New rule packs (from a trusted colleague or an offline feed on a USB stick) are imported through an admin gate: schema check first, then a self-test against the pack's own positive and negative examples - dead rules or rules that fire on benign traffic are refused and logged. Alerts also offer a drafted rule mined from their own evidence." />
        {ov?.rules_loaded ?? 0} rule groups loaded{ov?.rules_imported ? ` (${ov.rules_imported} imported after passing their self-test)` : ""} · unusual-behaviour model: {ov?.anomaly_model?.trained ? `trained on ${ov.anomaly_model.trained_on} samples` : "off (not trained), so only rules and behaviour limits raise alerts"}
      </p>
    </div>
  );
}
