import { useState } from "react";
import { Link } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { usePoll } from "../api";
import { Banner, Empty } from "../components/ui";
import { IncidentRow } from "./Home";

const TABS = [
  { id: "all", label: "All", test: () => true },
  { id: "you", label: "Needs you", test: (i) => i.status === "awaiting_approval" || i.status === "open" },
  { id: "stopped", label: "Blocked", test: (i) => ["contained", "block_recorded", "enforcement_failed"].includes(i.status) },
  { id: "ai", label: "AI-driven", test: (i) => i.ai_score >= 0.7 },
  { id: "done", label: "Resolved / allowed", test: (i) => ["resolved", "allowed", "unblocked"].includes(i.status) },
];

export default function Alerts() {
  const { data, error } = usePoll("/incidents", 2500);
  const [tab, setTab] = useState("all");
  const list = data || [];
  const shown = list.filter(TABS.find((t) => t.id === tab).test);
  if (error && !data) return <Banner tone="danger">Could not load alerts: {error}. This is NOT the same as "no alerts".</Banner>;
  if (!data) return <div className="card h-64 animate-pulse" />;
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap gap-2">
        {TABS.map((t) => {
          const n = list.filter(t.test).length;
          return (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`chip px-3.5 py-1.5 text-sm ${tab === t.id ? "border-ink bg-ink text-white" : "border-line bg-white text-ink-500 hover:text-ink"}`}>
              {t.label} <span className={tab === t.id ? "text-brand-100" : "text-ink-400"}>{n}</span>
            </button>
          );
        })}
      </div>
      {error && <Banner tone="danger">Showing the last loaded list. Refresh failed: {error}</Banner>}
      <div className="card p-4">
        {shown.length ? (
          <div className="space-y-2.5">{shown.map((i) => <IncidentRow key={i.id} inc={i} />)}</div>
        ) : (
          <Empty icon={ShieldAlert} title={list.length ? "Nothing in this group" : "No alerts yet"}
            text={list.length ? "Try another tab above." : "Alerts appear here as soon as Rakshak finds an attack."}
          />
        )}
      </div>
    </div>
  );
}
