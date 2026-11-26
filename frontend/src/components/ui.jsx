import { useState } from "react";
import { Bot, HelpCircle, User } from "lucide-react";
import { SEVERITY, STATUS, VALIDATION, aiTone } from "../api";

const TONES = {
  safe: "bg-safe-bg text-safe border-safe-line",
  warn: "bg-warn-bg text-warn border-warn-line",
  danger: "bg-danger-bg text-danger border-danger-line",
  info: "bg-info-bg text-info border-info-line",
  brand: "bg-brand-50 text-brand-700 border-brand-100",
  muted: "bg-slate-100 text-ink-500 border-slate-200",
};

export function Chip({ tone = "muted", children, icon: Icon, title }) {
  return (
    <span className={`chip ${TONES[tone]}`} title={title}>
      {Icon && <Icon size={12} strokeWidth={2.5} />}
      {children}
    </span>
  );
}

export const SeverityChip = ({ level }) => {
  const s = SEVERITY[level] || SEVERITY.low;
  return <Chip tone={s.tone} title={s.help}>{s.text} risk</Chip>;
};

export const StatusChip = ({ status }) => {
  const s = STATUS[status] || { text: status, tone: "muted" };
  return <Chip tone={s.tone}>{s.text}</Chip>;
};

export const ValidationChip = ({ value }) => {
  const v = VALIDATION[value] || VALIDATION.pending;
  return <Chip tone={v.tone} title={v.help}>{v.text}</Chip>;
};

export const AiChip = ({ score, label }) => (
  <Chip tone={aiTone(score)} icon={score >= 0.4 ? Bot : User} title="Rule-of-thumb score from behaviour, not proof and not a probability">
    {label} · {Math.round(score * 100)}%
  </Chip>
);

/** A small "?" that explains a term in plain words. Works on hover and on tap. */
export function InfoTip({ text, wide }) {
  const [open, setOpen] = useState(false);
  return (
    <span className="relative inline-flex align-middle"
      onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)}>
      <button type="button" aria-label="What does this mean?" onClick={() => setOpen((o) => !o)}
        className="text-ink-400 hover:text-brand-700">
        <HelpCircle size={15} />
      </button>
      {open && (
        <span className={`absolute left-1/2 top-6 z-30 -translate-x-1/2 rounded-xl bg-ink px-3 py-2 text-xs font-normal
          normal-case leading-relaxed tracking-normal text-white shadow-lg animate-fadeUp ${wide ? "w-80" : "w-60"}`}>
          {text}
        </span>
      )}
    </span>
  );
}

export function StatCard({ icon: Icon, label, value, hint, tone = "brand", sub }) {
  const ring = { brand: "bg-brand-50 text-brand-700", danger: "bg-danger-bg text-danger",
                 safe: "bg-safe-bg text-safe", warn: "bg-warn-bg text-warn", info: "bg-info-bg text-info" }[tone];
  return (
    <div className="card p-5">
      <div className="flex items-center gap-2 text-sm font-medium text-ink-500">
        <span className={`grid h-8 w-8 place-items-center rounded-lg ${ring}`}><Icon size={17} /></span>
        {label}
        {hint && <InfoTip text={hint} />}
      </div>
      <div className="mt-3 text-3xl font-bold tracking-tight">{value}</div>
      {sub && <div className="mt-1 text-xs text-ink-400">{sub}</div>}
    </div>
  );
}

export function SectionTitle({ title, hint, right, sub }) {
  return (
    <div className="mb-4 flex items-end justify-between gap-4">
      <div>
        <h2 className="flex items-center gap-2 text-lg font-bold">{title}{hint && <InfoTip text={hint} wide />}</h2>
        {sub && <p className="mt-0.5 text-sm text-ink-500">{sub}</p>}
      </div>
      {right}
    </div>
  );
}

export function Empty({ icon: Icon, title, text, action }) {
  return (
    <div className="flex flex-col items-center px-6 py-14 text-center">
      <span className="grid h-14 w-14 place-items-center rounded-2xl bg-brand-50 text-brand-700"><Icon size={26} /></span>
      <p className="mt-4 text-base font-semibold">{title}</p>
      {text && <p className="mt-1 max-w-md text-sm text-ink-500">{text}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function Banner({ tone = "info", icon: Icon, children }) {
  return (
    <div className={`flex items-start gap-3 rounded-xl border px-4 py-3 text-sm ${TONES[tone]}`}>
      {Icon && <Icon size={18} className="mt-0.5 shrink-0" />}
      <div className="text-ink">{children}</div>
    </div>
  );
}
