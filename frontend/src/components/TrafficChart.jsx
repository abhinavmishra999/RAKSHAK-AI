import { useState } from "react";

/** Requests per second over the last N seconds. Teal = normal, red = flagged as attack. */
export default function TrafficChart({ series = [], height = 170 }) {
  const [hover, setHover] = useState(null);
  const W = 1000, H = height, padL = 34, padB = 22, padT = 8;
  const max = Math.max(5, ...series.map((d) => d.total));
  const nice = Math.ceil(max / 5) * 5;
  const bw = (W - padL) / Math.max(series.length, 1);
  const y = (v) => H - padB - (v / nice) * (H - padB - padT);
  const ticks = [0, nice / 2, nice];
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" onMouseLeave={() => setHover(null)}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={padL} x2={W} y1={y(t)} y2={y(t)} stroke="#E2E8F0" strokeDasharray={t ? "3 4" : ""} />
            <text x={padL - 8} y={y(t) + 4} textAnchor="end" fontSize="11" fill="#64748B">{t}</text>
          </g>
        ))}
        {series.map((d, i) => {
          const x = padL + i * bw;
          const normal = d.total - d.attack;
          return (
            <g key={d.t} onMouseEnter={() => setHover({ i, d })}>
              <rect x={x} y={padT} width={bw} height={H - padB - padT} fill="transparent" />
              {normal > 0 && <rect x={x + 1} y={y(d.total)} width={Math.max(bw - 2, 1)} height={y(0) - y(normal)} rx="1.5" fill="#00A3AE" opacity=".75" />}
              {d.attack > 0 && <rect x={x + 1} y={y(d.attack)} width={Math.max(bw - 2, 1)} height={y(0) - y(d.attack)} rx="1.5" fill="#C62828" />}
            </g>
          );
        })}
        {[0, 0.5, 1].map((f) => {
          const i = Math.min(series.length - 1, Math.round(f * (series.length - 1)));
          const secs = series.length - 1 - i;
          return series.length ? (
            <text key={f} x={padL + i * bw + bw / 2} y={H - 5} fontSize="11" fill="#64748B"
              textAnchor={f === 0 ? "start" : f === 1 ? "end" : "middle"}>{secs ? `${secs} s ago` : "now"}</text>
          ) : null;
        })}
      </svg>
      {hover && (
        <div className="pointer-events-none absolute top-0 rounded-lg bg-ink px-2.5 py-1.5 text-xs text-white shadow"
          style={{ left: `${Math.min(85, ((padL + hover.i * bw) / W) * 100)}%` }}>
          {new Date(hover.d.t * 1000).toLocaleTimeString()} · {hover.d.total} requests
          {hover.d.attack > 0 && <span className="text-red-300"> · {hover.d.attack} attack</span>}
        </div>
      )}
    </div>
  );
}
