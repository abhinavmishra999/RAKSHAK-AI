import { createContext, useContext } from "react";
import { NavLink, Link, useLocation } from "react-router-dom";
import { Compass, GraduationCap, History, LayoutDashboard, ListChecks, Lock, LogOut, Radar, ShieldAlert, WifiOff } from "lucide-react";
import { api, usePoll } from "../api";

const OverviewCtx = createContext(null);
export const useOverview = () => useContext(OverviewCtx);

export const PAGES = [
  { to: "/", icon: LayoutDashboard, label: "Home", hint: "What needs attention?",
    title: "Home", desc: "What Rakshak can see right now, and anything that needs you." },
  { to: "/alerts", icon: ShieldAlert, label: "Alerts", hint: "What happened",
    title: "Alerts", desc: "Suspicious activity found in your logs, explained in plain words." },
  { to: "/tests", icon: Radar, label: "Security tests", hint: "Check your own systems",
    title: "Security tests", desc: "Run approved tools against assets your organisation owns. Every finding is re-checked." },
  { to: "/protection", icon: Lock, label: "Protection", hint: "What's blocked",
    title: "Protection", desc: "Choose how Rakshak responds, and see or undo every block." },
  { to: "/memory", icon: History, label: "Memory", hint: "Everything done so far",
    title: "Memory", desc: "The timeline of every threat detected, response taken and test run - built from the signed records." },
  { to: "/activity", icon: ListChecks, label: "Activity log", hint: "Who did what",
    title: "Activity log", desc: "A signed record of every login, approval, test and block." },
  { to: "/guide", icon: Compass, label: "Guide", hint: "How to use Rakshak",
    title: "Guide", desc: "Setup, every option, the principles, and exactly how detection works - start here on your first day." },
  { to: "/learn", icon: GraduationCap, label: "Learn", hint: "Security in plain words",
    title: "Learn", desc: "New to security? Every term used in Rakshak, explained simply." },
];

export function Logo({ dark }) {
  return (
    <Link to="/" className="flex items-center gap-2.5">
      <svg width="34" height="34" viewBox="0 0 34 34" aria-hidden>
        <path d="M17 2.5 29 7v9.2c0 7.3-5 13.4-12 15.3C10 29.6 5 23.5 5 16.2V7z" fill="#00A3AE" />
        <path d="M17 7.5 24.5 10.3v6c0 4.7-3.1 8.6-7.5 10-4.4-1.4-7.5-5.3-7.5-10v-6z" fill={dark ? "#0F2344" : "#fff"} />
        <path d="m13 17 3 3 5.5-6" stroke="#00A3AE" strokeWidth="2.6" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <span className={`text-[17px] font-bold tracking-tight ${dark ? "text-white" : "text-ink"}`}>
        RAKSHAK<span className="text-brand">·AI</span>
      </span>
    </Link>
  );
}

function Sidebar({ ov, user, onSignOut }) {
  const waiting = ov ? ov.awaiting : 0;
  const tests = ov ? ov.tests_waiting : 0;
  const readable = ov?.sources?.filter((s) => s.readable).length ?? 0;
  const signOut = async () => { try { await api("/auth/logout", { method: "POST" }); } catch { /* already signed out */ } onSignOut(); };
  return (
    <aside className="fixed inset-y-0 left-0 z-20 flex w-64 flex-col bg-ink px-4 py-5">
      <div className="px-2"><Logo dark /></div>
      <p className="mt-1 px-2 text-xs text-slate-400">Offline security console</p>
      <nav className="mt-7 flex flex-col gap-1">
        {PAGES.map(({ to, icon: Icon, label, hint }) => (
          <NavLink key={to} to={to} end={to === "/"}
            className={({ isActive }) => `group flex items-center gap-3 rounded-xl px-3 py-2.5 transition-colors ${
              isActive ? "bg-white/10 text-white" : "text-slate-300 hover:bg-white/5 hover:text-white"}`}>
            {({ isActive }) => (
              <>
                <Icon size={19} className={isActive ? "text-brand" : "text-slate-400 group-hover:text-slate-200"} />
                <span className="flex-1">
                  <span className="block text-sm font-semibold">{label}</span>
                  <span className="block text-[11px] text-slate-400">{hint}</span>
                </span>
                {to === "/alerts" && waiting > 0 && (
                  <span className="rounded-full bg-warn px-2 py-0.5 text-[11px] font-bold text-white">{waiting}</span>)}
                {to === "/tests" && tests > 0 && (
                  <span className="rounded-full bg-warn px-2 py-0.5 text-[11px] font-bold text-white">{tests}</span>)}
              </>
            )}
          </NavLink>
        ))}
      </nav>
      <div className="mt-auto space-y-3">
        <div className="space-y-2 rounded-xl bg-white/5 p-3 text-xs">
          <div className="flex items-center gap-2 text-slate-200"><WifiOff size={14} className="text-brand" /> Runs offline</div>
          <p className="text-slate-400">No cloud services. Data stays in this server's data folder.</p>
          <div className="flex items-center gap-2 pt-1 text-slate-300">
            <span className={`h-2 w-2 rounded-full ${ov?.engine_alive && readable ? "bg-emerald-400" : "bg-red-400"}`} />
            {!ov ? "Connecting..." : !ov.engine_alive ? "Engine stopped" : readable ? `Reading ${readable} log source(s)` : "No readable log source"}
          </div>
        </div>
        <div className="flex items-center gap-3 rounded-xl bg-white/5 p-3 text-xs text-slate-300">
          <span className="grid h-8 w-8 place-items-center rounded-full bg-brand-700 text-sm font-bold uppercase text-white">{user.username[0]}</span>
          <span className="flex-1 truncate"><span className="block font-semibold text-white">{user.username}</span>{user.role}</span>
          <button onClick={signOut} title="Sign out" aria-label="Sign out" className="rounded-lg p-1.5 hover:bg-white/10"><LogOut size={16} /></button>
        </div>
      </div>
    </aside>
  );
}

function Topbar({ ov, updatedAt, error }) {
  const { pathname } = useLocation();
  const page = PAGES.find((p) => (p.to === "/" ? pathname === "/" : pathname.startsWith(p.to))) || PAGES[0];
  const auto = ov?.mode === "auto";
  const fresh = updatedAt && Date.now() - updatedAt < 8000 && !error;
  return (
    <header className="sticky top-0 z-10 flex items-center justify-between gap-6 border-b border-line bg-canvas/90 px-8 py-4 backdrop-blur">
      <div>
        <h1 className="text-xl font-bold tracking-tight">{page.title}</h1>
        <p className="text-sm text-ink-500">{page.desc}</p>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        {ov && (
          <Link to="/protection" title="Change how Rakshak responds"
            className={`chip px-3 py-1.5 text-[13px] ${auto ? "border-brand-100 bg-brand-50 text-brand-700"
              : "border-line bg-white text-ink-500"}`}>
            <Lock size={13} /> {auto ? "Auto-block ON" : "Ask me first"}
            {ov.enforcer && !ov.enforcer.ready && <span className="text-warn">· not enforced</span>}
          </Link>
        )}
        <span className="flex items-center gap-2 text-xs font-medium text-ink-500">
          <span className={`inline-flex h-2.5 w-2.5 rounded-full ${fresh ? "bg-emerald-500" : "bg-slate-400"}`} />
          {fresh ? "Live" : error ? "Can't reach engine" : "Connecting"}
        </span>
      </div>
    </header>
  );
}

export default function Layout({ children, user, onSignOut }) {
  const { data: ov, updatedAt, error, reload } = usePoll("/overview", 3000);
  return (
    <OverviewCtx.Provider value={{ ov, reload, user }}>
      <Sidebar ov={ov} user={user} onSignOut={onSignOut} />
      <div className="pl-64">
        <Topbar ov={ov} updatedAt={updatedAt} error={error} />
        <main className="mx-auto max-w-[1240px] px-8 py-7">{children}</main>
      </div>
    </OverviewCtx.Provider>
  );
}
