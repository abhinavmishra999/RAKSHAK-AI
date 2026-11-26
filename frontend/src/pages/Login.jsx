import { useEffect, useState } from "react";
import {
  Activity, Eye, KeyRound, Loader2, LogIn, ShieldCheck, TerminalSquare, WifiOff,
} from "lucide-react";
import { api } from "../api";
import { Logo } from "../components/Layout";
import { Banner } from "../components/ui";

const FEATURES = [
  { icon: WifiOff, t: "Works fully offline", d: "Installed as a service on your own server. No cloud, no telemetry, nothing leaves the machine." },
  { icon: Eye, t: "System + web defence, one agent", d: "Watches the machine itself - critical files, accounts, listening ports - plus your web, SSH and application logs; flags attacks by signature and behaviour." },
  { icon: ShieldCheck, t: "Answers only what it can prove", d: "Nothing is called Confirmed until a second, independent re-check agrees. Blind means blind, never \u201csafe\u201d." },
  { icon: Activity, t: "Responds with you", d: "Proposes containment, a human approves, the firewall verifies it, every step expires and is remembered in Memory." },
];

export default function Login({ onSignedIn }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [hasUsers, setHasUsers] = useState(null);
  useEffect(() => { api("/auth/state").then((s) => setHasUsers(s.has_users)).catch(() => setHasUsers(null)); }, []);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      onSignedIn(await api("/auth/login", { method: "POST", body: { username, password } }));
    } catch (ex) {
      setErr(ex.message);
    }
    setBusy(false);
  };

  return (
    <div className="grid min-h-full lg:grid-cols-2">
      {/* Hero panel - who we are, what we do. Static product facts, no live security data. */}
      <div className="relative hidden flex-col justify-between overflow-hidden bg-ink px-12 py-10 lg:flex">
        <svg className="pointer-events-none absolute inset-0 h-full w-full opacity-[0.07]" aria-hidden>
          <defs>
            <pattern id="rk-grid" width="34" height="34" patternUnits="userSpaceOnUse">
              <path d="M34 0H0v34" fill="none" stroke="#fff" strokeWidth="1" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#rk-grid)" />
        </svg>
        <svg className="pointer-events-none absolute -right-40 -top-40 h-[560px] w-[560px] rounded-full bg-brand/10 blur-3xl" aria-hidden />
        <div className="relative">
          <Logo dark />
          <p className="mt-1 text-xs text-slate-400">Offline security console</p>
        </div>
        <div className="relative max-w-[480px]">
          <p className="mb-3 w-fit rounded-full border border-brand/40 bg-brand/10 px-3 py-1 text-[11px] font-bold uppercase tracking-widest text-brand">
            Security agent for your own servers
          </p>
          <h1 className="text-[34px] font-bold leading-[1.15] text-white">
            Detects attacks in real time.
            <span className="block text-brand">Responds only with you.</span>
          </h1>
          <p className="mt-4 text-sm leading-6 text-slate-300">
            Rakshak installs on the server it protects, watches that machine end to end - its files, accounts, open ports and logs -
            and shows your team what is happening - in plain words, with the exact evidence behind every claim.
            It was built for people who are new to security operations, not only for analysts.
          </p>
          <div className="mt-7 space-y-4">
            {FEATURES.map(({ icon: Icon, t, d }) => (
              <div key={t} className="flex gap-3.5">
                <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-white/10 text-brand"><Icon size={17} /></span>
                <div>
                  <p className="text-sm font-bold text-white">{t}</p>
                  <p className="text-[13px] leading-5 text-slate-400">{d}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
        <p className="relative text-xs text-slate-500">
          Runs on Linux (and WSL2 on Windows) as a system service. Serves the console on this machine only.
          Accounts, evidence and Memory stay in this server's data folder.
        </p>
      </div>

      {/* Sign-in panel */}
      <div className="flex items-center justify-center bg-canvas px-4 py-10">
        <div className="w-full max-w-[400px]">
          <div className="mb-7 flex justify-center lg:hidden"><Logo /></div>
          <div className="mb-7">
            <h2 className="text-2xl font-bold tracking-tight">Sign in</h2>
            <p className="mt-1.5 text-sm text-ink-500">The console lives on this computer. Your account is stored locally, never in the cloud.</p>
          </div>
          {hasUsers === false && (
            <div className="mb-5">
              <Banner tone="warn" icon={TerminalSquare}>
                No accounts exist yet. On the server, run
                <code className="mono mt-1 block rounded bg-white px-2 py-1 text-xs">python -m rakshak.admin your-name --role admin</code>
                then come back here. There is no default password.
              </Banner>
            </div>
          )}
          <form onSubmit={submit} className="card space-y-4 p-7">
            <label className="block">
              <span className="label">Username</span>
              <input className="mt-1 w-full rounded-xl border border-line bg-white px-3 py-2.5 text-sm" autoComplete="username"
                value={username} onChange={(e) => setUsername(e.target.value)} required maxLength={40} />
            </label>
            <label className="block">
              <span className="label">Password</span>
              <input type="password" className="mt-1 w-full rounded-xl border border-line bg-white px-3 py-2.5 text-sm"
                autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required maxLength={256} />
            </label>
            {err && <p className="text-sm font-medium text-danger">{err}</p>}
            <button className="btn-primary w-full" disabled={busy || !username || !password}>
              {busy ? <Loader2 size={16} className="animate-spin" /> : <LogIn size={16} />} Sign in
            </button>
            <p className="flex items-start gap-1.5 text-xs leading-5 text-ink-400"><KeyRound size={13} className="mt-0.5 shrink-0" />
              Sessions end after one hour. Five wrong passwords pause sign-in for 5 minutes. Every attempt is written to the signed activity log.</p>
          </form>
        </div>
      </div>
    </div>
  );
}
