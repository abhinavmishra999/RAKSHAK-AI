import { Link } from "react-router-dom";
import { Activity, ArrowRight, Bot, BookOpen, Clock, Copy, FlaskConical, KeyRound, Lock, Radar, Repeat2,
         ShieldCheck, Undo2, Users, Zap } from "lucide-react";
import { SectionTitle } from "../components/ui";

const READ = [
  { n: 1, title: "Look at the colour and title", text: "Red = high risk, amber = medium, blue = low. The title says in plain words what the attacker tried." },
  { n: 2, title: "Check the status", text: "'Blocked at firewall' means the firewall confirmed it. 'Block recorded, not enforced' means traffic is NOT stopped yet. 'Waiting for your OK' means you need to decide." },
  { n: 3, title: "Read the four boxes", text: "What happened, why it matters, what Rakshak did, what you should do. That's all most people need." },
  { n: 4, title: "Decide and report", text: "Approve or undo the block, then download the PDF report. In India it is due within 6 hours." },
];

const SIGNALS = [
  { icon: Zap, title: "Machine speed", text: "More than ~5 requests per second for a long time. People click about once a second." },
  { icon: Clock, title: "Perfectly even timing", text: "Scripts fire at regular intervals. Humans pause, read and type at uneven speeds." },
  { icon: Copy, title: "Many rewritten variants", text: "Dozens of different-but-similar attack strings. AI tools rewrite attacks to slip past filters." },
  { icon: Repeat2, title: "Keeps going after a block", text: "A person gives up or pauses when blocked. A bot keeps retrying at the same pace." },
  { icon: Users, title: "Switching identities", text: "One source pretending to be several different browsers to hide." },
];

const TERMS = [
  { t: "SQL injection", d: "Typing database commands into a website form, hoping the site runs them. Can leak or delete all records." },
  { t: "XSS (cross-site scripting)", d: "Planting a malicious script on a website so it runs in other visitors' browsers and steals their logins." },
  { t: "Brute force / password guessing", d: "Trying many passwords quickly until one works. Strong passwords and login limits stop it." },
  { t: "Scanning / reconnaissance", d: "Asking for many hidden pages to map a website and find weak spots. Usually the first step of an attack." },
  { t: "AI-driven attack", d: "An attack run by an automated agent, often using AI to rewrite payloads. Fast, tireless, and keeps changing." },
  { t: "Incident (alert)", d: "A group of suspicious events from the same source, treated as one attack." },
  { t: "Blocking", d: "Refusing all traffic from an address. Rakshak only calls it blocked when a connected firewall confirms it; otherwise it is only 'recorded'. Every block expires." },
  { t: "Scope", d: "The written list of systems your organisation owns and allows Rakshak to test (scope.yml). Anything else is refused, and attacker addresses are never tested." },
  { t: "Confirmed finding", d: "A problem a tool reported AND Rakshak reproduced with its own separate re-check." },
  { t: "Suspected / Not reproduced", d: "Suspected: reported but not re-checked. Not reproduced: Rakshak's re-check did not see it, so it is not counted." },
  { t: "Could not check", d: "The test could not finish (error, timeout, no answer). This is never treated as a pass." },
  { t: "Plugin (tool)", d: "An outside program such as Nmap, connected through a plugin.yml description. It is off until an admin reviews it, and its file fingerprint is pinned." },
  { t: "False alarm", d: "When something normal is flagged by mistake. Close it as a false alarm, or undo the block, and Rakshak will not block that source again for this alert." },
  { t: "Anomaly", d: "Behaviour that's very different from the normal traffic Rakshak learned, even if no known rule matches." },
  { t: "MITRE ATT&CK", d: "A free, worldwide catalogue of attacker techniques. Each alert shows its ID (e.g. T1190) so experts speak the same language." },
  { t: "CERT-In 6-hour rule", d: "India's cyber agency requires organisations to report cyber incidents within 6 hours and keep logs for 180 days." },
  { t: "Offline / air-gapped", d: "Working with no internet connection. Rakshak runs fully on this computer, so no data leaves it." },
];

const FAQ = [
  { q: "Does Rakshak need the internet?", a: "No. Detection, explanations, tests and reports all run on this server. New rules and tools can be copied in offline (for example from a reviewed USB update)." },
  { q: "What if it blocks a real person?", a: "Go to Protection or the alert and click Undo. If a firewall is connected, Rakshak removes the rule and checks it is gone; it won't re-block that person for the same alert." },
  { q: "Is the 'AI-driven' score certain?", a: "No. It's a rule-of-thumb score from behaviour, capped at 95%, not a probability. Its accuracy on real traffic has not been measured yet. Read the reasons listed under it." },
  { q: "Can I use it on my real website?", a: "Start in 'Ask me first' mode. Point RAKSHAK_LOGS at your nginx/Apache access log ('combined' format) or Linux auth.log, and run it beside your existing controls while you check its alerts. It is not yet a replacement for a tested commercial product." },
];

export default function Learn() {
  return (
    <div className="space-y-6">
      <div className="card flex flex-wrap items-center gap-5 bg-gradient-to-r from-brand-50 to-white p-6">
        <span className="grid h-12 w-12 place-items-center rounded-2xl bg-brand-700 text-white"><BookOpen size={24} /></span>
        <div className="flex-1">
          <h2 className="text-xl font-bold">You don't need to be a security expert</h2>
          <p className="text-ink-500">Rakshak explains every alert in plain words so any operator can understand it.</p>
        </div>
      </div>

      <div className="card p-6">
        <SectionTitle title="How to read an alert in 30 seconds" />
        <ol className="grid gap-3 md:grid-cols-4">
          {READ.map((r) => (
            <li key={r.n} className="rounded-xl border border-line p-4">
              <span className="grid h-8 w-8 place-items-center rounded-full bg-ink text-sm font-bold text-white">{r.n}</span>
              <p className="mt-3 font-semibold">{r.title}</p>
              <p className="mt-1 text-sm text-ink-500">{r.text}</p>
            </li>
          ))}
        </ol>
      </div>

      <div className="card p-6">
        <SectionTitle title="How Rakshak spots an AI-driven attack"
          sub="It doesn't read the attacker's mind. It measures behaviour. Each signal below adds to the score." />
        <div className="grid gap-3 md:grid-cols-5">
          {SIGNALS.map((s) => (
            <div key={s.title} className="rounded-xl bg-canvas p-4">
              <s.icon size={20} className="text-brand-700" />
              <p className="mt-2 font-semibold">{s.title}</p>
              <p className="mt-1 text-sm text-ink-500">{s.text}</p>
            </div>
          ))}
        </div>
        <p className="mt-4 flex items-center gap-2 text-sm text-ink-500"><Bot size={16} className="text-danger" />
          70% or more = "Likely AI / automated bot"; 40-69% = "Possibly automated"; below 40% = "Likely a person".</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="card p-6 lg:col-span-2">
          <SectionTitle title="Words you'll see" />
          <dl className="grid gap-3 md:grid-cols-2">
            {TERMS.map((t) => (
              <div key={t.t} className="rounded-xl border border-line p-4">
                <dt className="font-semibold">{t.t}</dt>
                <dd className="mt-1 text-sm text-ink-500">{t.d}</dd>
              </div>
            ))}
          </dl>
        </div>
        <div className="card p-6">
          <SectionTitle title="Common questions" />
          <div className="space-y-4">
            {FAQ.map((f) => (
              <div key={f.q}><p className="font-semibold">{f.q}</p><p className="mt-1 text-sm text-ink-500">{f.a}</p></div>
            ))}
          </div>
          <div className="mt-6 space-y-2 rounded-xl bg-canvas p-4 text-sm">
            <p className="font-semibold">Where to go next</p>
            {[["/check", "Check a website", Radar], ["/protection", "Choose a protection mode", Lock]].map(([to, l, I]) => (
              <Link key={to} to={to} className="flex items-center gap-2 text-brand-700 hover:underline"><I size={15} />{l}<ArrowRight size={14} /></Link>))}
          </div>
        </div>
      </div>
    </div>
  );
}
