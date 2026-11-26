import { useState } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle, BookOpen, CheckCircle2, Compass, Cpu, EyeOff, Fingerprint, Lock, Radio,
  RotateCcw, ScrollText, SearchCode, ShieldCheck, Workflow,
} from "lucide-react";
import { SectionTitle } from "../components/ui";

const SECTIONS = [
  { id: "start", icon: Compass, title: "Start here" },
  { id: "setup", icon: Workflow, title: "Setting it up (first time)" },
  { id: "options", icon: BookOpen, title: "Every option explained" },
  { id: "principles", icon: ShieldCheck, title: "The principles it follows" },
  { id: "detect", icon: SearchCode, title: "How it detects" },
  { id: "validate", icon: CheckCircle2, title: "Why you can trust a result" },
  { id: "tests", icon: Radio, title: "Security tests and your own tools" },
  { id: "respond", icon: Lock, title: "How responses and blocks work" },
  { id: "limits", icon: AlertTriangle, title: "What it cannot do (read this)" },
];

const Card = ({ children, className = "" }) => <div className={`card p-5 md:p-6 ${className}`}>{children}</div>;
const H = ({ children }) => <h3 className="mb-1.5 font-bold text-ink">{children}</h3>;
const P = ({ children }) => <p className="text-sm leading-6 text-ink-500">{children}</p>;
const Li = ({ n, children }) => (
  <li className="flex gap-3">
    <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-brand-50 text-xs font-bold text-brand-700">{n}</span>
    <span className="text-sm leading-6 text-ink-500">{children}</span>
  </li>
);
const Code = ({ children }) => <code className="rounded bg-ink/5 px-1.5 py-0.5 text-[12.5px] text-ink">{children}</code>;

export default function Guide() {
  const [open, setOpen] = useState("start");
  const go = (id) => {
    setOpen(id);
    document.getElementById(`guide-${id}`)?.scrollIntoView({ behavior: "smooth", block: "start" });
  };
  return (
    <div className="grid gap-6 lg:grid-cols-[220px_1fr]">
      <nav className="card sticky top-4 hidden h-fit p-3 lg:block">
        <p className="px-2 pb-2 pt-1 text-xs font-bold uppercase tracking-wide text-ink-400">Guide contents</p>
        {SECTIONS.map(({ id, icon: Icon, title }) => (
          <button key={id} onClick={() => go(id)}
            className={`flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-[13px] ${open === id ? "bg-brand-50 font-semibold text-brand-700" : "text-ink-500 hover:bg-ink/5"}`}>
            <Icon size={15} /> {title}
          </button>
        ))}
      </nav>
      <div className="space-y-6">
        <div className="card p-6">
          <div className="flex items-center gap-3">
            <span className="grid h-11 w-11 place-items-center rounded-xl bg-brand-50 text-brand-700"><BookOpen size={22} /></span>
            <div>
              <h2 className="text-lg font-bold">The complete guide to Rakshak</h2>
              <p className="text-sm text-ink-500">How to use every option, what the tool promises, and exactly how it decides things.</p>
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-2 lg:hidden">
            {SECTIONS.map(({ id, icon: Icon, title }) => (
              <button key={id} onClick={() => go(id)} className="chip px-3 py-1.5 text-xs border-line bg-white text-ink-500">
                <Icon size={13} className="mr-1 inline" />{title}
              </button>
            ))}
          </div>
        </div>

        <div id="guide-start" className="scroll-mt-4 space-y-3">
          <SectionTitle title="Start here" hint="Rakshak is an offline security console for the whole system: it watches this machine itself (its files, accounts and open ports), reads your own server logs, runs approved tests against your own systems, and helps a human respond. It never sends data anywhere - no cloud, no internet needed at runtime." />
          <Card>
            <H>Three jobs, nothing else</H>
            <ol className="space-y-3">
              <Li n="1"><b className="text-ink">Watch.</b> Two kinds of watch: the machine itself (critical files, accounts, listening ports - compared against a signed baseline every scan) and the log files you point it at, read the moment they are written. Activity that matches attack signatures, behaviour limits or a system change raises an alert. If it cannot read any log, the dashboard says <b className="text-ink">Rakshak is blind</b> - it never claims safety without sight.</Li>
              <Li n="2"><b className="text-ink">Check.</b> Only against assets you put in scope (<Code>data/scope.yml</Code>), only with tools an admin enabled, and only after someone approves each run. Every finding is re-checked independently before it is called Confirmed.</Li>
              <Li n="3"><b className="text-ink">Respond - with you.</b> By default (Ask me first) nothing is blocked until an analyst or admin approves it. Blocks expire, can be undone, and protected addresses can never be blocked.</Li>
            </ol>
          </Card>
        </div>

        <div id="guide-setup" className="scroll-mt-4 space-y-3">
          <SectionTitle title="Setting it up (first time)" hint="All commands run on your own Linux server. Windows is not supported; use Linux or WSL2." />
          <Card>
            <ol className="space-y-3">
              <Li n="1">Copy the folder to the server, then run <Code>./run.sh</Code> once. It creates a private <Code>data/</Code> folder, asks you to set the first admin password (14+ characters), and starts the console.</Li>
              <Li n="2">Open <Code>http://127.0.0.1:8000</Code> in a browser on that same server (that is deliberate: the console binds to localhost so nobody remote can reach it).</Li>
              <Li n="3">Sign in and go to <b className="text-ink">Security tests</b> → the scope card. Edit <Code>data/scope.yml</Code> so <Code>networks</Code> lists only the ranges your organisation owns, and put anything fragile (printers, SCADA, legacy) in <Code>never_scan</Code>. Tests outside scope are refused automatically.</Li>
              <Li n="4">Point <Code>RAKSHAK_LOGS</Code> at your real logs: web server access logs, and the OpenSSH auth log if you want password-guessing detection. The Home page shows each source as readable or not - fix what shows red.</Li>
              <Li n="5">System sensors run by default: this machine's critical files, accounts and listening ports are baselined on first start and re-scanned every 30 s (<Code>RAKSHAK_HOSTSEC_INTERVAL</Code>, 0 turns them off; <Code>RAKSHAK_FIM_PATHS</Code> adds files to watch). The first scan only records the baseline - so start from a known-good machine; a compromise that happened <i>before</i> installing looks like a normal starting point.</Li>
              <Li n="6">Optional, for blocking: have your firewall team create the chain <Code>RAKSHAK-BLOCK</Code>, install <Code>deploy/rakshak-fw</Code>, and add the sudoers line from <b className="text-ink">README.md</b>. The Protection page will then say "Connected to the firewall", and every block gets verified at the firewall before being counted.</Li>
              <Li n="7">Read a few real alerts with your team for 2-4 weeks in Ask me first mode before you ever consider Auto-block. See "What it cannot do" at the end of this guide before rolling out widely.</Li>
            </ol>
          </Card>
        </div>

        <Card className="space-y-3">
            <H><Radio size={15} className="mr-1.5 inline text-brand-700" />Watching several machines, still offline</H>
            <P>One console can act as the hub for the rest of your network. On each other machine run the tiny sensor agent (<Code>python -m rakshak.sensor --hub HUB_URL --name web01</Code>, secret from <Code>python -m rakshak.admin sensor-secret</Code>): it tails that machine's own logs and ships batches over your LAN. Every batch is HMAC-signed, timestamp-checked and sequence-numbered, so a forged, delayed or replayed batch is refused at the door; alerts then show which machine they came from. The sensor only observes - all responses stay on the hub, under the same approval rules. Home shows how many sensors are reporting.</P>
            <P><b className="text-ink">Settings and sign-ins survive restarts.</b> A <Code>rakshak.conf</Code> file next to the program (KEY=VALUE, one per line) keeps your configuration across boots - environment variables still win over it when both are set. And signed-in sessions are stored in the database, so restarting the console no longer signs everyone out; logging out still kills the session everywhere.</P>
          </Card>
        <div id="guide-options" className="scroll-mt-4 space-y-3">
          <SectionTitle title="Every option explained" hint="What each menu item is for and how to read it." />
          <div className="grid gap-4 md:grid-cols-2">
            <Card><H><Link to="/" className="underline decoration-brand/40">Home</Link></H>
              <P>The one-glance state: live alerts, what is blocked right now, tests waiting for approval, and whether Rakshak can actually see your logs. The six-step strip shows what happened to your traffic in this window. Anything needing a decision is counted at the top.</P></Card>
            <Card><H><Link to="/alerts" className="underline decoration-brand/40">Alerts</Link></H>
              <P>Detected threats, newest first - attacks from the network and changes on this machine (file integrity, accounts, listening ports). Open one to see the exact log lines or before/after fingerprints, a plain-English explanation, how confident the behaviour estimate is, and every response taken. "Re-check evidence" re-runs the rules on the stored lines (or looks at the live system again, for system alerts); for changes on this machine you can also propose their undo (restore file / stop process / lock account), approve a colleague's proposal, or accept the change as sanctioned. You can resolve an alert or prepare a draft report.</P></Card>
            <Card><H><Link to="/tests" className="underline decoration-brand/40">Security tests</Link></H>
              <P>The four-step flow: pick an enabled tool → check the scope card → request a run against one of your own assets with the authorisation ticked → a second person approves. Results show each finding as Confirmed, Not reproduced, Could not check or Looked fine, with the re-check evidence.</P></Card>
            <Card><H><Link to="/protection" className="underline decoration-brand/40">Protection</Link></H>
              <P>Choose Ask me first or Auto-block (admin only). See everyone blocked right now and when each block expires, undo any block, read every past response with who approved it, and export your current rules so the firewall team can review them. Protected addresses (never-block and your Trusted IPs) can never be blocked.</P></Card>
            <Card><H><Link to="/memory" className="underline decoration-brand/40">Memory</Link></H>
              <P>Everything done so far in one timeline: detected threats, every response (block, refusal, undo, expiry) and every security test, newest first, filterable by type, time range or search. It is rebuilt live from the signed records, so it always agrees with the evidence pages.</P></Card>
            <Card><H><Link to="/activity" className="underline decoration-brand/40">Activity log</Link></H>
              <P>The who-did-what trail for analysts and admins: sign-ins, approvals, enabler decisions, reports - each entry fingerprinted to the one before. "Check now" proves nothing was edited or deleted. This is what you show auditors.</P></Card>
            <Card><H><Link to="/learn" className="underline decoration-brand/40">Learn</Link></H>
              <P>Security words used in this app, explained for beginners with no jargon. Read the four validation statuses there before trusting any result anywhere.</P></Card>
            <Card><H>This Guide</H>
              <P>The full picture in one place: setup, options, principles, detection, and the honest limits. Share it with new team members on their first day.</P></Card>
          </div>
        </div>

        <div id="guide-principles" className="scroll-mt-4 space-y-3">
          <SectionTitle title="The principles it follows" hint="These are enforced in code, not just written here." />
          <Card>
            <ol className="space-y-3">
              <Li n="1"><b className="text-ink">Offline first.</b> Every capability runs on this machine. Nothing phones home; updates and new rules are things you copy in deliberately.</Li>
              <Li n="2"><b className="text-ink">Evidence or silence.</b> A result is shown only with the stored evidence behind it, or the page says it cannot see / could not check. There are no example, demo or filler entries anywhere - if a panel is empty it is because nothing has happened yet.</Li>
              <Li n="3"><b className="text-ink">Nothing is "Confirmed" without a second, independent check.</b> A tool's own output is never trusted alone; Rakshak re-observes it itself. Both observations are stored.</Li>
              <Li n="4"><b className="text-ink">Fail-closed scope.</b> If the scope file is missing or malformed, everything is refused. Every resolved IP of a target must be inside your declared ranges; never_scan always wins.</Li>
              <Li n="5"><b className="text-ink">No lone authority.</b> Tools start disabled; enabling pins the executable's hash; each run needs approval, admin-only tools need an admin, and the two-person rule can be switched on. A person cannot approve their own request when it is on.</Li>
              <Li n="6"><b className="text-ink">Least automation.</b> Ask me first is the default for a reason. Auto-block only exists for attack patterns with exact rules and re-checked evidence - never for a hunch or a score.</Li>
              <Li n="7"><b className="text-ink">Tamper evidence.</b> Log lines, responses and run records are hash-chained and signed. Break the chain and the dashboard flags it, and report generation refuses outright.</Li>
              <Li n="8"><b className="text-ink">Fail-open safety.</b> Rakshak never blocks your own trusted addresses, blocks always expire, and if Rakshak itself dies your network keeps working - blocks in place simply stop being managed.</Li>
            </ol>
          </Card>
        </div>

        <div id="guide-detect" className="scroll-mt-4 space-y-3">
          <SectionTitle title="How it detects" hint="Five layers: one watches the machine itself, four read your logs - all running locally." />
          <Card className="space-y-4">
            <div>
              <H><ShieldCheck size={15} className="mr-1.5 inline text-brand-700" />0. System sensors (the machine itself)</H>
              <P>Independently of any log file, Rakshak re-reads the live machine on a timer and compares it with its signed baseline: <b className="text-ink">file integrity</b> (SHA-256, size, permissions and ownership of critical files - the account database, sudoers, SSH keys, and Rakshak's own rules and scope files), <b className="text-ink">accounts</b> (new users, anyone becoming root-equivalent, new sudo/wheel members) and <b className="text-ink">listening ports</b> (a service that was not there before). This catches the system-security half of an intrusion - backdoor listeners, persistence accounts, tampered configuration - even when the attacker never touches the website again.</P>
            </div>
            <div>
              <H><Cpu size={15} className="mr-1.5 inline text-brand-700" />1. Attack signatures</H>
              <P>Each incoming log line is matched against rule groups written from published attack patterns: database break-in attempts (SQL injection), malicious script attempts (XSS), secret-file reads (path traversal and probes for <Code>.env</Code>, backups, admin panels), server command attempts, website mapping/scanners, hacking-tool user-agents, and request floods. A match stores the exact line and the rule that fired.</P>
            </div>
            <div>
              <H><Fingerprint size={15} className="mr-1.5 inline text-brand-700" />2. Behaviour limits</H>
              <P>Counts over a sliding window, not content: for example 8 failed logins from one address within 60 seconds becomes a password-guessing alert even though no line is "malicious". Each limit has a severity set in the rule definitions.</P>
            </div>
            <div>
              <H><SearchCode size={15} className="mr-1.5 inline text-brand-700" />3. Automation estimate</H>
              <P>Alerts carry "Likely a person: X%" - a rule-of-thumb score from timing regularity, request ordering, user-agent consistency and path knowledge. It is an estimate, never proof: it exists to help you triage, and it is clearly not used for automatic blocking.</P>
            </div>
            <div>
              <H><ScrollText size={15} className="mr-1.5 inline text-brand-700" />4. Unusual-behaviour model (off until trained)</H>
              <P>An optional local machine-learning model can learn normal traffic patterns from your own logs and flag deviations. Until it is trained on your data the dashboard says so and no anomaly findings are invented. (On encrypted traffic it sees only what your servers log - volume, paths, results - not contents.)</P>
                          <H><RotateCcw size={15} className="mr-1.5 inline text-brand-700" />5. Adapting to new attack patterns - still offline</H>
              <P>Signatures are not frozen. An admin can import a rule pack (a YAML file copied in from a trusted source or a colleague), but nothing goes live until it passes a two-stage gate: a schema check and a self-test against its own positive and negative examples - a rule that matches nothing, or that matches benign traffic, is refused and logged as refused. On any verified web alert, "Suggest a rule" mines the shared payload fragment out of the stored evidence and writes a draft; a draft is NOT active until it passes the same gate. Behaviour analysis also measures payload character entropy - machine-generated injections read very differently from hand-typed ones - and the unusual-behaviour model can be trained or retrained on your own traffic with one button. The whole loop runs with no internet.</P>
            </div>
          </Card>
        </div>

        <div id="guide-validate" className="scroll-mt-4 space-y-3">
          <SectionTitle title="Why you can trust a result" hint="The validation loop every finding passes through." />
          <Card className="space-y-4">
            <P>The core promise of this tool: <b className="text-ink">it would rather say "I could not check" than show you something unproven.</b> In practice:</P>
            <ol className="space-y-3">
              <Li n="1"><b className="text-ink">Store first.</b> Log lines are written with a fingerprint chain the moment they arrive. Alerts reference stored lines by ID.</Li>
              <Li n="2"><b className="text-ink">Re-check before "safe".</b> Alert evidence is re-validated from the stored rows (if the chain broke, you get "Evidence problem", not silence). System alerts are re-checked against the live machine: is the file still different, the port still listening, the account still there? Test findings are re-observed independently: a port the scanner saw open must answer a fresh Rakshak connection; a leaked file must return the same content hash again - and a catch-all page that answers everything cannot fake a pass.</Li>
              <Li n="3"><b className="text-ink">Four honest statuses.</b> Confirmed (seen twice, twice consistent) · Not reproduced (tool saw it; re-check did not - treated as no finding) · Could not check (re-check incomplete - explicitly not a pass) · Looked fine (one clean observation - a pass for that check, not a guarantee). Hover any chip for its meaning.</Li>
              <Li n="4"><b className="text-ink">Reports recompute.</b> The PDF numbers are recalculated from stored evidence at report time; if a record's signature fails, the report is refused and the dashboard shows why.</Li>
            </ol>
          </Card>
        </div>

        <div id="guide-tests" className="scroll-mt-4 space-y-3">
          <SectionTitle title="Security tests and your own tools" hint="Bringing a GitHub tool into the offline platform." />
          <Card className="space-y-4">
            <P>Rakshak ships two reviewed built-in tools (Website check and Port scan with Nmap). You can add your own offline copies of security tools:</P>
            <ol className="space-y-3">
              <Li n="1">Build or download the tool on an internet-connected machine, verify its source, and copy it to this server (USB or internal mirror) under <Code>plugins/&lt;name&gt;/</Code>.</Li>
              <Li n="2">Write a small <Code>plugin.yml</Code> (identity, exact executable + SHA-256, fixed argument list with <Code>{"{target}"}</Code> only, timeouts, output cap) and, if the tool's output is not already findings, a <Code>wrapper.py</Code> that converts it. <Code>examples/plugins/tcp-connect-check/</Code> is a complete working example.</Li>
              <Li n="3">Start Rakshak with the plugins folder enabled (<Code>RAKSHAK_ALLOW_EXTERNAL_PLUGINS=1</Code>). The tool appears as available but disabled.</Li>
              <Li n="4">An admin reviews the exact command and enables it - this pins the manifest and executable hashes. If a byte of the tool changes later, runs are refused before launch.</Li>
              <Li n="5">From then on every run follows the request → approve → execute-under-limits → re-check flow. The tool runs without a shell, with a scrubbed environment, memory/CPU/output limits and a hard timeout; it can only talk to the one approved target's pinned address.</Li>
            </ol>
            <P><b className="text-ink">Honest limit:</b> until OS-level isolation (network namespaces) ships, only enable tools your team has actually reviewed.</P>
          </Card>
        </div>

        <div id="guide-respond" className="scroll-mt-4 space-y-3">
          <SectionTitle title="How responses and blocks work" hint="From alert to containment and back." />
          <Card className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div><H>Ask me first (default)</H><P>Rakshak proposes a block with the alert attached. An analyst or admin approves - or the proposal dies when the alert is resolved. Nothing happens silently.</P></div>
              <div><H>Auto-block (admin switch)</H><P>High/critical alerts matching an exact rule with re-checked evidence are blocked on their own. Behaviour scores alone never trigger it. Intended only after weeks of proven accuracy.</P></div>
            </div>
            <P>Every block is recorded, applied through the firewall helper, and then <b className="text-ink">verified at the firewall</b> - "Blocked" on the dashboard means the rule provably exists. Blocks expire (default 1 hour) and can be unblocked instantly. Your own addresses, Trusted IPs and never-block entries are protected: Rakshak refuses to block them even if told to.</P>
            <P><b className="text-ink">System alerts are answered differently - and honestly.</b> A changed file or a new account has no attacker IP to block, so Rakshak never pretends to have "contained" it: it stores before/after fingerprints, immediately re-checks the live machine (is the change still there? was it reverted?), and gives you the fix-it-here steps - who was logged in around that time, how to revert, when to treat the box as compromised. The related network attacker (for example the IP that guessed its way in before creating the account) is still blockable through the normal flow.</P>
            <P><b className="text-ink">Undoing what an attacker changed.</b> For watched files Rakshak keeps private copies (the vault, a folder only its user can read); for a new listening port it traces the socket back to the process that opened it (PID and command line, via /proc); for accounts it drives a deliberately restricted root helper. The flow is always the same: an analyst <b className="text-ink">proposes</b> the undo - a proposal changes nothing and is signed - an admin <b className="text-ink">approves</b> it, Rakshak executes it and then <b className="text-ink">re-checks the live system</b>: a restore only counts as done when the file hash equals the recorded original again, a stop only when the port is genuinely gone, a lock/remove only when the account helper confirms the new state live. If the change came from your own team, "This was a sanctioned change" closes the alert with WHO accepted WHAT in the signed ledger, and the sensors' baseline follows the approved state so it does not cry twice.</P>
            <P><EyeOff size={14} className="mr-1 inline text-brand-700" /><b className="text-ink">Spoofing guard:</b> attacker addresses come only from server-side logs, never from spoofable headers, so an attacker cannot get a colleague blocked by forging a header.</P>
          </Card>
        </div>

        <div id="guide-limits" className="scroll-mt-4 space-y-3">
          <SectionTitle title="What it cannot do (read this)" hint="Honest limits. None of these are hidden in a footnote." />
          <Card className="space-y-3">
            <ol className="space-y-3">
              <Li n="1"><b className="text-ink">Accuracy on your traffic is yours to measure.</b> Detection/false-alarm rates depend on your logs and traffic. Run weeks in Ask me first mode and compare with your team's judgement before trusting Auto-block with anything.</Li>
              <Li n="2"><b className="text-ink">It sees what your servers log - nothing more.</b> No log file, no sight. Encrypted payloads are invisible unless your own servers log them. Add sources deliberately; Home shows when Rakshak is blind.</Li>
              <Li n="3"><b className="text-ink">It is not a full SOC.</b> No cloud threat feeds, no malware sandbox, no network tap. It complements your existing defences; patching, backups and people still matter more.</Li>
              <Li n="4"><b className="text-ink">System sensors see changes, not people.</b> They prove <i>what</i> changed and when it was observed, not who did it or why. Files readable only by root (like <Code>/etc/shadow</Code>) are watched by metadata - size, modification time, permissions - unless Rakshak runs as root. Anything that happened before the baseline was recorded looks like a normal starting point.</Li>
              <Li n="5"><b className="text-ink">A determined root-level attacker on this exact server can still do damage</b> - the hash chain makes edits visible, the sensors flag file/account/port changes, and reports refuse tampered data; but a root attacker can also stop the agent. Keep the server patched, disk-encrypted, and copy the audit log to separate storage for the strongest evidence.</Li>
              <Li n="6"><b className="text-ink">Windows is not supported yet;</b> Linux servers and WSL2 only (native Windows is on the plan, not built). And remember the console is for people your organisation trusts - protect the admin password.</Li>
            </ol>
          </Card>
        </div>
      </div>
    </div>
  );
}
