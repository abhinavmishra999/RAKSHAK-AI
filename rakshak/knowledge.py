"""Offline knowledge base: plain-language explanations, MITRE ATT&CK mapping and the
CERT-In incident category (Annexure I of the CERT-In Directions, 28 April 2022)."""

KB = {
    "sql_injection": {
        "title": "Someone tried to break into the database through a web form",
        "what": "The attacker typed database commands into the website (for example into the login or search box) "
                "hoping the site would run them.",
        "why": "If it works, they can log in without a password or copy every student/customer record.",
        "todo": ["Check that the website uses parameterised queries (prepared statements).",
                 "Review the evidence lines to see which page was targeted.",
                 "Keep the source blocked until the page is fixed."],
        "mitre": ("T1190", "Exploit Public-Facing Application"),
        "certin": "x. Attacks on Application such as E-Governance, E-Commerce etc.",
    },
    "xss": {
        "title": "Someone tried to plant a malicious script on the website",
        "what": "The attacker sent HTML/JavaScript code, hoping the site would show it to other visitors.",
        "why": "It can steal other users' logins (cookies) or redirect them to fake pages.",
        "todo": ["Make sure the site escapes user input before showing it.",
                 "Add a Content-Security-Policy header."],
        "mitre": ("T1190", "Exploit Public-Facing Application"),
        "certin": "iv. Defacement of website or intrusion into a website and unauthorised changes "
                  "such as inserting malicious code, links to external websites etc.",
    },
    "path_traversal": {
        "title": "Someone tried to read secret files from the server",
        "what": "The attacker used '../' tricks to reach files outside the website folder, such as /etc/passwd.",
        "why": "System files can reveal passwords, keys and configuration.",
        "todo": ["Never build file paths from user input.", "Check server file permissions."],
        "mitre": ("T1190", "Exploit Public-Facing Application"),
        "certin": "vi. Attack on servers such as Database, Mail and DNS and network devices such as Routers",
    },
    "command_injection": {
        "title": "Someone tried to run commands on the server",
        "what": "The attacker tried to make the website run operating-system commands like 'cat' or 'whoami'.",
        "why": "This can give full control of the server.",
        "todo": ["Treat as critical: check the server for new users, files and processes.",
                 "Never pass user input to a shell."],
        "mitre": ("T1059", "Command and Scripting Interpreter"),
        "certin": "ii. Compromise of critical systems/information",
    },
    "sensitive_probe": {
        "title": "Someone looked for secret or admin files",
        "what": "The attacker requested files like /.env, /.git or /phpmyadmin that often hold passwords.",
        "why": "This is usually the first step before a real break-in.",
        "todo": ["Make sure these files are not reachable from the web."],
        "mitre": ("T1595.003", "Active Scanning: Wordlist Scanning"),
        "certin": "i. Targeted scanning/probing of critical networks/systems",
    },
    "recon_scan": {
        "title": "Someone is mapping the website page by page",
        "what": "One source asked for many pages that don't exist, the way scanning tools do.",
        "why": "Attackers scan first to find weak spots to attack next.",
        "todo": ["Keep the scanner blocked.", "Run the Website check on the Security tests page to find what a scanner would find."],
        "mitre": ("T1595.003", "Active Scanning: Wordlist Scanning"),
        "certin": "i. Targeted scanning/probing of critical networks/systems",
    },
    "brute_force": {
        "title": "Someone is guessing passwords",
        "what": "Many failed logins came from one source in a short time.",
        "why": "Weak passwords will eventually be guessed.",
        "todo": ["Lock or reset the targeted accounts.", "Turn on login rate limits and strong passwords."],
        "mitre": ("T1110.001", "Brute Force: Password Guessing"),
        "certin": "iii. Unauthorised access of IT systems/data",
    },
    "flood": {
        "title": "Someone is flooding the server with requests",
        "what": "One source sent far more requests than any normal visitor.",
        "why": "It can slow down or crash the website for everyone.",
        "todo": ["Keep the source blocked.", "Add rate limiting at the web server."],
        "mitre": ("T1499", "Endpoint Denial of Service"),
        "certin": "viii. Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks",
    },
    "scanner_tool": {
        "title": "A known hacking tool was used against the website",
        "what": "The request identified itself as a known attack tool (for example sqlmap or nikto).",
        "why": "Someone is actively testing the site for weaknesses.",
        "todo": ["Check whether this was an approved security test. If not, keep it blocked."],
        "mitre": ("T1595.002", "Active Scanning: Vulnerability Scanning"),
        "certin": "i. Targeted scanning/probing of critical networks/systems",
    },
    "anomaly": {
        "title": "Unusual behaviour that doesn't match normal traffic",
        "what": "This source behaves very differently from the normal traffic Rakshak learned.",
        "why": "New attacks often have no known signature; unusual behaviour is the clue.",
        "todo": ["Review the evidence. If it is legitimate, mark it as a false alarm."],
        "mitre": ("T1595", "Active Scanning"),
        "certin": "i. Targeted scanning/probing of critical networks/systems",
    },
    "file_integrity": {
        "title": "A protected system file on this machine changed",
        "what": "Rakshak keeps a signed baseline (hash, size, permissions) of critical files such as the "
                "account file, sudoers, SSH keys and its own rules. One of them now differs from that baseline.",
        "why": "Attackers edit these files after breaking in: adding a user, opening SSH, installing a cron "
                "backdoor, or disabling the very rules that watch them. A change is strong evidence of "
                "compromise or of a configuration mistake worth catching.",
        "todo": ["Compare the before/after evidence on this alert with what your team changed today.",
                 "If nobody authorised it, treat the machine as compromised: disconnect it from the network "
                 "and investigate how the file was written (who was logged in at that time).",
                 "Restore from backup or re-apply the intended configuration, then let Rakshak re-baseline."],
        "mitre": ("T1554", "Compromise Client Software Binary"),
        "certin": "ii. Theft or leakage / unlawful exposure of data, iii. Installation of trojans, backdoors, "
                  "root kits, key loggers, ransomware etc. (suspected)",
    },
    "account_change": {
        "title": "System accounts or permissions on this machine changed",
        "what": "A user was added, removed or modified in the account database, or someone was added to an "
                "administrator group (sudo/wheel), or an extra uid-0 (root-equivalent) account appeared.",
        "why": "Creating a hidden account or granting sudo is the most common way attackers keep access after "
                "breaking in (persistence). An unexpected change here usually means someone already has a shell.",
        "todo": ["Confirm who made the change and when (last command history, auth logs around the time).",
                 "If unauthorised: disable/remove the account immediately, rotate all credentials on the box, "
                 "and check file-integrity and new-service alerts from the same time window.",
                 "Review login alerts for the preceding hours - the change is usually the second step, not the first."],
        "mitre": ("T1136", "Create Account"),
        "certin": "ii. Unauthorized access of IT systems and data / modification thereof",
    },
    "credential_compromise": {
        "title": "A login was accepted from an address that had been guessing at the door",
        "what": "This source failed several SSH logins, and then one attempt succeeded. Either the password was "
                "guessed, or the attacker already had a key. On this machine the failure burst and the success "
                "come from the same address within minutes.",
        "why": "This is the most serious kind of login alert: a working credential means real access to the "
                "system - data, accounts and installed software are all exposed from the inside.",
        "todo": ["Change that account's password and kill its sessions now (or disable the account).",
                 "Keep this source blocked while you investigate.",
                 "Check the system alerts (file integrity, accounts, listening ports) from the same time window - "
                 "post-compromise persistence usually follows within minutes."],
        "mitre": ("T1110", "Brute Force"),
        "certin": "ii. Unauthorized access of IT systems and data",
    },
    "new_service": {
        "title": "A new network service started listening on this machine",
        "what": "Something opened a new listening port (seen in /proc/net). Rakshak baselines the ports at "
                "install time; this one was not there before.",
        "why": "Backdoors, miners and tunnelled shells all listen on new ports. Even a legitimate 'quick test "
                "server' widens the attack surface of a production machine.",
        "todo": ["Identify the process that owns the port (for example `ss -tlnp` or Task Manager) and who started it.",
                 "If unauthorised, stop the process before deciding anything else, then review file-integrity "
                 "and login alerts from the same period.",
                 "If it is yours and intended, approve the change and restart Rakshak so the new state is baselined."],
        "mitre": ("T1571", "Non-Standard Port"),
        "certin": "iii. Installation of trojans, backdoors, root kits, key loggers, ransomware etc. (suspected)",
    },
}

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Which category is the "headline" when one source triggers several.
PRIORITY = ["command_injection", "sql_injection", "path_traversal", "xss", "brute_force",
            "credential_compromise", "account_change", "new_service", "file_integrity",
            "flood", "sensitive_probe", "recon_scan", "scanner_tool", "anomaly"]


def explain(category):
    k = KB.get(category, KB["anomaly"])
    return {"title": k["title"], "what": k["what"], "why": k["why"], "todo": k["todo"],
            "mitre_id": k["mitre"][0], "mitre_name": k["mitre"][1], "certin_category": k["certin"]}
