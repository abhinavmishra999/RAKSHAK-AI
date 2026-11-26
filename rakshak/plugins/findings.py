"""Turn untrusted plugin output into bounded, typed findings.

A pass is only an observed response, never proof that a security property holds.
Plugin-authored validation/confirmation flags are intentionally not accepted.
"""
import json
import re
import xml.etree.ElementTree as ET

SEVERITIES = ("high", "medium", "low", "info", "pass")
STATUSES = ("suspected", "observed_pass", "inconclusive", "info")
ALLOWED = ("id", "title", "severity", "passed", "what", "fix", "evidence", "port", "recheck", "status")
RISKY = {
    21: ("high", "FTP sends passwords in readable form.", "Use SFTP, or restrict FTP to trusted addresses."),
    23: ("high", "Telnet sends everything, including passwords, in readable form.", "Disable Telnet; use SSH."),
    135: ("high", "Windows RPC should never be reachable from untrusted networks.", "Block it at the firewall."),
    139: ("high", "NetBIOS exposes Windows file sharing.", "Block it at the firewall."),
    445: ("high", "SMB file sharing is a common ransomware entry point.", "Block it at the firewall; patch."),
    3389: ("high", "Remote Desktop is heavily attacked by password guessing.", "Put it behind a VPN; enable MFA."),
    5900: ("high", "VNC remote screen access is often weakly protected.", "Put it behind a VPN."),
    3306: ("medium", "A database port is reachable over the network.", "Allow only the application servers."),
    5432: ("medium", "A database port is reachable over the network.", "Allow only the application servers."),
    1433: ("medium", "A database port is reachable over the network.", "Allow only the application servers."),
    6379: ("high", "Redis often has no password by default.", "Bind to localhost or require authentication."),
    27017: ("high", "MongoDB is often exposed without authentication.", "Bind to localhost or require authentication."),
    11211: ("high", "Memcached has no authentication.", "Bind to localhost."),
    9200: ("high", "Elasticsearch is often exposed without authentication.", "Restrict access; require authentication."),
}
EXPECTED = {22: "SSH", 80: "HTTP", 443: "HTTPS"}


def _s(v, n=300):
    return str(v if v is not None else "")[:n]


def clean(f: dict) -> dict:
    if not isinstance(f, dict):
        raise ValueError("Each finding must be a JSON object.")
    if "passed" not in f or not isinstance(f["passed"], bool):
        raise ValueError("Finding 'passed' must be a JSON boolean.")
    out = {k: f.get(k) for k in ALLOWED if k in f}
    out["id"] = _s(out.get("id") or "FINDING", 80)
    out["title"] = _s(out.get("title") or out["id"], 200)
    sev = _s(out.get("severity", "info")).lower()
    out["severity"] = sev if sev in SEVERITIES else "info"
    out["passed"] = f["passed"]
    for k in ("what", "fix", "evidence"):
        out[k] = _s(out.get(k, ""), 600)
    rc = out.get("recheck")
    if rc is not None and not isinstance(rc, dict):
        raise ValueError("Finding 'recheck' must be an object when present.")
    out["recheck"] = {str(k): _s(v, 200) for k, v in (rc or {}).items()}
    if "port" in out:
        try:
            out["port"] = int(out["port"])
        except (TypeError, ValueError):
            raise ValueError("Finding 'port' must be an integer.")
        if not 1 <= out["port"] <= 65535:
            raise ValueError("Finding 'port' is outside the TCP port range.")
    # Never accept confirmed/validated/authored statuses.  The only plugin status
    # retained is an explicit inconclusive/info emitted by the built-in wrapper.
    requested_status = out.get("status")
    if requested_status not in ("inconclusive", "info"):
        requested_status = None
    if out["passed"]:
        out["severity"] = "pass"
        out["status"] = "observed_pass"
    else:
        out["status"] = requested_status or "suspected"
    return out


def parse_json_findings(text: str):
    try:
        data = json.loads(text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Plugin output is not valid JSON: {exc}") from exc
    if isinstance(data, dict):
        data = data.get("findings", [])
    if not isinstance(data, list):
        raise ValueError("Output must be a JSON list of findings (or {\"findings\": [...]} ).")
    if len(data) > 500:
        raise ValueError("Output contains more than 500 findings.")
    return [clean(f) for f in data]


def parse_nmap_xml(text: str):
    # Real Nmap output always carries the bare declaration "<!DOCTYPE nmaprun>" (no internal
    # subset, no SYSTEM/PUBLIC DTD). Remove exactly that one form; anything else that declares
    # a DOCTYPE or ENTITY (entity expansion, external DTDs) is refused.
    text = re.sub(r"<!DOCTYPE\s+nmaprun\s*>", "", text, count=1)
    if re.search(r"<!\s*(DOCTYPE|ENTITY)", text, re.I):
        raise ValueError("Refused: XML contains a DOCTYPE/ENTITY declaration.")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Nmap output is not valid XML: {exc}") from exc
    fin = root.find("runstats/finished")
    if fin is None or fin.get("exit") != "success":
        raise ValueError("Nmap did not finish successfully, so no result is reported.")
    hosts_up = root.find("runstats/hosts")
    try:
        up = int(hosts_up.get("up", "0")) if hosts_up is not None else 0
    except (TypeError, ValueError) as exc:
        raise ValueError("Nmap host count is invalid.") from exc
    out = []
    scanned = root.find("scaninfo")
    services = scanned.get("services", "") if scanned is not None else ""
    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "?"
        for p in host.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                num, proto = int(p.get("portid")), p.get("protocol", "tcp")
            except (TypeError, ValueError) as exc:
                raise ValueError("Nmap returned an invalid port.") from exc
            if not 1 <= num <= 65535:
                raise ValueError("Nmap returned a port outside the TCP range.")
            svc = p.find("service")
            name = (svc.get("name") if svc is not None else "") or "unknown"
            product = " ".join(x for x in ((svc.get("product") if svc is not None else ""),
                                           (svc.get("version") if svc is not None else "")) if x)
            if num in RISKY:
                sev, why, fix = RISKY[num]
            elif num in EXPECTED:
                sev, why, fix = "low", f"{EXPECTED[num]} is reachable. This is normal only if the service is meant to be public.", \
                    "Restrict it to the networks that need it, and keep the service patched."
            else:
                sev, why, fix = "medium", "A network service is reachable. Every open port is extra attack surface.", \
                    "Close the port or restrict it with a firewall if it is not needed."
            out.append(clean({"id": f"PORT-{proto}-{num}", "port": num, "severity": sev, "passed": False,
                              "title": f"Open port {num}/{proto} ({name}{' ' + product if product else ''}) on {addr}",
                              "what": why, "fix": fix,
                              "evidence": f"Nmap observed {num}/{proto} open on {addr}",
                              "recheck": {"kind": "tcp_open", "port": str(num)}}))
    if up == 0:
        raise ValueError("Nmap reports the host did not answer (0 hosts up). No claim is made about its ports.")
    if not out:
        out.append(clean({"id": "PORTS-NONE", "passed": True, "severity": "pass",
                          "title": "No open ports found among the ports scanned",
                          "what": f"Only the most common ports were scanned ({services or 'top 100 TCP'}). This is not proof that no other port is open.",
                          "evidence": "Nmap finished successfully; host was up."}))
    return out


def parse_text(text: str):
    return [{"id": "RAW-OUTPUT", "title": "Raw tool output (cannot be validated)", "severity": "info",
             "passed": False, "what": "This plugin produces plain text, so Rakshak cannot check its claims.",
             "fix": "", "evidence": _s(text, 4000), "recheck": {}, "status": "info"}]


PARSERS = {"nmap_xml": parse_nmap_xml, "json_findings": parse_json_findings, "text": parse_text}
