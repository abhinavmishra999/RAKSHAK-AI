#!/usr/bin/env python3
"""Example external plugin for RAKSHAK-AI: TCP connect check.

Copy this folder as a starting point when you connect your own offline tool (for example
a tool you cloned from GitHub). The contract is:

  * Rakshak runs this file WITHOUT a shell, with the fixed args from plugin.yml.
    "{target}" is replaced by the numeric IP that passed the scope check.
  * Print ONE JSON document on stdout: a list of findings (or {"findings": [...]}).
  * Each finding needs "passed" (true/false). Optional: id, title, severity
    (high|medium|low|info), what, fix, evidence, port, recheck.
  * You can NOT mark anything "confirmed". Only Rakshak's own validator can, by re-checking
    independently. Here every open port carries {"kind": "tcp_open", "port": N}, so the
    tcp_open validator opens its own new connection before it is shown as Confirmed.
  * Exit code 0 = success. Any other exit code means no findings are accepted.

If you wrap a separate binary (e.g. a Go tool from GitHub), check that binary's sha256
inside the wrapper before running it, because Rakshak pins only this wrapper file.
"""
import ipaddress
import json
import socket
import sys


def main(argv):
    if len(argv) != 3:
        print("usage: wrapper.py <ip> <comma-separated ports>", file=sys.stderr)
        return 2
    ip = str(ipaddress.ip_address(argv[1]))          # refuses anything that is not a numeric IP
    ports = sorted({int(p) for p in argv[2].split(",") if p.strip()})
    if not ports or any(not 1 <= p <= 65535 for p in ports) or len(ports) > 64:
        print("ports must be 1-64 values between 1 and 65535", file=sys.stderr)
        return 2
    findings = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=2.0):
                is_open = True
        except OSError:
            is_open = False
        if is_open:
            findings.append({
                "id": f"TCP-{port}", "title": f"TCP port {port} accepts connections on {ip}",
                "severity": "medium", "passed": False, "port": port,
                "what": "A network service is reachable on this port. Every open port is attack surface.",
                "fix": "Close the port or restrict it with a firewall if it is not needed.",
                "evidence": f"TCP connect to {ip}:{port} succeeded",
                "recheck": {"kind": "tcp_open", "port": str(port)},
            })
        else:
            findings.append({
                "id": f"TCP-{port}", "title": f"TCP port {port} did not accept a connection",
                "severity": "info", "passed": True, "port": port,
                "evidence": f"TCP connect to {ip}:{port} was refused or timed out",
            })
    print(json.dumps({"findings": findings}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
