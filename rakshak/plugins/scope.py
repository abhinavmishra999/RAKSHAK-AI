"""Scope: the list of assets Rakshak is allowed to actively test.

scope.yml (in the data folder) is written by a person, never by the dashboard:

    networks:   [10.20.0.0/16, 192.168.50.0/24]   # your own address ranges
    hosts:      [intranet.example.org, "*.apps.example.org"]   # names you own
    never_scan: [10.20.0.1, 10.20.99.0/24]        # gateways, medical devices, fragile systems

Rules (all enforced in code, not left to the plugin):
  1. FAIL CLOSED. No scope file, or an empty one, means nothing can be actively tested.
  2. A hostname is resolved first. EVERY address it resolves to must be allowed.
  3. `never_scan` always wins over `networks` and `hosts`.
  4. An address that Rakshak has ever flagged as an attacker or blocked is NEVER a target.
     Rakshak does not attack back, scan back, or "investigate" attackers actively.
"""
import hashlib
import ipaddress
import re
import socket
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urlsplit

import yaml

HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")


def _nets(items, field):
    """Every entry must be a valid network; one bad entry invalidates the whole file."""
    if items is None:
        return []
    if not isinstance(items, list):
        raise ValueError(f"'{field}' must be a list")
    out = []
    for i in items:
        if not isinstance(i, str):
            raise ValueError(f"'{field}' entries must be text like 10.20.0.0/16 (found {i!r})")
        try:
            out.append(ipaddress.ip_network(i, strict=False))
        except ValueError:
            raise ValueError(f"'{field}' entry {i!r} is not a valid IP address or network")
    return out


class TargetError(ValueError):
    """The target text is not a valid, safe target (or is out of scope)."""


class Scope:
    def __init__(self, path: Path, attackers=lambda: set()):
        self.path = path
        self.attackers = attackers
        self.reload()

    def reload(self):
        self.networks, self.hosts, self.never, self.error = [], [], [], ""
        self.sha256 = ""
        if not self.path.exists():
            self.error = "scope.yml does not exist: no asset can be actively tested until you create it."
            return
        raw = self.path.read_bytes()
        self.sha256 = hashlib.sha256(raw).hexdigest()
        try:
            d = yaml.safe_load(raw) or {}
        except yaml.YAMLError as exc:
            self.error = f"scope.yml is not valid YAML: {exc}"
            return
        try:
            if not isinstance(d, dict):
                raise ValueError("the file must contain the keys networks, hosts and never_scan")
            unknown = set(d) - {"networks", "hosts", "never_scan"}
            if unknown:
                raise ValueError(f"unknown key(s): {', '.join(sorted(map(str, unknown)))}")
            networks = _nets(d.get("networks"), "networks")
            never = _nets(d.get("never_scan"), "never_scan")
            hosts = d.get("hosts") or []
            if not isinstance(hosts, list) or not all(isinstance(h, str) and HOST_RE.match(h.replace("*.", "x.", 1))
                                                      for h in hosts):
                raise ValueError("'hosts' must be a list of host names (optionally starting with *.)")
        except ValueError as exc:
            # Fail closed: a malformed scope allows nothing, and says why.
            self.error = f"scope.yml is invalid, so all active tests are refused: {exc}"
            return
        self.networks, self.never, self.hosts = networks, never, [h.lower() for h in hosts]
        if not self.networks:
            self.error = "scope.yml lists no networks: no asset can be actively tested."

    def info(self):
        self.reload()
        return {"file": str(self.path), "sha256": self.sha256, "error": self.error,
                "networks": [str(n) for n in self.networks], "hosts": self.hosts,
                "never_scan": [str(n) for n in self.never]}

    # ---------- target parsing ----------
    @staticmethod
    def parse_target(text: str, target_type: str):
        """Validate the raw target text and return (host, normalised_target). Raises TargetError."""
        text = (text or "").strip()
        if not text or len(text) > 300 or text.startswith("-") or any(c.isspace() or ord(c) < 32 for c in text):
            raise TargetError("The target is empty, too long, or contains spaces or control characters.")
        if target_type == "url":
            if "://" not in text:
                text = "http://" + text
            u = urlsplit(text)
            if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
                raise TargetError("Enter a web address like http://app.internal:8080/ (no login details inside it).")
            host = u.hostname
            try:
                u.port
            except ValueError:
                raise TargetError("The port number in the address is not valid.")
            norm = text
        else:
            host = text.strip("[]")
            norm = host
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not HOST_RE.match(host):
                raise TargetError("That is not a valid IP address or host name.")
        return host.lower(), norm

    @staticmethod
    def resolve(host: str):
        try:
            return [ipaddress.ip_address(host)]
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            raise TargetError(f"'{host}' could not be resolved to an address on this network.")
        return sorted({ipaddress.ip_address(i[4][0]) for i in infos}, key=str)

    # ---------- the decision ----------
    def check(self, host: str):
        """Return (ips, None) if allowed, else raise TargetError with a plain-language reason."""
        self.reload()
        if self.error:
            raise TargetError(f"Refused: {self.error}")
        ips = self.resolve(host)
        attackers = self.attackers()
        is_name = not any(str(ip) == host for ip in ips)
        if is_name and not any(fnmatch(host, h) for h in self.hosts):
            raise TargetError(f"Refused: host name '{host}' is not listed under hosts in scope.yml.")
        for ip in ips:
            if str(ip) in attackers:
                raise TargetError(f"Refused: {ip} has been flagged or blocked by Rakshak as a source of attacks. "
                                  "Rakshak never scans or attacks back at attackers.")
            if any(ip in n for n in self.never):
                raise TargetError(f"Refused: {ip} is on your never_scan list.")
            # A listed host name is NOT enough: every address it resolves to must be in an owned network.
            if not any(ip in n for n in self.networks):
                raise TargetError(f"Refused: {ip} is not inside the scope you defined in scope.yml. "
                                  "Only assets your organisation owns can be tested.")
        return ips
