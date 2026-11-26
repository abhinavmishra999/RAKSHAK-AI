"""Parsers that turn raw log lines into normalised events.

Supported formats:
  * Rakshak shield JSON lines (written by the demo portal; includes POST bodies)
  * Apache / Nginx "combined" access log format
  * Linux sshd lines from /var/log/auth.log (failed / accepted passwords)
"""
import json
import re
import time
from datetime import datetime
from urllib.parse import urlsplit

COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<target>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)
SSHD = re.compile(
    r'(?P<result>Failed|Accepted) (?:password|publickey) for (?:invalid user )?(?P<user>\S+) '
    r'from (?P<ip>[\d.:a-fA-F]+)'
)


def parse_line(line: str, source: str = "auto"):
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            d = json.loads(line)
            return {
                "ts": float(d.get("ts", time.time())),
                "source_ip": d.get("ip"),
                "kind": "http",
                "method": d.get("method"),
                "path": d.get("path"),
                "query": d.get("query", ""),
                "body": d.get("body", ""),
                "status": int(d.get("status", 0)),
                "user_agent": d.get("ua", ""),
                "raw": line[:2000],
            }
        except (ValueError, TypeError):
            return None
    m = COMBINED.match(line)
    if m:
        target = urlsplit(m.group("target"))
        try:
            ts = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z").timestamp()
        except ValueError:
            ts = time.time()
        return {
            "ts": ts, "source_ip": m.group("ip"), "kind": "http", "method": m.group("method"),
            "path": target.path, "query": target.query, "body": "", "status": int(m.group("status")),
            "user_agent": m.group("ua") or "", "raw": line[:2000],
        }
    m = SSHD.search(line)
    if m:
        return {
            "ts": time.time(), "source_ip": m.group("ip"), "kind": "ssh_login",
            "method": "SSH", "path": m.group("user"), "query": "", "body": "",
            "status": 401 if m.group("result") == "Failed" else 200,
            "user_agent": "sshd", "raw": line[:2000],
        }
    return None
