"""Signature rule engine (Sigma-like, YAML based)."""
import re
from pathlib import Path
from urllib.parse import unquote_plus

import yaml


def decode(s: str) -> str:
    """URL-decode up to three times to defeat double/triple encoding tricks."""
    s = s or ""
    for _ in range(3):
        d = unquote_plus(s)
        if d == s:
            break
        s = d
    return s


class RuleEngine:
    def __init__(self, rules_dir):
        # one Path or a list of Paths: built-ins plus operator-imported packs
        if isinstance(rules_dir, (str, Path)):
            rules_dir = [rules_dir]
        self.rules_dirs = [Path(p) for p in rules_dir]
        self.rules_dir = self.rules_dirs[0]
        self.rules = []
        self.reload()

    def reload(self):
        rules = []
        seen_files = set()
        for d in self.rules_dirs:
            for f in sorted(d.glob("*.yml")):
                if f.name in seen_files:
                    continue
                seen_files.add(f.name)
                self._load_file(f, rules)
        self.rules = rules
        return len(rules)

    @staticmethod
    def _load_file(f, rules):
            for r in yaml.safe_load(f.read_text()) or []:
                r["compiled"] = [re.compile(p, re.I | re.S) for p in r["patterns"]]
                r.setdefault("match_on", "request")
                r["file"] = f.name
                rules.append(r)

    def match(self, ev: dict):
        if ev.get("kind") != "http":
            return []
        path = decode(ev.get("path"))
        request = " ".join([path, decode(ev.get("query")), decode(ev.get("body"))])
        ua = ev.get("user_agent") or ""
        hits = []
        for r in self.rules:
            target = {"path": path, "user_agent": ua}.get(r["match_on"], request)
            for rx in r["compiled"]:
                m = rx.search(target)
                if m:
                    hits.append({
                        "rule_id": r["id"], "category": r["category"], "severity": r["severity"],
                        "name": r["name"], "matched": m.group(0)[:120],
                    })
                    break
        return hits
