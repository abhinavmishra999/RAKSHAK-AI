"""Offline adaptation: bring new detection logic in without ever going online.

Two loops:

  IMPORT  - an admin copies a rule pack onto the machine (USB, internal share,
            the vendor's offline bundle). Before it can go live, every rule must
            PASS ITS OWN EXAMPLES here: the pack declares sample requests that
            MUST match and samples that MUST NOT. Anything failing the gate is
            refused and never touches the live rule set. Imported packs live in
            a separate folder (data/rules/imported) so built-ins are never edited.

  DRAFT   - "write me a rule for this incident": the engine mines the incident's
            real evidence lines, finds the common substring, and produces a draft
            YAML with positive samples taken from the actual stored (hash-chained)
            log lines and a negative sample. The draft is NOT loaded automatically;
            it goes through the same import gate when an admin approves it.

The knowledge base categories are fixed, so an imported rule cannot invent a new
category with unknown reporting semantics.
"""
import re
import tempfile
import time
from difflib import SequenceMatcher
from pathlib import Path

import yaml

from .detect.rules import RuleEngine
from .knowledge import PRIORITY

MAX_PACK_RULES = 60
MAX_PATTERNS = 8
MAX_PATTERN_LEN = 300
RULE_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,40}$")
SEVERITIES = {"low", "medium", "high", "critical"}


def _decode_sample_text(s):
    return str(s or "")[:2000]


def validate_pack(rules_yaml: str):
    """Parse and schema-check; returns (rules, errors). Does NOT touch disk."""
    errors = []
    try:
        data = yaml.safe_load(rules_yaml)
    except yaml.YAMLError as exc:
        return [], [f"not valid YAML: {exc}"]
    if not isinstance(data, list) or not data:
        return [], ["pack must be a non-empty YAML list of rules"]
    if len(data) > MAX_PACK_RULES:
        return [], [f"too many rules in one pack ({len(data)} > {MAX_PACK_RULES})"]
    seen_ids, rules = set(), []
    for idx, r in enumerate(data):
        if not isinstance(r, dict):
            errors.append(f"rule {idx}: not a mapping")
            continue
        for key in ("id", "name", "category", "severity", "patterns"):
            if key not in r:
                errors.append(f"rule {idx}: missing '{key}'")
        rid = str(r.get("id", ""))
        if not RULE_ID_RE.fullmatch(rid):
            errors.append(f"rule {idx}: id '{rid[:40]}' must match {RULE_ID_RE.pattern}")
        if rid in seen_ids:
            errors.append(f"rule {idx}: duplicate id {rid}")
        seen_ids.add(rid)
        if r.get("category") not in PRIORITY:
            errors.append(f"rule {rid}: unknown category (known: {', '.join(PRIORITY)})")
        if r.get("severity") not in SEVERITIES:
            errors.append(f"rule {rid}: severity must be low/medium/high/critical")
        if r.get("match_on") not in (None, "request", "path", "user_agent"):
            errors.append(f"rule {rid}: match_on must be request/path/user_agent")
        pats = r.get("patterns")
        if not isinstance(pats, list) or not pats:
            errors.append(f"rule {rid}: patterns must be a non-empty list")
            continue
        if len(pats) > MAX_PATTERNS:
            errors.append(f"rule {rid}: too many patterns")
        for p in pats:
            if not isinstance(p, str) or len(p) > MAX_PATTERN_LEN:
                errors.append(f"rule {rid}: pattern too long or not a string")
                continue
            try:
                re.compile(p, re.I | re.S)
            except re.error as exc:
                errors.append(f"rule {rid}: pattern does not compile: {exc}")
        rules.append(r)
    return rules, errors


def self_test(rules, samples):
    """Run candidate rules in ISOLATION against the declared samples.
    Returns list of failure strings; empty means the pack proves itself."""
    if not samples:
        return ["pack carries no samples: an untested rule pack is never activated"]
    errors = []
    pos = [s for s in samples if s.get("expect") == "match"]
    neg = [s for s in samples if s.get("expect") == "nomatch"]
    if not pos:
        return ["pack must show at least one sample that matches the new rules"]
    with tempfile.TemporaryDirectory() as td:
        Path(td, "candidate.yml").write_text(yaml.safe_dump(rules, sort_keys=False))
        eng = RuleEngine(Path(td))
        for s in samples:
            ev = {"kind": "http", "path": _decode_sample_text(s.get("path")),
                  "query": _decode_sample_text(s.get("query")),
                  "body": _decode_sample_text(s.get("body")),
                  "user_agent": _decode_sample_text(s.get("user_agent"))}
            hits = eng.match(ev)
            if s.get("expect") == "match" and not hits:
                errors.append(f"sample did NOT match: {ev['path'][:80]}")
            if s.get("expect") == "nomatch" and hits:
                errors.append(f"sample wrongly matched by {hits[0]['rule_id']}: {ev['path'][:80]}")
        # every declared rule id must fire at least once on a positive sample,
        # otherwise it is dead weight that can silently never work
        fired = {h["rule_id"] for s in pos for h in eng.match({
            "kind": "http", "path": _decode_sample_text(s.get("path")),
            "query": _decode_sample_text(s.get("query")), "body": _decode_sample_text(s.get("body")),
            "user_agent": _decode_sample_text(s.get("user_agent"))})}
        for r in rules:
            if r["id"] not in fired:
                errors.append(f"rule {r['id']} never matches any positive sample")
    return errors


def _common_substring(texts):
    """Longest literal piece shared by all texts (pairwise shrink; small n is fine)."""
    texts = [t.lower() for t in texts if t]
    if len(texts) < 2:
        return texts[0] if texts else ""
    best = texts[0]
    for t in texts[1:]:
        m = SequenceMatcher(None, best, t).find_longest_match(0, len(best), 0, len(t))
        best = best[m.a:m.a + m.size]
        if not best:
            break
    return best


def suggest_rule(inc, store, parsers_parse_line):
    """Draft a rule from the incident's real stored evidence. Returns
    (yaml_text, samples, note) or raises ValueError."""
    from urllib.parse import unquote_plus
    lines = [str(e) for e in (inc.get("evidence") or []) if e]
    evs = []
    for ln in lines[:12]:
        ev = parsers_parse_line(ln)
        if ev and ev.get("kind") == "http":
            q = unquote_plus(ev.get("query") or "")
            b = unquote_plus(ev.get("body") or "")
            if q or b:
                evs.append({"ev": ev, "payload": q or b})
    if len(evs) < 2:
        raise ValueError("this incident has fewer than two decodable HTTP payload lines to "
                         "generalise from; a single line is not enough evidence for a signature")
    shared = _common_substring([e["payload"] for e in evs])
    if len(shared) < 8:
        raise ValueError(f"evidence payloads share only '{shared}' (too short to generalise safely)")
    rid = f"ADP-{inc['id']}-{int(time.time()) % 100000:05d}"
    rule = {"id": rid, "name": f"Adapted from verified incident #{inc['id']}",
            "category": inc["category"], "severity": inc["severity"],
            "patterns": [re.escape(shared)[:MAX_PATTERN_LEN]]}
    positive = {"path": (evs[0]["ev"].get("path") or "/")[:400],
                "query": (evs[0]["ev"].get("query") or "")[:600],
                "body": (evs[0]["ev"].get("body") or "")[:600], "expect": "match"}
    negative = {"path": "/index.html", "query": "article=42&lang=en", "body": "", "expect": "nomatch"}
    if shared.lower() in negative["query"].lower():
        negative["query"] = "productId=12345"
    samples = [positive, negative]
    return (yaml.safe_dump([rule], sort_keys=False), samples,
            f"Draft rule {rid} generalises the shared payload fragment '{shared[:80]}'. "
            "Review it, then import it through the rule-pack gate; it is NOT active until then.")
