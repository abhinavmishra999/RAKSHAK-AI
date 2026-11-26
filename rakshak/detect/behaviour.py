"""Behaviour analysis: per-source sliding windows over real events.

Detects patterns that single requests can't show: password guessing, path
scanning (many 404s), request floods. Also exposes the window features used by
the AI-origin scorer and the anomaly model.
"""
import statistics
import math
import time
from collections import defaultdict, deque

WINDOW = 60.0  # seconds


class SourceWindow:
    def __init__(self):
        self.events = deque()

    def add(self, ev, hits):
        self.events.append((ev["ts"], ev, hits))
        cutoff = ev["ts"] - WINDOW
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def features(self):
        evs = list(self.events)
        n = len(evs)
        if n == 0:
            return None
        ts = [e[0] for e in evs]
        span = max(ts[-1] - ts[0], 1e-3)
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        mean_gap = statistics.mean(gaps) if gaps else WINDOW
        cv = (statistics.pstdev(gaps) / mean_gap) if len(gaps) > 2 and mean_gap > 0 else 1.0
        statuses = [e[1].get("status") or 0 for e in evs]
        paths = {e[1].get("path") for e in evs}
        uas = {e[1].get("user_agent") for e in evs}
        mal = [e for e in evs if e[2]]
        payloads = [((e[1].get("query") or "") + (e[1].get("body") or "")) for e in mal]
        uniq_payloads = list(dict.fromkeys(payloads))
        entropies = []
        for p in uniq_payloads[-15:]:
            if len(p) < 16:
                continue
            freq = {}
            for ch in p:
                freq[ch] = freq.get(ch, 0) + 1
            entropies.append(-sum((c / len(p)) * math.log2(c / len(p)) for c in freq.values()))
        logins = [e for e in evs if e[1].get("kind") == "ssh_login" or
                  (e[1].get("path") or "").endswith("/login") and e[1].get("method") == "POST"]
        failed_logins = [e for e in logins if (e[1].get("status") or 0) in (401, 403)]
        blocked = [e for e in evs if (e[1].get("status") or 0) == 403]
        after_block = 0
        if blocked:
            first_block = blocked[0][0]
            after_block = sum(1 for e in evs if e[0] > first_block)
        return {
            "count": n,
            "rate": n / span if n > 1 else 0.0,
            "mean_gap": mean_gap,
            "timing_cv": cv,
            "err_404_ratio": sum(1 for s in statuses if s == 404) / n,
            "unique_paths": len(paths),
            "unique_uas": len(uas),
            "malicious": len(mal),
            "unique_payloads": len(set(payloads)),
            "payloads": payloads[-40:],
            "payload_entropy": (sum(entropies) / len(entropies)) if entropies else None,
            "failed_logins": len(failed_logins),
            "login_users": len({e[1].get("body") or e[1].get("path") for e in failed_logins}),
            "requests_after_block": after_block,
        }


class BehaviourDetector:
    def __init__(self):
        self.windows = defaultdict(SourceWindow)

    def observe(self, ev, hits):
        w = self.windows[ev["source_ip"]]
        w.add(ev, hits)
        f = w.features()
        found = []
        if f["failed_logins"] >= 8:
            found.append({"rule_id": "BEH-BRUTE-001", "category": "brute_force", "severity": "high",
                          "name": f"{f['failed_logins']} failed logins in 60 s", "matched": ""})
        if f["err_404_ratio"] > 0.5 and f["unique_paths"] >= 15:
            found.append({"rule_id": "BEH-SCAN-001", "category": "recon_scan", "severity": "medium",
                          "name": f"{f['unique_paths']} different pages probed, mostly not found",
                          "matched": ""})
        if f["rate"] > 25 and f["count"] >= 200:
            found.append({"rule_id": "BEH-FLOOD-001", "category": "flood", "severity": "high",
                          "name": f"{f['rate']:.0f} requests per second", "matched": ""})
        return found, f

    def features_for(self, ip):
        w = self.windows.get(ip)
        return w.features() if w else None

    def reset(self):
        self.windows.clear()
