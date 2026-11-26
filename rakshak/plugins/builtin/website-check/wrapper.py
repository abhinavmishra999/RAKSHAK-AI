#!/usr/bin/env python3
"""Built-in website check entry point with controlled project-path insertion."""
import json
import sys
from pathlib import Path

# Derived only from this reviewed file; no user-controlled import path.
PROJECT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(PROJECT))
from rakshak.plugins.webchecks import run_all  # noqa: E402


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"findings": [{"id": "INPUT", "title": "Invalid wrapper input", "severity": "info",
                                         "passed": False, "what": "The built-in wrapper expected one URL.",
                                         "fix": "", "evidence": "exactly one URL argument required", "status": "inconclusive"}]}))
        return 2
    try:
        result = run_all(sys.argv[1])
    except Exception as exc:
        result = [{"id": "HOME-HTTP", "title": "Website check inconclusive", "severity": "info",
                   "passed": False, "what": "The harmless website check could not complete.", "fix": "",
                   "evidence": f"{exc.__class__.__name__}: {exc}", "recheck": {}, "status": "inconclusive"}]
    print(json.dumps({"findings": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
