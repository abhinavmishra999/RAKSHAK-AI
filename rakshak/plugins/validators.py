"""Independent validation of failed observations.

Only Rakshak-owned validator code can assign validation statuses.  A plugin's
``confirmed`` or ``validated`` fields are ignored by findings.clean().
"""
import socket
from urllib.parse import urlsplit

from . import webchecks


def _host_for_target(target):
    try:
        u = urlsplit(target)
        return u.hostname if u.scheme else target.strip("[]")
    except Exception:
        return ""


def validate_findings(plugin, target, findings):
    """Return findings with independent status fields set for failed findings."""
    out = []
    for f in findings:
        f = dict(f)
        if f.get("passed"):
            f["status"] = "observed_pass"
            out.append(f)
            continue
        if f.get("status") in ("inconclusive", "info"):
            # The first observation itself did not succeed (or is informational). A re-check
            # must never upgrade it to "confirmed": that would report something never observed.
            f["validation_evidence"] = ("Not re-checked: the first observation was inconclusive."
                                        if f["status"] == "inconclusive" else "Informational; not re-checked.")
            out.append(f)
            continue
        spec = f.get("recheck") if isinstance(f.get("recheck"), dict) else {}
        kind = spec.get("kind")
        reproduced, evidence = None, ""
        if plugin.validator == "tcp_open" and kind == "tcp_open":
            try:
                port = int(spec.get("port", ""))
                if not 1 <= port <= 65535:
                    raise ValueError
                host = _host_for_target(target)
                with socket.create_connection((host, port), timeout=2.0):
                    reproduced = True
                evidence = f"Independent TCP connection to {host}:{port} succeeded."
            except (ValueError, OSError, socket.timeout) as exc:
                if isinstance(exc, ValueError):
                    evidence = "Independent TCP re-check refused an invalid port."
                else:
                    reproduced = False
                    evidence = f"Independent TCP connection did not succeed: {exc.__class__.__name__}."
        elif plugin.validator == "http_recheck" and plugin.builtin and kind:
            # Only the built-in website-check is permitted to request HTTP probes.
            if plugin.id != "website-check" or plugin.target_type != "url":
                reproduced = None
                evidence = "HTTP validator refused: only built-in website-check may issue these probes."
            else:
                reproduced, evidence = webchecks.recheck(target, spec)
        else:
            evidence = "No independent validator is available for this finding."
        if reproduced is True:
            f["status"] = "confirmed"
        elif reproduced is False:
            f["status"] = "not_reproduced"
        else:
            f["status"] = "inconclusive"
        f["validation_evidence"] = str(evidence)[:600]
        out.append(f)
    return out
