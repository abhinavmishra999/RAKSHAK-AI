"""Harmless, bounded website observations and independent re-checks.

Only numeric-IP URLs are accepted by runner.py in this version.  HTTP clients do
not follow redirects, trust proxy environment variables, or disable TLS
verification.  A response over 128 KiB (counted AFTER decompression) is
inconclusive.  A response outside 2xx is inconclusive, except that a secret-file
path answered with 401/403/404/410 is recorded as "not served to this request"
(an observed pass, which is never proof of security).
"""
import re
import secrets
from urllib.parse import urlsplit

import httpx

MAX_RESPONSE = 128 * 1024
FILE_NOT_SERVED = {401, 403, 404, 410}
_DROP_HEADERS = {"content-encoding", "content-length", "transfer-encoding"}
SECRET_FILES = {
    "/.env": ("env", "Environment file with passwords or keys"),
    "/.git/HEAD": ("git", "Git repository metadata (lets attackers download your source code)"),
    "/backup.zip": ("zip", "Backup archive"),
    "/backup.sql": ("sql", "Database dump"),
    "/phpinfo.php": ("phpinfo", "PHP configuration page"),
}
SIGNATURES = {
    "env": lambda b: len(re.findall(rb"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\s*\S", b[:4000])) >= 2,
    "git": lambda b: b.startswith(b"ref:") and b"refs/" in b[:200],
    "zip": lambda b: b[:4] == b"PK\x03\x04",
    "sql": lambda b: re.search(rb"(?i)(create\s+table|insert\s+into|-- mysql dump|pg_dump)", b[:20000]) is not None,
    "phpinfo": lambda b: b"phpinfo()" in b[:50000] or b"PHP Version" in b[:50000],
}
SQL_ERRORS = re.compile(
    r"(you have an error in your sql syntax|sqlstate\[|unrecognized token|ora-\d{5}|pg_query\(\)|"
    r"sqlite3?\.operationalerror|unclosed quotation mark|mysql_fetch|syntax error at or near|"
    r"psycopg2\.errors|java\.sql\.sqlexception)", re.I)
HEADERS = [
    ("content-security-policy", "Content-Security-Policy", "medium",
     "Tells the browser which scripts may run. A missing header is only an observed configuration gap.",
     "Add a Content-Security-Policy header, for example: default-src 'self'."),
    ("x-frame-options", "X-Frame-Options", "medium",
     "Stops other sites from hiding your page inside a frame to trick clicks.",
     "Add X-Frame-Options: DENY (or a frame-ancestors rule in your CSP)."),
    ("x-content-type-options", "X-Content-Type-Options", "low",
     "Stops the browser from guessing file types.", "Add X-Content-Type-Options: nosniff."),
    ("referrer-policy", "Referrer-Policy", "low",
     "Controls how much of your internal URLs leak to other sites.",
     "Add Referrer-Policy: strict-origin-when-cross-origin."),
]
ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "pass": 4}


def _client():
    # identity: ask for uncompressed bodies; if a server compresses anyway, httpx decodes
    # while streaming and the size cap below applies to the decoded bytes.
    return httpx.Client(timeout=6, follow_redirects=False, verify=True, trust_env=False,
                        headers={"User-Agent": "RAKSHAK-AI-check/1.0", "Accept-Encoding": "identity"})


def _request(c, url, params=None, extra_ok=()):
    """Return a bounded in-memory response, or (None, reason)."""
    try:
        with c.stream("GET", url, params=params) as r:
            if not (200 <= r.status_code < 300 or r.status_code in extra_ok):
                return None, f"HTTP {r.status_code} is not a successful response"
            chunks, size = [], 0
            for chunk in r.iter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE:
                    return None, f"response exceeded the {MAX_RESPONSE} byte safety cap"
                chunks.append(chunk)
            # The body is already decoded: drop encoding/length headers so it is not decoded twice.
            headers = [(k, v) for k, v in r.headers.multi_items() if k.lower() not in _DROP_HEADERS]
            return httpx.Response(r.status_code, headers=headers, content=b"".join(chunks), request=r.request), ""
    except httpx.HTTPError as exc:
        return None, f"request failed: {exc.__class__.__name__}"


def base_of(url):
    u = urlsplit(url)
    return f"{u.scheme}://{u.netloc}"


def finding(id_, title, severity, passed, what, fix, evidence, recheck=None, status=None):
    return {"id": id_, "title": title, "severity": "pass" if passed else severity, "passed": bool(passed),
            "what": what, "fix": "" if passed else fix, "evidence": evidence,
            "recheck": recheck or {}, "status": status or ("observed_pass" if passed else "suspected")}


def inconclusive(id_, title, evidence, recheck=None, severity="info"):
    return finding(id_, title, severity, False,
                   "The harmless check could not establish an observation.",
                   "Retry after the endpoint returns a bounded successful response.", evidence,
                   recheck, status="inconclusive")


def check_file(c, base, path, kind):
    r, error = _request(c, base + path, extra_ok=FILE_NOT_SERVED)
    if r is None:
        return None, error
    if r.status_code in FILE_NOT_SERVED:
        return False, f"GET {path} -> HTTP {r.status_code}: not served to this request"
    exposed = r.status_code == 200 and SIGNATURES[kind](r.content[:50000])
    return exposed, (f"GET {path} -> HTTP {r.status_code}, {len(r.content)} bytes, "
                     + ("content looks like the real file" if exposed else "content is not that kind of file"))


def check_reflect(c, base):
    marker = "rk" + secrets.token_hex(4)
    probe = f"{marker}<b>x</b>"
    r, error = _request(c, base + "/", params={"q": probe, "s": probe, "search": probe})
    if r is None:
        return None, error
    html = "html" in r.headers.get("content-type", "").lower()
    reflected = html and probe in r.text
    return reflected, (f"Sent {probe}; probe "
                       + ("came back unescaped inside an HTML page" if reflected
                          else "not reflected; endpoint coverage limited"))


def check_sql_error(c, base):
    normal, nerr = _request(c, base + "/", params={"id": "1"})
    probe, perr = _request(c, base + "/", params={"id": "1'"})
    if normal is None or probe is None:
        return None, "normal/probe request inconclusive: " + (nerr or perr)
    m = SQL_ERRORS.search(probe.text or "")
    leaked = bool(m) and not SQL_ERRORS.search(normal.text or "")
    if leaked:
        return True, "Database error text observed only in the quote probe: " + m.group(0)[:80]
    return False, "No matching database error text observed in the normal/quote responses; this is not proof of query safety."


def run_all(url):
    """Run harmless checks; failed checks are observations, not exploit claims."""
    base = base_of(url)
    out = []
    with _client() as c:
        home, home_error = _request(c, base + "/")
        if home is None:
            out.append(inconclusive("HOME-HTTP", "Home response inconclusive", home_error))
            for key, name, sev, *_ in HEADERS:
                out.append(inconclusive(f"HDR-{name}", f"Could not observe {name}", home_error,
                                        {"kind": "header_missing", "header": key}, sev))
            out.append(inconclusive("INFO-SERVER", "Server header not observed", home_error,
                                    {"kind": "server_version"}, "low"))
            out.append(inconclusive("TLS", "Transport status not observed", home_error,
                                    {"kind": "scheme_http"}, "medium"))
        else:
            h = {k.lower(): v for k, v in home.headers.items()}
            html_eligible = "html" in h.get("content-type", "").lower()
            for key, name, sev, what, fix in HEADERS:
                if not html_eligible:
                    out.append(inconclusive(f"HDR-{name}", f"Could not observe {name} on a non-HTML response",
                                            f"Successful response Content-Type was {h.get('content-type', '(missing)')}",
                                            {"kind": "header_missing", "header": key}, sev))
                    continue
                present = key in h
                out.append(finding(f"HDR-{name}", f"Security header present: {name}" if present
                                   else f"Missing security header: {name}", sev, present, what, fix,
                                   f"{name}: {h[key][:120]}" if present else f"{name} was not sent by {base}/",
                                   {"kind": "header_missing", "header": key}))
            server = h.get("server", "")
            leaks = any(ch.isdigit() for ch in server)
            out.append(finding("INFO-SERVER", "Server version is visible" if leaks else "Server version is hidden",
                               "low", not leaks, "The exact server software and version is an observed disclosure.",
                               "Hide or shorten the Server header (nginx: server_tokens off;).",
                               f"Server: {server or '(not sent)'}", {"kind": "server_version"}))
            https = base.startswith("https://")
            out.append(finding("TLS", "Uses HTTPS" if https else "Connection is not encrypted (HTTP)", "medium", https,
                               "The URL scheme indicates whether this request used HTTP or HTTPS.",
                               "Serve the site over HTTPS.", f"Address scheme is {base.split(':')[0]}", {"kind": "scheme_http"}))
            if https and html_eligible and "strict-transport-security" not in h:
                out.append(finding("HDR-HSTS", "Missing security header: Strict-Transport-Security", "low", False,
                                   "The HSTS header was absent from this successful response.",
                                   "Add Strict-Transport-Security: max-age=31536000.",
                                   "Strict-Transport-Security was not sent", {"kind": "header_missing", "header": "strict-transport-security"}))
            cookies = home.headers.get_list("set-cookie")
            if cookies:
                bad = []
                for sc in cookies:
                    low = sc.lower()
                    miss = [f for f, ok in (("HttpOnly", "httponly" in low), ("SameSite", "samesite" in low),
                                            ("Secure", "secure" in low or not https)) if not ok]
                    if miss:
                        bad.append(f"{sc.split('=', 1)[0][:40]} lacks {', '.join(miss)}")
                out.append(finding("COOKIE-FLAGS", "Cookies are missing protection flags" if bad
                                   else "Cookies have protection flags", "medium", not bad,
                                   "Cookie flags are an observed response property.",
                                   "Set HttpOnly, Secure (on HTTPS) and SameSite on session cookies.",
                                   "; ".join(bad) or "All cookies carry HttpOnly/SameSite/Secure",
                                   {"kind": "cookie_flags"}))

        for path, (kind, label) in SECRET_FILES.items():
            exposed, ev = check_file(c, base, path, kind)
            if exposed is False and home is None:
                # A 404 from a site whose home page is itself failing (wrong vhost, proxy default,
                # outage) proves nothing about the real site: never turn it into a pass.
                exposed, ev = None, ev + "; the home page was not observable, so this is not treated as a pass"
            if exposed is None:
                out.append(inconclusive(f"FILE-{path}", f"Could not observe {path}", ev,
                                        {"kind": "file_exposed", "path": path}, "high"))
            else:
                out.append(finding(f"FILE-{path}", f"Secret-like content observed at {path}" if exposed
                                   else f"No signature of {path} observed", "high", not exposed,
                                   f"{label}. This is a content signature observation, not an exploit.",
                                   f"Block {path} in the web server or delete it from the site folder.", ev,
                                   {"kind": "file_exposed", "path": path}))
        refl, ev = check_reflect(c, base)
        if refl is None:
            out.append(inconclusive("XSS-REFLECT", "Reflection probe inconclusive", ev, {"kind": "reflect"}, "high"))
        else:
            out.append(finding("XSS-REFLECT", "Reflection probe returned unescaped HTML" if refl
                               else "Probe not reflected; endpoint coverage limited", "high", not refl,
                               "This is an exact reflection observation; it does not claim an XSS exploit.",
                               "Escape user input before putting it in a page.", ev, {"kind": "reflect"}))
        leak, ev = check_sql_error(c, base)
        if leak is None:
            out.append(inconclusive("SQL-ERROR", "Database-error probe inconclusive", ev, {"kind": "sql_error"}, "high"))
        else:
            out.append(finding("SQL-ERROR", "Database error text observed in quote probe" if leak
                               else "No database error text observed", "high", not leak,
                               "This is an exact error-text observation; it does not confirm SQL injection.",
                               "Use parameterised queries and show a generic error page.", ev, {"kind": "sql_error"}))
    out.sort(key=lambda f: ORDER.get(f.get("severity"), 3))
    return out


def recheck(url, spec):
    """Re-test one built-in finding from scratch. Returns (bool|None, evidence)."""
    base = base_of(url)
    kind = spec.get("kind")
    try:
        with _client() as c:
            if kind == "header_missing":
                hdr = spec.get("header", "").lower()
                r, err = _request(c, base + "/")
                if r is None:
                    return None, err
                names = {k.lower() for k in r.headers}
                return hdr not in names, f"New successful request to {base}/: {hdr} " + ("still missing" if hdr not in names else "is present now")
            if kind == "server_version":
                r, err = _request(c, base + "/")
                if r is None:
                    return None, err
                s = r.headers.get("server", "")
                return any(ch.isdigit() for ch in s), f"New successful request: Server: {s or '(not sent)'}"
            if kind == "scheme_http":
                return base.startswith("http://"), f"The address itself is {base}"
            if kind == "cookie_flags":
                r, err = _request(c, base + "/")
                if r is None:
                    return None, err
                https = base.startswith("https://")
                bad = [x for x in r.headers.get_list("set-cookie") if not all(t in x.lower() for t in ("httponly", "samesite")) or (https and "secure" not in x.lower())]
                return bool(bad), f"New request: {len(bad)} cookie(s) lack protection flags"
            if kind == "file_exposed":
                path = spec.get("path", "")
                if path not in SECRET_FILES:
                    return None, "Re-check refused: path is not allow-listed."
                exposed, ev = check_file(c, base, path, SECRET_FILES[path][0])
                return exposed, "New request: " + ev
            if kind == "reflect":
                refl, ev = check_reflect(c, base)
                return refl, "New probe with a new random marker: " + ev
            if kind == "sql_error":
                leak, ev = check_sql_error(c, base)
                return leak, "New normal/quote probe pair: " + ev
    except httpx.HTTPError as exc:
        return None, f"Re-check could not reach target: {exc.__class__.__name__}"
    return None, "No independent re-check exists for this finding type."
