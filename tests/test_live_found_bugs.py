"""Regression tests for bugs found by the LIVE end-to-end run (scripts/e2e_live_check.py, 26 Nov 2026).

1. nginx gzips text/html: the bounded reader decoded the body, then rebuilt a response that still
   said Content-Encoding: gzip, so every home-page observation failed with DecodingError.
2. Secret-file paths answered with 404 were recorded as "inconclusive" instead of "not served".
3. An inconclusive first observation ("Transport status not observed") was upgraded to "confirmed".
4. Real Nmap XML always has "<!DOCTYPE nmaprun>" and was refused; open-port findings lacked "passed".
A local HTTP server on 127.0.0.1 is used; nothing leaves the machine.
"""
import gzip
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from rakshak.plugins import findings, validators, webchecks
from rakshak.report import build_plugin_report

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_real_7.94.xml"
PAGE = b"<html><body>hello</body></html>"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/bomb"):
            body = gzip.compress(b"A" * (2 * 1024 * 1024))       # 2 MiB decoded, a few KiB on the wire
            ctype = "text/html"
        elif self.path in ("/", "/?id=1", "/?id=1%27") or self.path.startswith("/?"):
            body, ctype = gzip.compress(PAGE), "text/html"       # gzip even though identity was requested
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Encoding", "gzip")
            b = gzip.compress(b"<html>not found</html>")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def gzip_site():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/"
    srv.shutdown()


def test_gzip_responses_are_observed_not_double_decoded(gzip_site):
    out = {f["id"]: f for f in webchecks.run_all(gzip_site)}
    assert "HOME-HTTP" not in out
    assert out["HDR-Content-Security-Policy"]["status"] == "suspected"
    assert out["INFO-SERVER"]["status"] == "suspected"
    assert out["TLS"]["status"] == "suspected"
    ok, ev = webchecks.recheck(gzip_site, {"kind": "header_missing", "header": "x-frame-options"})
    assert ok is True and "still missing" in ev


def test_decompression_bomb_is_capped_after_decoding(gzip_site):
    with webchecks._client() as c:
        r, err = webchecks._request(c, gzip_site + "bomb")
    assert r is None and "safety cap" in err


def test_secret_file_404_is_recorded_as_not_served(gzip_site):
    out = {f["id"]: f for f in webchecks.run_all(gzip_site)}
    f = out["FILE-/.env"]
    assert f["passed"] is True and f["status"] == "observed_pass"
    assert "404" in f["evidence"] and "not served" in f["evidence"]


def test_inconclusive_first_observation_is_never_upgraded():
    plugin = SimpleNamespace(validator="http_recheck", builtin=True, id="website-check", target_type="url")
    f = webchecks.inconclusive("TLS", "Transport status not observed", "request failed", {"kind": "scheme_http"}, "medium")
    out = validators.validate_findings(plugin, "http://10.99.0.1:8081/", [findings.clean(f)])
    assert out[0]["status"] == "inconclusive"
    assert "first observation was inconclusive" in out[0]["validation_evidence"]


def test_real_nmap_xml_is_parsed_and_open_ports_are_failed_observations():
    out = findings.parse_nmap_xml(FIXTURE.read_text())
    ports = [f for f in out if f["id"].startswith("PORT-")]
    assert ports, "fixture captured from a real scan must contain open ports"
    assert all(f["passed"] is False and f["status"] == "suspected" for f in ports)
    assert all(f["recheck"]["kind"] == "tcp_open" for f in ports)


@pytest.mark.parametrize("bad", [
    '<!DOCTYPE nmaprun [<!ENTITY a "x">]><nmaprun/>',
    '<!DOCTYPE nmaprun SYSTEM "http://example.invalid/d.dtd"><nmaprun/>',
    '<!DOCTYPE nmaprun><!DOCTYPE other><nmaprun/>',
    '<!doctype nmaprun [<!entity e "boom">]><nmaprun/>',
])
def test_hostile_xml_declarations_still_refused(bad):
    with pytest.raises(ValueError, match="DOCTYPE/ENTITY"):
        findings.parse_nmap_xml(bad)


def test_report_shows_both_observations_for_confirmed_findings(tmp_path):
    run = {"id": 5, "plugin_id": "website-check", "plugin_version": "1.0", "target": "http://10.0.0.1/",
           "verified": True, "status": "completed", "requested_by": "a", "authorised_statement": "change 42",
           "approved_by": "b", "findings": [
               {"id": "FILE-/.env", "status": "confirmed", "passed": False, "severity": "high",
                "title": "Secret-like content observed at /.env", "what": "w", "fix": "f",
                "evidence": "GET /.env -> HTTP 200", "validation_evidence": "New request: GET /.env -> HTTP 200"},
               {"id": "X", "status": "not_reproduced", "passed": False, "severity": "low", "title": "flaky",
                "evidence": "e", "validation_evidence": "gone on re-check"}]}
    pdf = build_plugin_report(run, tmp_path)
    text = subprocess.run(["pdftotext", "-layout", str(pdf), "-"], capture_output=True, text=True).stdout
    assert "Independent re-check" in text and "Confirmed findings (1)" in text
    assert "Not reproduced" in text and "gone on re-check" in text


def test_brute_force_incident_counts_the_whole_window_as_evidence(tmp_path):
    """Live run showed 'events=3' for 10 failed logins: only post-threshold lines were counted."""
    from rakshak.parsers import parse_line
    from tests.test_engine import make_engine
    engine = make_engine(tmp_path)
    ip = "198.51.100.30"
    for i in range(10):
        line = (f"2026-11-26T08:00:{i:02d}.000000+00:00 host sshd[1]: Failed password for invalid user "
                f"nosuchuser from {ip} port {40000 + i} ssh2")
        engine.process(parse_line(line))
    inc = next(i for i in engine.store.list_incidents() if i["source_ip"] == ip)
    assert inc["category"] == "brute_force"
    assert inc["event_count"] == 10            # 8 in the window at detection + 2 later
    assert len(inc["evidence"]) == 10 and all("Failed password" in e for e in inc["evidence"])
    assert inc["validation"] == "evidence_checked"
