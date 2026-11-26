import hashlib
import http.server
import json
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from rakshak.audit import AuditLog, load_key
from rakshak.config import Settings
from rakshak.plugins import webchecks
from rakshak.plugins.findings import parse_json_findings
from rakshak.plugins.runner import PluginRunner
from rakshak.store import Store

ROOT = Path(__file__).resolve().parents[1]
BUILTINS = ROOT / "rakshak" / "plugins" / "builtin"


class _Handler(http.server.BaseHTTPRequestHandler):
    mode = "catchall"

    def do_GET(self):
        if self.mode == "errors":
            body, code = b"not found", 404
        else:
            body, code = b"<html><body>normal page</body></html>", 200
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class PluginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.data = self.root / "data"
        self.plugins = self.root / "plugins"
        self.data.mkdir()
        self.plugins.mkdir()
        (self.data / "scope.yml").write_text("networks: ['127.0.0.0/8']\nhosts: ['localhost']\n")
        self.store = Store(self.data / "rakshak.sqlite3")
        self.audit = AuditLog(self.store, load_key(self.data / "signing.key"))
        self.conf = Settings(data_dir=self.data, plugins_dir=self.plugins, builtin_plugins=BUILTINS,
                             plugin_user="")
        self.old_external = os.environ.pop("RAKSHAK_ALLOW_EXTERNAL_PLUGINS", None)
        self.runner = PluginRunner(self.conf, self.store, self.audit)

    def tearDown(self):
        if self.old_external is not None:
            os.environ["RAKSHAK_ALLOW_EXTERNAL_PLUGINS"] = self.old_external
        else:
            os.environ.pop("RAKSHAK_ALLOW_EXTERNAL_PLUGINS", None)
        self.store.conn.close()
        self.tmp.cleanup()

    def plugin(self, name, body, timeout=5, cap=32, validator="none"):
        folder = self.plugins / name
        folder.mkdir()
        (folder / "tool.py").write_text(body)
        (folder / "plugin.yml").write_text(f'''id: {name}
name: Test {name}
version: "1"
description: test
source: test
kind: active
approval: admin
interpreter: python
executable: tool.py
sha256: ""
target_type: host
args: ["{{target}}"]
timeout_s: {timeout}
max_output_kb: {cap}
parser: json_findings
validator: {validator}
''')
        os.environ["RAKSHAK_ALLOW_EXTERNAL_PLUGINS"] = "1"
        self.runner.reload()
        return name

    def enable_external(self, name):
        os.environ["RAKSHAK_ALLOW_EXTERNAL_PLUGINS"] = "1"
        return self.runner.enable(name, "admin")

    def request(self, name, target="127.0.0.1"):
        return self.runner.request(name, target, "requester", "approved asset test", True)

    def test_builtin_listing_is_available_but_disabled_and_enable_pins_hash(self):
        os.environ.pop("RAKSHAK_ALLOW_EXTERNAL_PLUGINS", None)
        listed = {x["id"]: x for x in self.runner.list()}
        self.assertIn("website-check", listed)
        self.assertFalse(listed["website-check"]["enabled"])
        self.assertTrue(listed["website-check"]["available"])
        enabled = self.runner.enable("website-check", "admin")
        self.assertTrue(enabled["enabled"])
        self.assertTrue(enabled["trusted_hash"])
        self.assertEqual(self.store.get_plugin_state("website-check")["exec_sha256"], enabled["trusted_hash"])

    def test_request_is_pending_and_requires_explicit_approve(self):
        name = self.plugin("pending", 'import json; print(json.dumps({"findings": []}))')
        self.enable_external(name)
        run = self.request(name)
        self.assertEqual(run["status"], "queued")
        self.assertEqual(self.store.get_run(run["id"])["status"], "queued")
        self.assertEqual(run["summary"]["approved_target_ips"], ["127.0.0.1"])
        self.assertNotIn(run["status"], ("completed", "failed"))

    def test_reject_and_approval_role_and_two_person_constraints(self):
        name = self.plugin("approval", 'import json; print(json.dumps({"findings": []}))')
        self.enable_external(name)
        queued = self.request(name)
        refused_role = self.runner.approve(queued["id"], "approver", "viewer")
        self.assertEqual(refused_role["status"], "refused")
        self.conf.two_person = True
        queued_two_person = self.request(name)
        refused_two_person = self.runner.approve(queued_two_person["id"], "requester", "admin")
        self.assertEqual(refused_two_person["status"], "refused")
        queued_reject = self.request(name)
        rejected = self.runner.reject(queued_reject["id"], "admin", "not in the maintenance window")
        self.assertEqual(rejected["status"], "refused")
        self.assertIn("maintenance", rejected["reason"])

    def test_modified_hash_refused_at_approval(self):
        name = self.plugin("hashcheck", 'import json; print(json.dumps({"findings": []}))')
        self.enable_external(name)
        run = self.request(name)
        with (self.plugins / name / "tool.py").open("a") as fh:
            fh.write("\n# changed after request\n")
        result = self.runner.approve(run["id"], "approver", "admin")
        self.assertEqual(result["status"], "refused")
        self.assertIn("changed", result["reason"].lower())
        self.assertTrue(self.runner.view(run["id"])["verified"])

    def test_disabled_out_of_scope_never_scan_and_attacker_refuse(self):
        name = self.plugin("refusals", 'import json; print(json.dumps({"findings": []}))')
        with self.assertRaises(ValueError):
            self.runner.request(name, "127.0.0.1", "u", "why", True)
        self.enable_external(name)
        with self.assertRaises(ValueError):
            self.runner.request(name, "192.0.2.1", "u", "why", True)
        (self.data / "scope.yml").write_text("networks: ['127.0.0.0/8']\nnever_scan: ['127.0.0.1']\n")
        with self.assertRaises(ValueError):
            self.runner.request(name, "127.0.0.1", "u", "why", True)
        (self.data / "scope.yml").write_text("networks: ['127.0.0.0/8']\n")
        self.store.block("127.0.0.1", "test attacker")
        with self.assertRaises(ValueError):
            self.runner.request(name, "127.0.0.1", "u", "why", True)
        self.runner.disable(name, "admin")
        with self.assertRaises(ValueError):
            self.runner.request(name, "127.0.0.1", "u", "why", True)

    def test_output_cap_and_timeout_fail_without_successful_parsing(self):
        cap = self.plugin("capcheck", 'import sys; sys.stdout.write("x" * 1000000); sys.stdout.flush()', cap=1)
        self.enable_external(cap)
        r1 = self.runner.approve(self.request(cap)["id"], "approver", "admin")
        self.assertEqual(r1["status"], "failed")
        self.assertEqual(r1["findings"], [])
        timeout = self.plugin("timeoutcheck", 'import time; time.sleep(5)', timeout=1, cap=4)
        self.enable_external(timeout)
        r2 = self.runner.approve(self.request(timeout)["id"], "approver", "admin")
        self.assertEqual(r2["status"], "failed")
        self.assertEqual(r2["findings"], [])

    def test_invalid_plugin_boolean_schema_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_json_findings('{"findings": [{"id":"x", "passed":"false"}]}')

    def _server(self, mode):
        _Handler.mode = mode
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        return f"http://127.0.0.1:{server.server_port}"

    def test_catchall_does_not_report_secret_file_and_http_errors_are_inconclusive(self):
        base = self._server("catchall")
        results = webchecks.run_all(base)
        env = next(x for x in results if x["id"] == "FILE-/.env")
        self.assertTrue(env["passed"])
        self.assertEqual(env["status"], "observed_pass")
        self.assertNotIn("exposed", env["title"].lower())
        _Handler.mode = "errors"
        errors = webchecks.run_all(base)
        self.assertTrue(any(x["status"] == "inconclusive" for x in errors))
        self.assertFalse(any(x["status"] == "observed_pass" for x in errors))

    def test_builtin_website_numeric_url_and_independent_statuses(self):
        base = self._server("catchall")
        self.runner.enable("website-check", "admin")
        run = self.runner.request("website-check", base, "u", "local website", True)
        result = self.runner.approve(run["id"], "approver", "admin")
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["findings"])
        self.assertTrue(any(x["status"] in ("confirmed", "not_reproduced", "inconclusive") for x in result["findings"] if not x["passed"]))
        with self.assertRaises(ValueError):
            self.runner.request("website-check", "http://localhost:80", "u", "dns not allowed", True)
        with self.assertRaises(ValueError):
            self.runner.request("website-check", base + "/user?q=1", "u", "path not allowed", True)

    @unittest.skipUnless(shutil.which("nmap"), "nmap is not installed")
    def test_nmap_real_local_integration_if_installed(self):
        self.runner.enable("nmap-ports", "admin")
        run = self.runner.request("nmap-ports", "127.0.0.1", "u", "local nmap test", True)
        result = self.runner.approve(run["id"], "approver", "admin")
        self.assertIn(result["status"], ("completed", "failed"))
        if result["status"] == "completed":
            self.assertIsInstance(result["findings"], list)

    def test_run_signature_verified_then_detects_persisted_field_change(self):
        name = self.plugin("signature", 'import json; print(json.dumps({"findings": []}))')
        self.enable_external(name)
        run = self.runner.approve(self.request(name)["id"], "approver", "admin")
        self.assertTrue(self.runner.view(run["id"])["verified"])
        self.store.update_run(run["id"], reason="tampered")
        self.assertFalse(self.runner.view(run["id"])["verified"])


if __name__ == "__main__":
    unittest.main()
