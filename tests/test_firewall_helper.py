"""The root firewall helper (deploy/rakshak-fw) must accept only Rakshak's own chain operations."""
import importlib.machinery
import importlib.util
from pathlib import Path

import pytest

HELPER = Path(__file__).resolve().parents[1] / "deploy" / "rakshak-fw"


@pytest.fixture()
def fw(monkeypatch):
    loader = importlib.machinery.SourceFileLoader("rakshak_fw", str(HELPER))
    spec = importlib.util.spec_from_loader("rakshak_fw", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    calls = []
    monkeypatch.setattr(mod.os, "execv", lambda path, argv: calls.append(argv))
    monkeypatch.setattr(mod.os.path, "isfile", lambda p: True)
    mod.calls = calls
    return mod


@pytest.mark.parametrize("args", [
    ["4", "-S", "RAKSHAK-BLOCK"],
    ["4", "-C", "INPUT", "-j", "RAKSHAK-BLOCK"],
    ["4", "-A", "RAKSHAK-BLOCK", "-s", "203.0.113.7/32", "-j", "DROP"],
    ["4", "-D", "RAKSHAK-BLOCK", "-s", "10.99.0.2/32", "-j", "DROP"],
    ["6", "-C", "RAKSHAK-BLOCK", "-s", "2001:db8::7/128", "-j", "DROP"],
])
def test_allowed_calls_are_passed_through_with_lock_wait(fw, args):
    fw.main(args)
    assert fw.calls and fw.calls[0][1] == "-w" and fw.calls[0][2:] == args[1:]


@pytest.mark.parametrize("args", [
    [], ["4"], ["5", "-S", "RAKSHAK-BLOCK"],
    ["4", "-F"], ["4", "-X", "RAKSHAK-BLOCK"], ["4", "-S"],
    ["4", "-I", "INPUT", "1", "-j", "ACCEPT"],
    ["4", "-A", "INPUT", "-s", "203.0.113.7/32", "-j", "DROP"],
    ["4", "-A", "RAKSHAK-BLOCK", "-s", "203.0.113.7/32", "-j", "ACCEPT"],
    ["4", "-A", "RAKSHAK-BLOCK", "-s", "0.0.0.0/0", "-j", "DROP"],
    ["4", "-A", "RAKSHAK-BLOCK", "-s", "10.0.0.0/8", "-j", "DROP"],
    ["4", "-A", "RAKSHAK-BLOCK", "-s", "127.0.0.1/32", "-j", "DROP"],
    ["4", "-A", "RAKSHAK-BLOCK", "-s", "169.254.1.1/32", "-j", "DROP"],
    ["4", "-A", "RAKSHAK-BLOCK", "-s", "224.0.0.1/32", "-j", "DROP"],
    ["6", "-A", "RAKSHAK-BLOCK", "-s", "203.0.113.7/32", "-j", "DROP"],
    ["6", "-A", "RAKSHAK-BLOCK", "-s", "::1/128", "-j", "DROP"],
    ["4", "-A", "RAKSHAK-BLOCK", "-s", "203.0.113.7/32", "-j", "DROP", "-i", "lo"],
    ["4", "-A", "RAKSHAK-BLOCK", "-s", "not-an-ip", "-j", "DROP"],
])
def test_everything_else_is_refused(fw, args):
    with pytest.raises(SystemExit) as exc:
        fw.main(args)
    assert exc.value.code == 2 and not fw.calls
