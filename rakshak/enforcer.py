"""Block enforcement back-ends.

The default ``none`` backend records decisions and exports advisory rules only.
Nftables is deliberately opt-in through an existing explicit environment setting;
this module never broadens sudo or runs as root by default.
"""
import ipaddress
import os
import re
import shlex
import subprocess

TABLE = "rakshak"
SETUP = """
table inet rakshak {
    set blocklist4 { type ipv4_addr; flags timeout; }
    set blocklist6 { type ipv6_addr; flags timeout; }
    chain input {
        type filter hook input priority -10; policy accept;
        ip saddr @blocklist4 counter drop
        ip6 saddr @blocklist6 counter drop
    }
}
"""


class NoEnforcer:
    name = "none"

    def status(self):
        return {"name": self.name, "ready": False,
                "detail": "Blocks are recorded but NOT applied to the network. Export rules for a separately reviewed firewall change."}

    def block(self, ip, ttl):
        return {"state": "not_enforced", "detail": "not applied to the network (enforcer = none)"}

    def unblock(self, ip):
        return {"state": "not_enforced", "detail": "nothing to remove (enforcer = none)"}

    def is_blocked(self, ip):
        return None


class NftEnforcer:
    name = "nftables"

    def __init__(self, cmd="nft"):
        self.cmd = shlex.split(cmd)
        self.ready, self.error = False, ""
        self._setup()

    def _run(self, args, stdin=None):
        proc = subprocess.run(self.cmd + args, input=stdin, capture_output=True, text=True, timeout=10)
        return proc.returncode, (proc.stdout + proc.stderr).strip()

    def _setup(self):
        try:
            rc, out = self._run(["list", "table", "inet", TABLE])
            if rc == 0:
                self.ready, self.error = True, ""
                return
            # Never create a firewall table on a real system implicitly. A test
            # double may opt in to setup so its missing-table path is testable.
            if os.environ.get("RAKSHAK_NFT_TEST_SETUP") == "1":
                rc, out = self._run(["-f", "-"], stdin=SETUP)
            self.ready = rc == 0
            self.error = "" if self.ready else out[:300] or "dedicated nftables table is absent"
        except (OSError, subprocess.SubprocessError) as exc:
            self.ready, self.error = False, f"{type(exc).__name__}: {exc}"

    def status(self):
        if self.ready:
            return {"name": self.name, "ready": True,
                    "detail": "Blocks are applied to this server's firewall (nftables table 'inet rakshak'). Stale set reconciliation is not performed automatically."}
        return {"name": self.name, "ready": False,
                "detail": f"nftables is not usable or its dedicated table is absent: {self.error}"}

    @staticmethod
    def _set(ip):
        return "blocklist6" if ipaddress.ip_address(ip).version == 6 else "blocklist4"

    @staticmethod
    def _contains_exact(out, ip):
        """Match a canonical address token, never a substring of another address."""
        needle = str(ipaddress.ip_address(ip))
        for token in re.split(r"[\s,;{}]+", out or ""):
            token = token.strip('"')
            try:
                if str(ipaddress.ip_address(token)) == needle:
                    return True
            except ValueError:
                continue
        return False

    def is_blocked(self, ip):
        rc, out = self._run(["list", "set", "inet", TABLE, self._set(ip)])
        if rc != 0:
            return None
        return self._contains_exact(out, ip)

    def block(self, ip, ttl):
        if not self.ready:
            return {"state": "failed", "detail": f"NOT applied: {self.error}"}
        element = f"{{ {ip} timeout {int(ttl)}s }}" if ttl > 0 else f"{{ {ip} }}"
        rc, out = self._run(["add", "element", "inet", TABLE, self._set(ip), element])
        if rc != 0:
            return {"state": "failed", "detail": f"NOT applied: nft error: {out[:200]}"}
        if self.is_blocked(ip):
            return {"state": "enforced", "detail": f"applied and verified in nftables set {self._set(ip)}"}
        return {"state": "failed", "detail": "nft accepted the command but the address is not in the set"}

    def unblock(self, ip):
        if not self.ready:
            return {"state": "failed", "detail": f"not removed: {self.error}"}
        if self.is_blocked(ip):
            rc, out = self._run(["delete", "element", "inet", TABLE, self._set(ip), f"{{ {ip} }}"])
            if rc != 0:
                return {"state": "failed", "detail": f"nft error: {out[:200]}"}
        if self.is_blocked(ip) is False:
            return {"state": "removed", "detail": "removed from nftables and verified"}
        return {"state": "failed", "detail": "could not confirm removal"}


def make_enforcer(conf):
    # A dataclass override alone must not activate a host firewall. Activation
    # requires the explicit pre-existing environment selection as well.
    if (getattr(conf, "enforcer", "none") == "nftables" and
            os.environ.get("RAKSHAK_ENFORCER") == "nftables"):
        return NftEnforcer(getattr(conf, "nft_cmd", "nft"))
    if (getattr(conf, "enforcer", "none") == "iptables" and
            os.environ.get("RAKSHAK_ENFORCER") == "iptables"):
        return IptablesEnforcer(os.environ.get("RAKSHAK_IPTABLES_CMD", "iptables"),
                                os.environ.get("RAKSHAK_IP6TABLES_CMD", "ip6tables"))
    return NoEnforcer()


CHAIN = "RAKSHAK-BLOCK"


class IptablesEnforcer:
    """Manages DROP rules ONLY inside the dedicated chain RAKSHAK-BLOCK.

    An administrator creates the chain and the jump once (Rakshak never edits INPUT):
        iptables -N RAKSHAK-BLOCK
        iptables -I INPUT 1 -j RAKSHAK-BLOCK
    (and the same with ip6tables if IPv6 is used). Every add/remove is verified with
    `iptables -C` (exact rule match). iptables has no per-rule timeout, so expiry is
    done by Rakshak's own expiry loop; if Rakshak is stopped, blocks stay until removed.
    """
    name = "iptables"

    def __init__(self, cmd="iptables", cmd6="ip6tables"):
        self.cmd4, self.cmd6 = shlex.split(cmd), shlex.split(cmd6)
        self.ready, self.error = False, ""
        try:
            rc1, out1 = self._run(self.cmd4, ["-S", CHAIN])
            rc2, out2 = self._run(self.cmd4, ["-C", "INPUT", "-j", CHAIN])
            self.ready = rc1 == 0 and rc2 == 0
            if not self.ready:
                self.error = (f"chain {CHAIN} or its jump from INPUT is missing. An administrator must run: "
                              f"iptables -N {CHAIN} && iptables -I INPUT 1 -j {CHAIN}")
        except (OSError, subprocess.SubprocessError) as exc:
            self.error = f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _run(cmd, args):
        proc = subprocess.run(cmd + args, capture_output=True, text=True, timeout=10)
        return proc.returncode, (proc.stdout + proc.stderr).strip()

    def _rule(self, ip):
        addr = ipaddress.ip_address(ip)
        cmd = self.cmd6 if addr.version == 6 else self.cmd4
        return cmd, ["-s", f"{addr}/{addr.max_prefixlen}", "-j", "DROP"]

    def status(self):
        if self.ready:
            return {"name": self.name, "ready": True,
                    "detail": f"Blocks are applied to this server's firewall (iptables chain {CHAIN}) and verified. "
                              "Expiry is done by Rakshak; blocks stay in place while Rakshak is stopped."}
        return {"name": self.name, "ready": False, "detail": f"iptables is not usable: {self.error}"}

    def is_blocked(self, ip):
        cmd, rule = self._rule(ip)
        rc, out = self._run(cmd, ["-C", CHAIN] + rule)
        if rc == 0:
            return True
        return False if "does a matching rule exist" in out or "Bad rule" in out or rc == 1 else None

    def block(self, ip, ttl):
        if not self.ready:
            return {"state": "failed", "detail": f"NOT applied: {self.error}"}
        if self.is_blocked(ip) is not True:
            cmd, rule = self._rule(ip)
            rc, out = self._run(cmd, ["-A", CHAIN] + rule)
            if rc != 0:
                return {"state": "failed", "detail": f"NOT applied: iptables error: {out[:200]}"}
        if self.is_blocked(ip) is True:
            return {"state": "enforced", "detail": f"applied and verified in iptables chain {CHAIN}"}
        return {"state": "failed", "detail": "iptables accepted the command but the rule is not present"}

    def unblock(self, ip):
        if not self.ready:
            return {"state": "failed", "detail": f"not removed: {self.error}"}
        cmd, rule = self._rule(ip)
        for _ in range(10):  # remove duplicates too
            if self.is_blocked(ip) is not True:
                break
            rc, out = self._run(cmd, ["-D", CHAIN] + rule)
            if rc != 0:
                return {"state": "failed", "detail": f"iptables error: {out[:200]}"}
        if self.is_blocked(ip) is False:
            return {"state": "removed", "detail": f"removed from iptables chain {CHAIN} and verified"}
        return {"state": "failed", "detail": "could not confirm removal"}
