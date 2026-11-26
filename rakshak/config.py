"""Deployment settings. Everything is read from environment variables so the same
code runs on a laptop, a VM or a systemd service without editing source files.

    RAKSHAK_DATA          data folder (database, keys, reports, scope.yml)   default ./data
    RAKSHAK_LOGS          comma-separated log files to watch                 default /var/log/auth.log
    RAKSHAK_MODE          auto | recommend                                   default recommend
    RAKSHAK_HOST/PORT     dashboard bind address                            default 127.0.0.1:8000
    RAKSHAK_TRUSTED       comma-separated source IPs never treated as attackers (e.g. your own scanner)
    RAKSHAK_NEVER_BLOCK   comma-separated IPs/CIDRs Rakshak must never block (gateways, admins)
    RAKSHAK_BLOCK_TTL     seconds a block lasts before it expires (0 = never)  default 86400
    RAKSHAK_ENFORCER      none | iptables | nftables                         default none
    RAKSHAK_IPTABLES_CMD  command for IPv4 iptables (e.g. "sudo -n /usr/local/sbin/rakshak-fw 4")
    RAKSHAK_IP6TABLES_CMD command for IPv6 ip6tables (e.g. "sudo -n /usr/local/sbin/rakshak-fw 6")
    RAKSHAK_NFT_CMD       command used for nftables                         default "nft"
    RAKSHAK_PLUGINS_DIR   folder with your own tool plugins                  default ./plugins
    RAKSHAK_ALLOW_EXTERNAL_PLUGINS 1 = list and allow your own (non-built-in) plugins
    RAKSHAK_READ_EXISTING 1 = on first start, read existing log history (default: start at the end)
    RAKSHAK_TRUST_MODEL   1 = load a saved anomaly model file (pickle; only if you created it)
    RAKSHAK_TWO_PERSON    1 = active tests need a second person to approve   default 0
    RAKSHAK_PLUGIN_USER   run plugins as this OS user (only when Rakshak runs as root)
    RAKSHAK_ORG           organisation name printed on reports
    RAKSHAK_ALLOW_REMOTE  1 = allow binding to a non-loopback address (put TLS + firewall in front first)
    RAKSHAK_COOKIE_SECURE 1 = mark the session cookie Secure (set when served over HTTPS)
    RAKSHAK_ALLOWED_HOSTS extra Host header values accepted (comma-separated), e.g. soc.example.org
    RAKSHAK_HOSTSEC_INTERVAL seconds between system-security scans (0 = off)     default 30
    RAKSHAK_FIM_PATHS    extra/comma-separated file-integrity watch paths (defaults cover
                         /etc/passwd, shadow, group, sudoers, sshd_config, ~/.ssh/authorized_keys,
                         plus Rakshak's own scope.yml and rule files)
    RAKSHAK_PASSWD_FILE / RAKSHAK_GROUP_FILE  account files to read   default /etc/passwd, /etc/group
    RAKSHAK_PROC_NET_FILES  socket tables to read  default /proc/net/tcp,/proc/net/tcp6
    RAKSHAK_ACCT_CMD    hardened account helper (e.g. "sudo -n /usr/local/sbin/rakshak-acct")
                        default empty: account remediation then stays guidance-only, never ad-hoc root
    RAKSHAK_NEVER_LOCK  extra account names that no remediation may ever lock or remove
    RAKSHAK_CONF        optional file of KEY=VALUE lines (same names as the variables above);
                        real environment variables always win over the file
    RAKSHAK_SENSOR_NAME label the sensor agent uses when streaming to a hub  default hostname
"""
import shlex
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent


def _apply_conf_file():
    """Optional config file, read once at import time. KEY=VALUE, '#' comments.
    Existing environment variables are never overwritten."""
    cands = [os.environ.get("RAKSHAK_CONF"), str(BASE / "rakshak.conf"),
             str(Path(os.environ.get("RAKSHAK_DATA", BASE / "data")) / "rakshak.conf")]
    for cand in cands:
        if not cand:
            continue
        try:
            text = Path(cand).read_text()
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip().strip('"').strip("'")
            if key.startswith("RAKSHAK_") and val:
                os.environ.setdefault(key, val)
        return


_apply_conf_file()


def _list(name, default=""):
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("RAKSHAK_DATA", BASE / "data")))
    logs: list = field(default_factory=lambda: _list("RAKSHAK_LOGS", "/var/log/auth.log"))
    mode: str = field(default_factory=lambda: os.environ.get("RAKSHAK_MODE", "recommend"))
    host: str = field(default_factory=lambda: os.environ.get("RAKSHAK_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.environ.get("RAKSHAK_PORT", "8000")))
    trusted: list = field(default_factory=lambda: _list("RAKSHAK_TRUSTED"))
    never_block: list = field(default_factory=lambda: _list("RAKSHAK_NEVER_BLOCK"))
    block_ttl: int = field(default_factory=lambda: int(os.environ.get("RAKSHAK_BLOCK_TTL", "86400")))
    enforcer: str = field(default_factory=lambda: os.environ.get("RAKSHAK_ENFORCER", "none"))
    nft_cmd: str = field(default_factory=lambda: os.environ.get("RAKSHAK_NFT_CMD", "nft"))
    plugins_dir: Path = field(default_factory=lambda: Path(os.environ.get("RAKSHAK_PLUGINS_DIR", BASE / "plugins")))
    two_person: bool = field(default_factory=lambda: os.environ.get("RAKSHAK_TWO_PERSON", "0") == "1")
    plugin_user: str = field(default_factory=lambda: os.environ.get("RAKSHAK_PLUGIN_USER", ""))
    org: str = field(default_factory=lambda: os.environ.get("RAKSHAK_ORG", "Your organisation"))
    allow_remote: bool = field(default_factory=lambda: os.environ.get("RAKSHAK_ALLOW_REMOTE", "0") == "1")
    cookie_secure: bool = field(default_factory=lambda: os.environ.get("RAKSHAK_COOKIE_SECURE", "0") == "1")
    allowed_hosts: list = field(default_factory=lambda: _list("RAKSHAK_ALLOWED_HOSTS"))
    hostsec_interval: int = field(default_factory=lambda: int(os.environ.get("RAKSHAK_HOSTSEC_INTERVAL", "30")))
    fim_paths: list = field(default_factory=lambda: _list("RAKSHAK_FIM_PATHS",
        "/etc/passwd,/etc/shadow,/etc/group,/etc/sudoers,/etc/ssh/sshd_config,~/.ssh/authorized_keys"))
    passwd_file: str = field(default_factory=lambda: os.environ.get("RAKSHAK_PASSWD_FILE", "/etc/passwd"))
    group_file: str = field(default_factory=lambda: os.environ.get("RAKSHAK_GROUP_FILE", "/etc/group"))
    proc_net_files: list = field(default_factory=lambda: _list(
        "RAKSHAK_PROC_NET_FILES", "/proc/net/tcp,/proc/net/tcp6"))
    acct_cmd: list = field(default_factory=lambda: shlex.split(os.environ.get("RAKSHAK_ACCT_CMD", "")))
    never_lock: list = field(default_factory=lambda: _list("RAKSHAK_NEVER_LOCK"))
    sensor_name: str = field(default_factory=lambda: os.environ.get(
        "RAKSHAK_SENSOR_NAME", socket.gethostname() or "sensor"))
    rules_dir: Path = BASE / "rakshak" / "rules"
    imported_rules_dir: Path = field(default_factory=lambda: Path(
        os.environ.get("RAKSHAK_DATA", BASE / "data")) / "rules" / "imported")
    draft_rules_dir: Path = field(default_factory=lambda: Path(
        os.environ.get("RAKSHAK_DATA", BASE / "data")) / "rules" / "drafts")
    builtin_plugins: Path = BASE / "rakshak" / "plugins" / "builtin"
    dist: Path = BASE / "frontend" / "dist"

    def __post_init__(self):
        if self.mode not in ("auto", "recommend"):
            self.mode = "recommend"
        if self.enforcer not in ("none", "nftables", "iptables"):
            self.enforcer = "none"
        self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.hostsec_interval < 0:
            self.hostsec_interval = 0
        # File-integrity watch list: configured paths (~ expanded) plus Rakshak's own
        # scope and rule files, so tampering with what it is allowed to see is itself detected.
        watch = [os.path.expanduser(p) for p in self.fim_paths]
        watch.append(str(Path(self.data_dir) / "scope.yml"))
        watch.extend(str(p) for p in sorted(Path(self.rules_dir).glob("*.yml")))
        watch.extend(str(p) for p in sorted(Path(self.imported_rules_dir).glob("*.yml")))
        seen, dedup = set(), []
        for p in watch:
            if p not in seen:
                seen.add(p)
                dedup.append(p)
        self.fim_paths = dedup
        self.imported_rules_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
