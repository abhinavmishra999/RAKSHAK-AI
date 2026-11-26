"""System security sensors (the machine itself, not the network).

Four capabilities, all offline, standard library + /proc only:
  * File integrity  - critical configuration files (accounts, sudoers, keys, Rakshak's own
    scope and rules). Baseline hashes are recorded once; any later difference is a finding.
    Readable file contents are also copied into a private vault so an APPROVED remediation
    can restore the original bytes and verify the restore against the recorded hash.
  * Accounts        - /etc/passwd and /etc/group: new login users, anything becoming uid 0,
    new sudo/wheel members.
  * Listening ports - /proc/net/tcp(6): a new service opening a port on this machine,
    attributed to the owning process (pid, uid, name, command line) via /proc/<pid>/fd,
    so a remediation can stop exactly the process holding the unauthorised socket.
  * Accepted changes - an analyst or admin can mark a confirmed change as sanctioned;
    the ledger records who accepted which object, when, so re-occurrences stay honest.

Each finding becomes a real event row (source "system") inside the same hash-chained store,
an incident, and an immediate independent re-check: the sensor looks at the live system again
before the alert is shown as "Evidence re-checked". Host findings are never network-blocked -
there is no attacker IP to contain - so their response is guidance, an optional verified
remediation (restore / stop / lock, behind approval) plus a report.
"""
import hashlib
import json
import os
import time
from pathlib import Path

SECURITY_FILES = {"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
                  "/etc/ssh/sshd_config", "/etc/sudoers.d", "/etc/crontab", "/var/spool/cron"}

VAULT_MAX_BYTES = 4 * 1024 * 1024  # content copies only for small, readable files


def _read(path):
    try:
        return Path(path).read_bytes()
    except (OSError, PermissionError):
        return None


def file_state(path):
    p = Path(path)
    st = None
    try:
        st = p.stat()
    except OSError:
        return {"exists": False}
    data = _read(path)
    out = {"exists": True, "size": st.st_size, "mtime": int(st.st_mtime),
           "mode": oct(st.st_mode & 0o7777), "uid": st.st_uid, "gid": st.st_gid}
    if data is not None:
        out["sha256"] = hashlib.sha256(data).hexdigest()
    return out


def proc_for_inode(inode):
    """Which process owns socket:[inode]? Walks /proc/<pid>/fd; needs no root for
    same-user processes and simply returns None for sockets we are not allowed to see."""
    if not inode:
        return None
    target = f"socket:[{inode}]"
    best = None
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            fd_dir = Path(f"/proc/{pid}/fd")
            for fd in os.listdir(fd_dir):
                try:
                    if os.readlink(fd_dir / fd) == target:
                        uid = os.stat(f"/proc/{pid}").st_uid
                        name = Path(f"/proc/{pid}/comm").read_text(errors="replace").strip()[:60]
                        cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")[:200].strip()
                        return {"pid": pid, "uid": uid, "name": name, "cmdline": cmd}
                except OSError:
                    continue
        except (OSError, PermissionError):
            continue
    return best


def listen_snapshot(proc_files):
    """Local ports from /proc/net/tcp(6). state 0A = LISTEN.
    Returns {'ip:port': {'raw': line summary, 'inode': socket inode}} (tolerates old str values)."""
    out = {}
    for name in proc_files:
        try:
            lines = Path(name).read_text().splitlines()[1:]
        except OSError:
            continue
        for ln in lines:
            parts = ln.split()
            if len(parts) < 10 or parts[3] != "0A":
                continue
            local = parts[1]
            hex_ip, hex_port = local.split(":")
            port = int(hex_port, 16)
            if len(hex_ip) == 8:                      # ipv4, little endian
                b = bytes.fromhex(hex_ip)
                ip = ".".join(str(x) for x in reversed(b))
            else:                                     # ipv6: show as :: when all zero
                ip = "::" if hex_ip == "0" * 32 else hex_ip
            out[f"{ip}:{port}"] = {
                "raw": f"{name.split('/')[-1]} listen {ip}:{port} uid={parts[7]}",
                "inode": parts[9]}
    return out


def port_line(obs) -> str:
    """Value stored for a listener finding may be a dict (new) or str (old state files)."""
    return obs.get("raw") if isinstance(obs, dict) else str(obs)


def account_snapshot(passwd_file, group_file):
    users, groups = {}, {}
    data = _read(passwd_file)
    if data:
        for ln in data.decode(errors="replace").splitlines():
            f = ln.split(":")
            if len(f) >= 7:
                users[f[0]] = {"uid": f[2], "gid": f[3], "shell": f[6]}
    data = _read(group_file)
    if data:
        for ln in data.decode(errors="replace").splitlines():
            f = ln.split(":")
            if len(f) >= 4:
                groups[f[0]] = set(x for x in f[3].split(",") if x)
    return users, groups


def state_sig(st):
    """What counts as 'the same file': existence, content hash (or size when unreadable),
    permissions and owner. mtime alone is deliberately EXCLUDED: attackers
    roll back timestamps, and a touched-but-unchanged file is not tampering evidence."""
    if not st.get("exists"):
        return ("gone",)
    return (st.get("sha256") if st.get("sha256") is not None else f"size:{st.get('size')}",
            st.get("mode"), st.get("uid"), st.get("gid"))


class Vault:
    """Content-addressed copies of watched file states, so remediation can prove it
    restored exactly what the sensor recorded. Only reachable by the service user."""

    def __init__(self, data_dir):
        self.root = Path(data_dir) / "vault"
        self.blobs = self.root / "blobs"
        try:
            self.blobs.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError:
            pass

    def _blob(self, sha):
        return self.blobs / sha

    def has(self, sha):
        return bool(sha) and self._blob(sha).exists()

    def load(self, sha):
        data = _read(self._blob(sha))
        if data is None or hashlib.sha256(data).hexdigest() != sha:
            return None      # blob edited outside Rakshak: refuse to restore from it
        return data

    def save_content(self, sha, data):
        if not data or len(data) > VAULT_MAX_BYTES or hashlib.sha256(data).hexdigest() != sha:
            return False
        if self.has(sha):
            return True
        tmp = self._blob(sha).with_suffix(".tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            tmp.replace(self._blob(sha))
            return True
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass
            return False

    def ensure(self, path, cur_state):
        """Keep a copy of the current content of a watched readable file."""
        sha = cur_state.get("sha256")
        if not sha or self.has(sha) or (cur_state.get("size") or 0) > VAULT_MAX_BYTES:
            return
        data = _read(path)
        if data is not None:
            self.save_content(sha, data)

    def count(self):
        try:
            return len(list(self.blobs.glob("*")))
        except OSError:
            return 0


class HostSecurity:
    def __init__(self, conf, store, audit, vault=None):
        self.conf, self.store, self.audit = conf, store, audit
        self.vault = vault
        self.state_path = Path(conf.data_dir) / "hostsec_state.json"
        self.state = self._load()
        self.last_scan = 0.0
        self.findings_total = 0
        self.watched = [str(p) for p in conf.fim_paths]
        self.priv_files = {p for p in self.watched
                           if p in SECURITY_FILES or p.endswith("/scope.yml") or "/rules" in p}

    # ---------- persistence ----------
    def _load(self):
        try:
            return json.loads(self.state_path.read_text())
        except (OSError, ValueError):
            return {"baseline": {}, "accounts": {}, "groups": {}, "ports": {}, "accepted": {}}

    def _save(self):
        tmp = self.state_path.with_suffix(".tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(self.state, fh)
            tmp.replace(self.state_path)
        except OSError:
            pass

    # ---------- scanning ----------
    def scan(self):
        """One pass. Returns fresh findings (and records them). First pass only baselines."""
        now = time.time()
        self.last_scan = now
        findings = []
        baseline_first = not self.state["baseline"] and not self.state["ports"]
        if self.vault is None:
            self.vault = Vault(self.conf.data_dir)
        for path in self.watched:
            cur = file_state(path)
            self.vault.ensure(path, cur)
            old = self.state["baseline"].get(path)
            if old is None:
                self.state["baseline"][path] = cur
                continue
            if state_sig(old) == state_sig(cur):
                continue
            critical = path in self.priv_files
            findings.append(self._mk("file_integrity",
                "high" if critical else "medium",
                f"HOST-FIM-001 {'protected' if critical else 'watched'} file changed",
                path, cur, old))
            self.state["baseline"][path] = cur
        users, groups = account_snapshot(self.conf.passwd_file, self.conf.group_file)
        if self.state["accounts"]:
            for name in sorted(set(users) - set(self.state["accounts"])):
                u = users[name]
                sev = "critical" if u["uid"] == "0" else ("high" if u["shell"].endswith(("sh", "bash")) else "medium")
                findings.append(self._mk("account_change", sev, "HOST-ACC-001 new account",
                                         f"passwd:{name}", users[name], {"absent": True}))
            for name, u in self.state["accounts"].items():
                cur = users.get(name)
                if cur and cur["uid"] == u["uid"]:
                    continue
                if cur is None:
                    findings.append(self._mk("account_change", "medium",
                                             "HOST-ACC-002 account removed", f"passwd:{name}",
                                             {"absent": True}, u))
                else:
                    findings.append(self._mk("account_change", "critical",
                                             "HOST-ACC-003 account changed (uid/group/shell)",
                                             f"passwd:{name}", cur, u))
        else:
            for name, u in users.items():
                if u["uid"] == "0" and name != "root":
                    findings.append(self._mk("account_change", "critical",
                                             "HOST-ACC-004 extra uid-0 account present", f"passwd:{name}", u, {}))
        for gname in ("sudo", "wheel"):
            members = groups.get(gname, set())
            known = set(self.state["groups"].get(gname, []))
            for m in sorted(members - known):
                findings.append(self._mk("account_change", "high",
                                         f"HOST-ACC-005 added to {gname} group", f"group:{gname}:{m}",
                                         {"member": m}, {"absent": True}))
        self.state["accounts"] = users
        self.state["groups"] = {g: sorted(m) for g, m in groups.items()}
        ports = listen_snapshot(self.conf.proc_net_files)
        if self.state["ports"]:
            own = f":{self.conf.port}"
            for key in sorted(set(ports) - set(self.state["ports"])):
                if key.endswith(own):     # our own console socket (worker restart), not an intruder
                    continue
                obs = dict(ports[key])
                obs["process"] = proc_for_inode(obs.get("inode"))
                findings.append(self._mk("new_service", "high", "HOST-LISTEN-001 new listening socket",
                                         key, obs, {"absent": True}))
        self.state["ports"] = ports
        self._save()
        if baseline_first:
            self.audit.write("system", "hostsec.baseline", json.dumps(
                {"files": len(self.state["baseline"]), "ports": len(ports), "accounts": len(users)}))
            return []
        return findings

    def _mk(self, category, severity, name, obj, observed, previous):
        shown = port_line(observed) if category == "new_service" else observed
        det = {"rule_id": name.split()[0], "category": category, "severity": severity,
               "name": name, "matched": str(obj), "before": previous, "found": observed}
        return {"category": category, "severity": severity, "object": str(obj),
                "detection": det, "observed": observed, "previous": previous,
                "evidence": [f"host {category} {obj}: before={json.dumps(previous)} after={json.dumps(shown)}"]}

    # ---------- analyst acceptance ----------
    def accept(self, obj, actor):
        """Record that a person sanctioned the current state of this object.
        The baseline already advanced to the current state on detection, so this is
        the LEDGER of who said it is fine - used by reports and by the re-check note."""
        self.state.setdefault("accepted", {})[str(obj)] = {"ts": time.time(), "actor": actor}
        self._save()
        self.audit.write(actor, "hostsec.accepted", str(obj))
        return True

    def accepted_by(self, obj):
        return self.state.get("accepted", {}).get(str(obj))

    # ---------- independent re-check ----------
    def recheck(self, inc):
        """Look at the live system again for a stored host finding."""
        if not inc["detections"]:
            return False, "incident carries no host detection to re-check"
        det = inc["detections"][0]
        obj, cat = str(det.get("matched") or ""), inc["category"]
        before = det.get("before")
        try:
            if cat == "file_integrity":
                cur = file_state(obj)
                if before is None:
                    return False, "finding carries no recorded original state"
                ok = state_sig(cur) != state_sig(before)
                return ok, ("file still differs from its recorded original state" if ok
                           else "file now matches the recorded original state again (change reverted)")
            if cat == "new_service":
                ports = listen_snapshot(self.conf.proc_net_files)
                ok = obj in ports
                return ok, (f"{obj} is still listening" if ok else f"{obj} is no longer listening")
            if cat == "account_change":
                users, groups = account_snapshot(self.conf.passwd_file, self.conf.group_file)
                kind = det.get("name", "")
                if "new account" in kind or "extra uid-0" in kind:
                    name = obj.split(":")[-1]
                    ok = name in users
                    return ok, (f"account {name} exists" if ok else f"account {name} no longer exists")
                if "removed" in kind:
                    name = obj.split(":")[-1]
                    ok = name not in users
                    return ok, (f"account {name} is indeed absent" if ok else f"account {name} exists again")
                if "added to" in kind:
                    parts = obj.split(":")
                    ok = parts[-1] in groups.get(parts[1], set())
                    return ok, (f"{parts[-1]} is still in {parts[1]}" if ok else f"membership not present now")
                name = obj.split(":")[-1]
                expected = det.get("found")
                ok = users.get(name) == expected
                return ok, (f"account {name} still shows the changed attributes" if ok
                            else "account no longer shows the reported attributes")
        except (ValueError, IndexError, KeyError, TypeError) as exc:
            return False, f"re-check could not evaluate the stored finding ({type(exc).__name__}: {exc})"
        return False, "no re-check exists for this host finding"

    def status(self):
        return {"enabled": True, "interval_s": self.conf.hostsec_interval,
                "last_scan": self.last_scan, "findings_total": self.findings_total,
                "watched_files": len(self.watched), "baselined": bool(self.state.get("baseline")),
                "ports_listening": len(self.state.get("ports", {})),
                "accounts_known": len(self.state.get("accounts", {})),
                "vault_copies": self.vault.count() if self.vault else 0,
                "accepted_changes": len(self.state.get("accepted", {}))}
