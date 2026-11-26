# RAKSHAK-AI — Install it on your own machine

This is the real deployment: the console runs on the machine whose logs, accounts, ports and firewall
it protects. Everything works offline — no internet is needed after installation. The dashboard is
reachable only from the machine itself (127.0.0.1) until you deliberately expose it.

You need: **Linux** (tested on Ubuntu 22.04/24.04), **Python 3.10+** (tested with 3.12), optionally
`nmap` for port-scan tests. On Windows, use **WSL2 (Ubuntu)** — every feature, including firewall
blocking and host sensors, works there.

---

## 1. Fast start (10 minutes, personal machine or test box)

```bash
# 1. unpack the archive you received
unzip RAKSHAK-AI.zip -d rakshak-app && cd rakshak-app

# 2. start it (point it at YOUR real logs first)
RAKSHAK_LOGS=/var/log/nginx/access.log,/var/log/auth.log ./run.sh
```

First start does three things and nothing more:
- creates `.venv` (installs from `wheelhouse/` automatically if you brought one — offline install);
- creates `data/scope.yml` **empty**, so no active security test can run until you list your own assets;
- asks you to create the first **administrator**. Passwords must be 14–256 characters; they are hashed
  600,000 times with PBKDF2 and stored locally. Nothing is sent anywhere.

Open **http://127.0.0.1:8000** and sign in. If the account running Rakshak cannot read `/var/log/auth.log`,
add it: `sudo usermod -aG adm $USER` (Ubuntu/Debian), then restart.

What you should see in the first five minutes: the Guide page, your log sources listed with read
status, host-sensor baseline recorded, and — if your logs really contain attack traffic — real alerts.
With no suspicious lines the dashboard honestly says "Nothing suspicious in the last 10 minutes",
never "all safe".

## 2. Tell it what you own: `data/scope.yml`

Only assets listed here can ever be scanned or tested — anything else is refused, fail-closed.
Full format and examples: README section 2.

## 3. Firewall blocking (optional but recommended)

1. Install the root helper (it only ever touches Rakshak's own iptables chain):
   ```bash
   sudo install -m 0755 deploy/rakshak-fw /usr/local/sbin/rakshak-fw
   ```
2. Give the service user passwordless sudo for exactly that helper (`/etc/sudoers.d/rakshak`):
   ```
   rakshak ALL=(root) NOPASSWD: /usr/local/sbin/rakshak-fw
   ```
3. Add to your settings (env or `rakshak.conf`):
   ```
   RAKSHAK_ENFORCER=iptables
   RAKSHAK_IPTABLES_CMD=sudo -n /usr/local/sbin/rakshak-fw 4
   RAKSHAK_IP6TABLES_CMD=sudo -n /usr/local/sbin/rakshak-fw 6
   RAKSHAK_TRUSTED=<your scanner or VPN gateway>
   RAKSHAK_NEVER_BLOCK=<your gateway, admin jump host>
   ```
   Blocks are only *proposed*; nothing is applied until a person approves (analyst or admin, per
   your mode), every change is verified against the live firewall, and blocks expire.

4. For account-level remediation (lock/remove attacker-created accounts) install the second helper:
   ```bash
   sudo install -m 0755 deploy/rakshak-acct /usr/local/sbin/rakshak-acct
   echo "root" | sudo tee -a /usr/local/etc/rakshak-acct-deny
   # add your own service accounts to the deny file
   ```
   and set `RAKSHAK_ACCT_CMD=sudo -n /usr/local/sbin/rakshak-acct` (+ extend the sudoers line).
   Without it, the console still analyses host compromise — it just refuses the account undo with
   a clear reason instead of pretending.

## 4. Run as a service (servers)

```bash
sudo useradd --system --home /opt/rakshak --shell /usr/sbin/nologin rakshak
sudo cp -r . /opt/rakshak && sudo chown -R root:root /opt/rakshak
sudo install -d -o rakshak -g rakshak -m 0700 /var/lib/rakshak
sudo install -m 0640 deploy/rakshak.env.example /etc/rakshak/rakshak.env   # then edit it
sudo -u rakshak RAKSHAK_DATA=/var/lib/rakshak /opt/rakshak/.venv/bin/python -m rakshak.admin <you> --role admin
sudo cp deploy/rakshak.service /etc/systemd/system/   # review its hardening lines first
sudo systemctl daemon-reload && sudo systemctl enable --now rakshak
```

The code is read-only for the service user; data (DB, signing key, vault, reports) lives in
`/var/lib/rakshak` mode 0700. **Back that folder up** — the signing key and evidence chain are in it.

## 5. Team accounts and access from your desk

```bash
./.venv/bin/python -m rakshak.admin priya --role analyst   # password at a hidden prompt
./.venv/bin/python -m rakshak.admin ravi  --role viewer
```

The dashboard binds 127.0.0.1 only. The safe way in from another computer is an SSH tunnel:

```bash
ssh -L 8000:127.0.0.1:8000 you@your-server
# then open http://127.0.0.1:8000 on YOUR computer
```

To serve it on the network you must first put TLS in front (nginx/caddy reverse proxy), then set
`RAKSHAK_ALLOW_REMOTE=1`, `RAKSHAK_COOKIE_SECURE=1`, `RAKSHAK_ALLOWED_HOSTS=soc.yourorg.internal`.

## 6. Watch more than one machine (optional, offline)

On each extra server run the sensor agent; it tails that machine's logs locally and streams HMAC-signed
batches to your hub — replayed, forged or stale batches are refused:

```bash
# once on the hub:  python -m rakshak.admin sensor-secret   -> data/sensor_secret.key (copy over USB)
python -m rakshak.sensor --hub http://HUB:8000 --secret /etc/rakshak/sensor.key --name web01
```

Alerts arrive named for their machine. Enforcement still happens on the hub only.

## 7. Verify your install (never trust an unverified security tool)

```bash
PYTHONPATH=. .venv/bin/python -m pytest -q    # must print: 117 passed
```

Then exercise the product itself, honestly: sign in, open the Guide, request a Website Check against
an asset you listed in scope.yml, approve it as admin, and see the independent re-check labels.
If a step shows anything you cannot explain, stop and read the Guide page — every screen explains
itself.

## 8. Windows machines

No native Windows service yet (planned). Use **WSL2 → Ubuntu 24.04** and follow sections 1–7 inside it.
You can protect the Linux files/logs there; for the Windows event log itself the native collector is
still on the roadmap.

---

### First-run honesty checklist

- The file-integrity baseline starts now — install on a machine you believe is clean.
- Old log history is *not* re-read on first start (no stale-alert burst); use `RAKSHAK_READ_EXISTING=1`
  once if you want it.
- Detection accuracy on *your* traffic is not known until you run it for a while — start in
  "Ask me first" mode; that is also what the accuracy numbers in `docs/ACCURACY_RESULTS.md` promise
  and *do not* promise.
- Nothing phones home. There is no update channel; when you choose to update, you copy a new archive
  in yourself, offline, and re-run `run.sh`.
