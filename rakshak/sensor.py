"""RAKSHAK sensor agent: watch this machine's logs, send detections' raw material to the hub.

Runs completely offline on the local network. It reads the real log files given in
RAKSHAK_LOGS (same parser as the hub), keeps its own read positions, and streams
batches of parsed events to the hub over plain HTTP with:

  * HMAC-SHA256 signature over timestamp + node + sequence + body (shared secret file),
  * a strictly increasing sequence number (the hub refuses replays),
  * a timestamp window of 120 seconds (no captured batches can be replayed later).

It never receives commands and never touches the firewall - it is a SENSE-only probe.
Respond decisions, host remediation and reports all live on the hub, with approval.

Usage (as a systemd service on each monitored machine):
    python -m rakshak.sensor --hub http://HUB:8000 --secret /etc/rakshak/sensor.key \
        --name web01 [--state /var/lib/rakshak-sensor/state.json]
Environment (same names as the console): RAKSHAK_LOGS, RAKSHAK_HUB_URL, RAKSHAK_SENSOR_SECRET,
RAKSHAK_SENSOR_NAME, RAKSHAK_SENSOR_INTERVAL (seconds, default 3).
"""
import argparse
import hashlib
import hmac
import json
import os
import socket
import sys
import time
import urllib.request
from pathlib import Path

from .config import Settings
from .parsers import parse_line


def sign(secret: bytes, ts: str, node: str, seq: int, body: bytes) -> str:
    msg = f"{ts}\n{node}\n{seq}\n{hashlib.sha256(body).hexdigest()}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


class Sensor:
    def __init__(self, hub, secret_path, name, logs, state_path, interval=3.0):
        self.hub = hub.rstrip("/")
        self.secret = Path(secret_path).read_bytes()
        self.name = name
        self.logs = [Path(x) for x in logs]
        self.state_path = Path(state_path)
        self.interval = interval
        self.seq = 0
        self.offsets = {}
        self.inodes = {}
        self._load()

    def _load(self):
        try:
            st = json.loads(self.state_path.read_text())
            self.offsets = {k: tuple(v) for k, v in st.get("offsets", {}).items()}
            self.seq = int(st.get("seq", 0))
        except (OSError, ValueError):
            pass

    def _save(self):
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"offsets": {k: list(v) for k, v in self.offsets.items()},
                                   "seq": self.seq}))
        tmp.replace(self.state_path)
        try:
            os.chmod(self.state_path, 0o600)
        except OSError:
            pass

    def _collect(self):
        events = []
        for f in self.logs:
            try:
                st = f.stat()
                size = st.st_size
            except OSError:
                continue
            prev_off, prev_ino = self.offsets.get(str(f), (None, None))
            if prev_ino != st.st_ino or prev_off is None:
                off = 0 if prev_ino != st.st_ino else (prev_off or size)
            else:
                off = prev_off if 0 <= prev_off <= size else 0
            if size == off:
                self.offsets[str(f)] = (off, st.st_ino)
                continue
            with f.open("r", errors="replace") as fh:
                fh.seek(off)
                while len(events) < 500:
                    line = fh.readline()
                    if not line or not line.endswith("\n"):
                        break
                    off = fh.tell()
                    ev = parse_line(line, source=str(f))
                    if ev:
                        events.append(ev)
                self.offsets[str(f)] = (off, st.st_ino)
        return events

    def send(self, events):
        if not events:
            return True
        self.seq += 1
        body = json.dumps({"node": self.name, "seq": self.seq, "events": events}).encode()
        ts = str(time.time())
        req = urllib.request.Request(self.hub + "/api/ingest", data=body, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "X-Rakshak-Sensor": self.name,
                                              "X-Rakshak-Timestamp": ts,
                                              "X-Rakshak-Seq": str(self.seq),
                                              "X-Rakshak-Sign": sign(self.secret, ts, self.name,
                                                                     self.seq, body)})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                ok = resp.status == 200
        except OSError as exc:
            print(f"sensor: hub unreachable: {exc}", file=sys.stderr)
            self.seq -= 1
            return False
        if ok:
            self._save()
        else:
            self.seq -= 1
        return ok

    def run(self):
        print(f"rakshak-sensor [{self.name}] -> {self.hub}; watching {len(self.logs)} file(s)",
              flush=True)
        while True:
            try:
                events = self._collect()
                if events:
                    self.send(events)
            except KeyboardInterrupt:
                return
            except Exception as exc:
                print(f"sensor loop error: {type(exc).__name__}: {exc}", file=sys.stderr)
            time.sleep(self.interval)


def main(argv=None):
    conf = Settings()
    ap = argparse.ArgumentParser(prog="rakshak.sensor")
    ap.add_argument("--hub", default=os.environ.get("RAKSHAK_HUB_URL", "http://127.0.0.1:8000"))
    ap.add_argument("--secret", default=os.environ.get("RAKSHAK_SENSOR_SECRET", ""))
    ap.add_argument("--name", default=conf.sensor_name or socket.gethostname())
    ap.add_argument("--logs", default=",".join(str(p) for p in conf.logs))
    ap.add_argument("--state", default=str(Path(conf.data_dir) / "sensor_state.json"))
    ap.add_argument("--interval", type=float, default=float(os.environ.get("RAKSHAK_SENSOR_INTERVAL", "3")))
    a = ap.parse_args(argv)
    if not a.secret:
        sys.exit("sensor: --secret (shared key file created by 'python -m rakshak.admin sensor-secret') is required")
    logs = [x.strip() for x in a.logs.split(",") if x.strip()]
    Sensor(a.hub, a.secret, a.name, logs, a.state, max(1.0, a.interval)).run()


if __name__ == "__main__":
    main()
