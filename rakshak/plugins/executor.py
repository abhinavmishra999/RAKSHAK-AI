"""Run one reviewed plugin process without a shell.

The launcher is a separate Python child. Resource limits are applied there rather
than through an unsafe parent-side child callback in Rakshak's threaded process. The process
boundary is not a full filesystem or packet sandbox.
"""
import hashlib
import os
import pwd
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

SAFE_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}
_LAUNCHER = Path(__file__).with_name("_launch.py")


def _plugin_user(configured=""):
    if os.geteuid() != 0:
        return None, ""
    name = configured or os.environ.get("RAKSHAK_PLUGIN_USER", "")
    if not name:
        return None, ("Refused: Rakshak is running as root and RAKSHAK_PLUGIN_USER is not set. "
                      "Plugins must never run as root.")
    try:
        user = pwd.getpwnam(name)
    except KeyError:
        return None, f"Refused: RAKSHAK_PLUGIN_USER '{name}' does not exist."
    if user.pw_uid == 0:
        return None, "Refused: RAKSHAK_PLUGIN_USER must not be root."
    return user, ""


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def execute(argv, workdir: Path, timeout_s: int, max_output_kb: int,
            plugin_user: str = "", mem_mb: int = 2048):
    """Return execution metadata; timeout/cap/error results are never parseable."""
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(x, str) for x in argv):
        return {"error": "Invalid argv: executable arguments must be strings."}
    if timeout_s < 1 or max_output_kb < 1:
        return {"error": "Invalid execution limits."}
    user, user_error = _plugin_user(plugin_user)
    if user_error:
        return {"error": user_error}

    workdir.mkdir(parents=True, exist_ok=True)
    env = dict(SAFE_ENV, HOME=str(workdir), TMPDIR=str(workdir))
    cap = max_output_kb * 1024
    out, err = bytearray(), bytearray()
    truncated = timed_out = False
    start = time.monotonic()
    proc = None
    sel = selectors.DefaultSelector()
    try:
        # The launcher receives limits as argv, not inherited configuration.
        launcher_argv = [sys.executable, "-I", str(_LAUNCHER), str(timeout_s), str(mem_mb), "64", "--", *argv]
        popen_args = dict(
            cwd=str(workdir), env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
            close_fds=True, start_new_session=True,
        )
        # Python's Popen performs the credential transition before exec; an empty
        # extra_groups tuple is required to drop supplementary groups.
        if user is not None:
            popen_args.update(user=user.pw_uid, group=user.pw_gid, extra_groups=())
        proc = subprocess.Popen(launcher_argv, **popen_args)
        sel.register(proc.stdout, selectors.EVENT_READ, out)
        sel.register(proc.stderr, selectors.EVENT_READ, err)
        open_streams = 2
        parent_exited = False
        while open_streams:
            if proc.poll() is not None and not parent_exited:
                parent_exited = True
                _kill_group(proc)
            remaining = timeout_s - (time.monotonic() - start)
            if remaining <= 0:
                timed_out = True
                _kill_group(proc)
                break
            events = sel.select(timeout=min(remaining, 0.2))
            if not events and proc.poll() is not None:
                _kill_group(proc)
            for key, _ in events:
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    try:
                        sel.unregister(key.fileobj)
                    except Exception:
                        pass
                    try:
                        key.fileobj.close()
                    except Exception:
                        pass
                    open_streams -= 1
                    continue
                buf = key.data
                room = (cap if buf is out else 16384) - len(buf)
                if buf is out and len(chunk) > max(room, 0):
                    truncated = True
                    _kill_group(proc)
                    break
                if room > 0:
                    buf.extend(chunk[:room])
            if truncated or timed_out:
                break
        if truncated or timed_out:
            _kill_group(proc)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            proc.wait(timeout=2)
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except Exception:
                pass
    except OSError as exc:
        return {"error": f"Could not start the tool: {exc.strerror or exc}"}
    finally:
        sel.close()
        if proc is not None and proc.poll() is None:
            _kill_group(proc)

    raw = bytes(out)
    return {
        "exit_code": proc.returncode,
        "stdout": raw.decode("utf-8", "replace"),
        "stdout_sha256": hashlib.sha256(raw).hexdigest(),
        "stdout_bytes": len(raw),
        "truncated": truncated,
        "timed_out": timed_out,
        "stderr_tail": bytes(err[-2000:]).decode("utf-8", "replace"),
        "duration_s": round(time.monotonic() - start, 2),
        "error": "",
    }
