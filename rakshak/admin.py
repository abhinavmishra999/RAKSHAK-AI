"""Provision local users at the terminal. Passwords are never command arguments."""
import argparse
import os
import secrets
import getpass
from .auth import make_user
from .audit import AuditLog, load_key
from .config import Settings
from .store import Store


def main():
    p = argparse.ArgumentParser(description="Manage offline RAKSHAK accounts")
    p.add_argument("username", help="account name, or 'sensor-secret' to create the hub ingest key")
    p.add_argument("--role", choices=["admin", "analyst", "viewer"], default="admin")
    p.add_argument("--replace", action="store_true", help="Explicitly reset an existing user's credentials")
    args = p.parse_args()
    conf = Settings()
    if args.username == "sensor-secret":
        path = conf.data_dir / "sensor_secret.key"
        if path.exists() and not args.replace:
            p.error("sensor_secret.key already exists. Use --replace to rotate it (all sensors must then be updated).")
        conf.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(secrets.token_bytes(32))
        print(f"Wrote hub ingest secret to {path} (0600).")
        print("Copy that file to each sensor machine out-of-band (USB/ssh), then run there:")
        print("    python -m rakshak.sensor --hub http://THIS-HUB:8000 --secret " + str(path) + " --name web01")
        return
    store = Store(conf.data_dir / "rakshak.db")
    if store.get_user(args.username) and not args.replace:
        p.error("User already exists. Use --replace only if you intend to reset it.")
    pw = getpass.getpass("Password (14+ characters): ")
    if pw != getpass.getpass("Confirm password: "):
        p.error("Passwords differ.")
    try:
        user = make_user(args.username, pw, args.role)
    except ValueError as exc:
        p.error(str(exc))
    store.put_user(user)
    AuditLog(store, load_key(conf.data_dir / "signing.key")).write(
        "terminal-admin", "auth.provision", args.username, role=args.role)
    print(f"Created/reset {args.username} ({args.role}) in {conf.data_dir}. Restart to invalidate existing sessions.")


if __name__ == "__main__":
    main()
