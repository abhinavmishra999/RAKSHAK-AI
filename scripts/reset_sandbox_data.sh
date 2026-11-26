#!/usr/bin/env bash
# SANDBOX TEST ONLY: archive the current data folder and create a fresh one with the
# sandbox scope and the test accounts from a credentials file kept OUTSIDE the repository.
# Usage: scripts/reset_sandbox_data.sh /path/to/creds.txt   (lines: "<user> <role> <password>")
set -euo pipefail
cd "$(dirname "$0")/.."
CREDS="${1:?credentials file required}"
if pgrep -f "python -m rakshak.api" >/dev/null; then echo "Stop the Rakshak console first." >&2; exit 1; fi
BACKUP="${RAKSHAK_BACKUP_DIR:-$HOME/rakshak_backups}"
mkdir -p "$BACKUP"
if [ -d data ]; then
  KEEP_SCOPE="$BACKUP/scope.yml.$$"
  [ -f data/scope.yml ] && cp data/scope.yml "$KEEP_SCOPE"
  mv data "$BACKUP/data_$(date +%Y%m%d_%H%M%S)"
fi
mkdir -m 700 data
if [ -n "${KEEP_SCOPE:-}" ] && [ -f "$KEEP_SCOPE" ]; then mv "$KEEP_SCOPE" data/scope.yml; else cp scope.example.yml data/scope.yml; fi
chmod 600 data/scope.yml
PYTHONPATH=. .venv/bin/python - "$CREDS" <<'EOF'
import sys
from rakshak.auth import make_user
from rakshak.audit import AuditLog, load_key
from rakshak.config import Settings
from rakshak.store import Store
conf = Settings()
store = Store(conf.data_dir / "rakshak.db")
audit = AuditLog(store, load_key(conf.data_dir / "signing.key"))
for line in open(sys.argv[1]):
    if line.strip():
        user, role, pw = line.split()[:3]
        store.put_user(make_user(user, pw, role))
        audit.write("terminal-admin", "auth.provision", user, role=role)
        print("created", user, role)
EOF
sudo -n iptables -F RAKSHAK-BLOCK 2>/dev/null || true
echo "Fresh data folder ready."
