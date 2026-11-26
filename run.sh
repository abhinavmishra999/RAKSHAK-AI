#!/usr/bin/env bash
# RAKSHAK-AI: start the offline security console on Linux (tested on Ubuntu 24.04).
# First run needs the Python packages (internet once, or an offline wheelhouse: see README).
set -euo pipefail
cd "$(dirname "$0")"
PY=./.venv/bin/python
DATA="${RAKSHAK_DATA:-./data}"

if [ ! -x "$PY" ]; then
  echo "[1/4] Creating the Python environment..."
  python3 -m venv .venv
  if [ -d wheelhouse ]; then
    ./.venv/bin/pip install --no-index --find-links wheelhouse -r requirements.txt -q
  else
    ./.venv/bin/pip install -r requirements.txt -q
  fi
fi

if [ ! -f frontend/dist/index.html ]; then
  echo "[2/4] Building the dashboard (needs Node.js 18+)..."
  (cd frontend && npm install --silent && npm run build)
fi

mkdir -p -m 700 "$DATA"
if [ ! -f "$DATA/scope.yml" ]; then
  cp scope.example.yml "$DATA/scope.yml" && chmod 600 "$DATA/scope.yml"
  echo "      Created $DATA/scope.yml (empty = no security test may run until you list your own assets)."
fi

USERS=$(RAKSHAK_DATA="$DATA" "$PY" -c "from rakshak.config import Settings; from rakshak.store import Store; print(Store(Settings().data_dir / 'rakshak.db').user_count())")
if [ "$USERS" = "0" ]; then
  echo "[3/4] No account exists yet. Create the first administrator now."
  read -r -p "      Admin username: " ADMIN_NAME
  RAKSHAK_DATA="$DATA" "$PY" -m rakshak.admin "$ADMIN_NAME" --role admin
fi

echo "[4/4] Starting RAKSHAK-AI"
echo "      Dashboard : http://${RAKSHAK_HOST:-127.0.0.1}:${RAKSHAK_PORT:-8000}"
echo "      Watching  : ${RAKSHAK_LOGS:-/var/log/auth.log}"
echo "      Mode      : ${RAKSHAK_MODE:-recommend}   Firewall: ${RAKSHAK_ENFORCER:-none}"
echo "      Press Ctrl+C to stop."
export RAKSHAK_DATA="$DATA"
exec "$PY" -m rakshak.api
