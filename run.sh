#!/usr/bin/env bash
# Start VulnScanner with a local virtual environment.
set -euo pipefail
cd "$(dirname "$0")"

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

PYTHON="${PYTHON:-python3}"
if [ ! -x .venv/bin/python ]; then
  echo "[vulnscanner] Creating .venv"
  "$PYTHON" -m venv .venv
fi

if [ ! -f .venv/.deps-ok ] || [ requirements.txt -nt .venv/.deps-ok ]; then
  echo "[vulnscanner] Installing Python dependencies"
  .venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
  touch .venv/.deps-ok
fi

HOST="${VS_HOST:-127.0.0.1}"
PORT="${VS_PORT:-8787}"
echo "[vulnscanner] Starting on http://${HOST}:${PORT}"
exec .venv/bin/python -m uvicorn app.main:app --host "$HOST" --port "$PORT" "$@"
