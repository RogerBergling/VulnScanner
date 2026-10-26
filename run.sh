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
PORT="${VS_PORT:-8765}"
SSL_ENABLED="$(printf '%s' "${VS_SSL:-true}" | tr '[:upper:]' '[:lower:]')"
case "${SSL_ENABLED}" in
  1|true|yes|on)
    CERT_FILE=$(.venv/bin/python -c "from app.certs import get_cert_paths; print(get_cert_paths()[0])")
    CERT_KEY=$(.venv/bin/python -c "from app.certs import get_cert_paths; print(get_cert_paths()[1])")
    echo "[vulnscanner] Starting on https://${HOST}:${PORT} (self-signed certificate)"
    exec .venv/bin/python -m uvicorn app.main:app --host "$HOST" --port "$PORT" --ssl-certfile "$CERT_FILE" --ssl-keyfile "$CERT_KEY" "$@"
    ;;
  *)
    echo "[vulnscanner] Starting on http://${HOST}:${PORT}"
    exec .venv/bin/python -m uvicorn app.main:app --host "$HOST" --port "$PORT" "$@"
    ;;
esac
