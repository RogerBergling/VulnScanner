#!/usr/bin/env bash
# Start VulnScanner with a local virtual environment.
set -euo pipefail
cd "$(dirname "$0")"

ENV_FILE="${VS_ENV_FILE:-.env}"
if [ "$ENV_FILE" = ".env" ] && [ ! -f .env ] && [ -f .env.example ]; then
  echo "[vulnscanner] Creating .env from .env.example"
  cp .env.example .env
  chmod 600 .env
fi

if [ -f "$ENV_FILE" ]; then
  # Explicit process environment variables take precedence over .env.
  ENV_KEYS=()
  ENV_VALUES=()
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    key="${line%%=*}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    if [ "${!key+x}" ]; then
      ENV_KEYS+=("$key")
      ENV_VALUES+=("${!key}")
    fi
  done < "$ENV_FILE"
  set -a
  # shellcheck disable=SC1091
  . "$ENV_FILE"
  set +a
  for i in "${!ENV_KEYS[@]}"; do
    export "${ENV_KEYS[$i]}=${ENV_VALUES[$i]}"
  done
else
  echo "[vulnscanner] WARNING: environment file not found: $ENV_FILE" >&2
fi

PYTHON="${PYTHON:-python3}"
if [ ! -x .venv/bin/python ]; then
  echo "[vulnscanner] Creating .venv"
  if ! "$PYTHON" -m venv .venv; then
    rm -rf .venv
    echo "[vulnscanner] Could not create .venv. Install python3-venv (Ubuntu/Debian) or python3 (Fedora) and retry." >&2
    exit 1
  fi
fi

# uv-created environments may not include pip; the launcher uses pip for the
# hashed lock install.
if ! .venv/bin/python -m pip --version >/dev/null 2>&1; then
  echo "[vulnscanner] Bootstrapping pip"
  .venv/bin/python -m ensurepip --upgrade
fi

if [ ! -f .venv/.deps-ok ] || [ requirements.txt -nt .venv/.deps-ok ]; then
  echo "[vulnscanner] Installing locked Python dependencies"
  .venv/bin/python -m pip install --disable-pip-version-check --require-hashes -r requirements.txt
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
