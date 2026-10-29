#!/usr/bin/env bash
# Safe VulnScanner update helper.
#
# It backs up the complete data directory before pulling code. It never runs
# `git clean`, `git reset --hard`, or deletes the data directory. Override the
# paths with VS_REPO_DIR, VS_DATA_DIR, VS_BACKUP_DIR and VS_SERVICE.
set -euo pipefail

REPO_DIR="${VS_REPO_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
if [ -f "$REPO_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$REPO_DIR/.env"
  set +a
fi
DATA_DIR="${VS_DATA_DIR:-$REPO_DIR/data}"
BACKUP_DIR="${VS_BACKUP_DIR:-/var/backups/vulnscanner}"
SERVICE="${VS_SERVICE:-vulnscanner}"
STAMP="$(date +%Y%m%d-%H%M%S)"
STOPPED=0

if [ ! -d "$DATA_DIR" ]; then
  echo "[update] Data directory not found: $DATA_DIR" >&2
  echo "[update] Set VS_DATA_DIR to the directory that contains vulnscanner.db." >&2
  exit 1
fi
DATA_DIR="$(cd "$DATA_DIR" && pwd)"
REPO_DIR="$(cd "$REPO_DIR" && pwd)"

case "$DATA_DIR" in
  "$REPO_DIR"/*)
    echo "[update] WARNING: VS_DATA_DIR is inside the Git checkout." >&2
    echo "[update] A future re-clone or 'git clean -fdx' could delete scans." >&2
    echo "[update] Prefer an external directory such as /var/lib/vulnscanner." >&2
    ;;
esac

mkdir -p "$BACKUP_DIR"
BACKUP_DIR="$(cd "$BACKUP_DIR" && pwd)"
BACKUP_FILE="$BACKUP_DIR/vulnscanner-before-update-$STAMP.tgz"
echo "[update] Backing up $DATA_DIR to $BACKUP_FILE"
tar -C "$(dirname "$DATA_DIR")" -czf "$BACKUP_FILE" "$(basename "$DATA_DIR")"
echo "[update] Backup written: $BACKUP_FILE"

restart_on_exit() {
  if [ "$STOPPED" -eq 1 ]; then
    echo "[update] Starting $SERVICE"
    systemctl start "$SERVICE" || true
  fi
}
trap restart_on_exit EXIT

if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE}\.service"; then
  echo "[update] Stopping $SERVICE"
  systemctl stop "$SERVICE"
  STOPPED=1
fi

cd "$REPO_DIR"
echo "[update] Pulling code with --ff-only"
git pull --ff-only

if [ -x .venv/bin/python ] && { [ ! -f .venv/.deps-ok ] || [ requirements.txt -nt .venv/.deps-ok ]; }; then
  echo "[update] Installing updated Python dependencies"
  .venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
  touch .venv/.deps-ok
fi

echo "[update] Update complete. Verify /api/health and open an existing scan."
echo "[update] Roll back with: tar -C \"$(dirname "$DATA_DIR")\" -xzf \"$BACKUP_FILE\""
