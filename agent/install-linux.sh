#!/usr/bin/env bash
# Install the VulnScanner endpoint agent as a systemd service.
#
# Typical use (run as root):
#   curl -fsSL https://scanner.example.com/agent/install-linux.sh -o install-linux.sh
#   sudo bash install-linux.sh --server https://scanner.example.com --token vs_enroll_...
#
# The script downloads the agent from the VulnScanner server, enrolls it with a
# one-time token, and installs a restart-on-failure systemd unit. If no token is
# supplied the agent is installed but the service is not started; enroll it
# manually using the command printed by the script.
set -euo pipefail

SERVER=""
TOKEN=""
AGENT_NAME="$(hostname 2>/dev/null || echo unknown-host)"
SERVICE_USER="vulnscanner"
INSTALL_DIR="/opt/vulnscanner-agent"
STATE_DIR="/var/lib/vulnscanner-agent"
CONFIG_FILE="${STATE_DIR}/agent.json"
PYTHON_BIN="${PYTHON_BIN:-python3}"
INSECURE=0
INSTALL_SERVICE=1
UNINSTALL=0
PURGE=0

usage() {
  cat <<'EOF'
Usage: install-linux.sh [options]

Options:
  --server URL        VulnScanner server URL (required unless --uninstall)
  --token TOKEN       One-time enrollment token from the Agents page
  --name NAME         Friendly agent name (default: this hostname)
  --user USER         Service account (default: vulnscanner; use root if the
                      agent must read privileged paths such as /root)
  --install-dir DIR   Program directory (default: /opt/vulnscanner-agent)
  --state-dir DIR     Writable state/config directory (default: /var/lib/vulnscanner-agent)
  --python PATH       Python 3 interpreter (default: $PYTHON_BIN or python3)
  --insecure          Do not verify the server TLS certificate (self-signed lab only)
  --no-service        Install and enroll but do not create/start a systemd unit
  --uninstall         Stop and remove the service and program files
  --purge             With --uninstall, also remove the state/config directory
  -h, --help          Show this help

Enrollment tokens are single-use and expire. Create a fresh token in the
VulnScanner UI if enrollment fails.
EOF
}

log() { printf '[vulnscanner] %s\n' "$*"; }
die() { printf '[vulnscanner] ERROR: %s\n' "$*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --server) SERVER="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --name) AGENT_NAME="${2:-}"; shift 2 ;;
    --user) SERVICE_USER="${2:-}"; shift 2 ;;
    --install-dir) INSTALL_DIR="${2:-}"; shift 2 ;;
    --state-dir) STATE_DIR="${2:-}"; CONFIG_FILE="${STATE_DIR}/agent.json"; shift 2 ;;
    --python) PYTHON_BIN="${2:-}"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    --no-service) INSTALL_SERVICE=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "Run this installer as root (sudo)."

SERVICE_NAME="vulnscanner-agent"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

if [ "$UNINSTALL" -eq 1 ]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  fi
  rm -f "$UNIT_PATH"
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
  rm -rf "$INSTALL_DIR"
  if [ "$PURGE" -eq 1 ]; then
    rm -rf "$STATE_DIR"
    if id "$SERVICE_USER" >/dev/null 2>&1; then
      userdel "$SERVICE_USER" >/dev/null 2>&1 || true
    fi
    log "Removed program, service and state directories."
  else
    log "Removed program and service. Configuration/data retained in $STATE_DIR."
  fi
  exit 0
fi

[ -n "$SERVER" ] || die "--server is required"
SERVER="${SERVER%/}"
case "$SERVER" in
  http://*|https://*) ;;
  *) die "--server must start with http:// or https://" ;;
esac

command -v "$PYTHON_BIN" >/dev/null 2>&1 || die "Python 3 was not found at '$PYTHON_BIN'. Install Python 3.8+ or use --python."
"$PYTHON_BIN" - <<'PY' || die "Python 3.8 or newer is required"
import sys
if sys.version_info < (3, 8):
    raise SystemExit(1)
PY

if command -v curl >/dev/null 2>&1; then
  DOWNLOAD="curl"
elif command -v wget >/dev/null 2>&1; then
  DOWNLOAD="wget"
else
  die "curl or wget is required to download the agent"
fi

INSTALL_DIR="${INSTALL_DIR%/}"
STATE_DIR="${STATE_DIR%/}"
CONFIG_FILE="${CONFIG_FILE}"
AGENT_FILE="${INSTALL_DIR}/vulnscanner_agent.py"

install -d -m 0755 "$INSTALL_DIR"

if [ -f "$(dirname "$0")/vulnscanner_agent.py" ] && [ "$(dirname "$0")" != "/tmp" ]; then
  install -m 0755 "$(dirname "$0")/vulnscanner_agent.py" "$AGENT_FILE"
  log "Using local agent file from $(dirname "$0")"
else
  log "Downloading agent from ${SERVER}/agent/vulnscanner_agent.py"
  TMP_AGENT="$(mktemp)"
  trap 'rm -f "$TMP_AGENT"' EXIT
  if [ "$DOWNLOAD" = "curl" ]; then
    curl -fsSL "$SERVER/agent/vulnscanner_agent.py" -o "$TMP_AGENT" || die "Could not download the agent"
  else
    wget -q "$SERVER/agent/vulnscanner_agent.py" -O "$TMP_AGENT" || die "Could not download the agent"
  fi
  head -n 1 "$TMP_AGENT" | grep -q '^#!' || die "Downloaded file does not look like the agent"
  install -m 0755 "$TMP_AGENT" "$AGENT_FILE"
fi

"$PYTHON_BIN" -m py_compile "$AGENT_FILE" || die "Downloaded agent failed a Python syntax check"

if id "$SERVICE_USER" >/dev/null 2>&1; then
  log "Using existing account: $SERVICE_USER"
else
  command -v useradd >/dev/null 2>&1 || die "useradd not found; create the '$SERVICE_USER' account manually or use --user"
  useradd --system --home-dir "$STATE_DIR" --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
  log "Created service account: $SERVICE_USER"
fi

SERVICE_GROUP="$(id -gn "$SERVICE_USER")"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_DIR"

run_as_service_user() {
  if [ "$SERVICE_USER" = "root" ]; then
    "$@"
  elif command -v runuser >/dev/null 2>&1; then
    runuser -u "$SERVICE_USER" -- env HOME="$STATE_DIR" "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -u "$SERVICE_USER" env HOME="$STATE_DIR" "$@"
  else
    die "Neither runuser nor sudo is available to run the enrollment as $SERVICE_USER"
  fi
}

if [ -n "$TOKEN" ]; then
  log "Enrolling agent '$AGENT_NAME' with $SERVER"
  ENROLL_ARGS=(enroll --server "$SERVER" --token "$TOKEN" --name "$AGENT_NAME")
  if [ "$INSECURE" -eq 1 ]; then
    ENROLL_ARGS+=(--insecure)
  fi
  run_as_service_user "$PYTHON_BIN" "$AGENT_FILE" --config "$CONFIG_FILE" "${ENROLL_ARGS[@]}"
  [ -f "$CONFIG_FILE" ] || die "Enrollment finished but no configuration was written to $CONFIG_FILE"
  chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_FILE"
  chmod 0600 "$CONFIG_FILE"
else
  log "No --token supplied. The agent is installed but not enrolled or started."
  log "Create a token in the VulnScanner UI, then run:"
  log "  runuser -u $SERVICE_USER -- $PYTHON_BIN $AGENT_FILE --config $CONFIG_FILE enroll --server $SERVER --token <TOKEN> --name '$AGENT_NAME'"
  log "Then start the service: systemctl enable --now $SERVICE_NAME"
  if [ "$INSTALL_SERVICE" -eq 1 ]; then
    log "The systemd unit will be installed but left stopped until enrollment is complete."
  fi
fi

if [ "$INSTALL_SERVICE" -eq 1 ]; then
  if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
    log "systemd was not detected. Start the agent manually or supervise it with your init system:"
    log "  runuser -u $SERVICE_USER -- $PYTHON_BIN $AGENT_FILE --config $CONFIG_FILE run"
    exit 0
  fi

  cat > "$UNIT_PATH" <<EOF
[Unit]
Description=VulnScanner endpoint agent
Documentation=${SERVER}/manual
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
ExecStart=${PYTHON_BIN} ${AGENT_FILE} --config ${CONFIG_FILE} run
Restart=always
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${STATE_DIR}
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null

  if [ -n "$TOKEN" ] && [ -f "$CONFIG_FILE" ]; then
    systemctl restart "$SERVICE_NAME"
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
      log "Service is running. Check status with: systemctl status $SERVICE_NAME"
    else
      log "Service did not stay running. Inspect: journalctl -u $SERVICE_NAME -n 100 --no-pager"
    fi
  else
    log "Enroll the agent, then run: systemctl restart $SERVICE_NAME"
  fi
fi

log "Installation complete."
