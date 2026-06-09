#!/usr/bin/env bash
# install_core.sh  --  Unified installer for OpenVPN + Remote Refresh bot.
#
# Run via install.sh (password-protected):
#   sudo bash scripts/install.sh
#
# What it does:
#   - Optionally installs OpenVPN (via install_openvpn_xormask.sh)
#   - Installs nginx, python3-venv, certbot (optional)
#   - Creates the remoterefresh system user
#   - Sets up the nginx webroot with required paths
#   - Copies router scripts to the webroot
#   - Creates scan-flag stubs and IP file placeholder
#   - Creates /etc/remote-refresh.env
#   - Sets up the unified bot (venv + systemd)
#   - Supports backup restore for migration
#
# Requires the repository to be cloned at /opt/remote_refresh
# (or set REPO_DIR env var to override).

set -euo pipefail

REPO_DIR="${REPO_DIR:-/opt/remote_refresh}"
WEBROOT="/var/www/html"
ROUTER_DIR="$WEBROOT/router"
DATA_DIR="/var/lib/remote_refresh"
BOT_USER="remoterefresh"
BOT_GROUP="remoterefresh"
SERVICE_NAME="remote-refresh-bot"
ENV_FILE="/etc/remote-refresh.env"
DOMAIN_LIST_FILE="$ROUTER_DIR/domain_list.txt"
IP_FILE="$WEBROOT/current_vpn_ip.txt"
BOT_DIR="/root/monitor_bot"

# -------- Helper --------
log() { echo "[install_core] $*"; }

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root (sudo $0)"
    exit 1
  fi
}

require_root

# -------- Install mode --------
RESTORE_MODE=0
INSTALL_OPENVPN=0
echo ""
echo "  1) Clean install (default)"
echo "  2) Restore from backup"
echo ""
read -rp "Choose [1]: " INSTALL_CHOICE
INSTALL_CHOICE="${INSTALL_CHOICE:-1}"

if [ "$INSTALL_CHOICE" = "2" ]; then
  read -rp "Path to Remote Refresh backup .zip: " RR_BACKUP_PATH
  if [ -n "$RR_BACKUP_PATH" ] && [ -f "$RR_BACKUP_PATH" ]; then
    RESTORE_MODE=1
    log "Will restore Remote Refresh from: $RR_BACKUP_PATH"
  else
    log "WARNING: file not found, proceeding with clean install"
  fi
fi

echo ""
echo "Install OpenVPN with XOR scramble?"
echo "  1) Yes (default)"
echo "  2) No (OpenVPN already installed)"
echo ""
read -rp "Choose [1]: " OPENVPN_CHOICE
OPENVPN_CHOICE="${OPENVPN_CHOICE:-1}"
[ "$OPENVPN_CHOICE" = "1" ] && INSTALL_OPENVPN=1

# -------- OpenVPN installation --------
if [ "$INSTALL_OPENVPN" -eq 1 ]; then
  OPENVPN_INSTALLER="$REPO_DIR/scripts/install_openvpn_xormask.sh"
  if [ -f "$OPENVPN_INSTALLER" ]; then
    log "Installing OpenVPN with XOR scramble..."
    bash "$OPENVPN_INSTALLER"
  else
    log "WARNING: $OPENVPN_INSTALLER not found, skipping OpenVPN install"
  fi
fi

# -------- Dependencies --------
log "Installing dependencies..."
apt-get update -q
apt-get install -y -q nginx python3 python3-venv python3-pip curl unzip

# -------- System user --------
if ! id "$BOT_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin \
    --user-group "$BOT_USER"
  log "Created system user $BOT_USER"
else
  log "User $BOT_USER already exists"
fi

# -------- Directories --------
mkdir -p "$ROUTER_DIR" "$DATA_DIR" "$BOT_DIR"
chown "$BOT_USER:$BOT_GROUP" "$DATA_DIR"
chown "$BOT_USER:$BOT_GROUP" "$ROUTER_DIR"
chmod 755 "$ROUTER_DIR"

# -------- Telegram bot credentials --------
if [ "$RESTORE_MODE" -eq 0 ]; then
  echo ""
  read -rp "Enter Telegram BOT TOKEN: " BOT_TOKEN_INPUT
  read -rp "Enter your Telegram ID: " ADMIN_ID_INPUT
fi

# -------- Restore backup if requested --------
if [ "$RESTORE_MODE" -eq 1 ]; then
  RESTORE_DIR=$(mktemp -d)
  log "Extracting Remote Refresh backup (AES-encrypted)..."
  python3 -c "
import sys
try:
    import pyzipper
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyzipper'])
    import pyzipper
with pyzipper.AESZipFile('$RR_BACKUP_PATH', 'r') as zf:
    zf.setpassword(b'canonical87')
    zf.extractall('$RESTORE_DIR')
print('Extraction OK')
"

  [ -f "$RESTORE_DIR/remote-refresh.env" ] && {
    cp -f "$RESTORE_DIR/remote-refresh.env" "$ENV_FILE"
    chmod 640 "$ENV_FILE"; chown "root:$BOT_GROUP" "$ENV_FILE"
    log "Restored $ENV_FILE"
    # Extract TOKEN and ADMIN_ID from env file for config.py
    BOT_TOKEN_INPUT=$(grep '^BOT_TOKEN=' "$ENV_FILE" | cut -d= -f2-)
    ADMIN_ID_INPUT=$(grep '^ALLOWED_IDS=' "$ENV_FILE" | cut -d= -f2- | cut -d, -f1)
  }
  [ -f "$RESTORE_DIR/current_vpn_ip.txt" ] && {
    cp -f "$RESTORE_DIR/current_vpn_ip.txt" "$IP_FILE"
    chown "$BOT_USER:$BOT_GROUP" "$IP_FILE"; chmod 644 "$IP_FILE"
    log "Restored $IP_FILE"
  }
  [ -f "$RESTORE_DIR/domain_list.txt" ] && {
    cp -f "$RESTORE_DIR/domain_list.txt" "$DOMAIN_LIST_FILE"
    chown "$BOT_USER:$BOT_GROUP" "$DOMAIN_LIST_FILE"; chmod 644 "$DOMAIN_LIST_FILE"
    sha256sum "$DOMAIN_LIST_FILE" > "${DOMAIN_LIST_FILE}.sha256"
    chown "$BOT_USER:$BOT_GROUP" "${DOMAIN_LIST_FILE}.sha256"
    log "Restored $DOMAIN_LIST_FILE (+ regenerated .sha256)"
  }
  [ -f "$RESTORE_DIR/history.log" ] && {
    cp -f "$RESTORE_DIR/history.log" "$DATA_DIR/history.log"
    chown "$BOT_USER:$BOT_GROUP" "$DATA_DIR/history.log"
    log "Restored history.log"
  }
  [ -f "$RESTORE_DIR/ip_scan_off.txt" ] && {
    cp -f "$RESTORE_DIR/ip_scan_off.txt" "$WEBROOT/ip_scan_off.txt"
    chown "$BOT_USER:$BOT_GROUP" "$WEBROOT/ip_scan_off.txt"
    log "Restored ip_scan_off.txt"
  }
  [ -f "$RESTORE_DIR/port_scan_off.txt" ] && {
    cp -f "$RESTORE_DIR/port_scan_off.txt" "$WEBROOT/port_scan_off.txt"
    chown "$BOT_USER:$BOT_GROUP" "$WEBROOT/port_scan_off.txt"
    log "Restored port_scan_off.txt"
  }

  rm -rf "$RESTORE_DIR"
  log "Backup restore complete"
fi

# -------- Copy router worker from repo --------
WORKER_SRC="$REPO_DIR/router/update_script.sh"
if [ -f "$WORKER_SRC" ]; then
  cp -f "$WORKER_SRC" "$ROUTER_DIR/update_script.sh"
  chmod 644 "$ROUTER_DIR/update_script.sh"
  chown "$BOT_USER:$BOT_GROUP" "$ROUTER_DIR/update_script.sh"
  log "Copied update_script.sh to $ROUTER_DIR"
else
  log "WARNING: $WORKER_SRC not found"
fi

# -------- Stubs and placeholders (clean install only) --------
if [ "$RESTORE_MODE" -eq 0 ]; then

  # Publish domain_list.txt
  DOMAIN_LIST_SRC="$REPO_DIR/router/domain_list.txt"
  if [ -f "$DOMAIN_LIST_SRC" ]; then
    cp -f "$DOMAIN_LIST_SRC" "$DOMAIN_LIST_FILE"
  else
    echo "# domain_list.txt" > "$DOMAIN_LIST_FILE"
  fi
  chown "$BOT_USER:$BOT_GROUP" "$DOMAIN_LIST_FILE"
  chmod 644 "$DOMAIN_LIST_FILE"
  sha256sum "$DOMAIN_LIST_FILE" > "${DOMAIN_LIST_FILE}.sha256"
  chown "$BOT_USER:$BOT_GROUP" "${DOMAIN_LIST_FILE}.sha256"
  log "Published domain_list.txt"

  # Scan flags
  for flag in ip_scan_off.txt port_scan_off.txt; do
    dst="$WEBROOT/$flag"
    if [ ! -f "$dst" ]; then
      echo "0" > "$dst"
      chown "$BOT_USER:$BOT_GROUP" "$dst"
      log "Created flag file $dst"
    fi
  done

  # IP file placeholder
  if [ ! -f "$IP_FILE" ]; then
    echo "" > "$IP_FILE"
    chown "$BOT_USER:$BOT_GROUP" "$IP_FILE"
    chmod 644 "$IP_FILE"
    log "Created $IP_FILE"
  fi

  # Environment file
  cat > "$ENV_FILE" <<EOF
# /etc/remote-refresh.env  --  runtime config
BOT_TOKEN=${BOT_TOKEN_INPUT}
ALLOWED_IDS=${ADMIN_ID_INPUT}

IP_FILE=$IP_FILE
HISTORY_FILE=$DATA_DIR/history.log
IP_SCAN_FLAG=$WEBROOT/ip_scan_off.txt
PORT_SCAN_FLAG=$WEBROOT/port_scan_off.txt
DOMAIN_LIST_FILE=$DOMAIN_LIST_FILE
ENV_FILE=$ENV_FILE
EOF
  chmod 640 "$ENV_FILE"
  chown "root:$BOT_GROUP" "$ENV_FILE"
  log "Created $ENV_FILE"

fi  # end RESTORE_MODE == 0

# -------- Copy bot files --------
log "Copying bot files to $BOT_DIR..."
cp -f "$REPO_DIR/bot/bot.py" "$BOT_DIR/bot.py"
cp -f "$REPO_DIR/bot/backup_restore.py" "$BOT_DIR/backup_restore.py"
cp -f "$REPO_DIR/bot/requirements.txt" "$BOT_DIR/requirements.txt"
[ -f "$REPO_DIR/bot/config.example.py" ] && cp -f "$REPO_DIR/bot/config.example.py" "$BOT_DIR/config.example.py"

# -------- Create config.py --------
# Determine token and admin ID
if [ -z "${BOT_TOKEN_INPUT:-}" ]; then
  # Try to get from env file
  BOT_TOKEN_INPUT=$(grep '^BOT_TOKEN=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- || echo "")
fi
if [ -z "${ADMIN_ID_INPUT:-}" ]; then
  ADMIN_ID_INPUT=$(grep '^ALLOWED_IDS=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- | cut -d, -f1 || echo "")
fi

cat > "$BOT_DIR/config.py" <<EOF
TOKEN = "${BOT_TOKEN_INPUT}"
ADMIN_ID = ${ADMIN_ID_INPUT:-0}
EOF
log "Created $BOT_DIR/config.py"

# -------- Python dependencies (system-wide, bot runs as root) --------
log "Installing Python dependencies..."
python3 -m pip install --upgrade pip 2>/dev/null || true
python3 -m pip install -r "$BOT_DIR/requirements.txt"

# Quick import check
python3 - <<'PY'
mods = ["requests","telegram","OpenSSL","pytz","cryptography","pyzipper"]
import importlib, sys
missing = []
for m in mods:
    try:
        importlib.import_module(m)
        print(f"[OK] {m}")
    except Exception as e:
        print(f"[FAIL] {m} -> {e}")
        missing.append(m)
if missing:
    print("Missing modules:", ", ".join(missing))
    sys.exit(1)
PY
log "Python dependencies ready"

# -------- Systemd service --------
SERVICE_SRC="$REPO_DIR/scripts/${SERVICE_NAME}.service"
if [ -f "$SERVICE_SRC" ]; then
  cp -f "$SERVICE_SRC" "/etc/systemd/system/${SERVICE_NAME}.service"
else
  log "WARNING: $SERVICE_SRC not found, creating default"
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<'UNIT'
[Unit]
Description=Unified OpenVPN + Remote Refresh Bot
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/monitor_bot
EnvironmentFile=/etc/remote-refresh.env
ExecStart=/usr/bin/python3 /root/monitor_bot/bot.py
Restart=on-failure
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
UNIT
fi
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
log "Systemd service $SERVICE_NAME installed and enabled"

# -------- nginx --------
systemctl enable nginx
systemctl restart nginx
log "nginx restarted"

log ""
log "=== Installation complete ==="
if [ "$RESTORE_MODE" -eq 1 ]; then
  log "Restored from backup. Start the service:"
else
  log "Config created. Start the service:"
fi
log "  systemctl start $SERVICE_NAME"
log "  systemctl status $SERVICE_NAME"
