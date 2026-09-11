#!/bin/bash
# install.sh  --  Password-protected entry point for the unified bot installer.
# Runs install_core.sh after password verification.
set -euo pipefail

EXPECTED_HASH="fba5d3ef73840727ec2c44adb99e14fcb547859fe89b34d901ba2af6713c74da"

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root (sudo $0)"
    exit 1
  fi
}

require_root

echo ""
echo "  Dynamic Text Translation API — Installer"
echo ""

MAX_ATTEMPTS=3
ATTEMPT=0

while [ "$ATTEMPT" -lt "$MAX_ATTEMPTS" ]; do
  read -rsp "Enter installation password: " INPUT_PASS
  echo ""
  PASS_HASH=$(echo -n "$INPUT_PASS" | sha256sum | awk '{print $1}')
  if [ "$PASS_HASH" = "$EXPECTED_HASH" ]; then
    echo "[OK] Password accepted."
    break
  else
    ATTEMPT=$((ATTEMPT + 1))
    REMAINING=$((MAX_ATTEMPTS - ATTEMPT))
    if [ "$REMAINING" -gt 0 ]; then
      echo "Wrong password. $REMAINING attempt(s) remaining."
    else
      echo "Too many failed attempts. Aborting."
      exit 1
    fi
  fi
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_SCRIPT="$SCRIPT_DIR/install_core.sh"

if [ ! -f "$CORE_SCRIPT" ]; then
  echo "ERROR: install_core.sh not found at $CORE_SCRIPT"
  exit 1
fi

exec bash "$CORE_SCRIPT"
