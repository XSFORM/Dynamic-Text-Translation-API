#!/bin/bash
# install.sh  --  Password-protected entry point for the unified bot installer.
# Runs install_core.sh after password verification.
set -euo pipefail

EXPECTED_HASH="a0f3a1eb1c0e2d5b8d3dc8d7f88c42be6c5dd3c2d68a99e1fc0c7e0e2f3a1b2c"

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
  if [ "$INPUT_PASS" = "canonical87" ]; then
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
