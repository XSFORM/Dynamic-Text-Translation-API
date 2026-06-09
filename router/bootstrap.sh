#!/bin/sh
# bootstrap.sh  --  One-shot Padavan router installer for the VPN IP updater
#
# Run once as root on the router:
#   wget -qO- http://<domain>/router/bootstrap.sh | sh
#   -- or --
#   sh /etc/storage/bootstrap.sh
#
# What it does:
#   1. Writes the seed domain cache (/etc/storage/remote_domains.list) if missing.
#   2. Downloads update_script.sh from the first reachable domain (5 retries).
#   3. Installs a cron entry every 15 min.
#   4. Enables crond via nvram and (re)starts it.
#   5. Runs update_script.sh --force once to test immediately.
#   6. Persists everything to flash with mtd_storage.sh save.
#
# Re-running this script is safe (idempotent).

export PATH=/sbin:/bin:/usr/sbin:/usr/bin:/opt/bin:/opt/sbin

LOG_TAG="bootstrap"
log() { logger -t "$LOG_TAG" "$*"; echo "$LOG_TAG: $*"; }

# -------- Config --------
# Space-separated seed domains (used if cache is missing)
SEED_DOMAINS="example-a.com example-b.com"

CACHE_FILE="/etc/storage/remote_domains.list"
SCRIPT_DEST="/etc/storage/update_script.sh"
CRON_DIR="/etc/storage/cron/crontabs"
CRON_FILE="$CRON_DIR/admin"
SCRIPT_URL_PATH="/router/update_script.sh"

# -------- 1. Write seed domain cache if missing --------
if [ ! -s "$CACHE_FILE" ]; then
  mkdir -p "$(dirname "$CACHE_FILE")"
  for d in $SEED_DOMAINS; do echo "$d"; done > "$CACHE_FILE"
  log "wrote seed domain cache: $CACHE_FILE"
else
  log "domain cache already present: $CACHE_FILE"
fi

# -------- 2. Download update_script.sh --------
DOWNLOADED=0
RETRY_MAX=5
for d in $SEED_DOMAINS; do
  URL="http://$d$SCRIPT_URL_PATH"
  log "trying $URL ..."
  i=0
  while [ "$i" -lt "$RETRY_MAX" ]; do
    if wget -q -T 15 -O "${SCRIPT_DEST}.tmp" "$URL"; then
      # Sanity check: must be a shell script
      if head -n1 "${SCRIPT_DEST}.tmp" | grep -q '^#!.*sh'; then
        # Back up existing script if present
        [ -f "$SCRIPT_DEST" ] && cp -f "$SCRIPT_DEST" "${SCRIPT_DEST}.bak"
        mv "${SCRIPT_DEST}.tmp" "$SCRIPT_DEST"
        chmod +x "$SCRIPT_DEST"
        log "downloaded $SCRIPT_DEST from $d"
        DOWNLOADED=1
        break 2
      else
        log "download from $d failed sanity check, retrying..."
        rm -f "${SCRIPT_DEST}.tmp"
      fi
    fi
    i=$((i + 1))
    sleep $((i * 2))
  done
  log "all retries exhausted for $d"
done

if [ "$DOWNLOADED" -ne 1 ]; then
  log "ERROR: could not download update_script.sh from any domain. Aborting."
  exit 1
fi

# -------- 3. Install cron entry (idempotent) --------
mkdir -p "$CRON_DIR"
CRON_LINE="*/15 * * * * $SCRIPT_DEST"
if [ -f "$CRON_FILE" ]; then
  # Remove any existing entry pointing to update_script.sh to avoid duplicates
  TMP_CRON="${CRON_FILE}.tmp"
  grep -v 'update_script\.sh' "$CRON_FILE" > "$TMP_CRON" 2>/dev/null || : > "$TMP_CRON"
  echo "$CRON_LINE" >> "$TMP_CRON"
  mv "$TMP_CRON" "$CRON_FILE"
  log "updated cron entry in $CRON_FILE"
else
  echo "$CRON_LINE" > "$CRON_FILE"
  log "created cron file $CRON_FILE"
fi

# -------- 4. Enable crond via nvram and (re)start --------
if nvram set crond_enable=1 >/dev/null 2>&1 && nvram commit >/dev/null 2>&1; then
  log "nvram crond_enable=1 committed"
else
  log "warn: nvram set crond_enable failed (may be ok on some firmware)"
fi

if command -v crond >/dev/null 2>&1; then
  killall crond 2>/dev/null; sleep 1
  crond -c "$CRON_DIR" -l 8
  log "crond started"
else
  log "warn: crond not found in PATH"
fi

# -------- 5. Run once immediately --------
log "running update_script.sh --force ..."
sh "$SCRIPT_DEST" --force

# -------- 6. Persist to flash --------
if command -v mtd_storage.sh >/dev/null 2>&1; then
  mtd_storage.sh save && log "mtd_storage.sh save done"
else
  log "warn: mtd_storage.sh not found, changes may not survive reboot"
fi

log "bootstrap complete"

# ---- Alternative: started_script.sh hook (for firmwares without working cron) ----
# If crond is not available or unreliable on your firmware, you can instead add
# the worker to /etc/storage/started_script.sh which runs at boot:
#
#   STARTED="/etc/storage/started_script.sh"
#   HOOK_LINE="(sleep 60 && sh /etc/storage/update_script.sh) &"
#   if ! grep -q 'update_script' "$STARTED" 2>/dev/null; then
#     echo "$HOOK_LINE" >> "$STARTED"
#     log "added boot hook to $STARTED"
#   fi
#
# Note: this only runs at boot, not periodically. Combine with crond for best results.
