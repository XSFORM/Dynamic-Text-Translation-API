#!/bin/sh
# update_script.sh  --  unified OpenVPN "remote" updater for Padavan / BusyBox
# Version: v2.1_selfheal
#
# v2.1 changes (self-heal fix):
#   - "no change" now checks the LIVE tunnel, not just the config IP.
#     If the IP is already correct but the tunnel is DOWN -> force a restart
#     (previously the worker exited here and never recovered a stuck tunnel).
#   - Replaced `kill -HUP` (soft restart preserves the OLD remote address) with
#     a FULL process restart (TERM -> wait -> kill-9 -> fresh start with --writepid),
#     which re-reads the config and actually moves to the new IP (mimics UI OFF/ON).
#   - Config is normalized to a SINGLE managed `remote <IP> <PORT>` line; dead
#     domain remotes are stripped (no more "Cannot resolve" cycling).
#
# What it does:
#   - If the OpenVPN tunnel is already UP -> exit immediately (no network poll).
#     This removes the every-15-min cleartext fingerprint that gets domains blocked.
#   - Only when the tunnel is DOWN: fetch a fresh IP, trying several domains in turn
#     (multi-domain failover), refresh the local domain list (sha256-verified),
#     rewrite "remote <IP> <PORT>" in client.conf and fully restart OpenVPN.
#
# Config switches (below):
#   CONNECTED_CHECK=1   1 = skip poll while tunnel is up (recommended). 0 = always poll.
#   USE_HTTPS=0         0 = http (BusyBox wget often lacks TLS). 1 = https.
#   USE_INTERVAL=0      1 = enforce MIN_INTERVAL between real runs. 0 = off.
#   SHOW_FETCH=0        1 = verbose fetch logging (debug).
#
# Force a full re-check ignoring the connected-check gate:
#   /etc/storage/update_script.sh --force
export PATH=/sbin:/bin:/usr/sbin:/usr/bin:/opt/bin:/opt/sbin

# -------- Config --------
SEED_DOMAINS="example-a.com example-b.com"      # used only if cache is empty
SOURCE_PATH="/current_vpn_ip.txt"
DOMAIN_LIST_PATH="/router/domain_list.txt"

RUNTIME_CONF="/etc/openvpn/client/client.conf"
PID_FILE="/var/run/openvpn_cli.pid"
TUN_IFACE="tun0"

LOCK_FILE="/tmp/vpn_update.lock"
STAMP_FILE="/tmp/vpn_update.last"
CACHE_FILE="/etc/storage/remote_domains.list"

MIN_INTERVAL=300
HUP_WAIT=8
FALLBACK_ENABLE=1
LOG_TAG="vpn-update"

CONNECTED_CHECK=1
USE_HTTPS=0
USE_INTERVAL=0
SHOW_FETCH=0

FORCE=0
[ "$1" = "--force" ] && FORCE=1

SCHEME="http"
[ "$USE_HTTPS" = "1" ] && SCHEME="https"

# -------- Helpers --------
log() { logger -t "$LOG_TAG" "$*"; echo "$LOG_TAG: $*"; }

clean_line() {
  line=$(printf '%s' "$1" | tr -d '\r')
  BOM=$(printf '\357\273\277')
  case "$line" in $BOM*) line=${line#"$BOM"} ;; esac
  line=$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  line=$(printf '%s' "$line" | tr -cd '0123456789.:')
  printf '%s' "$line"
}

is_valid_ipv4() {
  ip="$1"
  echo "$ip" | grep -q '^[0-9.]\{7,\}$' || return 1
  case "$ip" in .*|*.) return 1 ;; esac
  echo "$ip" | grep -q '\.\.' && return 1
  o1=$(echo "$ip" | cut -d. -f1)
  o2=$(echo "$ip" | cut -d. -f2)
  o3=$(echo "$ip" | cut -d. -f3)
  o4=$(echo "$ip" | cut -d. -f4)
  # Reject if there is a 5th field (more than 4 octets)
  o5=$(echo "$ip" | cut -d. -f5)
  [ -n "$o5" ] && return 1
  for o in "$o1" "$o2" "$o3" "$o4"; do
    [ -n "$o" ] || return 1
    [ "$o" -ge 0 ] 2>/dev/null && [ "$o" -le 255 ] 2>/dev/null || return 1
  done
  return 0
}

is_reserved_ipv4() {            # return 0 = reserved/local IP -> REJECT
  ip="$1"
  o1=$(echo "$ip" | cut -d. -f1); o2=$(echo "$ip" | cut -d. -f2)
  case "$o1" in
    0|10|127) return 0 ;;
    169) [ "$o2" = "254" ] && return 0 ;;
    172) [ "$o2" -ge 16 ] 2>/dev/null && [ "$o2" -le 31 ] 2>/dev/null && return 0 ;;
    192) [ "$o2" = "168" ] && return 0 ;;
    100) [ "$o2" -ge 64 ] 2>/dev/null && [ "$o2" -le 127 ] 2>/dev/null && return 0 ;;
  esac
  [ "$o1" -ge 224 ] 2>/dev/null && return 0
  return 1
}

iface_has_inet() {
  _if="$1"
  [ -n "$_if" ] || return 1
  ifconfig "$_if" 2>/dev/null | grep -qi 'inet addr' && return 0
  ifconfig "$_if" 2>/dev/null | grep -qi 'inet ' && return 0
  return 1
}

list_tun_ifaces() {
  ifconfig 2>/dev/null | grep -o '^tun[0-9]*'
  for d in /sys/class/net/tun*; do
    [ -e "$d" ] && basename "$d"
  done 2>/dev/null
}

tunnel_up() {
  _pid=""
  [ -f "$PID_FILE" ] && _pid=$(cat "$PID_FILE" 2>/dev/null)
  [ -n "$_pid" ] && kill -0 "$_pid" 2>/dev/null || return 1
  iface_has_inet "$TUN_IFACE" && return 0
  for _i in $(list_tun_ifaces); do
    iface_has_inet "$_i" && return 0
  done
  return 1
}

# Full restart of the OpenVPN client process (mimics the UI OFF/ON).
# A soft restart (HUP/SIGUSR1) preserves the OLD remote address, so we must
# fully kill and relaunch to pick up the new "remote" line from the config.
restart_openvpn() {
  _p=""
  [ -f "$PID_FILE" ] && _p=$(cat "$PID_FILE" 2>/dev/null)
  if [ -n "$_p" ] && kill -0 "$_p" 2>/dev/null; then
    kill -TERM "$_p" 2>/dev/null; log "TERM sent PID=$_p"
    _n=0
    while kill -0 "$_p" 2>/dev/null && [ "$_n" -lt 10 ]; do sleep 1; _n=$((_n + 1)); done
    if kill -0 "$_p" 2>/dev/null; then kill -9 "$_p" 2>/dev/null; log "KILL-9 PID=$_p"; sleep 2; fi
  fi
  killall openvpn 2>/dev/null; sleep 1
  /usr/sbin/openvpn --daemon openvpn-cli --cd /etc/openvpn/client \
    --config "$(basename "$RUNTIME_CONF")" --writepid "$PID_FILE"
  log "openvpn started fresh (remote $NEW_IP $CUR_PORT)"
}

verify_tunnel() {
  _try=0
  while [ "$_try" -lt 6 ]; do
    iface_has_inet "$TUN_IFACE" && return 0
    for _i in $(list_tun_ifaces); do iface_has_inet "$_i" && return 0; done
    _try=$((_try + 1)); sleep 2
  done
  return 1
}

read_domains() {
  if [ -s "$CACHE_FILE" ]; then
    cat "$CACHE_FILE"
  else
    for d in $SEED_DOMAINS; do echo "$d"; done
  fi
}

update_cache_from_server() {
  dom="$1"
  tmp="/tmp/domain_list.tmp"
  shatmp="/tmp/domain_list.sha"
  url="$SCHEME://$dom$DOMAIN_LIST_PATH"

  wget -q -T 10 -O "$tmp" "$url" || {
    [ "$SHOW_FETCH" = "1" ] && log "fetch domain list failed: $url"
    return
  }

  if command -v sha256sum >/dev/null 2>&1; then
    if wget -q -T 10 -O "$shatmp" "$url.sha256"; then
      expected=$(awk '{print $1}' "$shatmp" 2>/dev/null | head -n1)
      computed=$(sha256sum "$tmp" 2>/dev/null | awk '{print $1}')
      if [ -n "$expected" ] && [ "$expected" != "$computed" ]; then
        log "domain_list sha256 mismatch from $dom -> reject"
        rm -f "$tmp" "$shatmp"
        return
      fi
      [ "$SHOW_FETCH" = "1" ] && log "domain_list sha256 ok from $dom"
    fi
  fi

  out="/tmp/domain_list.clean"; : > "$out"; valid=0
  while IFS= read -r line; do
    line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -z "$line" ] && continue
    echo "$line" | grep -q '^#' && continue
    echo "$line" | grep -qE '^[A-Za-z0-9._-]+$' || continue
    echo "$line" >> "$out"; valid=1
  done < "$tmp"

  if [ "$valid" -eq 1 ]; then
    mkdir -p "$(dirname "$CACHE_FILE")"
    mv "$out" "$CACHE_FILE"
    log "domain cache updated from $dom"
  fi
  rm -f "$tmp" "$shatmp"
}

# -------- Lock (timestamped) --------
NOW=$(date +%s)
if [ -f "$LOCK_FILE" ]; then
  TS=$(awk -F: '{print $2}' "$LOCK_FILE" 2>/dev/null)
  [ -z "$TS" ] && TS=0
  AGE=$((NOW - TS))
  if [ "$AGE" -le 600 ] && [ "$AGE" -ge 0 ]; then
    log "lock present (age=${AGE}s), exit"
    exit 0
  fi
  log "stale lock removed"
  rm -f "$LOCK_FILE"
fi
echo "$$:$NOW" > "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"' EXIT INT TERM

# -------- Connected-check gate (the key fingerprint fix) --------
if [ "$CONNECTED_CHECK" = "1" ] && [ "$FORCE" -ne 1 ]; then
  if tunnel_up; then
    log "tunnel up -> skip poll"
    exit 0
  fi
  log "tunnel down -> proceed to check IP"
fi
[ "$FORCE" -eq 1 ] && log "force run (gate bypassed)"

# -------- Optional interval limiter --------
if [ "$USE_INTERVAL" -eq 1 ] && [ "$FORCE" -ne 1 ] && [ -f "$STAMP_FILE" ]; then
  PREV=$(cat "$STAMP_FILE" 2>/dev/null || echo 0)
  [ -z "$PREV" ] && PREV=0
  AGE=$((NOW - PREV))
  if [ "$AGE" -lt "$MIN_INTERVAL" ]; then
    log "skip within $MIN_INTERVAL s (age=$AGE)"
    exit 0
  fi
fi

# -------- Multi-domain IP fetch --------
TMP="/tmp/vpn_new_ip.txt"
SUCCESS=0; ACTIVE_DOMAIN=""; NEW_IP=""
for D in $(read_domains); do
  URL="$SCHEME://$D$SOURCE_PATH"
  [ "$SHOW_FETCH" = "1" ] && log "fetch try $URL"
  if wget -q -T 15 -O "$TMP" "$URL"; then
    RAW=$(head -n1 "$TMP" 2>/dev/null)
    RAW_CLEAN=$(clean_line "$RAW")
    [ -z "$RAW_CLEAN" ] && continue
    NEW_IP="$RAW_CLEAN"
    echo "$NEW_IP" | grep -q ':' && NEW_IP=$(echo "$NEW_IP" | cut -d: -f1)
    if is_valid_ipv4 "$NEW_IP" && ! is_reserved_ipv4 "$NEW_IP"; then
      [ "$SHOW_FETCH" = "1" ] && log "fetch ok $URL -> $NEW_IP"
      ACTIVE_DOMAIN="$D"; SUCCESS=1; break
    else
      [ "$SHOW_FETCH" = "1" ] && log "reject ip from $D ($NEW_IP) -> try next domain"
      continue
    fi
  fi
done

if [ "$SUCCESS" -ne 1 ]; then
  log "all domains failed"
  echo "$NOW" > "$STAMP_FILE"
  exit 0
fi

# -------- Scan flags (optional, best-effort) from the active domain --------
IP_SCAN_OFF=0; PORT_SCAN_OFF=0; TMP_FLAG="/tmp/vpn_scan_flag.txt"
if wget -q -T 10 -O "$TMP_FLAG" "$SCHEME://$ACTIVE_DOMAIN/ip_scan_off.txt" 2>/dev/null; then
  [ "$(head -n1 "$TMP_FLAG" 2>/dev/null | tr -cd '01')" = "1" ] && IP_SCAN_OFF=1
fi
if wget -q -T 10 -O "$TMP_FLAG" "$SCHEME://$ACTIVE_DOMAIN/port_scan_off.txt" 2>/dev/null; then
  [ "$(head -n1 "$TMP_FLAG" 2>/dev/null | tr -cd '01')" = "1" ] && PORT_SCAN_OFF=1
fi
if [ "$IP_SCAN_OFF" -eq 1 ] && [ "$PORT_SCAN_OFF" -eq 1 ]; then
  log "both scans disabled -> exit"
  echo "$NOW" > "$STAMP_FILE"
  exit 0
fi

update_cache_from_server "$ACTIVE_DOMAIN"

# -------- Parse current remote --------
REMOTE_LINE=$(grep '^remote ' "$RUNTIME_CONF" 2>/dev/null | head -n1)
CUR_IP=""; CUR_PORT=""
if [ -n "$REMOTE_LINE" ]; then
  CUR_IP=$(echo "$REMOTE_LINE" | awk '{print $2}')
  CUR_PORT=$(echo "$REMOTE_LINE" | awk '{print $3}')
fi
[ -z "$CUR_PORT" ] && CUR_PORT=$(nvram get vpnc_ov_port 2>/dev/null)
[ -z "$CUR_PORT" ] && CUR_PORT=443

[ "$IP_SCAN_OFF" -eq 1 ] && NEW_IP="$CUR_IP"

if is_reserved_ipv4 "$NEW_IP"; then
  log "reject bad ip ($NEW_IP) -> keep current"
  echo "$NOW" > "$STAMP_FILE"; exit 0
fi

# -------- Decide action (self-heal aware) --------
# Only a truly healthy state (IP correct AND tunnel up) is a no-op.
if [ "$CUR_IP" = "$NEW_IP" ] && tunnel_up; then
  log "no change ($CUR_IP), tunnel up -> ok"
  echo "$NOW" > "$STAMP_FILE"; exit 0
fi

if [ "$CUR_IP" = "$NEW_IP" ]; then
  log "ip ok ($CUR_IP) but tunnel DOWN -> normalize + restart"
else
  log "change: $CUR_IP -> $NEW_IP"
  nvram set vpnc_peer="$NEW_IP" >/dev/null 2>&1 || log "warn: nvram set failed"
  nvram commit >/dev/null 2>&1 || log "warn: nvram commit failed"
fi

# -------- Normalize config to a SINGLE managed remote line --------
TMP_CONF="${RUNTIME_CONF}.tmp_edit"; : > "$TMP_CONF"; done_flag=0
while IFS= read -r line; do
  if echo "$line" | grep -q '^remote '; then
    if [ "$done_flag" -eq 0 ]; then
      echo "remote $NEW_IP $CUR_PORT" >> "$TMP_CONF"; done_flag=1
    fi
    # drop any additional (dead) remote lines
  else
    echo "$line" >> "$TMP_CONF"
  fi
done < "$RUNTIME_CONF"
[ "$done_flag" -eq 0 ] && echo "remote $NEW_IP $CUR_PORT" >> "$TMP_CONF"
mv "$TMP_CONF" "$RUNTIME_CONF"

NEW_RUNTIME=$(grep '^remote ' "$RUNTIME_CONF" | head -n1)
log "runtime now: $NEW_RUNTIME"
echo "$NEW_RUNTIME" | grep -q "remote $NEW_IP " || {
  log "edit failed (still '$NEW_RUNTIME')"
  echo "$NOW" > "$STAMP_FILE"; exit 1
}

# -------- Full restart so OpenVPN actually uses the new remote --------
restart_openvpn
if verify_tunnel; then
  log "restart success: tunnel UP on $NEW_IP"
else
  log "restart done but tunnel still DOWN -> will retry next run"
fi

echo "$NOW" > "$STAMP_FILE"
log "done"
exit 0
