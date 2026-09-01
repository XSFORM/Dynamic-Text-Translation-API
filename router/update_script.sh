#!/bin/sh
# update_script.sh  --  unified OpenVPN "remote" updater for Padavan / BusyBox
# Version: v4.0_pptp
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
#   - Always fetches the current IP from the server via domain.
#     When VPN is UP, traffic goes through tunnel (ISP can't see domain).
#   - If IP matches and tunnel is UP -> no action.
#   - If IP changed -> rewrite config + restart OpenVPN.
#   - If IP matches but tunnel is DOWN -> restart OpenVPN (self-heal).
#
# Config switches (below):
#   CONNECTED_CHECK=0   1 = skip poll while tunnel is up. 0 = always poll (safe: VPN traffic is encrypted).
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
PORT_PATH="/current_vpn_port.txt"
DOMAIN_LIST_PATH="/router/domain_list.txt"
PROTOCOL_PATH="/router/protocol.txt"

RUNTIME_CONF="/etc/openvpn/client/client.conf"
STORAGE_CONF="/etc/storage/openvpn/client/client.conf"
PID_FILE="/var/run/openvpn_cli.pid"
TUN_IFACE="tun0"

# Fast failover timeouts (default OpenVPN = 60s per dead remote)
OPT_CONNECT_TIMEOUT=10
OPT_HAND_WINDOW=25
OPT_RESOLV_RETRY=5

# Markers for managed block in flash config
MARK_START="# vpn-update managed block start"
MARK_END="# vpn-update managed block end"

LOCK_FILE="/tmp/vpn_update.lock"
STAMP_FILE="/tmp/vpn_update.last"
CACHE_FILE="/etc/storage/remote_domains.list"
PREV_FILE="/etc/storage/remote_domains.prev"
SAVE_STAMP="/tmp/flash_save_count"
MAX_FLASH_SAVES=10
MAX_DOMAINS=20

MIN_INTERVAL=300
HUP_WAIT=8
FALLBACK_ENABLE=1
LOG_TAG="vpn-update"

CONNECTED_CHECK=0
USE_HTTPS=0
USE_INTERVAL=0
SHOW_FETCH=0

# -------- Self-update config --------
SELF_VERSION=1
VERSION_PATH="/router/version.txt"
SCRIPT_PATH="/router/update_script.sh"
SELF_FILE="/etc/storage/update_script.sh"
BAK_FILE="/etc/storage/update_script.sh.bak"
FAIL_FILE="/etc/storage/update_fail"
SELFUPD_ENABLE=1
MIN_SCRIPT_BYTES=4000
SELFTEST_TOKEN="UPDATE_SCRIPT_SELFTEST_OK"

# -------- PPTP config --------
PPTP_SOURCE_PATH="/current_pptp_ip.txt"
PPTP_TUN_IFACE="ppp0"

# -------- Beacon config --------
BEACON_ENABLE=1
BEACON_PATH="/router/beacon.txt"

# -------- Arguments --------
FORCE=0
for a in "$@"; do
  case "$a" in
    --force|-f) FORCE=1 ;;
    --selftest)
      echo "$SELFTEST_TOKEN $SELF_VERSION"
      exit 0
      ;;
    --version|-v)
      echo "$SELF_VERSION"
      exit 0
      ;;
  esac
done

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
  elif [ -s "$PREV_FILE" ]; then
    log "domain list empty, using backup"
    cp "$PREV_FILE" "$CACHE_FILE" 2>/dev/null
    cat "$PREV_FILE"
  else
    log "domain list empty, using seed domains"
    for d in $SEED_DOMAINS; do echo "$d"; done
  fi
}

# Atomic domain sync with safeguards:
#  1. Empty/bad server response -> list NOT touched
#  2. Working domain NEVER removed (even if server doesn't list it)
#  3. Working domain moved to FIRST position
#  4. Atomic write (temp+mv in same FS) + prev backup
#  5. Flash save only on actual change
update_cache_from_server() {
  dom="$1"
  _raw="/tmp/domain_list.raw"
  _srv="/tmp/domain_list.srv"
  rm -f "$_raw" "$_srv"

  wget -q -T 10 -O "$_raw" "$SCHEME://$dom$DOMAIN_LIST_PATH" || {
    [ "$SHOW_FETCH" = "1" ] && log "fetch domain list failed from $dom"
    rm -f "$_raw"
    return
  }

  # Parse and validate domains
  : > "$_srv"
  while IFS= read -r line; do
    line=$(printf '%s' "$line" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac
    echo "$line" | grep -qE '^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$' || continue
    echo "$line" | grep -q '\.' || continue
    grep -qxF "$line" "$_srv" 2>/dev/null || echo "$line" >> "$_srv"
  done < "$_raw"
  rm -f "$_raw"

  # Safeguard 1: server returned empty/garbage -> don't touch anything
  if [ ! -s "$_srv" ]; then
    log "domain_list.txt empty or invalid, list unchanged"
    rm -f "$_srv"
    return
  fi

  # Safeguards 2+3: working domain survives and goes first
  _final="$CACHE_FILE.new.$$"
  rm -f "$CACHE_FILE".new.* 2>/dev/null
  echo "$dom" > "$_final"
  _n=1
  while IFS= read -r d; do
    [ "$_n" -ge "$MAX_DOMAINS" ] && break
    [ "$d" = "$dom" ] && continue
    echo "$d" >> "$_final"
    _n=$((_n + 1))
  done < "$_srv"
  rm -f "$_srv"

  [ -s "$_final" ] || { rm -f "$_final"; return; }

  # No change -> skip write and flash save
  if [ -f "$CACHE_FILE" ] && cmp -s "$_final" "$CACHE_FILE"; then
    rm -f "$_final"
    return
  fi

  _old_n=$(grep -c . "$CACHE_FILE" 2>/dev/null || echo 0)
  _new_n=$(grep -c . "$_final")

  # Safeguard 4: backup prev + atomic mv
  [ -s "$CACHE_FILE" ] && cp "$CACHE_FILE" "$PREV_FILE" 2>/dev/null
  mv "$_final" "$CACHE_FILE"
  log "domain cache updated from $dom: $_old_n -> $_new_n"
  persist_flash
}

# -------- PPTP helpers --------
pptp_tunnel_up() {
  iface_has_inet "$PPTP_TUN_IFACE" && return 0
  for _i in $(ifconfig 2>/dev/null | grep -o '^ppp[0-9]*'); do
    iface_has_inet "$_i" && return 0
  done
  return 1
}

restart_vpnc() {
  for _rc in /sbin/restart_vpnc /usr/sbin/restart_vpnc; do
    if [ -x "$_rc" ]; then
      "$_rc" >/dev/null 2>&1
      log "vpnc restarted via $_rc"
      return 0
    fi
  done
  killall pppd 2>/dev/null; sleep 2
  log "pppd killed, waiting for auto-restart"
}

verify_pptp_tunnel() {
  _try=0
  while [ "$_try" -lt 8 ]; do
    pptp_tunnel_up && return 0
    _try=$((_try + 1)); sleep 2
  done
  return 1
}

# -------- Flash save (with wear limit) --------
persist_flash() {
  cnt=$(cat "$SAVE_STAMP" 2>/dev/null || echo 0)
  [ -z "$cnt" ] && cnt=0
  if [ "$cnt" -ge "$MAX_FLASH_SAVES" ]; then
    log "flash save skipped (limit $MAX_FLASH_SAVES per session)"
    return 1
  fi
  for s in /sbin/mtd_storage.sh /usr/bin/mtd_storage.sh /bin/mtd_storage.sh \
           /usr/sbin/mtd_storage.sh /opt/bin/mtd_storage.sh \
           /sbin/flashfs /usr/bin/flashfs /usr/sbin/flashfs; do
    if [ -x "$s" ]; then
      if "$s" save >/dev/null 2>&1; then
        echo $((cnt + 1)) > "$SAVE_STAMP"
        log "flash save ok ($s)"
        return 0
      else
        log "flash save FAILED ($s)"
        return 1
      fi
    fi
  done
  log "flash save FAILED: save utility not found"
  return 1
}

# -------- nvram with read-back verification --------
nvram_set_verified() {
  _nv_key="$1"; _nv_val="$2"
  nvram set "$_nv_key=$_nv_val" >/dev/null 2>&1 || log "warn: nvram set $_nv_key failed"
  nvram commit >/dev/null 2>&1 || log "warn: nvram commit failed"
  _nv_got=$(nvram get "$_nv_key" 2>/dev/null)
  if [ "$_nv_got" = "$_nv_val" ]; then
    log "nvram $_nv_key = $_nv_got (OK)"
    return 0
  fi
  log "nvram PROBLEM: wrote $_nv_val, read back '$_nv_got'"
  return 1
}

# -------- Flash config (managed block) --------
# Writes remote + fast timeouts between markers. User's manual lines preserved.
storage_conf_sync() {
  _sc_ip="$1"; _sc_port="$2"; _sc_proto="$3"
  [ -z "$_sc_proto" ] && _sc_proto="udp"
  _sc_dir=$(dirname "$STORAGE_CONF")
  [ -d "$_sc_dir" ] || mkdir -p "$_sc_dir" 2>/dev/null

  _sc_tmp="${STORAGE_CONF}.new.$$"
  rm -f "${STORAGE_CONF}".new.* 2>/dev/null

  # Write managed block
  {
    echo "$MARK_START"
    echo "remote $_sc_ip $_sc_port $_sc_proto"
    echo "connect-timeout $OPT_CONNECT_TIMEOUT"
    echo "hand-window $OPT_HAND_WINDOW"
    echo "resolv-retry $OPT_RESOLV_RETRY"
    echo "$MARK_END"
  } > "$_sc_tmp"

  # Copy user's manual lines (skip old managed block)
  if [ -f "$STORAGE_CONF" ]; then
    _skip=0
    while IFS= read -r _l; do
      case "$_l" in
        "$MARK_START") _skip=1; continue ;;
        "$MARK_END")   _skip=0; continue ;;
      esac
      [ "$_skip" -eq 1 ] && continue
      # Also skip bare remote lines outside markers (legacy cleanup)
      echo "$_l" | grep -q '^remote ' && continue
      echo "$_l" >> "$_sc_tmp"
    done < "$STORAGE_CONF"
  fi

  # No change? skip flash write
  if [ -f "$STORAGE_CONF" ] && cmp -s "$_sc_tmp" "$STORAGE_CONF"; then
    rm -f "$_sc_tmp"
    return 1
  fi

  mv "$_sc_tmp" "$STORAGE_CONF" || { rm -f "$_sc_tmp"; log "storage conf write failed"; return 1; }
  log "storage conf updated: remote $_sc_ip $_sc_port $_sc_proto"
  persist_flash
  return 0
}

# Add fast timeouts to live runtime config if missing
ensure_runtime_opts() {
  [ -f "$RUNTIME_CONF" ] || return 0
  _add=""
  grep -q '^connect-timeout ' "$RUNTIME_CONF" || _add="${_add}connect-timeout $OPT_CONNECT_TIMEOUT
"
  grep -q '^hand-window ' "$RUNTIME_CONF" || _add="${_add}hand-window $OPT_HAND_WINDOW
"
  grep -q '^resolv-retry ' "$RUNTIME_CONF" || _add="${_add}resolv-retry $OPT_RESOLV_RETRY
"
  [ -z "$_add" ] && return 0
  printf '%s' "$_add" >> "$RUNTIME_CONF"
  log "runtime: added fast timeouts"
}

# -------- Self-update helpers --------
vt_get() {
  f="$1"; k="$2"
  grep "^[[:space:]]*$k[[:space:]]*=" "$f" 2>/dev/null | head -n1 \
    | sed "s/^[[:space:]]*$k[[:space:]]*=//" \
    | sed 's/#.*$//' | tr -d '\r' \
    | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

is_number() {
  [ -n "$1" ] || return 1
  echo "$1" | grep -q '^[0-9]\{1,6\}$'
}

candidate_ok() {
  f="$1"; want="$2"
  [ -s "$f" ] || { log "selfupd: file empty"; return 1; }
  sz=$(wc -c < "$f" 2>/dev/null || echo 0)
  [ "$sz" -lt "$MIN_SCRIPT_BYTES" ] && { log "selfupd: too small ($sz b)"; return 1; }
  head -n1 "$f" | grep -q '^#!/bin/sh' || { log "selfupd: no shebang"; return 1; }
  got=$(grep '^SELF_VERSION=' "$f" 2>/dev/null | head -n1 | cut -d= -f2 | tr -d '\r ')
  [ -z "$got" ] && { log "selfupd: no SELF_VERSION in file"; return 1; }
  [ "$got" != "$want" ] && { log "selfupd: version mismatch (want $want, got $got)"; return 1; }
  sh -n "$f" 2>/dev/null || { log "selfupd: SYNTAX ERROR"; return 1; }
  return 0
}

mark_failed() {
  echo "$1" >> "$FAIL_FILE"
  tail -n 20 "$FAIL_FILE" > "$FAIL_FILE.t" 2>/dev/null && mv "$FAIL_FILE.t" "$FAIL_FILE"
}

is_failed() {
  [ -f "$FAIL_FILE" ] || return 1
  grep -qx "$1" "$FAIL_FILE" 2>/dev/null
}

self_update() {
  _su_dom="$1"
  [ "$SELFUPD_ENABLE" -eq 1 ] || return 0
  [ -f "$SELF_FILE" ] || { log "selfupd: $SELF_FILE not found"; return 0; }

  vt="/tmp/version.txt"
  rm -f "$vt"
  wget -q -T 10 -O "$vt" "$SCHEME://$_su_dom$VERSION_PATH" || { rm -f "$vt"; return 0; }

  sv=$(vt_get "$vt" version)
  _cv=$(vt_get "$vt" canary_version)
  _cids=$(vt_get "$vt" canary_ids)
  rm -f "$vt"
  is_number "$sv" || { log "selfupd: no valid version= in version.txt"; return 0; }

  # Canary: if my id is in canary_ids, use canary_version instead
  TARGET="$sv"
  _why="general"
  _myid=$(router_id)
  if is_number "$_cv" && [ -n "$_cids" ] && [ -n "$_myid" ]; then
    for _one in $_cids; do
      _one=$(printf '%s' "$_one" | tr -cd 'A-Za-z0-9._-')
      if [ "$_one" = "$_myid" ]; then
        TARGET="$_cv"
        _why="canary"
        break
      fi
    done
  fi

  log "selfupd: my=$SELF_VERSION target=$TARGET ($_why) id=$_myid"
  [ "$TARGET" = "$SELF_VERSION" ] && return 0
  [ "$TARGET" -lt "$SELF_VERSION" ] 2>/dev/null && { log "selfupd: target older, skip"; return 0; }

  if is_failed "$TARGET"; then
    log "selfupd: version $TARGET already failed on this router, skip"
    return 0
  fi

  new="/tmp/update_script.new"
  rm -f "$new"
  wget -q -T 20 -O "$new" "$SCHEME://$_su_dom$SCRIPT_PATH" || {
    log "selfupd: download failed"; rm -f "$new"; return 0
  }

  candidate_ok "$new" "$TARGET" || { rm -f "$new"; return 0; }

  # backup current
  cp "$SELF_FILE" "$BAK_FILE" 2>/dev/null || {
    log "selfupd: backup failed, abort"; rm -f "$new"; return 0
  }

  # install
  cp "$new" "$SELF_FILE" 2>/dev/null || {
    log "selfupd: write failed"; rm -f "$new"; return 0
  }
  chmod 755 "$SELF_FILE" 2>/dev/null
  rm -f "$new"

  # selftest
  out=$(sh "$SELF_FILE" --selftest 2>&1)
  case "$out" in
    *"$SELFTEST_TOKEN $TARGET"*)
      log "selfupd: $SELF_VERSION -> $TARGET installed OK"
      persist_flash
      return 0
      ;;
  esac

  # rollback
  log "selfupd: selftest FAILED ($out) -> rollback"
  cp "$BAK_FILE" "$SELF_FILE" 2>/dev/null && chmod 755 "$SELF_FILE" 2>/dev/null
  mark_failed "$TARGET"
  persist_flash
  return 0
}

# -------- Router ID (for beacon) --------
router_id() {
  # Try hostname first (nvram computer_name), then MAC
  _rid=$(nvram get computer_name 2>/dev/null | tr -d '\r' | sed 's/[[:space:]]//g')
  if [ -z "$_rid" ] || [ "$_rid" = "(none)" ]; then
    _rid=$(nvram get lan_hwaddr 2>/dev/null | tr -d ':-' | tr 'ABCDEF' 'abcdef')
  fi
  if [ -z "$_rid" ]; then
    for i in /sbin/ifconfig /bin/ifconfig /usr/sbin/ifconfig /usr/bin/ifconfig; do
      if [ -x "$i" ]; then
        _rid=$("$i" br0 2>/dev/null | grep -o '[0-9A-Fa-f:]\{17\}' | head -n1 | tr -d ':-' | tr 'ABCDEF' 'abcdef')
        break
      fi
    done
  fi
  printf '%s' "$_rid" | tr -cd 'A-Za-z0-9._-'
}

# -------- Beacon --------
send_beacon() {
  [ "$BEACON_ENABLE" -eq 1 ] || return 0
  _b_dom="$1"; _b_res="$2"; _b_ip="$3"; _b_port="$4"
  [ -n "$_b_dom" ] || return 0

  _b_id=$(router_id)
  [ -n "$_b_id" ] || _b_id="unknown"

  if tunnel_up; then _b_tun="up"; else _b_tun="down"; fi

  _b_up=$(cut -d. -f1 /proc/uptime 2>/dev/null)
  echo "$_b_up" | grep -q '^[0-9]\{1,\}$' || _b_up=0

  [ -n "$_b_ip" ] || _b_ip="0.0.0.0"
  [ -n "$_b_port" ] || _b_port="0"
  [ -n "$_b_res" ] || _b_res="ok"

  _b_url="$SCHEME://$_b_dom${BEACON_PATH}?id=$_b_id&v=$SELF_VERSION&tun=$_b_tun&ip=$_b_ip&port=$_b_port&up=$_b_up&r=$_b_res"
  wget -q -T 10 -O /dev/null "$_b_url" 2>/dev/null
  return 0
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

# -------- Self-update check --------
self_update "$ACTIVE_DOMAIN"

# -------- Detect VPN type --------
VPN_TYPE=$(nvram get vpnc_type 2>/dev/null | tr -cd '0-9')
[ -z "$VPN_TYPE" ] && VPN_TYPE=3

# ======== PPTP mode ========
if [ "$VPN_TYPE" = "1" ]; then
  PPTP_IP=""; TMP_PPTP="/tmp/pptp_new_ip.txt"
  for D in $(read_domains); do
    if wget -q -T 15 -O "$TMP_PPTP" "$SCHEME://$D$PPTP_SOURCE_PATH" 2>/dev/null; then
      RAW=$(head -n1 "$TMP_PPTP" 2>/dev/null)
      RAW_CLEAN=$(clean_line "$RAW")
      [ -z "$RAW_CLEAN" ] && continue
      PPTP_IP="$RAW_CLEAN"
      echo "$PPTP_IP" | grep -q ':' && PPTP_IP=$(echo "$PPTP_IP" | cut -d: -f1)
      if is_valid_ipv4 "$PPTP_IP" && ! is_reserved_ipv4 "$PPTP_IP"; then
        break
      fi
      PPTP_IP=""
    fi
  done
  rm -f "$TMP_PPTP"

  if [ -z "$PPTP_IP" ]; then
    log "pptp: all domains failed"
    send_beacon "$ACTIVE_DOMAIN" "err" "" ""
    echo "$NOW" > "$STAMP_FILE"; exit 0
  fi

  CUR_PEER=$(nvram get vpnc_peer 2>/dev/null | tr -d '\r' | sed 's/[[:space:]]//g')

  if [ "$CUR_PEER" = "$PPTP_IP" ] && pptp_tunnel_up; then
    log "pptp: no change ($PPTP_IP), tunnel up -> ok"
    send_beacon "$ACTIVE_DOMAIN" "ok" "$PPTP_IP" "pptp"
    echo "$NOW" > "$STAMP_FILE"; exit 0
  fi

  if [ "$CUR_PEER" != "$PPTP_IP" ]; then
    log "pptp: ip change $CUR_PEER -> $PPTP_IP"
    nvram_set_verified vpnc_peer "$PPTP_IP"
  else
    log "pptp: ip ok ($PPTP_IP) but tunnel DOWN -> restart"
  fi

  restart_vpnc
  if verify_pptp_tunnel; then
    log "pptp: restart success, tunnel UP on $PPTP_IP"
  else
    log "pptp: restart done but tunnel still DOWN"
  fi

  send_beacon "$ACTIVE_DOMAIN" "fix" "$PPTP_IP" "pptp"
  echo "$NOW" > "$STAMP_FILE"
  log "done (pptp)"
  exit 0
fi

# ======== OpenVPN mode (default) ========

# -------- Parse current remote --------
REMOTE_LINE=$(grep '^remote ' "$RUNTIME_CONF" 2>/dev/null | head -n1)
CUR_IP=""; CUR_PORT=""; CUR_PROTO=""
if [ -n "$REMOTE_LINE" ]; then
  CUR_IP=$(echo "$REMOTE_LINE" | awk '{print $2}')
  CUR_PORT=$(echo "$REMOTE_LINE" | awk '{print $3}')
  CUR_PROTO=$(echo "$REMOTE_LINE" | awk '{print $4}')
fi
[ -z "$CUR_PORT" ] && CUR_PORT=$(nvram get vpnc_ov_port 2>/dev/null)
[ -z "$CUR_PORT" ] && CUR_PORT=443
[ -z "$CUR_PROTO" ] && CUR_PROTO="udp"

[ "$IP_SCAN_OFF" -eq 1 ] && NEW_IP="$CUR_IP"

# -------- Fetch port from server (if port scan enabled) --------
NEW_PORT="$CUR_PORT"
if [ "$PORT_SCAN_OFF" -ne 1 ]; then
  TMP_PORT="/tmp/vpn_new_port.txt"
  if wget -q -T 10 -O "$TMP_PORT" "$SCHEME://$ACTIVE_DOMAIN$PORT_PATH" 2>/dev/null; then
    RAW_PORT=$(head -n1 "$TMP_PORT" 2>/dev/null | tr -cd '0123456789')
    if [ -n "$RAW_PORT" ] && [ "$RAW_PORT" -ge 1 ] 2>/dev/null && [ "$RAW_PORT" -le 65535 ] 2>/dev/null; then
      NEW_PORT="$RAW_PORT"
      [ "$SHOW_FETCH" = "1" ] && log "port from server: $NEW_PORT"
    fi
  fi
  rm -f "$TMP_PORT"
fi

# -------- Fetch protocol from server --------
VPN_PROTO="$CUR_PROTO"
TMP_PROTO="/tmp/vpn_proto.txt"
if wget -q -T 10 -O "$TMP_PROTO" "$SCHEME://$ACTIVE_DOMAIN$PROTOCOL_PATH" 2>/dev/null; then
  RAW_PROTO=$(head -n1 "$TMP_PROTO" 2>/dev/null | tr -cd 'a-z')
  case "$RAW_PROTO" in
    tcp|udp) VPN_PROTO="$RAW_PROTO" ;;
  esac
  [ "$SHOW_FETCH" = "1" ] && log "proto from server: $VPN_PROTO"
fi
rm -f "$TMP_PROTO"

if is_reserved_ipv4 "$NEW_IP"; then
  log "reject bad ip ($NEW_IP) -> keep current"
  echo "$NOW" > "$STAMP_FILE"; exit 0
fi

# -------- Decide action (self-heal aware) --------
# Only a truly healthy state (IP+port+proto correct AND tunnel up) is a no-op.
if [ "$CUR_IP" = "$NEW_IP" ] && [ "$CUR_PORT" = "$NEW_PORT" ] && [ "$CUR_PROTO" = "$VPN_PROTO" ] && tunnel_up; then
  log "no change ($CUR_IP:$CUR_PORT:$VPN_PROTO), tunnel up -> ok"
  echo "$NOW" > "$STAMP_FILE"
  send_beacon "$ACTIVE_DOMAIN" "ok" "$NEW_IP" "$NEW_PORT"
  exit 0
fi

if [ "$CUR_IP" = "$NEW_IP" ] && [ "$CUR_PORT" = "$NEW_PORT" ] && [ "$CUR_PROTO" = "$VPN_PROTO" ]; then
  log "ip+port+proto ok ($CUR_IP:$CUR_PORT:$VPN_PROTO) but tunnel DOWN -> normalize + restart"
else
  [ "$CUR_IP" != "$NEW_IP" ] && log "ip change: $CUR_IP -> $NEW_IP"
  [ "$CUR_PORT" != "$NEW_PORT" ] && log "port change: $CUR_PORT -> $NEW_PORT"
  [ "$CUR_PROTO" != "$VPN_PROTO" ] && log "proto change: $CUR_PROTO -> $VPN_PROTO"
fi

# -------- Flash config (survives reboot) --------
storage_conf_sync "$NEW_IP" "$NEW_PORT" "$VPN_PROTO"

# -------- Normalize config to a SINGLE managed remote line --------
TMP_CONF="${RUNTIME_CONF}.tmp_edit"; : > "$TMP_CONF"; done_flag=0
while IFS= read -r line; do
  if echo "$line" | grep -q '^remote '; then
    if [ "$done_flag" -eq 0 ]; then
      echo "remote $NEW_IP $NEW_PORT $VPN_PROTO" >> "$TMP_CONF"; done_flag=1
    fi
    # drop any additional (dead) remote lines
  else
    echo "$line" >> "$TMP_CONF"
  fi
done < "$RUNTIME_CONF"
[ "$done_flag" -eq 0 ] && echo "remote $NEW_IP $NEW_PORT $VPN_PROTO" >> "$TMP_CONF"
mv "$TMP_CONF" "$RUNTIME_CONF"

NEW_RUNTIME=$(grep '^remote ' "$RUNTIME_CONF" | head -n1)
log "runtime now: $NEW_RUNTIME"
echo "$NEW_RUNTIME" | grep -q "remote $NEW_IP " || {
  log "edit failed (still '$NEW_RUNTIME')"
  echo "$NOW" > "$STAMP_FILE"
  send_beacon "$ACTIVE_DOMAIN" "err" "$NEW_IP" "$NEW_PORT"
  exit 1
}

ensure_runtime_opts

# -------- Full restart so OpenVPN actually uses the new remote --------
restart_openvpn
if verify_tunnel; then
  log "restart success: tunnel UP on $NEW_IP:$NEW_PORT"
else
  log "restart done but tunnel still DOWN -> will retry next run"
fi

echo "$NOW" > "$STAMP_FILE"
log "done"
send_beacon "$ACTIVE_DOMAIN" "fix" "$NEW_IP" "$NEW_PORT"
exit 0
