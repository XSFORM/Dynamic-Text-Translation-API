#!/bin/sh
# update_script.sh  --  unified OpenVPN "remote" updater for Padavan / BusyBox
# Version: v3.0_selfupdate
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

# -------- Flash save --------
persist_flash() {
  for s in /sbin/mtd_storage.sh /usr/bin/mtd_storage.sh /bin/mtd_storage.sh \
           /usr/sbin/mtd_storage.sh /opt/bin/mtd_storage.sh \
           /sbin/flashfs /usr/bin/flashfs /usr/sbin/flashfs; do
    if [ -x "$s" ]; then
      if "$s" save >/dev/null 2>&1; then
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

if is_reserved_ipv4 "$NEW_IP"; then
  log "reject bad ip ($NEW_IP) -> keep current"
  echo "$NOW" > "$STAMP_FILE"; exit 0
fi

# -------- Decide action (self-heal aware) --------
# Only a truly healthy state (IP+port correct AND tunnel up) is a no-op.
if [ "$CUR_IP" = "$NEW_IP" ] && [ "$CUR_PORT" = "$NEW_PORT" ] && tunnel_up; then
  log "no change ($CUR_IP:$CUR_PORT), tunnel up -> ok"
  echo "$NOW" > "$STAMP_FILE"
  send_beacon "$ACTIVE_DOMAIN" "ok" "$NEW_IP" "$NEW_PORT"
  exit 0
fi

NEED_NVRAM=0
if [ "$CUR_IP" = "$NEW_IP" ] && [ "$CUR_PORT" = "$NEW_PORT" ]; then
  log "ip+port ok ($CUR_IP:$CUR_PORT) but tunnel DOWN -> normalize + restart"
else
  if [ "$CUR_IP" != "$NEW_IP" ]; then
    log "ip change: $CUR_IP -> $NEW_IP"
    nvram set vpnc_peer="$NEW_IP" >/dev/null 2>&1 || log "warn: nvram set ip failed"
    NEED_NVRAM=1
  fi
  if [ "$CUR_PORT" != "$NEW_PORT" ]; then
    log "port change: $CUR_PORT -> $NEW_PORT"
    nvram set vpnc_ov_port="$NEW_PORT" >/dev/null 2>&1 || log "warn: nvram set port failed"
    NEED_NVRAM=1
  fi
  [ "$NEED_NVRAM" -eq 1 ] && nvram commit >/dev/null 2>&1
fi

# -------- Normalize config to a SINGLE managed remote line --------
TMP_CONF="${RUNTIME_CONF}.tmp_edit"; : > "$TMP_CONF"; done_flag=0
while IFS= read -r line; do
  if echo "$line" | grep -q '^remote '; then
    if [ "$done_flag" -eq 0 ]; then
      echo "remote $NEW_IP $NEW_PORT" >> "$TMP_CONF"; done_flag=1
    fi
    # drop any additional (dead) remote lines
  else
    echo "$line" >> "$TMP_CONF"
  fi
done < "$RUNTIME_CONF"
[ "$done_flag" -eq 0 ] && echo "remote $NEW_IP $NEW_PORT" >> "$TMP_CONF"
mv "$TMP_CONF" "$RUNTIME_CONF"

NEW_RUNTIME=$(grep '^remote ' "$RUNTIME_CONF" | head -n1)
log "runtime now: $NEW_RUNTIME"
echo "$NEW_RUNTIME" | grep -q "remote $NEW_IP " || {
  log "edit failed (still '$NEW_RUNTIME')"
  echo "$NOW" > "$STAMP_FILE"
  send_beacon "$ACTIVE_DOMAIN" "err" "$NEW_IP" "$NEW_PORT"
  exit 1
}

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
