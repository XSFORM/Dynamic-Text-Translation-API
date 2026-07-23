# -*- coding: utf-8 -*-
"""
Unified Telegram Bot — OpenVPN management + Remote Refresh IP updater.
Runs as root. Single token, single process.
"""

import asyncio
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List, Dict
from html import escape
import glob
import json
import traceback
import re
import hashlib
import tempfile
import requests
import shutil
import socket
import logging
import paramiko

from OpenSSL import crypto
import pytz
import pyzipper

from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
)
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, ContextTypes,
    MessageHandler, filters
)

from config import TOKEN, ADMIN_ID
from backup_restore import (
    create_backup as br_create_backup,
    apply_restore,
    BACKUP_OUTPUT_DIR,
    MANIFEST_NAME
)

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# =====================================================================
#  OPENVPN SECTION — Constants / Globals
# =====================================================================
BOT_VERSION = "HYBRID OVPN+RR v2.3"
UPDATE_SOURCE_URL = "https://raw.githubusercontent.com/XSFORM/update_bot/main/openvpn_monitor_bot.py"
SIMPLE_UPDATE_CMD = (
    "curl -L -o /root/monitor_bot/openvpn_monitor_bot.py "
    f"{UPDATE_SOURCE_URL} && systemctl restart vpn_bot.service"
)

TELEGRAPH_TOKEN_FILE = "/root/monitor_bot/telegraph_token.txt"
TELEGRAPH_SHORT_NAME = "vpn-bot"
TELEGRAPH_AUTHOR = "VPN Bot"

KEYS_DIR = "/root"
OPENVPN_DIR = "/etc/openvpn"
EASYRSA_DIR = "/etc/openvpn/easy-rsa"
STATUS_LOG = "/var/log/openvpn/status.log"
CCD_DIR = "/etc/openvpn/ccd"

SEND_NEW_OVPN_ON_RENEW = False
TM_TZ = pytz.timezone("Asia/Ashgabat")

MGMT_SOCKET = "/var/run/openvpn.sock"
MANAGEMENT_HOST = "127.0.0.1"
MANAGEMENT_PORT = 7505
MANAGEMENT_TIMEOUT = 3

MIN_ONLINE_ALERT = 15
ALERT_INTERVAL_SEC = 300
last_alert_time = 0
alert_enabled = True
clients_last_online = set()

TRAFFIC_DB_PATH = "/root/monitor_bot/traffic_usage.json"
traffic_usage: Dict[str, Dict[str, int]] = {}
_last_session_state = {}
_last_traffic_save_time = 0
TRAFFIC_SAVE_INTERVAL = 60

CLIENT_META_PATH = "/root/monitor_bot/clients_meta.json"
client_meta: Dict[str, Dict[str, str]] = {}

ENFORCE_INTERVAL_SECONDS = 43200  # 12 hours

ROOT_ARCHIVE_EXCLUDE_GLOBS = ["/root/*.tar.gz", "/root/*.tgz"]
EXCLUDE_TEMP_DIR = "/root/monitor_bot/.excluded_root_archives"

PAGE_SIZE_KEYS = 40

MENU_MESSAGE_ID = None
MENU_CHAT_ID = None

_notified_expiry: Dict[str, str] = {}
UPCOMING_EXPIRY_DAYS = 1

# =====================================================================
#  REMOTE REFRESH SECTION — Constants
# =====================================================================
RR_IP_FILE = "/var/www/html/current_vpn_ip.txt"
RR_HISTORY_FILE = "/var/lib/remote_refresh/history.log"
RR_IP_SCAN_FLAG = "/var/www/html/ip_scan_off.txt"
RR_PORT_SCAN_FLAG = "/var/www/html/port_scan_off.txt"
RR_DOMAIN_LIST_FILE = "/var/www/html/router/domain_list.txt"
RR_ENV_FILE = "/etc/remote-refresh.env"
RR_BACKUP_PASSWORD = b"canonical87"

# =====================================================================
#  AUTO IP — pool & monitoring
# =====================================================================
AUTO_IP_POOL_FILE = "/root/monitor_bot/ip_pool.json"
AUTO_IP_STATE_FILE = "/root/monitor_bot/auto_ip_state.json"
DEPLOY_FRONT_IP_FILE = "/root/monitor_bot/deploy_front_ip.txt"
AUTO_IP_TM_CHECK = "217.174.235.161"       # Turkmentelecom probe IP
AUTO_IP_FAIL_THRESHOLD = 3                  # consecutive ping fails before switch
AUTO_IP_CHECK_INTERVAL = 60                 # seconds between checks
auto_ip_fail_count = 0

def _load_auto_ip_state() -> bool:
    if os.path.exists(AUTO_IP_STATE_FILE):
        try:
            with open(AUTO_IP_STATE_FILE) as f:
                return json.load(f).get("enabled", False)
        except Exception:
            pass
    return False

def _save_auto_ip_state(enabled: bool):
    try:
        with open(AUTO_IP_STATE_FILE, "w") as f:
            json.dump({"enabled": enabled}, f)
    except Exception:
        pass

auto_ip_enabled = _load_auto_ip_state()

def load_ip_pool() -> list:
    if os.path.exists(AUTO_IP_POOL_FILE):
        try:
            with open(AUTO_IP_POOL_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_ip_pool(pool: list) -> None:
    with open(AUTO_IP_POOL_FILE, "w") as f:
        json.dump(pool, f, indent=2, ensure_ascii=False)

def ping_via_ssh(host: str, user: str, password: str, target: str) -> bool:
    """SSH into host and ping target. Returns True if ping succeeds."""
    ok, out = ssh_exec(host, 22, user, password, f"ping -c 1 -W 3 {target}")
    print(f"[auto_ip] ping_via_ssh {host} -> {target}: ok={ok}, out={out!a}")
    if ok and ("1 received" in out or "bytes from" in out):
        return True
    return False

# =====================================================================
#  OVPN EDIT — file paths
# =====================================================================
OVPN_EDIT_FILES = {
    "server_conf": "/etc/openvpn/server.conf",
    "client_template": "/etc/openvpn/client-template.txt",
}

# =====================================================================
#  SSH ROUTERS — config
# =====================================================================
ROUTERS_FILE = "/root/monitor_bot/routers.json"
IPP_FILE = "/etc/openvpn/ipp.txt"
SSH_TIMEOUT = 10
SSH_CMD_TIMEOUT = 15

def load_routers() -> Dict:
    try:
        with open(ROUTERS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_routers(data: Dict):
    with open(ROUTERS_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def get_router_ip(cn: str) -> Optional[str]:
    """Get router VPN IP from ipp.txt by CN name."""
    try:
        with open(IPP_FILE, "r") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) >= 2 and parts[0] == cn:
                    return parts[1]
    except FileNotFoundError:
        pass
    return None

def get_online_clients() -> set:
    """Get set of currently connected client CNs from status.log."""
    online = set()
    try:
        with open(STATUS_LOG, "r") as f:
            in_routing = False
            for line in f:
                line = line.strip()
                if line.startswith("ROUTING TABLE"):
                    in_routing = True
                    continue
                if line.startswith("GLOBAL STATS"):
                    break
                if in_routing and "," in line and not line.startswith("Virtual"):
                    parts = line.split(",")
                    if len(parts) >= 2:
                        online.add(parts[1])
    except FileNotFoundError:
        pass
    return online

def ssh_exec(ip: str, port: int, user: str, password: str, command: str) -> Tuple[bool, str]:
    """Execute SSH command on router. Returns (success, output)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=port, username=user, password=password,
                       timeout=SSH_TIMEOUT, look_for_keys=False, allow_agent=False)
        stdin, stdout, stderr = client.exec_command(command, timeout=SSH_CMD_TIMEOUT)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        result = out if out else err
        return True, result if result else "(пустой вывод)"
    except paramiko.AuthenticationException:
        return False, "Ошибка авторизации (неверный логин/пароль)"
    except paramiko.SSHException as e:
        return False, f"SSH ошибка: {e}"
    except socket.timeout:
        return False, "Таймаут подключения"
    except Exception as e:
        return False, f"Ошибка: {e}"
    finally:
        client.close()

def ssh_exec_key(ip: str, port: int, user: str, key_path: str, command: str,
                 sudo_pass: str = None) -> Tuple[bool, str]:
    """Execute SSH command using PEM key file. Optionally wrap in sudo."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        pkey = paramiko.RSAKey.from_private_key_file(key_path)
    except Exception:
        try:
            pkey = paramiko.Ed25519Key.from_private_key_file(key_path)
        except Exception:
            try:
                pkey = paramiko.ECDSAKey.from_private_key_file(key_path)
            except Exception as e:
                return False, f"Ошибка чтения ключа: {e}"
    try:
        client.connect(ip, port=port, username=user, pkey=pkey,
                       timeout=SSH_TIMEOUT, look_for_keys=False, allow_agent=False)
        if sudo_pass:
            # Use sudo with password via stdin
            cmd = f"echo '{sudo_pass}' | sudo -S bash -c '{command}'"
        else:
            cmd = f"sudo {command}" if user != "root" else command
        stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        # Filter out sudo password prompt noise
        if err:
            err = "\n".join(l for l in err.split("\n") if "[sudo]" not in l and "password" not in l.lower())
        result = out if out else err
        return True, result if result else "(пустой вывод)"
    except paramiko.AuthenticationException:
        return False, "Ошибка авторизации (неверный ключ или пользователь)"
    except paramiko.SSHException as e:
        return False, f"SSH ошибка: {e}"
    except socket.timeout:
        return False, "Таймаут подключения"
    except Exception as e:
        return False, f"Ошибка: {e}"
    finally:
        client.close()

GOST_KEYS_DIR = "/root/monitor_bot/gost_keys"

# =====================================================================
#  GOST SECTION — Constants / Storage
# =====================================================================
GOST_SERVERS_FILE = "/root/monitor_bot/gost_servers.json"
GOST_BIN = "/usr/local/bin/gost"
GOST_SERVICE_PATH = "/usr/lib/systemd/system/gost.service"
GOST_BACKUP_DIR = "/var/backups/gost-xsform"
GOST_REPO = "ginuerzh/gost"

def load_gost_servers() -> Dict:
    try:
        with open(GOST_SERVERS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_gost_servers(data: Dict):
    with open(GOST_SERVERS_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# =====================================================================
#  NATURAL SORT
# =====================================================================
_nat_num_re = re.compile(r'(\d+)')

def _natural_key(s: str):
    return [int(x) if x.isdigit() else x.lower() for x in _nat_num_re.split(s)]

def natural_sorted(seq: List[str]) -> List[str]:
    return sorted(seq, key=_natural_key)

def locate_backup(fname: str) -> Optional[str]:
    if fname.startswith("/"):
        if os.path.isfile(fname):
            return fname
    try:
        if 'BACKUP_OUTPUT_DIR' in globals() and BACKUP_OUTPUT_DIR:
            p = os.path.join(BACKUP_OUTPUT_DIR, fname)
            if os.path.isfile(p):
                return p
    except Exception:
        pass
    p2 = os.path.join("/root", fname)
    if os.path.isfile(p2):
        return p2
    p3 = os.path.join("/root/backups", fname)
    if os.path.isfile(p3):
        return p3
    return None

# =====================================================================
#  OPENVPN — Logical expiry
# =====================================================================
def load_client_meta():
    global client_meta
    try:
        if os.path.exists(CLIENT_META_PATH):
            with open(CLIENT_META_PATH, "r") as f:
                client_meta = json.load(f)
        else:
            client_meta = {}
    except Exception as e:
        print(f"[meta] load error: {e}")
        client_meta = {}

def save_client_meta():
    try:
        tmp = CLIENT_META_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(client_meta, f)
        os.replace(tmp, CLIENT_META_PATH)
    except Exception as e:
        print(f"[meta] save error: {e}")

def set_client_expiry_days_from_now(name: str, days: int) -> str:
    if days < 1:
        days = 1
    dt = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=days)
    iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    client_meta.setdefault(name, {})["expire"] = iso
    save_client_meta()
    unblock_client_ccd(name)
    return iso

def get_client_expiry(name: str) -> Tuple[Optional[str], Optional[int]]:
    data = client_meta.get(name)
    if not data:
        return None, None
    iso = data.get("expire")
    if not iso:
        return None, None
    try:
        dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
        return iso, (dt - datetime.now(timezone.utc).replace(tzinfo=None)).days
    except Exception:
        return iso, None

def enforce_client_expiries():
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    changed = False
    for name, data in list(client_meta.items()):
        iso = data.get("expire")
        if not iso:
            continue
        try:
            dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
        if now > dt and not is_client_ccd_disabled(name):
            block_client_ccd(name)
            disconnect_client_sessions(name)
            changed = True
    if changed:
        print("[meta] enforced expiries")

def check_and_notify_expiring(bot):
    if not client_meta:
        return
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for name, data in client_meta.items():
        iso = data.get("expire")
        if not iso:
            continue
        try:
            dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
        days_left = (dt - now).days
        if days_left == UPCOMING_EXPIRY_DAYS and not is_client_ccd_disabled(name):
            if _notified_expiry.get(name) == iso:
                continue
            try:
                bot.send_message(
                    ADMIN_ID,
                    f"⚠️ Клиент {name} истекает через {days_left} день (до {iso}). Продли: ⌛ Обновить ключ."
                )
                _notified_expiry[name] = iso
            except Exception as e:
                print(f"[notify_expiring] fail {name}: {e}")
        elif _notified_expiry.get(name) and _notified_expiry.get(name) != iso and days_left >= 0:
            _notified_expiry.pop(name, None)

# =====================================================================
#  OPENVPN — Management (disconnect sessions)
# =====================================================================
def _mgmt_tcp_command(cmd: str) -> str:
    data = b""
    with socket.create_connection((MANAGEMENT_HOST, MANAGEMENT_PORT), MANAGEMENT_TIMEOUT) as s:
        s.settimeout(MANAGEMENT_TIMEOUT)
        try: data += s.recv(4096)
        except Exception: pass
        s.sendall((cmd.strip() + "\n").encode())
        time.sleep(0.15)
        try:
            while True:
                chunk = s.recv(65535)
                if not chunk: break
                data += chunk
                if len(chunk) < 65535: break
        except Exception: pass
        try: s.sendall(b"quit\n")
        except Exception: pass
    return data.decode(errors="ignore")

def disconnect_client_sessions(client_name: str) -> bool:
    try:
        out = _mgmt_tcp_command(f"client-kill {client_name}")
        if out:
            print(f"[mgmt] client-kill {client_name} -> {out.strip()[:120]}")
            return True
    except Exception:
        pass
    if os.path.exists(MGMT_SOCKET):
        try:
            subprocess.run(f'echo "kill {client_name}" | nc -U {MGMT_SOCKET}', shell=True)
            print(f"[mgmt] unix kill {client_name}")
            return True
        except Exception as e:
            print(f"[mgmt] unix kill failed {client_name}: {e}")
    return False

# =====================================================================
#  OPENVPN — Update helpers
# =====================================================================
async def show_update_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    await update.message.reply_text(
        f"<b>Команда обновления:</b>\n<code>{SIMPLE_UPDATE_CMD}</code>",
        parse_mode="HTML"
    )

async def send_simple_update_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True); return
    await q.answer()
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("📋 Копия", callback_data="copy_update_cmd")]])
    await context.bot.send_message(
        chat_id=q.message.chat_id,
        text=f"<b>Команда обновления (версия {BOT_VERSION}):</b>\n<code>{SIMPLE_UPDATE_CMD}</code>",
        parse_mode="HTML",
        reply_markup=kb
    )

async def resend_update_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True); return
    await q.answer("Отправлено")
    await context.bot.send_message(chat_id=q.message.chat_id, text=f"<code>{SIMPLE_UPDATE_CMD}</code>", parse_mode="HTML")

# =====================================================================
#  OPENVPN — Helpers
# =====================================================================
def get_ovpn_files():
    return [f for f in os.listdir(KEYS_DIR) if f.endswith(".ovpn")]

def is_client_ccd_disabled(client_name):
    p = os.path.join(CCD_DIR, client_name)
    if not os.path.exists(p): return False
    try:
        with open(p, "r") as f:
            return "disable" in f.read().lower()
    except:
        return False

def block_client_ccd(client_name):
    os.makedirs(CCD_DIR, exist_ok=True)
    with open(os.path.join(CCD_DIR, client_name), "w") as f:
        f.write("disable\n")
    disconnect_client_sessions(client_name)

def unblock_client_ccd(client_name):
    os.makedirs(CCD_DIR, exist_ok=True)
    with open(os.path.join(CCD_DIR, client_name), "w") as f:
        f.write("enable\n")

def split_message(text, max_length=4000):
    lines = text.split('\n')
    out, cur = [], ""
    for line in lines:
        if len(cur) + len(line) + 1 <= max_length:
            cur += line + "\n"
        else:
            out.append(cur); cur = line + "\n"
    if cur: out.append(cur)
    return out

def format_clients_by_certs():
    cert_dir = f"{EASYRSA_DIR}/pki/issued/"
    if not os.path.isdir(cert_dir):
        return "<b>Список клиентов:</b>\n\nКаталог issued отсутствует."
    certs = [f for f in os.listdir(cert_dir) if f.endswith(".crt")]
    certs = sorted(certs, key=lambda x: _natural_key(x[:-4]))
    res = "<b>Список клиентов (по сертификатам):</b>\n\n"
    idx = 1
    for f in certs:
        name = f[:-4]
        if name.startswith("server_"):
            continue
        mark = "⛔" if is_client_ccd_disabled(name) else "🟢"
        res += f"{idx}. {mark} <b>{name}</b>\n"
        idx += 1
    if idx == 1:
        res += "Нет выданных сертификатов."
    return res

def parse_remote_proto_from_ovpn(path: str):
    remote = ""; proto = ""
    try:
        with open(path, "r") as f:
            for line in f:
                ls = line.strip()
                if ls.startswith("remote "):
                    parts = ls.split()
                    if len(parts) >= 3:
                        remote = parts[2]
                elif ls.startswith("proto "):
                    proto = ls.split()[1]
                if remote and proto:
                    break
    except:
        pass
    return f"{remote}:{proto}" if (remote or proto) else ""

def get_cert_days_left(client_name: str) -> Optional[int]:
    cert_path = f"{EASYRSA_DIR}/pki/issued/{client_name}.crt"
    if not os.path.exists(cert_path): return None
    try:
        with open(cert_path, "rb") as f:
            data = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
        not_after = cert.get_notAfter().decode("ascii")
        expiry_dt = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")
        return (expiry_dt - datetime.now(timezone.utc).replace(tzinfo=None)).days
    except Exception:
        return None

def gather_key_metadata():
    rows = []
    files = get_ovpn_files()
    files = sorted(files, key=lambda x: _natural_key(x[:-5]))
    for f in files:
        name = f[:-5]
        days = get_cert_days_left(name)
        days_str = str(days) if days is not None else "-"
        ovpn_path = os.path.join(KEYS_DIR, f)
        cfg = parse_remote_proto_from_ovpn(ovpn_path)
        crt_path = f"{EASYRSA_DIR}/pki/issued/{name}.crt"
        ctime = "-"
        try:
            path_for_time = crt_path if os.path.exists(crt_path) else ovpn_path
            ts = os.path.getmtime(path_for_time)
            ctime = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
        except:
            pass
        rows.append({"name": name, "days": days_str, "cfg": cfg, "created": ctime})
    return rows

def build_keys_table_text(rows: List[Dict]):
    if not rows: return "Нет ключей."
    name_w = max([len(r["name"]) for r in rows] + [4])
    cfg_w = max([len(r["cfg"]) for r in rows] + [6])
    days_w = max([len(r["days"]) for r in rows] + [4])
    header = f"N | {'Имя'.ljust(name_w)} | {'СерДн'.ljust(days_w)} | {'Конфиг'.ljust(cfg_w)} | Создан"
    lines = [header]
    for i, r in enumerate(rows, 1):
        lines.append(f"{i} | {r['name'].ljust(name_w)} | {r['days'].ljust(days_w)} | {r['cfg'].ljust(cfg_w)} | {r['created']}")
    return "\n".join(lines)

# =====================================================================
#  OPENVPN — Telegraph
# =====================================================================
def get_telegraph_token() -> Optional[str]:
    try:
        if os.path.exists(TELEGRAPH_TOKEN_FILE):
            with open(TELEGRAPH_TOKEN_FILE, "r") as f:
                tok = f.read().strip()
                if tok: return tok
        resp = requests.post("https://api.telegra.ph/createAccount",
                             data={"short_name": TELEGRAPH_SHORT_NAME,"author_name": TELEGRAPH_AUTHOR},
                             timeout=10)
        data = resp.json()
        token = data.get("result", {}).get("access_token")
        if token:
            os.makedirs(os.path.dirname(TELEGRAPH_TOKEN_FILE), exist_ok=True)
            with open(TELEGRAPH_TOKEN_FILE, "w") as f:
                f.write(token)
            return token
    except Exception as e:
        print(f"[telegraph] token error: {e}")
    return None

def create_telegraph_pre_page(title: str, text: str) -> Optional[str]:
    token = get_telegraph_token()
    if not token: return None
    content_nodes = json.dumps([{"tag": "pre", "children": [text]}], ensure_ascii=False)
    try:
        resp = requests.post("https://api.telegra.ph/createPage", data={
            "access_token": token,
            "title": title,
            "author_name": TELEGRAPH_AUTHOR,
            "content": content_nodes,
            "return_content": "false"
        }, timeout=15)
        data = resp.json()
        return data.get("result", {}).get("url")
    except Exception as e:
        print(f"[telegraph] create page error: {e}")
        return None

def create_keys_detailed_page():
    rows = gather_key_metadata()
    if not rows: return None
    text = "Полный список ключей (СерДн = остаток по сертификату, не логический срок)\n\n" + build_keys_table_text(rows)
    return create_telegraph_pre_page("Список ключей", text)

def create_names_telegraph_page(names: List[str], title: str, caption: str) -> Optional[str]:
    if not names: return None
    names = natural_sorted(names)
    lines = [caption, ""]
    for i, n in enumerate(names, 1):
        lines.append(f"{i}. {n}")
    return create_telegraph_pre_page(title, "\n".join(lines))

# =====================================================================
#  OPENVPN — Bulk selection parser
# =====================================================================
def parse_bulk_selection(text: str, max_index: int) -> Tuple[List[int], List[str]]:
    text = text.strip().lower()
    if not text: return [], ["Пустой ввод."]
    if text == "all":
        return list(range(1, max_index + 1)), []
    parts = re.split(r"[,\s]+", text)
    chosen, errors = set(), []
    for p in parts:
        if not p: continue
        if re.fullmatch(r"\d+", p):
            idx = int(p)
            if 1 <= idx <= max_index: chosen.add(idx)
            else: errors.append(f"Число вне диапазона: {p}")
        elif re.fullmatch(r"\d+-\d+", p):
            a, b = p.split('-'); a, b = int(a), int(b)
            if a > b: a, b = b, a
            if a < 1 or b > max_index:
                errors.append(f"Диапазон вне диапазона: {p}")
                continue
            for i in range(a, b + 1):
                chosen.add(i)
        else:
            errors.append(f"Неверный фрагмент: {p}")
    return sorted(chosen), errors

# =====================================================================
#  OPENVPN — Bulk delete
# =====================================================================
def revoke_and_collect(names: List[str]) -> Tuple[List[str], List[str]]:
    revoked, failed = [], []
    for name in names:
        cert_path = f"{EASYRSA_DIR}/pki/issued/{name}.crt"
        if not os.path.exists(cert_path):
            revoked.append(name); continue
        try:
            subprocess.run(f"cd {EASYRSA_DIR} && ./easyrsa --batch revoke {name}", shell=True, check=True)
            revoked.append(name)
        except subprocess.CalledProcessError as e:
            failed.append(f"{name}: revoke error {e}")
    return revoked, failed

def generate_crl_once() -> Optional[str]:
    try:
        subprocess.run(f"cd {EASYRSA_DIR} && EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl", shell=True, check=True)
        crl_src = f"{EASYRSA_DIR}/pki/crl.pem"; crl_dst = "/etc/openvpn/crl.pem"
        if os.path.exists(crl_src):
            subprocess.run(f"cp {crl_src} {crl_dst}", shell=True, check=True)
            os.chmod(crl_dst, 0o644)
        return "OK"
    except Exception as e:
        return f"CRL error: {e}"

def remove_client_files(name: str):
    paths = [
        os.path.join(KEYS_DIR, f"{name}.ovpn"),
        f"{EASYRSA_DIR}/pki/issued/{name}.crt",
        f"{EASYRSA_DIR}/pki/private/{name}.key",
        f"{EASYRSA_DIR}/pki/reqs/{name}.req",
        os.path.join(CCD_DIR, name)
    ]
    for p in paths:
        try:
            if os.path.exists(p): os.remove(p)
        except Exception as e:
            print(f"[delete] cannot remove {p}: {e}")
    if name in client_meta:
        client_meta.pop(name, None); save_client_meta()
    if name in traffic_usage:
        traffic_usage.pop(name, None); save_traffic_db(force=True)

# =====================================================================
#  OPENVPN — Backup (hide archives from /root)
# =====================================================================
TMP_EXCLUDE_DIR = "/tmp/._exclude_root_archives"

def _temporarily_hide_root_backup_stuff() -> List[Tuple[str, str, str]]:
    os.makedirs(TMP_EXCLUDE_DIR, exist_ok=True)
    moved: List[Tuple[str, str, str]] = []
    for pattern in ("/root/*.tar.gz", "/root/*.tgz"):
        for src in glob.glob(pattern):
            dst = os.path.join(TMP_EXCLUDE_DIR, os.path.basename(src))
            try:
                if os.path.abspath(src) != os.path.abspath(dst):
                    if os.path.exists(dst): os.remove(dst)
                    shutil.move(src, dst)
                    moved.append(("file", src, dst))
            except Exception as e:
                print(f"[backup exclude] cannot move {src}: {e}")
    backups_dir = "/root/backups"
    if os.path.isdir(backups_dir):
        dst_dir = os.path.join(TMP_EXCLUDE_DIR, "__backups_dir__")
        try:
            if os.path.exists(dst_dir): shutil.rmtree(dst_dir, ignore_errors=True)
            shutil.move(backups_dir, dst_dir)
            moved.append(("dir", backups_dir, dst_dir))
        except Exception as e:
            print(f"[backup exclude] cannot move {backups_dir}: {e}")
    return moved

def _restore_hidden_root_backup_stuff(moved: List[Tuple[str, str, str]]):
    for kind, src, dst in reversed(moved):
        try:
            if os.path.exists(src):
                if os.path.exists(dst):
                    if kind == "dir": shutil.rmtree(dst, ignore_errors=True)
                    else: os.remove(dst)
                continue
            if os.path.exists(dst):
                os.makedirs(os.path.dirname(src), exist_ok=True)
                shutil.move(dst, src)
        except Exception as e:
            print(f"[backup exclude] cannot restore {src}: {e}")

def create_backup_in_root_excluding_archives() -> str:
    moved = _temporarily_hide_root_backup_stuff()
    try:
        path = br_create_backup()
        if not path or not os.path.exists(path):
            raise RuntimeError("Backup creation failed (no path returned)")
        dest = os.path.join("/root", os.path.basename(path))
        if os.path.abspath(path) != os.path.abspath(dest):
            if os.path.exists(dest): os.remove(dest)
            shutil.move(path, dest)
        else:
            dest = path
        return dest
    finally:
        _restore_hidden_root_backup_stuff(moved)

# =====================================================================
#  OPENVPN — Bulk handlers (delete/send/enable/disable)
# =====================================================================
async def start_bulk_delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    rows = gather_key_metadata()
    if not rows:
        await safe_edit_text(q, context, "Нет ключей."); return
    url = create_keys_detailed_page()
    if not url:
        await safe_edit_text(q, context, "Ошибка Telegraph."); return
    keys_order = [r["name"] for r in rows]
    context.user_data['bulk_delete_keys'] = keys_order
    context.user_data['await_bulk_delete_numbers'] = True
    text = ("<b>Удаление ключей</b>\n"
            "Формат: all | 1 | 1,2,5 | 3-7 | 1,2,5-9\n"
            f"<a href=\"{url}\">Полный список</a>\n\nОтправьте строку с номерами.")
    await safe_edit_text(q, context, text, parse_mode="HTML",
                         reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_delete")]]))

async def process_bulk_delete_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_bulk_delete_numbers'): return
    keys_order: List[str] = context.user_data.get('bulk_delete_keys', [])
    if not keys_order:
        await update.message.reply_text("Список потерян. Начните снова.")
        context.user_data.pop('await_bulk_delete_numbers', None); return
    selection_text = update.message.text.strip()
    idxs, errs = parse_bulk_selection(selection_text, len(keys_order))
    if errs:
        await update.message.reply_text("Ошибки:\n" + "\n".join(errs) + "\nПовторите ввод.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_delete")]]))
        return
    if not idxs:
        await update.message.reply_text("Ничего не выбрано.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_delete")]]))
        return
    selected_names = [keys_order[i - 1] for i in idxs]
    context.user_data['bulk_delete_selected'] = selected_names
    context.user_data['await_bulk_delete_numbers'] = False
    preview = "\n".join(selected_names[:25])
    if len(selected_names) > 25:
        preview += f"\n... ещё {len(selected_names)-25}"
    await update.message.reply_text(
        f"<b>Удалить ключи ({len(selected_names)}):</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_delete_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_delete")]
        ])
    )

async def bulk_delete_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    selected: List[str] = context.user_data.get('bulk_delete_selected', [])
    if not selected:
        await safe_edit_text(q, context, "Пусто."); return
    revoked, failed = revoke_and_collect(selected)
    crl_status = generate_crl_once()
    for name in revoked:
        remove_client_files(name)
        disconnect_client_sessions(name)
    context.user_data.pop('bulk_delete_selected', None)
    context.user_data.pop('bulk_delete_keys', None)
    summary = (f"<b>Удаление завершено</b>\n"
               f"Запрошено: {len(selected)}\nRevoked: {len(revoked)}\nОшибок: {len(failed)}\nCRL: {crl_status}")
    if failed:
        summary += "\n\n<b>Ошибки:</b>\n" + "\n".join(failed[:10])
        if len(failed) > 10:
            summary += f"\n... ещё {len(failed)-10}"
    await safe_edit_text(q, context, summary, parse_mode="HTML")

async def bulk_delete_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    for k in ['bulk_delete_selected', 'bulk_delete_keys', 'await_bulk_delete_numbers']:
        context.user_data.pop(k, None)
    await safe_edit_text(q, context, "Массовое удаление отменено.")

# --- Bulk send ---
async def start_bulk_send(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    files = get_ovpn_files()
    files = sorted(files, key=lambda x: _natural_key(x[:-5]))
    if not files:
        await safe_edit_text(q, context, "Нет ключей."); return
    names = [f[:-5] for f in files]
    url = create_names_telegraph_page(names, "Отправка ключей", "Список ключей")
    if not url:
        await safe_edit_text(q, context, "Ошибка Telegraph."); return
    context.user_data['bulk_send_keys'] = names
    context.user_data['await_bulk_send_numbers'] = True
    text = ("<b>Отправить ключи</b>\n"
            "Формат: all | 1 | 1,2,5 | 3-7 | 1,2,5-9\n"
            f"<a href=\"{url}\">Список</a>\n\nПришлите строку.")
    await safe_edit_text(q, context, text, parse_mode="HTML",
                         reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_send")]]))

async def process_bulk_send_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_bulk_send_numbers'): return
    names: List[str] = context.user_data.get('bulk_send_keys', [])
    if not names:
        await update.message.reply_text("Список потерян. Начните заново.")
        context.user_data.pop('await_bulk_send_numbers', None); return
    idxs, errs = parse_bulk_selection(update.message.text.strip(), len(names))
    if errs:
        await update.message.reply_text("Ошибки:\n" + "\n".join(errs),
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_send")]]))
        return
    if not idxs:
        await update.message.reply_text("Ничего не выбрано.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_send")]]))
        return
    selected = [names[i - 1] for i in idxs]
    context.user_data['bulk_send_selected'] = selected
    context.user_data['await_bulk_send_numbers'] = False
    preview = "\n".join(selected[:25])
    if len(selected) > 25: preview += f"\n... ещё {len(selected)-25}"
    await update.message.reply_text(
        f"<b>Отправить ({len(selected)}) ключей:</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_send_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_send")]
        ])
    )

async def bulk_send_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    import asyncio
    q = update.callback_query; await q.answer()
    selected: List[str] = context.user_data.get('bulk_send_selected', [])
    if not selected:
        await safe_edit_text(q, context, "Список пуст."); return
    await safe_edit_text(q, context, f"Отправляю {len(selected)} ключ(ов)...")
    sent = 0
    for name in selected:
        path = os.path.join(KEYS_DIR, f"{name}.ovpn")
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    await context.bot.send_document(chat_id=q.message.chat_id, document=InputFile(f), filename=f"{name}.ovpn")
                sent += 1
                await asyncio.sleep(0.25)
            except Exception as e:
                print(f"[bulk_send] error {name}: {e}")
    for k in ['bulk_send_selected', 'bulk_send_keys', 'await_bulk_send_numbers']:
        context.user_data.pop(k, None)
    await context.bot.send_message(chat_id=q.message.chat_id, text=f"✅ Отправлено: {sent} / {len(selected)}")

async def bulk_send_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    for k in ['bulk_send_selected', 'bulk_send_keys', 'await_bulk_send_numbers']:
        context.user_data.pop(k, None)
    await safe_edit_text(q, context, "Массовая отправка отменена.")

# --- Bulk enable ---
async def start_bulk_enable(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    files = get_ovpn_files()
    files = sorted(files, key=lambda x: _natural_key(x[:-5]))
    disabled = [f[:-5] for f in files if is_client_ccd_disabled(f[:-5])]
    if not disabled:
        await safe_edit_text(q, context, "Нет заблокированных клиентов."); return
    url = create_names_telegraph_page(disabled, "Включение клиентов", "Заблокированные клиенты")
    if not url:
        await safe_edit_text(q, context, "Ошибка Telegraph."); return
    context.user_data['bulk_enable_keys'] = disabled
    context.user_data['await_bulk_enable_numbers'] = True
    text = ("<b>Включить клиентов</b>\n"
            "Формат: all | 1 | 1,2 | 3-7 ...\n"
            f"<a href=\"{url}\">Список</a>\n\nПришлите строку.")
    await safe_edit_text(q, context, text, parse_mode="HTML",
                         reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_enable")]]))

async def process_bulk_enable_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_bulk_enable_numbers'): return
    names: List[str] = context.user_data.get('bulk_enable_keys', [])
    if not names:
        await update.message.reply_text("Список потерян.")
        context.user_data.pop('await_bulk_enable_numbers', None); return
    idxs, errs = parse_bulk_selection(update.message.text.strip(), len(names))
    if errs:
        await update.message.reply_text("Ошибки:\n" + "\n".join(errs),
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_enable")]]))
        return
    if not idxs:
        await update.message.reply_text("Ничего не выбрано.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_enable")]]))
        return
    selected = [names[i - 1] for i in idxs]
    context.user_data['bulk_enable_selected'] = selected
    context.user_data['await_bulk_enable_numbers'] = False
    preview = "\n".join(selected[:30])
    if len(selected) > 30: preview += f"\n... ещё {len(selected)-30}"
    await update.message.reply_text(
        f"<b>Включить ({len(selected)}):</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_enable_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_enable")]
        ])
    )

async def bulk_enable_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    selected: List[str] = context.user_data.get('bulk_enable_selected', [])
    if not selected:
        await safe_edit_text(q, context, "Пусто."); return
    for name in selected:
        unblock_client_ccd(name)
    for k in ['bulk_enable_selected', 'bulk_enable_keys', 'await_bulk_enable_numbers']:
        context.user_data.pop(k, None)
    await safe_edit_text(q, context, f"✅ Включено клиентов: {len(selected)}")

async def bulk_enable_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    for k in ['bulk_enable_selected', 'bulk_enable_keys', 'await_bulk_enable_numbers']:
        context.user_data.pop(k, None)
    await safe_edit_text(q, context, "Массовое включение отменено.")

# --- Bulk disable ---
async def start_bulk_disable(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    files = get_ovpn_files()
    files = sorted(files, key=lambda x: _natural_key(x[:-5]))
    active = [f[:-5] for f in files if not is_client_ccd_disabled(f[:-5])]
    if not active:
        await safe_edit_text(q, context, "Нет активных клиентов."); return
    url = create_names_telegraph_page(active, "Отключение клиентов", "Активные клиенты")
    if not url:
        await safe_edit_text(q, context, "Ошибка Telegraph."); return
    context.user_data['bulk_disable_keys'] = active
    context.user_data['await_bulk_disable_numbers'] = True
    text = ("<b>Отключить клиентов</b>\n"
            "Формат: all | 1 | 1,2,7 | 3-10 ...\n"
            f"<a href=\"{url}\">Список</a>\n\nПришлите строку.")
    await safe_edit_text(q, context, text, parse_mode="HTML",
                         reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_disable")]]))

async def process_bulk_disable_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_bulk_disable_numbers'): return
    names: List[str] = context.user_data.get('bulk_disable_keys', [])
    if not names:
        await update.message.reply_text("Список потерян.")
        context.user_data.pop('await_bulk_disable_numbers', None); return
    idxs, errs = parse_bulk_selection(update.message.text.strip(), len(names))
    if errs:
        await update.message.reply_text("Ошибки:\n" + "\n".join(errs),
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_disable")]]))
        return
    if not idxs:
        await update.message.reply_text("Ничего не выбрано.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_disable")]]))
        return
    selected = [names[i - 1] for i in idxs]
    context.user_data['bulk_disable_selected'] = selected
    context.user_data['await_bulk_disable_numbers'] = False
    preview = "\n".join(selected[:30])
    if len(selected) > 30: preview += f"\n... ещё {len(selected)-30}"
    await update.message.reply_text(
        f"<b>Отключить ({len(selected)}):</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_disable_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_disable")]
        ])
    )

async def bulk_disable_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    selected: List[str] = context.user_data.get('bulk_disable_selected', [])
    if not selected:
        await safe_edit_text(q, context, "Пусто."); return
    for name in selected:
        block_client_ccd(name); disconnect_client_sessions(name)
    for k in ['bulk_disable_selected', 'bulk_disable_keys', 'await_bulk_disable_numbers']:
        context.user_data.pop(k, None)
    await safe_edit_text(q, context, f"⚠️ Отключено клиентов: {len(selected)}")

async def bulk_disable_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    for k in ['bulk_disable_selected', 'bulk_disable_keys', 'await_bulk_disable_numbers']:
        context.user_data.pop(k, None)
    await safe_edit_text(q, context, "Массовое отключение отменено.")

# =====================================================================
#  OPENVPN — Update remote address
# =====================================================================
CLIENT_TEMPLATE_CANDIDATES = [
    "/etc/openvpn/client-template.txt",
    "/root/openvpn/client-template.txt"
]

def find_client_template_path() -> Optional[str]:
    for p in CLIENT_TEMPLATE_CANDIDATES:
        if os.path.exists(p): return p
    return None

def replace_remote_line_in_text(text: str, new_host: str, new_port: str) -> str:
    lines = []; replaced = False
    for line in text.splitlines():
        if line.strip().startswith("remote "):
            lines.append(f"remote {new_host} {new_port}"); replaced = True
        else:
            lines.append(line)
    if not replaced:
        lines.append(f"remote {new_host} {new_port}")
    return "\n".join(lines) + "\n"

def update_template_and_ovpn(new_host: str, new_port: str) -> Dict[str, int]:
    stats = {"template_updated": 0, "ovpn_updated": 0, "errors": 0}
    tpl = find_client_template_path()
    if tpl:
        try:
            with open(tpl, "r") as f: old = f.read()
            new = replace_remote_line_in_text(old, new_host, new_port)
            if new != old:
                backup = tpl + ".bak_" + datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y%m%d%H%M%S")
                shutil.copy2(tpl, backup)
                with open(tpl, "w") as f: f.write(new)
                stats["template_updated"] = 1
        except Exception as e:
            print(f"[update_remote] template error: {e}"); stats["errors"] += 1
    else:
        print("[update_remote] template not found")
    for f in get_ovpn_files():
        path = os.path.join(KEYS_DIR, f)
        try:
            with open(path, "r") as fr: oldc = fr.read()
            newc = replace_remote_line_in_text(oldc, new_host, new_port)
            if newc != oldc:
                bak = path + ".bak_" + datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y%m%d%H%M%S")
                shutil.copy2(path, bak)
                with open(path, "w") as fw: fw.write(newc)
                stats["ovpn_updated"] += 1
        except Exception as e:
            print(f"[update_remote] file {f} error: {e}"); stats["errors"] += 1
    return stats

async def start_update_remote_dialog(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    tpl = find_client_template_path()
    tpl_info = tpl if tpl else "не найден"
    text = ("Введите новый remote в формате host:port\n"
            f"(Обнаруженный шаблон: {tpl_info})\nПример: vpn.example.com:1194")
    await safe_edit_text(q, context, text,
                         reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_update_remote")]]))
    context.user_data['await_remote_input'] = True

async def process_remote_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_remote_input'): return
    raw = update.message.text.strip()
    if ':' not in raw:
        await update.message.reply_text("Формат неверный. Нужно host:port. Пример: myvpn.com:1194"); return
    host, port = raw.split(':', 1)
    host, port = host.strip(), port.strip()
    if not host or not port.isdigit():
        await update.message.reply_text("Некорректные host или port."); return
    stats = update_template_and_ovpn(host, port)
    context.user_data.pop('await_remote_input', None)
    await update.message.reply_text(
        f"✅ Обновление завершено.\nШаблон: {stats['template_updated']}\n.ovpn изменено: {stats['ovpn_updated']}\nОшибок: {stats['errors']}"
    )

# =====================================================================
#  OPENVPN — Generate .ovpn
# =====================================================================
def extract_pem_cert(cert_path: str) -> str:
    with open(cert_path, "r") as f:
        lines = f.read().splitlines()
    in_pem = False
    out = []
    for line in lines:
        if "-----BEGIN CERTIFICATE-----" in line:
            in_pem = True
        if in_pem:
            out.append(line)
        if "-----END CERTIFICATE-----" in line:
            break
    return "\n".join(out).strip()

def generate_ovpn_for_client(
    client_name,
    output_dir=KEYS_DIR,
    template_path=f"{OPENVPN_DIR}/client-template.txt",
    ca_path=f"{EASYRSA_DIR}/pki/ca.crt",
    cert_path=None,
    key_path=None,
    tls_crypt_path=f"{OPENVPN_DIR}/tls-crypt.key",
    tls_auth_path=f"{OPENVPN_DIR}/tls-auth.key",
    server_conf_path=f"{OPENVPN_DIR}/server.conf"
):
    if cert_path is None:
        cert_path = f"{EASYRSA_DIR}/pki/issued/{client_name}.crt"
    if key_path is None:
        key_path = f"{EASYRSA_DIR}/pki/private/{client_name}.key"
    ovpn_file = os.path.join(output_dir, f"{client_name}.ovpn")
    TLS_SIG = None
    if os.path.exists(server_conf_path):
        with open(server_conf_path, "r") as f:
            conf = f.read()
            if "tls-crypt" in conf: TLS_SIG = 1
            elif "tls-auth" in conf: TLS_SIG = 2
    with open(template_path, "r") as f:
        template_content = f.read().rstrip()
    with open(ca_path, "r") as f:
        ca_content = f.read().strip()
    cert_content = extract_pem_cert(cert_path)
    with open(key_path, "r") as f:
        key_content = f.read().strip()
    content = (template_content + "\n"
               "<ca>\n" + ca_content + "\n</ca>\n"
               "<cert>\n" + cert_content + "\n</cert>\n"
               "<key>\n" + key_content + "\n</key>\n")
    if TLS_SIG == 1 and os.path.exists(tls_crypt_path):
        with open(tls_crypt_path, "r") as f:
            tls_crypt_content = f.read().strip()
        content += "<tls-crypt>\n" + tls_crypt_content + "\n</tls-crypt>\n"
    elif TLS_SIG == 2 and os.path.exists(tls_auth_path):
        content += "key-direction 1\n"
        with open(tls_auth_path, "r") as f:
            tls_auth_content = f.read().strip()
        content += "<tls-auth>\n" + tls_auth_content + "\n</tls-auth>\n"
    with open(ovpn_file, "w") as f:
        f.write(content)
    return ovpn_file

# =====================================================================
#  OPENVPN — Create key (multi-create)
# =====================================================================
async def create_key_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get('await_key_name'):
        key_name = update.message.text.strip()
        if not key_name:
            await update.message.reply_text("Имя пустое. Введите имя:")
            return
        ovpn_file = os.path.join(KEYS_DIR, f"{key_name}.ovpn")
        if os.path.exists(ovpn_file):
            await update.message.reply_text("Такой клиент существует, введите другое имя.")
            return
        context.user_data['new_key_name'] = key_name
        context.user_data['await_key_name'] = False
        context.user_data['await_key_expiry'] = True
        await update.message.reply_text("Введите логический срок (дней, по умолчанию 30):")
        return

    if context.user_data.get('await_key_expiry'):
        try:
            days = int(update.message.text.strip())
            if days < 1: raise ValueError
        except:
            days = 30
        context.user_data['new_key_expiry'] = days
        context.user_data['await_key_expiry'] = False
        context.user_data['await_key_quantity'] = True
        await update.message.reply_text("Введите количество ключей (по умолчанию 1):")
        return

    if context.user_data.get('await_key_quantity'):
        try:
            qty = int(update.message.text.strip())
            if qty < 1: raise ValueError
        except:
            qty = 1
        if qty > 100:
            await update.message.reply_text("Слишком много. Максимум 100. Введите снова:")
            return
        base = context.user_data.get('new_key_name')
        days = context.user_data.get('new_key_expiry', 30)

        if qty == 1:
            names = [base]
        else:
            names = [base] + [f"{base}{i}" for i in range(2, qty + 1)]

        collisions = [n for n in names if os.path.exists(os.path.join(KEYS_DIR, f"{n}.ovpn"))]
        if collisions:
            await update.message.reply_text(
                "Конфликт имён (существуют): " + ", ".join(collisions) +
                "\nВведите другое базовое имя /start → Создать ключ"
            )
            context.user_data.clear()
            return

        created = []
        errors = []
        for n in names:
            try:
                subprocess.run(
                    f"EASYRSA_CERT_EXPIRE=3650 {EASYRSA_DIR}/easyrsa --batch build-client-full {n} nopass",
                    shell=True, check=True, cwd=EASYRSA_DIR
                )
                ovpn_path = generate_ovpn_for_client(n)
                iso = set_client_expiry_days_from_now(n, days)
                created.append((n, ovpn_path, iso))
            except subprocess.CalledProcessError as e:
                errors.append(f"{n}: {e}")
            except Exception as e:
                errors.append(f"{n}: {e}")

        if created:
            await update.message.reply_text(
                f"Создано ключей: {len(created)} (срок ~{days} дн)", parse_mode="HTML"
            )
            for (n, path, iso) in created:
                try:
                    await update.message.reply_text(f"{n}: до {iso}\n{path}")
                    with open(path, "rb") as f:
                        await context.bot.send_document(
                            chat_id=update.effective_chat.id,
                            document=InputFile(f),
                            filename=f"{n}.ovpn"
                        )
                except Exception as e:
                    await update.message.reply_text(f"Ошибка отправки {n}: {e}")
        if errors:
            err_txt = "\n".join(errors[:10])
            if len(errors) > 10: err_txt += f"\n... ещё {len(errors)-10}"
            await update.message.reply_text(f"Ошибки:\n{err_txt}")

        context.user_data.clear()
        return

# =====================================================================
#  OPENVPN — Renew key (logical expiry)
# =====================================================================
async def renew_key_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True); return
    await q.answer()
    rows = gather_key_metadata()
    if not rows:
        await safe_edit_text(q, context, "Нет ключей."); return
    url = create_keys_detailed_page()
    if not url:
        await safe_edit_text(q, context, "Ошибка Telegraph."); return
    order = [r["name"] for r in rows]
    context.user_data['renew_keys_order'] = order
    context.user_data['await_renew_number'] = True
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_renew")]])
    text = ("<b>Установить новый логический срок</b>\n"
            "Открой список и введи НОМЕР клиента:\n"
            f"<a href=\"{url}\">Список (Telegraph)</a>\n\nПример: 5")
    await safe_edit_text(q, context, text, parse_mode="HTML", reply_markup=kb)

async def process_renew_number(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_renew_number'): return
    text = update.message.text.strip()
    if not re.fullmatch(r"\d+", text):
        await update.message.reply_text("Нужно ввести один номер клиента.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_renew")]]))
        return
    idx = int(text)
    order: List[str] = context.user_data.get('renew_keys_order', [])
    if not order:
        await update.message.reply_text("Список потерян. Начните заново.")
        context.user_data.pop('await_renew_number', None); return
    if idx < 1 or idx > len(order):
        await update.message.reply_text(f"Номер вне диапазона 1..{len(order)}.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_renew")]]))
        return
    key_name = order[idx - 1]
    context.user_data['renew_key_name'] = key_name
    context.user_data['await_renew_number'] = False
    context.user_data['await_renew_expiry'] = True
    await update.message.reply_text(f"Введите НОВЫЙ срок (дней) для {key_name}:")

async def renew_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    for k in ['await_renew_number', 'await_renew_expiry', 'renew_keys_order', 'renew_key_name']:
        context.user_data.pop(k, None)
    await safe_edit_text(q, context, "Продление отменено.")

async def renew_key_select_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True); return
    await q.answer()
    data = q.data
    key_name = data.split('_', 1)[1]
    context.user_data['renew_key_name'] = key_name
    context.user_data['await_renew_expiry'] = True
    await safe_edit_text(q, context, f"Введите НОВЫЙ срок (дней) для {key_name}:")

async def renew_key_expiry_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_renew_expiry'): return
    key_name = context.user_data['renew_key_name']
    try:
        days = int(update.message.text.strip())
        if days < 1: raise ValueError
    except Exception:
        await update.message.reply_text("Некорректное число дней."); return
    iso = set_client_expiry_days_from_now(key_name, days)
    await update.message.reply_text(f"Логический срок для {key_name} установлен до: {iso} (~{days} дн). Клиент разблокирован.")
    context.user_data.clear()

# =====================================================================
#  OPENVPN — Log, Traffic, Status parsing
# =====================================================================
def get_status_log_tail(n=40):
    try:
        with open(STATUS_LOG, "r") as f:
            lines = f.readlines()
        return "".join(lines[-n:])
    except Exception as e:
        return f"Ошибка чтения status.log: {e}"

def _html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

def _count_clients_by_ip() -> str:
    """Parse status.log routing table and count clients per real IP."""
    try:
        with open(STATUS_LOG, "r") as f:
            lines = f.readlines()
    except Exception:
        return ""
    ip_counts: Dict[str, int] = {}
    in_routing = False
    for line in lines:
        line = line.strip()
        if line.startswith("ROUTING TABLE"):
            in_routing = True
            continue
        if line.startswith("GLOBAL STATS"):
            break
        if in_routing and "," in line and not line.startswith("Virtual"):
            parts = line.split(",")
            if len(parts) >= 3:
                real_addr = parts[2]  # IP:PORT
                real_ip = real_addr.rsplit(":", 1)[0] if ":" in real_addr else real_addr
                ip_counts[real_ip] = ip_counts.get(real_ip, 0) + 1
    if not ip_counts:
        return ""
    total = sum(ip_counts.values())
    sorted_ips = sorted(ip_counts.items(), key=lambda x: -x[1])
    lines_out = [f"\n📊 Клиентов по IP (всего {total}):"]
    for ip, cnt in sorted_ips:
        lines_out.append(f"  {ip} — {cnt}")
    return "\n".join(lines_out)

async def log_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    log_text = get_status_log_tail()
    ip_summary = _count_clients_by_ip()
    safe = _html_escape(log_text)
    safe_summary = _html_escape(ip_summary)
    msgs = split_message(f"<b>status.log (хвост):</b>\n<pre>{safe}</pre>\n<b>{safe_summary}</b>")
    await safe_edit_text(q, context, msgs[0], parse_mode="HTML")
    for m in msgs[1:]:
        await context.bot.send_message(chat_id=q.message.chat_id, text=m, parse_mode="HTML")

def load_traffic_db():
    global traffic_usage
    try:
        if os.path.exists(TRAFFIC_DB_PATH):
            with open(TRAFFIC_DB_PATH, "r") as f:
                raw = json.load(f)
            migrated = {}
            for k, v in raw.items():
                if isinstance(v, dict):
                    migrated[k] = {'rx': int(v.get('rx', 0)), 'tx': int(v.get('tx', 0))}
            traffic_usage = migrated
        else:
            traffic_usage = {}
    except Exception as e:
        print(f"[traffic] load error: {e}")
        traffic_usage = {}

def save_traffic_db(force=False):
    global _last_traffic_save_time
    now = time.time()
    if not force and now - _last_traffic_save_time < TRAFFIC_SAVE_INTERVAL: return
    try:
        tmp = TRAFFIC_DB_PATH + ".tmp"
        with open(tmp, "w") as f: json.dump(traffic_usage, f)
        os.replace(tmp, TRAFFIC_DB_PATH)
        _last_traffic_save_time = now
    except Exception as e:
        print(f"[traffic] save error: {e}")

def update_traffic_from_status(clients):
    global traffic_usage, _last_session_state
    changed = False
    for c in clients:
        name = c['name']
        try:
            recv = int(c.get('bytes_recv', 0))
            sent = int(c.get('bytes_sent', 0))
        except:
            continue
        connected_since = c.get('connected_since', '')
        prev = _last_session_state.get(name)
        if name not in traffic_usage:
            traffic_usage[name] = {'rx': 0, 'tx': 0}
        if prev is None or prev['connected_since'] != connected_since:
            _last_session_state[name] = {'connected_since': connected_since, 'rx': recv, 'tx': sent}
            continue
        delta_rx = recv - prev['rx']; delta_tx = sent - prev['tx']
        if delta_rx > 0:
            traffic_usage[name]['rx'] += delta_rx; prev['rx'] = recv; changed = True
        else:
            prev['rx'] = recv
        if delta_tx > 0:
            traffic_usage[name]['tx'] += delta_tx; prev['tx'] = sent; changed = True
        else:
            prev['tx'] = sent
    if changed: save_traffic_db()

def clear_traffic_stats():
    global traffic_usage, _last_session_state
    try:
        if os.path.exists(TRAFFIC_DB_PATH):
            ts = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y%m%d_%H%M%S")
            subprocess.run(f"cp {TRAFFIC_DB_PATH} {TRAFFIC_DB_PATH}.bak_{ts}", shell=True)
    except: pass
    traffic_usage = {}; _last_session_state = {}
    save_traffic_db(force=True)

def build_traffic_report():
    if not traffic_usage:
        return "<b>Трафик:</b>\nНет данных."
    items = sorted(traffic_usage.items(), key=lambda x: x[1]['rx'] + x[1]['tx'], reverse=True)
    lines = ["<b>Использование трафика:</b>"]
    for name, val in items:
        total = val['rx'] + val['tx']
        lines.append(f"• {name}: {total/1024/1024/1024:.2f} GB")
    return "\n".join(lines)

def parse_openvpn_status(status_path=STATUS_LOG):
    clients = []; online_names = set(); tunnel_ips = {}
    try:
        with open(status_path, "r") as f:
            lines = f.readlines()
        client_list_section = False
        routing_table_section = False
        for line in lines:
            line_s = line.strip()
            if line_s.startswith("OpenVPN CLIENT LIST"):
                client_list_section = True; continue
            if client_list_section and line_s.startswith("Common Name,Real Address"):
                continue
            if client_list_section and not line_s:
                client_list_section = False; continue
            if client_list_section and "," in line_s:
                parts = line_s.split(",")
                if len(parts) >= 5:
                    clients.append({
                        "name": parts[0],
                        "ip": parts[1].split(":")[0],
                        "port": parts[1].split(":")[1] if ":" in parts[1] else "",
                        "bytes_recv": parts[2],
                        "bytes_sent": parts[3],
                        "connected_since": parts[4],
                    })
            if line_s.startswith("ROUTING TABLE"):
                routing_table_section = True; continue
            if routing_table_section and line_s.startswith("Virtual Address,Common Name"):
                continue
            if routing_table_section and not line_s:
                routing_table_section = False; continue
            if routing_table_section and "," in line_s:
                parts = line_s.split(",")
                if len(parts) >= 2:
                    tunnel_ips[parts[1]] = parts[0]
                    online_names.add(parts[1])
    except Exception as e:
        print(f"[parse_openvpn_status] {e}")
    return clients, online_names, tunnel_ips

# =====================================================================
#  OPENVPN — Monitoring loop
# =====================================================================
async def check_new_connections(app: Application):
    import asyncio
    global clients_last_online, last_alert_time
    if not hasattr(check_new_connections, "_last_enforce"):
        check_new_connections._last_enforce = 0
    while True:
        try:
            clients, online_names, tunnel_ips = parse_openvpn_status()
            update_traffic_from_status(clients)
            now_t = time.time()
            if now_t - check_new_connections._last_enforce > ENFORCE_INTERVAL_SECONDS:
                enforce_client_expiries()
                check_and_notify_expiring(app.bot)
                check_new_connections._last_enforce = now_t
            online_count = len(online_names)
            total_keys = len(get_ovpn_files())
            now = time.time()
            if not alert_enabled:
                pass
            elif online_count == 0 and total_keys > 0:
                if now - last_alert_time > ALERT_INTERVAL_SEC:
                    await app.bot.send_message(ADMIN_ID, "❌ Все клиенты оффлайн!", parse_mode="HTML")
                    last_alert_time = now
            elif 0 < online_count < MIN_ONLINE_ALERT:
                if now - last_alert_time > ALERT_INTERVAL_SEC:
                    await app.bot.send_message(ADMIN_ID, f"⚠️ Онлайн мало: {online_count}/{total_keys}", parse_mode="HTML")
                    last_alert_time = now
            else:
                if online_count >= MIN_ONLINE_ALERT:
                    last_alert_time = 0
            clients_last_online = set(online_names)
            await asyncio.sleep(10)
        except Exception as e:
            print(f"[monitor] {e}")
            await asyncio.sleep(10)

# =====================================================================
#  ALERT MENU
# =====================================================================

async def alert_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    status = "🔔 ON" if alert_enabled else "🔕 OFF"
    kb = [
        [InlineKeyboardButton("🔔 Включить", callback_data='alert_on'),
         InlineKeyboardButton("🔕 Выключить", callback_data='alert_off')],
        [InlineKeyboardButton("── Порог «мало онлайн» ──", callback_data='noop')],
        [InlineKeyboardButton("15", callback_data='alert_threshold:15'),
         InlineKeyboardButton("30", callback_data='alert_threshold:30'),
         InlineKeyboardButton("45", callback_data='alert_threshold:45'),
         InlineKeyboardButton("60", callback_data='alert_threshold:60')],
        [InlineKeyboardButton("✏️ Ввести вручную", callback_data='alert_custom')],
        [InlineKeyboardButton("🏠 В главное меню", callback_data='home')],
    ]
    await safe_edit_text(q, context,
        f"🚨 <b>Тревога блокировки</b>\n\n"
        f"Статус: <b>{status}</b>\n"
        f"Порог: <b>{MIN_ONLINE_ALERT}</b> клиентов\n"
        f"Интервал: каждые 10 сек\n\n"
        f"Если онлайн &lt; порога → уведомление.",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

# =====================================================================
#  OPENVPN — Backup / Restore UI
# =====================================================================
def list_backups() -> List[str]:
    return sorted([os.path.basename(p) for p in glob.glob("/root/openvpn_full_backup_*.tar.gz")], reverse=True)

async def perform_backup_and_send(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    try:
        path = create_backup_in_root_excluding_archives()
        size = os.path.getsize(path)
        txt = f"✅ Бэкап создан: <code>{os.path.basename(path)}</code>\nРазмер: {size/1024/1024:.2f} MB"
        q = update.callback_query
        await safe_edit_text(q, context, txt, parse_mode="HTML", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("📤 Отправить", callback_data=f"backup_send_{os.path.basename(path)}")],
            [InlineKeyboardButton("📦 Список", callback_data="backup_list")],
        ]))
    except Exception as e:
        await update.callback_query.edit_message_text(f"Ошибка бэкапа: {e}")

async def send_backup_file(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    if not os.path.exists(full):
        await safe_edit_text(update.callback_query, context, "Файл не найден."); return
    with open(full, "rb") as f:
        await context.bot.send_document(chat_id=update.effective_chat.id, document=InputFile(f), filename=fname)
    await safe_edit_text(update.callback_query, context, "Отправлен.")

async def show_backup_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    bl = list_backups()
    if not bl:
        await safe_edit_text(update.callback_query, context, "Бэкапов нет."); return
    kb = [[InlineKeyboardButton(b, callback_data=f"backup_info_{b}")] for b in bl[:15]]
    await safe_edit_text(update.callback_query, context, "Список бэкапов:", reply_markup=InlineKeyboardMarkup(kb))

async def show_backup_info(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    staging = f"/tmp/info_{int(time.time())}"
    os.makedirs(staging, exist_ok=True)
    try:
        import tarfile
        with tarfile.open(full, "r:gz") as tar:
            tar.extractall(staging)
        manifest_path = os.path.join(staging, MANIFEST_NAME)
        if not os.path.exists(manifest_path):
            await safe_edit_text(update.callback_query, context, "manifest.json отсутствует."); return
        with open(manifest_path, "r") as f:
            m = json.load(f)
        clients = m.get("openvpn_pki", {}).get("clients", [])
        v_count = sum(1 for c in clients if c.get("status") == "V")
        r_count = sum(1 for c in clients if c.get("status") == "R")
        txt = (f"<b>{fname}</b>\nСоздан: {m.get('created_at')}\n"
               f"Файлов: {len(m.get('files', []))}\n"
               f"Клиентов V: {v_count} / R: {r_count}\nПоказать diff?")
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("🧪 Diff", callback_data=f"restore_dry_{fname}")],
            [InlineKeyboardButton("📤 Отправить", callback_data=f"backup_send_{fname}")],
            [InlineKeyboardButton("🗑️ Удалить", callback_data=f"backup_delete_{fname}")],
        ])
        await safe_edit_text(update.callback_query, context, txt, parse_mode="HTML", reply_markup=kb)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

async def restore_dry_run(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    backup_path = locate_backup(fname)
    if not backup_path:
        await safe_edit_text(update.callback_query, context,
                             f"Файл '{fname}' не найден.",
                             parse_mode="HTML")
        return
    try:
        report = apply_restore(backup_path, dry_run=True)
        diff = report["diff"]
        def lim(lst):
            return lst[:6] + [f"... ещё {len(lst)-6}"] if len(lst) > 6 else lst
        text = (f"<b>Diff {os.path.basename(backup_path)}</b>\n"
                f"Extra: {len(diff['extra'])}\n" + "\n".join(lim(diff['extra'])) + "\n\n"
                f"Missing: {len(diff['missing'])}\n" + "\n".join(lim(diff['missing'])) + "\n\n"
                f"Changed: {len(diff['changed'])}\n" + "\n".join(lim(diff['changed'])) + "\n\n"
                "Применить restore?")
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⚠️ Применить", callback_data=f"restore_apply_{fname}")],
            [InlineKeyboardButton("⬅️ Назад", callback_data=f"backup_info_{fname}")]
        ])
        await safe_edit_text(update.callback_query, context, text, parse_mode="HTML", reply_markup=kb)
    except Exception as e:
        await safe_edit_text(update.callback_query, context, f"Ошибка dry-run: {e}", parse_mode="HTML")

async def restore_apply(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    backup_path = locate_backup(fname)
    if not backup_path:
        await safe_edit_text(update.callback_query, context,
                             f"Файл '{fname}' не найден.",
                             parse_mode="HTML")
        return
    try:
        report = apply_restore(backup_path, dry_run=False)
        diff = report["diff"]
        text = (f"<b>Restore:</b> {os.path.basename(backup_path)}\n"
                f"Удалено extra: {len(diff['extra'])}\n"
                f"Missing: {len(diff['missing'])}\n"
                f"Changed: {len(diff['changed'])}\n"
                f"CRL: {report.get('crl_action')}\n"
                f"iptables: {report.get('iptables_restore', 'skipped')}\n"
                f"OpenVPN restart: {report.get('service_restart')}")
        await safe_edit_text(update.callback_query, context, text, parse_mode="HTML")
    except Exception as e:
        tb = traceback.format_exc()
        await safe_edit_text(update.callback_query, context, f"Ошибка restore: {e}\n{tb[-400:]}", parse_mode="HTML")

async def backup_delete_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    if not os.path.exists(full):
        await safe_edit_text(update.callback_query, context, "Файл не найден."); return
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Да, удалить", callback_data=f"backup_delete_confirm_{fname}")],
        [InlineKeyboardButton("⬅️ Назад", callback_data=f"backup_info_{fname}")]
    ])
    await safe_edit_text(update.callback_query, context, f"Удалить бэкап <b>{fname}</b>?", parse_mode="HTML", reply_markup=kb)

async def backup_delete_apply(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    try:
        if os.path.exists(full):
            os.remove(full)
            await safe_edit_text(update.callback_query, context, "🗑️ Бэкап удалён.")
            await show_backup_list(update, context)
        else:
            await safe_edit_text(update.callback_query, context, "Файл не найден.")
    except Exception as e:
        await safe_edit_text(update.callback_query, context, f"Ошибка удаления: {e}")

async def backup_hub(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("📦 Бэкап OpenVPN", callback_data="backup_create"),
         InlineKeyboardButton("💾 Бэкап RR", callback_data="rr_backup")],
        [InlineKeyboardButton("📋 Список бэкапов", callback_data="backup_list")],
        [InlineKeyboardButton("📤 Загрузить архив", callback_data="backup_upload_prompt")],
        [InlineKeyboardButton("🔄 Восстановить OpenVPN", callback_data="backup_list")],
        [InlineKeyboardButton("🔄 Восстановить RR", callback_data="rr_restore_prompt")],
        [InlineKeyboardButton("❌ Назад", callback_data="home")],
    ])
    await safe_edit_text(q, context, "📦 <b>Меню бэкапов</b>", parse_mode="HTML", reply_markup=kb)

# =====================================================================
#  REMOTE REFRESH — File helpers
# =====================================================================
def rr_read_file(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return default

def rr_write_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def rr_write_sha256(path: str) -> None:
    try:
        with open(path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        rr_write_file(path + ".sha256", digest + "  " + os.path.basename(path) + "\n")
    except OSError as exc:
        logger.warning("sha256 write failed for %s: %s", path, exc)

def rr_read_flag(path: str) -> bool:
    return rr_read_file(path, "0").startswith("1")

def rr_write_flag(path: str, value: bool) -> None:
    rr_write_file(path, "1" if value else "0")

# =====================================================================
#  REMOTE REFRESH — Domain list helpers
# =====================================================================
RR_DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$")

def rr_read_domains() -> list:
    raw = rr_read_file(RR_DOMAIN_LIST_FILE, "")
    domains = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domains.append(line)
    return domains

def rr_write_domains(domains: list) -> None:
    header = (
        "# domain_list.txt\n"
        "# One domain per line. Lines starting with '#' are ignored.\n"
    )
    content = header + "\n".join(domains) + "\n"
    rr_write_file(RR_DOMAIN_LIST_FILE, content)
    rr_write_sha256(RR_DOMAIN_LIST_FILE)

# =====================================================================
#  REMOTE REFRESH — History
# =====================================================================
def rr_append_history(entry: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    line = f"[{ts}] {entry}\n"
    os.makedirs(os.path.dirname(RR_HISTORY_FILE) or ".", exist_ok=True)
    with open(RR_HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(line)

def rr_read_history(lines: int = 20) -> str:
    raw = rr_read_file(RR_HISTORY_FILE, "")
    if not raw:
        return "(no history yet)"
    all_lines = raw.splitlines()
    return "\n".join(all_lines[-lines:])

# =====================================================================
#  REMOTE REFRESH — Handlers (InlineKeyboard callbacks)
# =====================================================================
async def rr_current_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    ip = rr_read_file(RR_IP_FILE, "(not set)")
    await safe_edit_text(q, context, f"<b>📡 Router IP:</b> <code>{ip}</code>", parse_mode="HTML")

async def rr_set_ip_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    current = rr_read_file(RR_IP_FILE, "(not set)")
    context.user_data['await_rr_ip'] = True
    await safe_edit_text(q, context,
        f"Текущий IP роутеров: <code>{current}</code>\nОтправьте новый IPv4 адрес:",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="rr_cancel")]]))

async def rr_set_ip_receive(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_rr_ip'): return
    text = update.message.text.strip()
    parts = text.split(".")
    valid = (
        len(parts) == 4
        and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
        and text not in ("0.0.0.0", "127.0.0.1")
    )
    if not valid:
        await update.message.reply_text("Неверный IP. Повторите или отмена.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="rr_cancel")]]))
        return
    old_ip = rr_read_file(RR_IP_FILE, "")
    rr_write_file(RR_IP_FILE, text + "\n")
    rr_append_history(f"IP changed: {old_ip} -> {text}")
    context.user_data.pop('await_rr_ip', None)
    await update.message.reply_text(f"✅ IP обновлён: <code>{text}</code>", parse_mode="HTML")

# =====================================================================
#  FORCE IP — принудительная смена IP на роутерах через SSH
# =====================================================================

async def force_ip_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    current = rr_read_file(RR_IP_FILE, "(не задан)")
    context.user_data['await_force_ip'] = True
    await safe_edit_text(q, context,
        f"🔄 <b>Принудительная смена IP</b>\n\n"
        f"Текущий IP в боте: <code>{current}</code>\n\n"
        f"Отправьте новый IPv4 адрес.\n"
        f"<i>(текущий IP показан для справки, можно ввести любой)</i>",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("❌ Отмена", callback_data="rr_cancel")]]))

async def force_ip_receive(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_force_ip'):
        return
    text = update.message.text.strip()
    parts = text.split(".")
    valid = (
        len(parts) == 4
        and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
        and text not in ("0.0.0.0", "127.0.0.1")
    )
    if not valid:
        await update.message.reply_text("Неверный IP. Повторите или отмена.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("❌ Отмена", callback_data="rr_cancel")]]))
        return
    context.user_data.pop('await_force_ip', None)
    # Save new IP to current_vpn_ip.txt
    old_ip = rr_read_file(RR_IP_FILE, "")
    rr_write_file(RR_IP_FILE, text + "\n")
    rr_append_history(f"FORCE: {old_ip} -> {text}")
    context.user_data['force_ip_new'] = text
    context.user_data['force_ip_old'] = old_ip
    context.user_data['force_ip_selected'] = set()
    # Show router selection
    routers = load_routers()
    if not routers:
        await update.message.reply_text(
            f"✅ IP обновлён: <code>{text}</code>\n"
            f"Список роутеров пуст — добавьте через SSH Роутеры.",
            parse_mode="HTML")
        return
    online = get_online_clients()
    cnt_online = sum(1 for cn in routers if cn in online)
    kb = [
        [InlineKeyboardButton(f"🌐 Все роутеры ({len(routers)})", callback_data='force_ip_all')],
        [InlineKeyboardButton("🖥 Один роутер", callback_data='force_ip_one')],
        [InlineKeyboardButton("☑️ Несколько", callback_data='force_ip_multi')],
        [InlineKeyboardButton("❌ Отмена (IP уже изменён)", callback_data='home')],
    ]
    await update.message.reply_text(
        f"✅ IP обновлён: <code>{old_ip}</code> → <code>{text}</code>\n\n"
        f"Онлайн роутеров: <b>{cnt_online}/{len(routers)}</b>\n\n"
        f"Выберите на какие роутеры принудительно применить новый IP:",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def force_ip_select_one(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    routers = load_routers()
    online = get_online_clients()
    kb = []
    for cn in sorted(routers.keys(), key=_natural_key):
        icon = "🟢" if cn in online else "🔴"
        kb.append([InlineKeyboardButton(f"{icon} {cn}", callback_data=f'force_ip_run:{cn}')])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='home')])
    await safe_edit_text(q, context, "🖥 Выберите роутер:", reply_markup=InlineKeyboardMarkup(kb))

async def force_ip_select_multi(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    routers = load_routers()
    online = get_online_clients()
    selected = context.user_data.get('force_ip_selected', set())
    kb = []
    for cn in sorted(routers.keys(), key=_natural_key):
        icon = "🟢" if cn in online else "🔴"
        check = "✅" if cn in selected else "⬜"
        kb.append([InlineKeyboardButton(f"{check} {icon} {cn}", callback_data=f'force_ip_t:{cn}')])
    kb.append([InlineKeyboardButton("▶️ Применить", callback_data='force_ip_go')])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='home')])
    await safe_edit_text(q, context,
        f"☑️ Выберите роутеры (выбрано: {len(selected)}):",
        reply_markup=InlineKeyboardMarkup(kb))

async def force_ip_toggle(update: Update, context: ContextTypes.DEFAULT_TYPE, cn: str):
    q = update.callback_query
    await q.answer()
    selected = context.user_data.get('force_ip_selected', set())
    if cn in selected:
        selected.discard(cn)
    else:
        selected.add(cn)
    context.user_data['force_ip_selected'] = selected
    await force_ip_select_multi(update, context)

async def _force_ip_execute(msg, targets, new_ip: str):
    """SSH to routers, directly sed the remote line in client.conf, restart OpenVPN."""
    routers = load_routers()
    total = len(targets)
    results = []
    for i, cn in enumerate(targets):
        r = routers.get(cn)
        if not r:
            results.append((cn, False, "не найден"))
            continue
        ip = get_router_ip(cn)
        if not ip:
            results.append((cn, False, "оффлайн (нет VPN IP)"))
            continue
        try:
            await msg.edit_text(
                f"🔄 Применяю IP на роутеры...\n{i+1}/{total} — {cn}",
                parse_mode="HTML")
        except Exception:
            pass
        # sed changes IP, save to flash, then background script
        # kills openvpn + runs update_script.sh AFTER ssh disconnects
        # (SSH goes through VPN, so killall openvpn kills SSH too)
        cmd = (
            f'CONF=/etc/openvpn/client/client.conf ; '
            f'OLD=$(grep "^remote " $CONF) ; '
            f'PORT=$(echo "$OLD" | awk \'{{print $3}}\') ; '
            f'[ -z "$PORT" ] && PORT=443 ; '
            f'sed -i "s|^remote .*|remote {new_ip} $PORT|" $CONF ; '
            f'mtd_storage.sh save 2>/dev/null ; '
            f'NEW=$(grep "^remote " $CONF) ; '
            f'echo "OLD: $OLD" ; echo "NEW: $NEW" ; '
            f'( sleep 2 ; killall openvpn 2>/dev/null ; sleep 3 ; '
            f'/etc/storage/update_script.sh ) > /dev/null 2>&1 & '
            f'echo "===DONE==="'
        )
        ok, out = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'), r.get('password', ''), cmd)
        results.append((cn, ok, out))
    # Build report
    lines = [f"🔄 <b>Принудительная смена IP — отчёт</b>\nНовый IP: <code>{new_ip}</code>\n"]
    ok_count = 0
    for cn, ok, out in results:
        if ok:
            old_line = ""
            new_line = ""
            for ln in out.split('\n'):
                ln_s = ln.strip()
                if ln_s.startswith('OLD: '):
                    old_line = ln_s[5:]
                elif ln_s.startswith('NEW: '):
                    new_line = ln_s[5:]
            applied = new_ip in new_line
            if applied:
                lines.append(f"✅ <b>{cn}</b>: {new_line}")
                ok_count += 1
            else:
                lines.append(f"⚠️ <b>{cn}</b>: {new_line or out[-80:]}")
        else:
            lines.append(f"❌ <b>{cn}</b>: {escape(out[:80])}")
    lines.append(f"\nИтого: {ok_count}/{total} применено")
    return "\n".join(lines)

async def force_ip_exec_all(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    new_ip = context.user_data.get('force_ip_new', '')
    if not new_ip:
        await safe_edit_text(q, context, "Ошибка: IP не задан. Начните заново.")
        return
    routers = load_routers()
    targets = sorted(routers.keys(), key=_natural_key)
    if not targets:
        await safe_edit_text(q, context, "Список роутеров пуст.")
        return
    await safe_edit_text(q, context, f"🔄 Применяю IP на все роутеры...\n0/{len(targets)}")
    report = await _force_ip_execute(q.message, targets, new_ip)
    kb = [[InlineKeyboardButton("🏠 Меню", callback_data='home')]]
    await q.message.edit_text(report, parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def force_ip_exec_one(update: Update, context: ContextTypes.DEFAULT_TYPE, cn: str):
    q = update.callback_query
    await q.answer()
    new_ip = context.user_data.get('force_ip_new', '')
    if not new_ip:
        await safe_edit_text(q, context, "Ошибка: IP не задан. Начните заново.")
        return
    await safe_edit_text(q, context, f"🔄 Применяю IP на <b>{cn}</b>...", parse_mode="HTML")
    report = await _force_ip_execute(q.message, [cn], new_ip)
    kb = [[InlineKeyboardButton("🏠 Меню", callback_data='home')]]
    await q.message.edit_text(report, parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def force_ip_exec_selected(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    new_ip = context.user_data.get('force_ip_new', '')
    selected = context.user_data.get('force_ip_selected', set())
    if not new_ip:
        await safe_edit_text(q, context, "Ошибка: IP не задан. Начните заново.")
        return
    if not selected:
        await safe_edit_text(q, context, "Ни один роутер не выбран.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("◀️ Назад", callback_data='force_ip_multi')]]))
        return
    targets = sorted(selected, key=_natural_key)
    await safe_edit_text(q, context, f"🔄 Применяю IP на {len(targets)} роутеров...\n0/{len(targets)}")
    report = await _force_ip_execute(q.message, targets, new_ip)
    kb = [[InlineKeyboardButton("🏠 Меню", callback_data='home')]]
    await q.message.edit_text(report, parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def rr_history(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    hist = rr_read_history()
    safe = _html_escape(hist)
    await safe_edit_text(q, context, f"<b>📋 История IP:</b>\n<pre>{safe}</pre>", parse_mode="HTML")

async def rr_ip_scan_toggle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    current = rr_read_flag(RR_IP_SCAN_FLAG)
    new_val = not current
    rr_write_flag(RR_IP_SCAN_FLAG, new_val)
    state = "OFF (disabled)" if new_val else "ON (enabled)"
    await safe_edit_text(q, context, f"IP scan: {state}")

async def rr_port_scan_toggle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    current = rr_read_flag(RR_PORT_SCAN_FLAG)
    new_val = not current
    rr_write_flag(RR_PORT_SCAN_FLAG, new_val)
    state = "OFF (disabled)" if new_val else "ON (enabled)"
    await safe_edit_text(q, context, f"Port scan: {state}")

async def rr_domains_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    domains = rr_read_domains()
    if not domains:
        text = "Список доменов пуст."
    else:
        numbered = "\n".join(f"{i+1}. {d}" for i, d in enumerate(domains))
        text = f"<b>🌐 Домены:</b>\n<pre>{numbered}</pre>"
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Добавить", callback_data="rr_dom_add"),
         InlineKeyboardButton("➖ Удалить", callback_data="rr_dom_remove")],
        [InlineKeyboardButton("🏠 Меню", callback_data="home")]
    ])
    await safe_edit_text(q, context, text, parse_mode="HTML", reply_markup=kb)

async def rr_dom_add_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    context.user_data['await_rr_domain_add'] = True
    await safe_edit_text(q, context, "Введите домен (например: my-domain.com):",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="rr_cancel")]]))

async def rr_dom_add_receive(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_rr_domain_add'): return
    text = update.message.text.strip()
    if not RR_DOMAIN_RE.match(text):
        await update.message.reply_text("Неверный формат домена. Повторите:")
        return
    domains = rr_read_domains()
    if text in domains:
        await update.message.reply_text(f"{text} уже в списке.")
        context.user_data.pop('await_rr_domain_add', None)
        return
    domains.append(text)
    rr_write_domains(domains)
    rr_append_history(f"domain added: {text}")
    context.user_data.pop('await_rr_domain_add', None)
    await update.message.reply_text(f"✅ Добавлен: {text}")

async def rr_dom_remove_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    domains = rr_read_domains()
    if not domains:
        await safe_edit_text(q, context, "Список пуст."); return
    kb = InlineKeyboardMarkup(
        [[InlineKeyboardButton(f"🗑 {d}", callback_data=f"rr_dom_del:{d}")] for d in domains]
        + [[InlineKeyboardButton("❌ Отмена", callback_data="rr_cancel")]]
    )
    await safe_edit_text(q, context, "Выберите домен для удаления:", reply_markup=kb)

async def rr_dom_remove_apply(update: Update, context: ContextTypes.DEFAULT_TYPE, domain: str):
    q = update.callback_query; await q.answer()
    domains = rr_read_domains()
    if domain in domains:
        domains.remove(domain)
        rr_write_domains(domains)
        rr_append_history(f"domain removed: {domain}")
        await safe_edit_text(q, context, f"✅ Удалён: {domain}")
    else:
        await safe_edit_text(q, context, f"{domain} не найден.")

async def rr_push_domains(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show current vs new domains and offer router selection."""
    q = update.callback_query; await q.answer()
    new_domains = rr_read_domains()
    if not new_domains:
        await safe_edit_text(q, context, "❌ Список доменов пуст.")
        return
    routers = load_routers()
    if not routers:
        await safe_edit_text(q, context, "❌ Список роутеров пуст.")
        return
    online = get_online_clients()
    # Fetch current domains from first online router
    old_domains_text = "—"
    for cn in online:
        if cn in routers:
            ip = get_router_ip(cn)
            if ip:
                r = routers[cn]
                ok, out = await asyncio.to_thread(
                    ssh_exec, ip, r.get('port', 22),
                    r.get('user', 'admin'), r.get('password', ''),
                    'cat /etc/storage/remote_domains.list 2>/dev/null || echo "(файл не найден)"')
                if ok and out.strip():
                    old_lines = [l.strip() for l in out.strip().splitlines() if l.strip()]
                    old_domains_text = "\n".join(f"  {i+1}. {d}" for i, d in enumerate(old_lines))
                    context.user_data['push_dom_old'] = old_lines
                break
    new_text = "\n".join(f"  {i+1}. {d}" for i, d in enumerate(new_domains))
    context.user_data['push_dom_new'] = new_domains
    context.user_data['push_dom_selected'] = set()
    cnt_online = sum(1 for cn in routers if cn in online)
    kb = [
        [InlineKeyboardButton(f"🌐 Все роутеры ({len(routers)})", callback_data='push_dom_all')],
        [InlineKeyboardButton("🖥 Один роутер", callback_data='push_dom_one')],
        [InlineKeyboardButton("☑️ Несколько", callback_data='push_dom_multi')],
        [InlineKeyboardButton("❌ Отмена", callback_data='home')],
    ]
    await safe_edit_text(q, context,
        f"📤 <b>Обновить домены на роутерах</b>\n\n"
        f"<b>Сейчас на роутерах:</b>\n<pre>{old_domains_text}</pre>\n\n"
        f"<b>Новый список:</b>\n<pre>{new_text}</pre>\n\n"
        f"Онлайн: <b>{cnt_online}/{len(routers)}</b>\n\n"
        f"Выберите роутеры:",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))


async def rr_push_dom_select_one(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    routers = load_routers()
    online = get_online_clients()
    kb = []
    for cn in sorted(routers.keys(), key=_natural_key):
        icon = "🟢" if cn in online else "🔴"
        kb.append([InlineKeyboardButton(f"{icon} {cn}", callback_data=f'push_dom_run:{cn}')])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='rr_push_domains')])
    await safe_edit_text(q, context, "🖥 Выберите роутер:", reply_markup=InlineKeyboardMarkup(kb))


async def rr_push_dom_select_multi(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    routers = load_routers()
    online = get_online_clients()
    selected = context.user_data.get('push_dom_selected', set())
    kb = []
    for cn in sorted(routers.keys(), key=_natural_key):
        icon = "🟢" if cn in online else "🔴"
        check = "☑️" if cn in selected else "⬜"
        kb.append([InlineKeyboardButton(f"{check} {icon} {cn}", callback_data=f'push_dom_tog:{cn}')])
    kb.append([InlineKeyboardButton(f"✅ Применить ({len(selected)})", callback_data='push_dom_go_sel')])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='rr_push_domains')])
    await safe_edit_text(q, context, "☑️ Выберите роутеры:", reply_markup=InlineKeyboardMarkup(kb))


async def rr_push_dom_toggle(update: Update, context: ContextTypes.DEFAULT_TYPE, cn: str):
    q = update.callback_query; await q.answer()
    selected = context.user_data.get('push_dom_selected', set())
    if cn in selected:
        selected.discard(cn)
    else:
        selected.add(cn)
    context.user_data['push_dom_selected'] = selected
    await rr_push_dom_select_multi(update, context)


async def _rr_push_dom_exec(update: Update, context: ContextTypes.DEFAULT_TYPE, targets: list):
    """Execute domain push to given list of router CNs."""
    q = update.callback_query
    domains = context.user_data.get('push_dom_new', rr_read_domains())
    if not domains:
        await safe_edit_text(q, context, "❌ Список доменов пуст.")
        return
    routers = load_routers()
    online = get_online_clients()
    dom_text = "\\n".join(domains)
    numbered = "\n".join(f"{i+1}. {d}" for i, d in enumerate(domains))
    msg = await q.message.reply_text(
        f"📤 Обновляю домены на {len(targets)} роутерах...",
        parse_mode="HTML")
    cmd = f'printf "{dom_text}\\n" > /etc/storage/remote_domains.list && mtd_storage.sh save && echo DOMUPD_OK'
    results = []
    ok_count = 0
    for cn in targets:
        r = routers.get(cn)
        if not r:
            results.append(f"❌ <b>{cn}</b> — не найден")
            continue
        if cn not in online:
            results.append(f"❌ <b>{cn}</b> — оффлайн")
            continue
        ip = get_router_ip(cn)
        if not ip:
            results.append(f"❌ <b>{cn}</b> — нет IP")
            continue
        ok, out = await asyncio.to_thread(
            ssh_exec, ip, r.get('port', 22),
            r.get('user', 'admin'), r.get('password', ''), cmd)
        if ok and 'DOMUPD_OK' in out:
            results.append(f"✅ <b>{cn}</b>")
            ok_count += 1
        else:
            short = out.strip()[:100] if out else "—"
            results.append(f"❌ <b>{cn}</b>: {escape(short)}")
    total = len(targets)
    report = "\n".join(results)
    await msg.edit_text(
        f"📤 <b>Домены обновлены</b>\n\n{report}\n\nИтого: {ok_count} из {total}",
        parse_mode="HTML")


# ----- Check domains on routers -----
async def chk_dom_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    routers = load_routers()
    if not routers:
        await safe_edit_text(q, context, "❌ Список роутеров пуст.")
        return
    online = get_online_clients()
    cnt_online = sum(1 for cn in routers if cn in online)
    context.user_data['chk_dom_selected'] = set()
    kb = [
        [InlineKeyboardButton(f"🌐 Все роутеры ({len(routers)})", callback_data='chk_dom_all')],
        [InlineKeyboardButton("🖥 Один роутер", callback_data='chk_dom_one')],
        [InlineKeyboardButton("☑️ Несколько", callback_data='chk_dom_multi')],
        [InlineKeyboardButton("❌ Отмена", callback_data='home')],
    ]
    await safe_edit_text(q, context,
        f"🔎 <b>Проверить домены на роутерах</b>\n\n"
        f"Онлайн: <b>{cnt_online}/{len(routers)}</b>\n\n"
        f"Выберите роутеры:",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))


async def chk_dom_select_one(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    routers = load_routers()
    online = get_online_clients()
    kb = []
    for cn in sorted(routers.keys(), key=_natural_key):
        icon = "🟢" if cn in online else "🔴"
        kb.append([InlineKeyboardButton(f"{icon} {cn}", callback_data=f'chk_dom_run:{cn}')])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='chk_dom_menu')])
    await safe_edit_text(q, context, "🖥 Выберите роутер:", reply_markup=InlineKeyboardMarkup(kb))


async def chk_dom_select_multi(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    routers = load_routers()
    online = get_online_clients()
    selected = context.user_data.get('chk_dom_selected', set())
    kb = []
    for cn in sorted(routers.keys(), key=_natural_key):
        icon = "🟢" if cn in online else "🔴"
        check = "☑️" if cn in selected else "⬜"
        kb.append([InlineKeyboardButton(f"{check} {icon} {cn}", callback_data=f'chk_dom_tog:{cn}')])
    kb.append([InlineKeyboardButton(f"✅ Проверить ({len(selected)})", callback_data='chk_dom_go_sel')])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='chk_dom_menu')])
    await safe_edit_text(q, context, "☑️ Выберите роутеры:", reply_markup=InlineKeyboardMarkup(kb))


async def chk_dom_toggle(update: Update, context: ContextTypes.DEFAULT_TYPE, cn: str):
    q = update.callback_query; await q.answer()
    selected = context.user_data.get('chk_dom_selected', set())
    if cn in selected:
        selected.discard(cn)
    else:
        selected.add(cn)
    context.user_data['chk_dom_selected'] = selected
    await chk_dom_select_multi(update, context)


async def _chk_dom_exec(update: Update, context: ContextTypes.DEFAULT_TYPE, targets: list):
    """Read domains from selected routers and show report."""
    q = update.callback_query
    routers = load_routers()
    online = get_online_clients()
    server_domains = rr_read_domains()
    server_set = set(server_domains)
    msg = await q.message.reply_text(
        f"🔎 Проверяю домены на {len(targets)} роутерах...")
    results = []
    for cn in targets:
        r = routers.get(cn)
        if not r:
            results.append(f"❌ <b>{cn}</b> — не найден"); continue
        if cn not in online:
            results.append(f"❌ <b>{cn}</b> — оффлайн"); continue
        ip = get_router_ip(cn)
        if not ip:
            results.append(f"❌ <b>{cn}</b> — нет IP"); continue
        ok, out = await asyncio.to_thread(
            ssh_exec, ip, r.get('port', 22),
            r.get('user', 'admin'), r.get('password', ''),
            'cat /etc/storage/remote_domains.list 2>/dev/null || echo "(нет файла)"')
        if ok:
            router_doms = [l.strip() for l in out.strip().splitlines() if l.strip()]
            router_set = set(router_doms)
            if router_set == server_set:
                status = "✅"
            else:
                status = "⚠️"
            dom_list = ", ".join(router_doms) if router_doms else "(пусто)"
            results.append(f"{status} <b>{cn}</b>: {dom_list}")
        else:
            short = out.strip()[:100] if out else "—"
            results.append(f"❌ <b>{cn}</b>: {escape(short)}")
    report = "\n".join(results)
    server_list = ", ".join(server_domains) if server_domains else "(пусто)"
    await msg.edit_text(
        f"🔎 <b>Домены на роутерах</b>\n\n"
        f"{report}\n\n"
        f"📋 На сервере: {server_list}",
        parse_mode="HTML")


async def rr_backup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    await context.bot.send_message(chat_id=q.message.chat_id, text="Создаю бэкап Remote Refresh...")

    files_to_backup = {
        "current_vpn_ip.txt": RR_IP_FILE,
        "domain_list.txt": RR_DOMAIN_LIST_FILE,
        "history.log": RR_HISTORY_FILE,
        "ip_scan_off.txt": RR_IP_SCAN_FLAG,
        "port_scan_off.txt": RR_PORT_SCAN_FLAG,
    }

    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".zip")
        os.close(fd)

        with pyzipper.AESZipFile(
            tmp_path, "w",
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as zf:
            zf.setpassword(RR_BACKUP_PASSWORD)
            for arcname, filepath in files_to_backup.items():
                if os.path.isfile(filepath):
                    zf.write(filepath, arcname)
                else:
                    logger.warning("rr_backup: %s not found, skipping", filepath)

        with open(tmp_path, "rb") as f:
            await context.bot.send_document(
                chat_id=q.message.chat_id,
                document=InputFile(f),
                filename="remote_refresh_backup.zip",
                caption="✅ Бэкап Remote Refresh готов.",
            )
    except Exception as exc:
        logger.error("rr_backup failed: %s", exc)
        await context.bot.send_message(chat_id=q.message.chat_id, text=f"Ошибка: {exc}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

async def rr_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    for k in ['await_rr_ip', 'await_rr_domain_add', 'await_force_ip',
              'await_oec_radd', 'await_oec_fedit', 'await_ssh_add']:
        context.user_data.pop(k, None)
    await safe_edit_text(q, context, "Отменено.")

# =====================================================================
#  OPENVPN — Keys expiry view
# =====================================================================
async def view_keys_expiry_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    files = get_ovpn_files()
    files = sorted(files, key=lambda x: _natural_key(x[:-5]))
    names = [f[:-5] for f in files]
    text = "<b>Логические сроки клиентов:</b>\n"
    if not names:
        text += "Нет."
    else:
        rows = []
        for name in names:
            iso, days_left = get_client_expiry(name)
            if iso is None:
                status = "нет срока"
            else:
                if days_left is not None:
                    if days_left < 0: status = f"❌ истёк ({iso})"
                    elif days_left == 0: status = f"⚠️ сегодня ({iso})"
                    else: status = f"{days_left}д (до {iso})"
                else:
                    status = iso
            mark = "⛔" if is_client_ccd_disabled(name) else "🟢"
            rows.append(f"{mark} {name}: {status}")
        text += "\n".join(rows)
    if update.callback_query:
        await safe_edit_text(update.callback_query, context, text, parse_mode="HTML")
    else:
        await update.message.reply_text(text, parse_mode="HTML")

# =====================================================================
#  safe_edit_text
# =====================================================================
async def safe_edit_text(q, context, text, **kwargs):
    if MENU_MESSAGE_ID and q.message.message_id == MENU_MESSAGE_ID:
        await context.bot.send_message(chat_id=q.message.chat_id, text=text, **kwargs)
    else:
        await q.edit_message_text(text, **kwargs)

# =====================================================================
#  UNIFIED MAIN KEYBOARD
# =====================================================================
def get_main_keyboard():
    keyboard = [
        # --- OpenVPN section ---
        [InlineKeyboardButton("──── OPENVPN ────", callback_data='noop')],
        [InlineKeyboardButton("📊 Статистика", callback_data='stats'),
         InlineKeyboardButton("🛣️ Тунель", callback_data='send_ipp')],
        [InlineKeyboardButton("📶 Трафик", callback_data='traffic'),
         InlineKeyboardButton("🔗 Обновление", callback_data='update_info')],
        [InlineKeyboardButton("🧹 Очистить трафик", callback_data='traffic_clear'),
         InlineKeyboardButton("🌐 Обновить адрес", callback_data='update_remote')],
        [InlineKeyboardButton("⏳ Сроки ключей", callback_data='keys_expiry'),
         InlineKeyboardButton("⌛ Обновить ключ", callback_data='renew_key')],
        [InlineKeyboardButton("✅ Вкл.клиента", callback_data='bulk_enable_start'),
         InlineKeyboardButton("⚠️ Откл.клиента", callback_data='bulk_disable_start')],
        [InlineKeyboardButton("➕ Создать ключ", callback_data='create_key'),
         InlineKeyboardButton("🗑️ Удалить ключ", callback_data='bulk_delete_start')],
        [InlineKeyboardButton("🔄 Список клиентов", callback_data='refresh'),
         InlineKeyboardButton("📤 Отправить ключи", callback_data='bulk_send_start')],
        [InlineKeyboardButton("📦 Бэкап", callback_data='backup_hub'),
         InlineKeyboardButton("📜 Просмотр лога", callback_data='log')],
        [InlineKeyboardButton("🚨 Тревога", callback_data='block_alert'),
         InlineKeyboardButton("⚡ Перезагрузка", callback_data='restart_menu')],
        [InlineKeyboardButton("📥 Git Pull", callback_data='git_pull')],
        [InlineKeyboardButton("📝 OVPN EDIT", callback_data='ovpn_edit_menu'),
         InlineKeyboardButton("🖥 SSH Роутеры", callback_data='ssh_routers')],
        [InlineKeyboardButton("🌐 GOST Серверы", callback_data='gost_menu')],
        # --- Remote Refresh section ---
        [InlineKeyboardButton("─── Remote Refresh ───", callback_data='noop')],
        [InlineKeyboardButton("📡 IP роутеров", callback_data='rr_current_ip'),
         InlineKeyboardButton("✏️ Сменить IP", callback_data='rr_set_ip')],
        [InlineKeyboardButton("🔄 Принудительная смена IP", callback_data='force_ip')],
        [InlineKeyboardButton("🔍 IP Scan", callback_data='rr_ip_scan'),
         InlineKeyboardButton("🔍 Port Scan", callback_data='rr_port_scan')],
        [InlineKeyboardButton("📋 История IP", callback_data='rr_history'),
         InlineKeyboardButton("🌐 Домены", callback_data='rr_domains')],
        [InlineKeyboardButton("🔎 Проверить домены", callback_data='chk_dom_menu')],
        [InlineKeyboardButton("🔄 Авто IP", callback_data='aip_menu')],
        # --- Common ---
        [InlineKeyboardButton("❓ Помощь", callback_data='help'),
         InlineKeyboardButton("🏠 В главное меню", callback_data='home')],
    ]
    return InlineKeyboardMarkup(keyboard)

# =====================================================================
#  UNIVERSAL TEXT HANDLER
# =====================================================================
async def universal_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    # OpenVPN text inputs
    if context.user_data.get('await_bulk_delete_numbers'):
        await process_bulk_delete_numbers(update, context); return
    if context.user_data.get('await_bulk_send_numbers'):
        await process_bulk_send_numbers(update, context); return
    if context.user_data.get('await_bulk_enable_numbers'):
        await process_bulk_enable_numbers(update, context); return
    if context.user_data.get('await_bulk_disable_numbers'):
        await process_bulk_disable_numbers(update, context); return
    if context.user_data.get('await_renew_number'):
        await process_renew_number(update, context); return
    if context.user_data.get('await_renew_expiry'):
        await renew_key_expiry_handler(update, context); return
    if (context.user_data.get('await_key_name') or
        context.user_data.get('await_key_expiry') or
        context.user_data.get('await_key_quantity')):
        await create_key_handler(update, context); return
    if context.user_data.get('await_remote_input'):
        await process_remote_input(update, context); return
    # SSH Routers text inputs
    # await_ssh_add stays active for multi-add; skip if ANY other await is active
    _other_awaits = [k for k in context.user_data if k.startswith('await_') and k != 'await_ssh_add']
    if context.user_data.get('await_ssh_add') and not _other_awaits:
        lines = [l.strip() for l in update.message.text.strip().splitlines() if l.strip()]
        routers = load_routers()
        added = []
        errors = []
        for line in lines:
            parts = line.split()
            if len(parts) < 2:
                errors.append(f"❌ <code>{escape(line)}</code> — нужно минимум имя и пароль")
                continue
            cn = parts[0]
            if len(parts) == 2:
                # имя пароль
                user = "admin"
                password = parts[1]
                port = 22
            elif len(parts) == 3:
                # имя логин пароль
                user = parts[1]
                password = parts[2]
                port = 22
            else:
                # имя логин пароль порт
                user = parts[1]
                password = parts[2]
                port = int(parts[3]) if parts[3].isdigit() else 22
            routers[cn] = {"user": user, "password": password, "port": port}
            added.append(cn)
        if added:
            save_routers(routers)
        result = ""
        if added:
            result += "✅ Добавлено: " + ", ".join(f"<b>{c}</b>" for c in added)
        if errors:
            result += ("\n" if result else "") + "\n".join(errors)
        # Show updated available list and keep await_ssh_add active
        available = []
        try:
            with open(IPP_FILE, "r") as f:
                for line in f:
                    p = line.strip().split(",")
                    if len(p) >= 2 and p[0] not in routers:
                        available.append(p[0])
        except FileNotFoundError:
            pass
        if available:
            avail_str = "  ".join(f"<code>{c}</code>" for c in sorted(available, key=_natural_key))
            hint = f"\n\nДоступные клиенты:\n{avail_str}"
        else:
            hint = ""
            context.user_data.pop('await_ssh_add', None)
        kb = [[InlineKeyboardButton("✅ Готово", callback_data='ssh_routers')]]
        await update.message.reply_text(
            (result or "Ничего не добавлено.") + hint +
            ("\n\nОтправьте ещё или нажмите Готово." if available else ""),
            parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))
        return
    if context.user_data.get('await_ssh_edit'):
        cn = context.user_data.pop('await_ssh_edit')
        parts = update.message.text.strip().split(":")
        routers = load_routers()
        if cn not in routers:
            await update.message.reply_text("Роутер не найден.")
            return
        if len(parts) == 1:
            routers[cn]["password"] = parts[0]
        elif len(parts) == 2:
            routers[cn]["user"] = parts[0]
            routers[cn]["password"] = parts[1]
        elif len(parts) >= 3:
            routers[cn]["user"] = parts[0]
            routers[cn]["password"] = parts[1]
            routers[cn]["port"] = int(parts[2])
        save_routers(routers)
        await update.message.reply_text(f"✅ Роутер <b>{cn}</b> обновлён.", parse_mode="HTML")
        return
    if context.user_data.get('await_ssh_cmd'):
        target = context.user_data.pop('await_ssh_cmd')
        cmd = update.message.text.strip()
        routers = load_routers()
        # Determine target list
        if target == '__all__':
            targets = sorted(routers.keys(), key=_natural_key)
            label = "ВСЕХ роутеров"
        elif isinstance(target, list):
            targets = target
            label = f"{len(targets)} роутеров"
        else:
            # Single router (legacy)
            targets = [target]
            label = target
        if len(targets) == 1:
            cn = targets[0]
            r = routers.get(cn)
            if not r:
                await update.message.reply_text("Роутер не найден.")
                return
            ip = get_router_ip(cn)
            if not ip:
                await update.message.reply_text(f"🔴 {cn} — нет IP.")
                return
            msg = await update.message.reply_text(f"💻 Выполняю на <b>{cn}</b>...", parse_mode="HTML")
            ok, out = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'), r.get('password', ''), cmd)
            result = f"💻 <b>{cn}</b> ({ip}):\n<pre>{escape(out[:3800])}</pre>"
            await msg.edit_text(result, parse_mode="HTML")
        else:
            msg = await update.message.reply_text(f"💻 Выполняю на {label}...\nЭто может занять время.", parse_mode="HTML")
            report = await ssh_exec_multi(msg, routers, targets, cmd, context)
            # Split if too long for Telegram
            if len(report) > 4000:
                await msg.edit_text(report[:4000] + "\n\n<i>...обрезано</i>", parse_mode="HTML")
            else:
                await msg.edit_text(report, parse_mode="HTML")
        return
    # OVPN EDIT text input
    if context.user_data.get('await_ovpn_edit'):
        file_key = context.user_data.pop('await_ovpn_edit')
        path = OVPN_EDIT_FILES.get(file_key)
        if path:
            new_content = update.message.text
            # Safety: reject if content is too short or looks like a bare IP
            if len(new_content.strip()) < 50 or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', new_content.strip()):
                await update.message.reply_text(
                    "⚠️ Отклонено: содержимое слишком короткое или похоже на IP-адрес.\n"
                    "Для редактирования конфига отправьте полный текст файла.")
                return
            try:
                # Save backup copy
                if os.path.exists(path):
                    shutil.copy2(path, path + ".bak")
                with open(path, "w", encoding="utf-8") as f:
                    f.write(new_content)
                fname = os.path.basename(path)
                await update.message.reply_text(
                    f"\u2705 {fname} обновлён.\nБэкап сохранён в {fname}.bak\n"
                    "Перезагрузка сервисов НЕ выполнена.")
            except Exception as exc:
                await update.message.reply_text(f"\u274c Ошибка записи: {exc}")
        return
    # Alert threshold text input
    if context.user_data.get('await_alert_threshold'):
        context.user_data.pop('await_alert_threshold', None)
        txt = update.message.text.strip()
        if txt.isdigit() and 1 <= int(txt) <= 999:
            global MIN_ONLINE_ALERT
            MIN_ONLINE_ALERT = int(txt)
            await update.message.reply_text(
                f"✅ Порог установлен: <b>{MIN_ONLINE_ALERT}</b> клиентов",
                parse_mode="HTML")
        else:
            await update.message.reply_text("Введите число от 1 до 999.")
        return
    # SSH deploy script text input
    if context.user_data.get('await_ssh_deploy_ip'):
        await ssh_deploy_receive_ip(update, context); return
    # SSH change password text input
    if context.user_data.get('await_ssh_chpass'):
        await ssh_chpass_receive(update, context); return
    # Auto IP text inputs
    if context.user_data.get('await_aip_add'):
        await auto_ip_add_handler(update, context); return
    if context.user_data.get('await_aip_replace'):
        await auto_ip_replace_receive(update, context); return
    # GOST text inputs
    if context.user_data.get('await_gost_add'):
        await gost_add_handler(update, context); return
    if context.user_data.get('await_gost_edit'):
        await gost_edit_handler(update, context); return
    if context.user_data.get('await_gost_rule') or context.user_data.get('await_gost_addrule'):
        await gost_rule_handler(update, context); return
    if context.user_data.get('await_gost_getroot') and context.user_data['await_gost_getroot'] != 'pem':
        await gost_getroot_handler(update, context); return
    # OpenVPN Ext Config text inputs
    if context.user_data.get('await_oec_radd'):
        await oec_remote_add_receive(update, context); return
    if context.user_data.get('await_oec_fedit'):
        await oec_full_edit_receive(update, context); return
    # Force IP text input
    if context.user_data.get('await_force_ip'):
        await force_ip_receive(update, context); return
    # Remote Refresh text inputs
    if context.user_data.get('await_rr_ip'):
        await rr_set_ip_receive(update, context); return
    if context.user_data.get('await_rr_domain_add'):
        await rr_dom_add_receive(update, context); return
    await update.message.reply_text("Неизвестный ввод. Используй меню или /start.")

# =====================================================================
#  BUTTON HANDLER (unified)
# =====================================================================
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Доступ запрещён.", show_alert=True); return
    await q.answer()
    data = q.data

    # Clear stale await flags when user clicks any button (prevents cross-menu writes)
    if data not in ('ovpn_view_server_conf', 'ovpn_view_client_template', 'ovpn_edit_cancel'):
        context.user_data.pop('await_ovpn_edit', None)
    print("DEBUG callback_data:", data)

    # --- OpenVPN callbacks ---
    if data == 'refresh':
        await safe_edit_text(q, context, format_clients_by_certs(), parse_mode="HTML")

    elif data == 'stats':
        clients, online_names, tunnel_ips = parse_openvpn_status()
        files = get_ovpn_files()
        files = sorted(files, key=lambda x: _natural_key(x[:-5]))
        lines = ["<b>Статус всех ключей:</b>"]
        cnt_online = 0
        cnt_offline = 0
        cnt_disabled = 0
        for f in files:
            name = f[:-5]
            if is_client_ccd_disabled(name):
                st = "⛔"
                cnt_disabled += 1
            elif name in online_names:
                st = "🟢"
                cnt_online += 1
            else:
                st = "🔴"
                cnt_offline += 1
            lines.append(f"{st} {name}")
        lines.append("")
        lines.append(f"🟢 Онлайн: <b>{cnt_online}</b>")
        lines.append(f"🔴 Оффлайн: <b>{cnt_offline}</b>")
        lines.append(f"⛔ Отключены: <b>{cnt_disabled}</b>")
        lines.append(f"📊 Всего: <b>{cnt_online + cnt_offline + cnt_disabled}</b>")
        text = "\n".join(lines)
        msgs = split_message(text)
        await safe_edit_text(q, context, msgs[0], parse_mode="HTML")
        for m in msgs[1:]:
            await context.bot.send_message(chat_id=q.message.chat_id, text=m, parse_mode="HTML")

    elif data == 'traffic':
        save_traffic_db(force=True)
        await safe_edit_text(q, context, build_traffic_report(), parse_mode="HTML")

    elif data == 'traffic_clear':
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="confirm_clear_traffic")],
            [InlineKeyboardButton("❌ Нет", callback_data="cancel_clear_traffic")]
        ])
        await safe_edit_text(q, context, "Очистить накопленный трафик?", reply_markup=kb)

    elif data == 'confirm_clear_traffic':
        clear_traffic_stats(); await safe_edit_text(q, context, "Очищено.")
    elif data == 'cancel_clear_traffic':
        await safe_edit_text(q, context, "Отменено.")

    elif data == 'update_remote':
        await start_update_remote_dialog(update, context)
    elif data == 'cancel_update_remote':
        context.user_data.pop('await_remote_input', None); await safe_edit_text(q, context, "Отменено.")

    elif data == 'renew_key':
        await renew_key_request(update, context)
    elif data.startswith('renew_'):
        await renew_key_select_handler(update, context)
    elif data == 'cancel_renew':
        await renew_cancel(update, context)

    elif data == 'backup_hub':
        await backup_hub(update, context)
    elif data == 'backup_create':
        await perform_backup_and_send(update, context)
    elif data == 'backup_list':
        await show_backup_list(update, context)
    elif data.startswith('backup_info_'):
        await show_backup_info(update, context, data.replace('backup_info_', '', 1))
    elif data.startswith('backup_send_'):
        await send_backup_file(update, context, data.replace('backup_send_', '', 1))
    elif data.startswith('restore_dry_'):
        await restore_dry_run(update, context, data.replace('restore_dry_', '', 1))
    elif data.startswith('restore_apply_'):
        await restore_apply(update, context, data.replace('restore_apply_', '', 1))
    elif data.startswith('backup_delete_confirm_'):
        await backup_delete_apply(update, context, data.replace('backup_delete_confirm_', '', 1))
    elif data.startswith('backup_delete_'):
        await backup_delete_prompt(update, context, data.replace('backup_delete_', '', 1))

    elif data == 'bulk_delete_start':
        await start_bulk_delete(update, context)
    elif data == 'bulk_delete_confirm':
        await bulk_delete_confirm(update, context)
    elif data == 'cancel_bulk_delete':
        await bulk_delete_cancel(update, context)

    elif data == 'bulk_send_start':
        await start_bulk_send(update, context)
    elif data == 'bulk_send_confirm':
        await bulk_send_confirm(update, context)
    elif data == 'cancel_bulk_send':
        await bulk_send_cancel(update, context)

    elif data == 'bulk_enable_start':
        await start_bulk_enable(update, context)
    elif data == 'bulk_enable_confirm':
        await bulk_enable_confirm(update, context)
    elif data == 'cancel_bulk_enable':
        await bulk_enable_cancel(update, context)

    elif data == 'bulk_disable_start':
        await start_bulk_disable(update, context)
    elif data == 'bulk_disable_confirm':
        await bulk_disable_confirm(update, context)
    elif data == 'cancel_bulk_disable':
        await bulk_disable_cancel(update, context)

    elif data == 'update_info':
        await send_simple_update_command(update, context)
    elif data == 'copy_update_cmd':
        await resend_update_command(update, context)

    elif data == 'keys_expiry':
        await view_keys_expiry_handler(update, context)

    elif data == 'send_ipp':
        ipp_path = "/etc/openvpn/ipp.txt"
        if os.path.exists(ipp_path):
            with open(ipp_path, "rb") as f:
                await context.bot.send_document(chat_id=q.message.chat_id, document=InputFile(f), filename="ipp.txt")
            await safe_edit_text(q, context, "ipp.txt отправлен.")
        else:
            await safe_edit_text(q, context, "ipp.txt не найден.")

    elif data == 'block_alert':
        await alert_menu(update, context)
    elif data == 'alert_on':
        global alert_enabled, MIN_ONLINE_ALERT
        alert_enabled = True
        await safe_edit_text(q, context,
            f"🔔 Тревога: <b>ON</b>\nПорог: <b>{MIN_ONLINE_ALERT}</b> клиентов",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='block_alert')]]))
    elif data == 'alert_off':
        alert_enabled = False
        await safe_edit_text(q, context,
            "🔕 Тревога: <b>OFF</b>",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='block_alert')]]))
    elif data.startswith('alert_threshold:'):
        val = int(data[len('alert_threshold:'):])
        MIN_ONLINE_ALERT = val
        await safe_edit_text(q, context,
            f"✅ Порог установлен: <b>{val}</b> клиентов",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='block_alert')]]))
    elif data == 'alert_custom':
        context.user_data['await_alert_threshold'] = True
        await safe_edit_text(q, context,
            "Введите число — минимум онлайн для тревоги:",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data='block_alert')]]))

    elif data == 'help':
        await send_help_file(update, context)

    elif data == 'log':
        await log_request(update, context)

    elif data == 'create_key':
        await safe_edit_text(q, context, "Введите имя нового клиента:")
        context.user_data['await_key_name'] = True

    elif data == 'home':
        await context.bot.send_message(q.message.chat_id, "Главное меню уже показано. Для обновления нажми /start.")

    elif data == 'noop':
        pass  # separator button

    # --- Backup hub callbacks ---
    elif data == 'backup_upload_prompt':
        await safe_edit_text(q, context,
            "Отправьте файл бэкапа OpenVPN (.tar.gz) в чат.\n"
            "Бот сохранит его в /root для последующего восстановления.")
        context.user_data['await_backup_upload'] = True

    elif data == 'rr_restore_prompt':
        await safe_edit_text(q, context,
            "Отправьте файл бэкапа Remote Refresh (.zip) в чат.\n"
            "Бот восстановит IP, домены, историю и флаги.")
        context.user_data['await_rr_restore'] = True

    # --- OVPN EDIT callbacks ---
    elif data == 'ovpn_edit_menu':
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⚙️ server.conf", callback_data='ovpn_view_server_conf')],
            [InlineKeyboardButton("📄 client-template.txt", callback_data='ovpn_view_client_template')],
            [InlineKeyboardButton("❌ Отмена", callback_data='ovpn_edit_cancel')],
        ])
        await safe_edit_text(q, context, "Выберите файл для просмотра/редактирования:", reply_markup=kb)

    elif data == 'ovpn_view_server_conf':
        path = OVPN_EDIT_FILES["server_conf"]
        try:
            with open(path, "r", encoding="utf-8") as f:
                file_content = f.read()
        except OSError as exc:
            await safe_edit_text(q, context, f"❌ Не удалось прочитать: {exc}")
            return
        if len(file_content) > 3900:
            await q.message.reply_document(
                document=file_content.encode("utf-8"),
                filename="server.conf",
                caption="Отправьте новое содержимое файла целиком для замены, или /cancel для отмены."
            )
            await safe_edit_text(q, context, "Файл отправлен выше (слишком длинный для сообщения).")
        else:
            await safe_edit_text(q, context,
                f"<b>server.conf:</b>\n<pre>{escape(file_content)}</pre>\n\n"
                "Отправьте новое содержимое файла целиком для замены.",
                parse_mode="HTML")
        context.user_data['await_ovpn_edit'] = 'server_conf'

    elif data == 'ovpn_view_client_template':
        path = OVPN_EDIT_FILES["client_template"]
        try:
            with open(path, "r", encoding="utf-8") as f:
                file_content = f.read()
        except OSError as exc:
            await safe_edit_text(q, context, f"❌ Не удалось прочитать: {exc}")
            return
        if len(file_content) > 3900:
            await q.message.reply_document(
                document=file_content.encode("utf-8"),
                filename="client-template.txt",
                caption="Отправьте новое содержимое файла целиком для замены, или /cancel для отмены."
            )
            await safe_edit_text(q, context, "Файл отправлен выше (слишком длинный для сообщения).")
        else:
            await safe_edit_text(q, context,
                f"<b>client-template.txt:</b>\n<pre>{escape(file_content)}</pre>\n\n"
                "Отправьте новое содержимое файла целиком для замены.",
                parse_mode="HTML")
        context.user_data['await_ovpn_edit'] = 'client_template'

    elif data == 'ovpn_edit_cancel':
        context.user_data.pop('await_ovpn_edit', None)
        await safe_edit_text(q, context, "Отменено.")

    # --- Restart callbacks ---
    elif data == 'restart_menu':
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔁 OpenVPN", callback_data='rst_openvpn')],
            [InlineKeyboardButton("🤖 Бот", callback_data='rst_bot')],
            [InlineKeyboardButton("❌ Отмена", callback_data='rst_cancel')],
        ])
        await safe_edit_text(q, context, "Что перезагрузить?", reply_markup=kb)

    elif data == 'rst_openvpn':
        await safe_edit_text(q, context, "Перезагрузка OpenVPN...")
        try:
            result = subprocess.run(
                ["systemctl", "restart", "openvpn@server"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                await safe_edit_text(q, context, "✅ OpenVPN перезагружен.")
            else:
                err = result.stderr.strip() or "неизвестная ошибка"
                await safe_edit_text(q, context, f"❌ Ошибка:\n{err}")
        except Exception as exc:
            await safe_edit_text(q, context, f"❌ Ошибка: {exc}")

    elif data == 'rst_bot':
        await safe_edit_text(q, context, "🔄 Перезагрузка бота через 2 сек...")
        await asyncio.sleep(2)
        subprocess.Popen(["systemctl", "restart", "remote-refresh-bot"])

    elif data == 'rst_cancel':
        await safe_edit_text(q, context, "Отменено.")

    elif data == 'git_pull':
        await safe_edit_text(q, context, "📥 Git Pull...")
        try:
            r1 = subprocess.run(
                ["git", "-C", "/opt/remote_refresh", "pull"],
                capture_output=True, text=True, timeout=30)
            pull_out = r1.stdout.strip() or r1.stderr.strip()
            if "Already up to date" in pull_out:
                await safe_edit_text(q, context, f"📥 <b>Git Pull:</b>\n<pre>{escape(pull_out)}</pre>\n\nОбновлений нет.",
                    parse_mode="HTML")
            else:
                shutil.copy2("/opt/remote_refresh/bot/bot.py", "/root/monitor_bot/bot.py")
                await safe_edit_text(q, context,
                    f"📥 <b>Git Pull:</b>\n<pre>{escape(pull_out[:2000])}</pre>\n\n"
                    "✅ bot.py скопирован.\n🔄 Перезапуск бота через 2 сек...",
                    parse_mode="HTML")
                await asyncio.sleep(2)
                subprocess.Popen(["systemctl", "restart", "remote-refresh-bot"])
        except Exception as e:
            await safe_edit_text(q, context, f"❌ Ошибка: {e}")

    # --- SSH Routers ---
    elif data == 'ssh_routers':
        await ssh_menu(update, context)
    elif data == 'ssh_list':
        await ssh_list_routers(update, context)
    elif data == 'ssh_add':
        await ssh_add_start(update, context)
    elif data == 'ssh_ping_all':
        await ssh_ping_all(update, context)
    elif data.startswith('ssh_status:'):
        cn = data[len('ssh_status:'):]
        await ssh_router_status(update, context, cn)
    elif data == 'ssh_select_status':
        await ssh_select_router(update, context, 'ssh_status')
    elif data == 'ssh_select_update':
        await ssh_select_router(update, context, 'ssh_update')
    elif data == 'ssh_select_deploy':
        await ssh_deploy_mode_menu(update, context)
    elif data == 'ssh_deploy_one':
        await ssh_select_router(update, context, 'ssh_deploy')
    elif data == 'ssh_deploy_multi':
        context.user_data['ssh_deploy_selected'] = []
        await ssh_deploy_multi_select(update, context)
    elif data.startswith('ssh_deploy_toggle:'):
        cn = data[len('ssh_deploy_toggle:'):]
        sel = context.user_data.get('ssh_deploy_selected', [])
        if cn in sel:
            sel.remove(cn)
        else:
            sel.append(cn)
        context.user_data['ssh_deploy_selected'] = sel
        await ssh_deploy_multi_select(update, context)
    elif data == 'ssh_deploy_multi_done':
        sel = context.user_data.get('ssh_deploy_selected', [])
        if not sel:
            await safe_edit_text(q, context, "Ни один роутер не выбран.",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='ssh_select_deploy')]]))
        else:
            context.user_data['ssh_deploy_targets'] = sel
            saved_front = ""
            try:
                with open(DEPLOY_FRONT_IP_FILE, "r") as f:
                    saved_front = f.read().strip()
            except FileNotFoundError:
                pass
            kb = []
            if saved_front:
                kb.append([InlineKeyboardButton(f"✅ {saved_front}", callback_data=f'ssh_deploy_multi_use:{saved_front}')])
            kb.append([InlineKeyboardButton("❌ Отмена", callback_data='ssh_routers')])
            names = ", ".join(sel)
            hint = f"\nПоследний фронт: <code>{saved_front}</code>" if saved_front else ""
            await safe_edit_text(q, context,
                f"📦 <b>Залить скрипт на {len(sel)} роутеров</b>\n"
                f"({names})\n\n"
                f"Введите IP фронт-сервера.{hint}\n\n"
                f"Или отправьте новый IP:",
                parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))
            context.user_data['await_ssh_deploy_ip'] = True
            context.user_data['ssh_deploy_cn'] = '__multi__'
    elif data.startswith('ssh_deploy_multi_use:'):
        front_ip = data[len('ssh_deploy_multi_use:'):]
        targets = context.user_data.pop('ssh_deploy_targets', [])
        context.user_data.pop('await_ssh_deploy_ip', None)
        context.user_data.pop('ssh_deploy_cn', None)
        if targets:
            await _do_ssh_deploy_multi(q, context, targets, front_ip)
    elif data == 'ssh_deploy_all':
        routers = load_routers()
        if not routers:
            await safe_edit_text(q, context, "Список роутеров пуст.")
            return
        context.user_data['ssh_deploy_targets'] = sorted(routers.keys(), key=_natural_key)
        saved_front = ""
        try:
            with open(DEPLOY_FRONT_IP_FILE, "r") as f:
                saved_front = f.read().strip()
        except FileNotFoundError:
            pass
        kb = []
        if saved_front:
            kb.append([InlineKeyboardButton(f"✅ {saved_front}", callback_data=f'ssh_deploy_multi_use:{saved_front}')])
        kb.append([InlineKeyboardButton("❌ Отмена", callback_data='ssh_routers')])
        hint = f"\nПоследний фронт: <code>{saved_front}</code>" if saved_front else ""
        await safe_edit_text(q, context,
            f"📦 <b>Залить скрипт на ВСЕ роутеры ({len(routers)})</b>\n\n"
            f"Введите IP фронт-сервера.{hint}\n\n"
            f"Или отправьте новый IP:",
            parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))
        context.user_data['await_ssh_deploy_ip'] = True
        context.user_data['ssh_deploy_cn'] = '__multi__'
    elif data.startswith('ssh_deploy:'):
        cn = data[len('ssh_deploy:'):]
        context.user_data['ssh_deploy_cn'] = cn
        # Read last saved front IP
        saved_front = ""
        try:
            with open(DEPLOY_FRONT_IP_FILE, "r") as f:
                saved_front = f.read().strip()
        except FileNotFoundError:
            pass
        front_ip = rr_read_file(RR_IP_FILE, "").strip()
        kb = []
        if saved_front:
            kb.append([InlineKeyboardButton(f"✅ {saved_front}", callback_data=f'ssh_deploy_use:{saved_front}')])
        kb.append([InlineKeyboardButton("❌ Отмена", callback_data='ssh_routers')])
        hint = f"\nПоследний фронт: <code>{saved_front}</code>" if saved_front else ""
        await safe_edit_text(q, context,
            f"📦 <b>Залить скрипт на {cn}</b>\n\n"
            f"Введите IP фронт-сервера (через который роутер скачает скрипт).{hint}\n\n"
            f"Или отправьте новый IP:",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup(kb))
        context.user_data['await_ssh_deploy_ip'] = True
    elif data.startswith('ssh_deploy_use:'):
        # Quick-select saved front IP
        front_ip = data[len('ssh_deploy_use:'):]
        cn = context.user_data.pop('ssh_deploy_cn', None)
        context.user_data.pop('await_ssh_deploy_ip', None)
        if not cn:
            await safe_edit_text(q, context, "Ошибка: роутер не выбран.")
            return
        await _do_ssh_deploy(q.message, context, cn, front_ip, edit_msg=q)
    elif data == 'ssh_select_heal':
        await ssh_select_router(update, context, 'ssh_heal')
    elif data == 'ssh_select_reboot':
        await ssh_select_router(update, context, 'ssh_reboot')
    elif data == 'ssh_select_cmd':
        await ssh_cmd_mode_menu(update, context)
    elif data == 'ssh_cmd_one':
        await ssh_select_router(update, context, 'ssh_cmd')
    elif data == 'ssh_cmd_all':
        context.user_data['await_ssh_cmd'] = '__all__'
        await safe_edit_text(q, context, "💻 Введите команду для <b>ВСЕХ</b> роутеров:", parse_mode="HTML")
    elif data == 'ssh_cmd_multi':
        context.user_data['ssh_cmd_selected'] = []
        await ssh_cmd_multi_select(update, context)
    elif data.startswith('ssh_cmd_toggle:'):
        cn = data[len('ssh_cmd_toggle:'):]
        sel = context.user_data.get('ssh_cmd_selected', [])
        if cn in sel:
            sel.remove(cn)
        else:
            sel.append(cn)
        context.user_data['ssh_cmd_selected'] = sel
        await ssh_cmd_multi_select(update, context)
    elif data == 'ssh_cmd_multi_done':
        sel = context.user_data.get('ssh_cmd_selected', [])
        if not sel:
            await safe_edit_text(q, context, "Ни один роутер не выбран.",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='ssh_select_cmd')]]))
        else:
            context.user_data['await_ssh_cmd'] = sel
            names = ", ".join(sel)
            await safe_edit_text(q, context, f"💻 Введите команду для: <b>{names}</b>", parse_mode="HTML")
    elif data == 'ssh_select_edit':
        await ssh_select_router(update, context, 'ssh_edit')
    elif data == 'ssh_select_delete':
        await ssh_select_router(update, context, 'ssh_delete')
    elif data.startswith('ssh_update:'):
        cn = data[len('ssh_update:'):]
        await ssh_update_script(update, context, cn)
    elif data.startswith('ssh_heal:'):
        cn = data[len('ssh_heal:'):]
        await ssh_heal_router(update, context, cn)
    elif data.startswith('ssh_reboot:'):
        cn = data[len('ssh_reboot:'):]
        await ssh_reboot_router(update, context, cn)
    elif data.startswith('ssh_cmd:'):
        cn = data[len('ssh_cmd:'):]
        context.user_data['await_ssh_cmd'] = cn
        context.user_data.pop('await_ssh_add', None)
        await safe_edit_text(q, context, f"💻 Введите команду для <b>{cn}</b>:", parse_mode="HTML")
    elif data.startswith('ssh_edit:'):
        cn = data[len('ssh_edit:'):]
        context.user_data['await_ssh_edit'] = cn
        context.user_data.pop('await_ssh_add', None)
        routers = load_routers()
        r = routers.get(cn, {})
        await safe_edit_text(q, context,
            f"✏️ <b>Редактировать {cn}</b>\n\n"
            f"Текущие: user=<code>{r.get('user','admin')}</code> port=<code>{r.get('port',22)}</code>\n\n"
            f"Введите новый пароль (или user:password или user:password:port):",
            parse_mode="HTML")
    elif data.startswith('ssh_delete:'):
        cn = data[len('ssh_delete:'):]
        routers = load_routers()
        if cn in routers:
            del routers[cn]
            save_routers(routers)
            await safe_edit_text(q, context, f"🗑️ Роутер <b>{cn}</b> удалён.", parse_mode="HTML")
        else:
            await safe_edit_text(q, context, "Роутер не найден.")

    # --- Change password callbacks ---
    elif data == 'ssh_chpass_menu':
        await ssh_chpass_mode_menu(update, context)
    elif data == 'ssh_chpass_one':
        await ssh_select_router(update, context, 'ssh_chpass')
    elif data == 'ssh_chpass_all':
        context.user_data['ssh_chpass_targets'] = '__all__'
        await safe_edit_text(q, context,
            "🔑 <b>Сменить пароль на ВСЕХ роутерах</b>\n\n"
            "Введите новый пароль:",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("❌ Отмена", callback_data='ssh_routers')]]))
        context.user_data['await_ssh_chpass'] = True
        context.user_data.pop('await_ssh_add', None)
    elif data == 'ssh_chpass_multi':
        context.user_data['ssh_chpass_selected'] = []
        await ssh_chpass_multi_select(update, context)
    elif data.startswith('ssh_chpass_toggle:'):
        cn = data[len('ssh_chpass_toggle:'):]
        sel = context.user_data.get('ssh_chpass_selected', [])
        if cn in sel:
            sel.remove(cn)
        else:
            sel.append(cn)
        context.user_data['ssh_chpass_selected'] = sel
        await ssh_chpass_multi_select(update, context)
    elif data == 'ssh_chpass_multi_done':
        sel = context.user_data.get('ssh_chpass_selected', [])
        if not sel:
            await safe_edit_text(q, context, "Не выбрано ни одного роутера.",
                reply_markup=InlineKeyboardMarkup(
                    [[InlineKeyboardButton("◀️ Назад", callback_data='ssh_chpass_menu')]]))
        else:
            context.user_data['ssh_chpass_targets'] = sel
            names = ", ".join(sel)
            await safe_edit_text(q, context,
                f"🔑 <b>Сменить пароль на: {names}</b>\n\n"
                "Введите логин и пароль через пробел:\n"
                "<code>admin новый_пароль</code>\n\n"
                "Или только пароль (логин = admin):",
                parse_mode="HTML",
                reply_markup=InlineKeyboardMarkup(
                    [[InlineKeyboardButton("❌ Отмена", callback_data='ssh_routers')]]))
            context.user_data['await_ssh_chpass'] = True
            context.user_data.pop('await_ssh_add', None)
    elif data.startswith('ssh_chpass:'):
        cn = data[len('ssh_chpass:'):]
        context.user_data['ssh_chpass_targets'] = [cn]
        await safe_edit_text(q, context,
            f"🔑 <b>Сменить пароль на {cn}</b>\n\n"
            "Введите новый пароль:",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("❌ Отмена", callback_data='ssh_routers')]]))
        context.user_data['await_ssh_chpass'] = True
        context.user_data.pop('await_ssh_add', None)

    # --- OpenVPN Ext Config callbacks ---
    elif data == 'oec_menu':
        await oec_menu(update, context)
    elif data == 'oec_rem':
        await ssh_select_router(update, context, 'oec_rem')
    elif data.startswith('oec_rem:'):
        cn = data[len('oec_rem:'):]
        await oec_remote_show(update, context, cn)
    elif data.startswith('oec_rdel:'):
        idx = int(data[len('oec_rdel:'):])
        await oec_remote_del(update, context, idx)
    elif data == 'oec_radd':
        await oec_remote_add_start(update, context)
    elif data == 'oec_apply':
        await oec_apply(update, context)
    elif data == 'oec_apply_one':
        await oec_apply_exec(update, context, 'one')
    elif data == 'oec_apply_all':
        await oec_apply_exec(update, context, '__all__')
    elif data == 'oec_refresh':
        await oec_refresh(update, context)
    elif data == 'oec_full':
        await ssh_select_router(update, context, 'oec_full')
    elif data.startswith('oec_full:'):
        cn = data[len('oec_full:'):]
        await oec_full_show(update, context, cn)
    elif data.startswith('oec_fedit:'):
        cn = data[len('oec_fedit:'):]
        await oec_full_edit_start(update, context, cn)
    elif data == 'oec_fedit_do_one':
        await oec_full_edit_exec(update, context, 'one')
    elif data == 'oec_fedit_do_all':
        await oec_full_edit_exec(update, context, '__all__')

    # --- Remote Refresh callbacks ---
    elif data == 'rr_current_ip':
        await rr_current_ip(update, context)
    elif data == 'rr_set_ip':
        await rr_set_ip_start(update, context)
    elif data == 'rr_history':
        await rr_history(update, context)
    elif data == 'rr_backup':
        await rr_backup(update, context)
    elif data == 'rr_ip_scan':
        await rr_ip_scan_toggle(update, context)
    elif data == 'rr_port_scan':
        await rr_port_scan_toggle(update, context)
    elif data == 'rr_domains':
        await rr_domains_menu(update, context)
    elif data == 'rr_dom_add':
        await rr_dom_add_start(update, context)
    elif data == 'rr_dom_remove':
        await rr_dom_remove_start(update, context)
    elif data.startswith('rr_dom_del:'):
        domain = data[len('rr_dom_del:'):]
        await rr_dom_remove_apply(update, context, domain)
    elif data == 'rr_push_domains':
        await rr_push_domains(update, context)
    elif data == 'push_dom_all':
        routers = load_routers()
        await _rr_push_dom_exec(update, context, list(routers.keys()))
    elif data == 'push_dom_one':
        await rr_push_dom_select_one(update, context)
    elif data == 'push_dom_multi':
        await rr_push_dom_select_multi(update, context)
    elif data.startswith('push_dom_run:'):
        cn = data[len('push_dom_run:'):]
        await _rr_push_dom_exec(update, context, [cn])
    elif data.startswith('push_dom_tog:'):
        cn = data[len('push_dom_tog:'):]
        await rr_push_dom_toggle(update, context, cn)
    elif data == 'push_dom_go_sel':
        selected = list(context.user_data.get('push_dom_selected', set()))
        if not selected:
            await update.callback_query.answer("Ничего не выбрано", show_alert=True)
        else:
            await _rr_push_dom_exec(update, context, selected)
    elif data == 'chk_dom_menu':
        await chk_dom_menu(update, context)
    elif data == 'chk_dom_all':
        routers = load_routers()
        await _chk_dom_exec(update, context, list(routers.keys()))
    elif data == 'chk_dom_one':
        await chk_dom_select_one(update, context)
    elif data == 'chk_dom_multi':
        await chk_dom_select_multi(update, context)
    elif data.startswith('chk_dom_run:'):
        cn = data[len('chk_dom_run:'):]
        await _chk_dom_exec(update, context, [cn])
    elif data.startswith('chk_dom_tog:'):
        cn = data[len('chk_dom_tog:'):]
        await chk_dom_toggle(update, context, cn)
    elif data == 'chk_dom_go_sel':
        selected = list(context.user_data.get('chk_dom_selected', set()))
        if not selected:
            await update.callback_query.answer("Ничего не выбрано", show_alert=True)
        else:
            await _chk_dom_exec(update, context, selected)
    elif data == 'rr_cancel':
        await rr_cancel(update, context)

    # --- Force IP callbacks ---
    elif data == 'force_ip':
        await force_ip_start(update, context)
    elif data == 'force_ip_all':
        await force_ip_exec_all(update, context)
    elif data == 'force_ip_one':
        await force_ip_select_one(update, context)
    elif data == 'force_ip_multi':
        await force_ip_select_multi(update, context)
    elif data.startswith('force_ip_t:'):
        cn = data[len('force_ip_t:'):]
        await force_ip_toggle(update, context, cn)
    elif data == 'force_ip_go':
        await force_ip_exec_selected(update, context)
    elif data.startswith('force_ip_run:'):
        cn = data[len('force_ip_run:'):]
        await force_ip_exec_one(update, context, cn)

    # --- Auto IP callbacks ---
    elif data == 'aip_menu':
        await auto_ip_menu(update, context)
    elif data == 'aip_toggle':
        await auto_ip_toggle(update, context)
    elif data == 'aip_add':
        await auto_ip_add_start(update, context)
    elif data == 'aip_remove':
        await auto_ip_remove_menu(update, context)
    elif data.startswith('aip_del:'):
        ip = data[len('aip_del:'):]
        await auto_ip_remove_apply(update, context, ip)
    elif data == 'aip_reorder':
        await auto_ip_reorder_menu(update, context)
    elif data == 'aip_ping':
        await auto_ip_ping_all(update, context)
    elif data == 'aip_replace':
        await auto_ip_replace_menu(update, context)
    elif data.startswith('aip_rep:'):
        old_ip = data[len('aip_rep:'):]
        await auto_ip_replace_start(update, context, old_ip)
    elif data.startswith('aip_move:'):
        # aip_move:INDEX:up or aip_move:INDEX:down
        parts = data[len('aip_move:'):].split(':')
        idx = int(parts[0])
        direction = parts[1]
        await auto_ip_move(update, context, idx, direction)

    # --- GOST callbacks ---
    elif data == 'gost_menu':
        await gost_menu(update, context)
    elif data == 'gost_list':
        await gost_list(update, context)
    elif data == 'gost_add':
        await gost_add_start(update, context)
    elif data.startswith('gost_edit:'):
        await gost_edit_start(update, context, data[len('gost_edit:'):])
    elif data.startswith('gost_del:'):
        await gost_delete(update, context, data[len('gost_del:'):])
    elif data == 'gost_select_install':
        await _gost_select_server(update, context, 'gost_install', "⚙️ <b>Установить GOST</b>\nВыберите сервер:")
    elif data.startswith('gost_install:'):
        await gost_install(update, context, data[len('gost_install:'):])
    elif data == 'gost_select_rules':
        await _gost_select_server(update, context, 'gost_rules', "📡 <b>Настроить правила</b>\nВыберите сервер:")
    elif data.startswith('gost_rules:'):
        await gost_configure_rules_start(update, context, data[len('gost_rules:'):])
    elif data == 'gost_select_addrule':
        await _gost_select_server(update, context, 'gost_addrule', "➕ <b>Добавить правило</b>\nВыберите сервер:")
    elif data.startswith('gost_addrule:'):
        await gost_add_rule_start(update, context, data[len('gost_addrule:'):])
    elif data == 'gost_rule_more':
        await gost_rule_more(update, context)
    elif data == 'gost_rule_done':
        await gost_rule_done(update, context)
    elif data == 'gost_select_showconf':
        await _gost_select_server(update, context, 'gost_showconf', "📄 <b>Показать конфиг</b>\nВыберите сервер:")
    elif data.startswith('gost_showconf:'):
        await gost_show_config(update, context, data[len('gost_showconf:'):])
    elif data == 'gost_ping_all':
        await gost_ping_all(update, context)
    elif data == 'gost_select_start':
        await _gost_select_server(update, context, 'gost_start', "▶️ <b>Запустить GOST</b>\nВыберите сервер:")
    elif data.startswith('gost_start:'):
        await gost_start_cmd(update, context, data[len('gost_start:'):])
    elif data == 'gost_select_stop':
        await _gost_select_server(update, context, 'gost_stop', "⏹ <b>Остановить GOST</b>\nВыберите сервер:")
    elif data.startswith('gost_stop:'):
        await gost_stop_cmd(update, context, data[len('gost_stop:'):])
    elif data == 'gost_select_restart':
        await _gost_select_server(update, context, 'gost_restart', "🔁 <b>Перезапустить GOST</b>\nВыберите сервер:")
    elif data.startswith('gost_restart:'):
        await gost_restart_cmd(update, context, data[len('gost_restart:'):])
    elif data == 'gost_select_status':
        await _gost_select_server(update, context, 'gost_status', "📊 <b>Статус GOST</b>\nВыберите сервер:")
    elif data.startswith('gost_status:'):
        await gost_status_cmd(update, context, data[len('gost_status:'):])
    elif data == 'gost_select_log':
        await _gost_select_server(update, context, 'gost_log', "📜 <b>Лог GOST</b>\nВыберите сервер:")
    elif data.startswith('gost_log:'):
        await gost_log_cmd(update, context, data[len('gost_log:'):])
    elif data == 'gost_select_backup':
        await _gost_select_server(update, context, 'gost_backup', "💾 <b>Бэкап GOST</b>\nВыберите сервер:")
    elif data.startswith('gost_backup:'):
        await gost_backup_cmd(update, context, data[len('gost_backup:'):])
    elif data == 'gost_select_restore':
        await _gost_select_server(update, context, 'gost_restore', "📥 <b>Восстановить GOST</b>\nВыберите сервер:")
    elif data.startswith('gost_restore:'):
        await gost_restore_cmd(update, context, data[len('gost_restore:'):])
    elif data.startswith('gost_restore_apply:'):
        # gost_restore_apply:IP:FILENAME
        rest = data[len('gost_restore_apply:'):]
        parts = rest.split(':', 1)
        await gost_restore_apply(update, context, parts[0], parts[1])
    elif data == 'gost_select_optimize':
        await _gost_select_server(update, context, 'gost_optimize', "🚀 <b>Ускорить TCP/UDP</b>\nВыберите сервер:")
    elif data.startswith('gost_optimize:'):
        await gost_optimize_cmd(update, context, data[len('gost_optimize:'):])
    elif data == 'gost_select_uninstall':
        await _gost_select_server(update, context, 'gost_uninstall', "🗑️ <b>Удалить GOST</b>\nВыберите сервер:")
    elif data.startswith('gost_uninstall:'):
        await gost_uninstall_cmd(update, context, data[len('gost_uninstall:'):])
    elif data == 'gost_help':
        await gost_help_send(update, context)
    elif data == 'gost_getroot':
        await gost_getroot_start(update, context)

    else:
        await safe_edit_text(q, context, "Неизвестная команда.")

# =====================================================================
#  SSH ROUTERS — handlers
# =====================================================================

async def ssh_deploy_mode_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show deploy target selection: one / several / all."""
    q = update.callback_query
    routers = load_routers()
    if not routers:
        await safe_edit_text(q, context, "Список роутеров пуст.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')]]))
        return
    kb = [
        [InlineKeyboardButton("🖥 Один роутер", callback_data='ssh_deploy_one')],
        [InlineKeyboardButton("☑️ Несколько роутеров", callback_data='ssh_deploy_multi')],
        [InlineKeyboardButton("🌐 Все роутеры", callback_data='ssh_deploy_all')],
        [InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')],
    ]
    await safe_edit_text(q, context, "📦 <b>Залить скрипт</b>\nВыберите режим:",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def ssh_deploy_multi_select(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show router list with toggle checkboxes for multi-deploy."""
    q = update.callback_query
    routers = load_routers()
    online = get_online_clients()
    selected = context.user_data.get('ssh_deploy_selected', [])
    kb = []
    for cn in sorted(routers.keys(), key=_natural_key):
        status = "🟢" if cn in online else "🔴"
        check = "☑️" if cn in selected else "☐"
        kb.append([InlineKeyboardButton(f"{check} {status} {cn}", callback_data=f'ssh_deploy_toggle:{cn}')])
    count = len(selected)
    kb.append([InlineKeyboardButton(f"✅ Готово ({count})", callback_data='ssh_deploy_multi_done')])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='ssh_select_deploy')])
    await safe_edit_text(q, context, "📦 Выберите роутеры для деплоя:\n(нажмите чтобы выбрать/убрать)",
        reply_markup=InlineKeyboardMarkup(kb))

async def _do_ssh_deploy_multi(q_or_msg, context, targets: list, front_ip: str):
    """Deploy script to multiple routers sequentially."""
    try:
        with open(DEPLOY_FRONT_IP_FILE, "w") as f:
            f.write(front_ip)
    except Exception:
        pass
    routers = load_routers()
    total = len(targets)
    if hasattr(q_or_msg, 'message'):
        msg = q_or_msg.message
        await safe_edit_text(q_or_msg, context,
            f"📦 Деплой на {total} роутеров через <code>{front_ip}</code>...\n0/{total}",
            parse_mode="HTML")
    else:
        msg = await q_or_msg.reply_text(
            f"📦 Деплой на {total} роутеров через <code>{front_ip}</code>...\n0/{total}",
            parse_mode="HTML")
    results = []
    for i, cn in enumerate(targets, 1):
        r = routers.get(cn)
        if not r:
            results.append(f"❌ <b>{cn}</b> — не найден")
            continue
        ip = get_router_ip(cn)
        if not ip:
            results.append(f"❌ <b>{cn}</b> — оффлайн")
            continue
        try:
            await msg.edit_text(
                f"📦 Деплой через <code>{front_ip}</code>...\n{i}/{total}: <b>{cn}</b>",
                parse_mode="HTML")
        except Exception:
            pass
        deploy_cmd = (
            f'cat /dev/null > /etc/storage/started_script.sh ; '
            f'wget -q -O /tmp/us.sh http://{front_ip}/router/update_script.sh && '
            f'[ "$(grep -c is_reserved_ipv4 /tmp/us.sh)" = "3" ] && '
            f"tail -n1 /tmp/us.sh | grep -q '^exit 0' && {{ "
            f'cp /etc/storage/update_script.sh /etc/storage/update_script.sh.bak.$(date +%H%M) 2>/dev/null ; '
            f'mv /tmp/us.sh /etc/storage/update_script.sh && chmod +x /etc/storage/update_script.sh ; '
            f'wget -q -O- http://{front_ip}/router/domain_list.txt | grep -E "^[A-Za-z0-9._-]+$" > /tmp/dom.tmp ; '
            f'[ -s /tmp/dom.tmp ] && mv /tmp/dom.tmp /etc/storage/remote_domains.list ; '
            f'( crontab -l 2>/dev/null | grep -v "update_script\\.sh" ; echo "*/5 * * * * /etc/storage/update_script.sh" ) | crontab - ; '
            f'nvram set crond_enable=1 >/dev/null 2>&1 ; nvram commit >/dev/null 2>&1 ; '
            f'mtd_storage.sh save ; '
            f'echo "DEPLOY OK" ; '
            f"}} || echo 'ABORTED'"
        )
        ok, out = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'), r.get('password', ''), deploy_cmd)
        if ok and "DEPLOY OK" in out:
            results.append(f"✅ <b>{cn}</b>")
        else:
            short = out.strip()[:150] if out else "—"
            results.append(f"❌ <b>{cn}</b>: {escape(short)}")
    report = "\n".join(results)
    ok_count = sum(1 for r in results if r.startswith("✅"))
    await msg.edit_text(
        f"📦 <b>Деплой завершён</b>: {ok_count}/{total}\n\n{report}",
        parse_mode="HTML")

async def ssh_cmd_mode_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show command target selection: one / several / all."""
    q = update.callback_query
    routers = load_routers()
    if not routers:
        await safe_edit_text(q, context, "Список роутеров пуст.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')]]))
        return
    kb = [
        [InlineKeyboardButton("🖥 Один роутер", callback_data='ssh_cmd_one')],
        [InlineKeyboardButton("☑️ Несколько роутеров", callback_data='ssh_cmd_multi')],
        [InlineKeyboardButton("🌐 Все роутеры", callback_data='ssh_cmd_all')],
        [InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')],
    ]
    await safe_edit_text(q, context, "💻 <b>Команда</b>\nВыберите режим:",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def ssh_cmd_multi_select(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show router list with toggle checkboxes for multi-select."""
    q = update.callback_query
    routers = load_routers()
    online = get_online_clients()
    selected = context.user_data.get('ssh_cmd_selected', [])
    kb = []
    for cn in sorted(routers.keys(), key=_natural_key):
        status = "🟢" if cn in online else "🔴"
        check = "☑️" if cn in selected else "☐"
        kb.append([InlineKeyboardButton(f"{check} {status} {cn}", callback_data=f'ssh_cmd_toggle:{cn}')])
    count = len(selected)
    kb.append([InlineKeyboardButton(f"✅ Готово ({count})", callback_data='ssh_cmd_multi_done')])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='ssh_select_cmd')])
    await safe_edit_text(q, context, "💻 Выберите роутеры для команды:\n(нажмите чтобы выбрать/убрать)",
        reply_markup=InlineKeyboardMarkup(kb))

async def ssh_exec_multi(msg, routers_dict, targets, cmd, context):
    """Execute SSH command on multiple routers and return report."""
    results = []
    total = len(targets)
    for i, cn in enumerate(targets, 1):
        r = routers_dict.get(cn)
        if not r:
            results.append((cn, False, "не найден в routers.json"))
            continue
        ip = get_router_ip(cn)
        online = get_online_clients()
        if cn not in online:
            results.append((cn, False, "оффлайн"))
            continue
        if not ip:
            results.append((cn, False, "нет IP"))
            continue
        ok, out = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'), r.get('password', ''), cmd)
        results.append((cn, ok, out))
    # Build report
    success = sum(1 for _, ok, _ in results if ok)
    fail = total - success
    lines = [f"💻 <b>Команда:</b> <code>{escape(cmd[:200])}</code>",
             f"✅ Успешно: {success}  ❌ Ошибки: {fail}\n"]
    for cn, ok, out in results:
        icon = "✅" if ok else "❌"
        short = out.strip()[:300] if out else "—"
        lines.append(f"{icon} <b>{cn}</b>:\n<pre>{escape(short)}</pre>")
    return "\n".join(lines)

async def ssh_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    routers = load_routers()
    count = len(routers)
    kb = [
        [InlineKeyboardButton(f"📋 Список роутеров ({count})", callback_data='ssh_list')],
        [InlineKeyboardButton("➕ Добавить", callback_data='ssh_add'),
         InlineKeyboardButton("✏️ Редактировать", callback_data='ssh_select_edit')],
        [InlineKeyboardButton("🗑️ Удалить", callback_data='ssh_select_delete')],
        [InlineKeyboardButton("📡 Пинг всех", callback_data='ssh_ping_all')],
        [InlineKeyboardButton("🔍 Статус роутера", callback_data='ssh_select_status')],
        [InlineKeyboardButton("📦 Залить скрипт", callback_data='ssh_select_deploy')],
        [InlineKeyboardButton("🩹 Лечение", callback_data='ssh_select_heal')],
        [InlineKeyboardButton("🔁 Перезагрузка", callback_data='ssh_select_reboot')],
        [InlineKeyboardButton("💻 Команда", callback_data='ssh_select_cmd')],
        [InlineKeyboardButton("🔑 Сменить пароль", callback_data='ssh_chpass_menu')],
        [InlineKeyboardButton("📝 Конфиг OpenVPN", callback_data='oec_menu')],
        [InlineKeyboardButton("🏠 В главное меню", callback_data='home')],
    ]
    await safe_edit_text(q, context,
        "🖥 <b>SSH Роутеры</b>\n\n"
        f"Сохранено роутеров: {count}",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def ssh_list_routers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    routers = load_routers()
    if not routers:
        await safe_edit_text(q, context, "Список пуст. Добавьте роутеры через ➕ Добавить.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')]]))
        return
    online = get_online_clients()
    lines = []
    for cn, info in sorted(routers.items(), key=lambda x: _natural_key(x[0])):
        ip = get_router_ip(cn)
        status = "🟢" if cn in online else "🔴"
        ip_str = ip or "—"
        lines.append(f"{status} <b>{cn}</b>  {ip_str}")
    text = "📋 <b>Роутеры:</b>\n\n" + "\n".join(lines)
    kb = [[InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')]]
    await safe_edit_text(q, context, text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def ssh_add_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    context.user_data['await_ssh_add'] = True
    # Show list of clients from ipp.txt that are NOT yet in routers.json
    routers = load_routers()
    available = []
    try:
        with open(IPP_FILE, "r") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) >= 2 and parts[0] not in routers:
                    available.append(parts[0])
    except FileNotFoundError:
        pass
    if available:
        avail_str = "  ".join(f"<code>{c}</code>" for c in sorted(available, key=_natural_key))
        hint = f"\n\nДоступные клиенты:\n{avail_str}"
    else:
        hint = "\n\nВсе клиенты из ipp.txt уже добавлены."
    await safe_edit_text(q, context,
        f"➕ <b>Добавить роутер</b>{hint}\n\n"
        "Формат: <code>имя пароль</code>\n"
        "или: <code>имя логин пароль</code>\n"
        "или: <code>имя логин пароль порт</code>\n"
        "Несколько — каждый с новой строки\n"
        "User по умолчанию: admin",
        parse_mode="HTML")

async def ssh_select_router(update: Update, context: ContextTypes.DEFAULT_TYPE, action: str):
    q = update.callback_query
    routers = load_routers()
    if not routers:
        await safe_edit_text(q, context, "Список роутеров пуст.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')]]))
        return
    online = get_online_clients()
    kb = []
    for cn in sorted(routers.keys(), key=_natural_key):
        status = "🟢" if cn in online else "🔴"
        kb.append([InlineKeyboardButton(f"{status} {cn}", callback_data=f'{action}:{cn}')])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')])
    titles = {
        'ssh_status': '🔍 Выберите роутер для статуса',
        'ssh_update': '🔄 Выберите роутер для обновления скрипта',
        'ssh_heal': '🩹 Выберите роутер для лечения',
        'ssh_reboot': '🔁 Выберите роутер для перезагрузки',
        'ssh_cmd': '💻 Выберите роутер для команды',
        'ssh_edit': '✏️ Выберите роутер для редактирования',
        'ssh_delete': '🗑️ Выберите роутер для удаления',
        'ssh_chpass': '🔑 Выберите роутер для смены пароля',
        'oec_rem': '🌐 Выберите роутер для Remote',
        'oec_full': '📝 Выберите роутер для конфига',
    }
    await safe_edit_text(q, context, titles.get(action, "Выберите роутер:"),
        reply_markup=InlineKeyboardMarkup(kb))

async def ssh_ping_all(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    routers = load_routers()
    if not routers:
        await safe_edit_text(q, context, "Список роутеров пуст.")
        return
    await safe_edit_text(q, context, "📡 Проверяю роутеры...")
    online = get_online_clients()
    results = []
    for cn in sorted(routers.keys(), key=_natural_key):
        ip = get_router_ip(cn)
        if cn not in online:
            results.append(f"🔴 <b>{cn}</b> — оффлайн")
            continue
        if not ip:
            results.append(f"🟡 <b>{cn}</b> — нет IP в ipp.txt")
            continue
        r = routers[cn]
        ok, out = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'), r.get('password', ''), "uptime")
        if ok:
            results.append(f"🟢 <b>{cn}</b> ({ip}) — {out[:80]}")
        else:
            results.append(f"❌ <b>{cn}</b> ({ip}) — {out[:60]}")
    text = "📡 <b>Пинг всех роутеров:</b>\n\n" + "\n".join(results)
    kb = [[InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')]]
    await q.message.edit_text(text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def ssh_router_status(update: Update, context: ContextTypes.DEFAULT_TYPE, cn: str):
    q = update.callback_query
    routers = load_routers()
    r = routers.get(cn)
    if not r:
        await safe_edit_text(q, context, "Роутер не найден.")
        return
    ip = get_router_ip(cn)
    online = get_online_clients()
    if cn not in online or not ip:
        await safe_edit_text(q, context, f"🔴 <b>{cn}</b> — оффлайн, SSH невозможен.",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')]]))
        return
    await safe_edit_text(q, context, f"🔍 Подключаюсь к <b>{cn}</b>...", parse_mode="HTML")
    cmd = (
        "echo UPTIME: $(uptime) && "
        "echo MEMORY: $(free 2>/dev/null | head -2 || cat /proc/meminfo | head -3) && "
        "echo VPN_STATUS: $(ifconfig tun0 2>/dev/null | grep 'inet addr' || echo 'tun0 not found') && "
        "echo CRON: $(crontab -l 2>/dev/null | grep update_script || echo 'no cron') && "
        "echo SCRIPT: $(head -3 /tmp/update_script.sh 2>/dev/null || echo 'not found') && "
        "echo FIRMWARE: $(cat /etc/storage/firmware_version 2>/dev/null || uname -r)"
    )
    ok, out = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'), r.get('password', ''), cmd)
    if ok:
        text = f"🔍 <b>Статус {cn}</b> ({ip}):\n\n<pre>{escape(out[:3500])}</pre>"
    else:
        text = f"❌ <b>{cn}</b>: {out}"
    kb = [[InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')]]
    await q.message.edit_text(text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def ssh_update_script(update: Update, context: ContextTypes.DEFAULT_TYPE, cn: str):
    q = update.callback_query
    routers = load_routers()
    r = routers.get(cn)
    if not r:
        await safe_edit_text(q, context, "Роутер не найден.")
        return
    ip = get_router_ip(cn)
    if not ip:
        await safe_edit_text(q, context, f"🔴 {cn} — нет IP.")
        return
    await safe_edit_text(q, context, f"🔄 Обновляю скрипт на <b>{cn}</b>...", parse_mode="HTML")
    # Read domains from domain_list.txt to build the wget command
    domains = []
    try:
        with open(RR_DOMAIN_LIST_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)
    except FileNotFoundError:
        pass
    if domains:
        domain = domains[0]
        cmd = f"wget -qO /tmp/update_script.sh http://{domain}/router/update_script.sh && echo OK || echo FAIL"
    else:
        cmd = "echo 'No domains configured'"
    ok, out = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'), r.get('password', ''), cmd)
    text = f"🔄 <b>{cn}</b>: {out}" if ok else f"❌ <b>{cn}</b>: {out}"
    kb = [[InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')]]
    await q.message.edit_text(text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def ssh_chpass_mode_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show change password target selection: one / several / all."""
    q = update.callback_query
    routers = load_routers()
    online = get_online_clients()
    online_count = sum(1 for cn in routers if cn in online)
    kb = [
        [InlineKeyboardButton("🖥 Один роутер", callback_data='ssh_chpass_one')],
        [InlineKeyboardButton("☑️ Несколько роутеров", callback_data='ssh_chpass_multi')],
        [InlineKeyboardButton(f"🌐 Все активные ({online_count})", callback_data='ssh_chpass_all')],
        [InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')],
    ]
    await safe_edit_text(q, context,
        "🔑 <b>Сменить пароль роутера</b>\n\nВыберите режим:",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def ssh_chpass_multi_select(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show router list with toggle checkboxes for multi-select (chpass)."""
    q = update.callback_query
    routers = load_routers()
    online = get_online_clients()
    sel = context.user_data.get('ssh_chpass_selected', [])
    kb = []
    for cn in sorted(routers.keys(), key=_natural_key):
        if cn not in online:
            continue
        mark = "☑️" if cn in sel else "⬜"
        kb.append([InlineKeyboardButton(f"{mark} {cn}", callback_data=f'ssh_chpass_toggle:{cn}')])
    count = len(sel)
    kb.append([InlineKeyboardButton(f"✅ Готово ({count})", callback_data='ssh_chpass_multi_done')])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='ssh_chpass_menu')])
    await safe_edit_text(q, context, "🔑 Выберите роутеры для смены пароля:",
        reply_markup=InlineKeyboardMarkup(kb))

async def ssh_chpass_receive(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive login/password and execute change on target routers."""
    if not context.user_data.get('await_ssh_chpass'):
        return
    context.user_data.pop('await_ssh_chpass', None)
    targets = context.user_data.pop('ssh_chpass_targets', None)
    password = update.message.text.strip()
    if not password or ' ' in password:
        await update.message.reply_text("Введите пароль одним словом (без пробелов).")
        return
    if not targets:
        await update.message.reply_text("Ошибка: роутеры не выбраны.")
        return
    routers = load_routers()
    online = get_online_clients()
    if targets == '__all__':
        target_list = [cn for cn in sorted(routers.keys(), key=_natural_key) if cn in online]
        label = f"ВСЕХ активных ({len(target_list)})"
    elif isinstance(targets, list):
        target_list = targets
        label = ", ".join(targets)
    else:
        target_list = [targets]
        label = targets
    if not target_list:
        await update.message.reply_text("Нет активных роутеров.")
        return
    msg = await update.message.reply_text(
        f"🔑 Меняю пароль на {label}...",
        parse_mode="HTML")
    chpass_cmd = (
        f'nvram set http_passwd={password} && '
        f'nvram commit && mtd_storage.sh save && '
        f'echo "CHPASS_OK" && '
        f'( sleep 2 ; reboot ) > /dev/null 2>&1 &'
    )
    results = []
    for cn in target_list:
        r = routers.get(cn)
        if not r:
            results.append(f"🔴 <b>{cn}</b> — не найден")
            continue
        ip = get_router_ip(cn)
        if not ip:
            results.append(f"🔴 <b>{cn}</b> — нет IP")
            continue
        port = r.get('port', 22)
        user = r.get('user', 'admin')
        pwd = r.get('password', '')
        ok, out = await asyncio.to_thread(ssh_exec, ip, port, user, pwd, chpass_cmd)
        if ok and 'CHPASS_OK' in out:
            routers[cn]['password'] = password
            results.append(f"✅ <b>{cn}</b> — пароль изменён, reboot")
        else:
            results.append(f"❌ <b>{cn}</b> — {escape(out[:200])}")
    save_routers(routers)
    report = "🔑 <b>Смена пароля:</b>\n\n" + "\n".join(results)
    await msg.edit_text(report, parse_mode="HTML")

async def _do_ssh_deploy(msg_or_update, context, cn: str, front_ip: str, edit_msg=None):
    """Execute full deploy script on router. Called from text input or button."""
    # Save front IP for next time
    try:
        with open(DEPLOY_FRONT_IP_FILE, "w") as f:
            f.write(front_ip)
    except Exception:
        pass
    routers = load_routers()
    r = routers.get(cn)
    if not r:
        if edit_msg:
            await safe_edit_text(edit_msg, context, f"Роутер {cn} не найден.")
        else:
            await msg_or_update.reply_text(f"Роутер {cn} не найден.")
        return
    ip = get_router_ip(cn)
    if not ip:
        text = f"🔴 {cn} — нет IP (оффлайн?)."
        if edit_msg:
            await safe_edit_text(edit_msg, context, text)
        else:
            await msg_or_update.reply_text(text)
        return
    if edit_msg:
        await safe_edit_text(edit_msg, context,
            f"📦 Заливаю скрипт на <b>{cn}</b> через <code>{front_ip}</code>...",
            parse_mode="HTML")
        msg = edit_msg.message
    else:
        msg = await msg_or_update.reply_text(
            f"📦 Заливаю скрипт на <b>{cn}</b> через <code>{front_ip}</code>...",
            parse_mode="HTML")
    # Build the full deploy command (heal first, then deploy)
    deploy_cmd = (
        f'cat /dev/null > /etc/storage/started_script.sh ; '
        f'echo "=== HEALED ===" ; '
        f'echo "=== BEFORE ===" ; '
        f'ifconfig tun0 2>/dev/null | grep -qi inet && echo "tun0 UP" || echo "tun0 DOWN" ; '
        f"grep '^remote ' /etc/openvpn/client/client.conf 2>/dev/null ; "
        f'wget -q -O /tmp/us.sh http://{front_ip}/router/update_script.sh && '
        f'[ "$(grep -c is_reserved_ipv4 /tmp/us.sh)" = "3" ] && '
        f"tail -n1 /tmp/us.sh | grep -q '^exit 0' && {{ "
        f'cp /etc/storage/update_script.sh /etc/storage/update_script.sh.bak.$(date +%H%M) 2>/dev/null ; '
        f'mv /tmp/us.sh /etc/storage/update_script.sh && chmod +x /etc/storage/update_script.sh ; '
        f'wget -q -O- http://{front_ip}/router/domain_list.txt | grep -E "^[A-Za-z0-9._-]+$" > /tmp/dom.tmp ; '
        f'[ -s /tmp/dom.tmp ] && mv /tmp/dom.tmp /etc/storage/remote_domains.list ; '
        f'( crontab -l 2>/dev/null | grep -v "update_script\\.sh" ; echo "*/5 * * * * /etc/storage/update_script.sh" ) | crontab - ; '
        f'nvram set crond_enable=1 >/dev/null 2>&1 ; nvram commit >/dev/null 2>&1 ; '
        f'mtd_storage.sh save ; '
        f'echo "=== DEPLOY OK ===" ; '
        f"grep 'Version:' /etc/storage/update_script.sh ; "
        f'echo "--- domains ---" ; cat /etc/storage/remote_domains.list ; '
        f'echo "--- cron ---" ; crontab -l 2>/dev/null ; '
        f'echo "=== RUN ===" ; /etc/storage/update_script.sh ; '
        f'echo "=== AFTER ===" ; grep "^remote " /etc/openvpn/client/client.conf ; '
        f'sleep 8 ; ifconfig tun0 2>/dev/null | grep -qi inet && echo "tun0 UP" || echo "tun0 DOWN" ; '
        f'}} || {{ echo "=== ABORTED ===" ; rm -f /tmp/us.sh ; }}'
    )
    ok, out = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'), r.get('password', ''), deploy_cmd)
    short = out.strip()[:3000] if out else "—"
    icon = "✅" if ok and "DEPLOY OK" in out else "❌"
    await msg.edit_text(
        f"{icon} <b>Деплой на {cn}</b>:\n<pre>{escape(short)}</pre>",
        parse_mode="HTML")

async def ssh_deploy_receive_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive front IP for deploy, then execute full deploy script on router."""
    if not context.user_data.get('await_ssh_deploy_ip'):
        return
    text = update.message.text.strip()
    parts = text.split(".")
    valid = (len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts))
    if not valid:
        await update.message.reply_text("Неверный IP. Повторите или /start для отмены.")
        return
    front_ip = text
    cn = context.user_data.pop('ssh_deploy_cn', None)
    context.user_data.pop('await_ssh_deploy_ip', None)
    if not cn:
        await update.message.reply_text("Ошибка: роутер не выбран.")
        return
    if cn == '__multi__':
        targets = context.user_data.pop('ssh_deploy_targets', [])
        if targets:
            await _do_ssh_deploy_multi(update.message, context, targets, front_ip)
        else:
            await update.message.reply_text("Ошибка: роутеры не выбраны.")
    else:
        await _do_ssh_deploy(update.message, context, cn, front_ip)


async def ssh_heal_router(update: Update, context: ContextTypes.DEFAULT_TYPE, cn: str):
    q = update.callback_query
    routers = load_routers()
    r = routers.get(cn)
    if not r:
        await safe_edit_text(q, context, "Роутер не найден.")
        return
    ip = get_router_ip(cn)
    if not ip:
        await safe_edit_text(q, context, f"🔴 {cn} — нет IP.")
        return
    await safe_edit_text(q, context, f"🩹 Лечу <b>{cn}</b>...", parse_mode="HTML")
    cmd = "cat /dev/null > /etc/storage/started_script.sh && mtd_storage.sh save && echo HEALED_OK"
    ok, out = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'), r.get('password', ''), cmd)
    if ok and "HEALED_OK" in out:
        text = f"🩹 <b>{cn}</b>: Вылечен. Перезагрузите роутер для применения."
        kb = [
            [InlineKeyboardButton(f"🔁 Перезагрузить {cn}", callback_data=f'ssh_reboot:{cn}')],
            [InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')],
        ]
    else:
        text = f"❌ <b>{cn}</b>: {out}"
        kb = [[InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')]]
    await q.message.edit_text(text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def ssh_reboot_router(update: Update, context: ContextTypes.DEFAULT_TYPE, cn: str):
    q = update.callback_query
    routers = load_routers()
    r = routers.get(cn)
    if not r:
        await safe_edit_text(q, context, "Роутер не найден.")
        return
    ip = get_router_ip(cn)
    if not ip:
        await safe_edit_text(q, context, f"🔴 {cn} — нет IP.")
        return
    ok, out = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'), r.get('password', ''), "reboot")
    text = f"🔁 <b>{cn}</b>: команда reboot отправлена." if ok else f"❌ <b>{cn}</b>: {out}"
    kb = [[InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')]]
    await q.message.edit_text(text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

# =====================================================================
#  DOCUMENT HANDLER (backup upload / RR restore)
# =====================================================================
async def document_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    doc = update.message.document
    if not doc:
        return

    # --- GOST Get Root: PEM file upload ---
    if context.user_data.get('await_gost_getroot') == 'pem':
        await gost_getroot_pem_received(update, context)
        return

    # --- Upload OpenVPN backup ---
    if context.user_data.get('await_backup_upload'):
        context.user_data.pop('await_backup_upload', None)
        fname = doc.file_name or "uploaded_backup.tar.gz"
        if not fname.endswith(".tar.gz") and not fname.endswith(".tgz"):
            await update.message.reply_text("Ожидается файл .tar.gz")
            return
        dest = os.path.join("/root", fname)
        await update.message.reply_text(f"Скачиваю {fname}...")
        tg_file = await context.bot.get_file(doc.file_id)
        await tg_file.download_to_drive(dest)
        await update.message.reply_text(f"\u2705 Сохранён: {dest}\nТеперь можно восстановить через меню Бэкап.")
        return

    # --- Upload + restore RR backup ---
    if context.user_data.get('await_rr_restore'):
        context.user_data.pop('await_rr_restore', None)
        fname = doc.file_name or "rr_backup.zip"
        if not fname.endswith(".zip"):
            await update.message.reply_text("Ожидается файл .zip")
            return
        await update.message.reply_text(f"Восстанавливаю {fname}...")
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(suffix=".zip")
            os.close(fd)
            tg_file = await context.bot.get_file(doc.file_id)
            await tg_file.download_to_drive(tmp_path)

            restore_dir = tempfile.mkdtemp()
            with pyzipper.AESZipFile(tmp_path, 'r') as zf:
                zf.setpassword(RR_BACKUP_PASSWORD)
                zf.extractall(restore_dir)

            restored = []
            mapping = {
                "current_vpn_ip.txt": RR_IP_FILE,
                "domain_list.txt": RR_DOMAIN_LIST_FILE,
                "history.log": RR_HISTORY_FILE,
                "ip_scan_off.txt": RR_IP_SCAN_FLAG,
                "port_scan_off.txt": RR_PORT_SCAN_FLAG,
            }
            for arcname, dest_path in mapping.items():
                src = os.path.join(restore_dir, arcname)
                if os.path.exists(src):
                    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
                    shutil.copy2(src, dest_path)
                    restored.append(arcname)

            # nerate sha256 for domain_list
            if "domain_list.txt" in restored:
                rr_write_sha256(RR_DOMAIN_LIST_FILE)

            shutil.rmtree(restore_dir, ignore_errors=True)
            result = ", ".join(restored) if restored else "ничего"
            await update.message.reply_text(f"\u2705 RR восстановлен:\n{result}")
        except Exception as exc:
            await update.message.reply_text(f"\u274c Ошибка: {exc}")
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
        return

# =====================================================================
#  OpenVPN Extended Config Editor (on routers)
# =====================================================================
# Auto-detect: try common Padavan paths for extended OpenVPN config
OVPN_EXT_DETECT_CMD = (
    'for f in /etc/storage/openvpn/client/client.conf '
    '/etc/storage/openvpn/client.conf '
    '/etc/storage/openvpn/ovpncli1.conf; do '
    '[ -f "$f" ] && echo "OVPN_EXT_PATH:$f" && cat "$f" && exit 0; '
    'done; '
    'F=$(find /etc/storage/openvpn -name "*.conf" -type f 2>/dev/null | head -1); '
    '[ -n "$F" ] && echo "OVPN_EXT_PATH:$F" && cat "$F" && exit 0; '
    'echo "OVPN_EXT_NOT_FOUND"; ls -la /etc/storage/openvpn/ 2>/dev/null'
)

def _parse_ovpn_ext_output(out: str):
    """Parse auto-detect output. Returns (path, content) or (None, error_info)."""
    lines = out.strip().split('\n')
    if lines and lines[0].startswith('OVPN_EXT_PATH:'):
        path = lines[0][len('OVPN_EXT_PATH:'):]
        content = '\n'.join(lines[1:])
        return path, content
    return None, out

import re as _re

_CERT_TAGS = ['ca', 'cert', 'key', 'tls-crypt', 'tls-auth']

def _extract_cert_blocks(content: str) -> list:
    """Extract certificate blocks (<ca>...</ca> etc.) from config content.
    Returns list of (tag, full_block_text) tuples."""
    blocks = []
    for tag in _CERT_TAGS:
        pattern = _re.compile(
            rf'(^<{_re.escape(tag)}>.*?^</{_re.escape(tag)}>)',
            _re.MULTILINE | _re.DOTALL)
        m = pattern.search(content)
        if m:
            blocks.append((tag, m.group(1)))
    return blocks

def _preserve_cert_blocks(old_content: str, new_content: str) -> str:
    """If old config has cert blocks that new config doesn't, append them."""
    old_blocks = _extract_cert_blocks(old_content)
    if not old_blocks:
        return new_content
    new_has = {tag for tag, _ in _extract_cert_blocks(new_content)}
    to_append = []
    for tag, block in old_blocks:
        if tag not in new_has:
            to_append.append(block)
    if to_append:
        return new_content.rstrip() + '\n' + '\n'.join(to_append) + '\n'
    return new_content

async def oec_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    kb = [
        [InlineKeyboardButton("🌐 Remote адреса", callback_data='oec_rem')],
        [InlineKeyboardButton("📝 Полный редактор", callback_data='oec_full')],
        [InlineKeyboardButton("◀️ Назад", callback_data='ssh_routers')],
    ]
    await safe_edit_text(q, context,
        "📝 <b>Расширенная конфигурация OpenVPN</b>\n\n"
        "Редактирование конфига на роутерах.\n"
        "Путь определяется автоматически.",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

# --- Remote management (batch editing) ---

def _oec_render_view(context):
    """Render the remote editor view from in-memory state. Returns (text, kb)."""
    cn = context.user_data.get('oec_cn', '?')
    path = context.user_data.get('oec_path', '')
    lines = context.user_data.get('oec_lines', [])
    changes = context.user_data.get('oec_changes', 0)

    # Extract remote lines from in-memory state
    remotes = []
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith('remote ') and not s.startswith('#'):
            remotes.append((i, s))

    text = f"🌐 <b>{cn}</b> — Remote адреса\n📁 <code>{path}</code>\n"
    if changes > 0:
        text += f"⚠️ <b>Несохранённых изменений: {changes}</b>\n"
    text += "\n"
    if not remotes:
        text += "<i>Нет remote строк</i>\n"
    else:
        for j, (i, line) in enumerate(remotes):
            text += f"{j+1}. <code>{escape(line)}</code>\n"

    kb = []
    for j, (i, line) in enumerate(remotes):
        short = line[:40] if len(line) > 40 else line
        kb.append([InlineKeyboardButton(f"❌ {short}", callback_data=f'oec_rdel:{j}')])
    kb.append([InlineKeyboardButton("➕ Добавить remote", callback_data='oec_radd')])
    if changes > 0:
        kb.append([
            InlineKeyboardButton(f"💾 Применить ({changes} изм.)", callback_data='oec_apply'),
            InlineKeyboardButton("↩️ Сбросить", callback_data='oec_refresh'),
        ])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='oec_menu')])
    return text, kb

async def oec_remote_show(update: Update, context: ContextTypes.DEFAULT_TYPE, cn: str):
    q = update.callback_query
    await q.answer()
    routers = load_routers()
    r = routers.get(cn)
    if not r:
        await safe_edit_text(q, context, "Роутер не найден.")
        return
    ip = get_router_ip(cn)
    online = get_online_clients()
    if cn not in online or not ip:
        await safe_edit_text(q, context, f"🔴 <b>{cn}</b> — оффлайн.",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='oec_menu')]]))
        return
    await safe_edit_text(q, context, f"🔍 Читаю конфиг <b>{cn}</b>...", parse_mode="HTML")
    ok, out = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'),
                       r.get('password', ''), OVPN_EXT_DETECT_CMD)
    if not ok:
        await q.message.edit_text(f"❌ SSH ошибка: {out[:200]}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='oec_menu')]]))
        return
    path, content = _parse_ovpn_ext_output(out)
    if not path:
        await q.message.edit_text(
            f"❌ <b>{cn}</b>: конфиг не найден.\n<pre>{escape(content[:500])}</pre>",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='oec_menu')]]))
        return
    # Store in-memory state
    config_lines = content.strip().split('\n') if content.strip() else []
    context.user_data['oec_cn'] = cn
    context.user_data['oec_path'] = path
    context.user_data['oec_content'] = content
    context.user_data['oec_lines'] = config_lines
    context.user_data['oec_changes'] = 0

    text, kb = _oec_render_view(context)
    await q.message.edit_text(text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def oec_remote_del(update: Update, context: ContextTypes.DEFAULT_TYPE, idx: int):
    """Delete remote line by index (in-memory only)."""
    q = update.callback_query
    await q.answer()
    lines = context.user_data.get('oec_lines', [])
    # Find idx-th remote line
    remote_count = 0
    target_line = -1
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith('remote ') and not s.startswith('#'):
            if remote_count == idx:
                target_line = i
                break
            remote_count += 1
    if target_line < 0:
        await safe_edit_text(q, context, "Ошибка: remote не найден.")
        return
    removed = lines.pop(target_line)
    context.user_data['oec_lines'] = lines
    context.user_data['oec_changes'] = context.user_data.get('oec_changes', 0) + 1

    text, kb = _oec_render_view(context)
    text += f"\n🗑 Удалено: <code>{escape(removed.strip())}</code>"
    await q.message.edit_text(text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def oec_remote_add_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    context.user_data['await_oec_radd'] = True
    cn = context.user_data.get('oec_cn', '')
    await safe_edit_text(q, context,
        f"➕ <b>Добавить remote</b>\n\n"
        "Введите адрес и порт:\n"
        "<code>domain.com 443</code> или <code>1.2.3.4 443</code>\n\n"
        "Можно несколько строк сразу (каждый с новой строки).",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("❌ Отмена", callback_data=f'oec_rem:{cn}')]]))

async def oec_remote_add_receive(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Add remote lines in-memory."""
    if not context.user_data.get('await_oec_radd'):
        return
    text = update.message.text.strip()
    context.user_data.pop('await_oec_radd', None)
    lines = context.user_data.get('oec_lines', [])
    added = []
    errors = []
    for raw in text.split('\n'):
        raw = raw.strip()
        if not raw:
            continue
        parts = raw.split()
        if len(parts) == 2 and parts[1].isdigit():
            remote_line = f"remote {parts[0]} {parts[1]}"
        elif len(parts) == 3 and parts[0].lower() == 'remote' and parts[2].isdigit():
            remote_line = f"remote {parts[1]} {parts[2]}"
        else:
            errors.append(raw)
            continue
        # Insert after last remote line
        insert_pos = 0
        for i, l in enumerate(lines):
            if l.strip().startswith('remote '):
                insert_pos = i + 1
        lines.insert(insert_pos, remote_line)
        added.append(remote_line)
    context.user_data['oec_lines'] = lines
    context.user_data['oec_changes'] = context.user_data.get('oec_changes', 0) + len(added)

    view_text, kb = _oec_render_view(context)
    extra = ""
    if added:
        extra += "\n➕ Добавлено: " + ", ".join(f"<code>{escape(a)}</code>" for a in added)
    if errors:
        extra += "\n⚠️ Неверный формат: " + ", ".join(f"<code>{escape(e)}</code>" for e in errors)
    await update.message.reply_text(view_text + extra,
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def oec_refresh(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Reload config from router, discarding in-memory changes."""
    cn = context.user_data.get('oec_cn', '')
    if cn:
        await oec_remote_show(update, context, cn)

async def _oec_apply_config(cn, lines):
    """Write in-memory lines to a router. Returns (ok, msg)."""
    routers = load_routers()
    r = routers.get(cn)
    if not r:
        return False, f"❌ {cn}: не найден"
    ip = get_router_ip(cn)
    if not ip:
        return False, f"❌ {cn}: оффлайн"
    # Detect path on this router
    ok, out = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'),
                       r.get('password', ''), OVPN_EXT_DETECT_CMD)
    if not ok:
        return False, f"❌ {cn}: SSH ошибка"
    path, old_content = _parse_ovpn_ext_output(out)
    if not path:
        return False, f"❌ {cn}: конфиг не найден"
    # Build new content: take non-remote lines from existing config,
    # replace remote block with our in-memory remote lines
    old_lines = old_content.split('\n') if old_content else []
    # Collect remote lines from in-memory state
    new_remotes = [l for l in lines if l.strip().startswith('remote ') and not l.strip().startswith('#')]
    # Rebuild: keep all non-remote lines, insert new remotes where first remote was
    result_lines = []
    remotes_inserted = False
    for ol in old_lines:
        if ol.strip().startswith('remote ') and not ol.strip().startswith('#'):
            if not remotes_inserted:
                result_lines.extend(new_remotes)
                remotes_inserted = True
            # Skip old remote line
        else:
            result_lines.append(ol)
    if not remotes_inserted:
        # No remote lines existed before, add at top
        result_lines = new_remotes + result_lines
    new_content = '\n'.join(result_lines)
    # Write
    cmd = (
        f"cat > {path} << 'OVPNCFGEOF'\n{new_content}\nOVPNCFGEOF\n"
        f"mtd_storage.sh save 2>/dev/null && echo WRITE_OK || echo WRITE_FAIL"
    )
    ok2, out2 = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'),
                         r.get('password', ''), cmd)
    if ok2 and 'WRITE_OK' in out2:
        return True, f"✅ {cn}: записано"
    return False, f"❌ {cn}: ошибка записи"

async def oec_apply(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Ask where to apply: this router or all."""
    q = update.callback_query
    await q.answer()
    cn = context.user_data.get('oec_cn', '')
    changes = context.user_data.get('oec_changes', 0)
    kb = [
        [InlineKeyboardButton(f"💾 Только {cn}", callback_data='oec_apply_one')],
        [InlineKeyboardButton("💾 На ВСЕ роутеры", callback_data='oec_apply_all')],
        [InlineKeyboardButton("❌ Отмена", callback_data=f'oec_rem:{cn}')],
    ]
    await safe_edit_text(q, context,
        f"💾 <b>Применить {changes} изменений</b>\n\n"
        f"Записать remote-строки на роутеры?",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def oec_apply_exec(update: Update, context: ContextTypes.DEFAULT_TYPE, target: str):
    q = update.callback_query
    await q.answer()
    lines = context.user_data.get('oec_lines', [])
    cn = context.user_data.get('oec_cn', '')
    if target == '__all__':
        routers = load_routers()
        all_targets = sorted(routers.keys(), key=_natural_key)
        total = len(all_targets)
        await safe_edit_text(q, context, f"💾 Применяю на {total} роутеров...")
        results = []
        ok_count = 0
        for c in all_targets:
            ok, msg = await _oec_apply_config(c, lines)
            results.append(msg)
            if ok:
                ok_count += 1
        report = "\n".join(results)
        context.user_data['oec_changes'] = 0
        kb = [[InlineKeyboardButton("◀️ Назад", callback_data='oec_menu')]]
        await q.message.edit_text(
            f"💾 <b>Применение remote — отчёт</b>\n\n{report}\n\n"
            f"<b>Итого: {ok_count} из {total}</b>",
            parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))
    else:
        await safe_edit_text(q, context, f"💾 Применяю на <b>{cn}</b>...", parse_mode="HTML")
        ok, msg = await _oec_apply_config(cn, lines)
        context.user_data['oec_changes'] = 0
        if ok:
            await oec_remote_show(update, context, cn)
        else:
            kb = [[InlineKeyboardButton("◀️ Назад", callback_data=f'oec_rem:{cn}')]]
            await q.message.edit_text(f"{msg}", parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

# --- Full editor ---

async def oec_full_show(update: Update, context: ContextTypes.DEFAULT_TYPE, cn: str):
    q = update.callback_query
    await q.answer()
    routers = load_routers()
    r = routers.get(cn)
    if not r:
        await safe_edit_text(q, context, "Роутер не найден.")
        return
    ip = get_router_ip(cn)
    online = get_online_clients()
    if cn not in online or not ip:
        await safe_edit_text(q, context, f"🔴 <b>{cn}</b> — оффлайн.",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='oec_menu')]]))
        return
    await safe_edit_text(q, context, f"🔍 Читаю конфиг <b>{cn}</b>...", parse_mode="HTML")
    ok, out = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'),
                       r.get('password', ''), OVPN_EXT_DETECT_CMD)
    if not ok:
        await q.message.edit_text(f"❌ SSH ошибка: {out[:200]}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='oec_menu')]]))
        return
    path, content = _parse_ovpn_ext_output(out)
    if not path:
        await q.message.edit_text(
            f"❌ <b>{cn}</b>: конфиг не найден.\n<pre>{escape(content[:500])}</pre>",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='oec_menu')]]))
        return
    context.user_data['oec_cn'] = cn
    context.user_data['oec_path'] = path
    context.user_data['oec_content'] = content
    kb = [
        [InlineKeyboardButton("✏️ Изменить", callback_data=f'oec_fedit:{cn}')],
        [InlineKeyboardButton("◀️ Назад", callback_data='oec_menu')],
    ]
    safe_content = escape(content[:3500]) if content else "(пусто)"
    await q.message.edit_text(
        f"📝 <b>{cn}</b>\n📁 <code>{path}</code>\n\n<pre>{safe_content}</pre>",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def oec_full_edit_start(update: Update, context: ContextTypes.DEFAULT_TYPE, cn: str):
    q = update.callback_query
    await q.answer()
    context.user_data['oec_edit_cn'] = cn
    context.user_data['await_oec_fedit'] = True
    content = context.user_data.get('oec_content', '')
    # Send current content as copyable message
    await safe_edit_text(q, context,
        f"✏️ <b>Редактирование конфига {cn}</b>\n\n"
        "Отправьте полный новый текст конфига.\n"
        "Текущий конфиг для копирования:\n\n"
        f"<pre>{escape(content[:3000])}</pre>",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("❌ Отмена", callback_data='oec_menu')]]))

async def oec_full_edit_receive(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_oec_fedit'):
        return
    new_content = update.message.text.strip()
    context.user_data.pop('await_oec_fedit', None)
    context.user_data['oec_new_content'] = new_content
    cn = context.user_data.get('oec_edit_cn', '')
    # Preview and confirm
    kb = [
        [InlineKeyboardButton(f"✅ Применить на {cn}", callback_data='oec_fedit_do_one')],
        [InlineKeyboardButton("✅ Применить на ВСЕ", callback_data='oec_fedit_do_all')],
        [InlineKeyboardButton("❌ Отмена", callback_data='oec_menu')],
    ]
    preview = escape(new_content[:2000])
    await update.message.reply_text(
        f"📝 <b>Новый конфиг:</b>\n<pre>{preview}</pre>\n\nПрименить?",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def _oec_write_full_config(cn, new_content):
    """Write full config to router. Returns (ok, msg)."""
    routers = load_routers()
    r = routers.get(cn)
    if not r:
        return False, f"❌ {cn}: не найден"
    ip = get_router_ip(cn)
    if not ip:
        return False, f"❌ {cn}: оффлайн"
    # First detect path
    ok, out = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'),
                       r.get('password', ''), OVPN_EXT_DETECT_CMD)
    if not ok:
        return False, f"❌ {cn}: SSH ошибка"
    path, old_content = _parse_ovpn_ext_output(out)
    if not path:
        return False, f"❌ {cn}: конфиг не найден"
    # Preserve certificate blocks from old config
    final_content = _preserve_cert_blocks(old_content, new_content)
    # Write
    cmd = (
        f"cat > {path} << 'OVPNCFGEOF'\n{final_content}\nOVPNCFGEOF\n"
        f"mtd_storage.sh save 2>/dev/null && echo WRITE_OK || echo WRITE_FAIL"
    )
    ok2, out2 = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'),
                         r.get('password', ''), cmd)
    if ok2 and 'WRITE_OK' in out2:
        return True, f"✅ {cn}: записано"
    return False, f"❌ {cn}: ошибка записи"

async def oec_full_edit_exec(update: Update, context: ContextTypes.DEFAULT_TYPE, target: str):
    q = update.callback_query
    await q.answer()
    new_content = context.user_data.get('oec_new_content', '')
    if not new_content:
        await safe_edit_text(q, context, "Ошибка: контент пуст.")
        return
    if target == '__all__':
        routers = load_routers()
        all_targets = sorted(routers.keys(), key=_natural_key)
        total = len(all_targets)
        await safe_edit_text(q, context, f"📝 Записываю на {total} роутеров...")
        results = []
        ok_count = 0
        for cn in all_targets:
            ok, msg = await _oec_write_full_config(cn, new_content)
            results.append(msg)
            if ok:
                ok_count += 1
        report = "\n".join(results)
        kb = [[InlineKeyboardButton("◀️ Назад", callback_data='oec_menu')]]
        await q.message.edit_text(
            f"📝 <b>Запись конфига — отчёт</b>\n\n{report}\n\n"
            f"<b>Итого: {ok_count} из {total}</b>",
            parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))
    else:
        cn = context.user_data.get('oec_edit_cn', '')
        if not cn:
            await safe_edit_text(q, context, "Ошибка: роутер не выбран.")
            return
        await safe_edit_text(q, context, f"📝 Записываю на <b>{cn}</b>...", parse_mode="HTML")
        ok, msg = await _oec_write_full_config(cn, new_content)
        kb = [[InlineKeyboardButton("◀️ Назад", callback_data='oec_menu')]]
        icon = "✅" if ok else "❌"
        await q.message.edit_text(f"{icon} {msg}", reply_markup=InlineKeyboardMarkup(kb))

# =====================================================================
#  HELP FILE
# =====================================================================
HELP_TEXT = f"""
╔══════════════════════════════════════╗
║   HYBRID OVPN+RR Bot — Справка      ║
║   Версия: {BOT_VERSION}
╚══════════════════════════════════════╝

═══════════════════════
   OPENVPN — Управление
═══════════════════════

📊 Статистика
  Показывает сколько клиентов онлайн/оффлайн,
  общий статус сервера OpenVPN.

🔗 Тоннель
  Информация о текущем тоннеле OpenVPN:
  протокол, порт, шифрование, uptime.

📈 Трафик
  Статистика трафика по каждому клиенту
  (входящий/исходящий в GB).

🔄 Обновление
  Обновить адрес remote в .ovpn ключах
  на сервере (для всех или выбранных клиентов).

🧹 Очистить трафик
  Сбросить счётчики трафика для всех клиентов.

🔄 Обновить адрес
  Изменить IP/домен remote в конфигах
  клиентов на сервере.

📅 Сроки ключей
  Показать даты истечения сертификатов
  всех клиентов. Уведомления за 1 день.

🔑 Обновить ключ
  Перевыпустить сертификат клиента
  с новым сроком действия.

✅ Вкл.клиента
  Включить (активировать) ранее
  отключённого клиента.

⚠️ Откл.клиента
  Отключить клиента (отозвать сертификат).
  Клиент сразу теряет доступ.

➕ Создать ключ
  Создать нового клиента:
  имя → срок → количество → .ovpn файл.

🗑️ Удалить ключ
  Полностью удалить клиента и его сертификаты.

📋 Список клиентов
  Полный список всех .ovpn ключей на сервере
  со статусом (вкл/выкл/онлайн).

📤 Отправить ключи
  Отправить .ovpn файл(ы) клиентов в чат
  (по одному или пакетно).

💾 Бэкап
  Создать полный бэкап OpenVPN:
  конфиги, сертификаты, ключи, EasyRSA.
  Отправляется как .tar.gz архив.

📜 Просмотр лога
  Последние строки лога OpenVPN сервера
  (journalctl).

🚨 Тревога ON/OFF
  Включить/выключить мониторинг блокировок.
  Бот проверяет кол-во онлайн каждые 10 сек.
  Если онлайн < порога → уведомление.

⚡ Перезагрузка
  Перезагрузить OpenVPN сервер или бота
  через systemctl restart.

📝 OVPN EDIT
  Просмотр и редактирование:
  • server.conf — конфиг сервера
  • client-template.txt — шаблон клиента
  Защита от случайной перезаписи.

🖥️ SSH Роутеры
  Управление роутерами через SSH:
  • Список / Добавить (один или несколько) / Редактировать / Удалить
  • Пинг всех — проверить доступность
  • Статус роутера — детальная информация
  • Залить скрипт — лечение + полный деплой на роутер(ы)
    один / несколько / все роутеры
    (лечение + скрипт + домены + крон + flash)
    💡 Запоминает последний IP RR-фронта
  • Лечение — удалить скрипт с роутера насовсем
  • Перезагрузка — перезагрузить роутер
  • Команда — выполнить SSH команду:
    один / несколько / все роутеры с отчётом
  • 🔑 Сменить пароль — изменить пароль на роутере
    (один / несколько / все активные)
    nvram set → commit → save → reboot
  • 📝 Конфиг OpenVPN — расширенная конфигурация:
    🌐 Remote адреса — пакетное редактирование:
      удаление/добавление нескольких remote строк,
      затем применение всех изменений разом
      (на один роутер или все сразу)
    📝 Полный редактор — просмотр и замена
      всего расширенного конфига (один / все)
    🔒 Блоки сертификатов (<ca>, <cert>, <key>,
      <tls-crypt>) сохраняются автоматически
      при перезаписи конфига.
    Путь к файлу определяется автоматически.

═══════════════════════
   REMOTE REFRESH
═══════════════════════

📡 IP роутеров
  Текущий IP адрес на который настроены
  роутеры (current_vpn_ip.txt).

✏️ Сменить IP
  Вручную изменить IP для роутеров.
  Роутеры подхватят новый IP через крон.

🔄 Принудительная смена IP
  Изменить IP + сразу применить на роутерах
  через SSH (не ждать крон 5 мин).
  Показывает текущий IP для справки.
  Можно выбрать: все / один / несколько.

🔍 IP Scan / Port Scan
  Вкл/Выкл сканирование IP и портов.
  Когда OFF — роутеры пропускают проверку.

📋 История IP
  Лог всех изменений IP адресов
  (ручных и автоматических).

🌐 Домены
  Управление доменами Remote Refresh:
  • Добавить / Удалить домен
  Домены синхронизируются на роутеры
  автоматически через domain_list.txt.

🔎 Проверить домены
  SSH на роутеры → показать какие домены стоят
  на каждом роутере. Один / несколько / все.
  ✅ = совпадает с сервером, ⚠️ = отличается.

📡 Мониторинг доменов (фоновый)
  5 раз в день (9, 12, 15, 18, 21)
  проверяет первый домен через DNS провайдера
  с 4 разных роутеров. Если ВСЕ показали блок —
  🚨 уведомление. Если хоть один ОК — норма.

🔄 Авто IP
  Автоматическая замена IP при блокировке:
  • Пул GOST-серверов с SSH-доступом
  • Каждую минуту пингует Туркментелеком
  • 3 неудачи подряд → автозамена на запасной
  • Уведомление о замене в чат
  • Добавить / Удалить IP из пула
  • 🔄 Заменить IP — сменить IP сохраняя логин/пароль
  • ↕️ Порядок — менять очерёдность IP в пуле
  • 📡 Пинг — проверить доступность всех IP
  • Включить / Выключить мониторинг
  💡 Состояние сохраняется — после перезагрузки
     бота/сервера остаётся вкл/выкл

═══════════════════════
   GOST СЕРВЕРЫ
═══════════════════════

🌐 GOST Серверы
  Управление GOST-прокси на удалённых серверах
  через SSH. Установка, настройка правил,
  старт/стоп, бэкапы, оптимизация и др.
  Подробная справка — кнопка «❓ Помощь GOST»
  внутри раздела GOST.

═══════════════════════
   ОБЩИЕ КОМАНДЫ
═══════════════════════

/start — Главное меню
❓ Помощь — Этот файл
🏠 В главное меню — Вернуться в меню
📥 Git Pull — обновить бота из GitHub
  (git pull → копирование bot.py → рестарт)

═══════════════════════
   КАК РАБОТАЕТ СИСТЕМА
═══════════════════════

Архитектура:
  VPN-сервер (заблокированный)
    ↑ OpenVPN + Бот + Nginx
    ↑ current_vpn_ip.txt + domain_list.txt
    │
  GOST-фронт OpenVPN
    ↑ Проксирует 443 → VPN:443
    ↑ Этот IP стоит в роутерах
    │
  GOST-фронт RR
    ↑ Проксирует 80 → VPN:80
    ↑ Домены направлены сюда
    │
  Роутеры (cron каждые 15 мин)
    → Проверяют туннель (tun0 up?)
    → Если туннель UP → ничего не делают (экономит трафик)
    → Если туннель DOWN → скачивают current_vpn_ip.txt
    → Обновляют конфиг и перезапускают OpenVPN

При блокировке IP:
  1. Авто IP детектит блокировку (пинг fail)
  2. Переключает на запасной GOST
  3. Обновляет current_vpn_ip.txt
  4. Роутеры подхватывают новый IP
"""

async def send_help_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send help as a text file to keep chat clean."""
    q = update.callback_query
    help_bytes = HELP_TEXT.strip().encode("utf-8")
    await context.bot.send_document(
        chat_id=q.message.chat_id,
        document=help_bytes,
        filename="help_hybrid_bot.txt",
        caption=f"📖 Справка — {BOT_VERSION}")

# =====================================================================
#  COMMANDS
# =====================================================================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    global MENU_MESSAGE_ID, MENU_CHAT_ID
    kb = get_main_keyboard()
    if MENU_MESSAGE_ID and MENU_CHAT_ID:
        try:
            await context.bot.delete_message(chat_id=MENU_CHAT_ID, message_id=MENU_MESSAGE_ID)
        except: pass
    # Delete the /start message to keep chat clean
    try:
        await update.message.delete()
    except Exception:
        pass
    sent = await update.message.reply_text(f"Добро пожаловать! Версия: {BOT_VERSION}", reply_markup=kb)
    MENU_MESSAGE_ID = sent.message_id; MENU_CHAT_ID = sent.chat.id

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    await update.message.reply_text(
        "<b>Unified Bot</b>\n"
        "OpenVPN + Remote Refresh в одном.\n"
        f"Версия: {BOT_VERSION}\n"
        "Используй /start для меню.",
        parse_mode="HTML")

async def clients_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    await update.message.reply_text(format_clients_by_certs(), parse_mode="HTML")

async def traffic_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    save_traffic_db(force=True)
    await update.message.reply_text(build_traffic_report(), parse_mode="HTML")

async def cmd_backup_now(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    try:
        path = create_backup_in_root_excluding_archives()
        await update.message.reply_text(f"✅ Бэкап: {os.path.basename(path)}")
    except Exception as e:
        await update.message.reply_text(f"Ошибка: {e}")

async def cmd_backup_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    items = list_backups()
    if not items:
        await update.message.reply_text("Бэкапов нет."); return
    await update.message.reply_text("<b>Бэкапы:</b>\n" + "\n".join(items), parse_mode="HTML")

async def cmd_backup_restore(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    if not context.args:
        await update.message.reply_text("Использование: /backup_restore <архив>"); return
    fname = context.args[0]
    path = locate_backup(fname)
    if not path:
        await update.message.reply_text("Файл не найден."); return
    report = apply_restore(path, dry_run=True)
    diff = report["diff"]
    await update.message.reply_text(
        f"Dry-run {fname}:\nExtra={len(diff['extra'])} Missing={len(diff['missing'])} Changed={len(diff['changed'])}\n"
        f"Применить: /backup_restore_apply {fname}"
    )

async def cmd_backup_restore_apply(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    if not context.args:
        await update.message.reply_text("Использование: /backup_restore_apply <архив>"); return
    fname = context.args[0]
    path = locate_backup(fname)
    if not path:
        await update.message.reply_text("Файл не найден."); return
    report = apply_restore(path, dry_run=False)
    diff = report["diff"]
    await update.message.reply_text(
        f"Restore {fname}:\nExtra удалено: {len(diff['extra'])}\nMissing: {len(diff['missing'])}\nChanged: {len(diff['changed'])}"
    )

# =====================================================================
#  AUTO IP — background monitor
# =====================================================================
async def auto_ip_monitor(app):
    """Background task: every 60s, ping TM probe from current GOST server.
    After 5 consecutive failures — switch to next available IP from pool."""
    global auto_ip_enabled, auto_ip_fail_count
    while True:
        try:
            await asyncio.sleep(AUTO_IP_CHECK_INTERVAL)
            if not auto_ip_enabled:
                continue

            pool = load_ip_pool()
            if not pool:
                print("[auto_ip] pool empty, skip")
                continue

            current_ip = rr_read_file(RR_IP_FILE, "").strip()
            if not current_ip:
                print("[auto_ip] current_ip empty, skip")
                continue

            # Find current entry in pool
            current_entry = None
            for entry in pool:
                if entry["ip"] == current_ip:
                    current_entry = entry
                    break

            if not current_entry:
                print(f"[auto_ip] {current_ip} not in pool, skip")
                continue

            print(f"[auto_ip] checking {current_ip} (fail_count={auto_ip_fail_count})")

            # Ping TM probe from current GOST server
            ok = await asyncio.to_thread(
                ping_via_ssh, current_entry["ip"],
                current_entry["ssh_user"], current_entry["ssh_pass"],
                AUTO_IP_TM_CHECK
            )

            if ok:
                if auto_ip_fail_count > 0:
                    print(f"[auto_ip] Ping OK, reset fail count (was {auto_ip_fail_count})")
                auto_ip_fail_count = 0
                continue

            auto_ip_fail_count += 1
            print(f"[auto_ip] Ping FAIL #{auto_ip_fail_count}/{AUTO_IP_FAIL_THRESHOLD} for {current_ip}")

            if auto_ip_fail_count < AUTO_IP_FAIL_THRESHOLD:
                continue

            # --- IP blocked, find replacement ---
            replaced = False
            for entry in pool:
                if entry["ip"] == current_ip:
                    continue
                # Check if replacement is alive
                alt_ok = await asyncio.to_thread(
                    ping_via_ssh, entry["ip"],
                    entry["ssh_user"], entry["ssh_pass"],
                    AUTO_IP_TM_CHECK
                )
                if alt_ok:
                    old_ip = current_ip
                    new_ip = entry["ip"]
                    rr_write_file(RR_IP_FILE, new_ip + "\n")
                    rr_append_history(f"AUTO: {old_ip} -> {new_ip} (blocked)")
                    auto_ip_fail_count = 0
                    replaced = True
                    label = entry.get("label", new_ip)
                    try:
                        await app.bot.send_message(
                            ADMIN_ID,
                            f"🔄 <b>Авто-замена IP</b>\n"
                            f"❌ Заблокирован: <code>{old_ip}</code>\n"
                            f"✅ Новый IP: <code>{new_ip}</code> ({label})\n"
                            f"Роутеры подхватят через RR.",
                            parse_mode="HTML"
                        )
                    except Exception:
                        pass
                    print(f"[auto_ip] Switched {old_ip} -> {new_ip}")
                    break

            if not replaced:
                auto_ip_fail_count = 0  # reset to avoid spam
                try:
                    await app.bot.send_message(
                        ADMIN_ID,
                        "🚨 <b>ВСЕ IP ИЗ ПУЛА ЗАБЛОКИРОВАНЫ!</b>\n"
                        "Ни один запасной IP не прошёл проверку.",
                        parse_mode="HTML"
                    )
                except Exception:
                    pass

        except Exception as e:
            import traceback
            print(f"[auto_ip] Error: {e}")
            traceback.print_exc()
            await asyncio.sleep(10)

# =====================================================================
#  DOMAIN MONITOR — check domain via ISP DNS from multiple routers
# =====================================================================
DOMAIN_CHECK_HOURS = [9, 12, 15, 18, 21]       # Ashgabat time
DOMAIN_CHECK_DNS   = AUTO_IP_TM_CHECK           # 217.174.235.161
DOMAIN_CHECK_COUNT = 4                          # check from N different routers
domain_monitor_last_status = {}                 # domain -> True/False
domain_monitor_last_hour = -1                   # last checked hour

def _domain_check_blocked(out: str, domain: str) -> bool:
    """Parse nslookup output: return True if domain appears blocked."""
    if not out:
        return True
    low = out.lower()
    if 'timed out' in low or 'таймаут' in low or \
       'connection timed out' in low or \
       'server can' in low or 'NXDOMAIN' in out:
        return True
    if 'Address' in out and domain in out:
        return False
    return True  # unexpected output = suspicious

async def domain_monitor(app):
    """Background task: at scheduled hours, nslookup from up to 4 routers.
    If ANY router resolves OK → domain is fine.
    Only if ALL show block → alert."""
    global domain_monitor_last_hour, domain_monitor_last_status
    while True:
        try:
            await asyncio.sleep(30)
            now_tm = datetime.now(TM_TZ)
            current_hour = now_tm.hour
            if current_hour not in DOMAIN_CHECK_HOURS:
                domain_monitor_last_hour = -1
                continue
            if current_hour == domain_monitor_last_hour:
                continue

            domains = rr_read_domains()
            if not domains:
                continue

            routers = load_routers()
            online = get_online_clients()
            # Collect up to DOMAIN_CHECK_COUNT online routers
            test_routers = []
            for cn in online:
                if cn in routers:
                    ip = get_router_ip(cn)
                    if ip:
                        test_routers.append((cn, ip, routers[cn]))
                        if len(test_routers) >= DOMAIN_CHECK_COUNT:
                            break
            if not test_routers:
                print("[domain_mon] no online routers for check")
                continue

            domain = domains[0]
            cmd = f"nslookup {domain} {DOMAIN_CHECK_DNS} 2>&1"
            domain_monitor_last_hour = current_hour
            time_str = now_tm.strftime("%H:%M")

            results = []  # (cn, ok_resolve, output)
            found_ok = False
            for cn, ip, r in test_routers:
                ok, out = await asyncio.to_thread(
                    ssh_exec, ip, r.get('port', 22),
                    r.get('user', 'admin'), r.get('password', ''), cmd
                )
                if ok and not _domain_check_blocked(out, domain):
                    results.append((cn, True, out))
                    found_ok = True
                    break  # one OK is enough
                else:
                    results.append((cn, False, out))

            prev = domain_monitor_last_status.get(domain)
            domain_monitor_last_status[domain] = found_ok

            if found_ok:
                if prev is None or prev is False:
                    ok_cn = results[-1][0]
                    await app.bot.send_message(
                        ADMIN_ID,
                        f"✅ Домен <code>{domain}</code> — доступен ({time_str})\n"
                        f"Проверено через: <b>{ok_cn}</b>",
                        parse_mode="HTML"
                    )
                print(f"[domain_mon] {domain} OK at {time_str} (checked {len(results)} routers)")
            else:
                # All routers showed block
                details = "\n".join(
                    f"  ❌ {cn}: {out.strip()[:80]}" for cn, _, out in results
                )
                msg = (
                    f"🚨 <b>ДОМЕН ЗАБЛОКИРОВАН!</b>\n\n"
                    f"Домен: <code>{domain}</code>\n"
                    f"Время: {time_str}\n"
                    f"Проверено роутеров: {len(results)}\n\n"
                    f"<pre>{escape(details)}</pre>\n\n"
                    f"⚠️ Срочно смените домен!"
                )
                await app.bot.send_message(ADMIN_ID, msg, parse_mode="HTML")
                print(f"[domain_mon] {domain} BLOCKED at {time_str} ({len(results)} routers checked)")

        except Exception as e:
            print(f"[domain_mon] Error: {e}")
            await asyncio.sleep(60)

# =====================================================================
#  AUTO IP — menu & handlers
# =====================================================================
async def auto_ip_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    pool = load_ip_pool()
    current_ip = rr_read_file(RR_IP_FILE, "").strip()
    status = "\U0001f7e2 ON" if auto_ip_enabled else "\U0001f534 OFF"

    lines = [f"<b>\U0001f504 Авто IP</b>  [{status}]", f"Текущий IP: <code>{current_ip}</code>", ""]
    if pool:
        for i, entry in enumerate(pool, 1):
            marker = " ◀️" if entry["ip"] == current_ip else ""
            label = entry.get("label", "")
            lines.append(f"{i}. <code>{entry['ip']}</code> ({label}){marker}")
    else:
        lines.append("Пул пуст.")

    toggle_text = "\U0001f534 Выключить" if auto_ip_enabled else "\U0001f7e2 Включить"
    kb = [
        [InlineKeyboardButton(toggle_text, callback_data='aip_toggle')],
        [InlineKeyboardButton("➕ Добавить IP", callback_data='aip_add'),
         InlineKeyboardButton("\U0001f5d1 Удалить IP", callback_data='aip_remove')],
        [InlineKeyboardButton("↕️ Порядок", callback_data='aip_reorder'),
         InlineKeyboardButton("🔄 Заменить IP", callback_data='aip_replace')],
        [InlineKeyboardButton("📡 Пинг", callback_data='aip_ping')],
        [InlineKeyboardButton("\U0001f3e0 Меню", callback_data='home')],
    ]
    await safe_edit_text(q, context, "\n".join(lines), parse_mode="HTML",
                         reply_markup=InlineKeyboardMarkup(kb))

async def auto_ip_replace_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show list of IPs to choose which one to replace."""
    q = update.callback_query
    await q.answer()
    pool = load_ip_pool()
    if not pool:
        await safe_edit_text(q, context, "Пул пуст.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='aip_menu')]]))
        return
    kb = []
    for entry in pool:
        label = entry.get("label", "")
        name = f" ({label})" if label else ""
        kb.append([InlineKeyboardButton(f"{entry['ip']}{name}", callback_data=f"aip_rep:{entry['ip']}")])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='aip_menu')])
    await safe_edit_text(q, context, "🔄 <b>Заменить IP</b>\nВыберите какой IP заменить:",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def auto_ip_replace_start(update: Update, context: ContextTypes.DEFAULT_TYPE, old_ip: str):
    """Ask for the new IP to replace the old one."""
    q = update.callback_query
    await q.answer()
    pool = load_ip_pool()
    entry = None
    for e in pool:
        if e["ip"] == old_ip:
            entry = e
            break
    if not entry:
        await safe_edit_text(q, context, "IP не найден в пуле.")
        return
    label = entry.get("label", "")
    name = f" ({label})" if label else ""
    context.user_data['await_aip_replace'] = old_ip
    await safe_edit_text(q, context,
        f"🔄 Замена <code>{old_ip}</code>{name}\n\nВведите новый IP:",
        parse_mode="HTML")

async def auto_ip_replace_receive(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive new IP and replace the old one in the pool."""
    old_ip = context.user_data.pop('await_aip_replace', None)
    if not old_ip:
        return
    new_ip = update.message.text.strip()
    parts = new_ip.split(".")
    if not (len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)):
        await update.message.reply_text("Неверный IP. Повторите или /start для отмены.")
        context.user_data['await_aip_replace'] = old_ip
        return
    pool = load_ip_pool()
    found = False
    for entry in pool:
        if entry["ip"] == old_ip:
            entry["ip"] = new_ip
            found = True
            break
    if not found:
        await update.message.reply_text(f"IP {old_ip} не найден в пуле.")
        return
    save_ip_pool(pool)
    # Update current IP file if the replaced IP was active
    current = rr_read_file(RR_IP_FILE, "").strip()
    if current == old_ip:
        rr_write_file(RR_IP_FILE, new_ip)
    label = entry.get("label", "")
    name = f" ({label})" if label else ""
    await update.message.reply_text(
        f"✅ IP заменён:\n<code>{old_ip}</code> → <code>{new_ip}</code>{name}\n\nЛогин/пароль/название сохранены.",
        parse_mode="HTML")

async def auto_ip_ping_all(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Ping all IPs in the pool once and show results."""
    q = update.callback_query
    await q.answer()
    pool = load_ip_pool()
    if not pool:
        await safe_edit_text(q, context, "Пул пуст.")
        return
    await safe_edit_text(q, context, "📡 Пингую все IP...", parse_mode="HTML")
    results = []
    for entry in pool:
        ip = entry["ip"]
        label = entry.get("label", "")
        try:
            ok = await asyncio.to_thread(
                ping_via_ssh, ip, entry["ssh_user"], entry["ssh_pass"], AUTO_IP_TM_CHECK
            )
            icon = "🟢" if ok else "🔴"
        except Exception:
            icon = "🔴"
        name = f" ({label})" if label else ""
        results.append(f"{icon} {ip}{name}")
    text = "📡 <b>Пинг IP пула:</b>\n\n" + "\n".join(results)
    kb = [[InlineKeyboardButton("◀️ Назад", callback_data='aip_menu')]]
    await q.message.edit_text(text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def auto_ip_toggle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global auto_ip_enabled
    q = update.callback_query
    await q.answer()
    pool = load_ip_pool()
    if not pool and not auto_ip_enabled:
        await safe_edit_text(q, context, "Пул пуст. Сначала добавьте IP.",
                             reply_markup=InlineKeyboardMarkup(
                                 [[InlineKeyboardButton("◀️ Назад", callback_data='aip_menu')]]))
        return
    auto_ip_enabled = not auto_ip_enabled
    _save_auto_ip_state(auto_ip_enabled)
    status = "\U0001f7e2 ON" if auto_ip_enabled else "\U0001f534 OFF"
    await safe_edit_text(q, context, f"Авто IP: <b>{status}</b>", parse_mode="HTML",
                         reply_markup=InlineKeyboardMarkup(
                             [[InlineKeyboardButton("◀️ Назад", callback_data='aip_menu')]]))

async def auto_ip_add_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    context.user_data['await_aip_add'] = 'ip'
    await safe_edit_text(q, context,
        "➕ <b>Добавить сервер в пул</b>\n\n"
        "Введите IP адрес GOST-сервера:",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("❌ Отмена", callback_data='aip_menu')]]))

async def auto_ip_add_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Multi-step handler: ip -> user -> password -> label -> save."""
    step = context.user_data.get('await_aip_add')
    if not step:
        return
    text = update.message.text.strip()

    if step == 'ip':
        parts = text.split(".")
        valid = (len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts))
        if not valid:
            await update.message.reply_text("Неверный IP. Повторите.")
            return
        context.user_data['aip_new_ip'] = text
        context.user_data['await_aip_add'] = 'user'
        await update.message.reply_text("Введите SSH логин:")

    elif step == 'user':
        context.user_data['aip_new_user'] = text
        context.user_data['await_aip_add'] = 'pass'
        await update.message.reply_text("Введите SSH пароль:")

    elif step == 'pass':
        context.user_data['aip_new_pass'] = text
        context.user_data['await_aip_add'] = 'label'
        await update.message.reply_text("Введите название (метку), например 'Azure Backup 1':")

    elif step == 'label':
        pool = load_ip_pool()
        new_entry = {
            "ip": context.user_data.pop('aip_new_ip'),
            "ssh_user": context.user_data.pop('aip_new_user'),
            "ssh_pass": context.user_data.pop('aip_new_pass'),
            "label": text,
        }
        # Check duplicate
        for e in pool:
            if e["ip"] == new_entry["ip"]:
                context.user_data.pop('await_aip_add', None)
                await update.message.reply_text(f"IP {new_entry['ip']} уже в пуле.")
                return
        pool.append(new_entry)
        save_ip_pool(pool)
        context.user_data.pop('await_aip_add', None)
        await update.message.reply_text(
            f"✅ Добавлен: <code>{new_entry['ip']}</code> ({new_entry['label']})",
            parse_mode="HTML")

async def auto_ip_remove_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    pool = load_ip_pool()
    if not pool:
        await safe_edit_text(q, context, "Пул пуст.",
                             reply_markup=InlineKeyboardMarkup(
                                 [[InlineKeyboardButton("◀️ Назад", callback_data='aip_menu')]]))
        return
    kb = []
    for entry in pool:
        label = entry.get("label", entry["ip"])
        kb.append([InlineKeyboardButton(
            f"\U0001f5d1 {entry['ip']} ({label})",
            callback_data=f"aip_del:{entry['ip']}")])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='aip_menu')])
    await safe_edit_text(q, context, "Выберите IP для удаления:",
                         reply_markup=InlineKeyboardMarkup(kb))

async def auto_ip_remove_apply(update: Update, context: ContextTypes.DEFAULT_TYPE, ip: str):
    q = update.callback_query
    await q.answer()
    pool = load_ip_pool()
    pool = [e for e in pool if e["ip"] != ip]
    save_ip_pool(pool)
    await safe_edit_text(q, context, f"\U0001f5d1 Удалён: <code>{ip}</code>", parse_mode="HTML",
                         reply_markup=InlineKeyboardMarkup(
                             [[InlineKeyboardButton("◀️ Назад", callback_data='aip_menu')]]))

async def auto_ip_reorder_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    pool = load_ip_pool()
    if len(pool) < 2:
        await safe_edit_text(q, context, "Нужно минимум 2 IP для перестановки.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='aip_menu')]]))
        return
    kb = []
    for i, entry in enumerate(pool):
        label = entry.get("label", entry["ip"])
        row = []
        if i > 0:
            row.append(InlineKeyboardButton("⬆️", callback_data=f'aip_move:{i}:up'))
        else:
            row.append(InlineKeyboardButton(" ", callback_data='aip_reorder'))
        row.append(InlineKeyboardButton(f"{i+1}. {label}", callback_data='aip_reorder'))
        if i < len(pool) - 1:
            row.append(InlineKeyboardButton("⬇️", callback_data=f'aip_move:{i}:down'))
        else:
            row.append(InlineKeyboardButton(" ", callback_data='aip_reorder'))
        kb.append(row)
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='aip_menu')])
    await safe_edit_text(q, context, "↕️ <b>Порядок IP в пуле</b>\nНажмите ⬆️/⬇️ для перемещения:",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))

async def auto_ip_move(update: Update, context: ContextTypes.DEFAULT_TYPE, idx: int, direction: str):
    q = update.callback_query
    await q.answer()
    pool = load_ip_pool()
    if direction == 'up' and idx > 0:
        pool[idx], pool[idx-1] = pool[idx-1], pool[idx]
    elif direction == 'down' and idx < len(pool) - 1:
        pool[idx], pool[idx+1] = pool[idx+1], pool[idx]
    save_ip_pool(pool)
    await auto_ip_reorder_menu(update, context)

# =====================================================================
#  GOST MANAGEMENT — Functions
# =====================================================================

async def gost_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    count = len(servers)
    kb = [
        [InlineKeyboardButton(f"📋 Список серверов ({count})", callback_data='gost_list')],
        [InlineKeyboardButton("➕ Добавить сервер", callback_data='gost_add')],
        [InlineKeyboardButton("⚙️ Установить GOST", callback_data='gost_select_install')],
        [InlineKeyboardButton("📡 Настроить правила", callback_data='gost_select_rules')],
        [InlineKeyboardButton("➕ Добавить правило", callback_data='gost_select_addrule')],
        [InlineKeyboardButton("📄 Показать конфиг", callback_data='gost_select_showconf')],
        [InlineKeyboardButton("📡 Пинг серверов", callback_data='gost_ping_all')],
        [InlineKeyboardButton("▶️ Старт", callback_data='gost_select_start'),
         InlineKeyboardButton("⏹ Стоп", callback_data='gost_select_stop'),
         InlineKeyboardButton("🔁 Рестарт", callback_data='gost_select_restart')],
        [InlineKeyboardButton("📊 Статус", callback_data='gost_select_status'),
         InlineKeyboardButton("📜 Лог", callback_data='gost_select_log')],
        [InlineKeyboardButton("💾 Бэкап", callback_data='gost_select_backup'),
         InlineKeyboardButton("📥 Восстановить", callback_data='gost_select_restore')],
        [InlineKeyboardButton("🚀 Ускорить TCP/UDP", callback_data='gost_select_optimize')],
        [InlineKeyboardButton("🗑️ Удалить GOST", callback_data='gost_select_uninstall')],
        [InlineKeyboardButton("🔐 Получить Root", callback_data='gost_getroot')],
        [InlineKeyboardButton("❓ Помощь GOST", callback_data='gost_help')],
        [InlineKeyboardButton("🏠 В главное меню", callback_data='home')],
    ]
    await safe_edit_text(q, context,
        f"🌐 <b>GOST Серверы</b> — управление\nСерверов: <b>{count}</b>",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))


async def gost_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    if not servers:
        await safe_edit_text(q, context, "Список серверов пуст.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("➕ Добавить", callback_data='gost_add'),
                  InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    lines = []
    for ip, info in servers.items():
        label = info.get("label", ip)
        rules_count = len(info.get("rules", []))
        lines.append(f"• <code>{ip}</code> — {label} ({rules_count} правил)")
    kb = []
    for ip, info in servers.items():
        label = info.get("label", ip)
        kb.append([InlineKeyboardButton(f"✏️ {ip} ({label})", callback_data=f'gost_edit:{ip}'),
                   InlineKeyboardButton("🗑️", callback_data=f'gost_del:{ip}')])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')])
    await safe_edit_text(q, context,
        "📋 <b>GOST серверы:</b>\n\n" + "\n".join(lines),
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))


async def gost_add_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    context.user_data['await_gost_add'] = 'ip'
    await safe_edit_text(q, context,
        "➕ <b>Добавить GOST-сервер</b>\n\nВведите IP адрес сервера:",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("❌ Отмена", callback_data='gost_menu')]]))


async def gost_add_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    step = context.user_data.get('await_gost_add')
    if not step:
        return
    text = update.message.text.strip()

    if step == 'ip':
        parts = text.split(".")
        valid = (len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts))
        if not valid:
            await update.message.reply_text("Неверный IP. Повторите.")
            return
        servers = load_gost_servers()
        if text in servers:
            context.user_data.pop('await_gost_add', None)
            await update.message.reply_text(f"Сервер {text} уже добавлен.")
            return
        context.user_data['gost_new_ip'] = text
        context.user_data['await_gost_add'] = 'user'
        await update.message.reply_text("Введите SSH логин (root):", reply_markup=None)

    elif step == 'user':
        context.user_data['gost_new_user'] = text
        context.user_data['await_gost_add'] = 'pass'
        await update.message.reply_text("Введите SSH пароль:")

    elif step == 'pass':
        context.user_data['gost_new_pass'] = text
        context.user_data['await_gost_add'] = 'label'
        await update.message.reply_text("Введите название (метку), например 'Front OVPN 1':")

    elif step == 'label':
        ip = context.user_data.pop('gost_new_ip')
        user = context.user_data.pop('gost_new_user')
        pwd = context.user_data.pop('gost_new_pass')
        context.user_data.pop('await_gost_add', None)
        servers = load_gost_servers()
        servers[ip] = {"ssh_user": user, "ssh_pass": pwd, "label": text, "rules": []}
        save_gost_servers(servers)
        await update.message.reply_text(
            f"✅ Сервер добавлен: <code>{ip}</code> ({text})", parse_mode="HTML")


async def gost_edit_start(update: Update, context: ContextTypes.DEFAULT_TYPE, ip: str):
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    if ip not in servers:
        await safe_edit_text(q, context, "Сервер не найден.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_list')]]))
        return
    context.user_data['await_gost_edit'] = ip
    info = servers[ip]
    await safe_edit_text(q, context,
        f"✏️ <b>Редактирование {ip}</b>\n"
        f"Логин: <code>{info['ssh_user']}</code>\n"
        f"Метка: {info.get('label', '-')}\n\n"
        f"Отправьте новые данные в формате:\n<code>логин:пароль:метка</code>\n"
        f"(можно частично: <code>пароль</code> или <code>логин:пароль</code>)",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("❌ Отмена", callback_data='gost_list')]]))


async def gost_edit_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ip = context.user_data.pop('await_gost_edit', None)
    if not ip:
        return
    text = update.message.text.strip()
    servers = load_gost_servers()
    if ip not in servers:
        await update.message.reply_text("Сервер не найден.")
        return
    parts = text.split(":")
    if len(parts) == 1:
        servers[ip]["ssh_pass"] = parts[0]
    elif len(parts) == 2:
        servers[ip]["ssh_user"] = parts[0]
        servers[ip]["ssh_pass"] = parts[1]
    elif len(parts) >= 3:
        servers[ip]["ssh_user"] = parts[0]
        servers[ip]["ssh_pass"] = parts[1]
        servers[ip]["label"] = ":".join(parts[2:])
    save_gost_servers(servers)
    await update.message.reply_text(f"✅ Сервер <code>{ip}</code> обновлён.", parse_mode="HTML")


async def gost_delete(update: Update, context: ContextTypes.DEFAULT_TYPE, ip: str):
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    removed = servers.pop(ip, None)
    if removed:
        save_gost_servers(servers)
        await safe_edit_text(q, context, f"🗑️ Удалён: <code>{ip}</code>", parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
    else:
        await safe_edit_text(q, context, "Сервер не найден.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))


def _gost_server_selector(servers: Dict, action: str, back: str = 'gost_menu') -> InlineKeyboardMarkup:
    """Build keyboard to select a GOST server for an action."""
    kb = []
    for ip, info in servers.items():
        label = info.get("label", ip)
        kb.append([InlineKeyboardButton(f"{ip} ({label})", callback_data=f'{action}:{ip}')])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data=back)])
    return InlineKeyboardMarkup(kb)


async def _gost_select_server(update: Update, context: ContextTypes.DEFAULT_TYPE,
                               action: str, title: str):
    """Show server selector for a given action."""
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    if not servers:
        await safe_edit_text(q, context, "Нет серверов. Сначала добавьте сервер.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("➕ Добавить", callback_data='gost_add'),
                  InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    await safe_edit_text(q, context, title, parse_mode="HTML",
        reply_markup=_gost_server_selector(servers, action))


async def gost_install(update: Update, context: ContextTypes.DEFAULT_TYPE, ip: str):
    """Install GOST on remote server via SSH."""
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    srv = servers.get(ip)
    if not srv:
        await safe_edit_text(q, context, "Сервер не найден.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    msg = await safe_edit_text(q, context, f"⏳ Устанавливаю GOST на <code>{ip}</code>...", parse_mode="HTML")
    install_cmd = (
        "apt-get update -qq && apt-get install -y -qq wget curl jq tar gzip > /dev/null 2>&1 ; "
        f"VER=$(curl -s 'https://api.github.com/repos/{GOST_REPO}/releases/latest' | jq -r '.tag_name' | sed 's/^v//') ; "
        "ARCH=$(dpkg --print-architecture 2>/dev/null || echo amd64) ; "
        "[ \"$ARCH\" = 'arm64' ] && ARCH='armv8' ; "
        "[ \"$ARCH\" = 'armhf' ] && ARCH='armv7' ; "
        "cd /tmp && "
        f"wget -q 'https://github.com/{GOST_REPO}/releases/download/v'$VER'/gost_'$VER'_linux_'$ARCH'.tar.gz' -O gost.tar.gz && "
        "tar -xzf gost.tar.gz && chmod +x gost && mv gost /usr/local/bin/gost && "
        "rm -f gost.tar.gz && "
        "echo \"GOST_OK:$VER\""
    )
    ok, out = ssh_exec(ip, 22, srv["ssh_user"], srv["ssh_pass"], install_cmd)
    if ok and "GOST_OK:" in out:
        ver = out.split("GOST_OK:")[-1].strip()
        result = f"✅ GOST v{ver} установлен на <code>{ip}</code>"
    else:
        result = f"❌ Ошибка установки на {ip}:\n<pre>{escape(out[:2000])}</pre>"
    await safe_edit_text(q, context, result, parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))


async def gost_configure_rules_start(update: Update, context: ContextTypes.DEFAULT_TYPE, ip: str):
    """Start interactive rule configuration for a server."""
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    if ip not in servers:
        await safe_edit_text(q, context, "Сервер не найден.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    context.user_data['await_gost_rule'] = {'ip': ip, 'step': 'proto', 'rules': []}
    await safe_edit_text(q, context,
        f"⚙️ <b>Настройка правил для {ip}</b>\n\n"
        "Протоколы: tcp, udp, http, socks5, tls, ws, relay\n\n"
        "Введите протокол (например <code>tcp</code>):",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("❌ Отмена", callback_data='gost_menu')]]))


async def gost_add_rule_start(update: Update, context: ContextTypes.DEFAULT_TYPE, ip: str):
    """Add single rule to existing config."""
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    if ip not in servers:
        await safe_edit_text(q, context, "Сервер не найден.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    context.user_data['await_gost_addrule'] = {'ip': ip, 'step': 'proto'}
    await safe_edit_text(q, context,
        f"➕ <b>Добавить правило к {ip}</b>\n\n"
        "Введите протокол (tcp/udp/http/socks5/...):",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("❌ Отмена", callback_data='gost_menu')]]))


async def gost_rule_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle multi-step rule input (configure rules / add rule)."""
    # Determine which flow
    rule_data = context.user_data.get('await_gost_rule')
    addrule_data = context.user_data.get('await_gost_addrule')
    data = rule_data or addrule_data
    if not data:
        return
    is_configure = rule_data is not None
    key = 'await_gost_rule' if is_configure else 'await_gost_addrule'

    text = update.message.text.strip()
    step = data['step']
    ip = data['ip']

    if step == 'proto':
        data['proto'] = text.lower()
        data['step'] = 'local_port'
        await update.message.reply_text("Введите локальный порт:")
    elif step == 'local_port':
        if not text.isdigit():
            await update.message.reply_text("Порт должен быть числом. Повторите:")
            return
        data['local_port'] = int(text)
        data['step'] = 'remote_ip'
        await update.message.reply_text("Введите IP назначения (бэкенд):")
    elif step == 'remote_ip':
        parts = text.split(".")
        valid = (len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts))
        if not valid:
            await update.message.reply_text("Неверный IP. Повторите:")
            return
        data['remote_ip'] = text
        data['step'] = 'remote_port'
        await update.message.reply_text("Введите порт назначения:")
    elif step == 'remote_port':
        if not text.isdigit():
            await update.message.reply_text("Порт должен быть числом. Повторите:")
            return
        rule = {
            "proto": data.pop('proto'),
            "local_port": data.pop('local_port'),
            "remote_ip": data.pop('remote_ip'),
            "remote_port": int(text),
        }
        if is_configure:
            data['rules'].append(rule)
            data['step'] = 'more'
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("➕ Ещё правило", callback_data='gost_rule_more')],
                [InlineKeyboardButton("✅ Готово — применить", callback_data='gost_rule_done')],
            ])
            rules_txt = "\n".join(
                f"  {r['proto']}://:{r['local_port']} → {r['remote_ip']}:{r['remote_port']}"
                for r in data['rules'])
            await update.message.reply_text(
                f"Правила для {ip}:\n{rules_txt}\n\nДобавить ещё или применить?",
                reply_markup=kb)
        else:
            # Single add rule — apply immediately
            context.user_data.pop(key, None)
            servers = load_gost_servers()
            srv = servers.get(ip)
            if not srv:
                await update.message.reply_text("Сервер не найден.")
                return
            srv.setdefault("rules", []).append(rule)
            save_gost_servers(servers)
            msg = await update.message.reply_text(f"⏳ Добавляю правило на {ip}...")
            new_l = f" -L={rule['proto']}://:{rule['local_port']}/{rule['remote_ip']}:{rule['remote_port']}"
            cmd = (
                f"sed -i '/^ExecStart=/ s|$|{new_l}|' {GOST_SERVICE_PATH} && "
                "systemctl daemon-reload && systemctl restart gost && echo RULE_ADDED_OK"
            )
            ok, out = ssh_exec(ip, 22, srv["ssh_user"], srv["ssh_pass"], cmd)
            if ok and "RULE_ADDED_OK" in out:
                await msg.edit_text(
                    f"✅ Правило добавлено на {ip}:\n"
                    f"<code>{rule['proto']}://:{rule['local_port']} → {rule['remote_ip']}:{rule['remote_port']}</code>",
                    parse_mode="HTML")
            else:
                await msg.edit_text(f"❌ Ошибка:\n<pre>{escape(out[:2000])}</pre>", parse_mode="HTML")


async def gost_rule_more(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """User wants to add another rule in configure flow."""
    q = update.callback_query
    await q.answer()
    data = context.user_data.get('await_gost_rule')
    if not data:
        return
    data['step'] = 'proto'
    await safe_edit_text(q, context, "Введите протокол для нового правила:")


async def gost_rule_done(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Apply all configured rules to server."""
    q = update.callback_query
    await q.answer()
    data = context.user_data.pop('await_gost_rule', None)
    if not data or not data.get('rules'):
        await safe_edit_text(q, context, "Нет правил для применения.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    ip = data['ip']
    rules = data['rules']
    servers = load_gost_servers()
    srv = servers.get(ip)
    if not srv:
        await safe_edit_text(q, context, "Сервер не найден.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    srv["rules"] = rules
    save_gost_servers(servers)
    msg = await safe_edit_text(q, context, f"⏳ Применяю {len(rules)} правил на <code>{ip}</code>...", parse_mode="HTML")
    gost_ls = " ".join(
        f"-L={r['proto']}://:{r['local_port']}/{r['remote_ip']}:{r['remote_port']}"
        for r in rules)
    service_content = (
        "[Unit]\\n"
        "Description=GO Simple Tunnel\\n"
        "After=network.target\\n"
        "Wants=network.target\\n"
        "\\n"
        "[Service]\\n"
        "Type=simple\\n"
        f"ExecStart={GOST_BIN} {gost_ls}\\n"
        "Restart=on-failure\\n"
        "\\n"
        "[Install]\\n"
        "WantedBy=multi-user.target"
    )
    cmd = (
        f"echo -e '{service_content}' > {GOST_SERVICE_PATH} && "
        "systemctl daemon-reload && systemctl enable gost && systemctl restart gost && echo GOST_CONF_OK"
    )
    ok, out = ssh_exec(ip, 22, srv["ssh_user"], srv["ssh_pass"], cmd)
    if ok and "GOST_CONF_OK" in out:
        rules_txt = "\n".join(
            f"  <code>{r['proto']}://:{r['local_port']} → {r['remote_ip']}:{r['remote_port']}</code>"
            for r in rules)
        await safe_edit_text(q, context,
            f"✅ GOST настроен на <code>{ip}</code>:\n{rules_txt}",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
    else:
        await safe_edit_text(q, context, f"❌ Ошибка:\n<pre>{escape(out[:2000])}</pre>", parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))


async def gost_show_config(update: Update, context: ContextTypes.DEFAULT_TYPE, ip: str):
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    srv = servers.get(ip)
    if not srv:
        await safe_edit_text(q, context, "Сервер не найден.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    msg = await safe_edit_text(q, context, f"⏳ Читаю конфиг с <code>{ip}</code>...", parse_mode="HTML")
    ok, out = ssh_exec(ip, 22, srv["ssh_user"], srv["ssh_pass"], f"cat {GOST_SERVICE_PATH} 2>/dev/null || echo NO_SERVICE")
    if ok:
        await safe_edit_text(q, context,
            f"📄 <b>Конфиг GOST на {ip}:</b>\n<pre>{escape(out[:3500])}</pre>",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
    else:
        await safe_edit_text(q, context, f"❌ Ошибка:\n{escape(out[:2000])}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))


async def gost_ping_all(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    if not servers:
        await safe_edit_text(q, context, "Нет серверов.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    msg = await safe_edit_text(q, context, "📡 Пингую серверы...")
    results = []
    for ip, info in servers.items():
        label = info.get("label", ip)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, 22))
            sock.close()
            results.append(f"🟢 <code>{ip}</code> — {label}")
        except Exception:
            results.append(f"🔴 <code>{ip}</code> — {label}")
    await safe_edit_text(q, context,
        "📡 <b>Пинг GOST серверов:</b>\n\n" + "\n".join(results),
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))


async def _gost_simple_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE, ip: str,
                            cmd: str, success_msg: str, title: str):
    """Execute a simple SSH command on GOST server and show result."""
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    srv = servers.get(ip)
    if not srv:
        await safe_edit_text(q, context, "Сервер не найден.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    msg = await safe_edit_text(q, context, f"⏳ {title} <code>{ip}</code>...", parse_mode="HTML")
    ok, out = ssh_exec(ip, 22, srv["ssh_user"], srv["ssh_pass"], cmd)
    if ok:
        await safe_edit_text(q, context,
            f"{success_msg}\n<pre>{escape(out[:3000])}</pre>",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
    else:
        await safe_edit_text(q, context, f"❌ Ошибка:\n<pre>{escape(out[:2000])}</pre>", parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))


async def gost_start_cmd(update, context, ip):
    await _gost_simple_cmd(update, context, ip,
        "systemctl start gost && systemctl is-active gost",
        f"▶️ GOST запущен на <code>{ip}</code>:", "Запускаю GOST на")

async def gost_stop_cmd(update, context, ip):
    await _gost_simple_cmd(update, context, ip,
        "systemctl stop gost && echo STOPPED",
        f"⏹ GOST остановлен на <code>{ip}</code>:", "Останавливаю GOST на")

async def gost_restart_cmd(update, context, ip):
    await _gost_simple_cmd(update, context, ip,
        "systemctl restart gost && systemctl is-active gost",
        f"🔁 GOST перезапущен на <code>{ip}</code>:", "Перезапускаю GOST на")

async def gost_status_cmd(update, context, ip):
    await _gost_simple_cmd(update, context, ip,
        "systemctl status gost --no-pager 2>&1 | head -20",
        f"📊 Статус GOST на <code>{ip}</code>:", "Проверяю статус на")

async def gost_log_cmd(update, context, ip):
    await _gost_simple_cmd(update, context, ip,
        "journalctl -u gost --no-pager -n 30 2>&1",
        f"📜 Лог GOST на <code>{ip}</code>:", "Читаю лог на")


async def gost_backup_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE, ip: str):
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    srv = servers.get(ip)
    if not srv:
        await safe_edit_text(q, context, "Сервер не найден.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    msg = await safe_edit_text(q, context, f"⏳ Создаю бэкап на <code>{ip}</code>...", parse_mode="HTML")
    cmd = (
        f"mkdir -p {GOST_BACKUP_DIR} && "
        f"tar -czf {GOST_BACKUP_DIR}/gost-backup-$(date +%Y%m%d-%H%M%S).tar.gz "
        f"{GOST_BIN} {GOST_SERVICE_PATH} 2>/dev/null && "
        f"ls -1t {GOST_BACKUP_DIR}/*.tar.gz | head -5 && echo BACKUP_OK"
    )
    ok, out = ssh_exec(ip, 22, srv["ssh_user"], srv["ssh_pass"], cmd)
    if ok and "BACKUP_OK" in out:
        await safe_edit_text(q, context,
            f"💾 Бэкап создан на <code>{ip}</code>:\n<pre>{escape(out.replace('BACKUP_OK','').strip()[:2000])}</pre>",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
    else:
        await safe_edit_text(q, context, f"❌ Ошибка:\n<pre>{escape(out[:2000])}</pre>", parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))


async def gost_restore_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE, ip: str):
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    srv = servers.get(ip)
    if not srv:
        await safe_edit_text(q, context, "Сервер не найден.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    # First list available backups
    msg = await safe_edit_text(q, context, f"⏳ Ищу бэкапы на <code>{ip}</code>...", parse_mode="HTML")
    ok, out = ssh_exec(ip, 22, srv["ssh_user"], srv["ssh_pass"],
        f"ls -1t {GOST_BACKUP_DIR}/*.tar.gz 2>/dev/null")
    if not ok or not out.strip():
        await safe_edit_text(q, context, f"Бэкапы не найдены на {ip}.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    files = [f.strip() for f in out.strip().split("\n") if f.strip()]
    if not files:
        await safe_edit_text(q, context, f"Бэкапы не найдены на {ip}.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    kb = []
    for f in files[:10]:
        fname = f.split("/")[-1]
        kb.append([InlineKeyboardButton(fname, callback_data=f'gost_restore_apply:{ip}:{fname}')])
    kb.append([InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')])
    await safe_edit_text(q, context, f"📥 <b>Бэкапы на {ip}:</b>\nВыберите для восстановления:",
        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(kb))


async def gost_restore_apply(update: Update, context: ContextTypes.DEFAULT_TYPE, ip: str, fname: str):
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    srv = servers.get(ip)
    if not srv:
        await safe_edit_text(q, context, "Сервер не найден.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    msg = await safe_edit_text(q, context, f"⏳ Восстанавливаю {fname} на <code>{ip}</code>...", parse_mode="HTML")
    cmd = (
        f"tar -xzf {GOST_BACKUP_DIR}/{fname} -C / && "
        "systemctl daemon-reload && systemctl restart gost && echo RESTORE_OK"
    )
    ok, out = ssh_exec(ip, 22, srv["ssh_user"], srv["ssh_pass"], cmd)
    if ok and "RESTORE_OK" in out:
        await safe_edit_text(q, context,
            f"✅ Бэкап {fname} восстановлен на <code>{ip}</code>, GOST перезапущен.",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
    else:
        await safe_edit_text(q, context, f"❌ Ошибка:\n<pre>{escape(out[:2000])}</pre>", parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))


async def gost_optimize_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE, ip: str):
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    srv = servers.get(ip)
    if not srv:
        await safe_edit_text(q, context, "Сервер не найден.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    msg = await safe_edit_text(q, context, f"⏳ Оптимизирую TCP/UDP на <code>{ip}</code>...", parse_mode="HTML")
    sysctl_content = (
        "net.ipv4.ip_forward = 1\\n"
        "net.core.default_qdisc = fq\\n"
        "net.core.rmem_max = 2500000\\n"
        "net.core.wmem_max = 2500000\\n"
        "net.core.optmem_max = 25165824\\n"
        "net.core.netdev_max_backlog = 5000\\n"
        "net.netfilter.nf_conntrack_udp_timeout = 60\\n"
        "net.netfilter.nf_conntrack_udp_timeout_stream = 180\\n"
        "net.ipv4.tcp_congestion_control = bbr\\n"
        "net.ipv4.tcp_fastopen = 3\\n"
        "net.ipv4.tcp_low_latency = 1"
    )
    cmd = (
        f"echo -e '{sysctl_content}' > /etc/sysctl.d/98-vpn-proxy.conf && "
        "modprobe nf_conntrack 2>/dev/null ; sysctl --system > /dev/null 2>&1 && "
        "sysctl net.ipv4.ip_forward net.core.default_qdisc net.ipv4.tcp_congestion_control "
        "net.ipv4.tcp_fastopen 2>/dev/null && echo OPTIMIZE_OK"
    )
    ok, out = ssh_exec(ip, 22, srv["ssh_user"], srv["ssh_pass"], cmd)
    if ok and "OPTIMIZE_OK" in out:
        await safe_edit_text(q, context,
            f"🚀 TCP/UDP оптимизация применена на <code>{ip}</code>:\n<pre>{escape(out.replace('OPTIMIZE_OK','').strip()[:2000])}</pre>",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
    else:
        await safe_edit_text(q, context, f"❌ Ошибка:\n<pre>{escape(out[:2000])}</pre>", parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))


async def gost_uninstall_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE, ip: str):
    q = update.callback_query
    await q.answer()
    servers = load_gost_servers()
    srv = servers.get(ip)
    if not srv:
        await safe_edit_text(q, context, "Сервер не найден.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
        return
    msg = await safe_edit_text(q, context, f"⏳ Удаляю GOST с <code>{ip}</code>...", parse_mode="HTML")
    cmd = (
        "systemctl stop gost 2>/dev/null ; systemctl disable gost 2>/dev/null ; "
        f"rm -f {GOST_BIN} {GOST_SERVICE_PATH} && systemctl daemon-reload && echo UNINSTALL_OK"
    )
    ok, out = ssh_exec(ip, 22, srv["ssh_user"], srv["ssh_pass"], cmd)
    if ok and "UNINSTALL_OK" in out:
        await safe_edit_text(q, context, f"✅ GOST удалён с <code>{ip}</code>", parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))
    else:
        await safe_edit_text(q, context, f"❌ Ошибка:\n<pre>{escape(out[:2000])}</pre>", parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data='gost_menu')]]))


# =====================================================================
#  GOST — HELP
# =====================================================================

GOST_HELP_TEXT = """
🌐  GOST Серверы — Подробная справка
════════════════════════════════════

📋 Список серверов
  Показывает все добавленные GOST-серверы
  с IP, меткой и количеством правил.
  Здесь же можно редактировать (✏️) логин/пароль/метку
  или удалить (🗑️) сервер из списка.

➕ Добавить сервер
  Добавить новый GOST-сервер в бот.
  Бот запросит: IP → SSH логин → SSH пароль → метку.
  Данные сохраняются в gost_servers.json.
  Все операции выполняются через SSH.

⚙️ Установить GOST
  Скачивает последнюю версию GOST с GitHub
  и устанавливает на выбранный сервер.
  Автоопределение архитектуры (amd64/arm64/armv7).
  После установки бинарник: /usr/local/bin/gost

📡 Настроить правила
  Полная (пере)настройка GOST на сервере.
  Создаёт systemd service с нуля.
  Бот спрашивает для каждого правила:
    • Протокол (tcp/udp/http/socks5/tls/ws/relay)
    • Локальный порт (на фронт-сервере)
    • IP назначения (бэкенд-сервер)
    • Порт назначения
  Можно добавить несколько правил за раз.
  ⚠️ Перезаписывает текущий конфиг!

  Примеры правил:
    TCP forward:  tcp :80 → 1.2.3.4:80  (nginx/http)
    UDP forward:  udp :443 → 1.2.3.4:443 (OpenVPN)
    HTTP proxy:   http :8080 (прокси без назначения)

➕ Добавить правило
  Добавляет одно правило к существующему конфигу
  без перезаписи. Правило дописывается в ExecStart.

📄 Показать конфиг
  Читает и показывает текущий файл
  /usr/lib/systemd/system/gost.service
  с удалённого сервера.

📡 Пинг серверов
  Проверяет доступность всех GOST-серверов
  (TCP подключение на порт 22).
  🟢 доступен / 🔴 недоступен

▶️ Старт / ⏹ Стоп / 🔁 Рестарт
  Управление systemd-сервисом gost:
    systemctl start/stop/restart gost

📊 Статус
  Показывает systemctl status gost
  (active/inactive, uptime, PID).

📜 Лог
  Последние 30 строк журнала GOST:
  journalctl -u gost -n 30

💾 Бэкап
  Создаёт tar.gz архив с бинарником gost
  и файлом gost.service на удалённом сервере.
  Сохраняется в /var/backups/gost-xsform/

📥 Восстановить
  Показывает список бэкапов на сервере
  и восстанавливает выбранный.
  После восстановления — автоперезапуск.

🚀 Ускорить TCP/UDP
  Применяет sysctl-оптимизации на сервере:
    • BBR congestion control
    • TCP Fast Open
    • Увеличенные буферы (rmem/wmem)
    • UDP conntrack таймауты
    • IP forwarding
    • fq qdisc
  Конфиг: /etc/sysctl.d/98-vpn-proxy.conf

🗑️ Удалить GOST
  Полное удаление GOST с сервера:
  остановка сервиса → disable → удаление
  бинарника и service-файла.

🔐 Получить Root
  Для серверов с PEM-ключом (AWS, GCP, Azure):
    1. Отправляешь .pem / .key / .ppk файл в чат
    2. Вводишь IP сервера
    3. Вводишь SSH-пользователя (ubuntu/ec2-user)
    4. Вводишь желаемый пароль root
  Бот автоматически:
    • PPK файлы конвертируются в PEM (puttygen)
    • Подключается по PEM-ключу
    • Задаёт пароль root
    • Включает PermitRootLogin yes
    • Включает PasswordAuthentication yes
    • Фиксит все sshd_config.d/*.conf
    • Рестартует sshd
    • Проверяет вход root+пароль
  Ключ удаляется сразу после использования.
  После этого сервер добавляется обычным способом.
"""

async def gost_help_send(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send GOST help as a text file."""
    q = update.callback_query
    await q.answer()
    help_bytes = GOST_HELP_TEXT.strip().encode("utf-8")
    await context.bot.send_document(
        chat_id=q.message.chat_id,
        document=help_bytes,
        filename="gost_help.txt",
        caption="📖 Справка — GOST Серверы")


# =====================================================================
#  GOST — GET ROOT (enable root SSH via PEM key)
# =====================================================================

async def gost_getroot_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start the Get Root flow — ask user to send PEM file."""
    q = update.callback_query
    await q.answer()
    # Clear any stale GOST/SSH await flags
    for k in list(context.user_data.keys()):
        if k.startswith('await_'):
            context.user_data.pop(k, None)
    context.user_data['await_gost_getroot'] = 'pem'
    await safe_edit_text(q, context,
        "🔐 <b>Получить Root</b>\n\n"
        "Этот инструмент включит root SSH-доступ по паролю\n"
        "на серверах где вход только по PEM-ключу (AWS, GCP и т.д.)\n\n"
        "📎 <b>Отправьте файл ключа (.pem / .key / .ppk) в чат</b>",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("❌ Отмена", callback_data='gost_menu')]]))


def _convert_ppk_to_pem(ppk_path: str, pem_path: str) -> Tuple[bool, str]:
    """Convert PuTTY PPK key to OpenSSH PEM format using puttygen."""
    # Ensure puttygen is available
    if not shutil.which('puttygen'):
        try:
            subprocess.run(['apt-get', 'install', '-y', 'putty-tools'],
                           capture_output=True, timeout=30)
        except Exception:
            pass
    if not shutil.which('puttygen'):
        return False, "puttygen не найден. Установите: apt-get install putty-tools"
    try:
        r = subprocess.run(
            ['puttygen', ppk_path, '-O', 'private-openssh', '-o', pem_path],
            capture_output=True, text=True, timeout=15)
        if r.returncode == 0 and os.path.exists(pem_path):
            os.chmod(pem_path, 0o600)
            return True, "OK"
        return False, r.stderr.strip() or f"puttygen exit code {r.returncode}"
    except Exception as e:
        return False, str(e)


async def gost_getroot_pem_received(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle PEM/PPK file upload — save and ask for IP."""
    doc = update.message.document
    if not doc.file_name.endswith(('.pem', '.key', '.ppk')):
        await update.message.reply_text(
            "⚠️ Отправьте файл с расширением .pem / .key / .ppk\n"
            "Или нажмите Отмена в меню выше.")
        return

    os.makedirs(GOST_KEYS_DIR, exist_ok=True)
    is_ppk = doc.file_name.lower().endswith('.ppk')
    raw_path = os.path.join(GOST_KEYS_DIR, f"temp_getroot_{update.effective_user.id}{'_raw.ppk' if is_ppk else '.pem'}")
    key_path = os.path.join(GOST_KEYS_DIR, f"temp_getroot_{update.effective_user.id}.pem")

    tg_file = await context.bot.get_file(doc.file_id)
    await tg_file.download_to_drive(raw_path)
    os.chmod(raw_path, 0o600)

    if is_ppk:
        ok, err = await asyncio.to_thread(_convert_ppk_to_pem, raw_path, key_path)
        try:
            os.remove(raw_path)
        except Exception:
            pass
        if not ok:
            await update.message.reply_text(
                f"❌ Ошибка конвертации PPK → PEM:\n<pre>{escape(err)}</pre>\n\n"
                "Попробуйте конвертировать вручную в PuTTYgen → Export OpenSSH key",
                parse_mode="HTML")
            return
    else:
        if raw_path != key_path:
            os.rename(raw_path, key_path)

    context.user_data['gost_getroot_key'] = key_path
    context.user_data['await_gost_getroot'] = 'ip'
    fmt = "PPK → PEM конвертирован" if is_ppk else "PEM-ключ получен"
    await update.message.reply_text(
        f"✅ {fmt}.\n\nВведите IP-адрес сервера:")


async def gost_getroot_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Multi-step text handler for getroot flow: ip → user → password."""
    step = context.user_data.get('await_gost_getroot')
    if not step or step == 'pem':
        return
    text = update.message.text.strip()

    if step == 'ip':
        parts = text.split(".")
        valid = (len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts))
        if not valid:
            await update.message.reply_text("Неверный IP. Повторите:")
            return
        context.user_data['gost_getroot_ip'] = text
        context.user_data['await_gost_getroot'] = 'user'
        await update.message.reply_text(
            "Введите SSH-пользователя (ubuntu / ec2-user / admin / ...):")

    elif step == 'user':
        context.user_data['gost_getroot_user'] = text
        context.user_data['await_gost_getroot'] = 'password'
        await update.message.reply_text(
            "Введите желаемый <b>пароль для root</b>:", parse_mode="HTML")

    elif step == 'password':
        root_pass = text
        ip = context.user_data.pop('gost_getroot_ip')
        user = context.user_data.pop('gost_getroot_user')
        key_path = context.user_data.pop('gost_getroot_key')
        context.user_data.pop('await_gost_getroot', None)

        msg = await update.message.reply_text(
            f"⏳ Подключаюсь к <code>{ip}</code> как <b>{user}</b>...\n"
            "Включаю root доступ...", parse_mode="HTML")

        # Build the enable-root command
        enable_root_cmd = (
            # Set root password
            f"echo 'root:{root_pass}' | chpasswd && "
            # Fix main sshd_config
            "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config ; "
            "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config ; "
            "grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config ; "
            "grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config ; "
            # Fix all sshd_config.d/*.conf files that might override
            "for f in /etc/ssh/sshd_config.d/*.conf; do "
            "  [ -f \"$f\" ] && "
            "  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' \"$f\" && "
            "  sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' \"$f\" ; "
            "done 2>/dev/null ; "
            # Fix cloud-init override if exists
            "[ -f /etc/ssh/sshd_config.d/60-cloudimg-settings.conf ] && "
            "sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' "
            "/etc/ssh/sshd_config.d/60-cloudimg-settings.conf ; "
            # Remove authorized_keys restrictions (no-port-forwarding, etc.)
            "[ -f /root/.ssh/authorized_keys ] && "
            "sed -i 's/^no-port-forwarding.*ssh-/ssh-/' /root/.ssh/authorized_keys 2>/dev/null ; "
            # Copy authorized_keys to root if needed
            f"[ ! -f /root/.ssh/authorized_keys ] && mkdir -p /root/.ssh && "
            f"cp /home/{user}/.ssh/authorized_keys /root/.ssh/ 2>/dev/null ; "
            # Restart sshd
            "systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || "
            "service sshd restart 2>/dev/null ; "
            "echo ROOT_ENABLED_OK"
        )

        ok, out = ssh_exec_key(ip, 22, user, key_path, enable_root_cmd)

        # Clean up temp key
        try:
            os.remove(key_path)
        except Exception:
            pass

        if ok and "ROOT_ENABLED_OK" in out:
            # Verify root login works
            ok2, out2 = ssh_exec(ip, 22, "root", root_pass, "whoami")
            if ok2 and "root" in out2:
                await msg.edit_text(
                    f"✅ <b>Root доступ включён на {ip}</b>\n\n"
                    f"Логин: <code>root</code>\n"
                    f"Пароль: <code>{escape(root_pass)}</code>\n\n"
                    f"Сервер готов к добавлению в GOST.",
                    parse_mode="HTML")
            else:
                await msg.edit_text(
                    f"⚠️ Команды выполнены на {ip}, но проверка root не прошла.\n"
                    f"Попробуйте подключиться вручную: <code>ssh root@{ip}</code>\n"
                    f"Вывод: <pre>{escape(out2[:1000])}</pre>",
                    parse_mode="HTML")
        else:
            await msg.edit_text(
                f"❌ Ошибка на {ip}:\n<pre>{escape(out[:2000])}</pre>",
                parse_mode="HTML")


# =====================================================================
#  MAIN
# =====================================================================
async def post_init(application):
    await application.bot.set_my_commands([
        ("start", "Главное меню"),
    ])

def main():
    app = Application.builder().token(TOKEN).post_init(post_init).build()
    load_traffic_db()
    load_client_meta()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("clients", clients_command))
    app.add_handler(CommandHandler("traffic", traffic_command))
    app.add_handler(CommandHandler("show_update_cmd", show_update_cmd))
    app.add_handler(CommandHandler("backup_now", cmd_backup_now))
    app.add_handler(CommandHandler("backup_list", cmd_backup_list))
    app.add_handler(CommandHandler("backup_restore", cmd_backup_restore))
    app.add_handler(CommandHandler("backup_restore_apply", cmd_backup_restore_apply))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, universal_text_handler))
    app.add_handler(MessageHandler(filters.Document.ALL, document_handler))
    app.add_handler(CallbackQueryHandler(button_handler))
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.create_task(check_new_connections(app))
    loop.create_task(auto_ip_monitor(app))
    loop.create_task(domain_monitor(app))
    app.run_polling()

if __name__ == '__main__':
    main()
