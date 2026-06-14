# -*- coding: utf-8 -*-
"""
Unified Telegram Bot — OpenVPN management + Remote Refresh IP updater.
Runs as root. Single token, single process.
"""

import os
import subprocess
import time
from datetime import datetime, timedelta
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
BOT_VERSION = "unified-2025-10-01"
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
    dt = datetime.utcnow() + timedelta(days=days)
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
        return iso, (dt - datetime.utcnow()).days
    except Exception:
        return iso, None

def enforce_client_expiries():
    now = datetime.utcnow()
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
    now = datetime.utcnow()
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
        return (expiry_dt - datetime.utcnow()).days
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
                backup = tpl + ".bak_" + datetime.utcnow().strftime("%Y%m%d%H%M%S")
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
                bak = path + ".bak_" + datetime.utcnow().strftime("%Y%m%d%H%M%S")
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

async def log_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    log_text = get_status_log_tail()
    safe = _html_escape(log_text)
    msgs = split_message(f"<b>status.log (хвост):</b>\n<pre>{safe}</pre>")
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
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
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
    from datetime import timezone
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
    for k in ['await_rr_ip', 'await_rr_domain_add']:
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
        [InlineKeyboardButton("🚨 Тревога ON/OFF", callback_data='block_alert'),
         InlineKeyboardButton("⚡ Перезагрузка", callback_data='restart_menu')],
        [InlineKeyboardButton("📝 OVPN EDIT", callback_data='ovpn_edit_menu'),
         InlineKeyboardButton("🖥 SSH Роутеры", callback_data='ssh_routers')],
        # --- Remote Refresh section ---
        [InlineKeyboardButton("─── Remote Refresh ───", callback_data='noop')],
        [InlineKeyboardButton("📡 IP роутеров", callback_data='rr_current_ip'),
         InlineKeyboardButton("✏️ Сменить IP", callback_data='rr_set_ip')],
        [InlineKeyboardButton("🔍 IP Scan", callback_data='rr_ip_scan'),
         InlineKeyboardButton("🔍 Port Scan", callback_data='rr_port_scan')],
        [InlineKeyboardButton("📋 История IP", callback_data='rr_history'),
         InlineKeyboardButton("🌐 Домены", callback_data='rr_domains')],
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
    if context.user_data.get('await_ssh_add'):
        context.user_data.pop('await_ssh_add')
        parts = update.message.text.strip().split()
        if len(parts) < 2:
            await update.message.reply_text("Формат: имя пароль [порт]")
            return
        cn = parts[0]
        password = parts[1]
        port = int(parts[2]) if len(parts) > 2 else 22
        routers = load_routers()
        routers[cn] = {"user": "admin", "password": password, "port": port}
        save_routers(routers)
        await update.message.reply_text(f"✅ Роутер <b>{cn}</b> добавлен.", parse_mode="HTML")
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
        cn = context.user_data.pop('await_ssh_cmd')
        routers = load_routers()
        r = routers.get(cn)
        if not r:
            await update.message.reply_text("Роутер не найден.")
            return
        ip = get_router_ip(cn)
        if not ip:
            await update.message.reply_text(f"🔴 {cn} — нет IP.")
            return
        cmd = update.message.text.strip()
        msg = await update.message.reply_text(f"💻 Выполняю на <b>{cn}</b>...", parse_mode="HTML")
        ok, out = ssh_exec(ip, r.get('port', 22), r.get('user', 'admin'), r.get('password', ''), cmd)
        result = f"💻 <b>{cn}</b> ({ip}):\n<pre>{escape(out[:3800])}</pre>"
        await msg.edit_text(result, parse_mode="HTML")
        return
    # OVPN EDIT text input
    if context.user_data.get('await_ovpn_edit'):
        file_key = context.user_data.pop('await_ovpn_edit')
        path = OVPN_EDIT_FILES.get(file_key)
        if path:
            new_content = update.message.text
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
    print("DEBUG callback_data:", data)

    # --- OpenVPN callbacks ---
    if data == 'refresh':
        await safe_edit_text(q, context, format_clients_by_certs(), parse_mode="HTML")

    elif data == 'stats':
        clients, online_names, tunnel_ips = parse_openvpn_status()
        files = get_ovpn_files()
        files = sorted(files, key=lambda x: _natural_key(x[:-5]))
        lines = ["<b>Статус всех ключей:</b>"]
        for f in files:
            name = f[:-5]
            st = "⛔" if is_client_ccd_disabled(name) else ("🟢" if name in online_names else "🔴")
            lines.append(f"{st} {name}")
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
        global alert_enabled
        alert_enabled = not alert_enabled
        if alert_enabled:
            await safe_edit_text(q, context,
                f"🔔 Тревога блокировки: <b>ON</b>\n"
                f"Порог MIN_ONLINE_ALERT = {MIN_ONLINE_ALERT}\n"
                "Проверка каждые 10с.", parse_mode="HTML")
        else:
            await safe_edit_text(q, context,
                "🔕 Тревога блокировки: <b>OFF</b>", parse_mode="HTML")

    elif data == 'help':
        await context.bot.send_message(chat_id=q.message.chat_id,
            text="<b>Unified Bot</b>\nВерхняя часть меню — OpenVPN управление.\n"
                 "Нижняя часть (Remote Refresh) — IP роутеров, домены, сканы.\n"
                 f"Версия: {BOT_VERSION}", parse_mode="HTML")

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
        import asyncio
        await asyncio.sleep(2)
        subprocess.Popen(["systemctl", "restart", "remote-refresh-bot"])

    elif data == 'rst_cancel':
        await safe_edit_text(q, context, "Отменено.")

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
    elif data == 'ssh_select_heal':
        await ssh_select_router(update, context, 'ssh_heal')
    elif data == 'ssh_select_reboot':
        await ssh_select_router(update, context, 'ssh_reboot')
    elif data == 'ssh_select_cmd':
        await ssh_select_router(update, context, 'ssh_cmd')
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
        await safe_edit_text(q, context, f"💻 Введите команду для <b>{cn}</b>:", parse_mode="HTML")
    elif data.startswith('ssh_edit:'):
        cn = data[len('ssh_edit:'):]
        context.user_data['await_ssh_edit'] = cn
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
    elif data == 'rr_cancel':
        await rr_cancel(update, context)

    else:
        await safe_edit_text(q, context, "Неизвестная команда.")

# =====================================================================
#  SSH ROUTERS — handlers
# =====================================================================

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
        [InlineKeyboardButton("🔄 Обновить скрипт", callback_data='ssh_select_update')],
        [InlineKeyboardButton("🩹 Лечение", callback_data='ssh_select_heal')],
        [InlineKeyboardButton("🔁 Перезагрузка", callback_data='ssh_select_reboot')],
        [InlineKeyboardButton("💻 Команда", callback_data='ssh_select_cmd')],
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
        avail_str = ", ".join(sorted(available, key=_natural_key))
        hint = f"\n\nДоступные клиенты:\n<code>{avail_str}</code>"
    else:
        hint = "\n\nВсе клиенты из ipp.txt уже добавлены."
    await safe_edit_text(q, context,
        f"➕ <b>Добавить роутер</b>{hint}\n\n"
        "Формат: <code>имя пароль</code>\n"
        "или: <code>имя пароль порт</code>\n"
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
            results.append(f"🟠 <b>{cn}</b> ({ip}) — {out[:60]}")
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

            # Regenerate sha256 for domain_list
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
#  MAIN
# =====================================================================
def main():
    app = Application.builder().token(TOKEN).build()
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
    import asyncio
    loop = asyncio.get_event_loop()
    loop.create_task(check_new_connections(app))
    app.run_polling()

if __name__ == '__main__':
    main()
