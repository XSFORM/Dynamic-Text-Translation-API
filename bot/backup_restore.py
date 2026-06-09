#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
backup_restore.py
Подсистема:
 - Полный snapshot-бэкап директорий (по списку BACKUP_ROOTS)
 - manifest.json (метаданные файлов + PKI index)
 - Diff (dry-run)
 - Жёсткий restore (удаляет файлы, которых нет в бэкапе, затем разворачивает)
 - Регенерация CRL (если PKI присутствует)
"""

import os
import tarfile
import hashlib
import json
import time
import shutil
import stat
import subprocess
from typing import List, Dict, Tuple, Optional

# ---------- Конфигурация ----------

BACKUP_ROOTS = [
    "/etc/openvpn",
    "/etc/iptables",
    "/root",
]

BACKUP_OUTPUT_DIR = "/root/backups"
MANIFEST_NAME = "manifest.json"
ARCHIVE_PREFIX = "openvpn_full_backup"
TMP_STAGING_PREFIX = "/tmp/restore_staging_"

# Что исключить (при желании расширить)
EXCLUDE_PATHS = {
    "/root/.bash_history",
    "/root/.cache",
    "/root/backups/.tmp",
}

EXCLUDE_SUFFIXES = {
    ".pyc",
    ".log",
    ".swp",
}

STRICT_PURGE = True            # удаляем всё лишнее в roots
AUTO_REGEN_CRL = True
EASYRSA_DIR = "/etc/openvpn/easy-rsa"

# ---------- Утилиты ----------

def _now_ts():
    return time.strftime("%Y%m%d_%H%M%S", time.gmtime())

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def sha256_file(path: str, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for data in iter(lambda: f.read(chunk), b""):
            h.update(data)
    return h.hexdigest()

def is_excluded(path: str) -> bool:
    norm = os.path.normpath(path)
    if norm in EXCLUDE_PATHS:
        return True
    for suf in EXCLUDE_SUFFIXES:
        if norm.endswith(suf):
            return True
    return False

def iter_files(root: str) -> List[str]:
    result = []
    if not os.path.exists(root):
        return result
    for base, dirs, files in os.walk(root, followlinks=False):
        # фильтр директорий
        for d in list(dirs):
            p = os.path.join(base, d)
            if is_excluded(p):
                dirs.remove(d)
        for fn in files:
            p = os.path.join(base, fn)
            if is_excluded(p):
                continue
            if os.path.isfile(p):
                result.append(p)
    return result

# ---------- Manifest ----------

def build_manifest(roots: List[str]) -> Dict:
    files_meta = []
    for r in roots:
        r = os.path.normpath(r)
        flist = iter_files(r)
        for fp in flist:
            try:
                st = os.lstat(fp)
            except FileNotFoundError:
                continue
            mode = stat.S_IMODE(st.st_mode)
            files_meta.append({
                "path": fp,
                "sha256": sha256_file(fp),
                "size": st.st_size,
                "mode": oct(mode),
                "uid": st.st_uid,
                "gid": st.st_gid,
            })

    pki_root = os.path.join(EASYRSA_DIR, "pki")
    index_path = os.path.join(pki_root, "index.txt")
    serial_path = os.path.join(pki_root, "serial")
    clients = []
    index_sha = None
    serial_val = None

    if os.path.exists(index_path):
        try:
            index_sha = sha256_file(index_path)
            with open(index_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    status = parts[0]          # V/R/E
                    expiry_raw = parts[1]
                    serial = parts[3]
                    subject = parts[-1]
                    cn = None
                    if subject.startswith('/'):
                        for part in subject.split('/'):
                            if part.startswith('CN='):
                                cn = part[3:]
                                break
                    clients.append({
                        "cn": cn or "?",
                        "status": status,
                        "serial": serial,
                        "expiry_raw": expiry_raw
                    })
        except Exception:
            pass

    if os.path.exists(serial_path):
        try:
            with open(serial_path, "r") as f:
                serial_val = f.read().strip()
        except Exception:
            pass

    manifest = {
        "version": 1,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "roots": roots,
        "files": files_meta,
        "openvpn_pki": {
            "pki_root": pki_root if os.path.exists(pki_root) else None,
            "index_sha256": index_sha,
            "serial": serial_val,
            "clients": clients,
        }
    }
    return manifest

def save_manifest(manifest: Dict, target_dir: str):
    path = os.path.join(target_dir, MANIFEST_NAME)
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    return path

def load_manifest_from_archive(archive_path: str, extract_to: str) -> Dict:
    with tarfile.open(archive_path, "r:gz") as tar:
        tar.extractall(extract_to)
    manifest_path = os.path.join(extract_to, MANIFEST_NAME)
    if not os.path.exists(manifest_path):
        raise RuntimeError("В архиве отсутствует manifest.json")
    with open(manifest_path, "r") as f:
        return json.load(f)

# ---------- Backup ----------

def create_backup() -> str:
    ensure_dir(BACKUP_OUTPUT_DIR)
    ts = _now_ts()
    archive_name = f"{ARCHIVE_PREFIX}_{ts}.tar.gz"
    archive_path = os.path.join(BACKUP_OUTPUT_DIR, archive_name)

    manifest = build_manifest(BACKUP_ROOTS)
    staging_dir = f"/tmp/backup_staging_{ts}"
    os.makedirs(staging_dir, exist_ok=True)
    save_manifest(manifest, staging_dir)

    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(os.path.join(staging_dir, MANIFEST_NAME), arcname=MANIFEST_NAME)
        for root in BACKUP_ROOTS:
            if os.path.exists(root):
                # arcname без ведущего /
                tar.add(root, arcname=root.lstrip('/'))
    shutil.rmtree(staging_dir, ignore_errors=True)
    return archive_path

# ---------- Diff ----------

def compute_diff(manifest: Dict) -> Dict:
    recorded = {f["path"]: f for f in manifest.get("files", [])}
    current_all = []
    for r in manifest.get("roots", []):
        current_all.extend(iter_files(r))
    current_set = set(current_all)
    recorded_set = set(recorded.keys())

    extra = sorted(list(current_set - recorded_set))
    missing = sorted(list(recorded_set - current_set))
    changed = []
    for path in recorded_set & current_set:
        try:
            current_hash = sha256_file(path)
            if current_hash != recorded[path]["sha256"]:
                changed.append(path)
        except Exception:
            changed.append(path)

    return {
        "extra": extra,
        "missing": missing,
        "changed": sorted(changed)
    }

# ---------- Purge / Copy / CRL ----------

def purge_extras(extra_list: List[str]):
    for path in sorted(extra_list, key=lambda p: len(p), reverse=True):
        if not os.path.exists(path):
            continue
        try:
            if os.path.isfile(path) or os.path.islink(path):
                os.remove(path)
            else:
                inside_root = any(os.path.commonpath([path, r]) == r for r in BACKUP_ROOTS)
                if inside_root:
                    shutil.rmtree(path, ignore_errors=True)
        except Exception as e:
            print(f"[purge] Не удалось удалить {path}: {e}")

def copy_from_staging(staging_dir: str, manifest: Dict):
    for root in manifest.get("roots", []):
        rel = root.lstrip('/')
        src_root = os.path.join(staging_dir, rel)
        if not os.path.exists(src_root):
            continue
        for base, dirs, files in os.walk(src_root):
            rel_base = os.path.relpath(base, src_root)
            dest_base = root if rel_base == "." else os.path.join(root, rel_base)
            os.makedirs(dest_base, exist_ok=True)
            for d in dirs:
                os.makedirs(os.path.join(dest_base, d), exist_ok=True)
            for fn in files:
                s = os.path.join(base, fn)
                d = os.path.join(dest_base, fn)
                try:
                    shutil.copy2(s, d)
                except Exception as e:
                    print(f"[restore copy] Ошибка копирования {s} -> {d}: {e}")

def regenerate_crl_if_possible():
    if not AUTO_REGEN_CRL:
        return False, "AUTO_REGEN_CRL disabled"
    pki_root = os.path.join(EASYRSA_DIR, "pki")
    index_path = os.path.join(pki_root, "index.txt")
    ca_key = os.path.join(pki_root, "private", "ca.key")
    easyrsa_script = os.path.join(EASYRSA_DIR, "easyrsa")
    if not (os.path.exists(index_path) and os.path.exists(ca_key) and os.path.exists(easyrsa_script)):
        return False, "PKI incomplete (no index/ca.key/easyrsa)."
    try:
        subprocess.run(f"cd {EASYRSA_DIR} && EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl",
                       shell=True, check=True)
        crl_src = os.path.join(pki_root, "crl.pem")
        crl_dst = "/etc/openvpn/crl.pem"
        if os.path.exists(crl_src):
            shutil.copy2(crl_src, crl_dst)
            os.chmod(crl_dst, 0o644)
        return True, "CRL regenerated."
    except Exception as e:
        return False, f"CRL regen failed: {e}"

# ---------- Restore ----------

def apply_restore(archive_path: str, dry_run: bool = True) -> Dict:
    ts = _now_ts()
    staging_dir = f"{TMP_STAGING_PREFIX}{ts}"
    os.makedirs(staging_dir, exist_ok=True)
    try:
        manifest = load_manifest_from_archive(archive_path, staging_dir)
        diff = compute_diff(manifest)

        report = {
            "archive": archive_path,
            "dry_run": dry_run,
            "diff": diff,
            "purge_mode": "strict" if STRICT_PURGE else "none",
            "crl_action": None,
            "service_restart": None,
            "errors": []
        }

        if dry_run:
            return report

        if STRICT_PURGE and diff["extra"]:
            purge_extras(diff["extra"])

        copy_from_staging(staging_dir, manifest)

        success, msg = regenerate_crl_if_possible()
        report["crl_action"] = msg

        try:
            subprocess.run("systemctl restart openvpn@server || systemctl restart openvpn", shell=True, check=True)
            report["service_restart"] = "OK"
        except Exception as e:
            report["service_restart"] = f"Failed: {e}"
            report["errors"].append(str(e))

        return report
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)
