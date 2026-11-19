#!/usr/bin/env python3
"""
Диагностика спидтеста по SSH.

Зачем: замер в один поток показал 0.2 Мбит/с там, где HTTP даёт 2.8.
Подозрение на окно SSH у dropbear — при большом RTT пропускная способность
упирается в "окно / задержка", а не в канал. Скрипт показывает реальные
договорённые параметры канала и сравнивает один поток с несколькими.

Запуск на бэкенде:
    python3 speed_diag.py <имя_роутера> <vpn_ip>
    python3 speed_diag.py pop 10.9.0.23
"""
import json
import os
import sys
import threading
import time

import paramiko

# Локаль на сервере может быть latin-1, тогда кириллица в print падает.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROUTERS_FILE = "/root/monitor_bot/routers.json"
WARMUP_S = 2
MEASURE_S = 6
PARALLEL_SET = (1, 2, 4)
# Большие куски проверяем специально: если скорость растёт с размером,
# значит упор в накладные расходы на вызов, а не в полосу.
CHUNK_SET = (32768, 131072, 524288, 1048576)
REPEATS = 3


def connect(ip, port, user, password):
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(ip, port=port, username=user, password=password,
                timeout=15, look_for_keys=False, allow_agent=False)
    return cli


def pump(chan, chunk, seconds, warmup):
    """Лить в канал. Прогрев выбрасывается, меряется только вторая фаза."""
    warm_end = time.monotonic() + warmup
    while time.monotonic() < warm_end:
        chan.sendall(chunk)
    sent = 0
    started = time.monotonic()
    deadline = started + seconds
    while time.monotonic() < deadline:
        chan.sendall(chunk)
        sent += len(chunk)
    return sent, time.monotonic() - started


def open_stream(cli, timeout=60):
    chan = cli.get_transport().open_session(timeout=15)
    chan.settimeout(timeout)
    chan.exec_command("cat > /dev/null")
    return chan


def run_parallel(conns, chunk, seconds, warmup):
    """Параллель через ОТДЕЛЬНЫЕ соединения.

    Каналы на одном Transport делят общую блокировку paramiko и вместо
    параллельной работы мешают друг другу — прошлый прогон это показал.
    Отдельные соединения = отдельные сокеты и потоки, без общей блокировки.
    """
    n = len(conns)
    chans = [open_stream(c) for c in conns]
    results = [None] * n

    def worker(i):
        try:
            results[i] = pump(chans[i], chunk, seconds, warmup)
        except Exception:
            results[i] = (0, 0.0)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.monotonic() - t0
    for c in chans:
        try:
            c.close()
        except Exception:
            pass
    total = sum(r[0] for r in results if r)
    span = max((r[1] for r in results if r and r[1] > 0), default=0)
    return total, span, wall


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    name, ip = sys.argv[1], sys.argv[2]
    with open(ROUTERS_FILE) as f:
        routers = json.load(f)
    r = routers.get(name)
    if not r:
        print(f"Роутер {name} не найден в {ROUTERS_FILE}")
        sys.exit(1)

    print(f"Подключаюсь к {name} ({ip})...")
    cli = connect(ip, int(r.get("port", 22)), r.get("user", "admin"),
                  r.get("password", ""))
    tr = cli.get_transport()
    print(f"Шифр:       {tr.local_cipher}")
    print(f"Сжатие:     {tr.local_compression}  (должно быть none)")
    print(f"Сервер:     {tr.remote_version}")

    probe = open_stream(cli)
    print(f"Окно SSH:   {probe.out_window_size} байт   <-- ключевая цифра")
    print(f"Макс.пакет: {probe.out_max_packet_size} байт")
    rtt_hint = probe.out_window_size * 8 / 0.110 / 1_000_000
    print(f"Потолок при RTT 110мс в один поток: ~{rtt_hint:.2f} Мбит/с")
    probe.close()

    print(f"\nРазмер куска, {REPEATS} прогона по {MEASURE_S}с (1 поток):")
    print("  размер      прогоны (Мбит/с)        медиана")
    for chunk_size in CHUNK_SET:
        chunk = os.urandom(chunk_size)
        runs = []
        for _ in range(REPEATS):
            chan = open_stream(cli)
            try:
                sent, spent = pump(chan, chunk, MEASURE_S, WARMUP_S)
                runs.append(sent * 8 / spent / 1_000_000)
            except Exception as e:
                print(f"  {chunk_size:>8} -> ошибка: {e}")
                break
            finally:
                try:
                    chan.close()
                except Exception:
                    pass
        if runs:
            med = sorted(runs)[len(runs) // 2]
            shown = "  ".join(f"{v:5.2f}" for v in runs)
            print(f"  {chunk_size:>8}   {shown}    {med:6.2f}")

    big = os.urandom(262144)
    print(f"\nПараллель через ОТДЕЛЬНЫЕ соединения (кусок 256К, {MEASURE_S}с):")
    for n in PARALLEL_SET:
        conns = []
        try:
            for _ in range(n):
                conns.append(connect(ip, int(r.get("port", 22)),
                                     r.get("user", "admin"), r.get("password", "")))
            total, span, wall = run_parallel(conns, big, MEASURE_S, WARMUP_S)
            mbps = total * 8 / span / 1_000_000 if span else 0
            print(f"  {n} соед. -> {mbps:6.2f} Мбит/с  (всего {total/1024/1024:.1f} МБ за {wall:.1f}с)")
        except Exception as e:
            print(f"  {n} соед. -> ошибка: {e}")
        finally:
            for c in conns:
                try:
                    c.close()
                except Exception:
                    pass

    cli.close()
    print("\nЧто смотреть:")
    print("  - если с ростом куска скорость растёт и выходит на полку —")
    print("    упор был в накладные расходы на вызов, берём большой кусок;")
    print("  - если отдельные соединения дают прирост — гоним в несколько;")
    print("  - если везде потолок ~5 Мбит/с — это аплинк самого бэкенда.")


if __name__ == "__main__":
    main()
