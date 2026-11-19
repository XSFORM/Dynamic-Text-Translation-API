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

ROUTERS_FILE = "/root/monitor_bot/routers.json"
WARMUP_S = 2
MEASURE_S = 6
PARALLEL_SET = (1, 2, 4, 8)
CHUNK_SET = (4096, 16384, 32768)


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


def run_parallel(cli, n, chunk, seconds, warmup):
    """n потоков одновременно. Складываем байты, делим на общее время."""
    chans = [open_stream(cli) for _ in range(n)]
    results = [None] * n

    def worker(i):
        try:
            results[i] = pump(chans[i], chunk, seconds, warmup)
        except Exception as e:
            results[i] = (0, 0.0, str(e))

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
    total = sum(r[0] for r in results if r and len(r) >= 2)
    # Делим на измеренное окно, а не на всё время вместе с прогревом.
    span = max((r[1] for r in results if r and len(r) >= 2 and r[1] > 0), default=0)
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

    print(f"\nРазмер куска (1 поток, {MEASURE_S}с замера):")
    for chunk_size in CHUNK_SET:
        chunk = os.urandom(chunk_size)
        chan = open_stream(cli)
        try:
            sent, spent = pump(chan, chunk, MEASURE_S, WARMUP_S)
            mbps = sent * 8 / spent / 1_000_000
            print(f"  {chunk_size:>6} байт -> {mbps:6.2f} Мбит/с")
        except Exception as e:
            print(f"  {chunk_size:>6} байт -> ошибка: {e}")
        finally:
            try:
                chan.close()
            except Exception:
                pass

    best_chunk = os.urandom(16384)
    print(f"\nПараллельные потоки (кусок 16384, {MEASURE_S}с замера):")
    for n in PARALLEL_SET:
        try:
            total, span, wall = run_parallel(cli, n, best_chunk, MEASURE_S, WARMUP_S)
            mbps = total * 8 / span / 1_000_000 if span else 0
            print(f"  {n} поток(ов) -> {mbps:6.2f} Мбит/с  (всего {total/1024/1024:.1f} МБ за {wall:.1f}с)")
        except Exception as e:
            print(f"  {n} поток(ов) -> ошибка: {e}")

    cli.close()
    print("\nЕсли с ростом числа потоков скорость растёт почти линейно —")
    print("упор в окно SSH, лечится параллельными каналами.")


if __name__ == "__main__":
    main()
