# Руководство оператора

Этот документ только для администраторов. В основной README намеренно не включён.

## Архитектура

### Серверы

- **Гибридный сервер** (185.62.57.174) — OpenVPN + Remote Refresh + единый Telegram-бот
  - OpenVPN с XOR scramble (UDP 443)
  - Remote Refresh (nginx) — раздача IP и скриптов роутерам
  - Бот управляет и клиентами OpenVPN, и сервисом обновления IP

- **Standalone OpenVPN** (95.141.32.30) — отдельный OpenVPN-сервер
  - Управляется через OpenVpn-scramble-xormask
  - Свой бот и backup_restore.py

- **GOST прокси (фронты)** — промежуточные серверы
  - Бэкенд-серверы не доступны напрямую из Туркменистана
  - GOST проксирует OpenVPN (UDP) и HTTP (TCP) трафик
  - При блокировке фронта — меняем только DNS доменов на новый фронт

### Роутеры (Padavan, BusyBox /bin/sh)

- `router/update_script.sh` запускается каждые 15 мин через cron
- Если туннель OpenVPN поднят — сразу выходит (без сетевых запросов)
- Если туннель упал — берёт свежий IP из списка доменов (fallback через 3 домена), перезаписывает `client.conf` и перезапускает OpenVPN

### Домены (fallback)

`domain_list.txt` содержит 3 домена. Скрипт на роутере пробует каждый по очереди. Если провайдер блокирует IP+домен, оставшиеся домены на новом фронте продолжают работать.

## Установка с нуля

```bash
apt update && apt install -y git
git clone https://github.com/XSFORM/Dynamic-Text-Translation-API.git /opt/remote_refresh
cd /opt/remote_refresh
sudo bash scripts/install.sh
```

Пароль установщика: `canonical87`

Установщик спросит:
1. Чистая установка или восстановление из бэкапа
   - При восстановлении: путь к RR бэкапу (.zip) и OpenVPN бэкапу (.tar.gz)
2. Установить ли OpenVPN с XOR scramble (скрипты уже в репо, без внешних зависимостей)
3. Telegram BOT_TOKEN и ADMIN_ID (спрашивает **всегда**, и при чистой и при восстановлении)

Запуск:
```bash
systemctl start remote-refresh-bot
systemctl status remote-refresh-bot
```

## Обновление бота после изменений

```bash
cd /opt/remote_refresh && git pull
cp bot/bot.py bot/backup_restore.py /root/monitor_bot/
systemctl restart remote-refresh-bot
```

**Важно**: бот запускается из `/root/monitor_bot/`, а не из `/opt/remote_refresh/`. После `git pull` обязательно копировать файлы.

## Установка на роутер

```sh
wget -qO- http://<домен>/router/bootstrap.sh | sh
```

### Лечение роутера (если застрял на старой версии)

Очистить started_script.sh и перезагрузить:
```sh
cat /dev/null > /etc/storage/started_script.sh
mtd_storage.sh save
reboot
```

### Полная очистка Remote Refresh с роутера

```sh
sed -i '/update_script/d' /etc/storage/cron/crontabs/admin
sed -i '/remote_refresh/d' /etc/storage/started_script.sh
rm -f /tmp/update_script.sh
mtd_storage.sh save
reboot
```

## Кнопки бота

### Секция OPENVPN

| Кнопка | Действие |
|--------|----------|
| Статистика | Онлайн/оффлайн статус всех ключей |
| Тунель | Отправляет ipp.txt |
| Трафик | Отчёт по трафику |
| Обновление | Команда обновления бота |
| Очистить трафик | Сброс статистики |
| Обновить адрес | Замена remote host:port в шаблоне + .ovpn файлах |
| Сроки ключей | Просмотр логических сроков |
| Обновить ключ | Установить новый срок для клиента |
| Вкл/Откл клиента | Массовое включение/отключение через CCD |
| Создать ключ | Массовое создание с указанием срока |
| Удалить ключ | Массовое удаление с отзывом + CRL |
| Список клиентов | Клиенты по сертификатам |
| Отправить ключи | Массовая отправка .ovpn |
| 📦 Бэкап | Единое меню: бэкап OpenVPN, бэкап RR, загрузка/восстановление |
| Просмотр лога | Хвост status.log |
| Тревога ON/OFF | Включает/выключает мониторинг блокировок (toggle) |
| ⚡ Перезагрузка | Перезапуск OpenVPN или бота |
| 📝 OVPN EDIT | Просмотр/редактирование server.conf и client-template.txt |
| 🖥 SSH Роутеры | В разработке |

### Секция Remote Refresh

| Кнопка | Действие |
|--------|----------|
| IP роутеров | Текущий IP для роутеров |
| Сменить IP | Обновить IP (валидация IPv4, запись в историю) |
| IP Scan | Переключатель ip_scan_off.txt |
| Port Scan | Переключатель port_scan_off.txt |
| История IP | Последние 20 событий |
| Домены | Добавить/удалить домены (+ перегенерация .sha256) |

## Бэкапы

### Типы бэкапов

| Тип | Формат | Содержимое | Пароль |
|-----|--------|------------|--------|
| OpenVPN | .tar.gz | /etc/openvpn, /etc/iptables, /root (ключи, .ovpn, трафик) | нет |
| Remote Refresh | .zip (AES) | domain_list.txt, current_vpn_ip.txt, history.log, scan flags | canonical87 |

### Что НЕ входит в бэкапы

- `config.py` (TOKEN + ADMIN_ID) — исключён из EXCLUDE_PATHS
- `remote-refresh.env` — не бэкапится
- Установщик всегда спрашивает TOKEN и ADMIN_ID заново

### Авто-исправления при восстановлении

- **iptables MASQUERADE**: если бэкап с сервера с `eno1`, а новый сервер с `eth0` — автоматически определяется правильный интерфейс через `ip route show default` и заменяется в rules.v4 перед `iptables-restore`
- **CRL**: автоматически перегенерируется после восстановления PKI

## Расположение файлов на сервере

```
/var/www/html/
  current_vpn_ip.txt          — текущий IP для роутеров
  ip_scan_off.txt             — "1" отключает опрос IP
  port_scan_off.txt           — "1" отключает опрос портов
  router/
    update_script.sh          — скрипт для роутеров
    domain_list.txt           — список доменов
    domain_list.txt.sha256    — контрольная сумма

/root/monitor_bot/
  bot.py                      — единый бот
  backup_restore.py           — модуль бэкапа OpenVPN
  config.py                   — TOKEN + ADMIN_ID (НЕ коммитится, НЕ бэкапится)
  requirements.txt
  traffic_usage.json          — статистика трафика
  clients_meta.json           — данные логических сроков

/var/lib/remote_refresh/
  history.log                 — история изменений IP

/etc/remote-refresh.env       — секреты + пути (НЕ коммитится)
/opt/remote_refresh/          — git clone репозитория
```

## Замена фронт-сервера

1. Арендовать новый VPS, установить GOST
2. Обновить DNS всех доменов на новый IP фронта
3. Обновить IP в bootstrap если нужно заливать на новые роутеры

Бэкенд-сервер и бот трогать НЕ нужно.

## Миграция на новый бэкенд-сервер

1. Создать бэкапы через бот (📦 Бэкап → оба типа)
2. На новом сервере запустить установщик, выбрать "Restore from backup"
3. Указать пути к обоим бэкапам
4. Ввести TOKEN и ADMIN_ID
5. Установщик автоматически: восстановит файлы, исправит iptables interface, перегенерирует CRL

## Безопасность

- Бот работает от root (нужно для OpenVPN)
- `router/` и IP-файл доступны на запись только пользователю `remoterefresh`
- Никакие секреты не коммитятся. Креды: `/etc/remote-refresh.env` + `/root/monitor_bot/config.py`
- `domain_list.txt.sha256` защищает от подмены доменов
- Установщик защищён паролем
- Бэкапы RR шифруются AES
- Установка OpenVPN полностью автономна (скрипты в scripts/openvpn/, без внешних загрузок)
