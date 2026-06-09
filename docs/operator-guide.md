# Operator Guide

This document is for system maintainers only. It is intentionally kept out of the main README.

## Architecture overview

- **Server**: Linux VPS (95.141.32.30) running OpenVPN + nginx + unified Telegram bot.
  - OpenVPN traffic is proxied via GOST front (UDP 443).
  - Remote Refresh (nginx) is proxied via a separate GOST front (TCP 80).
  - The bot manages both OpenVPN clients and the router IP update service.

- **Routers** (Padavan firmware, BusyBox `/bin/sh`):
  - `router/update_script.sh` runs every 15 min via cron.
  - If the OpenVPN tunnel is up -> exits immediately (no network fetch).
  - If the tunnel is down -> fetches a fresh IP from the domain list, rewrites `client.conf`, and reloads OpenVPN.

## Server installation

```bash
git clone <repo> /opt/remote_refresh
cd /opt/remote_refresh
sudo bash scripts/install.sh
```

The installer will ask for a password, then offer:
1. Clean install or restore from backup
2. Whether to install OpenVPN with XOR scramble
3. Telegram BOT_TOKEN and ADMIN_ID (clean install only)

Start the service:
```bash
sudo systemctl start remote-refresh-bot
sudo systemctl status remote-refresh-bot
```

## Router installation

Run on the router as root:
```sh
wget -qO- http://<your-domain>/router/bootstrap.sh | sh
```

## Bot commands / buttons

### OpenVPN section (upper menu)

| Button              | Action                                          |
|---------------------|-------------------------------------------------|
| Список клиентов     | Shows clients by certificate                    |
| Статистика          | Online/offline status of all keys               |
| Тунель              | Sends ipp.txt                                   |
| Трафик              | Traffic usage report                            |
| Обновление          | Bot update command                              |
| Очистить трафик     | Reset traffic stats                             |
| Обновить адрес      | Update remote host:port in template + .ovpn     |
| Сроки ключей        | Logical expiry view                             |
| Обновить ключ       | Set new logical expiry for a client             |
| Вкл/Откл клиента    | Bulk enable/disable via CCD                     |
| Создать ключ        | Multi-create with expiry                        |
| Удалить ключ        | Bulk delete with revoke + CRL                   |
| Отправить ключи     | Bulk send .ovpn files                           |
| Просмотр лога       | Tail of status.log                              |
| Бэкап OpenVPN       | Full snapshot backup (/etc/openvpn, /root, etc) |
| Восстан.бэкап       | Diff + hard restore                             |
| Тревога блокировки  | Monitoring alert info                           |

### Remote Refresh section (lower menu)

| Button         | Action                                                    |
|----------------|-----------------------------------------------------------|
| IP роутеров    | Shows the IP currently served to routers                  |
| Сменить IP     | Update the served IP (validates IPv4, logs to history)    |
| История IP     | Shows the last 20 IP-change events                       |
| Бэкап RR       | AES-encrypted zip backup of RR config                     |
| IP Scan        | Toggles ip_scan_off.txt (pause IP polling on routers)     |
| Port Scan      | Toggles port_scan_off.txt                                 |
| Домены         | Add / remove domains in domain_list.txt (+ regen .sha256) |

## Domain list management

The bot's Domains button lets you add or remove domains interactively. After each change the bot rewrites `domain_list.txt` and regenerates `domain_list.txt.sha256`.

Manual edit: update `/var/www/html/router/domain_list.txt`, then run:
```bash
sha256sum /var/www/html/router/domain_list.txt > /var/www/html/router/domain_list.txt.sha256
```

## File layout (server)

```
/var/www/html/
  current_vpn_ip.txt          <- current OpenVPN server IP for routers
  ip_scan_off.txt             <- "1" disables IP polling on routers
  port_scan_off.txt           <- "1" disables port polling on routers
  router/
    update_script.sh          <- worker script served to routers
    domain_list.txt           <- list of domains
    domain_list.txt.sha256    <- sha256 of domain_list.txt
/var/lib/remote_refresh/
  history.log                 <- IP-change history
/root/monitor_bot/
  bot.py                      <- unified bot
  backup_restore.py           <- OpenVPN backup/restore module
  config.py                   <- TOKEN + ADMIN_ID (not committed)
  requirements.txt
  traffic_usage.json          <- traffic stats
  clients_meta.json           <- logical expiry data
/etc/remote-refresh.env       <- secrets + paths (not committed)
/opt/remote_refresh/          <- git clone of this repository
```

## Changing the front server

If the ISP blocks the current front IP:
1. Rent a new VPS, install GOST
2. Update DNS for all domains to the new front IP
3. Update the bootstrap one-liner IP if deploying to new routers

The backend server (95.141.32.30) and the bot do NOT need to be touched.

## Security notes

- The bot runs as root (required for OpenVPN key management).
- The webroot `router/` directory and IP file are writable by `remoterefresh`.
- No secrets are committed to this repository. Credentials live in `/etc/remote-refresh.env` and `/root/monitor_bot/config.py`.
- The `domain_list.txt.sha256` prevents a network attacker from injecting hostile domains.
- The connected-check gate in `update_script.sh` eliminates the cleartext polling fingerprint while the tunnel is healthy.
- Installer is password-protected (canonical87).
- Remote Refresh backups are AES-encrypted (canonical87).
