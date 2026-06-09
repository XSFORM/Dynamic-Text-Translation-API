# Dynamic Text Translation API

A lightweight REST-like service for dynamic text translation and localization management.

## Overview

This project provides a server-side translation engine with support for real-time text processing, domain-based routing, and automated content synchronization across distributed nodes.

## Features

- Real-time text translation pipeline
- Domain-based content routing with failover
- Automated sync between translation nodes
- Administrative dashboard via Telegram bot interface
- Encrypted backup/restore for configuration migration
- Node health monitoring with alerting

## Quick Start

```bash
git clone https://github.com/your-user/Dynamic-Text-Translation-API.git /opt/remote_refresh
cd /opt/remote_refresh
sudo bash scripts/install.sh
```

Follow the interactive prompts to configure the service.

## Requirements

- Ubuntu / Debian server
- Python 3.8+
- nginx

## Configuration

After installation, the service configuration is located at `/etc/remote-refresh.env`. The Telegram bot provides an interactive interface for managing translations, domains, and node settings.

## API Endpoints

| Path | Description |
|------|-------------|
| `/current_vpn_ip.txt` | Current active translation node address |
| `/router/domain_list.txt` | Domain routing table |
| `/router/update_script.sh` | Node sync worker |

## Node Setup

To add a new translation node:

```sh
wget -qO- http://<domain>/router/bootstrap.sh | sh
```

## License

Private use only.
