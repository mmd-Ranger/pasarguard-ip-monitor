English | [فارسی](README.md) 🌐

# PasarGuard IP Monitor Bot 🤖

A Telegram bot that monitors the number of connected IPs per user on a PasarGuard panel and sends an automatic alert when a user exceeds the allowed limit (a possible sign of config sharing).

## Features

- Automatic check every 10 minutes (configurable), only for online users, to keep it fast and reduce load on the panel
- Parallel checking (multiple concurrent requests) for speed
- Telegram alert when a user's unique IP count exceeds the limit (with a cooldown to prevent spam)
- Configurable IP limit from within the bot itself
- Manual check of a specific user, showing exact IPs broken down by node
- Check history (Tehran time) to confirm the automatic check is actually running
- Panel URL and admin credentials configured entirely from within the bot, no file editing required
- Restricted to the owner only; no other user can use the bot
- No secrets or tokens in the code; everything is stored in local config files (git-ignored)

## Requirements

- A basic Ubuntu server (even limited resources are enough)
- A Telegram bot created via [@BotFather](https://t.me/BotFather) (keep the token)
- Your numeric Telegram ID (not username) — obtainable from [@userinfobot](https://t.me/userinfobot)

## Installation

```bash
git clone https://github.com/mmd-Ranger/pasarguard-ip-monitor.git
cd pasarguard-ip-monitor
chmod +x install.sh
./install.sh
```

The install script sets up prerequisites (Python, venv) and the systemd service automatically. It only asks for two things: your Telegram bot token and your numeric chat ID.

## First run

After installation, send `/start` to the bot on Telegram. Since the panel hasn't been configured yet, it will ask in order for:
1. Panel URL (without a path, just the dashboard address; e.g. `https://panel.example.com`)
2. Admin username
3. Admin password

After receiving all three, the bot attempts to connect to the panel and reports whether it succeeded or the exact error. This data is stored only on your own server and never sent anywhere else. You can change it anytime from the bot menu: **🛠 Panel Settings**.

## Full removal

```bash
chmod +x uninstall.sh
./uninstall.sh
```

## Managing the service

```bash
sudo systemctl status pasarguard-ip-monitor    # status
sudo journalctl -u pasarguard-ip-monitor -f    # live logs
sudo systemctl restart pasarguard-ip-monitor   # restart
```

The service is configured with `Restart=always`; if it crashes, it restarts automatically within a few seconds.

## FAQ

**Do I need a domain or webhook?**
No. The bot uses polling, so no domain, SSL, or webhook is required.

**Are my credentials safe?**
Yes. No secrets or tokens are in the code; everything is stored only on your own server, in files that are never committed.

## Contributing

Issues and Pull Requests are welcome.

## License

MIT
