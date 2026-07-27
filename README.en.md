English | [فارسی](README.md) 🌐

# PasarGuard IP Monitor Bot 🤖

A Telegram bot that keeps an eye on your PasarGuard panel and pings you when a user's config is connected from too many IPs at once (usually means it's being shared).

## What it does

Every 10 minutes, it checks online users and counts unique IPs per user. If someone crosses the limit (default 8, changeable from inside the bot), you get an instant alert. There's also a button to manually check a specific user and see their exact IP list.

Only you (the owner) can use it — anyone else messaging the bot gets ignored.

## Requirements

- A basic Ubuntu server (even a cheap/small one is fine)
- A Telegram bot from [@BotFather](https://t.me/BotFather) — keep the token
- Your numeric Telegram chat ID (not username) — get it from [@userinfobot](https://t.me/userinfobot)

## Install

```bash
git clone https://github.com/mmd-Ranger/pasarguard-ip-monitor.git
cd pasarguard-ip-monitor
chmod +x install.sh
./install.sh
```

The script installs all prerequisites (Python, venv) and sets up a systemd service automatically. It only asks for your bot token and owner chat ID.

## First run

Open Telegram and send `/start`. Since the panel isn't linked yet, it'll ask for the panel URL, then admin username, then password — and actually test the connection, telling you if it succeeded or failed. This info is stored only on your own server. You can change it anytime from the bot menu.

## Uninstall

```bash
chmod +x uninstall.sh
./uninstall.sh
```

## If it ever goes down

```bash
sudo systemctl status pasarguard-ip-monitor
sudo journalctl -u pasarguard-ip-monitor -f
```
It auto-restarts on crash, so no need to worry.

## FAQ

**Do I need a domain or SSL?** No, not at all.

**Is my password safe?** Yes, nothing is hardcoded in the code — everything lives only on your server.

## License

MIT
