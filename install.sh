#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "== PasarGuard IP Monitor - Install =="

echo "Installing prerequisites..."
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_SUSPEND=1
export NEEDRESTART_MODE=a
sudo -E apt-get update -qq
sudo -E apt-get install -y -qq python3 python3-venv python3-pip > /dev/null

read -rp "Telegram bot token: " BOT_TOKEN
while [ -z "$BOT_TOKEN" ]; do read -rp "Cannot be empty, try again: " BOT_TOKEN; done

read -rp "Your numeric Telegram chat ID (owner): " OWNER_ID
while ! [[ "$OWNER_ID" =~ ^-?[0-9]+$ ]]; do read -rp "Must be a number: " OWNER_ID; done

cat > .env << ENVEOF
TELEGRAM_BOT_TOKEN=$BOT_TOKEN
OWNER_CHAT_ID=$OWNER_ID
ENVEOF

echo "Setting up virtualenv..."
python3 -m venv .venv
./.venv/bin/pip install --quiet --upgrade pip
./.venv/bin/pip install --quiet -r requirements.txt

SERVICE_NAME="pasarguard-ip-monitor"
CURRENT_USER="$(whoami)"

sudo tee "/etc/systemd/system/${SERVICE_NAME}.service" > /dev/null << SVEOF
[Unit]
Description=PasarGuard IP Monitor Telegram Bot
After=network.target

[Service]
Type=simple
User=$CURRENT_USER
WorkingDirectory=$SCRIPT_DIR
ExecStart=$SCRIPT_DIR/.venv/bin/python -u $SCRIPT_DIR/bot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVEOF

sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME" > /dev/null
sudo systemctl start "$SERVICE_NAME"

echo
echo "Done. Bot is running as a systemd service."
echo "Status:  sudo systemctl status $SERVICE_NAME"
echo "Logs:    sudo journalctl -u $SERVICE_NAME -f"
echo
echo "Now open Telegram and send /start to your bot."
