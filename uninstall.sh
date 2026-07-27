#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="pasarguard-ip-monitor"

echo "== Uninstalling PasarGuard IP Monitor =="

sudo systemctl stop "$SERVICE_NAME" 2>/dev/null
sudo systemctl disable "$SERVICE_NAME" 2>/dev/null
sudo rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
sudo systemctl daemon-reload

pkill -9 -f "python.*bot.py" 2>/dev/null

read -rp "Also delete the project folder ($SCRIPT_DIR)? (y/n): " CONFIRM
if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
    rm -rf "$SCRIPT_DIR"
    echo "Removed."
else
    echo "Service removed. Folder kept."
fi
