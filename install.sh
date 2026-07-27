#!/usr/bin/env bash
# نصب و راه‌اندازی ربات مانیتور IP پنل PasarGuard
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=================================================="
echo "  نصب ربات مانیتور IP پنل PasarGuard"
echo "=================================================="
echo

if ! command -v python3 &> /dev/null; then
    echo "❌ python3 پیدا نشد. اول پایتون ۳ رو نصب کن."
    exit 1
fi

# ---------- گرفتن اطلاعات لازم ----------
read -rp "توکن ربات تلگرام (از @BotFather): " BOT_TOKEN
while [ -z "$BOT_TOKEN" ]; do
    read -rp "توکن نمی‌تونه خالی باشه، دوباره وارد کن: " BOT_TOKEN
done

echo
echo "آیدی عددی خودت رو لازم داریم (نه یوزرنیم!). اگه نمی‌دونی چیه،"
echo "به ربات @userinfobot تو تلگرام پیام بده تا آیدی عددیت رو بهت بگه."
read -rp "آیدی عددی تلگرام (Owner Chat ID): " OWNER_ID
while ! [[ "$OWNER_ID" =~ ^-?[0-9]+$ ]]; do
    read -rp "این یه عدد نبود، دوباره وارد کن: " OWNER_ID
done

# ---------- ساخت .env ----------
cat > .env << EOF
TELEGRAM_BOT_TOKEN=$BOT_TOKEN
OWNER_CHAT_ID=$OWNER_ID
EOF
echo "✅ فایل .env ساخته شد."

# ---------- ساخت محیط مجازی و نصب پکیج‌ها ----------
echo
echo "در حال ساخت محیط مجازی پایتون و نصب پکیج‌ها..."
python3 -m venv .venv
./.venv/bin/pip install --quiet --upgrade pip
./.venv/bin/pip install --quiet -r requirements.txt
echo "✅ پکیج‌ها نصب شدن."

# ---------- ساخت سرویس systemd (نیاز به sudo) ----------
echo
read -rp "می‌خوای به‌عنوان سرویس systemd نصب بشه که همیشه روشن بمونه و بعد از ریبوت هم بالا بیاد؟ (y/n): " USE_SYSTEMD

if [[ "$USE_SYSTEMD" =~ ^[Yy]$ ]]; then
    SERVICE_NAME="pasarguard-ip-monitor"
    CURRENT_USER="$(whoami)"
    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

    sudo tee "$SERVICE_FILE" > /dev/null << EOF
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
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable "$SERVICE_NAME"
    sudo systemctl start "$SERVICE_NAME"

    echo
    echo "✅ سرویس نصب و استارت شد."
    echo "   وضعیت:      sudo systemctl status $SERVICE_NAME"
    echo "   لاگ زنده:   sudo journalctl -u $SERVICE_NAME -f"
    echo "   ری‌استارت:  sudo systemctl restart $SERVICE_NAME"
    echo "   توقف:       sudo systemctl stop $SERVICE_NAME"
else
    echo
    echo "باشه، پس خودت دستی اجراش کن:"
    echo "   ./.venv/bin/python -u bot.py"
fi

echo
echo "=================================================="
echo "  نصب تموم شد!"
echo "  حالا برو تو تلگرام به ربات /start بزن."
echo "  اول ازت آدرس پنل و اطلاعات ادمین رو می‌پرسه."
echo "=================================================="
