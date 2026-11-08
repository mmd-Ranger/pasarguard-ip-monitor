#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ربات تلگرام مانیتور IP پنل PasarGuard

نصب و راه‌اندازی: به فایل README.md مراجعه کن یا از install.sh استفاده کن.

نکته‌ی امنیتی: این فایل هیچ رمز/توکنی داخلش نداره. همه چیز از فایل .env
(توکن ربات + آیدی عددی مالک) و panel_config.json (آدرس پنل + یوزر/پسورد ادمین،
که از داخل خود ربات تنظیم می‌شه) خونده می‌شه.
"""

import concurrent.futures
import datetime
import html
import ipaddress
import json
import logging
import os
import random
import sys
import threading
import time
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# ================== تنظیمات ثابت (از .env، فقط این دوتا لازمه برای بالا اومدن ربات) ==================
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
_owner_raw = os.environ.get("OWNER_CHAT_ID")

if not TELEGRAM_BOT_TOKEN or not _owner_raw:
    print("❌ فایل .env پیدا نشد یا کامل نیست.")
    print("   TELEGRAM_BOT_TOKEN و OWNER_CHAT_ID رو تنظیم کن (install.sh رو اجرا کن) یا دستی .env بساز.")
    sys.exit(1)

try:
    OWNER_CHAT_ID = int(_owner_raw)
except ValueError:
    print("❌ OWNER_CHAT_ID باید یه عدد باشه (آیدی عددی خودت تو تلگرام).")
    sys.exit(1)

# ================== تنظیمات قابل تغییر ==================
DEFAULT_MAX_ALLOWED_IPS = 8
DEFAULT_CHECK_INTERVAL_MINUTES = 15  # فاصله‌ی بررسی خودکار (دقیقه) - قابل تغییر از داخل ربات
ALERT_COOLDOWN_SECONDS = 1800      # هر یوزر حداکثر هر ۳۰ دقیقه یک بار هشدار بگیره
ONLINE_WINDOW_SECONDS = 120        # یوزر رو "آنلاین" حساب کن اگه online_at توی این بازه بوده
REQUEST_TIMEOUT = 15
MAX_WORKERS = 12                   # تعداد درخواست همزمان به پنل
HISTORY_KEEP = 50
CONFIRM_DELAY_SECONDS = 20         # قبل از هشدار، یوزرهای بالای حد دوباره چک می‌شن (کم‌ترین عدد دو بار ملاک است)
MAX_FUTURE_SKEW = 300              # زمان IP که بیش از این (ثانیه) در آینده باشه، مشکوک حساب می‌شه و تازه نیست
DEFAULT_IP_FRESH_WINDOW_MINUTES = 5  # فقط IPهایی که تو این بازه دیده شدن شمرده می‌شن - قابل تغییر از داخل ربات

TEHRAN_TZ = ZoneInfo("Asia/Tehran")

CANDIDATE_IP_ENDPOINTS = [
    "/api/node/online_stats/{id}/ip",
    "/api/user/by-id/{id}/ip",
    "/api/user/by-id/{id}/ips",
    "/api/user/by-id/{id}/online_ips",
    "/api/user/{id}/ip",
    "/api/user/{id}/ips",
    "/api/user/{id}/online_ips",
    "/api/user/{id}/nodes/ip",
    "/api/user/{username}/ip",
]

STATE_FILE = BASE_DIR / "bot_state.json"
PANEL_CONFIG_FILE = BASE_DIR / "panel_config.json"
TG_API = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("pg_bot")

# ================== وضعیت مشترک ==================
state_lock = threading.Lock()
runtime = {
    "working_endpoint": None,
    "last_check_time": None,
    "last_check_over_limit": [],
    "alert_state": {},
    "panel_token": None,
    "panel_token_time": 0,
    "max_allowed_ips": DEFAULT_MAX_ALLOWED_IPS,
    "check_interval_minutes": DEFAULT_CHECK_INTERVAL_MINUTES,
    "ip_fresh_window_minutes": DEFAULT_IP_FRESH_WINDOW_MINUTES,
    "check_history": [],
    "pending_action": {},   # chat_id -> "set_limit" | "check_user" | "set_panel_url" | "set_panel_username" | "set_panel_password"
}


def fmt_tehran(epoch) -> str:
    if not epoch:
        return "—"
    dt = datetime.datetime.fromtimestamp(epoch, TEHRAN_TZ)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ================== تنظیمات پنل (قابل ویرایش از داخل ربات) ==================
def load_panel_config():
    if PANEL_CONFIG_FILE.exists():
        try:
            return json.loads(PANEL_CONFIG_FILE.read_text())
        except Exception:
            return None
    return None


def save_panel_config(cfg: dict):
    PANEL_CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))
    # با عوض شدن تنظیمات پنل، توکن و endpoint کش‌شده دیگه معتبر نیست
    runtime["panel_token"] = None
    runtime["panel_token_time"] = 0


def panel_is_configured() -> bool:
    cfg = load_panel_config()
    return bool(cfg and cfg.get("base_url") and cfg.get("username") and cfg.get("password"))


# ================== ذخیره/بارگذاری وضعیت ربات ==================
def load_state():
    if STATE_FILE.exists():
        try:
            saved = json.loads(STATE_FILE.read_text())
            runtime["alert_state"] = saved.get("alert_state", {})
            runtime["working_endpoint"] = saved.get("working_endpoint")
            runtime["max_allowed_ips"] = saved.get("max_allowed_ips", DEFAULT_MAX_ALLOWED_IPS)
            runtime["check_interval_minutes"] = saved.get("check_interval_minutes", DEFAULT_CHECK_INTERVAL_MINUTES)
            runtime["ip_fresh_window_minutes"] = saved.get("ip_fresh_window_minutes", DEFAULT_IP_FRESH_WINDOW_MINUTES)
            runtime["check_history"] = saved.get("check_history", [])
        except Exception:
            pass


def save_state():
    # نوشتن اتمیک (اول فایل موقت، بعد جایگزینی) تا با چند thread هم فایل خراب نشه
    try:
        with state_lock:
            tmp = STATE_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps({
                "alert_state": runtime["alert_state"],
                "working_endpoint": runtime["working_endpoint"],
                "max_allowed_ips": runtime["max_allowed_ips"],
                "check_interval_minutes": runtime["check_interval_minutes"],
                "ip_fresh_window_minutes": runtime["ip_fresh_window_minutes"],
                "check_history": runtime["check_history"][-HISTORY_KEEP:],
            }))
            tmp.replace(STATE_FILE)
    except Exception as e:
        log.warning(f"ذخیره state ناموفق: {e}")


# ================== ارتباط با پنل ==================
class PanelNotConfigured(Exception):
    pass


def get_panel_token(force=False) -> str:
    cfg = load_panel_config()
    if not cfg:
        raise PanelNotConfigured("پنل هنوز تنظیم نشده")

    if not force and runtime["panel_token"] and (time.time() - runtime["panel_token_time"] < 1200):
        return runtime["panel_token"]

    resp = requests.post(
        f"{cfg['base_url']}/api/admin/token",
        data={"username": cfg["username"], "password": cfg["password"]},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]
    runtime["panel_token"] = token
    runtime["panel_token_time"] = time.time()
    return token


def get_all_users(token: str) -> list:
    cfg = load_panel_config()
    headers = {"Authorization": f"Bearer {token}"}
    users, offset, limit = [], 0, 100
    while True:
        resp = requests.get(
            f"{cfg['base_url']}/api/users",
            headers=headers, params={"offset": offset, "limit": limit},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("users", [])
        users.extend(batch)
        total = data.get("total", len(users))
        offset += limit
        if offset >= total or not batch:
            break
    return users


def parse_iso_to_epoch(ts):
    if not ts:
        return None
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.datetime.fromisoformat(ts).timestamp()
    except Exception:
        return None


def is_recently_online(user, window=ONLINE_WINDOW_SECONDS) -> bool:
    epoch = parse_iso_to_epoch(user.get("online_at"))
    if epoch is None:
        return False
    return (time.time() - epoch) <= window


def normalize_ip(ip):
    """IPv6 رو به /64 تبدیل می‌کنه (آدرس‌های موقت/privacy یه دستگاه رو یکی می‌شمره)؛ IPv4-mapped رو به IPv4"""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return str(ip).strip()
    if addr.version == 6:
        if addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/64", strict=False).network_address) + "/64"
    return str(addr)


def _to_epoch(value):
    """مقدار زمانی هر IP رو به epoch (ثانیه) تبدیل می‌کنه. عدد، رشته‌ی عددی و رشته‌ی ISO رو می‌فهمه؛ وگرنه None"""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, str):
        v = value.strip()
        try:
            f = float(v)
        except ValueError:
            return parse_iso_to_epoch(v)
        value = f
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v > 1e17:    # نانوثانیه
        v /= 1e9
    elif v > 1e14:  # میکروثانیه
        v /= 1e6
    elif v > 1e11:  # میلی‌ثانیه
        v /= 1000.0
    return v


def extract_ip_entries(data) -> dict:
    """خروجی: {ip: {"ts": آخرین زمان دیده‌شدن یا None, "nodes": {node_id, ...}}}"""
    entries = {}

    def add(ip, ts, node):
        if not ip:
            return
        ip = normalize_ip(ip)
        e = entries.setdefault(ip, {"ts": None, "nodes": set()})
        if ts is not None and (e["ts"] is None or ts > e["ts"]):
            e["ts"] = ts
        if node is not None:
            e["nodes"].add(str(node))

    # شکل تأییدشده: {"nodes": {"1": {"ips": {"1.2.3.4": <timestamp>}}, ...}}
    if isinstance(data, dict) and isinstance(data.get("nodes"), dict):
        for node_id, node_info in data["nodes"].items():
            if not isinstance(node_info, dict):
                continue
            node_ips = node_info.get("ips")
            if isinstance(node_ips, dict):
                for ip, ts in node_ips.items():
                    add(ip, _to_epoch(ts), node_id)
            elif isinstance(node_ips, list):
                for item in node_ips:
                    if isinstance(item, str):
                        add(item, None, node_id)
                    elif isinstance(item, dict):
                        add(item.get("ip") or item.get("address"),
                            _to_epoch(item.get("last_seen") or item.get("ts")), node_id)
        return entries

    # شکل‌های جایگزین (لیست ساده یا دیکشنری از لیست‌ها)
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = [i for v in data.values() if isinstance(v, list) for i in v]
    else:
        items = []
    for item in items:
        if isinstance(item, str):
            add(item, None, None)
        elif isinstance(item, dict):
            add(item.get("ip") or item.get("address"),
                _to_epoch(item.get("last_seen") or item.get("ts")), None)
    return entries


def split_fresh(entries: dict, window_seconds: float, now=None) -> dict:
    """فقط IPهایی که تو بازه‌ی window_seconds دیده شدن (IP بدون زمان، تازه حساب می‌شه)"""
    now = now or time.time()
    out = {}
    for ip, e in entries.items():
        ts = e["ts"]
        if ts is None:
            out[ip] = e
        elif -MAX_FUTURE_SKEW <= (now - ts) <= window_seconds:
            out[ip] = e
    return out


def extract_ip_count(data) -> int:
    return len(extract_ip_entries(data))


def fmt_age(ts, now=None) -> str:
    if ts is None:
        return "زمان نامشخص"
    sec = max(0, int((now or time.time()) - ts))
    if sec < 60:
        return f"{sec} ثانیه پیش"
    if sec < 3600:
        return f"{sec // 60} دقیقه پیش"
    return f"{sec // 3600} ساعت پیش"


def try_get_user_ip_data(token: str, user_id, username: str, probe=False):
    """
    حالت عادی: وقتی endpoint درست مشخصه، فقط همون رو (با یک بار تلاش مجدد) صدا می‌زنه.
    حالت probe (تست API): همه‌ی endpointهای احتمالی رو امتحان می‌کنه.
    """
    cfg = load_panel_config()
    headers = {"Authorization": f"Bearer {token}"}
    known = runtime["working_endpoint"]
    if known and not probe:
        candidates, attempts = [known], 2
    else:
        candidates = ([known] if known else []) + [e for e in CANDIDATE_IP_ENDPOINTS if e != known]
        attempts = 1

    results = []
    for template in candidates:
        url = f"{cfg['base_url']}{template.format(id=user_id, username=username)}"
        for attempt in range(attempts):
            try:
                resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            except Exception as e:
                results.append((template, None, f"خطای شبکه: {e}"))
                if attempt + 1 < attempts:
                    time.sleep(1)
                continue
            results.append((template, resp.status_code, resp.text[:500]))
            if resp.status_code == 200:
                if runtime["working_endpoint"] != template:
                    runtime["working_endpoint"] = template
                    save_state()
                try:
                    return template, resp.json(), results
                except Exception:
                    return template, None, results
            if resp.status_code in (429, 500, 502, 503, 504) and attempt + 1 < attempts:
                time.sleep(1)
                continue
            break
    return None, None, results


# ================== تلگرام ==================
def tg_send(text: str, chat_id=None, reply_markup=None):
    try:
        payload = {
            "chat_id": chat_id or OWNER_CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
        }
        if reply_markup:
            payload["reply_markup"] = json.dumps(reply_markup)
        requests.post(f"{TG_API}/sendMessage", data=payload, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        log.error(f"ارسال پیام تلگرام ناموفق: {e}")


def tg_answer_callback(callback_id, text=""):
    try:
        requests.post(f"{TG_API}/answerCallbackQuery",
                       data={"callback_query_id": callback_id, "text": text}, timeout=REQUEST_TIMEOUT)
    except Exception:
        pass


def main_menu_keyboard():
    return {
        "inline_keyboard": [
            [{"text": "🔍 الان بررسی کن", "callback_data": "check_now"},
             {"text": "🔎 بررسی یوزر خاص", "callback_data": "check_user"}],
            [{"text": "⚙️ حد مجاز IP", "callback_data": "set_limit"},
             {"text": "⏱ فاصله بررسی", "callback_data": "set_interval"}],
            [{"text": "⏳ بازه اعتبار IP", "callback_data": "set_fresh"},
             {"text": "📈 تحلیل نمونه", "callback_data": "sample"}],
            [{"text": "🕐 تاریخچه", "callback_data": "history"},
             {"text": "🧪 تست اتصال API", "callback_data": "test_api"}],
            [{"text": "ℹ️ وضعیت", "callback_data": "status"},
             {"text": "🛠 تنظیمات پنل", "callback_data": "panel_menu"}],
        ]
    }


def panel_menu_keyboard():
    return {
        "inline_keyboard": [
            [{"text": "👁 نمایش تنظیمات فعلی", "callback_data": "panel_show"}],
            [{"text": "🌐 تغییر آدرس پنل", "callback_data": "set_panel_url"}],
            [{"text": "👤 تغییر یوزرنیم ادمین", "callback_data": "set_panel_username"}],
            [{"text": "🔑 تغییر پسورد ادمین", "callback_data": "set_panel_password"}],
            [{"text": "◀️ بازگشت", "callback_data": "main_menu"}],
        ]
    }


# ================== تنظیمات پنل از داخل تلگرام ==================
def handle_panel_menu(chat_id):
    if panel_is_configured():
        tg_send("تنظیمات پنل:", chat_id=chat_id, reply_markup=panel_menu_keyboard())
    else:
        tg_send(
            "⚠️ پنل هنوز تنظیم نشده.\nبرای شروع، آدرس پنل رو وارد کن (مثلاً: https://panel.example.com)",
            chat_id=chat_id,
        )
        runtime["pending_action"][chat_id] = "set_panel_url"


def handle_panel_show(chat_id):
    cfg = load_panel_config() or {}
    if not cfg:
        tg_send("پنل هنوز تنظیم نشده.", chat_id=chat_id, reply_markup=panel_menu_keyboard())
        return
    masked_pass = "•" * min(len(cfg.get("password", "")), 10) or "—"
    tg_send(
        f"🌐 آدرس پنل: <code>{cfg.get('base_url', '—')}</code>\n"
        f"👤 یوزرنیم ادمین: <code>{cfg.get('username', '—')}</code>\n"
        f"🔑 پسورد: <code>{masked_pass}</code>",
        chat_id=chat_id, reply_markup=panel_menu_keyboard(),
    )


CHAIN_NEXT = {"setup_url": "setup_username", "setup_username": "setup_password"}
FIELD_MAP = {
    "setup_url": "base_url", "set_panel_url": "base_url",
    "setup_username": "username", "set_panel_username": "username",
    "setup_password": "password", "set_panel_password": "password",
}
NEXT_PROMPT = {
    "setup_username": "یوزرنیم ادمین (سودو) پنل رو بفرست:",
    "setup_password": "رمز ادمین پنل رو بفرست:",
}


def start_panel_setup_wizard(chat_id):
    tg_send(
        "🔌 جهت اتصال به پنل، آدرس پنل خودت رو بدون path (همون آدرس داشبورد) بفرست:\n"
        "مثلاً: https://panel.example.com\n"
        "اگه پنلت روی یه پورت خاص هست، پورت رو هم بعد از آدرس بذار، مثلاً: https://panel.example.com:2096",
        chat_id=chat_id,
    )
    runtime["pending_action"][chat_id] = "setup_url"


def handle_panel_field_reply(chat_id, pending, text):
    text = text.strip()
    cfg = load_panel_config() or {"base_url": "", "username": "", "password": ""}
    field = FIELD_MAP[pending]

    if field == "base_url":
        if not text.startswith("http"):
            tg_send("❌ آدرس باید با http:// یا https:// شروع بشه. دوباره بفرست:", chat_id=chat_id)
            runtime["pending_action"][chat_id] = pending
            return
        text = text.rstrip("/")

    cfg[field] = text
    save_panel_config(cfg)

    next_step = CHAIN_NEXT.get(pending)
    if next_step:
        runtime["pending_action"][chat_id] = next_step
        tg_send(f"✅ ذخیره شد.\n{NEXT_PROMPT[next_step]}", chat_id=chat_id)
        return

    if cfg.get("base_url") and cfg.get("username") and cfg.get("password"):
        tg_send("🔄 در حال اتصال به پنل...", chat_id=chat_id)
        try:
            get_panel_token(force=True)
            tg_send(
                "✅ به پنل متصل شد!\n\n"
                "📌 این ربات چیکار می‌کنه؟\n"
                "ربات هر چند دقیقه‌ای که شما تعیین کنید (پیش‌فرض ۱۵ دقیقه)، خودکار IP یوزرهای آنلاین پنل رو بررسی می‌کنه "
                "و در صورت عبور از حد مجاز، بهتون هشدار می‌ده.",
                chat_id=chat_id, reply_markup=main_menu_keyboard(),
            )
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 401:
                tg_send(
                    "❌ اتصال ناموفق: یوزرنیم یا پسورد اشتباهه (خطای 401 Unauthorized).\n"
                    "از «🛠 تنظیمات پنل» دوباره وارد کن.",
                    chat_id=chat_id, reply_markup=main_menu_keyboard(),
                )
            else:
                tg_send(f"❌ اتصال ناموفق: {e}\nاز «🛠 تنظیمات پنل» می‌تونی دوباره امتحان کنی.",
                        chat_id=chat_id, reply_markup=main_menu_keyboard())
        except Exception as e:
            tg_send(f"❌ اتصال ناموفق: {e}\nاز «🛠 تنظیمات پنل» می‌تونی دوباره امتحان کنی.",
                    chat_id=chat_id, reply_markup=main_menu_keyboard())
    else:
        tg_send("✅ ذخیره شد.", chat_id=chat_id, reply_markup=panel_menu_keyboard())


# ================== منطق اصلی چک کردن (موازی) ==================
def _fetch_one(token, user, window):
    """خروجی: (username, همه‌ی IPها, IPهای تازه, خطا)"""
    user_id = user.get("id")
    username = user.get("username", str(user_id))
    try:
        template, data, results = try_get_user_ip_data(token, user_id, username)
        if data is None:
            last = results[-1][1] if results else "?"
            return username, None, None, f"پاسخ معتبر نیومد (status: {last})"
        entries = extract_ip_entries(data)
        return username, entries, split_fresh(entries, window), None
    except Exception as e:
        return username, None, None, str(e)


_ONLINE_AGES = {}


def send_alert_batches(to_alert, max_allowed, window):
    """هشدارها رو دسته‌ای می‌فرسته تا با تعداد زیاد، فلود تلگرام (429) نخوریم"""
    if not to_alert:
        return
    to_alert.sort(key=lambda x: -x[1])
    detail = len(to_alert) <= 5
    now = time.time()
    header = (f"⚠️ <b>هشدار تعداد IP بالا</b>\n"
              f"حد مجاز: {max_allowed} | بازه اعتبار IP: {window // 60} دقیقه\n\n")
    chunk = header
    for username, fc, total, fresh in to_alert:
        online_age = _ONLINE_AGES.get(username)
        age_txt = f" | آخرین آنلاین: {fmt_age(online_age, now)}" if online_age else ""
        unk = sum(1 for e in fresh.values() if e["ts"] is None)
        if unk:
            age_txt += f" | ⚠️ {unk} IP بدون زمان"
        block = f"• <code>{html.escape(username)}</code>: <b>{fc}</b> IP تازه (کل ثبت‌شده: {total}){age_txt}"
        if detail:
            for ip, e in sorted(fresh.items(), key=lambda kv: -(kv[1]["ts"] or 0)):
                block += f"\n   {ip} — {fmt_age(e['ts'], now)}"
        if len(chunk) + len(block) + 2 > 3800:
            tg_send(chunk)
            chunk = ""
        chunk += block + "\n\n"
    if chunk.strip():
        tg_send(chunk)


def run_check(notify_chat_id=None):
    started = time.time()
    try:
        token = get_panel_token()
        users = get_all_users(token)
    except PanelNotConfigured:
        tg_send("⚠️ پنل هنوز تنظیم نشده. از «🛠 تنظیمات پنل» استفاده کن.", chat_id=notify_chat_id)
        return
    except Exception as e:
        tg_send(f"❌ خطا در اتصال به پنل: {e}", chat_id=notify_chat_id)
        return

    active_users = [u for u in users if is_recently_online(u)]
    if not active_users:
        log.warning("هیچ یوزر آنلاینی بر اساس online_at پیدا نشد؛ برای اطمینان همه رو چک می‌کنیم")
        active_users = users

    window = runtime["ip_fresh_window_minutes"] * 60
    user_by_name = {u.get("username", str(u.get("id"))): u for u in users}
    _ONLINE_AGES.clear()
    for _name, _u in user_by_name.items():
        _ONLINE_AGES[_name] = parse_iso_to_epoch(_u.get("online_at"))
    results = {}   # username -> (IPهای تازه, تعداد کل IP ثبت‌شده)
    errors = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(_fetch_one, token, u, window) for u in active_users]
        for fut in concurrent.futures.as_completed(futures):
            username, entries, fresh, err = fut.result()
            if err:
                errors += 1
                log.warning(f"خطا در گرفتن IP برای {username}: {err}")
                continue
            results[username] = (fresh, len(entries))

    max_allowed = runtime["max_allowed_ips"]

    # --- تأیید دوباره: فقط یوزرهای بالای حد، بعد از چند ثانیه دوباره گرفته می‌شن ---
    suspects = [u for u, (fr, _) in results.items() if len(fr) > max_allowed]
    if suspects:
        time.sleep(CONFIRM_DELAY_SECONDS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futs = {executor.submit(_fetch_one, token, user_by_name[u], window): u for u in suspects if u in user_by_name}
            for fut in concurrent.futures.as_completed(futs):
                uname = futs[fut]
                _, entries2, fresh2, err2 = fut.result()
                if err2 or fresh2 is None:
                    continue
                fresh1, total1 = results[uname]
                # IPهایی که در هر دو بار تازه بودن (اشتراک) + اگه تعدادشون از حد کمتره، ردش کن
                common = {ip: e for ip, e in fresh1.items() if ip in fresh2}
                # اگه هیچ IP مشترکی نیست یعنی داده‌ی لحظه‌ای پایدار نیست؛ کمینه‌ی دو شمارش رو ملاک بگیر
                if len(common) < min(len(fresh1), len(fresh2)):
                    keep = fresh1 if len(fresh1) <= len(fresh2) else fresh2
                else:
                    keep = common
                results[uname] = (keep if len(keep) <= len(fresh1) else fresh1, total1)

    now = time.time()
    over_limit, to_alert = [], []
    for username, (fresh, total) in results.items():
        fc = len(fresh)
        if fc > max_allowed:
            over_limit.append((username, fc, total))
            if now - runtime["alert_state"].get(username, 0) >= ALERT_COOLDOWN_SECONDS:
                to_alert.append((username, fc, total, fresh))
                runtime["alert_state"][username] = now
        else:
            runtime["alert_state"].pop(username, None)
    send_alert_batches(to_alert, max_allowed, window)

    duration = int(time.time() - started)
    runtime["last_check_time"] = now
    runtime["last_check_over_limit"] = [(u, fc) for u, fc, _ in over_limit]
    runtime["check_history"].append({
        "time": now,
        "users_checked": len(results),
        "over_limit_count": len(over_limit),
        "manual": bool(notify_chat_id),
        "errors": errors,
        "duration": duration,
    })
    runtime["check_history"] = runtime["check_history"][-HISTORY_KEEP:]
    save_state()

    if notify_chat_id:
        footer = f"\n\n⏱ مدت: {duration} ثانیه | خطا: {errors} | بازه اعتبار IP: {window // 60} دقیقه"
        if over_limit:
            over_limit.sort(key=lambda x: -x[1])
            shown = over_limit[:40]
            lines = "\n".join(f"• <code>{html.escape(u)}</code>: {fc} IP تازه (کل {total})" for u, fc, total in shown)
            more = f"\n... و {len(over_limit) - len(shown)} مورد دیگه" if len(over_limit) > len(shown) else ""
            tg_send(f"بررسی تمام شد. {len(over_limit)} یوزر بالای حد مجاز ({max_allowed}):\n{lines}{more}{footer}",
                    chat_id=notify_chat_id)
        else:
            tg_send(f"بررسی تمام شد. {len(results)} یوزر آنلاین چک شد، همه زیر حد مجاز ({max_allowed}) بودن. ✅{footer}",
                    chat_id=notify_chat_id)


def handle_test_api(chat_id):
    tg_send("در حال تست endpoint های احتمالی روی چند یوزر اول...", chat_id=chat_id)
    try:
        token = get_panel_token()
        users = get_all_users(token)[:2]
    except PanelNotConfigured:
        tg_send("⚠️ پنل هنوز تنظیم نشده. از «🛠 تنظیمات پنل» استفاده کن.", chat_id=chat_id)
        return
    except Exception as e:
        tg_send(f"❌ خطا در لاگین/گرفتن یوزرها: {e}", chat_id=chat_id)
        return

    for user in users:
        user_id = user.get("id")
        username = user.get("username", str(user_id))
        template, data, results = try_get_user_ip_data(token, user_id, username, probe=True)
        report = f"یوزر: {username}\n"
        if template:
            entries = extract_ip_entries(data)
            fresh = split_fresh(entries, runtime["ip_fresh_window_minutes"] * 60)
            report += f"✅ متصل شد - IP تازه: {len(fresh)} | کل ثبت‌شده: {len(entries)}\n"
        else:
            report += "❌ هیچ‌کدوم از endpoint ها جواب 200 ندادن:\n"
            for tmpl, status, body in results:
                report += f"  {tmpl} -> {status}\n  {body[:200]}\n"
        tg_send(f"<pre>{report}</pre>", chat_id=chat_id)


def handle_status(chat_id):
    over = runtime["last_check_over_limit"]
    over_str = ", ".join(f"{u}({c})" for u, c in over) if over else "هیچکدوم"
    tg_send(
        f"🟢 وضعیت اسکریپت: فعال\n"
        f"🛠 وضعیت پنل: {'متصل ✅' if panel_is_configured() else 'تنظیم نشده ❌'}\n"
        f"📊 حد مجاز IP: {runtime['max_allowed_ips']}\n"
        f"⏱ فاصله بررسی خودکار: هر {runtime['check_interval_minutes']} دقیقه\n"
        f"⏳ بازه اعتبار IP: {runtime['ip_fresh_window_minutes']} دقیقه\n"
        f"⚠️ یوزرهای بالای حد در آخرین بررسی: {over_str}",
        chat_id=chat_id,
    )


def handle_history(chat_id):
    hist = runtime["check_history"]
    if not hist:
        tg_send("هنوز هیچ بررسی‌ای ثبت نشده.", chat_id=chat_id)
        return
    lines = []
    for entry in reversed(hist[-10:]):
        tag = "دستی 👤" if entry.get("manual") else "خودکار 🤖"
        lines.append(
            f"🕐 {fmt_tehran(entry['time'])} ({tag})\n"
            f"   {entry['users_checked']} یوزر چک شد، {entry['over_limit_count']} تا بالای حد"
            + (f" | {entry['duration']} ثانیه، {entry.get('errors', 0)} خطا" if "duration" in entry else "")
        )
    tg_send("<b>۱۰ بررسی آخر (وقت تهران):</b>\n\n" + "\n\n".join(lines), chat_id=chat_id)


def handle_set_limit_prompt(chat_id):
    runtime["pending_action"][chat_id] = "set_limit"
    tg_send(f"عدد حد مجاز IP رو بفرست (الان: {runtime['max_allowed_ips']}).\nمثلاً: 5", chat_id=chat_id)


def handle_set_limit_reply(chat_id, text):
    try:
        val = int(text.strip())
        if val <= 0:
            raise ValueError
    except ValueError:
        tg_send("❌ فقط یه عدد صحیح مثبت بفرست، مثلاً 5", chat_id=chat_id)
        runtime["pending_action"][chat_id] = "set_limit"
        return
    runtime["max_allowed_ips"] = val
    save_state()
    tg_send(f"✅ حد مجاز IP روی {val} تنظیم شد.", chat_id=chat_id, reply_markup=main_menu_keyboard())


def handle_set_interval_prompt(chat_id):
    runtime["pending_action"][chat_id] = "set_interval"
    tg_send(
        f"تعیین کنید ربات هر چند دقیقه IP یوزرهای آنلاین پنل رو بررسی کنه.\n"
        f"الان: هر {runtime['check_interval_minutes']} دقیقه\n"
        f"یکی از گزینه‌های پیشنهادی رو انتخاب کن یا یه عدد دلخواه (به دقیقه) بفرست:",
        chat_id=chat_id,
        reply_markup={
            "inline_keyboard": [
                [{"text": "5", "callback_data": "interval_5"},
                 {"text": "10 (پیشنهادی)", "callback_data": "interval_10"}],
                [{"text": "15", "callback_data": "interval_15"},
                 {"text": "30", "callback_data": "interval_30"}],
            ]
        },
    )


def handle_set_interval_reply(chat_id, text):
    try:
        val = int(text.strip())
        if val <= 0:
            raise ValueError
    except ValueError:
        tg_send("❌ فقط یه عدد صحیح مثبت بفرست (به دقیقه)، مثلاً 10", chat_id=chat_id)
        runtime["pending_action"][chat_id] = "set_interval"
        return
    runtime["check_interval_minutes"] = val
    save_state()
    tg_send(f"✅ فاصله‌ی بررسی خودکار روی هر {val} دقیقه تنظیم شد.", chat_id=chat_id, reply_markup=main_menu_keyboard())


def handle_check_user_prompt(chat_id):
    runtime["pending_action"][chat_id] = "check_user"
    tg_send("یوزرنیم رو بفرست تا تعداد و لیست IPهاش رو دقیق نشونت بدم.", chat_id=chat_id)


def handle_check_user_reply(chat_id, username_query):
    username_query = username_query.strip()
    tg_send(f"در حال بررسی یوزر «{username_query}»...", chat_id=chat_id)
    try:
        token = get_panel_token()
        users = get_all_users(token)
    except PanelNotConfigured:
        tg_send("⚠️ پنل هنوز تنظیم نشده. از «🛠 تنظیمات پنل» استفاده کن.", chat_id=chat_id)
        return
    except Exception as e:
        tg_send(f"❌ خطا در اتصال به پنل: {e}", chat_id=chat_id)
        return

    match = next((u for u in users if u.get("username", "").lower() == username_query.lower()), None)
    if not match:
        tg_send(f"یوزری با نام «{username_query}» پیدا نشد.", chat_id=chat_id, reply_markup=main_menu_keyboard())
        return

    user_id = match.get("id")
    username = match.get("username", str(user_id))
    template, data, _ = try_get_user_ip_data(token, user_id, username)
    if not template or data is None:
        tg_send("❌ نتونستم لیست IP این یوزر رو بگیرم.", chat_id=chat_id, reply_markup=main_menu_keyboard())
        return

    entries = extract_ip_entries(data)
    window = runtime["ip_fresh_window_minutes"] * 60
    fresh = split_fresh(entries, window)
    now = time.time()
    msg = (f"یوزر: <code>{html.escape(username)}</code>\n"
           f"IP تازه ({runtime['ip_fresh_window_minutes']} دقیقه اخیر): <b>{len(fresh)}</b> | "
           f"کل ثبت‌شده: {len(entries)} | حد مجاز: {runtime['max_allowed_ips']}\n")
    if entries:
        msg += "\n"
        ordered = sorted(entries.items(), key=lambda kv: -(kv[1]["ts"] or 0))
        for ip, e in ordered[:40]:
            mark = "🟢" if ip in fresh else "⚪️"
            nodes = "، ".join(sorted(e["nodes"])) if e["nodes"] else "—"
            msg += f"{mark} {ip} — {fmt_age(e['ts'], now)} (نود {nodes})\n"
        if len(ordered) > 40:
            msg += f"... و {len(ordered) - 40} مورد دیگه\n"
        msg += "\n🟢 تازه (شمرده می‌شه)   ⚪️ قدیمی (شمرده نمی‌شه)"
    tg_send(msg, chat_id=chat_id, reply_markup=main_menu_keyboard())


def handle_raw(chat_id, username_query):
    """خروجی خام API پنل برای یه یوزر - برای دیباگ شمارش اشتباه"""
    try:
        token = get_panel_token()
        users = get_all_users(token)
    except Exception as e:
        tg_send(f"❌ خطا: {e}", chat_id=chat_id)
        return
    match = next((u for u in users if u.get("username", "").lower() == username_query.strip().lower()), None)
    if not match:
        tg_send("یوزر پیدا نشد.", chat_id=chat_id)
        return
    template, data, results = try_get_user_ip_data(token, match.get("id"), match.get("username"))
    if data is None:
        tg_send(f"❌ پاسخ معتبر نیومد: {results[-1] if results else '?'}", chat_id=chat_id)
        return
    raw = json.dumps(data, ensure_ascii=False)
    entries = extract_ip_entries(data)
    fresh = split_fresh(entries, runtime["ip_fresh_window_minutes"] * 60)
    head = (f"endpoint: {template}\nonline_at: {match.get('online_at')} | status: {match.get('status')}\n"
            f"بعد از نرمال‌سازی: {len(entries)} IP (تازه: {len(fresh)}، بدون زمان: {sum(1 for e in entries.values() if e['ts'] is None)})\nخام ({len(raw)} کاراکتر):\n")
    tg_send(f"<pre>{html.escape(head + raw[:3000])}</pre>", chat_id=chat_id)


def handle_set_fresh_prompt(chat_id):
    runtime["pending_action"][chat_id] = "set_fresh"
    tg_send(
        "فقط IPهایی شمرده می‌شن که تو این بازه آخرین بار دیده شده باشن؛ IPهای قدیمی‌تر نادیده گرفته می‌شن.\n"
        f"الان: {runtime['ip_fresh_window_minutes']} دقیقه\n"
        "یکی از گزینه‌ها رو انتخاب کن یا عدد دلخواه (به دقیقه) بفرست:",
        chat_id=chat_id,
        reply_markup={
            "inline_keyboard": [
                [{"text": "2", "callback_data": "fresh_2"},
                 {"text": "5 (پیشنهادی)", "callback_data": "fresh_5"}],
                [{"text": "10", "callback_data": "fresh_10"},
                 {"text": "30", "callback_data": "fresh_30"}],
            ]
        },
    )


def _apply_fresh(chat_id, val):
    runtime["ip_fresh_window_minutes"] = val
    save_state()
    tg_send(f"✅ بازه اعتبار IP روی {val} دقیقه تنظیم شد.", chat_id=chat_id, reply_markup=main_menu_keyboard())


def handle_set_fresh_reply(chat_id, text):
    try:
        val = int(text.strip())
        if val <= 0:
            raise ValueError
    except ValueError:
        tg_send("❌ فقط یه عدد صحیح مثبت بفرست (به دقیقه)، مثلاً 5", chat_id=chat_id)
        runtime["pending_action"][chat_id] = "set_fresh"
        return
    _apply_fresh(chat_id, val)


def _percentile(sorted_vals, p):
    if not sorted_vals:
        return None
    return sorted_vals[min(len(sorted_vals) - 1, int(len(sorted_vals) * p))]


def handle_sample_analysis(chat_id):
    """نمونه‌ی تصادفی از یوزرهای آنلاین رو تحلیل می‌کنه تا معلوم بشه IPهای قدیمی چقدر شمارش رو بالا می‌برن"""
    tg_send("📈 در حال تحلیل یه نمونه‌ی تصادفی (حداکثر ۱۵۰ یوزر آنلاین)...", chat_id=chat_id)
    try:
        token = get_panel_token()
        users = get_all_users(token)
    except PanelNotConfigured:
        tg_send("⚠️ پنل هنوز تنظیم نشده. از «🛠 تنظیمات پنل» استفاده کن.", chat_id=chat_id)
        return
    except Exception as e:
        tg_send(f"❌ خطا در اتصال به پنل: {e}", chat_id=chat_id)
        return

    online = [u for u in users if is_recently_online(u)] or users
    sample = random.sample(online, min(150, len(online)))
    window = runtime["ip_fresh_window_minutes"] * 60
    limit = runtime["max_allowed_ips"]
    n = errors = over_all = over_fresh = total_ips = fresh_ips = 0
    ages = []
    now = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for fut in concurrent.futures.as_completed([executor.submit(_fetch_one, token, u, window) for u in sample]):
            _, entries, fresh, err = fut.result()
            if err:
                errors += 1
                continue
            n += 1
            total_ips += len(entries)
            fresh_ips += len(fresh)
            over_all += len(entries) > limit
            over_fresh += len(fresh) > limit
            ages.extend((now - e["ts"]) / 60 for e in entries.values() if e["ts"] is not None)

    if n == 0:
        tg_send(f"❌ هیچ نمونه‌ی معتبری گرفته نشد (خطا: {errors}).", chat_id=chat_id, reply_markup=main_menu_keyboard())
        return
    ages.sort()
    med, p90 = _percentile(ages, 0.5), _percentile(ages, 0.9)
    age_line = f"\nسن IPها: میانه {med:.1f} دقیقه | ۹۰٪ زیر {p90:.1f} دقیقه" if ages else ""
    tg_send(
        f"📈 <b>تحلیل نمونه</b> ({n} یوزر، خطا: {errors})\n"
        f"حد مجاز: {limit} | بازه اعتبار: {window // 60} دقیقه\n\n"
        f"بالای حد با «همه IPها»: <b>{over_all}</b>\n"
        f"بالای حد با «فقط IPهای تازه»: <b>{over_fresh}</b>\n"
        f"میانگین IP برای هر یوزر: کل {total_ips / n:.1f} | تازه {fresh_ips / n:.1f}"
        f"{age_line}",
        chat_id=chat_id, reply_markup=main_menu_keyboard(),
    )


# ================== حلقه polling تلگرام ==================
def telegram_polling_loop():
    offset = 0
    while True:
        try:
            resp = requests.get(f"{TG_API}/getUpdates", params={"offset": offset, "timeout": 30}, timeout=40)
            updates = resp.json().get("result", [])
        except Exception as e:
            log.warning(f"خطا در polling: {e}")
            time.sleep(5)
            continue

        for update in updates:
            offset = update["update_id"] + 1

            if "callback_query" in update:
                cq = update["callback_query"]
                chat_id = cq["message"]["chat"]["id"]
                if chat_id != OWNER_CHAT_ID:
                    tg_answer_callback(cq["id"], "⛔ این ربات فقط برای مالک اصلی کار می‌کنه.")
                    continue
                data = cq.get("data")
                tg_answer_callback(cq["id"])

                if data == "check_now":
                    tg_send("در حال بررسی...", chat_id=chat_id)
                    threading.Thread(target=run_check, kwargs={"notify_chat_id": chat_id}).start()
                elif data == "test_api":
                    threading.Thread(target=handle_test_api, args=(chat_id,)).start()
                elif data == "status":
                    handle_status(chat_id)
                elif data == "history":
                    handle_history(chat_id)
                elif data == "set_limit":
                    handle_set_limit_prompt(chat_id)
                elif data == "set_interval":
                    handle_set_interval_prompt(chat_id)
                elif data.startswith("interval_"):
                    val = int(data.split("_")[1])
                    runtime["pending_action"].pop(chat_id, None)
                    runtime["check_interval_minutes"] = val
                    save_state()
                    tg_send(f"✅ فاصله‌ی بررسی خودکار روی هر {val} دقیقه تنظیم شد.", chat_id=chat_id, reply_markup=main_menu_keyboard())
                elif data == "check_user":
                    handle_check_user_prompt(chat_id)
                elif data == "set_fresh":
                    handle_set_fresh_prompt(chat_id)
                elif data.startswith("fresh_"):
                    runtime["pending_action"].pop(chat_id, None)
                    _apply_fresh(chat_id, int(data.split("_")[1]))
                elif data == "sample":
                    threading.Thread(target=handle_sample_analysis, args=(chat_id,)).start()
                elif data == "panel_menu":
                    handle_panel_menu(chat_id)
                elif data == "panel_show":
                    handle_panel_show(chat_id)
                elif data == "set_panel_url":
                    runtime["pending_action"][chat_id] = "set_panel_url"
                    tg_send("آدرس پنل رو بفرست (مثلاً: https://panel.example.com یا با پورت: https://panel.example.com:2096)", chat_id=chat_id)
                elif data == "set_panel_username":
                    runtime["pending_action"][chat_id] = "set_panel_username"
                    tg_send("یوزرنیم ادمین پنل رو بفرست:", chat_id=chat_id)
                elif data == "set_panel_password":
                    runtime["pending_action"][chat_id] = "set_panel_password"
                    tg_send("پسورد ادمین پنل رو بفرست:", chat_id=chat_id)
                elif data == "main_menu":
                    tg_send("منوی اصلی:", chat_id=chat_id, reply_markup=main_menu_keyboard())

            elif "message" in update:
                msg = update["message"]
                chat_id = msg["chat"]["id"]
                text = (msg.get("text") or "").strip()

                if chat_id != OWNER_CHAT_ID:
                    log.info(f"پیام از چت غیرمجاز نادیده گرفته شد: {chat_id}")
                    continue

                pending = runtime["pending_action"].pop(chat_id, None)
                if pending in ("setup_url", "setup_username", "setup_password",
                               "set_panel_url", "set_panel_username", "set_panel_password"):
                    handle_panel_field_reply(chat_id, pending, text)
                elif pending == "set_limit":
                    handle_set_limit_reply(chat_id, text)
                elif pending == "set_interval":
                    handle_set_interval_reply(chat_id, text)
                elif pending == "set_fresh":
                    handle_set_fresh_reply(chat_id, text)
                elif pending == "check_user":
                    threading.Thread(target=handle_check_user_reply, args=(chat_id, text)).start()
                elif text.startswith("/raw "):
                    threading.Thread(target=handle_raw, args=(chat_id, text[5:])).start()
                elif text in ("/start", "/menu"):
                    if not panel_is_configured():
                        start_panel_setup_wizard(chat_id)
                    else:
                        tg_send("سلام! منوی مدیریت مانیتور IP:", chat_id=chat_id, reply_markup=main_menu_keyboard())


# ================== حلقه چک خودکار پس‌زمینه ==================
def background_check_loop():
    while True:
        time.sleep(runtime["check_interval_minutes"] * 60)
        if panel_is_configured():
            log.info("اجرای بررسی خودکار دوره‌ای...")
            run_check()
        else:
            log.info("پنل تنظیم نشده، بررسی خودکار رد شد.")


def main():
    load_state()
    if panel_is_configured():
        tg_send(
            f"🤖 ربات روشن شد و آماده‌ست.\nهر {runtime['check_interval_minutes']} دقیقه خودکار چک می‌کنه (حد مجاز فعلی: {runtime['max_allowed_ips']} IP).",
            reply_markup=main_menu_keyboard(),
        )
    else:
        tg_send("🤖 ربات روشن شد، ولی پنل هنوز تنظیم نشده.")
        start_panel_setup_wizard(OWNER_CHAT_ID)

    threading.Thread(target=background_check_loop, daemon=True).start()
    telegram_polling_loop()


if __name__ == "__main__":
    main()
