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
import hashlib
import html
import ipaddress
import json
import logging
import os
import random
import re
import sys
import threading
import time
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
from urllib.parse import quote
from requests.adapters import HTTPAdapter
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
ONLINE_WINDOW_SECONDS = 300        # یوزر رو "آنلاین" حساب کن اگه online_at توی این بازه بوده (online_at تو پنل کمی دیر آپدیت می‌شه، پس حاشیه‌ی امن)
REQUEST_TIMEOUT = 15
MAX_WORKERS = 16                   # تعداد درخواست همزمان به پنل
HISTORY_KEEP = 50
CONFIRM_DELAY_SECONDS = 20         # قبل از هشدار، یوزرهای بالای حد دوباره چک می‌شن (کم‌ترین عدد دو بار ملاک است)
MAX_FUTURE_SKEW = 300              # زمان IP که بیش از این (ثانیه) در آینده باشه، مشکوک حساب می‌شه و تازه نیست
DEFAULT_IP_FRESH_WINDOW_MINUTES = 5  # فقط IPهایی که تو این بازه دیده شدن شمرده می‌شن - قابل تغییر از داخل ربات

# اتصال مشترک (keep-alive): به‌جای handshake جدید برای هر درخواست، اتصال‌ها دوباره استفاده می‌شن
HTTP = requests.Session()
HTTP.mount("http://", HTTPAdapter(pool_connections=4, pool_maxsize=64))
HTTP.mount("https://", HTTPAdapter(pool_connections=4, pool_maxsize=64))

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
    "auto_disable": {"mode": "off", "strikes_needed": 3, "reenable_hours": 0, "exempt": []},
    "strikes": {},          # username -> تعداد بررسی‌های پشت‌سرهم بالای حد
    "disabled_users": {},   # username -> اطلاعات یوزرهایی که ربات غیرفعال کرده
    "ip_whitelist": [],     # قانون‌های لیست سفید IP (پیشوند، IP کامل یا CIDR)
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
            runtime["ip_whitelist"] = saved.get("ip_whitelist", [])
            runtime["auto_disable"].update(saved.get("auto_disable", {}))
            runtime["strikes"] = saved.get("strikes", {})
            runtime["disabled_users"] = saved.get("disabled_users", {})
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
                "ip_whitelist": runtime["ip_whitelist"],
                "auto_disable": runtime["auto_disable"],
                "strikes": runtime["strikes"],
                "disabled_users": runtime["disabled_users"],
            }))
            tmp.replace(STATE_FILE)
    except Exception as e:
        log.warning(f"ذخیره state ناموفق: {e}")


# ================== ارتباط با پنل ==================
class PanelNotConfigured(Exception):
    pass


token_lock = threading.Lock()


def refresh_token_if_stale(old_token: str) -> str:
    """اگه توکن عوض نشده، یه توکن جدید می‌گیره؛ اگه thread دیگه‌ای قبلاً عوضش کرده همون رو برمی‌گردونه"""
    with token_lock:
        if runtime["panel_token"] and runtime["panel_token"] != old_token:
            return runtime["panel_token"]
        return get_panel_token(force=True)


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


USERS_PAGE_LIMIT = 100
MAX_USER_LIST_PASSES = 6   # اگه ترتیب صفحه‌بندی پنل ناپایدار بود، حداکثر چند بار لیست رو دوباره بگیر تا همه‌ی یوزرها جمع بشن
_USERS_STATS = {"raw": 0, "unique": 0, "total": 0, "passes": 0}


def _users_page(cfg, headers, offset, sort):
    params = {"offset": offset, "limit": USERS_PAGE_LIMIT}
    if sort:
        params["sort"] = sort
    resp = HTTP.get(f"{cfg['base_url']}/api/users", headers=headers, params=params, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    return data.get("users", []), data.get("total")


def _users_pass(cfg, headers, sort):
    """یک دور کامل گرفتن لیست یوزرها (صفحه‌ی اول برای فهمیدن total، بقیه موازی)"""
    first, total = _users_page(cfg, headers, 0, sort)
    users = list(first)
    total = total if isinstance(total, int) else len(first)
    offsets = list(range(USERS_PAGE_LIMIT, total, USERS_PAGE_LIMIT))
    if offsets:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            for batch, _ in ex.map(lambda o: _users_page(cfg, headers, o, sort), offsets):
                users.extend(batch)
    return users, total


def get_all_users(token: str) -> list:
    """
    لیست همه‌ی یوزرها، بدون تکراری (بر اساس id).
    اگه ترتیب صفحه‌بندی پنل ناپایدار باشه (یوزرهای تکراری/جا‌مونده)، با مرتب‌سازی پایدار و یک دور دوم
    در جهت معکوس جبران می‌شه.
    """
    cfg = load_panel_config()
    headers = {"Authorization": f"Bearer {token}"}
    merged, raw, total, passes = {}, 0, 0, 0
    sorts = ["username", "-username"]
    for k in range(MAX_USER_LIST_PASSES):
        sort = sorts[k % len(sorts)] if sorts else None
        try:
            users, total = _users_pass(cfg, headers, sort)
        except requests.exceptions.HTTPError as e:
            if sort and e.response is not None and e.response.status_code in (400, 422):
                sorts = []          # sort پشتیبانی نمی‌شه؛ بدون اون ادامه بده
                users, total = _users_pass(cfg, headers, None)
            else:
                raise
        passes += 1
        raw += len(users)
        for u in users:
            merged[u.get("id", u.get("username"))] = u
        if len(merged) >= total:
            break
    _USERS_STATS.update(raw=raw, unique=len(merged), total=total, passes=passes)
    if len(merged) != total or raw != len(merged):
        log.warning(f"لیست یوزرها: خام={raw} یکتا={len(merged)} total پنل={total} دورها={passes}")
    return list(merged.values())


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


def _extract_ip_entries_raw(data) -> dict:
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


# ================== لیست سفید IP ==================
def parse_whitelist_entry(raw):
    """ورودی کاربر رو به یه قانون استاندارد تبدیل می‌کنه (یا None اگه نامعتبر بود).
    نمونه‌ها: 140.248  |  140.248.74.  |  140.248.*  |  1.2.3.4  |  10.0.0.0/8  |  2001:db8"""
    s = (raw or "").strip().lower().replace("*", "").rstrip(".")
    if not s:
        return None
    if "/" in s:
        try:
            return str(ipaddress.ip_network(s, strict=False))
        except ValueError:
            return None
    if ":" in s:
        if not re.fullmatch(r"[0-9a-f:]+", s):
            return None
        try:
            return normalize_ip(str(ipaddress.ip_address(s)))   # آدرس کامل IPv6 -> /64
        except ValueError:
            return s.rstrip(":") if s.rstrip(":") else None      # پیشوند IPv6
    parts = s.split(".")
    if 1 <= len(parts) <= 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return ".".join(str(int(p)) for p in parts)
    return None


def fmt_whitelist_rule(rule: str) -> str:
    if "/" in rule or ":" in rule:
        return rule
    return rule if rule.count(".") == 3 else rule + ".*"


def ip_whitelisted(ip: str, rules) -> bool:
    for r in rules:
        if "/" in r:
            try:
                net = ipaddress.ip_network(r, strict=False)
                addr = ipaddress.ip_address(ip.split("/")[0])
                if addr.version == net.version and addr in net:
                    return True
            except ValueError:
                continue
        elif ":" in r:
            try:
                ip_hex = ipaddress.ip_address(ip.split("/")[0]).exploded.split(":")
            except ValueError:
                continue
            rule_hex = [h.zfill(4) for h in r.split(":") if h]
            if ip_hex[:len(rule_hex)] == rule_hex:
                return True
        elif ":" not in ip:
            parts = r.split(".")
            if ip.split(".")[:len(parts)] == parts:
                return True
    return False


def extract_ip_entries(data) -> dict:
    """IPهای هر یوزر (بدون IPهای لیست سفید)"""
    entries = _extract_ip_entries_raw(data)
    rules = runtime.get("ip_whitelist") or []
    if rules:
        entries = {ip: e for ip, e in entries.items() if not ip_whitelisted(ip, rules)}
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
    refreshed = False
    for template in candidates:
        url = f"{cfg['base_url']}{template.format(id=user_id, username=username)}"
        for attempt in range(attempts):
            try:
                resp = HTTP.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            except Exception as e:
                results.append((template, None, f"خطای شبکه: {e}"))
                if attempt + 1 < attempts:
                    time.sleep(1)
                continue
            results.append((template, resp.status_code, resp.text[:500]))
            if resp.status_code == 401 and not refreshed:
                refreshed = True
                try:
                    headers = {"Authorization": f"Bearer {refresh_token_if_stale(token)}"}
                    resp = HTTP.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
                    results.append((template, resp.status_code, resp.text[:500]))
                except Exception as e:
                    results.append((template, None, f"خطا در تمدید توکن: {e}"))
                    break
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
            [{"text": "🛡 لیست سفید IP", "callback_data": "whitelist"},
             {"text": "🔒 غیرفعال‌سازی خودکار", "callback_data": "autodis"}],
        ]
    }


def whitelist_keyboard():
    rules = runtime["ip_whitelist"]
    rows = [[{"text": "➕ افزودن", "callback_data": "wl_add"}]]
    btns = [{"text": f"❌ {fmt_whitelist_rule(r)}", "callback_data": f"wl_del:{r}"} for r in rules]
    for i in range(0, len(btns), 2):
        rows.append(btns[i:i + 2])
    rows.append([{"text": "◀️ بازگشت", "callback_data": "main_menu"}])
    return {"inline_keyboard": rows}


def handle_whitelist_menu(chat_id, note=""):
    rules = runtime["ip_whitelist"]
    if rules:
        body = "\n".join(f"• <code>{html.escape(fmt_whitelist_rule(r))}</code>" for r in rules)
        body = "لیست فعلی:\n" + body + "\n\nبرای حذف، روی ❌ مورد نظر بزن."
    else:
        body = "لیست خالیه."
    tg_send(f"{note}🛡 <b>لیست سفید IP</b>\nIPهای این لیست تو شمارش یوزرها حساب نمی‌شن.\n\n{body}",
            chat_id=chat_id, reply_markup=whitelist_keyboard())


def handle_whitelist_add_prompt(chat_id):
    runtime["pending_action"][chat_id] = "wl_add"
    tg_send("IP یا پیشوند رو بفرست. چندتا رو می‌تونی با فاصله یا خط جدید جدا کنی.\n\n"
            "مثال:\n<code>140.248</code>  (کل رنج 140.248.*.*)\n<code>140.248.74</code>  (کل 140.248.74.*)\n"
            "<code>1.2.3.4</code>  (فقط یه IP)\n<code>10.0.0.0/8</code>  (CIDR)", chat_id=chat_id)


def handle_whitelist_add_reply(chat_id, text):
    added, dup, bad = [], [], []
    for tok in re.split(r"[\s,،;]+", text.strip()):
        if not tok:
            continue
        rule = parse_whitelist_entry(tok)
        if rule is None:
            bad.append(tok)
        elif rule in runtime["ip_whitelist"] or rule in added:
            dup.append(rule)
        else:
            added.append(rule)
    runtime["ip_whitelist"].extend(added)
    if added:
        save_state()
    note = ""
    if added:
        note += "✅ اضافه شد: " + "، ".join(f"<code>{html.escape(fmt_whitelist_rule(r))}</code>" for r in added) + "\n"
    if dup:
        note += "ℹ️ از قبل بود: " + "، ".join(f"<code>{html.escape(fmt_whitelist_rule(r))}</code>" for r in dup) + "\n"
    if bad:
        note += "❌ نامعتبر: " + "، ".join(f"<code>{html.escape(b)}</code>" for b in bad) + "\n"
    handle_whitelist_menu(chat_id, note=note + "\n" if note else "")


def handle_whitelist_delete(chat_id, rule):
    if rule in runtime["ip_whitelist"]:
        runtime["ip_whitelist"].remove(rule)
        save_state()
        handle_whitelist_menu(chat_id, note=f"🗑 حذف شد: <code>{html.escape(fmt_whitelist_rule(rule))}</code>\n\n")
    else:
        handle_whitelist_menu(chat_id)


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
_ONLINE_REF = [0.0]   # لحظه‌ای که لیست یوزرها گرفته شد (مبنای «آخرین آنلاین»)


def _severity(fc, limit):
    if fc >= limit * 2:
        return "🔴"
    if fc >= limit * 1.5:
        return "🟠"
    return "🟡"


def send_alert_batches(to_alert, max_allowed, window):
    """هشدارها رو مرتب و دسته‌ای می‌فرسته (بیشترین IP اول)"""
    if not to_alert:
        return
    to_alert.sort(key=lambda x: -x[1])
    detail = False   # لیست IPها تو هشدار نمایش داده نمی‌شه (برای دیدنش از /raw یا «بررسی یوزر خاص» استفاده کن)
    ref = _ONLINE_REF[0] or time.time()
    header = (f"⚠️ <b>هشدار تعداد IP بالا</b> ({len(to_alert)} یوزر)\n"
              f"حد مجاز: <b>{max_allowed}</b> | بازه اعتبار IP: {window // 60} دقیقه\n"
              f"🔴 ≥۲× حد   🟠 ≥۱.۵× حد   🟡 بالاتر از حد\n"
              f"━━━━━━━━━━━━━━\n")
    chunk = header
    for i, (username, fc, total, fresh) in enumerate(to_alert, 1):
        online_ts = _ONLINE_AGES.get(username)
        online_txt = f"  ⏱ {fmt_age(online_ts, ref)}" if online_ts else ""
        st = runtime["strikes"].get(username)
        strike_txt = (f"  🔁 {st}/{runtime['auto_disable']['strikes_needed']}"
                      if st and runtime["auto_disable"]["mode"] != "off" else "")
        online_txt += strike_txt
        unk = sum(1 for e in fresh.values() if e["ts"] is None)
        unk_txt = f"  ⚠️ {unk} IP بی‌زمان" if unk else ""
        block = (f"{_severity(fc, max_allowed)} <b>{i}.</b> <code>{html.escape(username)}</code>\n"
                 f"      <b>{fc}</b> IP  (کل: {total}){online_txt}{unk_txt}")
        if detail:
            for ip, e in sorted(fresh.items(), key=lambda kv: -(kv[1]["ts"] or 0)):
                block += f"\n      · {ip} — {fmt_age(e['ts'], ref)}"
        if len(chunk) + len(block) + 2 > 3800:
            tg_send(chunk)
            chunk = ""
        chunk += block + "\n\n"
    if chunk.strip():
        tg_send(chunk)


check_lock = threading.Lock()


def run_check(notify_chat_id=None):
    """فقط یک بررسی همزمان اجرا می‌شه (بررسی دستی و خودکار با هم قاطی نشن)"""
    if not check_lock.acquire(blocking=False):
        if notify_chat_id:
            tg_send("⏳ یه بررسی هم‌اکنون در حال اجراست؛ بعد از تموم شدنش دوباره امتحان کن.", chat_id=notify_chat_id)
        else:
            log.info("بررسی قبلی هنوز تموم نشده؛ این نوبت رد شد.")
        return
    try:
        _run_check_impl(notify_chat_id)
        try:
            process_auto_reenable()
        except Exception:
            log.exception("خطا در فعال‌سازی مجدد خودکار")
    finally:
        check_lock.release()


def _run_check_impl(notify_chat_id=None):
    started = time.time()
    try:
        token = get_panel_token()
        try:
            users = get_all_users(token)
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 401:
                token = refresh_token_if_stale(token)
                users = get_all_users(token)
            else:
                raise
    except PanelNotConfigured:
        tg_send("⚠️ پنل هنوز تنظیم نشده. از «🛠 تنظیمات پنل» استفاده کن.", chat_id=notify_chat_id)
        return
    except Exception as e:
        tg_send(f"❌ خطا در اتصال به پنل: {e}", chat_id=notify_chat_id)
        return

    active_users = [u for u in users if is_recently_online(u)]
    total_users, online_candidates = len(users), len(active_users)
    if not active_users:
        log.warning("هیچ یوزر آنلاینی بر اساس online_at پیدا نشد؛ برای اطمینان همه رو چک می‌کنیم")
        active_users = users

    window = runtime["ip_fresh_window_minutes"] * 60
    user_by_name = {u.get("username", str(u.get("id"))): u for u in users}
    _ONLINE_REF[0] = time.time()
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
                # ملاک، کمینه‌ی دو شمارش (محتاطانه): اگه تو بار دوم کمتر شد، همون کمتر ملاکه
                results[uname] = (fresh1 if len(fresh1) <= len(fresh2) else fresh2, total1)

    expected = len(active_users)
    run_ok = errors <= max(3, expected * 0.05) and len(results) >= expected * 0.9

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
    update_strikes(over_limit, run_ok)
    send_alert_batches(to_alert, max_allowed, window)
    process_auto_disable(over_limit, user_by_name, run_ok, max_allowed)

    duration = int(time.time() - started)
    runtime["last_check_time"] = now
    runtime["last_check_over_limit"] = [(u, fc) for u, fc, _ in over_limit]
    runtime["check_history"].append({
        "time": now,
        "users_checked": len(results),
        "users_total": total_users,
        "online_candidates": online_candidates,
        "over_limit_count": len(over_limit),
        "manual": bool(notify_chat_id),
        "errors": errors,
        "duration": duration,
    })
    runtime["check_history"] = runtime["check_history"][-HISTORY_KEEP:]
    save_state()

    if notify_chat_id:
        incomplete = " ⚠️ ناقص" if len(results) < online_candidates else ""
        footer = (f"\n\n👥 کل یوزرها: {total_users} (پنل: {_USERS_STATS['total']}) | "
                  f"آنلاین (online_at ≤ {ONLINE_WINDOW_SECONDS // 60} دقیقه): {online_candidates}"
                  f"\n✅ چک‌شده: {len(results)} از {online_candidates}{incomplete}"
                  f"\n⏱ مدت: {duration} ثانیه | خطا: {errors} | بازه اعتبار IP: {window // 60} دقیقه")
        if over_limit:
            over_limit.sort(key=lambda x: -x[1])
            shown = over_limit[:40]
            lines = "\n".join(f"{_severity(fc, max_allowed)} <b>{i}.</b> <code>{html.escape(u)}</code> — <b>{fc}</b> IP (کل {total})"
                              for i, (u, fc, total) in enumerate(shown, 1))
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
        f"🔒 غیرفعال‌سازی خودکار: {AD_MODES[runtime['auto_disable']['mode']]} | غیرفعال‌شده‌ها: {len(runtime['disabled_users'])}\n"
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
            f"   {entry['users_checked']} یوزر چک شد"
            + (f" (از {entry['users_total']} کل)" if "users_total" in entry else "")
            + f"، {entry['over_limit_count']} تا بالای حد"
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
# ================== غیرفعال‌سازی خودکار ==================
MAX_AUTO_DISABLE_PER_RUN = 15      # سقف ایمنی: اگه بیش از این تعداد یوزر همزمان واجد شرایط بودن، هیچ‌کدوم غیرفعال نمی‌شه
AD_MODES = {"off": "⚪ خاموش", "dry": "🧪 آزمایشی", "on": "🟢 فعال"}
AD_STRIKE_CHOICES = [1, 2, 3, 4, 5, 6]
AD_REENABLE_CHOICES = [0, 6, 12, 24, 72]
AD_LIST_MAX_SHOWN = 30


def _name_hash(name: str) -> str:
    return hashlib.sha1(name.lower().encode()).hexdigest()[:10]


def _panel_user_call(method, username, json_body=None):
    cfg = load_panel_config()
    if not cfg:
        raise PanelNotConfigured("پنل هنوز تنظیم نشده")
    token = get_panel_token()
    url = f"{cfg['base_url']}/api/user/{quote(username, safe='')}"
    resp = None
    for attempt in range(2):
        headers = {"Authorization": f"Bearer {token}"}
        resp = HTTP.request(method, url, headers=headers, json=json_body, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 401 and attempt == 0:
            token = refresh_token_if_stale(token)
            continue
        break
    return resp


def panel_get_user_status(username):
    """(status, error). اگه یوزر تو پنل نبود status='__missing__'"""
    try:
        resp = _panel_user_call("GET", username)
    except Exception as e:
        return None, str(e)
    if resp.status_code == 404:
        return "__missing__", None
    if resp.status_code != 200:
        return None, f"HTTP {resp.status_code}"
    try:
        return resp.json().get("status"), None
    except Exception:
        return None, "پاسخ نامعتبر از پنل"


def panel_set_user_status(username, status):
    """وضعیت یوزر رو تغییر می‌ده و بعدش از پنل دوباره می‌خونه تا مطمئن بشه. (ok, error)"""
    try:
        resp = _panel_user_call("PUT", username, {"status": status})
        if resp.status_code == 405:
            resp = _panel_user_call("PATCH", username, {"status": status})
        if not (200 <= resp.status_code < 300):
            hint = " (دسترسی ادمین ربات کافی نیست)" if resp.status_code == 403 else ""
            return False, f"HTTP {resp.status_code}{hint}: {resp.text[:120]}"
    except Exception as e:
        return False, str(e)
    new_status, err = panel_get_user_status(username)
    if err is None and new_status != status:
        return False, f"بعد از تغییر، وضعیت تو پنل «{new_status}» هست"
    return True, None


def update_strikes(over_limit, run_ok):
    """شمارنده‌ی بررسی‌های پشت‌سرهم بالای حد؛ یوزری که این بار بالای حد نبود صفر می‌شه"""
    if runtime["auto_disable"]["mode"] == "off":
        if runtime["strikes"]:
            runtime["strikes"].clear()
            save_state()
        return
    if not run_ok:
        return
    over_names = {u for u, _, _ in over_limit}
    strikes = runtime["strikes"]
    for n in over_names:
        strikes[n] = strikes.get(n, 0) + 1
    for n in list(strikes):
        if n not in over_names:
            del strikes[n]
    save_state()


def _ad_button_row():
    return {"inline_keyboard": [[{"text": "📋 لیست غیرفعال‌شده‌ها", "callback_data": "ad_list"}]]}


def process_auto_disable(over_limit, user_by_name, run_ok, max_allowed):
    cfg = runtime["auto_disable"]
    mode = cfg["mode"]
    if mode == "off":
        return
    if not run_ok:
        tg_send("⚠️ این بار بررسی کامل نبود (خطای زیاد یا یوزرهای ناقص)؛ شمارنده‌ها و غیرفعال‌سازی این دوره نادیده گرفته شد.")
        return
    need = cfg["strikes_needed"]
    exempt = {e.lower() for e in cfg["exempt"]}
    strikes = runtime["strikes"]
    fc_map = {u: fc for u, fc, _ in over_limit}
    candidates = []
    for n, fc in fc_map.items():
        if strikes.get(n, 0) < need or n.lower() in exempt or n in runtime["disabled_users"]:
            continue
        u = user_by_name.get(n)
        if not u or u.get("status") != "active":
            continue
        candidates.append(n)
    if not candidates:
        return
    candidates.sort(key=lambda n: -fc_map[n])

    if mode == "dry":
        fresh_ones = [n for n in candidates if strikes.get(n, 0) == need]   # فقط بار اول که به آستانه می‌رسن
        if fresh_ones:
            lines = "\n".join(f"• <code>{html.escape(n)}</code> — {fc_map[n]} IP" for n in fresh_ones)
            tg_send(f"🧪 <b>حالت آزمایشی:</b> این یوزرها الان غیرفعال می‌شدن (بالای حد در {need} بررسی پشت‌سرهم):\n{lines}\n\n"
                    "برای واقعی شدن، حالت رو روی «فعال» بذار.")
        return

    if len(candidates) > MAX_AUTO_DISABLE_PER_RUN:
        tg_send(f"🛑 {len(candidates)} یوزر همزمان واجد شرایط غیرفعال‌سازی بودن که از سقف ایمن ({MAX_AUTO_DISABLE_PER_RUN}) بیشتره؛ "
                "برای جلوگیری از اشتباه، هیچ‌کدوم غیرفعال نشد. وضعیت رو دستی بررسی کن.")
        return

    done, failed = [], []
    for n in candidates:
        ok, err = panel_set_user_status(n, "disabled")
        if ok:
            u = user_by_name[n]
            runtime["disabled_users"][n] = {"id": u.get("id"), "time": time.time(), "ips": fc_map[n],
                                            "limit": max_allowed, "strikes": strikes.get(n, need)}
            strikes.pop(n, None)
            done.append(n)
        else:
            failed.append((n, err))
    save_state()
    msg = ""
    if done:
        msg += f"🔒 <b>غیرفعال شدن</b> (بالای حد {max_allowed} در {need} بررسی پشت‌سرهم):\n"
        msg += "\n".join(f"• <code>{html.escape(n)}</code> — {fc_map[n]} IP" for n in done) + "\n"
    if failed:
        msg += "\n❌ <b>غیرفعال نشد:</b>\n"
        msg += "\n".join(f"• <code>{html.escape(n)}</code> — {html.escape(str(e))}" for n, e in failed)
    tg_send(msg.strip(), reply_markup=_ad_button_row())


def _reenable_user(username):
    """(state, detail): enabled | already | gone | error"""
    status, err = panel_get_user_status(username)
    if err:
        return "error", err
    if status == "__missing__":
        runtime["disabled_users"].pop(username, None)
        return "gone", None
    if status != "disabled":
        runtime["disabled_users"].pop(username, None)
        return "already", status
    ok, err = panel_set_user_status(username, "active")
    if ok:
        runtime["disabled_users"].pop(username, None)
        runtime["strikes"].pop(username, None)
        return "enabled", None
    return "error", err


def process_auto_reenable():
    hours = runtime["auto_disable"]["reenable_hours"]
    if hours <= 0 or not runtime["disabled_users"]:
        return
    now = time.time()
    due = [n for n, i in list(runtime["disabled_users"].items()) if now - i.get("time", now) >= hours * 3600]
    if not due:
        return
    enabled, errors = [], []
    for n in due:
        state, detail = _reenable_user(n)
        if state == "enabled":
            enabled.append(n)
        elif state == "error":
            errors.append((n, detail))
    save_state()
    msg = ""
    if enabled:
        msg += f"♻️ <b>فعال‌سازی مجدد خودکار</b> (بعد از {hours} ساعت):\n" + "\n".join(f"• <code>{html.escape(n)}</code>" for n in enabled)
    if errors:
        msg += "\n❌ فعال نشد:\n" + "\n".join(f"• <code>{html.escape(n)}</code> — {html.escape(str(e))}" for n, e in errors)
    if msg.strip():
        tg_send(msg.strip())


# ---------- منوها ----------
def autodis_keyboard():
    cfg = runtime["auto_disable"]
    mode_row = [{"text": ("✓ " if cfg["mode"] == k else "") + v, "callback_data": f"ad_mode:{k}"} for k, v in AD_MODES.items()]
    n_row = [{"text": ("✓ " if cfg["strikes_needed"] == n else "") + str(n), "callback_data": f"ad_n:{n}"} for n in AD_STRIKE_CHOICES]
    h_row = [{"text": ("✓ " if cfg["reenable_hours"] == h else "") + ("دستی" if h == 0 else f"{h}س"), "callback_data": f"ad_h:{h}"}
             for h in AD_REENABLE_CHOICES]
    return {"inline_keyboard": [
        mode_row,
        [{"text": "تعداد بررسی پشت‌سرهم ⬇️", "callback_data": "ad_noop"}], n_row,
        [{"text": "فعال‌سازی مجدد خودکار ⬇️", "callback_data": "ad_noop"}], h_row,
        [{"text": f"📋 غیرفعال‌شده‌ها ({len(runtime['disabled_users'])})", "callback_data": "ad_list"},
         {"text": f"👤 استثناها ({len(cfg['exempt'])})", "callback_data": "ad_ex"}],
        [{"text": "◀️ بازگشت", "callback_data": "main_menu"}],
    ]}


def handle_autodis_menu(chat_id, note=""):
    cfg = runtime["auto_disable"]
    re_txt = "دستی" if cfg["reenable_hours"] == 0 else f"بعد از {cfg['reenable_hours']} ساعت"
    tg_send(
        f"{note}🔒 <b>غیرفعال‌سازی خودکار</b>\n"
        f"وضعیت: {AD_MODES[cfg['mode']]}\n"
        f"شرط: بالای حد مجاز ({runtime['max_allowed_ips']} IP) در <b>{cfg['strikes_needed']}</b> بررسی پشت‌سرهم\n"
        f"فعال‌سازی مجدد: {re_txt}\n"
        f"غیرفعال‌شده‌ی فعلی: {len(runtime['disabled_users'])} | استثنا: {len(cfg['exempt'])}\n\n"
        "• آزمایشی: فقط اعلام می‌کنه کی غیرفعال می‌شد، بدون تغییر تو پنل.\n"
        "• فقط یوزرهای «active» غیرفعال می‌شن و فقط همونایی که خود ربات غیرفعال کرده تو لیست می‌مونن.",
        chat_id=chat_id, reply_markup=autodis_keyboard())


def handle_autodis_set(chat_id, kind, value):
    cfg = runtime["auto_disable"]
    note = ""
    if kind == "mode" and value in AD_MODES:
        cfg["mode"] = value
        if value == "off":
            runtime["strikes"].clear()
        if value == "on":
            note = "⚠️ حالا یوزرهای متخلف واقعاً غیرفعال می‌شن. (پیشنهاد: اول چند دور تو حالت آزمایشی ببین)\n\n"
    elif kind == "n" and value.isdigit() and int(value) in AD_STRIKE_CHOICES:
        cfg["strikes_needed"] = int(value)
    elif kind == "h" and value.isdigit() and int(value) in AD_REENABLE_CHOICES:
        cfg["reenable_hours"] = int(value)
    save_state()
    handle_autodis_menu(chat_id, note=note)


def handle_disabled_list(chat_id, note=""):
    items = sorted(runtime["disabled_users"].items(), key=lambda kv: -kv[1].get("time", 0))
    if not items:
        tg_send(f"{note}📋 هیچ یوزری توسط ربات غیرفعال نشده.", chat_id=chat_id,
                reply_markup={"inline_keyboard": [[{"text": "◀️ بازگشت", "callback_data": "autodis"}]]})
        return
    shown = items[:AD_LIST_MAX_SHOWN]
    lines = "\n".join(f"{i}. <code>{html.escape(n)}</code> — {info.get('ips', '?')} IP — {fmt_age(info.get('time'))}"
                      for i, (n, info) in enumerate(shown, 1))
    more = f"\n... و {len(items) - len(shown)} مورد دیگه" if len(items) > len(shown) else ""
    btns = [{"text": f"✅ {n[:22]}", "callback_data": f"ad_en:{_name_hash(n)}"} for n, _ in shown]
    rows = [btns[i:i + 2] for i in range(0, len(btns), 2)]
    rows.append([{"text": "✅ فعال‌سازی همه", "callback_data": "ad_en_all"}])
    rows.append([{"text": "◀️ بازگشت", "callback_data": "autodis"}])
    tg_send(f"{note}🔒 <b>غیرفعال‌شده‌ها</b> ({len(items)} یوزر)\n\n{lines}{more}\n\nبرای فعال‌سازی دوباره روی ✅ بزن.",
            chat_id=chat_id, reply_markup={"inline_keyboard": rows})


def _state_text(name, state, detail):
    n = f"<code>{html.escape(name)}</code>"
    if state == "enabled":
        return f"✅ {n} فعال شد."
    if state == "already":
        return f"ℹ️ {n} تو پنل از قبل «{html.escape(str(detail))}» بود؛ از لیست حذف شد."
    if state == "gone":
        return f"ℹ️ {n} دیگه تو پنل نیست؛ از لیست حذف شد."
    return f"❌ {n} فعال نشد: {html.escape(str(detail))}"


def handle_reenable_one(chat_id, name_hash):
    name = next((n for n in list(runtime["disabled_users"]) if _name_hash(n) == name_hash), None)
    if not name:
        handle_disabled_list(chat_id, note="این مورد دیگه تو لیست نیست.\n\n")
        return
    state, detail = _reenable_user(name)
    save_state()
    handle_disabled_list(chat_id, note=_state_text(name, state, detail) + "\n\n")


def handle_reenable_all(chat_id):
    names = list(runtime["disabled_users"])
    results = [_state_text(n, *_reenable_user(n)) for n in names]
    save_state()
    summary = "\n".join(results[:40]) + (f"\n... و {len(results) - 40} مورد دیگه" if len(results) > 40 else "")
    handle_disabled_list(chat_id, note=summary + "\n\n" if summary else "")


def exempt_keyboard():
    rows = [[{"text": "➕ افزودن", "callback_data": "ad_ex_add"}]]
    btns = [{"text": f"❌ {n[:24]}", "callback_data": f"ad_ex_del:{_name_hash(n)}"} for n in runtime["auto_disable"]["exempt"]]
    rows += [btns[i:i + 2] for i in range(0, len(btns), 2)]
    rows.append([{"text": "◀️ بازگشت", "callback_data": "autodis"}])
    return {"inline_keyboard": rows}


def handle_exempt_menu(chat_id, note=""):
    ex = runtime["auto_disable"]["exempt"]
    body = ("لیست فعلی:\n" + "\n".join(f"• <code>{html.escape(n)}</code>" for n in ex) + "\n\nبرای حذف، روی ❌ بزن.") if ex else "لیست خالیه."
    tg_send(f"{note}👤 <b>استثناهای غیرفعال‌سازی</b>\nاین یوزرها هیچ‌وقت خودکار غیرفعال نمی‌شن (هشدار می‌گیرن ولی غیرفعال نمی‌شن).\n\n{body}",
            chat_id=chat_id, reply_markup=exempt_keyboard())


def handle_exempt_add_prompt(chat_id):
    runtime["pending_action"][chat_id] = "ad_ex_add"
    tg_send("اسم یوزر(ها) رو بفرست (دقیقاً مثل پنل). چندتا رو با فاصله یا خط جدید جدا کن.", chat_id=chat_id)


def handle_exempt_add_reply(chat_id, text):
    ex = runtime["auto_disable"]["exempt"]
    added, dup = [], []
    for tok in re.split(r"[\s,،;]+", text.strip()):
        tok = tok.strip()
        if not tok:
            continue
        if tok.lower() in {e.lower() for e in ex} or tok.lower() in {a.lower() for a in added}:
            dup.append(tok)
        else:
            added.append(tok)
    ex.extend(added)
    if added:
        save_state()
    note = ""
    if added:
        note += "✅ اضافه شد: " + "، ".join(f"<code>{html.escape(a)}</code>" for a in added) + "\n"
    if dup:
        note += "ℹ️ از قبل بود: " + "، ".join(f"<code>{html.escape(d)}</code>" for d in dup) + "\n"
    handle_exempt_menu(chat_id, note=note + "\n" if note else "")


def handle_exempt_delete(chat_id, name_hash):
    ex = runtime["auto_disable"]["exempt"]
    name = next((n for n in ex if _name_hash(n) == name_hash), None)
    if name:
        ex.remove(name)
        save_state()
        handle_exempt_menu(chat_id, note=f"🗑 حذف شد: <code>{html.escape(name)}</code>\n\n")
    else:
        handle_exempt_menu(chat_id)


def handle_update(update):

    if "callback_query" in update:
        cq = update["callback_query"]
        chat_id = cq["message"]["chat"]["id"]
        if chat_id != OWNER_CHAT_ID:
            tg_answer_callback(cq["id"], "⛔ این ربات فقط برای مالک اصلی کار می‌کنه.")
            return
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
        elif data == "whitelist":
            handle_whitelist_menu(chat_id)
        elif data == "wl_add":
            handle_whitelist_add_prompt(chat_id)
        elif data.startswith("wl_del:"):
            handle_whitelist_delete(chat_id, data[len("wl_del:"):])
        elif data == "autodis":
            handle_autodis_menu(chat_id)
        elif data == "ad_noop":
            pass
        elif data.startswith("ad_mode:"):
            handle_autodis_set(chat_id, "mode", data.split(":", 1)[1])
        elif data.startswith("ad_n:"):
            handle_autodis_set(chat_id, "n", data.split(":", 1)[1])
        elif data.startswith("ad_h:"):
            handle_autodis_set(chat_id, "h", data.split(":", 1)[1])
        elif data == "ad_list":
            handle_disabled_list(chat_id)
        elif data.startswith("ad_en:"):
            threading.Thread(target=handle_reenable_one, args=(chat_id, data.split(":", 1)[1])).start()
        elif data == "ad_en_all":
            threading.Thread(target=handle_reenable_all, args=(chat_id,)).start()
        elif data == "ad_ex":
            handle_exempt_menu(chat_id)
        elif data == "ad_ex_add":
            handle_exempt_add_prompt(chat_id)
        elif data.startswith("ad_ex_del:"):
            handle_exempt_delete(chat_id, data.split(":", 1)[1])
        elif data == "main_menu":
            tg_send("منوی اصلی:", chat_id=chat_id, reply_markup=main_menu_keyboard())

    elif "message" in update:
        msg = update["message"]
        chat_id = msg["chat"]["id"]
        text = (msg.get("text") or "").strip()

        if chat_id != OWNER_CHAT_ID:
            log.info(f"پیام از چت غیرمجاز نادیده گرفته شد: {chat_id}")
            return

        pending = runtime["pending_action"].pop(chat_id, None)
        if pending in ("setup_url", "setup_username", "setup_password",
                       "set_panel_url", "set_panel_username", "set_panel_password"):
            handle_panel_field_reply(chat_id, pending, text)
        elif pending == "ad_ex_add":
            handle_exempt_add_reply(chat_id, text)
        elif pending == "wl_add":
            handle_whitelist_add_reply(chat_id, text)
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
            try:
                handle_update(update)
            except Exception:
                log.exception("خطا در پردازش پیام تلگرام")


# ================== حلقه چک خودکار پس‌زمینه ==================
def background_check_loop():
    while True:
        time.sleep(runtime["check_interval_minutes"] * 60)
        if panel_is_configured():
            log.info("اجرای بررسی خودکار دوره‌ای...")
            try:
                run_check()
            except Exception:
                log.exception("خطا در بررسی خودکار")
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
