# -*- coding: utf-8 -*-
"""Настройки проекта. Все секреты читаются из .env, в код не попадают."""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# Где лежат рабочие файлы.
#
# В собранном приложении писать внутрь .app нельзя: при переносе в
# Applications или обновлении всё потеряется. Поэтому сессия, логи,
# настройки и .env живут в ~/Library/Application Support/RadarZmiiv.
# При запуске из исходников (python monitor.py) — рядом с кодом, как раньше.
IS_APP = getattr(sys, "frozen", False)

if IS_APP:
    BASE_DIR = Path.home() / "Library" / "Application Support" / "RadarZmiiv"
    BASE_DIR.mkdir(parents=True, exist_ok=True)
else:
    BASE_DIR = Path(__file__).resolve().parent

# На Railway диск контейнера стирається при кожному перезапуску — без
# постійного диска (Volume) стан тривоги й закріпленого забувається,
# і радар при кожному рестарті дублює повідомлення в канал. RADAR_DATA_DIR
# вказує на змонтований Volume, коли він є.
_data_override = os.getenv("RADAR_DATA_DIR", "").strip()
DATA_DIR = Path(_data_override) if _data_override else BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
DATA_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# Чи це хмарний (Railway) екземпляр — вливає на те, як трактувати
# власну роль у панелі керування ботом (див. config.cloud_active()).
IS_CLOUD = os.getenv("RADAR_IS_CLOUD", "").strip() == "1"

# Єдиний номер версії радара. Показується у вікні застосунку, поруч
# з назвою «Радар Зміїв». Піднімати на одиницю при кожному помітному
# оновленні — і в застосунку, і в назві файлу архіву при збірці.
VERSION = "4.1"

# Читаем .env (файл создаёт и заполняет владелец проекта вручную)
load_dotenv(BASE_DIR / ".env")

# --- Секреты из окружения ---------------------------------------------------
TG_API_ID = os.getenv("TG_API_ID", "").strip()
TG_API_HASH = os.getenv("TG_API_HASH", "").strip()
TG_PHONE = os.getenv("TG_PHONE", "").strip()
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
TARGET_CHAT_ID = os.getenv("TARGET_CHAT_ID", "").strip()

# Для керування хмарним екземпляром із застосунку/бота (перемикач
# локально/онлайн, перезапуск). НЕ обов'язкові: без них ці кнопки
# просто повідомлять «не налаштовано». НІКОЛИ не заповнюються на
# хмарному екземплярі — токен дає керування самим Railway-проєктом,
# тримати його на публічному сервері не можна.
RAILWAY_TOKEN = os.getenv("RAILWAY_TOKEN", "").strip()
RAILWAY_PROJECT_ID = os.getenv("RAILWAY_PROJECT_ID", "").strip()
RAILWAY_SERVICE_ID = os.getenv("RAILWAY_SERVICE_ID", "").strip()
RAILWAY_ENVIRONMENT_ID = os.getenv("RAILWAY_ENVIRONMENT_ID", "").strip()

# Значения из настроек приложения перекрывают .env: так можно
# перенаправить радар в другой канал, не трогая файлы.

# --- Настройки, меняемые из интерфейса --------------------------------------
# Живут в data/settings.json (модуль settings.py). Здесь они разворачиваются
# в привычные имена, чтобы остальной код их просто читал.
import settings as _settings

_S = _settings.load()

CHANNELS = _S["channels"]                       # каналы, username без "@"
HIGH_INCLUDES_NEIGHBORS = _S["high_includes_neighbors"]
SEND_MEDIUM = _S["send_medium"]
SEND_LOW = _S["send_low"]
SEND_INFO = _S["send_info"]
ANNOUNCE_ALARM = _S["announce_alarm"]
QUIET_HOURS_ENABLED = _S["quiet_hours_enabled"]
QUIET_FROM = _S["quiet_from"]
QUIET_TO = _S["quiet_to"]
DEDUP_WINDOW_MIN = _S["dedup_window_min"]
STATUS_UPDATE_MIN = _S["status_update_min"]
STATUS_ALARM_WINDOW_MIN = _S["status_alarm_window_min"]
TRACK_OBLAST_ALARM = _S["track_oblast_alarm"]
STATUS_REFRESH_BUTTON = _S["status_refresh_button"]
CLEAR_THREAT = _S["clear_threat"]
CLEAR_AFTER_MIN = _S["clear_after_min"]
CRITICAL_ENABLED = _S["critical_enabled"]
CRITICAL_REPEATS = _S["critical_repeats"]
CRITICAL_INTERVAL_SEC = _S["critical_interval_sec"]
CRITICAL_MAX_BURSTS = _S["critical_max_bursts"]
CRITICAL_SERIES = _S["critical_series"]
CRITICAL_EPISODE_MIN = _S["critical_episode_min"]
SEND_NEAR = _S["send_near"]
SEND_CIVIL = _S["send_civil"]
TYPES_LOUD = _S["types_loud"]
TYPES_SILENT = _S["types_silent"]
TYPES_PINNED = _S["types_pinned"]
TYPES_REPLACE = _S["types_replace"]
FILTER_PLANNED = _S["filter_planned"]
FILTER_CONFIDENCE = _S["filter_confidence"]
FILTER_VOTES = _S["filter_votes"]
FILTER_CONTEXT = _S["filter_context"]
SMART_REVIEW = _S["smart_review"]
REVIEW_MINUTES = _S["review_minutes"]
REVIEW_LIMIT = _S["review_limit"]
SMART_EXPLAIN = _S["smart_explain"]
SMART_BEFORE_SERIES = _S["smart_before_series"]
DUP_NOTICE_ENABLED = _S["dup_notice_enabled"]
# Глибокий розбір повідомлення (reader.py) і зняття за зведеннями
SMART_READ = _S["smart_read"]
REPORT_CLEAR = _S["report_clear"]
REPORT_CLEAR_VOTES = _S["report_clear_votes"]
REPEAT_WINDOW_MIN = _S["repeat_window_min"]
RAID_CALM = _S["raid_calm"]
RAID_COOLDOWN_MIN = _S["raid_cooldown_min"]
ROLE = _S["role"]
OWNER_ID = _S["owner_id"]


def cloud_active() -> bool:
    """Чи зараз активна саме хмара (для галочки «Локально/Онлайн» у боті).

    ROLE описує роль ЦЬОГО екземпляра, а не те, хто активний глобально.
    На хмарі ROLE == "main" означає, що активна хмара; на локальному
    пристрої те саме означає активна саме хмара, коли ROLE == "backup".
    Без цієї різниці бот, відповідаючи з хмари, показував би галочку
    так, ніби активний локальний пристрій.
    """
    return ROLE == "main" if IS_CLOUD else ROLE == "backup"
if _S.get("target_chat_id"):
    TARGET_CHAT_ID = _S["target_chat_id"].strip()
if _S.get("bot_token"):
    BOT_TOKEN = _S["bot_token"].strip()
CITY_MAIN_NAME = _S["city_main_name"]
CITY_MAIN_VARIANTS = _S["city_main_variants"]
CITY_2_ON = _S["city_2_on"]
CITY_3_ON = _S["city_3_on"]
CITY_2_NAME = _S["city_2_name"]
CITY_2_VARIANTS = _S["city_2_variants"]
CITY_3_NAME = _S["city_3_name"]
CITY_3_VARIANTS = _S["city_3_variants"]
DISTRICT_NAME = _S["district_name"]
DISTRICT_VARIANTS = _S["district_variants"]
TELEGRAM_CONTROL = _S["telegram_control"]
DUMP_DAYS = _S["dump_days"]


def in_quiet_hours(hour: int) -> bool:
    """Попадает ли час в тихий промежуток (может переходить через полночь)."""
    if not QUIET_HOURS_ENABLED:
        return False
    start, end = QUIET_FROM, QUIET_TO
    if start == end:
        return False
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end          # через полночь, например 23→7

PAUSE_BETWEEN_CHANNELS = 2.5        # пауза между каналами при выгрузке, секунды
SESSION_PATH = str(DATA_DIR / "session_monitor")   # файл сессии Telethon


def reload_settings() -> dict:
    """Перечитывает settings.json — после сохранения из интерфейса."""
    global CHANNELS, HIGH_INCLUDES_NEIGHBORS, DEDUP_WINDOW_MIN
    global STATUS_UPDATE_MIN, STATUS_ALARM_WINDOW_MIN, DUMP_DAYS
    global SEND_MEDIUM, SEND_LOW, SEND_INFO, TRACK_OBLAST_ALARM, ANNOUNCE_ALARM
    global STATUS_REFRESH_BUTTON, CLEAR_THREAT, CLEAR_AFTER_MIN
    global CRITICAL_ENABLED, CRITICAL_REPEATS, CRITICAL_INTERVAL_SEC
    global CRITICAL_MAX_BURSTS, CRITICAL_SERIES, CRITICAL_EPISODE_MIN, SEND_CIVIL
    global SEND_NEAR
    global TYPES_LOUD, TYPES_SILENT, TYPES_PINNED, TYPES_REPLACE
    global FILTER_PLANNED, FILTER_CONFIDENCE, FILTER_VOTES, FILTER_CONTEXT
    global SMART_REVIEW, REVIEW_MINUTES, REVIEW_LIMIT
    global SMART_EXPLAIN, SMART_BEFORE_SERIES, DUP_NOTICE_ENABLED
    global SMART_READ, REPORT_CLEAR, REPORT_CLEAR_VOTES, REPEAT_WINDOW_MIN
    global RAID_CALM, RAID_COOLDOWN_MIN
    global ROLE, OWNER_ID, TELEGRAM_CONTROL, TARGET_CHAT_ID, BOT_TOKEN
    global CITY_2_ON, CITY_3_ON
    global CITY_MAIN_NAME, CITY_MAIN_VARIANTS, CITY_2_NAME, CITY_2_VARIANTS
    global CITY_3_NAME, CITY_3_VARIANTS, DISTRICT_NAME, DISTRICT_VARIANTS
    global QUIET_HOURS_ENABLED, QUIET_FROM, QUIET_TO
    s = _settings.load()
    CHANNELS = s["channels"]
    HIGH_INCLUDES_NEIGHBORS = s["high_includes_neighbors"]
    SEND_MEDIUM = s["send_medium"]
    SEND_LOW = s["send_low"]
    SEND_INFO = s["send_info"]
    ANNOUNCE_ALARM = s["announce_alarm"]
    QUIET_HOURS_ENABLED = s["quiet_hours_enabled"]
    QUIET_FROM = s["quiet_from"]
    QUIET_TO = s["quiet_to"]
    DEDUP_WINDOW_MIN = s["dedup_window_min"]
    STATUS_UPDATE_MIN = s["status_update_min"]
    STATUS_ALARM_WINDOW_MIN = s["status_alarm_window_min"]
    TRACK_OBLAST_ALARM = s["track_oblast_alarm"]
    STATUS_REFRESH_BUTTON = s["status_refresh_button"]
    CLEAR_THREAT = s["clear_threat"]
    CLEAR_AFTER_MIN = s["clear_after_min"]
    CRITICAL_ENABLED = s["critical_enabled"]
    CRITICAL_REPEATS = s["critical_repeats"]
    CRITICAL_INTERVAL_SEC = s["critical_interval_sec"]
    CRITICAL_MAX_BURSTS = s["critical_max_bursts"]
    CRITICAL_SERIES = s["critical_series"]
    CRITICAL_EPISODE_MIN = s["critical_episode_min"]
    SEND_NEAR = s["send_near"]
    SEND_CIVIL = s["send_civil"]
    TYPES_LOUD = s["types_loud"]
    TYPES_SILENT = s["types_silent"]
    TYPES_PINNED = s["types_pinned"]
    TYPES_REPLACE = s["types_replace"]
    FILTER_PLANNED = s["filter_planned"]
    FILTER_CONFIDENCE = s["filter_confidence"]
    FILTER_VOTES = s["filter_votes"]
    FILTER_CONTEXT = s["filter_context"]
    SMART_REVIEW = s["smart_review"]
    REVIEW_MINUTES = s["review_minutes"]
    REVIEW_LIMIT = s["review_limit"]
    SMART_EXPLAIN = s["smart_explain"]
    SMART_BEFORE_SERIES = s["smart_before_series"]
    DUP_NOTICE_ENABLED = s["dup_notice_enabled"]
    SMART_READ = s["smart_read"]
    REPORT_CLEAR = s["report_clear"]
    REPORT_CLEAR_VOTES = s["report_clear_votes"]
    REPEAT_WINDOW_MIN = s["repeat_window_min"]
    RAID_CALM = s["raid_calm"]
    RAID_COOLDOWN_MIN = s["raid_cooldown_min"]
    ROLE = s["role"]
    OWNER_ID = s["owner_id"]
    TARGET_CHAT_ID = (s.get("target_chat_id") or "").strip() or \
        os.getenv("TARGET_CHAT_ID", "").strip()
    BOT_TOKEN = (s.get("bot_token") or "").strip() or \
        os.getenv("BOT_TOKEN", "").strip()
    CITY_MAIN_NAME = s["city_main_name"]
    CITY_MAIN_VARIANTS = s["city_main_variants"]
    CITY_2_ON = s["city_2_on"]
    CITY_3_ON = s["city_3_on"]
    CITY_2_NAME = s["city_2_name"]
    CITY_2_VARIANTS = s["city_2_variants"]
    CITY_3_NAME = s["city_3_name"]
    CITY_3_VARIANTS = s["city_3_variants"]
    DISTRICT_NAME = s["district_name"]
    DISTRICT_VARIANTS = s["district_variants"]
    TELEGRAM_CONTROL = s["telegram_control"]
    DUMP_DAYS = s["dump_days"]
    return s


def require(*names: str) -> None:
    """Проверяет, что нужные переменные окружения заполнены.

    Значения не печатаются — только имена отсутствующих переменных.
    """
    missing = [n for n in names if not globals().get(n)]
    if missing:
        raise SystemExit(
            "Не заполнены переменные в .env: "
            + ", ".join(missing)
            + "\nСкопируйте .env.example в .env и заполните."
        )


def api_id_int() -> int:
    """TG_API_ID как число (Telethon требует int)."""
    require("TG_API_ID")
    try:
        return int(TG_API_ID)
    except ValueError:
        raise SystemExit("TG_API_ID должен быть числом.")




