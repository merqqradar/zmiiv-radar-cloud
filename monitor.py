# -*- coding: utf-8 -*-
"""Ядро мониторинга: слушает каналы и шлёт уведомления.

Используется в двух режимах:
  python monitor.py        — из терминала, останов по Ctrl+C
  menubar.py               — из приложения в строке меню

Уровни:
  HIGH   — со звуком, угроза самому Зміїву
  MEDIUM — без звука, подлёт через ближние сёла / последствия
  LOW    — без звука, відбій

Дубли из разных каналов склеиваются в окне config.DEDUP_WINDOW_MIN минут.
"""

import asyncio
import json
import logging
import logging.handlers
from datetime import datetime, timedelta, timezone
from html import escape

from telethon import TelegramClient, events

import classify
import config
import geo
import threats
import settings
import notify
import reader
import public_source
import railway_ctl
import status

# --- Логирование ------------------------------------------------------------
LOG_FILE = config.LOGS_DIR / "monitor.log"

# Лог крутится по кругу: 1 МБ на файл, три архива. Больше 4 МБ
# папка с логами не займёт никогда, чистить руками не нужно.
_rotating = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[_rotating, logging.StreamHandler()],
)
logging.getLogger("telethon").setLevel(logging.WARNING)
log = logging.getLogger("monitor")

STATE_FILE = config.DATA_DIR / "seen.json"

# Если відбій по какой-то причине не пришёл (канал молчал, радар
# перезапускался), тревога снимается сама — иначе закреплённое
# сообщение врало бы часами.
ALARM_MAX_HOURS = 6

# Як часто опитувати публічні сторінки каналів у хмарному режимі.
# У локальному режимі подія Telethon приходить миттєво; опитування —
# компроміс, потрібний, щоб не тягнути файл сесії на сторонній хостинг.
CLOUD_POLL_SECONDS = 20

# Скільки хвилин вважати попереднє повідомлення про те саме місце
# «підозріло свіжим» для позначки можливого дубляжу з іншого каналу.
DUP_NOTICE_WINDOW_MIN = 8

# Скорочена серія — для загроз НЕ самому місту (район, сусіди).
# Чотири повідомлення з паузою в пів хвилини замість повної серії:
# знати треба, але кричати без упину через ціль за 40 км — ні.
SHORT_REPEATS = 4
SHORT_INTERVAL_SEC = 30

# Скільки хвилин живуть голоси «у зведенні по області цілі немає».
REPORT_VOTE_MIN = 15

# Журнал подій доби: скільки записів тримаємо і скільки показуємо у звіті.
EVENT_LOG_LIMIT = 60
EVENT_SHOW_LIMIT = 8
# За скільки годин назад уточнення «це було розмінування» ще стосується
# вже записаного прильоту.
EXPLAIN_IMPACT_HOURS = 4

# Состояние тревоги переживает перезапуск приложения: иначе после
# обновления или перезагрузки закреплённое сообщение показывало бы
# «загроз немає» посреди настоящей тривоги.
ALARM_FILE = config.DATA_DIR / "alarm.json"
DAILY_FILE = config.DATA_DIR / "daily.json"
ACTIVE_THREAT_FILE = config.DATA_DIR / "active_threat.json"


def load_active_threat():
    """Читает активну ціль, якщо вона ще не протухла.

    Без цього після перезапуску (оновлення версії, збій, ребут сервера)
    радар мовчки забував, за якою ціллю стежить — і повідомлення
    «загроза минула» просто ніколи не приходило.
    """
    if not ACTIVE_THREAT_FILE.exists():
        return None
    try:
        raw = json.loads(ACTIVE_THREAT_FILE.read_text(encoding="utf-8"))
        last_src = raw.get("last_src")
        threat = {"place": raw["place"],
                  "since": datetime.fromisoformat(raw["since"]),
                  "last_seen": datetime.fromisoformat(raw["last_seen"]),
                  "kind": raw.get("kind", ""),
                  "last_src": tuple(last_src) if last_src else None}
    except (json.JSONDecodeError, KeyError, ValueError):
        return None
    if datetime.now() - threat["last_seen"] > timedelta(hours=ALARM_MAX_HOURS):
        return None
    return threat


def save_active_threat(threat) -> None:
    if threat is None:
        ACTIVE_THREAT_FILE.unlink(missing_ok=True)
        return
    ACTIVE_THREAT_FILE.write_text(json.dumps({
        "place": threat["place"], "since": threat["since"].isoformat(),
        "last_seen": threat["last_seen"].isoformat(),
        "kind": threat.get("kind", ""),
        "last_src": list(threat["last_src"]) if threat.get("last_src") else None,
    }, ensure_ascii=False), encoding="utf-8")
PREV_FILE = config.DATA_DIR / "daily_prev.json"


def load_daily() -> dict:
    """Счётчики за сутки. При смене даты обнуляются."""
    today = datetime.now().strftime("%Y-%m-%d")
    if DAILY_FILE.exists():
        try:
            data = json.loads(DAILY_FILE.read_text(encoding="utf-8"))
            if data.get("date") == today:
                return data
        except (json.JSONDecodeError, ValueError):
            pass
    return {"date": today, "seen": 0, "threats": 0, "impacts": 0,
            "alarms": 0, "civil": {}, "by_type": {}, "impact_types": {}}


def save_daily(daily: dict) -> None:
    DAILY_FILE.write_text(json.dumps(daily, ensure_ascii=False),
                          encoding="utf-8")


def load_state() -> tuple:
    """Читает состояние тревоги и то, что последним объявлено в канале.

    Возвращает (alarm, announced), где alarm — ("Повітряна тривога", когда)
    или None, а announced — "on" / "off" / None: какое состояние последним
    ушло в чат. По нему видно, нужно ли досылать сообщение после запуска.
    """
    if not ALARM_FILE.exists():
        return None, None
    try:
        raw = json.loads(ALARM_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError):
        return None, None

    announced = raw.get("announced")
    alarm = None
    if raw.get("kind") and raw.get("since"):
        try:
            when = datetime.fromisoformat(raw["since"])
            if datetime.now() - when <= timedelta(hours=ALARM_MAX_HOURS):
                alarm = (raw["kind"], when)
        except ValueError:
            pass
    return alarm, announced


def save_state(alarm, announced) -> None:
    """Сохраняет состояние тревоги и последнее объявленное в чате."""
    data = {"announced": announced}
    if alarm:
        data["kind"], data["since"] = alarm[0], alarm[1].isoformat()
    ALARM_FILE.write_text(json.dumps(data, ensure_ascii=False),
                          encoding="utf-8")

# Пояснение к панели: без него по одному слову на кнопке не всегда
# понятно, что произойдёт. Приходит при /start и /panel.
PANEL_HELP = """🎛 <b>Керування радаром</b>

⚪️ <b>Скасувати тривогу</b> — прибирає ХИБНУ тривогу: знімає активну ціль і зупиняє гучні повтори, але радар працює далі й наступну справжню загрозу підніме як звичайно. Саме це варто натискати, коли радар помилився, — замість паузи чи вимкнення звуку.

⏸ <b>Пауза</b> — радар слухає канали, але нічого не надсилає. Кнопка стає «Відновити».

🔕 <b>Тиша на годину</b> — повідомлення приходять, але без звуку. Корисно, коли обстріл триває довго, а ви вже в укритті. Діє й на екстрені повтори.

📊 <b>Звіт</b> — надсилає в канал підсумок за добу: загрози, прильоти, тривоги, відключення світла.

🏠 <b>Локально</b> / 🌐 <b>Онлайн</b> — де зараз працює радар: на цьому пристрої чи на сервері. Активний варіант позначений ✅. Перемикання одразу застосовується з обох боків, якщо хмара налаштована.

🔁 <b>Перезапустити онлайн</b> — на випадок збою хмарного екземпляра.

ℹ️ <b>Стан радара</b> — відповідає сюди: чи працює, скільки каналів слухає, скільки повідомлень переглянув, чи триває тривога.

🔄 <b>Оновити статус</b> — оновлює закріплене повідомлення в каналі просто зараз.

📌 <b>Новий закріп</b> — створює закріплене заново, якщо старе видалили або воно загубилося.

✅ <b>Перевірка зв'язку</b> — надсилає в канал тестове повідомлення.

🔎 <b>Кнопка «Оновити»: смарт-режим</b> — увімкнено (типово): кнопка «Оновити» під закріпленим переглядає останні повідомлення каналів і сама вирішує, чи знята ціль. Вимкнено — кнопка просто перемальовує час, як стара версія, без жодного аналізу.

<i>Команди: /panel /pause /resume /mute /report /status /state
/local /online /restart_cloud
Кнопки працюють, поки радар запущений.</i>"""

LEVEL_STYLE = {
    "HIGH":   ("🔴", "УВАГА"),
    "MEDIUM": ("🟠", "Поруч"),
    "LOW":    ("🟢", "Відбій"),
    "INFO":   ("🔵", "Інфо"),
    "CIVIL":  ("🟣", "Інше"),
}


def headline(res: dict) -> str:
    """Первая строка уведомления.

    В push на телефоне и в шторке ноутбука видно только начало текста,
    поэтому первым словом идёт ТИП УГРОЗЫ, а не служебная пометка:
    «ШАХЕД → Зміїв», а не «УВАГА · загроза Зміїву».
    """
    icon = LEVEL_STYLE[res["level"]][0]

    # Главный НП: если назван сам Зміїв — всегда он, иначе первое из найденных
    places = res["places"]
    main = geo.main_name()
    place = main if main in places else (places[0] if places else "—")

    if res["level"] == "LOW":
        return f"{icon} <b>ВІДБІЙ → {place}</b>"

    if res["level"] == "INFO":
        # Первым словом — суть: «ЗВУКИ НАШІ», «РОБОТА ППО»
        # watch — окремий випадок («робота ППО у ворога»): жовтий,
        # бо це не рутинна синя інфа, а привід бути уважним.
        if res.get("watch"):
            icon = "🟡"
        where = f" → {place}" if places else ""
        return f"{icon} <b>{res['reason'].upper()}{where}</b>"

    if res["threats"]:
        # Назва НП попереду: коли міст кілька, важливо одразу бачити,
        # про яке саме йдеться. «ЗМІЇВ · РАКЕТА», а не «РАКЕТА → Зміїв».
        name, emoji = res["threats"][0]
        count = res.get("count") or 0
        label = f"{name.upper()} {count} ШТ" if count >= 2 else name.upper()
        return f"{emoji} <b>{place.upper()} · {label}</b>"

    # Тип не назвали — берём смысл из причины срабатывания
    if "наслідки" in res["reason"]:
        word = "ВИБУХ"
    elif "курс" in res["reason"] or "підліт" in res["reason"]:
        word = "ЦІЛЬ"
    else:
        word = "УВАГА"
    return f"{icon} <b>{place.upper()} · {word}</b>"


def plain_headline(res: dict) -> str:
    """Заголовок без HTML — для меню приложения и логов."""
    return headline(res).replace("<b>", "").replace("</b>", "")


def format_message(res: dict, channel: str, link: str, dup_src=None) -> str:
    """Полный текст уведомления.

    dup_src — (канал, посилання) попереднього повідомлення про, схоже,
    ту саму ціль з ІНШОГО каналу за останні кілька хвилин. Радар не
    об'єднує цілі (це ризиковано), а лише попереджає — без 100%
    підтвердження вирішувати вам.
    """
    icon, title = LEVEL_STYLE[res["level"]]
    if res.get("watch"):
        icon, title = "🟡", "Увага"
    places = ", ".join(res["places"]) or "—"
    top = headline(res)

    # У сообщений об отбое хвост со списком чужих районов не нужен,
    # и «угроза» там всегда бессмысленная — она вычитана из этого же хвоста.
    if res["level"] in ("LOW", "INFO"):
        body = escape(classify.alert_head(res["text"]).strip())[:400]
        head = f"{top}\n{icon} {title} · {escape(res['reason'])}\n"
    else:
        threat = " ".join(f"{e} {n}" for n, e in res["threats"])
        if not threat:
            guess = res.get("guess")
            threat = (f"тип не вказано · ймовірно {guess} "
                      f"(за обстановкою в області)" if guess else "тип не вказано")
        body = escape(res["text"])[:600]
        head = (f"{top}\n"
                f"{icon} {title} · {escape(res['reason'])}\n"
                f"<b>Загроза:</b> {escape(threat)}\n")

    # Радар не впевнений — так і кажемо, замість того щоб стверджувати
    if (res.get("confidence") == "low" and res["level"] != "INFO"
            and config.FILTER_CONFIDENCE):
        head += ("<i>⚠️ Радар не впевнений: у повідомленні немає прямої "
                 "згадки міста або типу загрози. Перевірте джерело.</i>\n")

    if dup_src:
        dup_channel, dup_link = dup_src
        head += (f"<i>⚠️ Можливо, це та сама ціль, що вже згадувалась "
                f"нещодавно в іншому каналі — "
                f"<a href=\"{dup_link}\">{escape(dup_channel)}</a>. "
                f"100% підтвердження немає, перевірте самі.</i>\n")

    return (f"{head}"
            f"<b>НП:</b> {escape(places)}\n"
            f"\n{body}\n"
            f"\n<i>{escape(channel)}</i> · <a href=\"{link}\">джерело</a>")


def source_line(src) -> str:
    """Ссылка на исходное сообщение канала.

    Показывается под КАЖДЫМ уведомлением: читатель должен видеть,
    откуда взялась информация, и мочь открыть первоисточник.
    Если вывод сделал сам радар (например, цель перестали упоминать),
    так и пишем — без ссылки, но с указанием, что это его вывод.
    """
    if not src:
        return "\n\n<i>джерело: радар</i>"
    username, link = src
    return (f"\n\n<i>{escape(username)}</i> · "
            f"<a href=\"{link}\">джерело</a>")


def format_alarm(kind: str, when, active: bool, restored: bool = False,
                 src=None) -> str:
    """Текст объявления тревоги или отбоя для канала.

    restored=True — состояние восстановлено из истории после запуска,
    поэтому пишем «триває з», а не «оголошено о»: сообщение приходит
    задним числом и не должно выглядеть как новое объявление.
    """
    if active:
        line = (f"🟡 Триває з {when:%H:%M}" if restored
                else f"🟡 Оголошено о {when:%H:%M}")
        return (f"🟡 <b>{kind.upper()} → {config.DISTRICT_NAME}</b>\n{line}\n"
                f"\nЗагрози саме місту поки не зафіксовано. "
                f"Радар продовжує стежити." + source_line(src))
    line = (f"🟢 Відбій був о {when:%H:%M}" if restored
            else f"🟢 Відбій о {when:%H:%M}")
    return (f"🟢 <b>ВІДБІЙ ТРИВОГИ → {config.DISTRICT_NAME}</b>\n{line}"
            + source_line(src))


def format_gone(threat: dict, wording: str, source: str = "", src=None) -> str:
    """Сообщение о том, что ранее объявленная угроза больше не наблюдается.

    Формулировки осторожные: радар не знает, сбита цель, пролетела или
    уже прилетела. Он знает только то, что каналы перестали о ней писать.
    """
    when = threat["since"]
    head = f"🟢 <b>{threat['place'].upper()} · ЗАГРОЗА, СКОРІШЕ ЗА ВСЕ, МИНУЛА</b>\n"
    last_src = threat.get("last_src")
    if source:
        body = (f"🟢 {wording.capitalize()} · загроза була о {when:%H:%M}\n"
                f"\n{escape(source)[:250]}")
        tail = source_line(src)
        # Якщо є ще й джерело ОСТАННЬОЇ згадки цілі (до цього «не
        # фіксується») і воно не те саме повідомлення — додаємо і його:
        # так можна вручну звірити, що обидва допису дійсно про одну й
        # ту саму ціль.
        if last_src and tuple(last_src) != tuple(src or ()):
            tail += (f"\n<i>Востаннє згадувалась:</i> "
                    f"<a href=\"{last_src[1]}\">{escape(last_src[0])}</a>")
        return head + body + tail

    body = (f"🟢 Ціль більше не згадується · була о {when:%H:%M}\n"
            f"\nКанали перестали про неї писати. Могла пролетіти далі, "
            f"бути збитою або вже влучити. Це не офіційний відбій.")
    # Джерело ОСТАННЬОЇ згадки — щоб можна було вручну перевірити, чи
    # справді ціль зникла, а не радар щось проґавив. Без цього мовчазне
    # зняття не давало жодного посилання взагалі.
    last_src = threat.get("last_src")
    tail = source_line(last_src) if last_src else ""
    return head + body + tail + "\n\n<i>висновок радара: мовчання каналів</i>"


def format_short(text: str, place_time, src=None) -> str:
    """Очень короткое повторное сообщение — чтобы разбудить."""
    tail = ""
    if src:
        tail = f" · <a href=\"{src[1]}\">джерело</a>"
    return f"❗️ <b>{text}</b>\n<i>{place_time:%H:%M} · повтор{tail}</i>"


def res_seen_rockets(radar, rockets) -> bool:
    """Чи повідомляли вже про таку саму кількість ракет за останні 20 хв."""
    if not radar.rockets:
        return False
    count, kind, when = radar.rockets
    if datetime.now() - when > timedelta(minutes=20):
        return False
    return count >= rockets[0] and kind == rockets[1]


class Dedup:
    """Склейка одинаковых событий, приходящих из разных каналов."""

    def __init__(self, window_min: int):
        self.window = timedelta(minutes=window_min)
        self.seen = {}
        self._load()

    def _load(self) -> None:
        if STATE_FILE.exists():
            try:
                raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
                self.seen = {k: datetime.fromisoformat(v) for k, v in raw.items()}
            except (json.JSONDecodeError, ValueError):
                log.warning("Файл состояния повреждён — начинаю с чистого")

    def save(self) -> None:
        data = {k: v.isoformat() for k, v in self.seen.items()}
        STATE_FILE.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def is_duplicate(self, key: str, when: datetime) -> bool:
        prev = self.seen.get(key)
        if prev and when - prev < self.window:
            return True
        self.seen[key] = when
        cutoff = when - self.window * 10          # чистим старое
        self.seen = {k: v for k, v in self.seen.items() if v > cutoff}
        return False


class Radar:
    """Монитор. Умеет работать в фоновом потоке и ставиться на паузу."""

    def __init__(self, on_alert=None, on_status=None):
        # on_alert(level, headline, text) — вызывается при отправке уведомления
        # on_status(text) — короткая строка состояния для интерфейса
        self.on_alert = on_alert
        self.on_status = on_status
        self.stats = {"seen": 0, "matched": 0, "sent": 0, "dupes": 0, "errors": 0}
        self.counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
                       "ALARM": 0, "CIVIL": 0}
        self.started = datetime.now()
        self.last_alert = None
        self.alarm, self.announced = load_state()   # стан і що вже в чаті
        self.active_threat = load_active_threat()  # конкретна ціль, про яку вже сповістили
        self.near_threat = None         # ціль «поруч» (сусіднє село) — легший стан, не переживає рестарт
        self.daily = load_daily()       # лічильники за добу
        self.critical = None            # епізод особливої небезпеки
        self.recent_high = []           # часи гучних сповіщень (для серії)
        self.recent_alerts = []         # (час, канал, посилання) — для позначки можливого дубляжу
        self.recent_sent = {}           # (тип, НП) -> (час, рівень): проти десяти сповіщень про одну ціль
        self.report_votes = []          # (час, канал, id) — зведення по області без нашої цілі
        self.moved_away = False         # уже сказали «ціль пішла далі» — не дублювати «минула»
        self._wake_reason = None        # чому оновлюємо закріплене
        self.standby = False            # резерв мовчить, поки живий онлайн
        self.mute_until = None          # тиша на годину: звук тимчасово вимкнено
        self.last_alarm_off = None      # коли надіслали відбій (проти дублів)
        self.last_false_alarm = None    # коли востаннє попередили про хибні цілі
        self.oblast = None              # (опис, посилання, час) — для закріпленого
        self.gone_votes = {}            # канали, що повідомили про зникнення цілі
        self.radiation_votes = {}       # канали, що повідомили про радіаційну загрозу
        self.rockets = None             # (скільки, тип, час) — ракети в області
        self.pending_impact = None      # вибух без пояснення: чекаємо уточнення
        self.recent_types = []          # (час, тип) — щоб визначати невідомі загрози
        self.last_types_by_channel = {}  # канал -> (час, типи): для ланцюжків
        self.client = None               # для огляду за кнопкою
        self.review = None               # (підсумок, час) — результат огляду
        self.mode_message = ""           # текст після перемикання локально/онлайн
        self._our_edit = None           # коли ми самі правили закріплене
        self.last_status_ok = None      # удалось ли последнее обновление статуса
        self.paused = False
        self.running = False
        self._stop = None
        self._status_dirty = None       # сигнал «обнови закреплённое сейчас»

    def _status(self, text: str) -> None:
        if self.on_status:
            self.on_status(text)

    async def _restore_alarm(self, client) -> None:
        """Восстанавливает обстановку по истории каналов при запуске.

        Иначе после перезапуска радар считает, что всё спокойно, даже если
        тривога триває — и закріплене повідомлення бреше. Сообщений в канал
        при восстановлении НЕ шлём, только выставляем состояние.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=ALARM_MAX_HOURS)
        events = []
        for channel in config.CHANNELS:
            try:
                async for msg in client.iter_messages(channel, limit=200):
                    if msg.date < cutoff:
                        break
                    text = msg.text or ""
                    if not text:
                        continue
                    state = classify.alarm_state(text)
                    if state:
                        events.append((msg.date, state, channel, msg.id))
            except Exception as e:                       # noqa: BLE001
                log.warning("не вдалося прочитати %s при відновленні: %s",
                            channel, type(e).__name__)

        if not events:
            log.info("відновлення: оголошень за %d год не знайдено",
                     ALARM_MAX_HOURS)
            return

        events.sort(key=lambda e: e[0])
        when, state, channel, msg_id = events[-1]
        local = when.astimezone().replace(tzinfo=None)
        src = (channel, f"https://t.me/{channel}/{msg_id}")

        if state[0] == "on":
            self.alarm = (state[1], local)
            log.info("відновлено: %s триває з %s", state[1],
                     local.strftime("%H:%M"))
        else:
            self.alarm = None
            log.info("відновлено: відбій о %s", local.strftime("%H:%M"))

        # В списке чатов видно последнее сообщение, а не закреплённое.
        # Если там висит устаревшее состояние — досылаем актуальное,
        # беззвучно и с пометкой, что это не новое оголошення.
        now_state = "on" if self.alarm else "off"
        if config.ANNOUNCE_ALARM and self.announced != now_state:
            kind = self.alarm[0] if self.alarm else ""
            sent = await self._announce(format_alarm(kind, local, bool(self.alarm),
                                                      restored=True, src=src))
            self.announced = now_state
            log.info("%s стан у чат: %s", "дослано" if sent else "резерв — не надсилаю",
                     now_state)

        save_state(self.alarm, self.announced)

    async def _restore_active_threat(self, client) -> None:
        """Відновлює активну ціль по історії каналів при запуску.

        Без цього рестарт (оновлення версії, збій, перезавантаження
        сервера) тихо забуває, за якою ціллю стежили — і повідомлення
        «загроза минула» ніколи не приходить, бо новому процесу
        нема що закривати. Свіжість (last_seen) береться з реальної
        дати повідомлення, тому наступна ж перевірка _watch_threat
        (раз на хвилину) сама вирішить, чи час її знімати.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=ALARM_MAX_HOURS)
        found = None
        for channel in config.CHANNELS:
            try:
                async for msg in client.iter_messages(channel, limit=30):
                    if msg.date < cutoff or not msg.text:
                        continue
                    res = classify.classify(msg.text)
                    if not res or res["level"] not in ("HIGH", "MEDIUM"):
                        continue
                    if not (res["level"] == "HIGH" or res.get("main_city")):
                        continue
                    if found is None or msg.date > found[0]:
                        main = geo.main_name()
                        place = main if main in res["places"] else (
                            res["places"][0] if res["places"] else main)
                        kind = res["threats"][0][0] if res["threats"] else ""
                        link = f"https://t.me/{channel}/{msg.id}"
                        found = (msg.date, place, kind, (channel, link))
            except Exception as e:                       # noqa: BLE001
                log.warning("не вдалося прочитати %s при відновленні цілі: %s",
                            channel, type(e).__name__)

        if not found:
            return
        when, place, kind, last_src = found
        local = when.astimezone().replace(tzinfo=None)

        # Якщо ціль уже застаріла станом на момент відновлення (застосунок
        # був вимкнений довше, ніж CLEAR_AFTER_MIN) — не відновлюємо її
        # як активну. Інакше перший же тік _watch_threat одразу шле
        # «загроза минула» про подію, що давно нікому не цікава, і в чаті
        # з'являється сплутане повідомлення з давнім часом посеред ночі.
        # Такий сценарій справді вже траплявся при перезапуску.
        if datetime.now() - local > timedelta(minutes=config.CLEAR_AFTER_MIN):
            log.info("ціль з %s вже застаріла на момент запуску — не відновлюю",
                     local.strftime("%H:%M"))
            return

        self.active_threat = {"place": place, "since": local, "last_seen": local,
                              "kind": kind, "last_src": last_src}
        save_active_threat(self.active_threat)
        log.info("відновлено активну ціль: %s, останнє згадування о %s",
                 place, local.strftime("%H:%M"))

    async def _refresh_with_review(self) -> None:
        """Смарт-перевірка і оновлення закріпленого. Помилки не глушимо.

        Заразом перевіряє активну ціль — але лише двома способами, тими
        самими, що й пасивно, без жодного «спрощеного» додаткового
        правила:
          1. Явне «не фіксується» / «збито» від каналу, що сам згадував
             саме цю ціль (city_gone) — знімаємо одразу.
          2. Реальна тиша каналів про цю ціль довше CLEAR_AFTER_MIN,
             рахуючи від active_threat["last_seen"] — той самий поріг,
             що й у пасивній _watch_threat, просто перевірений негайно
             за натиском кнопки, а не на наступному тіку раз на хвилину.
        Раніше тут була ще й «свіжість за оглядом» — 40-хвилинний, до
        того ж обмежений кількістю повідомлень міні-скан, який міг
        просто не побачити ціль, і тоді радар знімав загрозу вже через
        три хвилини тиші, ще коли всі канали кричали про ракету. Ціль
        не можна знімати «бо огляд її не знайшов» — лише за прямим
        підтвердженням або за-справжньою тривалою тишею.
        """
        try:
            if not config.SMART_REVIEW:
                # Вимкнено — кнопка лише перемальовує час, без огляду.
                # Без цього старий мінізвіт від попереднього натискання
                # (коли смарт-режим ще був увімкнений) висів би в
                # закріпленому й далі, до найближчого планового оновлення.
                self.review = None
            else:
                self.review = await self._smart_review()

                if config.CLEAR_THREAT and self.active_threat:
                    city_gone = self.review.get("city_gone")
                    # Сигнал зняття повинен бути НОВІШИЙ за останню відому
                    # згадку цілі — інакше стара «не фіксується» з початку
                    # 40-хвилинного вікна (про попередній, уже завершений
                    # епізод) могла б зняти щойно оголошену нову тривогу,
                    # яка почалась ПІЗНІШЕ за цей допис. Так одного разу
                    # загроза «знялася» за 10 хвилин ДО того, як реально
                    # оголосили нову.
                    when = self.review.get("city_gone_when")
                    if city_gone and when:
                        when_local = when.astimezone().replace(tzinfo=None)
                        if when_local <= self.active_threat["last_seen"]:
                            city_gone = False
                            log.info("gone-сигнал з огляду застарів "
                                    "(%s ⩽ останньої згадки %s) — ігнорую",
                                    when_local.strftime("%H:%M"),
                                    self.active_threat["last_seen"]
                                    .strftime("%H:%M"))
                    quiet = (datetime.now() - self.active_threat["last_seen"])
                    silent_enough = quiet > timedelta(
                        minutes=config.CLEAR_AFTER_MIN)
                    if city_gone or silent_enough:
                        if city_gone:
                            # Явний сигнал — повідомлення так і мусить
                            # казати «не фіксується», а не «канали
                            # замовкли»: це різні речі, і радар не має
                            # права видавати одне за інше.
                            src = self.review.get("city_gone_link")
                            msg = format_gone(
                                self.active_threat,
                                self.review.get("city_gone_wording", ""),
                                self.review.get("city_gone_text", ""), src)
                        else:
                            msg = format_gone(self.active_threat, "")
                        sent = await self._announce(msg)
                        if sent:
                            log.info("загроза знята за смарт-перевіркою "
                                    "(кнопка, %s)",
                                    "явне «не фіксується»" if city_gone
                                    else f"мовчання {config.CLEAR_AFTER_MIN} хв")
                            self.active_threat = None
                            save_active_threat(None)
                            self.last_alert = None
                            self.critical = None
                        else:
                            log.warning("зняття загрози НЕ надіслано — "
                                       "ціль залишаю активною")
        except Exception:                                   # noqa: BLE001
            log.exception("огляд каналів не вдався")
            self.review = None
        finally:
            self._wake_reason = "кнопка"
            if self._status_dirty:
                self._status_dirty.set()

    async def _smart_review(self) -> dict:
        """Перечитує останні повідомлення всіх каналів і будує мікрозвіт.

        Потрібно, коли натискають «Оновити»: канали пишуть ланцюжком,
        і останнє повідомлення саме по собі нічого не каже.
        Повертає словник для status.format_review().
        """
        data = {"when": datetime.now(), "channels": 0, "messages": 0,
                "threats": 0, "oblast": 0, "near": 0, "by_type": {},
                "threat_items": [],
                "top": None, "top_when": None, "top_link": None,
                "top_gone": False,
                "oblast_link": None, "oblast_when": None,
                "city_last_seen": None, "city_gone": False,
                "city_gone_wording": "", "city_gone_text": "",
                "city_gone_link": None, "city_gone_when": None}
        if not self.client:
            return data

        now_utc = datetime.now(timezone.utc)
        cutoff = now_utc - timedelta(minutes=config.REVIEW_MINUTES)
        # Загрозу вважаємо ще актуальною, лише якщо про неї писали не
        # давніше CLEAR_AFTER_MIN тому — той самий поріг, що й для
        # зняття активної цілі. REVIEW_MINUTES (40 хв) — це лише як
        # глибоко читати історію, а не «наскільки старе ще вважати
        # живим»: без цієї різниці огляд показував ракету, про яку
        # востаннє писали 30+ хвилин тому, як актуальну просто тому,
        # що вона трапилась у вікні огляду.
        fresh_cutoff = now_utc - timedelta(minutes=config.CLEAR_AFTER_MIN)

        # Одну й ту саму ціль різні канали (і той самий канал ланцюжком
        # повідомлень) описують кілька разів. Рахуємо унікальні загрози
        # за ключем склейки дублів, а не кожне повідомлення окремо —
        # інакше «6 поруч» замість «1 шахед поруч».
        seen_keys = set()
        # Один канал часто описує ОДНУ ціль ланцюжком повідомлень, і
        # супутнє село в тексті змінюється від допису до допису (курс
        # рухається) — за ключем склейки такі дублі не збігаються.
        # Тому рахуємо не більше однієї загрози «місту» і однієї «поруч»
        # від кожного каналу за огляд: інакше рух однієї цілі роздувався
        # у кілька штук («поруч: 6» замість «поруч: 1»).
        threat_channels, near_channels = set(), set()
        # Канал часто сам знімає свою ціль повідомленням «не фіксується» /
        # «не спостерігається». Без цього смарт-огляд рахував саму згадку
        # загрози, навіть якщо той самий канал уже написав, що вона зникла —
        # і заголовок закріпленого («немає загроз») суперечив рядку огляду.
        # Повідомлення йдуть від найновішого до найстаршого, тому на
        # момент, коли доходимо до самого допису про загрозу, «зняття»
        # цього ж каналу вже потрапило в gone_channels.
        gone_channels = set()
        # Найсвіжіший сигнал зняття, чий власний контекст (те, на що він
        # відповідає) сам згадує головне місто — див. пояснення нижче
        # біля city_gone.
        city_gone_evidence = None
        # Ракети в області: (час, кількість, тип, канал, id) з усіх
        # каналів — групуємо по часу нижче, після циклу.
        oblast_hits = []

        for channel in config.CHANNELS:
            ok_channel = False
            try:
                async for msg in self.client.iter_messages(
                        channel, limit=config.REVIEW_LIMIT):
                    ok_channel = True
                    if msg.date < cutoff or not msg.text:
                        continue
                    data["messages"] += 1

                    # threat_gone сам перевіряє релевантність контексту
                    # (Зміїв / ближній круг / район) і відкидає «не
                    # фіксується», що насправді стосується вже іншого
                    # села, куди ціль встигла піти (Безлюдівка,
                    # Покотилівка...) до цього допису. Раніше тут
                    # передавався порожній контекст, і ця перевірка
                    # мовчки пропускалась — саме тому «не фіксується» про
                    # зовсім інше село помилково знімало загрозу місту.
                    # expected_kind: якщо зараз активна конкретна зброя
                    # (напр. Шахед), «не фіксується» про іншу зброю
                    # (Бандероль) поруч не повинно рахуватись як зняття
                    # нашої цілі — це просто інша ціль по сусідству.
                    reply_ctx = getattr(msg, "reply_text", None) or ""
                    expected_kind = (self.active_threat.get("kind", "")
                                     if self.active_threat else "")
                    gone_hit = classify.threat_gone(msg.text, reply_ctx,
                                                    expected_kind)
                    if gone_hit:
                        gone_channels.add(channel)
                        if (city_gone_evidence is None
                                or msg.date > city_gone_evidence[4]):
                            city_gone_evidence = (
                                gone_hit[0], msg.text, channel, msg.id,
                                msg.date)

                    res = classify.classify(msg.text)
                    if res and res["level"] in ("HIGH", "MEDIUM"):
                        key = res.get("key")
                        is_new_key = key not in seen_keys
                        # Додаємо в seen_keys лише свіжі згадки: інакше
                        # застаріла ракета з початку 40-хвилинного вікна
                        # «займала» ключ, і справді свіжа згадка того
                        # самого типу/місця від іншого каналу мовчки не
                        # рахувалась — «зайнято», хоча насправді той
                        # запис уже занадто старий, щоб на нього зважати.
                        if key and msg.date >= fresh_cutoff:
                            seen_keys.add(key)

                        if res.get("main_city"):
                            is_new = channel not in threat_channels
                            threat_channels.add(channel)
                            # Свіжість беремо з БУДЬ-якої згадки міста,
                            # навіть повторної: для рішення «чи ще
                            # актуально» важливо, коли про це писали
                            # востаннє, а не скільки разів за 40 хв.
                            if (data["city_last_seen"] is None
                                    or msg.date > data["city_last_seen"]):
                                data["city_last_seen"] = msg.date
                        elif res.get("near_home"):
                            is_new = channel not in near_channels
                            near_channels.add(channel)
                        else:
                            is_new = False

                        if is_new and is_new_key and msg.date >= fresh_cutoff:
                            # Загрозою місту рахуємо лише те, де назване
                            # саме воно. Решта, що справді поруч — «поруч».
                            # Якщо цей самий канал уже написав «не
                            # фіксується» — ціль не рахуємо як актуальну:
                            # інакше огляд суперечив би заголовку
                            # закріпленого, яке це зняття вже врахувало.
                            # msg.date >= fresh_cutoff — не рахуємо те, про
                            # що вже CLEAR_AFTER_MIN хвилин ніхто не пише:
                            # інакше стара ракета з початку 40-хвилинного
                            # вікна виглядала б у звіті як актуальна.
                            if res.get("main_city"):
                                if channel not in gone_channels:
                                    data["threats"] += 1
                                    # Не лише число, а й ЩО саме: «загроз 2»
                                    # без розшифровки перевірити ніяк.
                                    data["threat_items"].append({
                                        "t": msg.date.astimezone().strftime("%H:%M"),
                                        "kind": (res["threats"][0][0]
                                                 if res["threats"]
                                                 else "тип не вказано"),
                                        "ch": channel,
                                        "link": f"https://t.me/{channel}/{msg.id}",
                                    })
                            elif res.get("near_home"):
                                data["near"] += 1
                            for name, _e in res["threats"]:
                                data["by_type"][name] = \
                                    data["by_type"].get(name, 0) + 1

                        # Найсвіжіша і найважливіша загроза — для посилання
                        better = (data["top_when"] is None
                                  or msg.date > data["top_when"])
                        if better and (res.get("main_city")
                                       or data["top"] is None):
                            data["top"] = plain_headline(res)
                            data["top_when"] = msg.date
                            data["top_link"] = f"https://t.me/{channel}/{msg.id}"
                            data["top_gone"] = channel in gone_channels

                    hit = classify.oblast_rockets(msg.text)
                    if hit:
                        count, kind = hit
                        oblast_hits.append((msg.date, count, kind, channel,
                                           msg.id))
            except Exception:                               # noqa: BLE001
                continue
            if ok_channel:
                data["channels"] += 1

        # Явне підтвердження зняття рахуємо, лише якщо його власний
        # контекст сам згадує місто (city_gone_evidence) — інакше це
        # могло стосуватись іншого села, куди ціль устигла піти.
        if city_gone_evidence:
            wording, text, channel, msg_id, when = city_gone_evidence
            data["city_gone"] = True
            data["city_gone_wording"] = wording
            data["city_gone_text"] = text
            data["city_gone_link"] = (channel, f"https://t.me/{channel}/{msg_id}")
            data["city_gone_when"] = when

        # Ракети в області: рахуємо лише свіжі (не старші за
        # CLEAR_AFTER_MIN — якщо про них уже 10+ хвилин ніхто не пише,
        # показувати їх у міні-звіті як актуальні — вводити в оману).
        # Різні канали часто пишуть про ОДНУ й ту саму ракету протягом
        # однієї-двох хвилин — це не 2 окремі цілі, а один допис,
        # підтверджений кількома каналами, тому такі згадки групуємо і
        # рахуємо як одну подію (беремо найбільшу названу кількість).
        # А ось повідомлення з різницею в 5-10+ хвилин — це вже, швидше
        # за все, різні, окремі ракети, і їх додаємо одна до одної.
        fresh_hits = sorted(
            (h for h in oblast_hits
             if now_utc - h[0] <= timedelta(minutes=config.CLEAR_AFTER_MIN)),
            key=lambda h: h[0])
        clusters = []
        for hit in fresh_hits:
            if clusters and hit[0] - clusters[-1][-1][0] <= timedelta(minutes=2):
                clusters[-1].append(hit)
            else:
                clusters.append([hit])
        total = 0
        best_when, best_link = None, None
        for cluster in clusters:
            best = max(cluster, key=lambda h: h[1])
            total += best[1]
            if best_when is None or best[0] > best_when:
                best_when = best[0]
                best_link = f"https://t.me/{best[3]}/{best[4]}"
        data["oblast"] = total
        data["oblast_link"] = best_link
        data["oblast_when"] = best_when

        log.info("огляд: канали %d, повідомлень %d, загроз %d",
                 data["channels"], data["messages"], data["threats"])
        return data

    async def _standby_tick(self) -> None:
        """Одна перевірка режиму — чи зараз резерв, чи основний.

        КРИТИЧНО викликати цю перевірку ПЕРЕД будь-яким відновленням
        стану на старті (_restore_alarm/_restore_active_threat): вони
        самі можуть надіслати повідомлення в канал (наприклад «відбій»),
        а self.standby за замовчуванням False, поки перша перевірка ще
        не відбулась. Без виклику тут «до» — щойно запущений резервний
        екземпляр міг встигнути реально написати в канал раніше, ніж
        зрозуміти, що він резерв.
        """
        if config.ROLE != "backup":
            if self.standby:
                self.standby = False
                log.info("режим: основний — працюю")
            return

        ok, res = await asyncio.to_thread(
            notify.call, "getChat", {"chat_id": config.TARGET_CHAT_ID})
        if not ok or not isinstance(res, dict):
            return                            # мережа моргнула — стан не міняємо

        pinned = res.get("pinned_message") or {}
        edited = pinned.get("edit_date")
        if not edited:
            # Немає закріпленого взагалі — вважаємо, що активного
            # екземпляра немає, і резерв обережно бере роботу на себе.
            if self.standby:
                self.standby = False
                log.info("режим: резерв — закріпленого немає, починаю сам")
            return

        edited_at = datetime.fromtimestamp(edited)
        ours = self._our_edit and abs((edited_at - self._our_edit)
                                      .total_seconds()) < 90
        fresh = datetime.now() - edited_at < timedelta(
            minutes=config.STATUS_UPDATE_MIN * 2 + 5)

        alive = fresh and not ours
        if alive and not self.standby:
            self.standby = True
            log.info("режим: резерв — онлайн працює, мовчу")
        elif not alive and self.standby:
            self.standby = False
            log.warning("режим: резерв — онлайн не відповідає, беру роботу")
            await self._announce(
                "🔁 <b>РЕЗЕРВ УВІМКНЕНО</b>\n"
                "Основний екземпляр не відповідає. Працює запасний.")

    async def _check_standby(self) -> None:
        """Резервний режим: чи працює онлайн-екземпляр.

        Ознака життя онлайн-радара — свіжа правка закріпленого повідомлення,
        яку робили не ми. Якщо такої правки давно немає, резерв бере
        роботу на себе. Так два екземпляри не дублюють одне одного
        і не залишають канал без нагляду. Перша перевірка робиться ще
        до старту цього циклу — див. _standby_tick і його виклик у run().
        """
        while True:
            await asyncio.sleep(60)
            try:
                await self._standby_tick()
            except Exception:                                # noqa: BLE001
                # КРИТИЧНО: це саме той цикл, що вмикає резерв при збої
                # онлайну. Якщо він сам колись впаде без цього захисту —
                # аварійне перемикання просто перестане працювати,
                # непомітно для будь-кого.
                log.exception("_standby_tick впав — пропускаю цю перевірку")

    async def _announce(self, text: str) -> bool:
        """Шлёт объявление тривоги/відбою в канал. Завжди без звуку.

        Повертає, чи справді пішло повідомлення — щоб виклики, які потім
        пишуть у лог «дослано», не брехали, коли резерв мовчки нічого
        не надіслав (self.standby/self.paused).
        """
        if self.standby or self.paused:
            return False
        ok, info = await asyncio.to_thread(notify.send, text, True)
        if ok:
            self.stats["sent"] += 1
            self.counts["ALARM"] = self.counts.get("ALARM", 0) + 1
        else:
            self.stats["errors"] += 1
            log.error("оголошення НЕ надіслано: %s", info)
        return ok

    def _bump(self, field: str) -> None:
        """Увеличивает суточный счётчик, переводя дату при смене суток."""
        today = datetime.now().strftime("%Y-%m-%d")
        if self.daily.get("date") != today:
            previous = dict(self.daily)
            if previous.get("date"):
                PREV_FILE.write_text(json.dumps(previous, ensure_ascii=False),
                                     encoding="utf-8")   # звіт за вчора
            self.daily = {"date": today, "seen": 0, "threats": 0, "impacts": 0,
                          "alarms": 0, "civil": {}, "by_type": {},
                          "impact_types": {}, "threat_log": [],
                          "impact_log": []}
        self.daily[field] = self.daily.get(field, 0) + 1
        save_daily(self.daily)

    def _log_event(self, field: str, kind: str, place: str, src) -> None:
        """Записує подію в журнал доби: коли, що, де і ЗВІДКИ.

        Без цього звіт казав лише «прильотів 2» — а де саме і за яким
        повідомленням це порахувалось, перевірити було ніяк. Тепер під
        кожним числом видно рядки з часом, місцем і посиланням на
        першоджерело.
        """
        now = datetime.now()
        entry = {"at": now.isoformat(timespec="seconds"),
                 "t": now.strftime("%H:%M"),
                 "kind": kind or "тип не вказано",
                 "place": place or "—",
                 "ch": src[0] if src else "",
                 "link": src[1] if src else "",
                 "note": "", "note_link": "", "note_ch": ""}
        journal = self.daily.setdefault(field, [])
        journal.append(entry)
        del journal[:-EVENT_LOG_LIMIT]
        save_daily(self.daily)

    def _explain_impacts(self, text: str, src) -> None:
        """Пізніше з'ясувалось, що вибух був плановим розмінуванням.

        Канали спершу пишуть «вибух», радар чесно рахує це прильотом, і
        лише через півгодини з'являється «це були планові підривні
        роботи, щось пішло не за планом». Саме такий випадок і був.
        Заднім числом позначаємо вже записані прильоти — обережно
        («можливо») і з посиланням, щоб можна було звірити самому.
        """
        journal = self.daily.get("impact_log") or []
        now = datetime.now()
        marked = 0
        for entry in journal:
            if entry.get("note"):
                continue
            try:
                when = datetime.fromisoformat(entry["at"])
            except (ValueError, KeyError):
                continue
            if now - when > timedelta(hours=EXPLAIN_IMPACT_HOURS):
                continue
            entry["note"] = ("можливо, це були планові підривні роботи "
                             "(розмінування), а не приліт")
            entry["note_link"] = src[1] if src else ""
            entry["note_ch"] = src[0] if src else ""
            marked += 1
        if marked:
            save_daily(self.daily)
            log.info("уточнення заднім числом: %d приліт(и) позначено як "
                     "можливі планові підривні роботи", marked)

    def _bump_type(self, field: str, name: str) -> None:
        """Считает угрозы и прилёты по типам — для отчёта."""
        table = self.daily.setdefault(field, {})
        table[name] = table.get(name, 0) + 1
        save_daily(self.daily)

    def _bump_civil(self, name: str) -> None:
        """Считает иные угрозы по категориям — для суточного отчёта."""
        civil = self.daily.setdefault("civil", {})
        civil[name] = civil.get(name, 0) + 1
        save_daily(self.daily)

    def build_report(self, day: str = "today") -> str:
        """Отчёт за сутки. day: "today" или "yesterday"."""
        if day == "yesterday":
            try:
                data = json.loads(PREV_FILE.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError):
                return "📊 <b>Звіт за вчора</b>\n\nДаних за попередню добу немає."
            title = f"📊 <b>ЗВІТ ЗА {data.get('date', 'вчора')}</b>"
        else:
            data = self.daily
            title = (f"📊 <b>ЗВІТ ЗА СЬОГОДНІ</b> · станом на "
                     f"{datetime.now():%H:%M}")

        def block(caption, total, table, journal=None, with_place=False):
            """Число, розбивка за типами і сам перелік подій з джерелами.

            Саме перелік і робить звіт перевірним: видно, о котрій,
            що і де — і за яким повідомленням радар так вирішив.
            """
            lines = [f"{caption} <b>{total}</b>"]
            for name, count in sorted(table.items(), key=lambda kv: -kv[1]):
                lines.append(f"     └ {name.lower()}: {count}")
            journal = journal or []
            if not journal:
                return lines
            shown = journal[-EVENT_SHOW_LIMIT:]
            if len(journal) > len(shown):
                lines.append(f"     <i>(показано останні {len(shown)} з "
                             f"{len(journal)})</i>")
            for item in shown:
                what = item.get("kind", "").lower()
                where = f" · {escape(item.get('place', ''))}" if with_place else ""
                src_txt = ""
                if item.get("link"):
                    src_txt = (f" · <a href=\"{item['link']}\">"
                               f"{escape(item.get('ch') or 'джерело')}</a>")
                lines.append(f"     • {item.get('t', '')} · "
                             f"{escape(what)}{where}{src_txt}")
                if item.get("note"):
                    note_src = ""
                    if item.get("note_link"):
                        note_src = (f" · <a href=\"{item['note_link']}\">"
                                    f"{escape(item.get('note_ch') or 'джерело')}</a>")
                    lines.append(f"        ⚠️ <i>{escape(item['note'])}</i>"
                                 f"{note_src}")
            return lines

        lines = [title, ""]
        lines += block("🔴 Загроз Змієву:", data.get("threats", 0),
                       data.get("by_type") or {},
                       data.get("threat_log"))
        lines.append("")
        lines += block("💥 Прильотів поруч:", data.get("impacts", 0),
                       data.get("impact_types") or {},
                       data.get("impact_log"), with_place=True)
        lines += ["", f"🟡 Тривог по району: <b>{data.get('alarms', 0)}</b>"]

        civil = data.get("civil") or {}
        if civil:
            lines.append("🟣 Інше:")
            for name, count in sorted(civil.items(), key=lambda kv: -kv[1]):
                lines.append(f"     └ {name.lower()}: {count}")

        lines += ["", f"Переглянуто повідомлень: {data.get('seen', 0)}"]
        if day == "today" and self.alarm:
            lines.append(f"\n🟡 Зараз триває {self.alarm[0].lower()} "
                         f"з {self.alarm[1]:%H:%M}")
        lines.append("\n<i>Інформація орієнтовна: зібрана з Telegram-каналів "
                     "моніторингу й може містити неточності.</i>")
        text = "\n".join(lines)
        # Telegram не приймає повідомлення довші за 4096 символів — у
        # день з великою кількістю подій звіт просто не надіслався б.
        if len(text) > 3900:
            text = text[:3900].rsplit("\n", 1)[0] + "\n\n<i>…звіт скорочено</i>"
        return text

    async def _handle(self, event) -> None:
        """Telethon-адаптер: дістає прості дані з event і йде в _ingest."""
        text = event.message.text or ""
        chat = await event.get_chat()
        username = getattr(chat, "username", "") or "?"

        reply_text = None
        try:
            if config.FILTER_CONTEXT and event.message.reply_to:
                parent = await event.message.get_reply_message()
                if parent and parent.text:
                    reply_text = parent.text
        except Exception:                                    # noqa: BLE001
            pass

        await self._ingest(username, event.message.id, event.message.date,
                           text, reply_text)

    async def _ingest(self, username: str, msg_id: int, date, text: str,
                      reply_text: str | None) -> None:
        """Обробка одного повідомлення каналу — не залежить від джерела.

        Викликається і з Telethon (_handle, локальний режим — потрібен
        файл сесії), і з опитування публічних сторінок t.me/s/<канал>
        (_poll_public, хмарний режим — файлу сесії не потребує взагалі,
        бо канали публічні).
        """
        self.stats["seen"] += 1
        self._bump("seen")
        if not text or self.paused or self.standby:
            return

        # Ссылку на первоисточник готовим сразу: она нужна каждому
        # уведомлению — тревоге, відбою, зняттю загрози, повторам.
        link = f"https://t.me/{username}/{msg_id}"
        src = (username, link)

        # Канали часто відповідають самі собі: «дві ракети в районі» →
        # «одна на Змиев, друга далі». Без контексту відповідь незрозуміла.
        context = reply_text or ""

        # Объявление тревоги по нашему району в канал не шлём —
        # оно только меняет закреплённое сообщение, беззвучно.
        alarm_changed = False
        if config.TRACK_OBLAST_ALARM:
            state = classify.alarm_state(text)
            if state:
                kind = state[1]
                now = datetime.now()
                if state[0] == "on" and (self.alarm is None
                                         or self.alarm[0] != kind):
                    self.alarm = (kind, now)
                    alarm_changed = True
                    self._bump("alarms")
                    log.info("тривога по району: %s", kind)
                    if config.ANNOUNCE_ALARM:
                        await self._announce(format_alarm(kind, now, True,
                                                          src=src))
                        self.announced = "on"
                    save_state(self.alarm, self.announced)
                elif state[0] == "off" and self.alarm:
                    self.alarm = None
                    alarm_changed = True
                    log.info("відбій тривоги по району")
                    if config.ANNOUNCE_ALARM:
                        await self._announce(format_alarm("", now, False,
                                                          src=src))
                        self.announced = "off"
                        self.last_alarm_off = now
                    save_state(None, self.announced)
                if alarm_changed and self._status_dirty:
                    self._status_dirty.set()

        # Канали пізніше пояснили вибух: це були планові підривні роботи.
        # Перевіряємо ДО класифікації, бо саме таке повідомлення саме по
        # собі сповіщення не дає (це INFO, який може бути вимкнений), а
        # вже записаний «приліт» лишався б у звіті без пояснення.
        if classify.planned_works(text) and (
                geo.find_zmiiv(text.lower()) or geo.find_close(text.lower())
                or geo.find_home_district(text.lower())):
            self._explain_impacts(text, src)

        # Свет, вода, газ, химия, ДРГ, радиация — без звука.
        # Исключение: радиационная угроза, она со звуком.
        if config.SEND_CIVIL:
            civil = classify.civil_state(text)
            if civil:
                emoji, name, loud, body = civil
                key = classify.dedup_key("CIVIL", [name], [], body)
                if not self.dedup.is_duplicate(key, date
                                               or datetime.now(timezone.utc)):
                    # Радіаційна загроза — це серйозно, і саме тому
                    # найлегше сплутати через одну помилку чи описку
                    # першоджерела. Впевнено кричимо, лише коли
                    # підтвердили два РІЗНІ канали протягом години;
                    # від одного каналу — обережне «можливо».
                    head = name.upper()
                    if name == "Радіаційна загроза":
                        now_ts = datetime.now()
                        self.radiation_votes[username] = now_ts
                        votes = len([t for t in self.radiation_votes.values()
                                    if now_ts - t < timedelta(hours=1)])
                        if votes < 2:
                            head = f"МОЖЛИВО: {name.upper()}"
                            log.info("радіаційна загроза: 1 канал (%s) — "
                                    "«можливо»", username)
                        else:
                            log.info("радіаційна загроза: %d канали "
                                    "підтвердили", votes)
                    msg = (f"{emoji} <b>{head}</b>\n"
                           f"{emoji} Інше · не повітряна загроза\n"
                           f"\n{escape(body)[:500]}\n"
                           f"\n<i>{escape(username)}</i> · "
                           f"<a href=\"{link}\">джерело</a>")
                    ok, info = await asyncio.to_thread(notify.send, msg, not loud)
                    if ok:
                        self.stats["sent"] += 1
                        self.counts["CIVIL"] += 1
                        self._bump_civil(name)
                        log.info("CIVIL відправлено [%s] %s", name, body[:50])
                    else:
                        self.stats["errors"] += 1
                        log.error("CIVIL НЕ відправлено: %s", info)
                    self.dedup.save()
                return

        # Канал попереджає про масові хибні спрацьовування ППО по цілі
        # (наприклад «Бандероль»). Це не про конкретну ціль, а загальне
        # попередження — надсилаємо не частіше ніж раз на годину, щоб
        # кілька таких дописів поспіль не спамили канал.
        notice = classify.false_alarm_notice(text)
        if notice:
            now_ts = datetime.now()
            if (self.last_false_alarm is None
                    or now_ts - self.last_false_alarm > timedelta(hours=1)):
                msg = ("⚠️ <b>МОЖЛИВІ ХИБНІ СПРАЦЬОВУВАННЯ</b>\n"
                      f"⚠️ {notice.capitalize()}\n"
                      f"\n{escape(text)[:400]}\n"
                      f"\n<i>Це попередження від {escape(username)}, "
                      "не висновок радара.</i>" + source_line(src))
                ok, info = await asyncio.to_thread(notify.send, msg, True)
                if ok:
                    self.stats["sent"] += 1
                    self.last_false_alarm = now_ts
                    log.info("попередження про хибні цілі надіслано (%s)",
                             username)
                else:
                    self.stats["errors"] += 1
                    log.error("попередження про хибні цілі НЕ надіслано: %s",
                              info)
            return

        # Ціль пішла в інший бік — це не відбій, казати «все добре» рано
        if self.active_threat and context:
            parent_clean = classify.clean(context).lower()
            away = (classify.moved_away(text)
                    if geo.find_zmiiv(parent_clean) else None)
            if away:
                await self._announce(
                    f"🟡 <b>ЦІЛЬ ПІШЛА ДАЛІ → {escape(away)}</b>\n"
                    f"🟡 Загроза Змієву зменшилась, але це <b>не відбій</b>.\n"
                    f"Ціль може повернутися. Залишайтесь в укритті "
                    f"до офіційного відбою." + source_line(src))
                log.info("ціль пішла далі: %s", away)
                # Про цю ціль уже сказано. Через 10 хвилин тиші не треба
                # присилати ще й «загроза, скоріше за все, минула» — це
                # те саме іншими словами, і виглядає як нова подія.
                self.moved_away = True
                self.critical = None
                if self._status_dirty:
                    self._status_dirty.set()
                return

        # Канал повідомив, що ціль зникла або збита.
        # Один канал — ще не відбій: чекаємо підтвердження другого.
        if config.CLEAR_THREAT and not self.active_threat:
            # Діагностика: якщо схоже на «зняття», але activate_threat уже
            # порожній — саме так виглядав би пропуск оголошення «загроза
            # минула» (ціль зняли раніше, ніж прийшла ця відповідь).
            if classify.threat_gone(text, context):
                log.info("gone-сигнал від %s, але active_threat вже порожній "
                         "— пропускаю", username)
        if config.CLEAR_THREAT and self.active_threat:
            # classify.threat_gone сам перевіряє релевантність контексту
            # (Зміїв / ближній круг / район) і тип зброї (expected_kind) —
            # без другого шахед і бандероль поруч гасили б одне одного.
            gone = classify.threat_gone(text, context,
                                        self.active_threat.get("kind", ""))
            # Допис старіший за останню відому згадку цілі — стосується
            # попереднього, вже завершеного епізоду, а не щойно
            # оголошеної нової тривоги. Рідкісний випадок (канал з
            # затримкою публікації), але саме так одного разу «зняття»
            # прийшло раніше за саму тривогу.
            stale = False
            if gone and date:
                msg_local = date.astimezone().replace(tzinfo=None)
                stale = msg_local <= self.active_threat["last_seen"]
            if gone:
                other_region = geo.mentions_other_region(text.lower())
                log.info("gone-сигнал від %s: %s (враховано: %s)",
                         username, gone[0], not other_region and not stale)
            if gone and not geo.mentions_other_region(text.lower()) and not stale:
                self.gone_votes[username] = datetime.now()
                votes = len([t for t in self.gone_votes.values()
                             if datetime.now() - t < timedelta(minutes=15)])
                self.critical = None          # повтори зупиняємо одразу

                if votes < 2 and config.FILTER_VOTES:
                    await self._announce(
                        f"🟡 <b>{gone[0].upper()} → "
                        f"{self.active_threat['place']}</b>\n"
                        f"🟡 Про це повідомив поки що один канал. "
                        f"Це <b>не відбій</b> — чекаємо підтвердження."
                        + source_line(src))
                    log.info("зняття загрози: 1 голос (%s)", username)
                else:
                    sent = await self._announce(format_gone(
                        self.active_threat, gone[0], gone[1], src=src))
                    if sent:
                        log.info("знято загрозу: %d канали підтвердили", votes)
                        self.active_threat = None
                        save_active_threat(None)
                        self.last_alert = None
                        self.gone_votes.clear()
                    else:
                        # Якщо повідомлення не пішло (збій мережі,
                        # standby) — НЕ знімаємо ціль мовчки: інакше
                        # закріплене показало б «загроз немає», а в чат
                        # ніхто так і не дізнався б, що загроза минула.
                        # Спробуємо ще раз при наступній згадці/тіку.
                        log.warning("зняття загрози НЕ надіслано — "
                                   "ціль залишаю активною до наступної спроби")
                if self._status_dirty:
                    self._status_dirty.set()
                return

        # Ракети в області: курс може змінитися, тому попереджаємо.
        # Одна-дві — тихо, більше двох — зі звуком.
        rockets = classify.oblast_rockets(text)
        if rockets and not res_seen_rockets(self, rockets):
            count, kind = rockets
            self.rockets = (count, kind, datetime.now())
            loud = count > 2
            await asyncio.to_thread(
                notify.send,
                f"🟡 <b>{'УВАГА · ' if loud else ''}РАКЕТИ В ОБЛАСТІ</b>\n"
                f"🟡 {kind}: {count} в Харківській області\n"
                f"\nЗагрози саме Змієву поки немає, але курс може "
                f"змінитися. Будьте уважні." + source_line(src),
                not loud or self.is_muted())
            self.stats["sent"] += 1
            log.info("ракети в області: %d × %s (звук: %s)", count, kind, loud)
            if self._status_dirty:
                self._status_dirty.set()

        # ЗВЕДЕННЯ ПО ОБЛАСТІ ЯК ПІДСТАВА ЗНЯТИ ЦІЛЬ.
        # Канали раз на кілька хвилин дають повний зріз усього, що зараз
        # летить по області. Якщо в СВІЖОМУ зрізі нашої цілі вже немає —
        # її вже немає: вона долетіла, збита або пішла. Чекати 10 хвилин
        # тиші, щоб це зрозуміти, не треба.
        #
        # Одного зрізу мало (канал міг просто не написати про ціль),
        # тому потрібно кілька — скільки саме, задає налаштування.
        if config.REPORT_CLEAR and config.CLEAR_THREAT and self.active_threat:
            report = reader.area_report(text)
            if report:
                now_rep = datetime.now()
                place = self.active_threat["place"]
                self.report_votes = [
                    v for v in self.report_votes
                    if now_rep - v[0] < timedelta(minutes=REPORT_VOTE_MIN)]
                if place in report["places"]:
                    # Ціль усе ще в зведенні — усі попередні голоси
                    # недійсні, відлік починається заново.
                    if self.report_votes:
                        log.info("ціль %s знову у зведенні — голоси скинуто",
                                 place)
                    self.report_votes = []
                    self.active_threat["last_seen"] = now_rep
                    self.active_threat["last_src"] = src
                    save_active_threat(self.active_threat)
                elif not any(v[1] == username and v[2] == msg_id
                             for v in self.report_votes):
                    self.report_votes.append((now_rep, username, msg_id))
                    votes = len(self.report_votes)
                    log.info("зведення по області без цілі %s: %d з %d",
                             place, votes, config.REPORT_CLEAR_VOTES)
                    if votes >= config.REPORT_CLEAR_VOTES:
                        sent = await self._announce(format_gone(
                            self.active_threat,
                            "у свіжих зведеннях по області цілі вже немає",
                            f"Перевірено за {votes} зведеннями обстановки "
                            f"по області — ця ціль у них більше не згадується.",
                            src=src))
                        if sent:
                            log.info("ціль знята за зведеннями (%d)", votes)
                            self.active_threat = None
                            save_active_threat(None)
                            self.last_alert = None
                            self.critical = None
                            self.report_votes = []
                            self.gone_votes.clear()
                            if self._status_dirty:
                                self._status_dirty.set()

        # Обстановка по області — тільки в закріплене, без сповіщень
        summary = classify.oblast_summary(text)
        if summary:
            self.oblast = (summary[0], link, datetime.now())
            if self._status_dirty:
                self._status_dirty.set()
        elif self.oblast:
            # Свіже повідомлення каже «чисто в області/районі» — старий
            # підрахунок цілей у закріпленому вже не актуальний, навіть
            # якщо він ще не старший за 20-хвилинне вікно показу. Раніше
            # закріплене показувало застарілу кількість аж до таймауту.
            area_gone = classify.threat_gone(text)
            if area_gone and area_gone[0] in ("чисто в області",
                                              "чисто в районі"):
                self.oblast = None
                if self._status_dirty:
                    self._status_dirty.set()

        # Копимо, які типи загроз згадують канали: за ними визначаємо
        # тип там, де його не назвали.
        now_ts = datetime.now()
        self.recent_types = [(t, k) for t, k in self.recent_types
                             if now_ts - t < timedelta(minutes=15)]
        for name, _emoji in threats.detect_threats(text.lower()):
            self.recent_types.append((now_ts, name))

        # Уточнення до незрозумілого вибуху: інший канал назвав тип.
        # «Загроза артобстрілу» уточненням НЕ вважається: це попередження
        # про можливість, а не пояснення того, що вже гримнуло.
        if (config.SMART_EXPLAIN and self.pending_impact
                and datetime.now() - self.pending_impact["when"]
                < timedelta(minutes=10)):
            low_text = text.lower()
            warning = any(m in low_text for m in
                          ("загроза артобстріл", "загроза обстріл",
                           "угроза артобстрел", "угроза обстрел",
                           "можлив", "ймовірн"))
            kinds = [n for n, _e in threats.detect_threats(low_text)
                     if n not in ("Артилерія", "Загроза пуску")]
            near_here = (geo.find_zmiiv(low_text) or geo.find_close(low_text)
                         or geo.find_home_district(low_text))
            if kinds and near_here and not warning:
                place = self.pending_impact["place"]
                self.pending_impact = None
                await self._announce(
                    f"🔎 <b>{place.upper()} · ЙМОВІРНЕ ДЖЕРЕЛО ВИБУХУ</b>\n"
                    f"🔎 Схоже на <b>{kinds[0]}</b> — за повідомленнями "
                    f"інших каналів у той самий час.\n"
                    f"\n<i>Це автоматичний висновок, він може бути "
                    f"хибним. Перевірте джерело.</i>" + source_line(src))
                log.info("уточнено вибух: %s", kinds[0])

        res = classify.classify(text)
        if not res:
            return
        self.stats["matched"] += 1

        # Канали часто пишуть ланцюжком: спершу «Шахеди:», далі самі
        # цифри й напрямки. Тип беремо з попереднього повідомлення
        # цього ж каналу, якщо воно свіже.
        own = threats.detect_threats(text.lower())
        if own:
            self.last_types_by_channel[username] = (now_ts, own[0][0])
        elif not res.get("threats"):
            prev = self.last_types_by_channel.get(username)
            if prev and now_ts - prev[0] < timedelta(minutes=10):
                res["guess"] = prev[1]

        # Тип не названий — підказуємо його з обстановки в області
        if not res["threats"] and res["level"] in ("HIGH", "MEDIUM"):
            guess = self._guess_type()
            if guess:
                res["guess"] = guess

        # Уровни, отключённые в настройках, дальше не идут
        if res["level"] == "MEDIUM" and not config.SEND_MEDIUM:
            return
        if res["level"] == "LOW" and not config.SEND_LOW:
            return
        # Відбій уже пішов у канал — другий раз не потрібен.
        # Раніше дубль приходив, коли про відбій писали два канали:
        # перший міняв стан тривоги, другий проходив як звичайний LOW.
        # Про відбій повідомляє тільки механізм тривоги — одним
        # повідомленням. Раніше той самий відбій приходив двічі:
        # як оголошення і як звичайний LOW з іншого каналу, причому
        # у будь-якому порядку.
        if (res["level"] == "LOW" and config.ANNOUNCE_ALARM
                and config.TRACK_OBLAST_ALARM):
            return
        if res["level"] == "INFO" and not config.SEND_INFO:
            return

        when = date or datetime.now(timezone.utc)
        if self.dedup.is_duplicate(res["key"], when):
            self.stats["dupes"] += 1
            log.info("дубль (%s) — пропуск: %s", res["level"], res["text"][:60])
            # Дубль не шлемо в канал, але це РЕАЛЬНА, свіжа згадка тієї
            # самої цілі — якщо цю ж ціль зараз стежимо, оновлюємо
            # last_seen. Без цього при частих повторах (кожні 1-3 хв,
            # усі в межах вікна дедуплікації) активна ціль «протухала» б
            # за лічені хвилини, хоча канали пишуть про неї безперервно —
            # саме так кнопка «Оновити» одного разу зняла загрозу одразу
            # після свіжого повідомлення про ту саму ракету.
            if self.active_threat and (
                    res["level"] == "HIGH"
                    or (res["level"] == "MEDIUM" and res.get("main_city"))):
                main = geo.main_name()
                place = main if main in res["places"] else (
                    res["places"][0] if res["places"] else main)
                if self.active_threat["place"] == place:
                    self.active_threat["last_seen"] = datetime.now()
                    self.active_threat["last_src"] = src
                    save_active_threat(self.active_threat)
            return

        # Можливий дубляж з іншого каналу: та сама ціль (місто чи сусіднє
        # село) уже згадувалась нещодавно, просто з іншого джерела.
        # Радар НЕ об'єднує цілі (це ризиковано й може помилятись) —
        # лише додає позначку в текст і не рахує подію в серію для
        # «Особливої небезпеки», щоб кілька каналів, які пишуть про
        # одну ціль, самі не викликали зайву серію гучних повторів.
        dup_src = None
        relevant = res["level"] in ("HIGH", "MEDIUM") and (
            res.get("main_city") or res.get("near_home"))

        # ПОВТОРИ ПРО ТУ САМУ ЦІЛЬ. Один шахед над Зміївом давав до
        # десяти однакових сповіщень поспіль — по одному з кожного
        # каналу. Тепер у чат іде лише перше, решта тихо оновлює
        # закріплене й час останньої згадки цілі.
        #
        # Глушимо ТІЛЬКИ рівний або слабший повтор: якщо загроза
        # виросла (стала HIGH замість MEDIUM або з'явилась масовість) —
        # повідомлення піде обов'язково.
        if config.REPEAT_WINDOW_MIN and relevant:
            now_rep = datetime.now()
            kind = res["threats"][0][0] if res["threats"] else "—"
            main = geo.main_name()
            spot = main if main in res["places"] else (
                res["places"][0] if res["places"] else main)
            rkey = (kind, spot)
            prev = self.recent_sent.get(rkey)
            self.recent_sent = {
                k: v for k, v in self.recent_sent.items()
                if now_rep - v[0] < timedelta(minutes=config.REPEAT_WINDOW_MIN)}
            grew = bool(res.get("mass_reason")) or (
                prev and res["level"] == "HIGH" and prev[1] != "HIGH")
            if prev and not grew:
                self.stats["dupes"] += 1
                log.info("повтор про ту саму ціль (%s · %s) з %s — у чат не "
                         "дублюю", kind, spot, username)
                if self.active_threat and self.active_threat["place"] == spot:
                    self.active_threat["last_seen"] = now_rep
                    self.active_threat["last_src"] = src
                    save_active_threat(self.active_threat)
                if self.near_threat and self.near_threat["place"] == spot:
                    self.near_threat["last_seen"] = now_rep
                if self._status_dirty:
                    self._status_dirty.set()
                return
            self.recent_sent[rkey] = (now_rep, res["level"])

        if config.DUP_NOTICE_ENABLED and relevant:
            now_check = datetime.now()
            self.recent_alerts = [a for a in self.recent_alerts if now_check
                                  - a[0] < timedelta(minutes=DUP_NOTICE_WINDOW_MIN)]
            for _when, a_channel, a_link in self.recent_alerts:
                if a_channel != username:
                    dup_src = (a_channel, a_link)
                    break

        # HIGH — со звуком, остальное тихо. В тихие часы звук снимается
        # и с HIGH: сообщение приходит, но не будит.
        # Зі звуком — лише коли радар упевнений. Невпевнений висновок
        # не має права будити: саме так планове розмінування колись
        # прийшло як «наслідки прильоту».
        silent = (res["level"] != "HIGH"
                  or (res.get("confidence") == "low"
                      and config.FILTER_CONFIDENCE)
                  or config.in_quiet_hours(datetime.now().hour)
                  or self.is_muted())
        ok, info = await asyncio.to_thread(
            notify.send, format_message(res, username, link, dup_src), silent)
        if ok:
            if relevant:
                self.recent_alerts.append((datetime.now(), username, link))
            self.stats["sent"] += 1
            self.counts[res["level"]] += 1
            # Запоминаем конкретную цель, чтобы потом сообщить, когда
            # каналы перестанут о ней писать
            # «Загроз Змієву» — только про главный город, а не про
            # дополнительные и не про соседние сёла.
            if res["level"] == "HIGH" and res.get("main_city"):
                self._bump("threats")
                for name, _emoji in res["threats"]:
                    self._bump_type("by_type", name)
                if not res["threats"]:
                    self._bump_type("by_type", res.get("guess") or "невідомо")
                self._log_event(
                    "threat_log",
                    res["threats"][0][0] if res["threats"]
                    else (res.get("guess") or "тип не вказано"),
                    geo.main_name(), src)

            # «Прильотів» — только если взрыв или прилёт случился
            # в самом городе, в его сёлах или в нашем районе.
            # Раньше сюда попадал любой взрыв где угодно в области.
            # Незрозумілий вибух: тип не названий. Запам'ятовуємо і
            # чекаємо, чи пояснять інші канали протягом 10 хвилин.
            if (classify.is_impact(res["text"].lower())
                    and res.get("impact_zone") and not res["threats"]):
                self.pending_impact = {"when": datetime.now(),
                                       "place": (res["places"] or ["район"])[0]}

            if (classify.is_impact(res["text"].lower())
                    and res.get("impact_zone")):
                self._bump("impacts")
                for name, _emoji in res["threats"]:
                    self._bump_type("impact_types", name)
                self._log_event(
                    "impact_log",
                    res["threats"][0][0] if res["threats"] else "вибух",
                    (res["places"] or ["район"])[0], src)

            # Стан (активна ціль, заголовок закріпленого) виставляємо
            # ДО «особливої небезпеки» нижче: _raise_critical шле пачку
            # повторів з паузами між ними, а тим часом _critical_loop
            # (тік раз на 10 с) перевіряє active_threat і, побачивши
            # його порожнім, одразу закриває епізод після першої ж
            # пачки. Раніше active_threat виставлявся вже ПІСЛЯ виклику
            # _raise_critical — і саме тому серія іноді уривалась на
            # «1 пачці» замість того, щоб тривати, поки триває обстріл.
            if res["level"] == "HIGH" or (res["level"] == "MEDIUM"
                                          and res.get("main_city")):
                now_ts = datetime.now()
                main = geo.main_name()
                place = main if main in res["places"] else (
                    res["places"][0] if res["places"] else main)
                kind = res["threats"][0][0] if res["threats"] else ""
                if self.active_threat and self.active_threat["place"] == place:
                    self.active_threat["last_seen"] = now_ts
                    self.active_threat["last_src"] = src
                    # Тип не перезаписуємо, якщо він уже відомий: інакше
                    # згадка іншої зброї в тому самому місці (шахед і
                    # бандероль поруч) тихо підмінила б собою першу ціль,
                    # і «не фіксується» про НОВУ зброю знімало б СТАРУ.
                    if not self.active_threat.get("kind"):
                        self.active_threat["kind"] = kind
                else:
                    self.active_threat = {"place": place, "since": now_ts,
                                          "last_seen": now_ts, "kind": kind,
                                          "last_src": src}
                    # Нова ціль — прапорець «уже сказали, що пішла далі»
                    # стосувався попередньої, скидаємо.
                    self.moved_away = False
                    self.report_votes = []
                save_active_threat(self.active_threat)
            elif res["level"] == "MEDIUM":
                # «Поруч» (сусіднє село чи ціль курсом на віддалене село
                # з дальнього поясу — near_home тут не обов'язково True)
                # досі не мав власного закриття: на відміну від
                # active_threat, він ніколи не знімався по тиші —
                # «загроза минула» про такі цілі просто ніколи не
                # приходила. Окремий, легший стан: не займає active_threat
                # (інакше сусіднє село тихо підмінило б собою реальну
                # ціль по місту). Умова тут ловить БУДЬ-яке MEDIUM, що не
                # потрапило у гілку вище (main_city вже виключено там).
                now_ts = datetime.now()
                near_place = res["places"][0] if res["places"] else "поруч"
                if self.near_threat and self.near_threat["place"] == near_place:
                    self.near_threat["last_seen"] = now_ts
                else:
                    self.near_threat = {"place": near_place, "since": now_ts,
                                        "last_seen": now_ts}
            if res.get("main_city"):
                self.last_alert = (datetime.now(), res["level"],
                                   plain_headline(res))

            # Особлива небезпека: масова або важка загроза, або серія
            # гучних сповіщень підряд. Одна ціль повторів не дає.
            if config.CRITICAL_ENABLED and res["level"] == "HIGH":
                now_ts = datetime.now()
                self.recent_high = [t for t in self.recent_high
                                    if now_ts - t < timedelta(minutes=10)]
                # dup_src — підозра, що це не нова ціль, а той самий
                # об'єкт з іншого каналу: не рахуємо в серію повторів.
                if res.get("main_city") and not dup_src:
                    self.recent_high.append(now_ts)
                series = (len(self.recent_high) >= config.CRITICAL_SERIES
                          and res.get("main_city"))
                if series and config.SMART_BEFORE_SERIES:
                    # Перед тим як спамити серією, перевіряємо по каналах,
                    # чи справді загроз кілька. Раніше серія спрацьовувала
                    # від повторів про одну й ту саму ціль.
                    check = await self._smart_review()
                    self.review = check
                    if check["threats"] < config.CRITICAL_SERIES:
                        log.info("серія скасована: за оглядом загроз %d",
                                 check["threats"])
                        series = False
                        self.recent_high = []
                if res.get("mass_reason") or series:
                    await self._raise_critical(res, series, src)

            log.info("%s отправлено [%s] %s", res["level"], res["reason"],
                     res["text"][:60])
            if self.on_alert:
                self.on_alert(res["level"], plain_headline(res), res["text"])
        else:
            self.stats["errors"] += 1
            log.error("НЕ отправлено (%s): %s", info, res["text"][:60])
        self._status(f"відправлено {self.stats['sent']}")

        # Закреплённое сообщение должно отражать тревогу сразу,
        # а не через десять минут по расписанию.
        if res["level"] in ("HIGH", "MEDIUM") and self._status_dirty:
            self._status_dirty.set()

        self.dedup.save()

    async def _heartbeat(self) -> None:
        """Пишет в лог, что радар жив.

        Без этого молчание в логе двусмысленно: то ли тревог нет,
        то ли радар перестал получать сообщения и мы об этом не знаем.
        Первая запись через минуту после старта, дальше раз в 15 минут.
        """
        await asyncio.sleep(60)
        while True:
            try:
                s = self.stats
                log.info("жив: переглянуто %d, надіслано %d, дублів %d, "
                        "помилок %d%s", s["seen"], s["sent"], s["dupes"],
                        s["errors"], " (ПАУЗА)" if self.paused else "")
                if s["seen"] == 0:
                    log.warning("за час роботи не надійшло жодного "
                               "повідомлення — перевірте список каналів "
                               "і мережу")
            except Exception:                                # noqa: BLE001
                log.exception("_heartbeat впав на цій ітерації — продовжую")
            await asyncio.sleep(15 * 60)

    async def _raise_critical(self, res: dict, series: bool, src=None) -> None:
        """Начинает или продлевает эпизод особой опасности."""
        short = classify.short_alert(res)
        if series and not res.get("mass_reason"):
            short = f"СЕРІЯ ЗАГРОЗ · {short}"

        now_ts = datetime.now()
        if self.critical and now_ts - self.critical["started"] < timedelta(
                minutes=config.CRITICAL_EPISODE_MIN):
            # Эпизод уже идёт — обновляем текст, новую пачку не шлём:
            # её отправит таймер, чтобы не спамить очередями подряд.
            self.critical["short"] = short
            self.critical["last_event"] = now_ts
            self.critical["src"] = src or self.critical.get("src")
            return

        # ДВА РІВНІ ГУЧНОСТІ.
        # Пряма загроза самому місту («ракети на Зміїв», «10 шахедів
        # через Зміїв») — повна серія повторів, як і було.
        # Загроза по району чи сусідах («2-3 ракети на Чугуїв») — це
        # привід знати, але не привід кричати десять разів: одна
        # коротка серія з рідшими повторами, і на цьому все.
        scale = "full" if res.get("main_city") else "short"
        self.critical = {"short": short, "started": now_ts,
                         "last_event": now_ts, "last_burst": now_ts,
                         "bursts": 0, "src": src, "scale": scale}
        log.warning("ОСОБЛИВА НЕБЕЗПЕКА (%s): %s", scale, short)
        await self._send_burst()

    def _burst_plan(self) -> tuple:
        """Скільки повторів і з якою паузою. Залежить від рівня загрози."""
        if (self.critical or {}).get("scale") == "short":
            return SHORT_REPEATS, SHORT_INTERVAL_SEC, 1
        return (config.CRITICAL_REPEATS, config.CRITICAL_INTERVAL_SEC,
                config.CRITICAL_MAX_BURSTS)

    async def _send_burst(self) -> None:
        """Отправляет пачку коротких сообщений со звуком."""
        if not self.critical:
            return
        if self.paused:                # пауза глушить і повтори теж
            self.critical = None
            return
        repeats, interval, max_bursts = self._burst_plan()
        self.critical["bursts"] += 1
        self.critical["last_burst"] = datetime.now()
        head = self.critical["short"]
        if self.critical.get("scale") == "short":
            head = f"{head} · не саме {geo.main_name()}"
        for i in range(repeats):
            ok, info = await asyncio.to_thread(
                notify.send, format_short(head, datetime.now(),
                                          self.critical.get("src")),
                self.is_muted())
            if ok:
                self.stats["sent"] += 1
            else:
                self.stats["errors"] += 1
                log.error("повтор НЕ надіслано: %s", info)
            if i < repeats - 1:
                await asyncio.sleep(interval)
        log.warning("надіслано пачку повторів %d з %d",
                    self.critical["bursts"], max_bursts)

    async def _critical_loop(self) -> None:
        """Повторяет пачки, пока угроза жива, но не больше лимита."""
        while True:
            await asyncio.sleep(10)
            try:
                if not self.critical:
                    continue
                now_ts = datetime.now()

                # Эпизод закончился: давно нет новых сообщений или исчерпан лимит
                quiet = now_ts - self.critical["last_event"]
                _r, _i, max_bursts = self._burst_plan()
                if (quiet > timedelta(minutes=config.CRITICAL_EPISODE_MIN)
                        or self.critical["bursts"] >= max_bursts
                        or self.active_threat is None):
                    log.info("епізод особливої небезпеки завершено (%d пачок)",
                             self.critical["bursts"])
                    self.critical = None
                    continue

                # Обстрел продолжается — ещё пачка через минуту
                if now_ts - self.critical["last_burst"] >= timedelta(minutes=1):
                    await self._send_burst()
            except Exception:                                # noqa: BLE001
                log.exception("_critical_loop впав на цій ітерації — "
                              "продовжую")

    async def cancel_alarm(self, who: str = "вручну") -> str:
        """Скасовує ПОМИЛКОВУ тривогу, не вимикаючи радар.

        Тиша на годину глушить усе підряд, пауза зупиняє роботу — а тут
        треба інше: прибрати конкретну хибну ціль і повтори, лишивши
        радар працювати далі. Наступна справжня загроза підніме тривогу
        як звичайно.
        """
        had = bool(self.critical or self.active_threat or self.near_threat)
        place = (self.active_threat or self.near_threat or {}).get("place", "")
        self.critical = None
        self.active_threat = None
        self.near_threat = None
        self.last_alert = None
        self.gone_votes.clear()
        self.report_votes.clear()
        self.recent_high = []
        self.recent_sent = {}
        self.moved_away = False
        save_active_threat(None)
        if self._status_dirty:
            self._status_dirty.set()

        if not had:
            log.info("скасування тривоги (%s): активної цілі не було", who)
            return "Активної тривоги не було — закріплене оновлено."

        log.warning("ТРИВОГУ СКАСОВАНО %s (ціль: %s)", who, place or "—")
        await self._announce(
            f"⚪️ <b>ТРИВОГУ СКАСОВАНО ВРУЧНУ</b>\n"
            f"⚪️ Попереднє сповіщення{' про ' + escape(place) if place else ''}"
            f" визнано хибним.\n"
            f"\nРадар продовжує стежити — це не відбій офіційної тривоги."
            f"\n\n<i>скасував власник радара о {datetime.now():%H:%M}</i>")
        return f"Тривогу скасовано{(' · ' + place) if place else ''}"

    async def _watch_threat(self) -> None:
        """Снимает угрозу, если каналы перестали о ней писать.

        Проверка раз в минуту. Радар не утверждает, что цель сбита —
        только то, что о ней больше не пишут.
        """
        while True:
            await asyncio.sleep(60)
            try:
                if config.CLEAR_THREAT and self.active_threat:
                    quiet = datetime.now() - self.active_threat["last_seen"]
                    if quiet > timedelta(minutes=config.CLEAR_AFTER_MIN):
                        # Якщо вже сказали «ціль пішла далі» — знімаємо
                        # тихо: повторювати те саме іншими словами не
                        # треба, читач і так усе зрозумів.
                        if self.moved_away:
                            log.info("ціль знята мовчки: про неї вже "
                                     "повідомили, що пішла далі")
                            self.active_threat = None
                            save_active_threat(None)
                            self.last_alert = None
                            self.critical = None
                            self.moved_away = False
                            if self._status_dirty:
                                self._status_dirty.set()
                            continue
                        sent = await self._announce(
                            format_gone(self.active_threat, ""))
                        if sent:
                            log.info("загроза знята за мовчанням каналів "
                                    "(%d хв)", config.CLEAR_AFTER_MIN)
                            self.active_threat = None
                            save_active_threat(None)
                            self.last_alert = None  # закріплене повертається у спокій
                            self.critical = None
                            if self._status_dirty:
                                self._status_dirty.set()
                        else:
                            # Не знімаємо мовчки, якщо повідомлення не
                            # пішло — інакше закріплене «заспокоїться», а в
                            # чат ніхто так і не дізнається, що загроза
                            # минула. Спробуємо ще раз за хвилину.
                            log.warning("зняття загрози НЕ надіслано — "
                                       "ціль залишаю активною до наступної "
                                       "спроби")

                # Те саме, але для «поруч» (сусіднє село) — раніше такі
                # цілі взагалі не знімались: «загроза минула» про них
                # ніколи не приходила, і незрозуміло було, чи ще актуально.
                if config.CLEAR_THREAT and self.near_threat:
                    quiet = datetime.now() - self.near_threat["last_seen"]
                    if quiet > timedelta(minutes=config.CLEAR_AFTER_MIN):
                        sent = await self._announce(
                            format_gone(self.near_threat, ""))
                        if sent:
                            log.info("ціль «поруч» знята за мовчанням "
                                    "каналів (%d хв)", config.CLEAR_AFTER_MIN)
                            self.near_threat = None
                        else:
                            log.warning("зняття цілі «поруч» НЕ надіслано "
                                       "— залишаю активною до наступної "
                                       "спроби")
            except Exception:                                # noqa: BLE001
                log.exception("_watch_threat впав на цій ітерації — "
                              "продовжую")

    async def _poll_buttons(self) -> None:
        """Принимает нажатия кнопок: «Оновити» в канале и панель владельца."""
        offset, first = -1, True
        while True:
            if not (config.STATUS_REFRESH_BUTTON or config.TELEGRAM_CONTROL):
                await asyncio.sleep(30)
                continue
            if self.standby:            # слушает тот, кто сейчас работает
                await asyncio.sleep(30)
                continue
            try:
                updates, offset = await asyncio.to_thread(
                    notify.get_updates, offset, 25)
            except Exception:                            # noqa: BLE001
                await asyncio.sleep(5)
                continue

            if first:            # старые нажатия из очереди не отрабатываем
                first = False
                continue

            for upd in updates:
                try:
                    await self._handle_update(upd)
                except Exception:                        # noqa: BLE001
                    log.exception("помилка обробки команди")
            if not updates:
                await asyncio.sleep(1)

    async def _handle_update(self, upd: dict) -> None:
        """Разбирает одно обновление от Telegram."""
        query = upd.get("callback_query")
        if query:
            data = query.get("data") or ""
            if data == "refresh":                # кнопка под закреплённым
                log.info("натиснуто «Оновити» у каналі")
                # Відповідаємо одразу: Telegram гасить «часики» за секунди,
                # а огляд каналів триває довше. Раніше через це кнопка
                # виглядала як така, що не спрацювала.
                await asyncio.to_thread(
                    notify.answer_callback, query["id"],
                    "Перевіряю канали…" if config.SMART_REVIEW else "Оновлюю…")
                asyncio.create_task(self._refresh_with_review())
                return
            if data.startswith("ctl:"):
                await self._control(query, data[4:])
            return

        message = upd.get("message") or {}
        text = (message.get("text") or "").strip().lower()
        chat = message.get("chat") or {}
        if not text or chat.get("type") != "private":
            return
        await self._command(message, text)

    def _is_owner(self, user_id: int) -> bool:
        """Первый, кто написал боту, становится владельцем."""
        if not config.OWNER_ID:
            saved = settings.load()
            saved["owner_id"] = user_id
            settings.save(saved)
            config.reload_settings()
            log.warning("власника керування встановлено: id %s", user_id)
            return True
        return user_id == config.OWNER_ID

    async def _command(self, message: dict, text: str) -> None:
        """Текстовые команды в личной переписке с ботом."""
        if not config.TELEGRAM_CONTROL:
            return
        user_id = (message.get("from") or {}).get("id")
        chat_id = (message.get("chat") or {}).get("id")
        if not self._is_owner(user_id):
            log.info("команда від стороннього id %s — ігнорую", user_id)
            return

        if text in ("/start", "/panel", "/menu", "старт"):
            await asyncio.to_thread(
                notify.send_to, chat_id, PANEL_HELP,
                notify.control_panel(self.paused, self.is_muted(),
                                     config.FILTER_PLANNED,
                                     config.cloud_active(),
                                     config.SMART_REVIEW))
        elif text.startswith("/mute"):
            self.mute_until = datetime.now() + timedelta(hours=1)
            await asyncio.to_thread(notify.send_to, chat_id,
                                    f"🔕 Тиша до {self.mute_until:%H:%M}")
        elif text.startswith("/local"):
            await asyncio.to_thread(notify.send_to, chat_id,
                                    "🏠 " + await self.set_mode(online=False))
        elif text.startswith("/online"):
            await asyncio.to_thread(notify.send_to, chat_id,
                                    "🌐 " + await self.set_mode(online=True))
        elif text.startswith("/restart_cloud"):
            ok, info = await asyncio.to_thread(railway_ctl.restart)
            await asyncio.to_thread(notify.send_to, chat_id,
                                    "🔁 Онлайн перезапускається" if ok else f"⚠️ {info}")
        elif text.startswith("/pause"):
            self.paused = True
            await asyncio.to_thread(notify.send_to, chat_id, "⏸ Пауза увімкнена")
        elif text.startswith("/resume"):
            self.paused = False
            await asyncio.to_thread(notify.send_to, chat_id, "▶️ Радар відновлено")
        elif text.startswith("/report"):
            await asyncio.to_thread(notify.send, self.build_report(), True)
            await asyncio.to_thread(notify.send_to, chat_id, "📊 Звіт надіслано в канал")
        elif text.startswith("/status"):
            self._wake_reason = "кнопка"
            if self._status_dirty:
                self._status_dirty.set()
            await asyncio.to_thread(notify.send_to, chat_id, "🔄 Закріплене оновлюється")
        elif text.startswith("/state"):
            await asyncio.to_thread(notify.send_to, chat_id, self._state_text())
        else:
            await asyncio.to_thread(
                notify.send_to, chat_id,
                "Команди: /panel /pause /resume /mute /report /status /state /local /online /restart_cloud")

    async def set_mode(self, online: bool) -> str:
        """Перемикає локально/онлайн: власну роль і, якщо налаштовано, хмару.

        online=True  — цей екземпляр іде в резерв, хмара стає активною.
        online=False — цей екземпляр стає активним, хмара іде в резерв.

        Використовується і кнопкою в застосунку, і кнопкою в боті —
        єдина логіка, щоб не розходилась поведінка.
        """
        my_role = "backup" if online else "main"
        cloud_role = "main" if online else "backup"

        saved = settings.load()
        saved["role"] = my_role
        settings.save(saved)
        config.reload_settings()
        await self._standby_tick()          # застосувати одразу, не чекаючи хвилину

        lines = [f"Цей екземпляр: {'резерв' if online else 'основний'}."]
        if railway_ctl.available():
            ok, info = await asyncio.to_thread(railway_ctl.set_role, cloud_role)
            lines.append(f"Хмара: {'активна' if ok and online else 'резерв' if ok else info}")
        elif online:
            lines.append("Хмарне керування не налаштоване — увімкніть хмару "
                         "вручну, якщо вона ще не активна.")

        return "\n".join(lines)

    async def _control(self, query: dict, action: str) -> None:
        """Нажатие кнопки на панели управления."""
        user_id = (query.get("from") or {}).get("id")
        if not (config.TELEGRAM_CONTROL and self._is_owner(user_id)):
            await asyncio.to_thread(notify.answer_callback, query["id"],
                                    "Немає доступу")
            return

        chat_id = ((query.get("message") or {}).get("chat") or {}).get("id")
        if action == "pause":
            self.paused = not self.paused
            reply = "⏸ Пауза" if self.paused else "▶️ Відновлено"
            await asyncio.to_thread(
                notify.send_to, chat_id,
                f"{reply}\n<i>{datetime.now():%H:%M}</i>",
                notify.control_panel(self.paused, self.is_muted(),
                                     config.FILTER_PLANNED,
                                     config.cloud_active(),
                                     config.SMART_REVIEW))
        elif action == "mute":
            if self.is_muted():
                self.mute_until = None
                reply = "🔔 Звук увімкнено"
            else:
                self.mute_until = datetime.now() + timedelta(hours=1)
                reply = f"🔕 Тиша до {self.mute_until:%H:%M}"
            await asyncio.to_thread(
                notify.send_to, chat_id, reply,
                notify.control_panel(self.paused, self.is_muted(),
                                     config.FILTER_PLANNED,
                                     config.cloud_active(),
                                     config.SMART_REVIEW))

        elif action == "cancel_alarm":
            reply = "⚪️ " + await self.cancel_alarm("з телефона")

        elif action == "review":
            data = await self._smart_review()
            self.review = data
            await asyncio.to_thread(
                notify.send,
                status.format_review(data, geo.main_name()) +
                "\n\n<i>Смарт-перевірка на вимогу. "
                "Автоматичний підрахунок, може бути неточним.</i>", True)
            if self._status_dirty:
                self._wake_reason = "кнопка"
                self._status_dirty.set()
            reply = "🔎 Смарт-звіт надіслано в канал"

        elif action == "renew":
            status.STATE_FILE.unlink(missing_ok=True)
            self._wake_reason = "кнопка"
            if self._status_dirty:
                self._status_dirty.set()
            reply = "📌 Створюю нове закріплене"

        elif action == "smart_button":
            # Окремий перемикач лише для кнопки «Оновити» під закрі-
            # пленим: вимкнено — вона просто перемальовує час, як
            # раніше, без повного огляду каналів. На відміну від
            # «Розумні фільтри» нижче — той перемикач чіпає ще й live-
            # обробку кожного повідомлення (planned/confidence/votes/
            # context), а цей — лише поведінку самої кнопки.
            saved = settings.load()
            new_value = not saved.get("smart_review", True)
            saved["smart_review"] = new_value
            settings.save(saved)
            config.reload_settings()
            reply = ("🔎 Кнопка «Оновити»: смарт-режим увімкнено"
                     if new_value else
                     "🔄 Кнопка «Оновити»: тепер просте оновлення")
            await asyncio.to_thread(
                notify.send_to, chat_id, reply,
                notify.control_panel(self.paused, self.is_muted(),
                                     config.FILTER_PLANNED,
                                     config.cloud_active(), new_value))

        elif action == "smart":
            # Разом вмикає або вимикає всі розумні фільтри — на випадок,
            # якщо котрийсь із них почне заважати.
            saved = settings.load()
            keys = ("filter_planned", "filter_confidence", "filter_votes",
                    "filter_context", "smart_review", "smart_explain",
                    "smart_before_series")
            new_value = not all(saved.get(k, True) for k in keys)
            for key in keys:
                saved[key] = new_value
            settings.save(saved)
            config.reload_settings()
            reply = ("🧠 Розумні фільтри увімкнено" if new_value
                     else "⚠️ Розумні фільтри вимкнено")
            await asyncio.to_thread(
                notify.send_to, chat_id, reply,
                notify.control_panel(self.paused, self.is_muted(), new_value,
                                     config.cloud_active(), new_value))

        elif action == "test":
            ok, info = await asyncio.to_thread(
                notify.send, "✅ <b>Перевірка зв'язку</b>\nРадар працює, "
                f"канал доступний. {datetime.now():%H:%M}", True)
            reply = "✅ Надіслано в канал" if ok else f"Помилка: {info}"

        elif action in ("report", "report_prev"):
            day = "yesterday" if action == "report_prev" else "today"
            await asyncio.to_thread(notify.send, self.build_report(day), True)
            reply = "📊 Звіт надіслано в канал"
        elif action == "status":
            asyncio.create_task(self._refresh_with_review())
            if self._status_dirty:
                self._status_dirty.set()
            reply = "🔄 Оновлюю закріплене"
        elif action == "state":
            await asyncio.to_thread(notify.send_to, chat_id, self._state_text())
            reply = "ℹ️ Надіслано"

        elif action == "mode_local":
            reply = "🏠 " + await self.set_mode(online=False)
        elif action == "mode_online":
            reply = "🌐 " + await self.set_mode(online=True)
        elif action == "restart_cloud":
            ok, info = await asyncio.to_thread(railway_ctl.restart)
            reply = "🔁 Онлайн перезапускається" if ok else f"⚠️ {info}"
        else:
            reply = "Невідома дія"

        await asyncio.to_thread(notify.answer_callback, query["id"], reply[:190])

    def _guess_type(self) -> str:
        """Найчастіший тип загрози за останні 15 хвилин по області.

        Канали часто пишуть просто «далі на Зміїв», не називаючи тип.
        Тоді дивимось, про що взагалі пишуть зараз, і підказуємо.
        """
        if not self.recent_types:
            return ""
        counts = {}
        for _when, name in self.recent_types:
            counts[name] = counts.get(name, 0) + 1
        name, hits = max(counts.items(), key=lambda kv: kv[1])
        return name if hits >= 2 else ""

    def is_muted(self) -> bool:
        """Действует ли временная тишина, включённая кнопкой в боте."""
        return bool(self.mute_until and datetime.now() < self.mute_until)

    async def send_review_to_channel(self) -> None:
        """Смарт-перевірка і окреме повідомлення в канал."""
        data = await self._smart_review()
        self.review = data
        await asyncio.to_thread(
            notify.send,
            status.format_review(data, geo.main_name()) +
            "\n\n<i>Смарт-перевірка на вимогу. "
            "Автоматичний підрахунок, може бути неточним.</i>", True)
        self._wake_reason = "кнопка"
        if self._status_dirty:
            self._status_dirty.set()

    def _state_text(self) -> str:
        """Короткая сводка состояния радара — по запросу владельца."""
        d = self.daily
        lines = [f"ℹ️ <b>Стан радара</b> · {datetime.now():%H:%M}",
                 f"Режим: {'резерв (чекає)' if self.standby else 'працює'}"
                 + (" · ПАУЗА" if self.paused else ""),
                 f"Каналів: {len(config.CHANNELS)}"
                 + (f" · 🔕 тиша до {self.mute_until:%H:%M}"
                    if self.is_muted() else ""),
                 f"Переглянуто за добу: {d.get('seen', 0)}"]
        if self.alarm:
            lines.append(f"🟡 {self.alarm[0]} з {self.alarm[1]:%H:%M}")
        if self.last_alert:
            when, _lvl, head = self.last_alert
            lines.append(f"Остання загроза: {head} о {when:%H:%M}")
        return "\n".join(lines)

    async def _status_loop(self) -> None:
        """Держит закреплённое сообщение в канале свежим.

        Обновляется по расписанию (config.STATUS_UPDATE_MIN) и внепланово
        сразу после тревоги. Если сообщение перестало обновляться —
        значит радар встал, и это видно прямо в канале.
        """
        reason = "старт"
        while True:
            try:
                # Просроченная тревога снимается сама
                if self.alarm and (datetime.now() - self.alarm[1]
                                   > timedelta(hours=ALARM_MAX_HOURS)):
                    log.warning("тривога висить понад %d год без відбою — "
                               "знімаю", ALARM_MAX_HOURS)
                    self.alarm = None
                    save_state(None, self.announced)

                if reason == "за розкладом":
                    self.review = None      # мікрозвіт живе до автооновлення

                text = status.build_text(
                    self.stats, self.started, self.last_alert, self.paused,
                    self.counts, self.alarm, self._wake_reason or reason,
                    self.daily,
                    self.critical["short"] if self.critical else None,
                    self.oblast, self.review, self.active_threat)
                self._wake_reason = None
                if self.standby:              # закріплене веде онлайн-екземпляр
                    await asyncio.sleep(30)
                    continue
                ok, info = await asyncio.to_thread(status.publish, text)
                self._our_edit = datetime.now()
                self.last_status_ok = ok
                if ok:
                    log.info("статус: %s (%s)", info, reason)
                else:
                    log.error("статус НЕ оновлено: %s (%s)", info, reason)
            except Exception:                                # noqa: BLE001
                # КРИТИЧНО: цей цикл тримає закріплене повідомлення живим.
                # Без цього захисту одна помилка форматування чи мережі
                # назавжди зупинила б оновлення закріпленого — і про це
                # ніхто б не дізнався, доки хтось не помітив би застиглий
                # час у каналі.
                log.exception("_status_loop впав на цій ітерації — "
                              "продовжую")
                await asyncio.sleep(30)

            try:
                await asyncio.wait_for(self._status_dirty.wait(),
                                       timeout=config.STATUS_UPDATE_MIN * 60)
            except asyncio.TimeoutError:
                reason = "за розкладом"
            else:
                reason = "тривога"
                self._status_dirty.clear()
                await asyncio.sleep(2)  # дать тревоге долететь раньше статуса

    async def _poll_public(self) -> None:
        """Хмарний цикл: опитує публічні сторінки каналів замість Telethon.

        Перший прохід лише запам'ятовує поточні id, нічого не сповіщає —
        інакше кожен старт радар «заново побачив» би останні ~20
        повідомлень кожного каналу як нові.
        """
        last_id = {}
        for channel in config.CHANNELS:
            try:
                msgs = await asyncio.to_thread(public_source.fetch_channel,
                                               channel)
                last_id[channel] = max((m.id for m in msgs), default=0)
            except Exception as e:                          # noqa: BLE001
                log.warning("не вдалося прочитати %s на старті: %s",
                            channel, type(e).__name__)
                last_id[channel] = 0

        while True:
            await asyncio.sleep(CLOUD_POLL_SECONDS)
            for channel in config.CHANNELS:
                try:
                    msgs = await asyncio.to_thread(
                        public_source.fetch_channel, channel)
                except Exception as e:                      # noqa: BLE001
                    log.warning("не вдалося прочитати %s: %s",
                                channel, type(e).__name__)
                    continue
                new = [m for m in msgs if m.id > last_id.get(channel, 0)]
                if not new:
                    continue
                last_id[channel] = max(m.id for m in msgs)
                for m in sorted(new, key=lambda x: x.id):
                    reply_text = m.reply_text if config.FILTER_CONTEXT else None
                    try:
                        await self._ingest(channel, m.id, m.date, m.text,
                                           reply_text)
                    except Exception:                        # noqa: BLE001
                        # КРИТИЧНО: без цього одне «погане» повідомлення
                        # назавжди вбиває весь цикл опитування — решта
                        # тасків (кнопки, статус) далі працюють, і це
                        # виглядає так, ніби радар живий, але мовчить.
                        # Саме так одного разу «Оновити» ще працювало,
                        # а нові повідомлення взагалі не оброблялись.
                        log.exception("_ingest впав на %s/%s — пропускаю "
                                      "це повідомлення, продовжую опитування",
                                      channel, m.id)

    async def run(self, stop_event: asyncio.Event) -> None:
        """Основной цикл. Завершается, когда выставлен stop_event."""
        config.require("TG_API_ID", "TG_API_HASH", "BOT_TOKEN", "TARGET_CHAT_ID")
        self.dedup = Dedup(config.DEDUP_WINDOW_MIN)
        self._stop = stop_event

        client = TelegramClient(config.SESSION_PATH, config.api_id_int(),
                                config.TG_API_HASH)
        self.client = client
        await client.connect()
        if not await client.is_user_authorized():
            self._status("немає сесії — запустіть auth.py")
            raise SystemExit("Сессия не найдена. Сначала запустите: python auth.py")

        # КРИТИЧНО: спершу з'ясовуємо, чи ми зараз резерв, і лише потім
        # відновлюємо стан — відновлення саме може слати повідомлення
        # в канал (наприклад «відбій»), а без цієї перевірки щойно
        # запущений резервний екземпляр міг би встигнути написати
        # в реальний канал раніше, ніж зрозуміє, що він резерв.
        await self._standby_tick()

        # Тепер відновлюємо обстановку, і тільки потім слухаємо нове
        if config.TRACK_OBLAST_ALARM:
            await self._restore_alarm(client)
        if config.CLEAR_THREAT and not self.active_threat:
            await self._restore_active_threat(client)

        client.add_event_handler(self._handle, events.NewMessage(chats=config.CHANNELS))

        self.running = True
        log.info("Мониторинг запущен. Каналов: %d", len(config.CHANNELS))
        log.info("Сусіди в HIGH: %s",
                 "так" if config.HIGH_INCLUDES_NEIGHBORS else "ні (MEDIUM)")
        self._status("працює")

        self._status_dirty = asyncio.Event()
        tasks = [asyncio.create_task(self._heartbeat()),
                 asyncio.create_task(self._status_loop()),
                 asyncio.create_task(self._watch_threat()),
                 asyncio.create_task(self._poll_buttons()),
                 asyncio.create_task(self._critical_loop()),
                 asyncio.create_task(self._check_standby())]
        try:
            await stop_event.wait()
        finally:
            for task in tasks:
                task.cancel()
            self.running = False
            self.dedup.save()
            await client.disconnect()
            log.info("Остановлен. Просмотрено %d, подошло %d, отправлено %d, "
                     "дублей %d, ошибок %d", self.stats["seen"],
                     self.stats["matched"], self.stats["sent"],
                     self.stats["dupes"], self.stats["errors"])
            self._status("зупинено")


    async def run_cloud(self, stop_event: asyncio.Event) -> None:
        """Хмарний режим: без Telethon і файлу сесії.

        Читає публічні сторінки каналів (https://t.me/s/<канал>) замість
        MTProto-з'єднання під особистим акаунтом. Файл сесії ПОТРІБЕН
        лише локально — на сторонній хостинг його заливати не можна,
        це повний доступ до акаунту Telegram. Тут достатньо BOT_TOKEN
        і TARGET_CHAT_ID: увесь інший код (classify/threats/geo/notify/
        status) працює однаково незалежно від джерела повідомлень.
        """
        config.require("BOT_TOKEN", "TARGET_CHAT_ID")
        self.dedup = Dedup(config.DEDUP_WINDOW_MIN)
        self._stop = stop_event

        client = public_source.PublicClient()
        self.client = client

        # Та сама критична перевірка, що й у локальному run() — див.
        # коментар там. Особливо важливо в хмарі: перший запуск нового
        # деплою майже завжди відбувається, поки локальний екземпляр
        # ще працює.
        await self._standby_tick()

        if config.TRACK_OBLAST_ALARM:
            await self._restore_alarm(client)
        if config.CLEAR_THREAT and not self.active_threat:
            await self._restore_active_threat(client)

        self.running = True
        log.info("Хмарний моніторинг запущено (без сесії). Каналів: %d",
                 len(config.CHANNELS))
        log.info("Сусіди в HIGH: %s",
                 "так" if config.HIGH_INCLUDES_NEIGHBORS else "ні (MEDIUM)")
        self._status("працює (хмара)")

        self._status_dirty = asyncio.Event()
        tasks = [asyncio.create_task(self._heartbeat()),
                 asyncio.create_task(self._status_loop()),
                 asyncio.create_task(self._watch_threat()),
                 asyncio.create_task(self._poll_buttons()),
                 asyncio.create_task(self._critical_loop()),
                 asyncio.create_task(self._check_standby()),
                 asyncio.create_task(self._poll_public())]
        try:
            await stop_event.wait()
        finally:
            for task in tasks:
                task.cancel()
            self.running = False
            self.dedup.save()
            log.info("Зупинено (хмара). Просмотрено %d, підійшло %d, "
                     "відправлено %d, дублів %d, помилок %d",
                     self.stats["seen"], self.stats["matched"],
                     self.stats["sent"], self.stats["dupes"],
                     self.stats["errors"])
            self._status("зупинено")


async def _main() -> None:
    import signal

    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        asyncio.get_running_loop().add_signal_handler(sig, stop.set)
    await Radar().run(stop)


if __name__ == "__main__":
    asyncio.run(_main())
