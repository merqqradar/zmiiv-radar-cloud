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
        threat = {"place": raw["place"],
                  "since": datetime.fromisoformat(raw["since"]),
                  "last_seen": datetime.fromisoformat(raw["last_seen"])}
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

⏸ <b>Пауза</b> — радар слухає канали, але нічого не надсилає. Кнопка стає «Відновити».

🔕 <b>Тиша на годину</b> — повідомлення приходять, але без звуку. Корисно, коли обстріл триває довго, а ви вже в укритті. Діє й на екстрені повтори.

📊 <b>Звіт</b> — надсилає в канал підсумок за добу: загрози, прильоти, тривоги, відключення світла.

🏠 <b>Локально</b> / 🌐 <b>Онлайн</b> — де зараз працює радар: на цьому пристрої чи на сервері. Активний варіант позначений ✅. Перемикання одразу застосовується з обох боків, якщо хмара налаштована.

🔁 <b>Перезапустити онлайн</b> — на випадок збою хмарного екземпляра.

ℹ️ <b>Стан радара</b> — відповідає сюди: чи працює, скільки каналів слухає, скільки повідомлень переглянув, чи триває тривога.

🔄 <b>Оновити статус</b> — оновлює закріплене повідомлення в каналі просто зараз.

📌 <b>Новий закріп</b> — створює закріплене заново, якщо старе видалили або воно загубилося.

✅ <b>Перевірка зв'язку</b> — надсилає в канал тестове повідомлення.

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


def format_message(res: dict, channel: str, link: str) -> str:
    """Полный текст уведомления."""
    icon, title = LEVEL_STYLE[res["level"]]
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
    if source:
        body = (f"🟢 {wording.capitalize()} · загроза була о {when:%H:%M}\n"
                f"\n{escape(source)[:250]}")
        return head + body + source_line(src)

    body = (f"🟢 Ціль більше не згадується · була о {when:%H:%M}\n"
            f"\nКанали перестали про неї писати. Могла пролетіти далі, "
            f"бути збитою або вже влучити. Це не офіційний відбій.")
    return head + body + "\n\n<i>висновок радара: мовчання каналів</i>"


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
        self.daily = load_daily()       # лічильники за добу
        self.critical = None            # епізод особливої небезпеки
        self.recent_high = []           # часи гучних сповіщень (для серії)
        self._wake_reason = None        # чому оновлюємо закріплене
        self.standby = False            # резерв мовчить, поки живий онлайн
        self.mute_until = None          # тиша на годину: звук тимчасово вимкнено
        self.last_alarm_off = None      # коли надіслали відбій (проти дублів)
        self.oblast = None              # (опис, посилання, час) — для закріпленого
        self.gone_votes = {}            # канали, що повідомили про зникнення цілі
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
                        found = (msg.date, place)
            except Exception as e:                       # noqa: BLE001
                log.warning("не вдалося прочитати %s при відновленні цілі: %s",
                            channel, type(e).__name__)

        if not found:
            return
        when, place = found
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

        self.active_threat = {"place": place, "since": local, "last_seen": local}
        save_active_threat(self.active_threat)
        log.info("відновлено активну ціль: %s, останнє згадування о %s",
                 place, local.strftime("%H:%M"))

    async def _refresh_with_review(self) -> None:
        """Смарт-перевірка і оновлення закріпленого. Помилки не глушимо.

        Заразом перевіряє активну ціль: якщо огляд каналів за останні
        REVIEW_MINUTES не знайшов жодної загрози місту, а ціль досі
        значиться активною — не чекаємо пасивний тайм-аут «мовчання»,
        а одразу звіряємось і, якщо підтвердилось, шлемо в чат «загроза
        минула». Раніше кнопка лише перемальовувала закріплене, і воно
        могло тихо «заспокоїтися» без жодного повідомлення в чаті.
        """
        try:
            if config.SMART_REVIEW:
                self.review = await self._smart_review()

                if config.CLEAR_THREAT and self.active_threat:
                    # Важлива саме СВІЖІСТЬ останньої згадки міста, а не
                    # «чи є взагалі щось у 40-хвилинному вікні огляду» —
                    # старе повідомлення весь час залишалось у вікні й
                    # блокувало зняття, навіть коли ситуація вже стихла.
                    last_seen = self.review.get("city_last_seen")
                    fresh = (last_seen is not None
                             and datetime.now(timezone.utc) - last_seen
                             < timedelta(minutes=config.CLEAR_AFTER_MIN))
                    quiet_enough = (datetime.now() -
                                    self.active_threat["last_seen"]
                                    > timedelta(minutes=3))
                    if not fresh and quiet_enough:
                        await self._announce(format_gone(self.active_threat, ""))
                        log.info("загроза знята за смарт-перевіркою (кнопка)")
                        self.active_threat = None
                        save_active_threat(None)
                        self.last_alert = None
                        self.critical = None
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
                "top": None, "top_when": None, "top_link": None,
                "top_gone": False,
                "oblast_link": None, "oblast_when": None,
                "city_last_seen": None}
        if not self.client:
            return data

        cutoff = datetime.now(timezone.utc) - timedelta(
            minutes=config.REVIEW_MINUTES)

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

        for channel in config.CHANNELS:
            ok_channel = False
            try:
                async for msg in self.client.iter_messages(
                        channel, limit=config.REVIEW_LIMIT):
                    ok_channel = True
                    if msg.date < cutoff or not msg.text:
                        continue
                    data["messages"] += 1

                    if classify.threat_gone(msg.text, ""):
                        gone_channels.add(channel)

                    res = classify.classify(msg.text)
                    if res and res["level"] in ("HIGH", "MEDIUM"):
                        key = res.get("key")
                        is_new_key = key not in seen_keys
                        if key:
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

                        if is_new and is_new_key:
                            # Загрозою місту рахуємо лише те, де назване
                            # саме воно. Решта, що справді поруч — «поруч».
                            # Якщо цей самий канал уже написав «не
                            # фіксується» — ціль не рахуємо як актуальну:
                            # інакше огляд суперечив би заголовку
                            # закріпленого, яке це зняття вже врахувало.
                            if res.get("main_city"):
                                if channel not in gone_channels:
                                    data["threats"] += 1
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
                        count, _kind = hit
                        # Джерело беремо від найдетальнішого повідомлення:
                        # де названо найбільшу кількість цілей.
                        if count >= data["oblast"]:
                            data["oblast"] = count
                            data["oblast_link"] = f"https://t.me/{channel}/{msg.id}"
                            data["oblast_when"] = msg.date
            except Exception:                               # noqa: BLE001
                continue
            if ok_channel:
                data["channels"] += 1

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
            await self._standby_tick()

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
                          "impact_types": {}}
        self.daily[field] = self.daily.get(field, 0) + 1
        save_daily(self.daily)

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

        def block(caption, total, table):
            lines = [f"{caption} <b>{total}</b>"]
            for name, count in sorted(table.items(), key=lambda kv: -kv[1]):
                lines.append(f"     └ {name.lower()}: {count}")
            return lines

        lines = [title, ""]
        lines += block("🔴 Загроз Змієву:", data.get("threats", 0),
                       data.get("by_type") or {})
        lines.append("")
        lines += block("💥 Прильотів поруч:", data.get("impacts", 0),
                       data.get("impact_types") or {})
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
        return "\n".join(lines)

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

        # Свет, вода, газ, химия, ДРГ, радиация — без звука.
        # Исключение: радиационная угроза, она со звуком.
        if config.SEND_CIVIL:
            civil = classify.civil_state(text)
            if civil:
                emoji, name, loud, body = civil
                key = classify.dedup_key("CIVIL", [name], [], body)
                if not self.dedup.is_duplicate(key, date
                                               or datetime.now(timezone.utc)):
                    msg = (f"{emoji} <b>{name.upper()}</b>\n"
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
            gone = classify.threat_gone(text, context)
            if gone:
                other_region = geo.mentions_other_region(text.lower())
                log.info("gone-сигнал від %s: %s (враховано: %s)",
                         username, gone[0], not other_region)
            if gone and not geo.mentions_other_region(text.lower()):
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
                    await self._announce(format_gone(self.active_threat,
                                                     gone[0], gone[1], src=src))
                    log.info("знято загрозу: %d канали підтвердили", votes)
                    self.active_threat = None
                    save_active_threat(None)
                    self.last_alert = None
                    self.gone_votes.clear()
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

        # Обстановка по області — тільки в закріплене, без сповіщень
        summary = classify.oblast_summary(text)
        if summary:
            self.oblast = (summary[0], link, datetime.now())
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
            return

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
            notify.send, format_message(res, username, link), silent)
        if ok:
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
                if self.active_threat and self.active_threat["place"] == place:
                    self.active_threat["last_seen"] = now_ts
                else:
                    self.active_threat = {"place": place, "since": now_ts,
                                          "last_seen": now_ts}
                save_active_threat(self.active_threat)
            if res.get("main_city"):
                self.last_alert = (datetime.now(), res["level"],
                                   plain_headline(res))

            # Особлива небезпека: масова або важка загроза, або серія
            # гучних сповіщень підряд. Одна ціль повторів не дає.
            if config.CRITICAL_ENABLED and res["level"] == "HIGH":
                now_ts = datetime.now()
                self.recent_high = [t for t in self.recent_high
                                    if now_ts - t < timedelta(minutes=10)]
                if res.get("main_city"):
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
            s = self.stats
            log.info("жив: переглянуто %d, надіслано %d, дублів %d, помилок %d%s",
                     s["seen"], s["sent"], s["dupes"], s["errors"],
                     " (ПАУЗА)" if self.paused else "")
            if s["seen"] == 0:
                log.warning("за час роботи не надійшло жодного повідомлення — "
                            "перевірте список каналів і мережу")
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

        self.critical = {"short": short, "started": now_ts,
                         "last_event": now_ts, "last_burst": now_ts,
                         "bursts": 0, "src": src}
        log.warning("ОСОБЛИВА НЕБЕЗПЕКА: %s", short)
        await self._send_burst()

    async def _send_burst(self) -> None:
        """Отправляет пачку коротких сообщений со звуком."""
        if not self.critical:
            return
        if self.paused:                # пауза глушить і повтори теж
            self.critical = None
            return
        self.critical["bursts"] += 1
        self.critical["last_burst"] = datetime.now()
        for i in range(config.CRITICAL_REPEATS):
            ok, info = await asyncio.to_thread(
                notify.send, format_short(self.critical["short"],
                                          datetime.now(),
                                          self.critical.get("src")),
                self.is_muted())
            if ok:
                self.stats["sent"] += 1
            else:
                self.stats["errors"] += 1
                log.error("повтор НЕ надіслано: %s", info)
            if i < config.CRITICAL_REPEATS - 1:
                await asyncio.sleep(config.CRITICAL_INTERVAL_SEC)
        log.warning("надіслано пачку повторів %d з %d",
                    self.critical["bursts"], config.CRITICAL_MAX_BURSTS)

    async def _critical_loop(self) -> None:
        """Повторяет пачки, пока угроза жива, но не больше лимита."""
        while True:
            await asyncio.sleep(10)
            if not self.critical:
                continue
            now_ts = datetime.now()

            # Эпизод закончился: давно нет новых сообщений или исчерпан лимит
            quiet = now_ts - self.critical["last_event"]
            if (quiet > timedelta(minutes=config.CRITICAL_EPISODE_MIN)
                    or self.critical["bursts"] >= config.CRITICAL_MAX_BURSTS
                    or self.active_threat is None):
                log.info("епізод особливої небезпеки завершено (%d пачок)",
                         self.critical["bursts"])
                self.critical = None
                continue

            # Обстрел продолжается — ещё пачка через минуту
            if now_ts - self.critical["last_burst"] >= timedelta(minutes=1):
                await self._send_burst()

    async def _watch_threat(self) -> None:
        """Снимает угрозу, если каналы перестали о ней писать.

        Проверка раз в минуту. Радар не утверждает, что цель сбита —
        только то, что о ней больше не пишут.
        """
        while True:
            await asyncio.sleep(60)
            if not (config.CLEAR_THREAT and self.active_threat):
                continue
            quiet = datetime.now() - self.active_threat["last_seen"]
            if quiet > timedelta(minutes=config.CLEAR_AFTER_MIN):
                await self._announce(format_gone(self.active_threat, ""))
                log.info("загроза знята за мовчанням каналів (%d хв)",
                         config.CLEAR_AFTER_MIN)
                self.active_threat = None
                save_active_threat(None)
                self.last_alert = None        # закріплене повертається у спокій
                self.critical = None
                if self._status_dirty:
                    self._status_dirty.set()

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
                                     config.cloud_active()))
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
                                     config.cloud_active()))
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
                                     config.cloud_active()))

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
                                     config.cloud_active()))

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
            # Просроченная тревога снимается сама
            if self.alarm and (datetime.now() - self.alarm[1]
                               > timedelta(hours=ALARM_MAX_HOURS)):
                log.warning("тривога висить понад %d год без відбою — знімаю",
                            ALARM_MAX_HOURS)
                self.alarm = None
                save_state(None, self.announced)

            if reason == "за розкладом":
                self.review = None      # мікрозвіт живе до автооновлення

            text = status.build_text(
                self.stats, self.started, self.last_alert, self.paused,
                self.counts, self.alarm, self._wake_reason or reason,
                self.daily, self.critical["short"] if self.critical else None,
                self.oblast, self.review)
            self._wake_reason = None
            if self.standby:                  # закріплене веде онлайн-екземпляр
                await asyncio.sleep(30)
                continue
            ok, info = await asyncio.to_thread(status.publish, text)
            self._our_edit = datetime.now()
            self.last_status_ok = ok
            if ok:
                log.info("статус: %s (%s)", info, reason)
            else:
                log.error("статус НЕ оновлено: %s (%s)", info, reason)

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
