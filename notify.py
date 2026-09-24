# -*- coding: utf-8 -*-
"""Отправка и обновление сообщений в Telegram через Bot API.

Общий модуль: им пользуются test_notify.py, monitor.py и menubar.py.
Только стандартная библиотека, никаких лишних зависимостей.
"""

import json
import ssl
import time
import urllib.error
import urllib.request

import config

TIMEOUT = 20
_ctx = None


def ssl_context() -> ssl.SSLContext:
    """SSL-контекст с рабочим набором корневых сертификатов.

    У сборок Python с python.org на macOS системное хранилище часто пустое,
    из-за чего любой HTTPS падает с CERTIFICATE_VERIFY_FAILED.
    В этом случае берём бандл из certifi.
    """
    global _ctx
    if _ctx is None:
        _ctx = ssl.create_default_context()
        if ssl.get_default_verify_paths().cafile is None:
            try:
                import certifi

                _ctx.load_verify_locations(certifi.where())
            except ImportError:
                pass
    return _ctx


def explain(status: int, payload: dict) -> str:
    """Человеческая расшифровка ошибки Bot API."""
    desc = (payload.get("description") or "").lower()
    if status == 401:
        return "401 — неверный BOT_TOKEN. Проверьте токен у @BotFather."
    if status == 404:
        return "404 — токен не распознан: скорее всего BOT_TOKEN обрезан."
    if status == 400 and "chat not found" in desc:
        return ("400 chat not found — неверный TARGET_CHAT_ID "
                "(для канала это -100XXXXXXXXXX).")
    if status == 400 and "message to edit not found" in desc:
        return "400 — закреплённое сообщение удалено, создам новое."
    if status == 400 and "message is not modified" in desc:
        return "400 — текст не изменился, правка не нужна."
    if status == 403:
        return ("403 — бот не админ канала или нет права публикации/закрепления. "
                "Дайте боту права 'Публикация сообщений' и 'Закрепление сообщений'.")
    if status == 429:
        return ("429 — лимит частоты, повтор через "
                f"{payload.get('parameters', {}).get('retry_after', '?')} с.")
    return f"HTTP {status} — {payload.get('description', 'без описания')}"


def _call(method: str, payload: dict, retries: int = 3) -> tuple:
    """Вызов метода Bot API. Возвращает (успех, результат или текст ошибки).

    Токен нигде не печатается, даже в тексте ошибки.
    """
    url = f"https://api.telegram.org/bot{config.BOT_TOKEN}/{method}"
    body = json.dumps(payload).encode("utf-8")

    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT,
                                        context=ssl_context()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("ok"):
                return True, data.get("result")
            return False, explain(200, data)

        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = {"description": raw[:200]}
            if e.code == 429:                       # лимит частоты — переждать
                wait = int(data.get("parameters", {}).get("retry_after", 3))
                time.sleep(wait + 1)
                continue
            return False, explain(e.code, data)

        except urllib.error.URLError as e:
            if attempt < retries:                   # сеть моргнула — ещё разок
                time.sleep(2 * attempt)
                continue
            reason = str(e.reason)
            if "CERTIFICATE_VERIFY_FAILED" in reason:
                return False, "нет корневых сертификатов у Python — поставьте certifi"
            return False, f"сеть недоступна: {reason}"

    return False, "не удалось выполнить запрос после всех попыток"


# Кнопка под закреплённым сообщением. Нажать может любой читатель канала.
REFRESH_BUTTON = {"inline_keyboard": [[{"text": "🔄 Оновити",
                                        "callback_data": "refresh"}]]}

# Панель управления в личной переписке с ботом. Доступна только владельцу.
def control_panel(paused: bool, muted: bool = False,
                  smart: bool = True, online: bool = False,
                  smart_button: bool = True) -> dict:
    """Панель управления в личной переписке. Доступна только владельцу.

    online — де зараз активна робота: True — на хмарі (Онлайн),
    False — на цьому пристрої (Локально). Активний варіант позначений ✅.
    smart_button — чи кнопка «Оновити» під закріпленим робить повний
    смарт-огляд каналів, чи просто перемальовує час (окремо від
    загального перемикача «Розумні фільтри» нижче).
    """
    return {"inline_keyboard": [
        # Найперша кнопка: коли радар помилково підняв червону тривогу,
        # шукати щось у списку ніколи — треба одразу її прибрати.
        [{"text": "⚪️ Зняти тривогу", "callback_data": "ctl:cancel_alarm"}],
        [{"text": "▶️ Відновити" if paused else "⏸ Пауза",
          "callback_data": "ctl:pause"},
         {"text": "🔔 Увімкнути звук" if muted else "🔕 Тиша на годину",
          "callback_data": "ctl:mute"}],
        [{"text": ("✅ " if not online else "") + "🏠 Локально",
          "callback_data": "ctl:mode_local"},
         {"text": ("✅ " if online else "") + "🌐 Онлайн",
          "callback_data": "ctl:mode_online"}],
        [{"text": "🔁 Перезапустити онлайн", "callback_data": "ctl:restart_cloud"}],
        [{"text": "📊 Звіт сьогодні", "callback_data": "ctl:report"},
         {"text": "📅 Звіт за вчора", "callback_data": "ctl:report_prev"}],
        [{"text": "ℹ️ Стан радара", "callback_data": "ctl:state"}],
        [{"text": "🔄 Оновити статус", "callback_data": "ctl:status"},
         {"text": "🔎 Смарт-звіт у канал", "callback_data": "ctl:review"}],
        [{"text": "📌 Новий закріп", "callback_data": "ctl:renew"}],
        [{"text": "🔎 Кнопка «Оновити»: смарт-режим" if smart_button
                  else "🔄 Кнопка «Оновити»: просте оновлення",
          "callback_data": "ctl:smart_button"}],
        [{"text": "🧠 Розумні фільтри: увімк" if smart
                  else "⚠️ Розумні фільтри: ВИМК",
          "callback_data": "ctl:smart"}],
        [{"text": "✅ Перевірка зв'язку", "callback_data": "ctl:test"}],
    ]}


def send_to(chat_id, text: str, markup=None, silent: bool = True) -> tuple:
    """Отправка в произвольный чат — для личной переписки с владельцем."""
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML",
               "disable_web_page_preview": True, "disable_notification": silent}
    if markup:
        payload["reply_markup"] = markup
    ok, res = _call("sendMessage", payload, retries=1)
    return ok, (res if not ok else "ok")


def call(method: str, payload: dict) -> tuple:
    """Публичный вызов Bot API — для служебных проверок."""
    return _call(method, payload, retries=1)


def send(text: str, silent: bool = False) -> tuple:
    """Отправляет сообщение. Возвращает (успех, описание)."""
    ok, res = _call("sendMessage", {
        "chat_id": config.TARGET_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
        "disable_notification": silent,
    })
    if ok:
        return True, f"msg_id={res.get('message_id')}"
    return False, res


def send_id(text: str, silent: bool = True, markup=None) -> tuple:
    """Отправляет сообщение и возвращает (id или None, описание)."""
    payload = {
        "chat_id": config.TARGET_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
        "disable_notification": silent,
    }
    if markup:
        payload["reply_markup"] = markup
    ok, res = _call("sendMessage", payload)
    return (res.get("message_id"), "ok") if ok else (None, res)


def edit(message_id: int, text: str, markup=None) -> tuple:
    """Правит ранее отправленное сообщение (для закреплённого статуса).

    markup передаём при каждой правке: без него Telegram снимет кнопку.
    """
    payload = {
        "chat_id": config.TARGET_CHAT_ID,
        "message_id": message_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if markup:
        payload["reply_markup"] = markup
    ok, res = _call("editMessageText", payload)
    return ok, ("ok" if ok else res)


def pin(message_id: int) -> tuple:
    """Закрепляет сообщение в канале, без уведомления подписчиков."""
    ok, res = _call("pinChatMessage", {
        "chat_id": config.TARGET_CHAT_ID,
        "message_id": message_id,
        "disable_notification": True,
    })
    return ok, ("ok" if ok else res)


def get_updates(offset: int, timeout: int = 25) -> tuple:
    """Забирает нажатия кнопок (long polling).

    Возвращает (список обновлений, новый offset). Обычные сообщения боту
    не нужны — просим у Telegram только callback_query.
    """
    ok, res = _call("getUpdates", {
        "offset": offset,
        "timeout": timeout,
        "allowed_updates": ["callback_query", "message"],
    }, retries=1)
    if not ok or not res:
        return [], offset
    return res, res[-1]["update_id"] + 1


def answer_callback(callback_id: str, text: str) -> None:
    """Гасит «часики» на кнопке и показывает всплывающую подсказку."""
    _call("answerCallbackQuery",
          {"callback_query_id": callback_id, "text": text}, retries=1)
