# -*- coding: utf-8 -*-
"""Закреплённое сообщение со статусом радара.

Одно сообщение в канале, которое постоянно переписывается:
видно, работает ли радар, есть ли сейчас угроза и когда была
последняя проверка. Если время обновления «застыло» — значит
радар остановился, и это заметно без всякого лога.

ID закреплённого сообщения хранится в data/status_msg.json,
чтобы после перезапуска править то же самое сообщение, а не плодить новые.
"""

import json
from datetime import datetime, timedelta

import config
import geo
import notify

STATE_FILE = config.DATA_DIR / "status_msg.json"

MONTHS = ["січня", "лютого", "березня", "квітня", "травня", "червня",
          "липня", "серпня", "вересня", "жовтня", "листопада", "грудня"]


def human_time(dt: datetime) -> str:
    """«2 вересня, 16:35» — привычный вид, а не ISO."""
    return f"{dt.day} {MONTHS[dt.month - 1]}, {dt:%H:%M}"


def human_uptime(delta: timedelta) -> str:
    """«3 год 12 хв» из timedelta."""
    total = int(delta.total_seconds())
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days} дн {hours} год"
    if hours:
        return f"{hours} год {minutes} хв"
    return f"{minutes} хв"


# Как называть причину обновления в строке «Оновлено»
REASON_LABEL = {
    "старт": "автоматично",
    "за розкладом": "автоматично",
    "тривога": "зміна стану",
    "кнопка": "оновив глядач",
}


def _types_line(data: dict) -> str:
    """«1 ракета, 2 шахеди, 3 розвідники» — розбивка за типами."""
    table = data.get("by_type") or {}
    if not table:
        return str(data.get("oblast", 0))
    parts = [f"{count} × {name.lower()}"
             for name, count in sorted(table.items(), key=lambda kv: -kv[1])]
    return ", ".join(parts[:4])


def format_review(data: dict, city: str, html: bool = True) -> str:
    """Мікрозвіт після натискання «Оновити». Один формат для каналу і застосунку."""
    b = (lambda t: f"<b>{t}</b>") if html else (lambda t: t)
    lines = [
        f"🔎 {b(data['when'].strftime('%H:%M'))} · смарт-перевірка "
        f"за {config.REVIEW_MINUTES} хв",
        f"Основне місто: {city}",
        f"Перевірено каналів: {data['channels']}",
        f"Прочитано повідомлень: {data['messages']}",
        f"Виявлено загроз місту: {data['threats']}",
        f"Цілей в області: {_types_line(data)}"
        + (f" · <a href=\"{data['oblast_link']}\">джерело</a>"
           if html and data.get("oblast_link") else ""),
        f"Поруч (сусідні НП): {data['near']}",
    ]
    if data.get("top"):
        when = data["top_when"].astimezone().strftime("%H:%M")
        # Канал сам написав «не фіксується» — не показуємо це як живу
        # загрозу, інакше рядок суперечить заголовку, який зняття вже
        # врахував.
        note = " · <i>вже не актуально</i>" if data.get("top_gone") else ""
        if html and data.get("top_link"):
            lines.append(f"Найсвіжіша: {data['top']} о {when} · "
                         f"<a href=\"{data['top_link']}\">джерело</a>{note}")
        else:
            lines.append(f"Найсвіжіша: {data['top']} о {when}{note}")
    return "\n".join(lines)


def build_text(stats: dict, started: datetime, last_alert, paused: bool,
               counts: dict, alarm=None, reason: str = "", daily=None,
               critical=None, oblast=None, review=None,
               active_threat=None) -> str:
    """Собирает текст закреплённого сообщения.

    Первая строка — самая важная: в списке закреплённых Telegram
    показывает только её начало, поэтому там сразу состояние,
    без названия канала и прочего оформления.
    """
    now = datetime.now()
    daily = daily or {}

    # --- Первая строка: состояние -------------------------------------------
    if paused:
        head = "⏸ <b>ПАУЗА</b> — сповіщення вимкнені"
    elif critical:
        head = f"❗️ <b>ОСОБЛИВА НЕБЕЗПЕКА · {critical}</b>"
    elif last_alert and (now - last_alert[0]) < timedelta(
            minutes=config.STATUS_ALARM_WINDOW_MIN):
        when, level, title = last_alert
        icon = "🔴" if level == "HIGH" else "🟠"
        # Заголовок уже вида «🚀 РАКЕТА → Зміїв» — берём его как есть
        clean = title.split(" ", 1)[-1] if " " in title else title
        head = f"{icon} <b>{clean.upper()}</b> · о {when:%H:%M}"
    elif active_threat:
        # last_alert не переживає перезапуск (не зберігається на диск),
        # а active_threat — переживає. Без цієї гілки закріплене після
        # перезапуску показувало б «загроз немає» під час реальної цілі,
        # яку радар усередині досі вважає активною.
        head = (f"🔴 <b>ЗАГРОЗА → {active_threat['place'].upper()}</b> · "
               f"з {active_threat['since']:%H:%M}")
    elif alarm:
        head = f"🟡 <b>{alarm[0].upper()}</b> · з {alarm[1]:%H:%M}"
    else:
        head = f"🟢 <b>ЗАГРОЗ НЕМАЄ</b> · {geo.main_name()}"

    lines = [head, ""]

    # --- Пояснение под состоянием -------------------------------------------
    if alarm and not paused and not critical:
        if last_alert and (now - last_alert[0]) < timedelta(
                minutes=config.STATUS_ALARM_WINDOW_MIN):
            lines.append(f"🟡 Тривога по району з {alarm[1]:%H:%M}")
        else:
            lines.append(f"Конкретної загрози для міста {geo.main_name()} "
                         f"не зафіксовано.")
        lines.append("")

    # --- Обстановка по области ----------------------------------------------
    # Не уведомление: просто контекст, чтобы понимать общую картину.
    if oblast:
        note, link, when = oblast
        if now - when < timedelta(minutes=20):
            lines += [f"🛩 <b>По області:</b> {note} · "
                      f"<a href=\"{link}\">джерело</a> ({when:%H:%M})", ""]

    # Мікрозвіт після натискання «Оновити». Тримається до планового
    # оновлення закріпленого, потім зникає.
    if review:
        lines += [format_review(review, geo.main_name()), ""]

    # --- Служебная часть -----------------------------------------------------
    lines += [
        f"<b>Оновлено:</b> {human_time(now)}"
        + (f" · {REASON_LABEL.get(reason, reason)}" if reason else ""),
        f"<b>За добу:</b> загроз {daily.get('threats', 0)} · "
        f"прильотів {daily.get('impacts', 0)} · "
        f"переглянуто {daily.get('seen', 0)}",
        "",
        "<i>Збирає повідомлення кількох Telegram-каналів моніторингу, "
        "відбирає ті, що стосуються Змієва, і пересилає сюди.</i>",
    ]
    return "\n".join(lines)


def _load_id() -> int | None:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8")).get("message_id")
        except (json.JSONDecodeError, ValueError):
            return None
    return None


def _save_id(message_id: int) -> None:
    STATE_FILE.write_text(json.dumps({"message_id": message_id}),
                          encoding="utf-8")


def publish(text: str) -> tuple:
    """Обновляет закреплённое сообщение, при необходимости создаёт заново.

    Возвращает (успех, описание).
    """
    message_id = _load_id()

    markup = notify.REFRESH_BUTTON if config.STATUS_REFRESH_BUTTON else None

    if message_id:
        ok, info = notify.edit(message_id, text, markup)
        if ok:
            return True, "оновлено"
        # Текст не изменился — это не ошибка
        if "не изменился" in info:
            return True, "без змін"
        # Сообщение удалили из канала — создаём новое
        if "удалено" not in info and "not found" not in info.lower():
            return False, info

    new_id, info = notify.send_id(text, silent=True, markup=markup)
    if not new_id:
        return False, info
    _save_id(new_id)
    pinned, pin_info = notify.pin(new_id)
    if not pinned:
        # Сообщение создано и обновляется, но наверху канала не висит —
        # значит боту не дали право закреплять. Об этом надо сказать.
        return True, f"створено, але НЕ закріплено ({pin_info})"
    return True, "створено та закріплено"
