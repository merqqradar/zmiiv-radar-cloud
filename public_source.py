# -*- coding: utf-8 -*-
"""Чтение публичных Telegram-каналов без аккаунта — для онлайн-версии.

Обычная HTML-страница https://t.me/s/<канал> отдаёт последние ~20
сообщений, включая контекст ответов (reply). Никакой файл сессии не
нужен — только эта страница и Bot API для отправки. Это то, ради чего
задумывался онлайн-режим: файл сессии Telethon даёт полный доступ
к аккаунту Telegram, его нельзя заливать на сторонний хостинг.

Локальный режим (auth.py/monitor.Radar.run) продолжает использовать
Telethon — этот модуль его не заменяет, а дополняет для облака.
"""

import asyncio
import html
import re
import urllib.request
from datetime import datetime

import notify

BASE = "https://t.me/s/{channel}"
UA = "Mozilla/5.0 (compatible; RadarZmiiv/1.0)"

# Одно сообщение целиком — от data-post до следующего data-post (или конца)
_MSG_SPLIT_RE = re.compile(r'(?=<div class="tgme_widget_message[^"]*" data-post=")')
_POST_RE = re.compile(r'data-post="[^/"]+/(\d+)"')
_TIME_RE = re.compile(r'<time datetime="([^"]+)"')
_TEXT_RE = re.compile(
    r'<div class="tgme_widget_message_text js-message_text"[^>]*>(.*?)</div>',
    re.S)
_REPLY_HREF_RE = re.compile(
    r'<a class="tgme_widget_message_reply[^"]*" href="[^"]*?/(\d+)"')
_REPLY_TEXT_RE = re.compile(
    r'class="tgme_widget_message_text js-message_reply_text"[^>]*>(.*?)</div>',
    re.S)


def _strip_html(fragment: str) -> str:
    """HTML-фрагмент -> обычный текст, как приходит из Telethon message.text."""
    text = re.sub(r"<br\s*/?>", "\n", fragment)
    text = re.sub(r"<[^>]+>", "", text)
    return html.unescape(text).strip()


class ChannelMessage:
    """Одно сообщение канала в форме, одинаковой что для Telethon, что для HTTP."""

    __slots__ = ("channel", "id", "date", "text", "reply_id", "reply_text")

    def __init__(self, channel, msg_id, date, text, reply_id=None,
                 reply_text=None):
        self.channel = channel
        self.id = msg_id
        self.date = date          # datetime с таймзоной (UTC)
        self.text = text
        self.reply_id = reply_id
        self.reply_text = reply_text

    @property
    def link(self) -> str:
        return f"https://t.me/{self.channel}/{self.id}"


def fetch_channel(channel: str, timeout: int = 15) -> list:
    """Забирает та розбирає останні повідомлення каналу.

    Синхронна функція — з асинхронного коду викликати через
    asyncio.to_thread(fetch_channel, channel).
    Помилки мережі не ловить навмисно: виклик сам вирішує, чи повторити.
    """
    req = urllib.request.Request(BASE.format(channel=channel),
                                 headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout,
                                context=notify.ssl_context()) as resp:
        raw = resp.read().decode("utf-8", errors="replace")

    out = []
    chunks = _MSG_SPLIT_RE.split(raw)
    for chunk in chunks:
        post = _POST_RE.search(chunk)
        time_m = _TIME_RE.search(chunk)
        if not post or not time_m:
            continue
        msg_id = int(post.group(1))
        date = datetime.fromisoformat(time_m.group(1))

        text_m = _TEXT_RE.search(chunk)
        text = _strip_html(text_m.group(1)) if text_m else ""
        if not text:
            continue                       # чисто медийные посты пропускаем

        reply_id = reply_text = None
        reply_href = _REPLY_HREF_RE.search(chunk)
        reply_txt_m = _REPLY_TEXT_RE.search(chunk)
        if reply_href:
            reply_id = int(reply_href.group(1))
        if reply_txt_m:
            reply_text = _strip_html(reply_txt_m.group(1))

        out.append(ChannelMessage(channel, msg_id, date, text,
                                  reply_id, reply_text))

    out.sort(key=lambda m: m.id)
    return out


class PublicClient:
    """Легкий адаптер під той самий інтерфейс, що й Telethon-клієнт.

    monitor.py викликає client.iter_messages(channel, limit=N) і читає
    у msg лише .id / .date / .text — рівно ці три поля повертає
    ChannelMessage. Завдяки цьому _restore_alarm, _restore_active_threat
    і _smart_review працюють БЕЗ жодної зміни, хоч локально за client
    стоїть Telethon+сесія, а в хмарі — оце, без сесії взагалі.
    """

    def __init__(self):
        self._cache: dict[str, tuple] = {}   # channel -> (час, повідомлення)
        self._cache_ttl = 5.0                # секунд, щоб не смикати сторінку
                                             # двічі поспіль (restore_alarm +
                                             # restore_active_threat на старті)

    async def _fetch_cached(self, channel: str) -> list:
        import time
        now = time.monotonic()
        cached = self._cache.get(channel)
        if cached and now - cached[0] < self._cache_ttl:
            return cached[1]
        msgs = await asyncio.to_thread(fetch_channel, channel)
        self._cache[channel] = (now, msgs)
        return msgs

    async def iter_messages(self, channel: str, limit: int = 20):
        """Async-ітератор найновіших повідомлень, як у Telethon (новіші перші)."""
        msgs = await self._fetch_cached(channel)
        for m in sorted(msgs, key=lambda x: x.id, reverse=True)[:limit]:
            yield m
