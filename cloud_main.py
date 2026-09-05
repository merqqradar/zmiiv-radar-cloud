# -*- coding: utf-8 -*-
"""Точка входа для хмарного розгортання (Railway).

Працює БЕЗ файлу сесії Telethon: читає публічні сторінки каналів
(public_source.py) і шле сповіщення через Bot API. Потрібні лише
BOT_TOKEN і TARGET_CHAT_ID — задаються змінними середовища на Railway,
файл .env на сервері не потрібен і не завантажується.

Локальний застосунок (menubar.py) як і раніше використовує Telethon —
цей файл його не замінює.
"""

import asyncio
import signal

import monitor


async def _main() -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass                    # на деяких платформах сигнали недоступні

    radar = monitor.Radar()
    await radar.run_cloud(stop)


if __name__ == "__main__":
    asyncio.run(_main())
