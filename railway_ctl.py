# -*- coding: utf-8 -*-
"""Керування хмарним екземпляром через Railway API.

Використовується лише локальним застосунком (на Mac) — токен Railway
НІКОЛИ не потрапляє на сам хмарний сервер, щоб не давати публічному
сервісу доступ до керування власним хостингом.

Без налаштованих RAILWAY_* у .env усі функції тут просто повертають
(False, "не налаштовано") — застосунок і бот працюють як раніше,
без цих кнопок.
"""

import json
import urllib.error
import urllib.request

import config
import notify

API_URL = "https://backboard.railway.app/graphql/v2"
# Cloudflare перед Railway API блокує запити без звичайного User-Agent
# браузера — без цього заголовка все падає з 403 "error code: 1010".
UA = "Mozilla/5.0 (compatible; RadarZmiiv-Control/1.0)"


def available() -> bool:
    """Чи налаштовано керування хмарою в цьому екземплярі."""
    return bool(config.RAILWAY_TOKEN and config.RAILWAY_PROJECT_ID
               and config.RAILWAY_SERVICE_ID and config.RAILWAY_ENVIRONMENT_ID)


def _call(query: str, variables: dict) -> tuple:
    """Один запит до Railway GraphQL API. Повертає (успіх, дані_або_текст)."""
    body = json.dumps({"query": query, "variables": variables}).encode()
    req = urllib.request.Request(
        API_URL, data=body,
        headers={"Content-Type": "application/json", "User-Agent": UA,
                "Authorization": f"Bearer {config.RAILWAY_TOKEN}"})
    try:
        with urllib.request.urlopen(req, timeout=25,
                                    context=notify.ssl_context()) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except Exception as e:                                  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"

    if "errors" in data:
        return False, data["errors"][0].get("message", "невідома помилка")
    return True, data.get("data")


def set_role(role: str) -> tuple:
    """Змінює RADAR_ROLE хмарного сервісу і перезапускає його з новим значенням.

    role: "main" (хмара стає активною) або "backup" (хмара мовчить).
    """
    if not available():
        return False, "хмарне керування не налаштоване"

    ok, err = _call(
        "mutation($input: VariableUpsertInput!) { variableUpsert(input: $input) }",
        {"input": {"projectId": config.RAILWAY_PROJECT_ID,
                   "environmentId": config.RAILWAY_ENVIRONMENT_ID,
                   "serviceId": config.RAILWAY_SERVICE_ID,
                   "name": "RADAR_ROLE", "value": role, "skipDeploys": True}})
    if not ok:
        return False, f"не вдалося змінити роль: {err}"

    return restart()


def push_settings(data: dict) -> tuple:
    """Надсилає локальні налаштування в хмару й перезапускає її.

    Односторонньо: з комп'ютера в хмару. data повинна вже містити
    актуальну мітку "_synced_at" — за нею settings.load() на хмарі
    зрозуміє, що це нові дані, і застосує їх один раз.
    """
    if not available():
        return False, "хмарне керування не налаштоване"

    ok, err = _call(
        "mutation($input: VariableUpsertInput!) { variableUpsert(input: $input) }",
        {"input": {"projectId": config.RAILWAY_PROJECT_ID,
                   "environmentId": config.RAILWAY_ENVIRONMENT_ID,
                   "serviceId": config.RAILWAY_SERVICE_ID,
                   "name": "RADAR_SETTINGS_JSON",
                   "value": json.dumps(data, ensure_ascii=False),
                   "skipDeploys": True}})
    if not ok:
        return False, f"не вдалося надіслати налаштування: {err}"

    return restart()


def restart() -> tuple:
    """Перезапускає хмарний сервіс із поточними налаштуваннями.

    Той самий виклик, що й «Перезапустити онлайн» — рестарт підхоплює
    щойно змінені змінні середовища, а окремо цю кнопку використовують
    і при збоях, коли хмара просто зависла.
    """
    if not available():
        return False, "хмарне керування не налаштоване"

    ok, res = _call(
        "mutation($id: String!, $envId: String!) { "
        "serviceInstanceRedeploy(serviceId: $id, environmentId: $envId) }",
        {"id": config.RAILWAY_SERVICE_ID, "envId": config.RAILWAY_ENVIRONMENT_ID})
    if not ok:
        return False, f"не вдалося перезапустити: {res}"
    return True, "перезапущено"
