"""Источник Kaspersky OpenTIP: репутация хешей, IP, доменов и URL.

Ключ: https://opentip.kaspersky.com/token/ (регистрация и согласие с условиями).
Механика сверена с официальным клиентом KasperskyLab/OpenTIP-scanner:
заголовок x-api-key, GET search/{тип}?request=..., 404 — объект не найден.
Лимиты Kaspersky не публикует, поэтому пауза между запросами настраивается
через OPENTIP_RATE_LIMIT_PER_MIN (по умолчанию без паузы).
Файлы в облако намеренно не загружаются — только репутационные запросы.
"""

import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request

from ioc_triage.sources import Verdict
from ioc_triage.sources.ratelimit import RateLimiter

API_KEY_ENV = "OPENTIP_API_KEY"
RATE_LIMIT_ENV = "OPENTIP_RATE_LIMIT_PER_MIN"
API_BASE = "https://opentip.kaspersky.com/api/v1"
HTTP_TIMEOUT = 20
SOURCE = "opentip"

SEARCH_TYPES = {"md5": "hash", "sha1": "hash", "sha256": "hash", "ip": "ip", "domain": "domain", "url": "url"}

ZONE_VERDICTS = {
    "red": "вредоносный",
    "orange": "подозрительный",
    "yellow": "подозрительный",
    "green": "похоже на легитимный",
    "grey": "нет данных в OpenTIP",
}
# Статусы, которые официальный клиент считает отсутствием угрозы.
CLEAN_FILE_STATUSES = {"Clean", "NotCategorized", "NoThreats"}

limiter = RateLimiter("OpenTIP", RATE_LIMIT_ENV, 0)


def check(indicator: str, indicator_type: str) -> Verdict:
    """Проверка индикатора в OpenTIP. Исключения наружу не выбрасываются."""
    verdict = Verdict(indicator, indicator_type, SOURCE)

    api_key = os.environ.get(API_KEY_ENV)
    if not api_key:
        verdict.verdict = f"пропущено (нет {API_KEY_ENV})"
        return verdict

    search_type = SEARCH_TYPES.get(indicator_type)
    if search_type is None:
        verdict.verdict = "тип индикатора не поддерживается OpenTIP"
        return verdict

    value = indicator if indicator_type == "url" else indicator.lower()
    url = f"{API_BASE}/search/{search_type}?request={urllib.parse.quote(value, safe='')}"
    try:
        data = _get(url, api_key)
    except urllib.error.HTTPError as exc:
        verdict.verdict = _http_error_text(exc)
        verdict.cacheable = exc.code == 404
        return verdict
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as exc:
        verdict.verdict = f"ошибка сети: {_short_err(exc)}"
        return verdict
    except ValueError as exc:
        verdict.verdict = f"ошибка разбора ответа: {_short_err(exc)}"
        return verdict

    _fill_verdict(verdict, data)
    verdict.cacheable = True
    return verdict


def _fill_verdict(verdict: Verdict, data: dict) -> None:
    # FileGeneralInfo, IpGeneralInfo и т.д.; для домена и URL структура не подтверждена,
    # поэтому берём любой блок *GeneralInfo, если он есть.
    general = next(
        (v for k, v in data.items() if k.endswith("GeneralInfo") and isinstance(v, dict)),
        {},
    )

    names = []
    for item in data.get("DetectionsInfo") or []:
        name = item.get("DetectionName")
        if name and name not in names:
            names.append(name)
    verdict.detections = ", ".join(names[:3]) or None
    verdict.first_seen = general.get("FirstSeen")

    zone = data.get("Zone")
    status = general.get("FileStatus") or general.get("Status")
    context = []
    if zone:
        context.append(f"zone={zone}")
    for key in ("FileStatus", "Status", "Type", "HitsCount", "CountryCode"):
        if general.get(key) not in (None, ""):
            context.append(f"{key}={general[key]}")
    verdict.context = "; ".join(context) or None

    if zone and zone.lower() in ZONE_VERDICTS:
        text = ZONE_VERDICTS[zone.lower()]
    elif general.get("FileStatus"):
        text = "похоже на легитимный" if general["FileStatus"] in CLEAN_FILE_STATUSES else "вредоносный"
    else:
        text = f"неизвестно (статус: {status})" if status else "нет данных в OpenTIP"

    if text == "вредоносный" and names:
        text = f"вредоносный ({names[0]})"
    verdict.verdict = text


def _http_error_text(exc: urllib.error.HTTPError) -> str:
    if exc.code == 404:
        return "не найден в OpenTIP"
    if exc.code == 401:
        return f"отказ в доступе (HTTP 401): проверь {API_KEY_ENV}"
    if exc.code == 403:
        # Официальный клиент трактует 403 и как исчерпанную квоту.
        return f"доступ запрещён (HTTP 403): неверный {API_KEY_ENV} или исчерпана квота"
    if exc.code == 400:
        return "OpenTIP отклонил запрос (HTTP 400)"
    if exc.code == 429:
        return "превышен лимит запросов OpenTIP (HTTP 429)"
    return f"ошибка HTTP {exc.code}"


def _get(url: str, api_key: str) -> dict:
    limiter.wait()
    req = urllib.request.Request(
        url,
        headers={"x-api-key": api_key, "Accept": "application/json", "User-Agent": "ioc-triage/0.2"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8")) if raw else {}


def _short_err(exc: Exception) -> str:
    msg = str(exc)
    return msg[:120] if msg else exc.__class__.__name__
