"""Источники репутации abuse.ch: URLhaus, ThreatFox, MalwareBazaar.

С конца 2024 года все публичные API abuse.ch требуют заголовок ``Auth-Key``.
Регистрация ключа бесплатная: https://auth.abuse.ch/ (вход через GitHub/Google).
Ключ один на все три сервиса.
"""

import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request

from ioc_triage.sources import Verdict

API_KEY_ENV = "ABUSECH_AUTH_KEY"

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"

HASH_TYPES = {"md5", "sha1", "sha256"}
HTTP_TIMEOUT = 15


def check(indicator: str, indicator_type: str) -> Verdict:
    """Основная точка входа: маршрутизирует индикатор к нужному сервису abuse.ch."""
    source_hint = _source_hint(indicator_type)
    verdict = Verdict(indicator, indicator_type, source_hint)

    api_key = os.environ.get(API_KEY_ENV)
    if not api_key:
        verdict.verdict = f"пропущено (нет {API_KEY_ENV})"
        return verdict

    try:
        if indicator_type in HASH_TYPES:
            return _check_malwarebazaar(indicator, indicator_type, api_key)
        if indicator_type == "url":
            return _check_urlhaus_url(indicator, api_key)
        if indicator_type in ("domain", "ip"):
            # ThreatFox даёт самое широкое покрытие (C2, вредоносные хосты);
            # если ничего не нашёл — спрашиваем URLhaus про хост как fallback.
            tf = _check_threatfox(indicator, indicator_type, api_key)
            if tf.verdict.startswith("не найден"):
                uh = _check_urlhaus_host(indicator, indicator_type, api_key)
                if not uh.verdict.startswith("не найден"):
                    return uh
            return tf
        verdict.verdict = "тип индикатора не поддерживается abuse.ch"
        return verdict
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            verdict.verdict = f"отказ в доступе (HTTP {exc.code}): проверь {API_KEY_ENV}"
        elif exc.code == 429:
            verdict.verdict = "превышен лимит запросов abuse.ch (HTTP 429)"
        else:
            verdict.verdict = f"ошибка HTTP {exc.code}"
        return verdict
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as exc:
        verdict.verdict = f"ошибка сети: {_short_err(exc)}"
        return verdict
    except (ValueError, KeyError) as exc:
        # Невалидный JSON или неожиданная структура ответа.
        verdict.verdict = f"ошибка разбора ответа: {_short_err(exc)}"
        return verdict


# ---------------------------------------------------------------------------
# MalwareBazaar
# ---------------------------------------------------------------------------


def _check_malwarebazaar(indicator: str, indicator_type: str, api_key: str) -> Verdict:
    data = _post_form(
        MALWAREBAZAAR_URL,
        {"query": "get_info", "hash": indicator},
        api_key,
    )
    verdict = Verdict(indicator, indicator_type, "abuse.ch/MalwareBazaar")

    status = data.get("query_status")
    if status == "hash_not_found":
        verdict.verdict = "не найден в MalwareBazaar"
        return verdict
    if status in ("illegal_hash", "no_hash_provided"):
        verdict.verdict = f"MalwareBazaar: {status}"
        return verdict
    if status != "ok":
        verdict.verdict = f"MalwareBazaar вернул статус: {status}"
        return verdict

    sample = (data.get("data") or [{}])[0]
    family = sample.get("signature") or sample.get("file_type") or "неизвестное семейство"
    tags = sample.get("tags") or []
    verdict.detections = family
    verdict.first_seen = sample.get("first_seen")
    verdict.context = ", ".join(tags) if tags else sample.get("file_name")
    verdict.verdict = f"вредоносный ({family})"
    return verdict


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------


def _check_urlhaus_url(indicator: str, api_key: str) -> Verdict:
    data = _post_form(URLHAUS_URL, {"url": indicator}, api_key)
    verdict = Verdict(indicator, "url", "abuse.ch/URLhaus")

    status = data.get("query_status")
    if status == "no_results":
        verdict.verdict = "не найден в URLhaus"
        return verdict
    if status != "ok":
        verdict.verdict = f"URLhaus вернул статус: {status}"
        return verdict

    threat = data.get("threat") or "malware_download"
    tags = data.get("tags") or []
    url_status = data.get("url_status")  # online/offline
    verdict.detections = threat
    verdict.first_seen = data.get("date_added")
    verdict.context = ", ".join(tags) if tags else None
    verdict.verdict = f"вредоносный URL ({threat}, {url_status or 'статус неизв.'})"
    return verdict


def _check_urlhaus_host(indicator: str, indicator_type: str, api_key: str) -> Verdict:
    data = _post_form(URLHAUS_HOST_URL, {"host": indicator}, api_key)
    verdict = Verdict(indicator, indicator_type, "abuse.ch/URLhaus")

    status = data.get("query_status")
    if status == "no_results":
        verdict.verdict = "не найден в URLhaus"
        return verdict
    if status != "ok":
        verdict.verdict = f"URLhaus вернул статус: {status}"
        return verdict

    urls = data.get("urls") or []
    online_count = sum(1 for u in urls if u.get("url_status") == "online")
    verdict.detections = f"{online_count}/{len(urls)} активных URL"
    verdict.first_seen = data.get("firstseen")
    verdict.context = f"blacklists: {data.get('blacklists') or {}}"
    verdict.verdict = f"известный вредоносный хост ({len(urls)} URL в базе)"
    return verdict


# ---------------------------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------------------------


def _check_threatfox(indicator: str, indicator_type: str, api_key: str) -> Verdict:
    data = _post_json(
        THREATFOX_URL,
        {"query": "search_ioc", "search_term": indicator},
        api_key,
    )
    verdict = Verdict(indicator, indicator_type, "abuse.ch/ThreatFox")

    status = data.get("query_status")
    if status == "no_result":
        verdict.verdict = "не найден в ThreatFox"
        return verdict
    if status != "ok":
        verdict.verdict = f"ThreatFox вернул статус: {status}"
        return verdict

    # search_ioc ищет по подстроке: google.com совпадает с google-proxy-....google.com.
    # exact_match не подходит — он теряет записи вида ip:port, поэтому фильтруем сами.
    rows = [r for r in (data.get("data") or []) if _ioc_matches(r.get("ioc"), indicator)]
    if not rows:
        verdict.verdict = "не найден в ThreatFox"
        return verdict

    first = rows[0]
    malware = first.get("malware_printable") or first.get("malware") or "неизвестное семейство"
    threat_type = first.get("threat_type") or "ioc"
    verdict.detections = f"{malware} ({threat_type})"
    verdict.first_seen = first.get("first_seen")
    parts = []
    if first.get("ioc"):
        parts.append(f"ioc={first['ioc']}")
    if first.get("confidence_level") is not None:
        parts.append(f"confidence={first['confidence_level']}")
    tags = first.get("tags") or []
    if tags:
        parts.append(", ".join(tags))
    if len(rows) > 1:
        parts.append(f"записей: {len(rows)}")
    verdict.context = "; ".join(parts) or None
    verdict.verdict = f"вредоносный ({malware})"
    return verdict


# ---------------------------------------------------------------------------
# HTTP-утилиты (stdlib urllib — чтобы не тянуть зависимости)
# ---------------------------------------------------------------------------


def _post_form(url: str, fields: dict, api_key: str) -> dict:
    body = urllib.parse.urlencode(fields).encode("utf-8")
    return _request(url, body, api_key, content_type="application/x-www-form-urlencoded")


def _post_json(url: str, payload: dict, api_key: str) -> dict:
    body = json.dumps(payload).encode("utf-8")
    return _request(url, body, api_key, content_type="application/json")


def _request(url: str, body: bytes, api_key: str, content_type: str) -> dict:
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Auth-Key": api_key,
            "Content-Type": content_type,
            "Accept": "application/json",
            "User-Agent": "ioc-triage/0.1",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        raw = resp.read()
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def _ioc_matches(ioc: str | None, indicator: str) -> bool:
    """Точное совпадение IOC ThreatFox с индикатором, допускается суффикс :порт."""
    if not ioc:
        return False
    ioc = ioc.lower()
    indicator = indicator.lower()
    return ioc == indicator or (ioc.startswith(indicator + ":") and ioc[len(indicator) + 1 :].isdigit())


def _source_hint(indicator_type: str) -> str:
    if indicator_type in HASH_TYPES:
        return "abuse.ch/MalwareBazaar"
    if indicator_type == "url":
        return "abuse.ch/URLhaus"
    return "abuse.ch/ThreatFox"


def _short_err(exc: Exception) -> str:
    msg = str(exc)
    return msg[:120] if msg else exc.__class__.__name__
