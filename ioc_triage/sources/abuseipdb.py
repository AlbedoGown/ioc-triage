"""Источник AbuseIPDB API v2: репутация IP по жалобам пользователей.

Ключ: https://www.abuseipdb.com/account/api (бесплатный после регистрации).
Free tier: 1000 проверок в сутки.
"""

import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request

from ioc_triage.sources import Verdict

API_KEY_ENV = "ABUSEIPDB_API_KEY"
API_URL = "https://api.abuseipdb.com/api/v2/check"
MAX_AGE_DAYS = 90
HTTP_TIMEOUT = 15
SOURCE = "abuseipdb"


def check(indicator: str, indicator_type: str) -> Verdict:
    if indicator_type != "ip":
        raise ValueError("abuseipdb проверяет только IP")

    verdict = Verdict(indicator, indicator_type, SOURCE)
    api_key = os.environ.get(API_KEY_ENV)
    if not api_key:
        verdict.verdict = f"пропущено (нет {API_KEY_ENV})"
        return verdict

    query = urllib.parse.urlencode({"ipAddress": indicator, "maxAgeInDays": MAX_AGE_DAYS})
    try:
        data = _get(f"{API_URL}?{query}", api_key)
    except urllib.error.HTTPError as exc:
        verdict.verdict = _http_error_text(exc)
        return verdict
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as exc:
        verdict.verdict = f"ошибка сети: {_short_err(exc)}"
        return verdict
    except ValueError as exc:
        verdict.verdict = f"ошибка разбора ответа: {_short_err(exc)}"
        return verdict

    _fill_verdict(verdict, data.get("data") or {})
    return verdict


def _fill_verdict(verdict: Verdict, info: dict) -> None:
    score = int(info.get("abuseConfidenceScore") or 0)
    reports = int(info.get("totalReports") or 0)

    verdict.detections = f"{score}% ({reports} жалоб)"
    # AbuseIPDB отдаёт только дату последней жалобы — first_seen не заполняем.
    context = []
    if info.get("lastReportedAt"):
        context.append(f"последняя жалоба {info['lastReportedAt'][:10]}")
    for key in ("countryCode", "isp", "usageType"):
        if info.get(key):
            context.append(str(info[key]))
    if info.get("isTor"):
        context.append("Tor")
    if info.get("isWhitelisted"):
        context.append("в whitelist AbuseIPDB")
    verdict.context = "; ".join(context) or None

    if reports == 0:
        verdict.verdict = f"нет жалоб за {MAX_AGE_DAYS} дней"
    elif score >= 75:
        verdict.verdict = "вредоносный"
    elif score >= 25:
        verdict.verdict = "подозрительный"
    else:
        verdict.verdict = "низкий риск"


def _http_error_text(exc: urllib.error.HTTPError) -> str:
    if exc.code in (401, 403):
        return f"отказ в доступе (HTTP {exc.code}): проверь {API_KEY_ENV}"
    if exc.code == 429:
        return "превышен суточный лимит AbuseIPDB (HTTP 429)"
    if exc.code == 422:
        return "AbuseIPDB отклонил адрес (HTTP 422)"
    return f"ошибка HTTP {exc.code}"


def _get(url: str, api_key: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={"Key": api_key, "Accept": "application/json", "User-Agent": "ioc-triage/0.1"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8")) if raw else {}


def _short_err(exc: Exception) -> str:
    msg = str(exc)
    return msg[:120] if msg else exc.__class__.__name__
