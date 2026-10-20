"""Источник VirusTotal API v3: файлы (хеши), URL, домены, IP.

Ключ: https://www.virustotal.com/gui/my-apikey (бесплатный после регистрации).
Free tier: 4 запроса в минуту и 500 в сутки, поэтому запросы идут не чаще
одного раза в 60 / VT_RATE_LIMIT_PER_MIN секунд.
"""

import base64
import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from ioc_triage.sources import Verdict
from ioc_triage.sources.ratelimit import RateLimiter

API_KEY_ENV = "VT_API_KEY"
RATE_LIMIT_ENV = "VT_RATE_LIMIT_PER_MIN"
DEFAULT_RATE_LIMIT_PER_MIN = 4
MALICIOUS_THRESHOLD_ENV = "VT_MALICIOUS_THRESHOLD"
DEFAULT_MALICIOUS_THRESHOLD = 3

API_BASE = "https://www.virustotal.com/api/v3"
HTTP_TIMEOUT = 20
SOURCE = "virustotal"

HASH_TYPES = {"md5", "sha1", "sha256"}

limiter = RateLimiter("VirusTotal", RATE_LIMIT_ENV, DEFAULT_RATE_LIMIT_PER_MIN)


def check(indicator: str, indicator_type: str) -> Verdict:
    """Проверка индикатора в VirusTotal. Исключения наружу не выбрасываются."""
    verdict = Verdict(indicator, indicator_type, SOURCE)

    api_key = os.environ.get(API_KEY_ENV)
    if not api_key:
        verdict.verdict = f"пропущено (нет {API_KEY_ENV})"
        return verdict

    path = _object_path(indicator, indicator_type)
    if path is None:
        verdict.verdict = "тип индикатора не поддерживается VirusTotal"
        return verdict

    try:
        data = _get(f"{API_BASE}/{path}", api_key)
    except urllib.error.HTTPError as exc:
        verdict.verdict = _http_error_text(exc)
        return verdict
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as exc:
        verdict.verdict = f"ошибка сети: {_short_err(exc)}"
        return verdict
    except ValueError as exc:
        verdict.verdict = f"ошибка разбора ответа: {_short_err(exc)}"
        return verdict

    attrs = (data.get("data") or {}).get("attributes") or {}
    _fill_verdict(verdict, attrs, indicator_type)
    return verdict


def _object_path(indicator: str, indicator_type: str) -> str | None:
    if indicator_type in HASH_TYPES:
        return f"files/{indicator.lower()}"
    if indicator_type == "url":
        # Идентификатор URL в API v3 — base64url без padding.
        url_id = base64.urlsafe_b64encode(indicator.encode("utf-8")).decode("ascii").rstrip("=")
        return f"urls/{url_id}"
    if indicator_type == "domain":
        return f"domains/{urllib.parse.quote(indicator.lower(), safe='')}"
    if indicator_type == "ip":
        return f"ip_addresses/{urllib.parse.quote(indicator, safe='')}"
    return None


def _fill_verdict(verdict: Verdict, attrs: dict, indicator_type: str) -> None:
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    total = sum(int(v or 0) for v in stats.values())

    verdict.detections = f"{malicious}/{total}" if total else None
    # first_submission_date есть только у файлов и URL; у доменов и IP его нет.
    verdict.first_seen = _ts_to_date(attrs.get("first_submission_date"))

    context = []
    label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
    if label:
        context.append(label)
    if suspicious:
        context.append(f"suspicious={suspicious}")
    if attrs.get("reputation") is not None and indicator_type in ("domain", "ip"):
        context.append(f"reputation={attrs['reputation']}")
    tags = attrs.get("tags") or []
    if tags:
        context.append(", ".join(tags[:5]))
    verdict.context = "; ".join(context) or None

    if not total:
        verdict.verdict = "нет результатов анализа в VirusTotal"
    elif malicious >= _malicious_threshold():
        verdict.verdict = f"вредоносный ({label})" if label else "вредоносный"
    elif malicious or suspicious:
        # 1–2 движка на популярных доменах — типичное ложное срабатывание.
        verdict.verdict = "подозрительный"
    else:
        verdict.verdict = "похоже на легитимный"


def _malicious_threshold() -> int:
    try:
        return max(1, int(os.environ.get(MALICIOUS_THRESHOLD_ENV) or DEFAULT_MALICIOUS_THRESHOLD))
    except ValueError:
        return DEFAULT_MALICIOUS_THRESHOLD


def _http_error_text(exc: urllib.error.HTTPError) -> str:
    if exc.code == 404:
        return "не найден в VirusTotal"
    if exc.code in (401, 403):
        return f"отказ в доступе (HTTP {exc.code}): проверь {API_KEY_ENV}"
    if exc.code == 429:
        return "превышена квота VirusTotal (HTTP 429)"
    return f"ошибка HTTP {exc.code}"


def _get(url: str, api_key: str) -> dict:
    limiter.wait()
    req = urllib.request.Request(
        url,
        headers={"x-apikey": api_key, "Accept": "application/json", "User-Agent": "ioc-triage/0.1"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8")) if raw else {}


def _ts_to_date(ts) -> str | None:
    if not ts:
        return None
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")


def _short_err(exc: Exception) -> str:
    msg = str(exc)
    return msg[:120] if msg else exc.__class__.__name__
