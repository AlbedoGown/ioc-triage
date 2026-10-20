# Changelog

## [Unreleased]

### Добавлено
- Источник Kaspersky OpenTIP для хешей, IP, доменов и URL (`OPENTIP_API_KEY`), настраиваемая пауза `OPENTIP_RATE_LIMIT_PER_MIN`.
- Общий ограничитель частоты запросов для источников.

## [0.2.0] — 2026-10-20

### Добавлено
- Источник abuse.ch: MalwareBazaar (хеши), URLhaus (URL, резерв для IP и доменов), ThreatFox (IP, домены). Требуется бесплатный `ABUSECH_AUTH_KEY`.
- Источник VirusTotal API v3 для хешей, URL, доменов и IP с паузой под лимит бесплатного тарифа (`VT_RATE_LIMIT_PER_MIN`).
- Порог вердикта VirusTotal (`VT_MALICIOUS_THRESHOLD`, по умолчанию 3): 1–2 детекта дают «подозрительный».
- Источник AbuseIPDB API v2 для IP.
- Тесты с подменой HTTP, CI на GitHub Actions (Python 3.10–3.13).
- README на английском и русском.

### Исправлено
- ThreatFox: засчитываются только точные совпадения, `google.com` больше не совпадает с `*.google.com`.
- Нереализованный источник больше не пропадает из вывода молча.
- README: abuse.ch больше не описан как работающий без ключа.

## [0.1.0]

- Каркас: CLI, определение типа индикатора, вывод table/csv/json, модуль кэша, заглушки источников.
