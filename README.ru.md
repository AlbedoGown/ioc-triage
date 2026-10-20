<div align="center">

[English](https://github.com/AlbedoGown/ioc-triage/blob/main/README.md) | **Русский**

# ioc-triage

**Пакетная проверка индикаторов компрометации из терминала**

IP · домены · URL · MD5 / SHA1 / SHA256 → VirusTotal, AbuseIPDB, Kaspersky OpenTIP, URLhaus, ThreatFox, MalwareBazaar

[![tests](https://github.com/AlbedoGown/ioc-triage/actions/workflows/tests.yml/badge.svg)](https://github.com/AlbedoGown/ioc-triage/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
[![license](https://img.shields.io/badge/license-MIT-green)](https://github.com/AlbedoGown/ioc-triage/blob/main/LICENSE)

</div>

---

SOC-аналитик получает из алерта, лога или отчёта threat intel десятки индикаторов и проверяет каждый вручную в браузере. `ioc-triage` берёт весь список сразу, сам определяет тип каждого индикатора и опрашивает подходящие источники через их официальные API — без скрейпинга веб-интерфейсов.

## Зачем несколько источников

Результаты живых проверок (октябрь 2026):

| Индикатор | VirusTotal | abuse.ch | Что показывает ioc-triage |
|---|---|---|---|
| `203.195.219.186`, C2-сервер | 0/92, чистый | ThreatFox: VShell | VirusTotal ничего не видит, C2 ловит только ThreatFox |
| `google.com` | 1/92 | ThreatFox: только совпадения по подстроке вроде `google-proxy-66-249-88-66.google.com` | «подозрительный», а не «вредоносный»: один движок ниже порога 3; совпадения по подстроке отброшены |
| SHA256 образца из MalwareBazaar | 23/75, `trojan.cryxos/alien` | — | «вредоносный (trojan.cryxos/alien)» |

Один источник либо пропускает угрозу, либо поднимает ложную тревогу. Несколько источников рядом и точное сопоставление дают вердикт, по которому аналитик может действовать.

## Возможности

- **Автоопределение типа**: IP, домен, URL, MD5, SHA1, SHA256 — указывать вручную не нужно
- **Шесть источников** через официальные API, у каждого свой модуль с единым интерфейсом
- **Приватные адреса не уходят наружу**: RFC1918, CGNAT, link-local и loopback помечаются как внутренние без запросов
- **Параллельно и с учётом лимитов**: источники опрашиваются параллельно, у каждого своя пауза между запросами (VirusTotal free tier — 4 запроса/мин); понятные сообщения при 429
- **Локальный кэш**: результаты хранятся 24 часа, повторная проверка тех же индикаторов не тратит лимит API; сетевые ошибки не кэшируются
- **Без падений**: нет ключа, сетевая ошибка, неверный ключ — всё это строка в результатах, а не traceback
- **Вывод для людей и скриптов**: таблица, `--output csv`, `--output json`
- **Ноль зависимостей**: только стандартная библиотека Python

## Источники

| Источник | Типы | Ключ | Бесплатный лимит |
|---|---|---|---|
| [VirusTotal](https://www.virustotal.com/) API v3 | хеши, URL, домены, IP | `VT_API_KEY` | 4 запроса/мин, 500/сутки |
| [AbuseIPDB](https://www.abuseipdb.com/) API v2 | IP | `ABUSEIPDB_API_KEY` | 1000 проверок/сутки |
| [Kaspersky OpenTIP](https://opentip.kaspersky.com/) | хеши, URL, домены, IP | `OPENTIP_API_KEY` | не опубликован |
| [MalwareBazaar](https://bazaar.abuse.ch/) | хеши | `ABUSECH_AUTH_KEY` | — |
| [URLhaus](https://urlhaus.abuse.ch/) | URL; IP и домены (резерв) | `ABUSECH_AUTH_KEY` | — |
| [ThreatFox](https://threatfox.abuse.ch/) | IP, домены | `ABUSECH_AUTH_KEY` | — |

Все ключи бесплатные. Источник без ключа не ломает проверку, а помечается как «пропущено (нет …)».

## Быстрый старт

```bash
git clone https://github.com/AlbedoGown/ioc-triage.git
cd ioc-triage
pip install -e .

cp .env.example .env          # впиши свои ключи

echo "8.8.8.8" | ioc-triage
```

`.env` из текущей папки подхватывается автоматически, другой файл можно указать через `--env-file`. Переменные, уже заданные в окружении, важнее значений из файла.

## Использование

```bash
# список индикаторов построчно
ioc-triage --input iocs.txt

# CSV: указать столбец с индикатором
ioc-triage --input alerts.csv --column src_ip

# stdin
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' firewall.log | sort -u | ioc-triage

# структурированный вывод
ioc-triage --input iocs.txt --output json > result.json
ioc-triage --input iocs.txt --output csv  > result.csv

# кэш: свой срок жизни или без кэша
ioc-triage --input iocs.txt --cache-ttl 6
ioc-triage --input iocs.txt --no-cache

# ключи из конкретного файла, меньше параллельных запросов на источник
ioc-triage --input iocs.txt --env-file ~/secrets/ioc.env --workers 2
```

Кэш лежит в `~/.cache/ioc-triage/cache.json` (доступен только тебе) и хранит настоящие ответы источников, включая «не найден». Ошибки, пропущенные источники и ответы о превышении лимита не кэшируются. Пауза для каждого источника задаётся через `VT_RATE_LIMIT_PER_MIN`, `OPENTIP_RATE_LIMIT_PER_MIN`, `ABUSEIPDB_RATE_LIMIT_PER_MIN` и `ABUSECH_RATE_LIMIT_PER_MIN` (пусто — без паузы, для VT по умолчанию 4).

### Поля результата

Одна строка на пару «индикатор + источник». Одни и те же поля — это колонки таблицы и CSV и ключи JSON:

| Поле | Что в нём |
|---|---|
| `indicator`, `indicator_type` | индикатор и его определённый тип |
| `source` | `virustotal`, `abuseipdb`, `opentip`, `abuse.ch/...`; `local` для внутренних адресов |
| `detections` | сработавшие движки (VT), уверенность и жалобы (AbuseIPDB), семейство вредоноса (abuse.ch), названия детектов (OpenTIP) |
| `first_seen` | дата первого обнаружения, если источник её отдаёт |
| `context` | теги, страна, провайдер и другие детали от источника |
| `verdict` | вывод или причина, по которой источник пропущен или не ответил |

Поля заполняются только тем, что реально отдаёт источник; если поля у источника нет, оно пустое (`null` в JSON).

## Получение ключей

<details>
<summary><b>VirusTotal</b></summary>

1. Зарегистрируйся на https://www.virustotal.com/
2. Скопируй ключ на https://www.virustotal.com/gui/my-apikey в `VT_API_KEY`.

Бесплатный ключ даёт 4 запроса в минуту: между запросами инструмент ждёт 15 секунд и пишет об этом в stderr. Пакет из 100 индикаторов проверяется около 25 минут. Для премиум-ключа подними лимит через `VT_RATE_LIMIT_PER_MIN`.

Вердикт: от 3 сработавших движков — «вредоносный», 1–2 — «подозрительный» (одиночный детект на популярном домене — типичное ложное срабатывание). Порог задаётся через `VT_MALICIOUS_THRESHOLD`.

</details>

<details>
<summary><b>AbuseIPDB</b></summary>

1. Зарегистрируйся на https://www.abuseipdb.com/
2. Создай ключ на https://www.abuseipdb.com/account/api и запиши его в `ABUSEIPDB_API_KEY`.

Учитываются жалобы за последние 90 дней. Вердикт: от 75% уверенности — «вредоносный», от 25% — «подозрительный».

</details>

<details>
<summary><b>Kaspersky OpenTIP</b></summary>

1. Зарегистрируйся на https://opentip.kaspersky.com/ и прими условия.
2. Создай ключ на https://opentip.kaspersky.com/token/ и запиши его в `OPENTIP_API_KEY`.

Вердикт берётся из поля `Zone`: Red — «вредоносный», Orange/Yellow — «подозрительный», Green — «похоже на легитимный», Grey — «нет данных». Лимиты Kaspersky не публикует, паузу между запросами задаёт `OPENTIP_RATE_LIMIT_PER_MIN`. HTTP 403 может означать как неверный ключ, так и исчерпанную квоту. Делаются только репутационные запросы, файлы в облако не загружаются. URL-индикатор уходит в параметре запроса и может попасть в логи сервиса.

</details>

<details>
<summary><b>abuse.ch</b> (URLhaus, ThreatFox, MalwareBazaar)</summary>

С 2024 года API abuse.ch без ключа отвечают `401 Unauthorized`. Ключ один на все три сервиса:

1. Войди на https://auth.abuse.ch/ через GitHub, Google или LinkedIn.
2. Нажми «Generate Key» в профиле и запиши ключ в `ABUSECH_AUTH_KEY`.

| Тип | Запрос |
|---|---|
| MD5 / SHA1 / SHA256 | MalwareBazaar `get_info` |
| URL | URLhaus `/v1/url/` |
| IP / домен | ThreatFox `search_ioc`; если не найден — URLhaus `/v1/host/` |

ThreatFox ищет по подстроке, поэтому засчитываются только точные совпадения (`google.com` не совпадёт с `proxy.google.com`); записи вида `ip:port` учитываются для голого IP.

</details>

## Архитектура

```
ioc_triage/
├── cli.py            # аргументы, чтение входа, маршрутизация по типу
├── detect.py         # определение типа индикатора, приватные сети
├── cache.py          # локальный кэш с TTL
├── envfile.py        # загрузка .env
├── output.py         # table / csv / json
└── sources/
    ├── __init__.py   # dataclass Verdict
    ├── virustotal.py
    ├── abuseipdb.py
    ├── opentip.py    # Kaspersky OpenTIP
    ├── abusech.py    # URLhaus, ThreatFox, MalwareBazaar
    └── ratelimit.py  # пауза между запросами к источнику
```

Каждый источник — модуль с функцией `check(indicator, indicator_type) -> Verdict`. Новый источник добавляется одним файлом и строкой в `SOURCES_BY_TYPE` в `cli.py`.

## Разработка

```bash
python -m unittest discover -s tests -v
```

Тесты подменяют HTTP-ответы и не ходят в сеть, ключи для них не нужны.

## Отказ от ответственности

Учебный и портфолио-проект. Инструмент агрегирует публичные данные репутации: он не заменяет анализ инцидента и не гарантирует точность вердиктов сторонних источников. Соблюдай условия использования каждого API.

## Лицензия

[MIT](https://github.com/AlbedoGown/ioc-triage/blob/main/LICENSE) © 2026 AlbedoGown
