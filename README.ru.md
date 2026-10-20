<div align="center">

[English](https://github.com/AlbedoGown/ioc-triage/blob/main/README.md) | **Русский**

# ioc-triage

**Проверка пачки индикаторов компрометации одной командой**

IP · домены · URL · MD5 / SHA1 / SHA256 → VirusTotal, AbuseIPDB, Kaspersky OpenTIP, URLhaus, ThreatFox, MalwareBazaar

[![tests](https://github.com/AlbedoGown/ioc-triage/actions/workflows/tests.yml/badge.svg)](https://github.com/AlbedoGown/ioc-triage/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
[![license](https://img.shields.io/badge/license-MIT-green)](https://github.com/AlbedoGown/ioc-triage/blob/main/LICENSE)

</div>

---

`ioc-triage` проверяет список индикаторов компрометации по нескольким источникам репутации за один запуск. Тип каждого индикатора определяется автоматически, запросы идут через официальные API с твоими ключами, без скрейпинга веб-интерфейсов.

## Что умеет

- **Сам определяет тип.** IP, домен, URL, MD5, SHA1, SHA256: подсказывать не нужно.
- **Шесть источников.** Все через официальные API, у каждого свой модуль с общим интерфейсом.
- **Внутренние адреса никуда не уходят.** RFC1918, CGNAT, link-local и loopback сразу помечаются как внутренние, без единого запроса наружу.
- **Параллельные запросы с учетом лимитов.** Источники опрашиваются одновременно, а у каждого своя пауза между запросами (бесплатный VirusTotal дает 4 запроса в минуту). При ответе 429 в результатах будет понятное сообщение.
- **Помнит, что уже проверял.** Результаты живут в локальном кэше 24 часа, так что повторный прогон тех же индикаторов не съедает квоту. Сетевые ошибки в кэш не попадают.
- **Не падает из-за одного источника.** Нет ключа, отвалилась сеть, ключ не приняли: это просто строка в результатах, а не traceback посреди работы.
- **Пишет и для людей, и для скриптов.** Таблица в терминале, `--output csv` или `--output json`.
- **Ноль зависимостей.** Только стандартная библиотека Python.

## Источники

| Источник | Что проверяет | Ключ | Бесплатный лимит |
|---|---|---|---|
| [VirusTotal](https://www.virustotal.com/) API v3 | хеши, URL, домены, IP | `VT_API_KEY` | 4 запроса в минуту, 500 в сутки |
| [AbuseIPDB](https://www.abuseipdb.com/) API v2 | IP | `ABUSEIPDB_API_KEY` | 1000 проверок в сутки |
| [Kaspersky OpenTIP](https://opentip.kaspersky.com/) | хеши, URL, домены, IP | `OPENTIP_API_KEY` | не публикуется |
| [MalwareBazaar](https://bazaar.abuse.ch/) | хеши | `ABUSECH_AUTH_KEY` | не указан |
| [URLhaus](https://urlhaus.abuse.ch/) | URL, а IP и домены как запасной вариант | `ABUSECH_AUTH_KEY` | не указан |
| [ThreatFox](https://threatfox.abuse.ch/) | IP, домены | `ABUSECH_AUTH_KEY` | не указан |

Все ключи бесплатные. Если какого-то ключа нет, проверка не сломается: источник просто будет помечен как «пропущено (нет …)».

## Быстрый старт

```bash
pip install ioc-triage
```

Дальше положи ключи в `.env` (имена переменных в таблице выше) и проверь первый индикатор:

```bash
cat > .env <<'KEYS'
VT_API_KEY=
ABUSEIPDB_API_KEY=
OPENTIP_API_KEY=
ABUSECH_AUTH_KEY=
KEYS

echo "8.8.8.8" | ioc-triage
```

`.env` из текущей папки подхватывается сам. Если ключи лежат в другом месте, укажи файл через `--env-file`. Переменные, которые уже заданы в окружении, главнее значений из файла.

## Как пользоваться

```bash
# список индикаторов, по одному на строку
ioc-triage --input iocs.txt

# CSV: скажи, в каком столбце индикатор
ioc-triage --input alerts.csv --column src_ip

# через stdin, например все уникальные IP из лога файрвола
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' firewall.log | sort -u | ioc-triage

# структурированный вывод для дальнейшей обработки
ioc-triage --input iocs.txt --output json > result.json
ioc-triage --input iocs.txt --output csv  > result.csv

# кэш: свой срок жизни или вообще без него
ioc-triage --input iocs.txt --cache-ttl 6
ioc-triage --input iocs.txt --no-cache

# ключи из конкретного файла и поменьше параллельных запросов
ioc-triage --input iocs.txt --env-file ~/secrets/ioc.env --workers 2
```

Кэш лежит в `~/.cache/ioc-triage/cache.json`, читать его можешь только ты. В нем хранятся настоящие ответы источников, включая «не найден». Ошибки, пропущенные источники и ответы про превышение лимита туда не пишутся.

Паузу для каждого источника можно подкрутить: `VT_RATE_LIMIT_PER_MIN`, `OPENTIP_RATE_LIMIT_PER_MIN`, `ABUSEIPDB_RATE_LIMIT_PER_MIN` и `ABUSECH_RATE_LIMIT_PER_MIN`. Пустое значение значит «без паузы», для VT по умолчанию стоит 4.

### Что в результатах

На каждую пару «индикатор + источник» одна строка. Набор полей везде один и тот же: это колонки таблицы и CSV и ключи в JSON.

| Поле | Что в нем |
|---|---|
| `indicator`, `indicator_type` | сам индикатор и его тип |
| `source` | `virustotal`, `abuseipdb`, `opentip`, `abuse.ch/...`, а для внутренних адресов `local` |
| `detections` | сколько движков сработало (VT), уверенность и число жалоб (AbuseIPDB), семейство вредоноса (abuse.ch), названия детектов (OpenTIP) |
| `first_seen` | когда индикатор впервые заметили, если источник это знает |
| `context` | теги, страна, провайдер и прочие подробности от источника |
| `verdict` | вывод или причина, почему источник пропущен или не ответил |

Инструмент ничего не додумывает: в поле попадает только то, что реально вернул источник. Если такого поля у источника нет, оно останется пустым (`null` в JSON).

## Где взять ключи

<details>
<summary><b>VirusTotal</b></summary>

1. Зарегистрируйся на https://www.virustotal.com/
2. Возьми ключ на https://www.virustotal.com/gui/my-apikey и запиши в `VT_API_KEY`.

Бесплатный ключ дает всего 4 запроса в минуту, поэтому между запросами инструмент ждет 15 секунд и пишет об этом в stderr. Сотня индикаторов проверяется примерно за 25 минут. С премиум-ключом подними лимит через `VT_RATE_LIMIT_PER_MIN`.

Как ставится вердикт: если сработали 3 движка и больше, это «вредоносный», если 1 или 2, то «подозрительный». Одиночный детект на популярном домене почти всегда оказывается ложным срабатыванием, поэтому порог не единица. Поменять его можно через `VT_MALICIOUS_THRESHOLD`.

</details>

<details>
<summary><b>AbuseIPDB</b></summary>

1. Зарегистрируйся на https://www.abuseipdb.com/
2. Создай ключ на https://www.abuseipdb.com/account/api и запиши в `ABUSEIPDB_API_KEY`.

Учитываются жалобы за последние 90 дней. Уверенность от 75% дает «вредоносный», от 25% «подозрительный».

</details>

<details>
<summary><b>Kaspersky OpenTIP</b></summary>

1. Зарегистрируйся на https://opentip.kaspersky.com/ и прими условия.
2. Создай ключ на https://opentip.kaspersky.com/token/ и запиши в `OPENTIP_API_KEY`.

Вердикт берется из поля `Zone`: Red значит «вредоносный», Orange и Yellow «подозрительный», Green «похоже на легитимный», Grey «нет данных».

Пара нюансов:
- Лимиты Kaspersky не публикует, так что паузу между запросами задавай сам через `OPENTIP_RATE_LIMIT_PER_MIN`.
- HTTP 403 может означать и неверный ключ, и закончившуюся квоту.
- Инструмент делает только репутационные запросы и никогда не загружает файлы в облако.
- URL без пути (например `https://example.com/`) OpenTIP как URL не принимает и отвечает 400. Такой URL инструмент сам проверяет как домен или IP и пишет об этом в `context`.
- URL-индикатор уходит в параметре запроса, поэтому может осесть в логах сервиса. Помни об этом, если URL чувствительный.

</details>

<details>
<summary><b>abuse.ch</b> (URLhaus, ThreatFox, MalwareBazaar)</summary>

С 2024 года API abuse.ch без ключа отвечают `401 Unauthorized`. Ключ один на все три сервиса.

1. Войди на https://auth.abuse.ch/ через GitHub, Google или LinkedIn.
2. Нажми «Generate Key» в профиле и запиши ключ в `ABUSECH_AUTH_KEY`.

| Тип | Куда идет запрос |
|---|---|
| MD5 / SHA1 / SHA256 | MalwareBazaar `get_info` |
| URL | URLhaus `/v1/url/` |
| IP / домен | ThreatFox `search_ioc`, а если там пусто, то URLhaus `/v1/host/` |

ThreatFox ищет по подстроке, поэтому `google.com` совпадает, например, с `proxy.google.com`. Инструмент засчитывает только точные совпадения. Исключение: записи вида `ip:port` засчитываются для голого IP.

</details>

## Как устроено

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

Каждый источник это модуль с функцией `check(indicator, indicator_type) -> Verdict`. Новый источник добавляется одним файлом и одной строкой в `SOURCES_BY_TYPE` в `cli.py`.

## Разработка

```bash
git clone https://github.com/AlbedoGown/ioc-triage.git
cd ioc-triage
pip install -e .
python -m unittest discover -s tests -v
```

Тесты подменяют HTTP-ответы и в сеть не ходят, так что ключи для них не нужны.

## Отказ от ответственности

Это учебный и портфолио-проект. Инструмент собирает публичные данные о репутации в одном месте, но не заменяет разбор инцидента и не ручается за точность вердиктов сторонних источников. И соблюдай условия использования каждого API.

## Лицензия

[MIT](https://github.com/AlbedoGown/ioc-triage/blob/main/LICENSE) © 2026 AlbedoGown
