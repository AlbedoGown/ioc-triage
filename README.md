<div align="center">

**English** | [Русский](https://github.com/AlbedoGown/ioc-triage/blob/main/README.ru.md)

# ioc-triage

**Bulk triage of indicators of compromise from the terminal**

IP · domains · URLs · MD5 / SHA1 / SHA256 → VirusTotal, AbuseIPDB, Kaspersky OpenTIP, URLhaus, ThreatFox, MalwareBazaar

[![tests](https://github.com/AlbedoGown/ioc-triage/actions/workflows/tests.yml/badge.svg)](https://github.com/AlbedoGown/ioc-triage/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
[![license](https://img.shields.io/badge/license-MIT-green)](https://github.com/AlbedoGown/ioc-triage/blob/main/LICENSE)

</div>

---

A SOC analyst gets dozens of indicators from an alert, a log or a threat intel report and checks each one by hand in a browser. `ioc-triage` takes the whole list at once, detects the type of every indicator and queries the matching sources through their official APIs — no scraping of web interfaces.

## Features

- **Automatic type detection**: IP, domain, URL, MD5, SHA1, SHA256 — no need to specify it
- **Six sources** via official APIs, each in its own module behind a common interface
- **Private addresses never leave your network**: RFC1918, CGNAT, link-local and loopback are marked as internal without any request
- **Parallel, rate-limit aware**: sources are queried in parallel, each with its own request pacing (VirusTotal free tier: 4 requests/min); clear messages on HTTP 429
- **Local cache**: results are cached for 24 hours, so re-checking the same indicators does not spend API quota; network errors are never cached
- **Never crashes on a source**: a missing key, a network error or a rejected key becomes a row in the results, not a traceback
- **Output for humans and scripts**: table, `--output csv`, `--output json`
- **Zero dependencies**: Python standard library only

## Sources

| Source | Types | Key | Free tier |
|---|---|---|---|
| [VirusTotal](https://www.virustotal.com/) API v3 | hashes, URLs, domains, IPs | `VT_API_KEY` | 4 req/min, 500/day |
| [AbuseIPDB](https://www.abuseipdb.com/) API v2 | IPs | `ABUSEIPDB_API_KEY` | 1000 checks/day |
| [Kaspersky OpenTIP](https://opentip.kaspersky.com/) | hashes, URLs, domains, IPs | `OPENTIP_API_KEY` | not published |
| [MalwareBazaar](https://bazaar.abuse.ch/) | hashes | `ABUSECH_AUTH_KEY` | — |
| [URLhaus](https://urlhaus.abuse.ch/) | URLs; IPs and domains (fallback) | `ABUSECH_AUTH_KEY` | — |
| [ThreatFox](https://threatfox.abuse.ch/) | IPs, domains | `ABUSECH_AUTH_KEY` | — |

All keys are free. A source without a key does not break the run — it is reported as skipped.

## Quick start

```bash
git clone https://github.com/AlbedoGown/ioc-triage.git
cd ioc-triage
pip install -e .

cp .env.example .env          # put your keys here

echo "8.8.8.8" | ioc-triage
```

`.env` in the current directory is loaded automatically; another file can be passed with `--env-file`. Variables already set in the environment take precedence over the file.

## Usage

```bash
# one indicator per line
ioc-triage --input iocs.txt

# CSV: name the column that holds the indicator
ioc-triage --input alerts.csv --column src_ip

# stdin
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' firewall.log | sort -u | ioc-triage

# structured output
ioc-triage --input iocs.txt --output json > result.json
ioc-triage --input iocs.txt --output csv  > result.csv

# cache: custom lifetime or bypass
ioc-triage --input iocs.txt --cache-ttl 6
ioc-triage --input iocs.txt --no-cache

# keys from a specific file, fewer parallel requests per source
ioc-triage --input iocs.txt --env-file ~/secrets/ioc.env --workers 2
```

The cache lives in `~/.cache/ioc-triage/cache.json` (readable only by you) and stores real source answers, including "not found"; errors, skipped sources and rate-limit responses are not cached. Per-source pacing is set with `VT_RATE_LIMIT_PER_MIN`, `OPENTIP_RATE_LIMIT_PER_MIN`, `ABUSEIPDB_RATE_LIMIT_PER_MIN` and `ABUSECH_RATE_LIMIT_PER_MIN` (empty means no pause, VT defaults to 4).

### Output fields

One row per indicator and source. The same fields are table columns, CSV columns and JSON keys:

| Field | Meaning |
|---|---|
| `indicator`, `indicator_type` | the indicator and its detected type |
| `source` | `virustotal`, `abuseipdb`, `opentip`, `abuse.ch/...`; `local` for internal addresses |
| `detections` | engines that flagged it (VT), confidence and reports (AbuseIPDB), malware family (abuse.ch), detection names (OpenTIP) |
| `first_seen` | first seen date, if the source reports it |
| `context` | tags, country, provider and other details from the source |
| `verdict` | the conclusion, or the reason the source was skipped or failed |

Fields hold only what the source actually returns; if a source has no such field, it is empty (`null` in JSON).

## Getting API keys

<details>
<summary><b>VirusTotal</b></summary>

1. Sign up at https://www.virustotal.com/
2. Copy your key from https://www.virustotal.com/gui/my-apikey into `VT_API_KEY`.

The free key allows 4 requests per minute, so the tool waits 15 seconds between requests and reports the wait on stderr. A batch of 100 indicators takes about 25 minutes. With a premium key, raise the limit via `VT_RATE_LIMIT_PER_MIN`.

Verdict: 3+ engines flag it as malicious, 1–2 engines as suspicious (a single detection on a popular domain is a typical false positive). Tune with `VT_MALICIOUS_THRESHOLD`.

</details>

<details>
<summary><b>AbuseIPDB</b></summary>

1. Sign up at https://www.abuseipdb.com/
2. Create a key at https://www.abuseipdb.com/account/api and put it into `ABUSEIPDB_API_KEY`.

Reports from the last 90 days are taken into account. Verdict: 75%+ confidence is malicious, 25%+ is suspicious.

</details>

<details>
<summary><b>Kaspersky OpenTIP</b></summary>

1. Sign up at https://opentip.kaspersky.com/ and accept the terms.
2. Create a key at https://opentip.kaspersky.com/token/ and put it into `OPENTIP_API_KEY`.

Verdict follows the `Zone` field: Red is malicious, Orange/Yellow suspicious, Green clean, Grey no data. Kaspersky does not publish quotas; set `OPENTIP_RATE_LIMIT_PER_MIN` to pace requests. HTTP 403 may mean either a bad key or an exhausted quota. Only reputation lookups are made — files are never uploaded. Note that URL indicators are sent as a query parameter and may end up in the service's logs.

</details>

<details>
<summary><b>abuse.ch</b> (URLhaus, ThreatFox, MalwareBazaar)</summary>

Since 2024 the abuse.ch APIs answer `401 Unauthorized` without a key. One key covers all three services:

1. Sign in at https://auth.abuse.ch/ with GitHub, Google or LinkedIn.
2. Click "Generate Key" in your profile and put the key into `ABUSECH_AUTH_KEY`.

| Type | Query |
|---|---|
| MD5 / SHA1 / SHA256 | MalwareBazaar `get_info` |
| URL | URLhaus `/v1/url/` |
| IP / domain | ThreatFox `search_ioc`; if not found — URLhaus `/v1/host/` |

ThreatFox searches by substring, so only exact matches count (`google.com` does not match `proxy.google.com`); `ip:port` entries do count for a bare IP.

</details>

## Architecture

```
ioc_triage/
├── cli.py            # arguments, input reading, routing by type
├── detect.py         # indicator type detection, private networks
├── cache.py          # local TTL cache
├── envfile.py        # .env loader
├── output.py         # table / csv / json
└── sources/
    ├── __init__.py   # Verdict dataclass
    ├── virustotal.py
    ├── abuseipdb.py
    ├── opentip.py    # Kaspersky OpenTIP
    ├── abusech.py    # URLhaus, ThreatFox, MalwareBazaar
    └── ratelimit.py  # per-source request pacing
```

Every source is a module with `check(indicator, indicator_type) -> Verdict`. A new source is one file plus a line in `SOURCES_BY_TYPE` in `cli.py`.

## Development

```bash
python -m unittest discover -s tests -v
```

Tests mock HTTP responses and never touch the network, so no keys are needed.

## Disclaimer

An educational and portfolio project. The tool aggregates public reputation data: it does not replace incident analysis and does not guarantee the accuracy of third-party verdicts. Respect the terms of use of each API.

## License

[MIT](https://github.com/AlbedoGown/ioc-triage/blob/main/LICENSE) © 2026 AlbedoGown
