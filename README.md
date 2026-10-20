<div align="center">

**English** | [Русский](https://github.com/AlbedoGown/ioc-triage/blob/main/README.ru.md)

# ioc-triage

**Check a whole batch of IOCs with one command**

IP · domains · URLs · MD5 / SHA1 / SHA256 → VirusTotal, AbuseIPDB, Kaspersky OpenTIP, URLhaus, ThreatFox, MalwareBazaar

[![tests](https://github.com/AlbedoGown/ioc-triage/actions/workflows/tests.yml/badge.svg)](https://github.com/AlbedoGown/ioc-triage/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
[![license](https://img.shields.io/badge/license-MIT-green)](https://github.com/AlbedoGown/ioc-triage/blob/main/LICENSE)

</div>

---

You know the drill: an alert, a log or a threat intel report drops thirty IPs and hashes on you, and you paste them into a browser one by one. It's slow, it's boring, and by the twentieth indicator your eyes glaze over.

`ioc-triage` takes the whole list in one go. It figures out which line is an IP, a domain or a hash, then asks the right sources about each one through their official APIs. No scraping of web interfaces, just honest API calls with your own keys.

## What it does

- **Detects the type for you.** IP, domain, URL, MD5, SHA1, SHA256: no hints needed.
- **Six sources.** All through official APIs, each in its own module behind a common interface.
- **Internal addresses stay internal.** RFC1918, CGNAT, link-local and loopback are flagged as internal right away, without a single outbound request.
- **Runs in parallel without upsetting the APIs.** Sources are queried at the same time, each with its own pacing (free VirusTotal gives you 4 requests a minute). If you hit a limit and get a 429, the tool tells you so.
- **Remembers what it already checked.** Results stay in a local cache for 24 hours, so re-running the same indicators doesn't burn your quota. Network errors never get cached.
- **One flaky source won't take it down.** A missing key, a dropped connection or a rejected key is just a row in the results, not a traceback halfway through.
- **Talks to humans and scripts.** A table in the terminal, `--output csv` or `--output json`.
- **Zero dependencies.** Python standard library only, installs in seconds.

## Sources

| Source | Checks | Key | Free tier |
|---|---|---|---|
| [VirusTotal](https://www.virustotal.com/) API v3 | hashes, URLs, domains, IPs | `VT_API_KEY` | 4 requests a minute, 500 a day |
| [AbuseIPDB](https://www.abuseipdb.com/) API v2 | IPs | `ABUSEIPDB_API_KEY` | 1000 checks a day |
| [Kaspersky OpenTIP](https://opentip.kaspersky.com/) | hashes, URLs, domains, IPs | `OPENTIP_API_KEY` | not published |
| [MalwareBazaar](https://bazaar.abuse.ch/) | hashes | `ABUSECH_AUTH_KEY` | not stated |
| [URLhaus](https://urlhaus.abuse.ch/) | URLs, plus IPs and domains as a fallback | `ABUSECH_AUTH_KEY` | not stated |
| [ThreatFox](https://threatfox.abuse.ch/) | IPs, domains | `ABUSECH_AUTH_KEY` | not stated |

All keys are free. If a key is missing, the run doesn't break: that source is simply reported as skipped.

## Quick start

```bash
git clone https://github.com/AlbedoGown/ioc-triage.git
cd ioc-triage
pip install -e .

cp .env.example .env          # put your keys here

echo "8.8.8.8" | ioc-triage
```

A `.env` in the current directory is picked up automatically. If your keys live somewhere else, point to the file with `--env-file`. Variables already set in the environment win over the file.

## Usage

```bash
# one indicator per line
ioc-triage --input iocs.txt

# CSV: tell it which column holds the indicator
ioc-triage --input alerts.csv --column src_ip

# via stdin, e.g. every unique IP from a firewall log
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' firewall.log | sort -u | ioc-triage

# structured output for further processing
ioc-triage --input iocs.txt --output json > result.json
ioc-triage --input iocs.txt --output csv  > result.csv

# cache: your own lifetime, or none at all
ioc-triage --input iocs.txt --cache-ttl 6
ioc-triage --input iocs.txt --no-cache

# keys from a specific file and fewer parallel requests
ioc-triage --input iocs.txt --env-file ~/secrets/ioc.env --workers 2
```

The cache lives in `~/.cache/ioc-triage/cache.json` and only you can read it. It stores real answers from the sources, "not found" included. Errors, skipped sources and rate-limit responses never go in.

You can tune the pause for each source with `VT_RATE_LIMIT_PER_MIN`, `OPENTIP_RATE_LIMIT_PER_MIN`, `ABUSEIPDB_RATE_LIMIT_PER_MIN` and `ABUSECH_RATE_LIMIT_PER_MIN`. An empty value means no pause; VT defaults to 4.

### What's in the results

One row for every indicator and source pair. The fields are the same everywhere: table columns, CSV columns and JSON keys.

| Field | What it holds |
|---|---|
| `indicator`, `indicator_type` | the indicator and its type |
| `source` | `virustotal`, `abuseipdb`, `opentip`, `abuse.ch/...`, or `local` for internal addresses |
| `detections` | how many engines fired (VT), confidence and report count (AbuseIPDB), malware family (abuse.ch), detection names (OpenTIP) |
| `first_seen` | when the indicator was first spotted, if the source knows |
| `context` | tags, country, provider and other details from the source |
| `verdict` | the conclusion, or why the source was skipped or didn't answer |

The tool never fills in the blanks: a field only holds what the source actually returned. If a source has no such field, it stays empty (`null` in JSON).

## Getting API keys

<details>
<summary><b>VirusTotal</b></summary>

1. Sign up at https://www.virustotal.com/
2. Grab your key at https://www.virustotal.com/gui/my-apikey and put it into `VT_API_KEY`.

The free key gives you just 4 requests a minute, so the tool waits 15 seconds between requests and says so on stderr. A hundred indicators take about 25 minutes: a good moment for a coffee. With a premium key, raise the limit via `VT_RATE_LIMIT_PER_MIN`.

How the verdict works: 3 or more engines means "malicious", 1 or 2 means "suspicious". A single detection on a popular domain is almost always a false positive, which is why the threshold isn't one. Change it with `VT_MALICIOUS_THRESHOLD`.

</details>

<details>
<summary><b>AbuseIPDB</b></summary>

1. Sign up at https://www.abuseipdb.com/
2. Create a key at https://www.abuseipdb.com/account/api and put it into `ABUSEIPDB_API_KEY`.

Reports from the last 90 days count. Confidence of 75% or more means "malicious", 25% or more means "suspicious".

</details>

<details>
<summary><b>Kaspersky OpenTIP</b></summary>

1. Sign up at https://opentip.kaspersky.com/ and accept the terms.
2. Create a key at https://opentip.kaspersky.com/token/ and put it into `OPENTIP_API_KEY`.

The verdict comes from the `Zone` field: Red is "malicious", Orange and Yellow are "suspicious", Green is "looks legitimate", Grey is "no data".

A few things to know:
- Kaspersky doesn't publish its limits, so set your own pacing with `OPENTIP_RATE_LIMIT_PER_MIN`.
- HTTP 403 can mean either a bad key or a used-up quota.
- The tool only makes reputation lookups and never uploads files to the cloud.
- URL indicators travel as a query parameter, so they may end up in the service's logs. Keep that in mind for sensitive URLs.

</details>

<details>
<summary><b>abuse.ch</b> (URLhaus, ThreatFox, MalwareBazaar)</summary>

Since 2024 the abuse.ch APIs answer `401 Unauthorized` without a key. The good news: one key covers all three services.

1. Sign in at https://auth.abuse.ch/ with GitHub, Google or LinkedIn.
2. Click "Generate Key" in your profile and put the key into `ABUSECH_AUTH_KEY`.

| Type | Where the query goes |
|---|---|
| MD5 / SHA1 / SHA256 | MalwareBazaar `get_info` |
| URL | URLhaus `/v1/url/` |
| IP / domain | ThreatFox `search_ioc`, and if nothing turns up, URLhaus `/v1/host/` |

ThreatFox has a catch: it searches by substring, so `google.com` happily "matches" something like `proxy.google.com`. That's why only exact matches count. The one exception: `ip:port` entries do count for a bare IP.

</details>

## How it's built

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

Every source is a module with a `check(indicator, indicator_type) -> Verdict` function. Want to add one? One file plus one line in `SOURCES_BY_TYPE` in `cli.py`, and you're done.

## Development

```bash
python -m unittest discover -s tests -v
```

Tests mock HTTP responses and never touch the network, so you don't need any keys to run them.

## Disclaimer

This is an educational and portfolio project. The tool brings public reputation data together in one place, but it doesn't replace incident analysis and doesn't vouch for the accuracy of third-party verdicts. And please respect each API's terms of use.

## License

[MIT](https://github.com/AlbedoGown/ioc-triage/blob/main/LICENSE) © 2026 AlbedoGown
