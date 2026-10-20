import os

from ioc_triage.sources import Verdict

API_KEY_ENV = "ABUSEIPDB_API_KEY"


def check(indicator: str, indicator_type: str) -> Verdict:
    if indicator_type != "ip":
        raise ValueError("abuseipdb проверяет только IP")
    if not os.environ.get(API_KEY_ENV):
        return Verdict(indicator, indicator_type, "abuseipdb", verdict="пропущено (нет ABUSEIPDB_API_KEY)")
    raise NotImplementedError
