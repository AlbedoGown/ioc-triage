import os

from ioc_triage.sources import Verdict

API_KEY_ENV = "VT_API_KEY"


def check(indicator: str, indicator_type: str) -> Verdict:
    if not os.environ.get(API_KEY_ENV):
        return Verdict(indicator, indicator_type, "virustotal", verdict="пропущено (нет VT_API_KEY)")
    raise NotImplementedError("free tier: 4 запроса/мин, учесть rate-limit")
