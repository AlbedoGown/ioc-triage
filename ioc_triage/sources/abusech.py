from ioc_triage.sources import Verdict

# URLhaus, ThreatFox, MalwareBazaar — открытые API abuse.ch, ключ не нужен.
# https://urlhaus-api.abuse.ch/ | https://threatfox.abuse.ch/api/ | https://bazaar.abuse.ch/api/


def check(indicator: str, indicator_type: str) -> Verdict:
    raise NotImplementedError("MVP: реализовать первым, источники без ключа")
