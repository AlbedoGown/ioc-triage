from dataclasses import dataclass, field
from typing import Optional

PUBLIC_FIELDS = ("indicator", "indicator_type", "source", "detections", "first_seen", "context", "verdict")


@dataclass
class Verdict:
    indicator: str
    indicator_type: str
    source: str
    detections: Optional[str] = None
    first_seen: Optional[str] = None
    context: Optional[str] = None
    verdict: str = "неизвестно"
    # True только для настоящего ответа источника; ошибки и «пропущено» не кэшируются.
    cacheable: bool = field(default=False, repr=False, compare=False)

    def to_dict(self) -> dict:
        return {name: getattr(self, name) for name in PUBLIC_FIELDS}
