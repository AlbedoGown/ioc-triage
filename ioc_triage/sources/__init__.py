from dataclasses import dataclass
from typing import Optional


@dataclass
class Verdict:
    indicator: str
    indicator_type: str
    source: str
    detections: Optional[str] = None
    first_seen: Optional[str] = None
    context: Optional[str] = None
    verdict: str = "неизвестно"
