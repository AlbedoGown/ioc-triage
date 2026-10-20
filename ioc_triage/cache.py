import json
import time
from pathlib import Path
from typing import Optional

DEFAULT_CACHE_PATH = Path.home() / ".cache" / "ioc-triage" / "cache.json"
DEFAULT_TTL_SECONDS = 24 * 60 * 60


class Cache:
    def __init__(self, path: Path = DEFAULT_CACHE_PATH, ttl: int = DEFAULT_TTL_SECONDS):
        self.path = path
        self.ttl = ttl
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data = self._load()

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text())

    def get(self, key: str) -> Optional[dict]:
        entry = self._data.get(key)
        if not entry:
            return None
        if time.time() - entry["timestamp"] > self.ttl:
            return None
        return entry["value"]

    def set(self, key: str, value: dict) -> None:
        self._data[key] = {"timestamp": time.time(), "value": value}
        self.path.write_text(json.dumps(self._data))
