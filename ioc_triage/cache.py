import json
import os
import threading
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
        self._lock = threading.Lock()
        self._data = self._load()

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # Нет файла или он повреждён — начинаем с пустого кэша, а не падаем.
            return {}
        return data if isinstance(data, dict) else {}

    def get(self, key: str) -> Optional[dict]:
        with self._lock:
            entry = self._data.get(key)
        if not entry:
            return None
        if time.time() - entry["timestamp"] > self.ttl:
            return None
        return entry["value"]

    def set(self, key: str, value: dict) -> None:
        with self._lock:
            self._data[key] = {"timestamp": time.time(), "value": value}
            # Пишем во временный файл и подменяем, чтобы прерванная запись не портила кэш.
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, ensure_ascii=False), encoding="utf-8")
            # В кэше лежат проверенные индикаторы — доступ только владельцу.
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
