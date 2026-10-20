"""Потокобезопасный ограничитель частоты запросов: не чаще N в минуту на источник."""

import os
import sys
import threading
import time


class RateLimiter:
    def __init__(self, name: str, env_var: str, default_per_min: float):
        self.name = name
        self.env_var = env_var
        self.default_per_min = default_per_min
        self.next_slot: float | None = None
        self._lock = threading.Lock()

    def interval(self) -> float:
        try:
            per_min = float(os.environ.get(self.env_var) or self.default_per_min)
        except ValueError:
            per_min = self.default_per_min
        return 60.0 / per_min if per_min > 0 else 0.0

    def wait(self) -> None:
        """Резервирует ближайший свободный слот и спит до него (вне блокировки)."""
        with self._lock:
            now = time.monotonic()
            slot = now if self.next_slot is None else max(now, self.next_slot)
            self.next_slot = slot + self.interval()
        delay = slot - now
        if delay > 0:
            if delay >= 1:
                print(f"{self.name}: ожидание {delay:.0f} с (лимит запросов)", file=sys.stderr)
            time.sleep(delay)
