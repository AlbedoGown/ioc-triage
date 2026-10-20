"""Потокобезопасный ограничитель частоты запросов: не чаще N в минуту на источник."""

import os
import threading
import time


class RateLimiter:
    def __init__(self, name: str, env_var: str, default_per_min: float):
        self.name = name
        self.env_var = env_var
        self.default_per_min = default_per_min
        self.next_slot: float | None = None
        self._lock = threading.Lock()

    def per_min(self) -> float:
        try:
            return float(os.environ.get(self.env_var) or self.default_per_min)
        except ValueError:
            return float(self.default_per_min)

    def interval(self) -> float:
        per_min = self.per_min()
        return 60.0 / per_min if per_min > 0 else 0.0

    def estimate(self, requests: int) -> float:
        """Сколько секунд займут requests запросов подряд с учетом паузы."""
        return max(requests - 1, 0) * self.interval()

    def wait(self) -> None:
        """Резервирует ближайший свободный слот и спит до него (вне блокировки)."""
        with self._lock:
            now = time.monotonic()
            slot = now if self.next_slot is None else max(now, self.next_slot)
            self.next_slot = slot + self.interval()
        delay = slot - now
        if delay > 0:
            time.sleep(delay)
