"""Простой ограничитель частоты запросов: не чаще N в минуту на источник."""

import os
import sys
import time


class RateLimiter:
    def __init__(self, name: str, env_var: str, default_per_min: float):
        self.name = name
        self.env_var = env_var
        self.default_per_min = default_per_min
        self.last_request_at: float | None = None

    def interval(self) -> float:
        try:
            per_min = float(os.environ.get(self.env_var) or self.default_per_min)
        except ValueError:
            per_min = self.default_per_min
        return 60.0 / per_min if per_min > 0 else 0.0

    def wait(self) -> None:
        """Блокирует до момента, когда можно отправить следующий запрос."""
        now = time.monotonic()
        if self.last_request_at is not None:
            delay = self.last_request_at + self.interval() - now
            if delay > 0:
                print(f"{self.name}: ожидание {delay:.0f} с (лимит запросов)", file=sys.stderr)
                time.sleep(delay)
                now = time.monotonic()
        self.last_request_at = now
