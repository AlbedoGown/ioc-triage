"""Минимальный загрузчик .env без внешних зависимостей."""

import os
from pathlib import Path


def parse_env(text: str) -> dict[str, str]:
    """Разбирает строки вида KEY=VALUE; поддерживает export, кавычки и комментарии."""
    result = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key.isidentifier():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        else:
            # Комментарий после значения допустим только через пробел: KEY=abc # note
            value = value.split(" #", 1)[0].rstrip()
        result[key] = value
    return result


def load_env_file(path: Path) -> list[str]:
    """Загружает переменные из файла, не перезаписывая уже заданные в окружении.

    Возвращает имена переменных, которые были установлены.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    loaded = []
    for key, value in parse_env(text).items():
        if key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded
