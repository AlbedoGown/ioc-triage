import argparse
import os
import sys
import threading
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Optional

from ioc_triage.cache import DEFAULT_TTL_SECONDS, Cache
from ioc_triage.detect import detect_type, is_private_ip
from ioc_triage.envfile import load_env_file
from ioc_triage.output import render
from ioc_triage.sources import Verdict
from ioc_triage.sources import abusech, virustotal, abuseipdb, opentip

CheckFn = Callable[[str, str], Verdict]

SOURCES_BY_TYPE: dict[str, list[CheckFn]] = {
    "ip": [abuseipdb.check, virustotal.check, opentip.check, abusech.check],
    "domain": [virustotal.check, opentip.check, abusech.check],
    "url": [virustotal.check, opentip.check, abusech.check],
    "md5": [virustotal.check, opentip.check, abusech.check],
    "sha1": [virustotal.check, opentip.check, abusech.check],
    "sha256": [virustotal.check, opentip.check, abusech.check],
}

DEFAULT_WORKERS_PER_SOURCE = 4


def read_indicators(args: argparse.Namespace) -> list[str]:
    if args.input:
        with open(args.input, newline="") as f:
            if args.column:
                import csv

                reader = csv.DictReader(f)
                return [row[args.column].strip() for row in reader if row.get(args.column)]
            return [line.strip() for line in f if line.strip()]
    return [line.strip() for line in sys.stdin if line.strip()]


def source_name(check_fn: CheckFn) -> str:
    return check_fn.__module__.rsplit(".", 1)[-1]


def cache_key(check_fn: CheckFn, indicator: str, indicator_type: str) -> str:
    # Регистр важен только в URL (путь и параметры), остальное нормализуем.
    value = indicator if indicator_type == "url" else indicator.lower()
    return f"{source_name(check_fn)}:{indicator_type}:{value}"


def local_verdict(indicator: str, indicator_type: str) -> Optional[Verdict]:
    """Вердикт без обращения к источникам: внутренний адрес или неизвестный тип."""
    if indicator_type == "ip" and is_private_ip(indicator):
        return Verdict(indicator, "ip", "local", verdict="внутренний адрес, проверка не имеет смысла")
    if indicator_type == "unknown":
        return Verdict(indicator, "unknown", "-", verdict="не удалось определить тип")
    return None


def format_duration(seconds: float) -> str:
    if seconds < 90:
        return f"{round(seconds)} с"
    return f"{round(seconds / 60)} мин"


def announce_rate_limits(requests_by_source: Counter) -> None:
    """Одна строка на источник с лимитом: сколько запросов и сколько примерно ждать."""
    for check_fn, count in requests_by_source.items():
        limiter = getattr(sys.modules.get(check_fn.__module__), "limiter", None)
        if limiter is None:
            continue
        seconds = limiter.estimate(count)
        if seconds >= 1:
            print(
                f"{limiter.name}: {count} запросов при лимите {limiter.per_min():g} в минуту, "
                f"это займет около {format_duration(seconds)}",
                file=sys.stderr,
            )


class Progress:
    """Строка «готово k из n» в stderr, только если stderr это терминал."""

    def __init__(self, total: int):
        self.total = total
        self.done = 0
        self.enabled = total > 0 and sys.stderr.isatty()
        self._lock = threading.Lock()

    def tick(self, _future: Future) -> None:
        with self._lock:
            self.done += 1
            if self.enabled:
                sys.stderr.write(f"\rготово {self.done} из {self.total}")
                sys.stderr.flush()

    def clear(self) -> None:
        if self.enabled:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()


def check_indicators(
    indicators: list[str],
    cache: Optional[Cache] = None,
    workers_per_source: int = DEFAULT_WORKERS_PER_SOURCE,
) -> list[Verdict]:
    """Проверяет индикаторы: источники работают параллельно, у каждого свой пул и свой лимит.

    Порядок результата совпадает с порядком входа и источников в SOURCES_BY_TYPE.
    """
    executors: dict[CheckFn, ThreadPoolExecutor] = {}
    pending: dict[str, Future] = {}
    slots: list[Verdict | tuple[str, Future]] = []
    requests_by_source: Counter = Counter()
    cache_hits = 0
    interrupted = False
    progress: Optional[Progress] = None

    try:
        for indicator in indicators:
            indicator_type = detect_type(indicator)
            local = local_verdict(indicator, indicator_type)
            if local:
                slots.append(local)
                continue

            for check_fn in SOURCES_BY_TYPE.get(indicator_type, []):
                key = cache_key(check_fn, indicator, indicator_type)
                cached = cache.get(key) if cache else None
                if cached is not None:
                    cache_hits += 1
                    slots.append(Verdict(**{**cached, "indicator": indicator}))
                    continue
                if key not in pending:
                    if check_fn not in executors:
                        executors[check_fn] = ThreadPoolExecutor(
                            max_workers=workers_per_source, thread_name_prefix=source_name(check_fn)
                        )
                    pending[key] = executors[check_fn].submit(check_fn, indicator, indicator_type)
                    requests_by_source[check_fn] += 1
                slots.append((key, pending[key]))

        announce_rate_limits(requests_by_source)
        progress = Progress(len(pending))
        for future in pending.values():
            future.add_done_callback(progress.tick)

        results = []
        stored = set()
        for slot in slots:
            if isinstance(slot, Verdict):
                results.append(slot)
                continue
            key, future = slot
            verdict = future.result()
            if cache and verdict.cacheable and key not in stored:
                cache.set(key, verdict.to_dict())
                stored.add(key)
            results.append(verdict)
    except KeyboardInterrupt:
        interrupted = True
        raise
    finally:
        if progress:
            progress.clear()
        # При Ctrl+C не ждем потоки, которые спят в паузе под лимит.
        for executor in executors.values():
            executor.shutdown(wait=not interrupted, cancel_futures=True)

    if cache_hits:
        print(f"Из кэша: {cache_hits}", file=sys.stderr)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Пакетная проверка индикаторов компрометации")
    parser.add_argument("--input", help="файл со списком индикаторов или CSV")
    parser.add_argument("--column", help="имя столбца в CSV с индикатором")
    parser.add_argument("--output", choices=["table", "csv", "json"], default="table")
    parser.add_argument("--env-file", help="файл с ключами (по умолчанию .env в текущей папке, если есть)")
    parser.add_argument("--no-cache", action="store_true", help="не читать и не писать кэш")
    parser.add_argument(
        "--cache-ttl",
        type=float,
        default=DEFAULT_TTL_SECONDS / 3600,
        metavar="HOURS",
        help="срок жизни записей кэша в часах (по умолчанию 24)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS_PER_SOURCE,
        help=f"параллельных запросов на один источник (по умолчанию {DEFAULT_WORKERS_PER_SOURCE})",
    )
    args = parser.parse_args()

    if args.env_file:
        if not Path(args.env_file).is_file():
            parser.error(f"файл не найден: {args.env_file}")
        load_env_file(Path(args.env_file))
    else:
        load_env_file(Path(".env"))

    if args.workers < 1:
        parser.error("--workers должен быть не меньше 1")

    cache = None if args.no_cache else Cache(ttl=int(args.cache_ttl * 3600))
    indicators = read_indicators(args)
    try:
        verdicts = check_indicators(indicators, cache=cache, workers_per_source=args.workers)
    except KeyboardInterrupt:
        # os._exit не ждет рабочие потоки (пауза под лимит или запрос в сети), иначе Ctrl+C
        # срабатывал бы только после них. Кэш пишется атомарно, прерывание его не портит.
        print("\nПрервано.", file=sys.stderr)
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(130)

    if not verdicts:
        print("Нет результатов.", file=sys.stderr)
        return

    render(verdicts, args.output)


if __name__ == "__main__":
    main()
