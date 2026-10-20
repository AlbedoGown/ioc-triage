"""Тесты кэша, загрузки .env, лимитера и параллельной проверки в cli."""

import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from ioc_triage import cli
from ioc_triage.cache import Cache
from ioc_triage.envfile import load_env_file, parse_env
from ioc_triage.sources import Verdict
from ioc_triage.sources.ratelimit import RateLimiter


class TempDirTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)


class CacheTests(TempDirTestCase):
    def test_roundtrip_and_persistence(self):
        Cache(self.tmp / "c.json").set("k", {"a": 1})
        self.assertEqual(Cache(self.tmp / "c.json").get("k"), {"a": 1})

    def test_expired_entry_is_ignored(self):
        cache = Cache(self.tmp / "c.json", ttl=60)
        with mock.patch("time.time", return_value=1000.0):
            cache.set("k", {"a": 1})
        with mock.patch("time.time", return_value=1061.0):
            self.assertIsNone(cache.get("k"))

    def test_corrupted_file_starts_empty(self):
        path = self.tmp / "c.json"
        path.write_text("{not json")
        cache = Cache(path)
        self.assertIsNone(cache.get("k"))
        cache.set("k", {"a": 1})
        self.assertEqual(json.loads(path.read_text())["k"]["value"], {"a": 1})


class EnvFileTests(TempDirTestCase):
    def test_parse(self):
        text = """
        # комментарий
        VT_API_KEY=abc
        export ABUSECH_AUTH_KEY="with spaces # not a comment"
        ABUSEIPDB_API_KEY='single'
        OPENTIP_API_KEY=tok # trailing comment
        EMPTY=
        not a line
        1BAD=x
        """
        self.assertEqual(
            parse_env(text),
            {
                "VT_API_KEY": "abc",
                "ABUSECH_AUTH_KEY": "with spaces # not a comment",
                "ABUSEIPDB_API_KEY": "single",
                "OPENTIP_API_KEY": "tok",
                "EMPTY": "",
            },
        )

    def test_does_not_override_existing_env(self):
        path = self.tmp / ".env"
        path.write_text("IOC_T_A=from_file\nIOC_T_B=from_file\n")
        with mock.patch.dict(os.environ, {"IOC_T_A": "from_env"}):
            loaded = load_env_file(path)
            self.assertEqual(os.environ["IOC_T_A"], "from_env")
            self.assertEqual(os.environ["IOC_T_B"], "from_file")
        self.assertEqual(loaded, ["IOC_T_B"])

    def test_missing_file_is_ignored(self):
        self.assertEqual(load_env_file(self.tmp / "nope.env"), [])


class RateLimiterTests(unittest.TestCase):
    def test_concurrent_waiters_get_distinct_slots(self):
        limiter = RateLimiter("test", "IOC_T_RATE", 60)  # интервал 1 с
        delays = []
        lock = threading.Lock()

        def fake_sleep(d):
            with lock:
                delays.append(round(d, 3))

        with mock.patch("time.monotonic", return_value=50.0), mock.patch("time.sleep", side_effect=fake_sleep):
            threads = [threading.Thread(target=limiter.wait) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual(sorted(delays), [1.0, 2.0, 3.0])


def _fake_source(name: str, calls: list, verdict_text: str = "чисто", cacheable: bool = True, delay: float = 0.0):
    def check(indicator, indicator_type):
        calls.append((threading.current_thread().name, indicator))
        if delay:
            time.sleep(delay)
        return Verdict(indicator, indicator_type, name, verdict=verdict_text, cacheable=cacheable)

    check.__module__ = f"fake.{name}"
    return check


class CheckIndicatorsTests(TempDirTestCase):
    def _patch_sources(self, mapping):
        patcher = mock.patch.dict(cli.SOURCES_BY_TYPE, mapping, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_order_and_local_verdicts(self):
        calls = []
        a, b = _fake_source("a", calls), _fake_source("b", calls)
        self._patch_sources({"ip": [a, b], "domain": [b]})
        result = cli.check_indicators(["8.8.8.8", "10.0.0.1", "example.com", "???"])
        self.assertEqual(
            [(v.indicator, v.source) for v in result],
            [("8.8.8.8", "a"), ("8.8.8.8", "b"), ("10.0.0.1", "local"), ("example.com", "b"), ("???", "-")],
        )

    def test_sources_run_in_parallel(self):
        calls = []
        slow_a = _fake_source("a", calls, delay=0.3)
        slow_b = _fake_source("b", calls, delay=0.3)
        self._patch_sources({"ip": [slow_a, slow_b]})
        started = time.monotonic()
        cli.check_indicators(["8.8.8.8", "1.1.1.1"], workers_per_source=1)
        elapsed = time.monotonic() - started
        # Последовательно было бы 4 × 0.3 = 1.2 с; параллельно по источникам — около 0.6 с.
        self.assertLess(elapsed, 1.0)
        self.assertEqual({t.split("_")[0] for t, _ in calls}, {"a", "b"})

    def test_duplicates_are_requested_once(self):
        calls = []
        self._patch_sources({"domain": [_fake_source("a", calls)]})
        result = cli.check_indicators(["Example.com", "example.com"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(result), 2)

    def test_cache_hit_skips_request(self):
        calls = []
        self._patch_sources({"domain": [_fake_source("a", calls)]})
        cache = Cache(self.tmp / "c.json")
        cli.check_indicators(["example.com"], cache=cache)
        with mock.patch("sys.stderr"):
            result = cli.check_indicators(["example.com"], cache=cache)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result[0].verdict, "чисто")
        self.assertEqual(result[0].source, "a")

    def test_errors_are_not_cached(self):
        calls = []
        self._patch_sources({"domain": [_fake_source("a", calls, verdict_text="ошибка сети", cacheable=False)]})
        cache = Cache(self.tmp / "c.json")
        cli.check_indicators(["example.com"], cache=cache)
        cli.check_indicators(["example.com"], cache=cache)
        self.assertEqual(len(calls), 2)

    def test_cache_key_keeps_url_case_only(self):
        fn = _fake_source("a", [])
        self.assertEqual(cli.cache_key(fn, "EXAMPLE.com", "domain"), "a:domain:example.com")
        self.assertEqual(cli.cache_key(fn, "http://x.com/A", "url"), "a:url:http://x.com/A")


class MainTests(TempDirTestCase):
    def test_env_file_is_loaded_and_cache_disabled(self):
        env_path = self.tmp / "keys.env"
        env_path.write_text("IOC_T_KEY=loaded\n")
        seen = {}

        def fake_check(indicators, cache, workers_per_source):
            seen["key"] = os.environ.get("IOC_T_KEY")
            seen["cache"] = cache
            return []

        argv = ["ioc-triage", "--env-file", str(env_path), "--no-cache", "--input", str(env_path)]
        with mock.patch.dict(os.environ, {}, clear=False), mock.patch("sys.argv", argv), mock.patch.object(
            cli, "check_indicators", side_effect=fake_check
        ), mock.patch("sys.stderr"):
            os.environ.pop("IOC_T_KEY", None)
            cli.main()
        self.assertEqual(seen, {"key": "loaded", "cache": None})

    def test_missing_env_file_is_an_error(self):
        with mock.patch("sys.argv", ["ioc-triage", "--env-file", str(self.tmp / "nope")]), mock.patch(
            "sys.stderr"
        ), self.assertRaises(SystemExit):
            cli.main()


if __name__ == "__main__":
    unittest.main()
