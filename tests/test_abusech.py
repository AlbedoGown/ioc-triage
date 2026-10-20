"""Тесты источника abuse.ch. HTTP мокается, живых запросов нет."""

import io
import json
import os
import unittest
import urllib.error
from unittest import mock

from ioc_triage.sources import abusech

SHA256 = "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d"


def _fake_response(payload: dict):
    resp = mock.MagicMock()
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    resp.__enter__.return_value = resp
    return resp


class AbuseChTestCase(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {abusech.API_KEY_ENV: "test-key"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _patch_urlopen(self, *responses):
        patcher = mock.patch("urllib.request.urlopen", side_effect=list(responses))
        urlopen = patcher.start()
        self.addCleanup(patcher.stop)
        return urlopen


class NoKeyTests(unittest.TestCase):
    def test_no_key_skips_without_request(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("urllib.request.urlopen") as urlopen:
            v = abusech.check(SHA256, "sha256")
        urlopen.assert_not_called()
        self.assertIn("нет ABUSECH_AUTH_KEY", v.verdict)
        self.assertEqual(v.source, "abuse.ch/MalwareBazaar")


class MalwareBazaarTests(AbuseChTestCase):
    def test_hash_found(self):
        urlopen = self._patch_urlopen(
            _fake_response(
                {
                    "query_status": "ok",
                    "data": [
                        {
                            "sha256_hash": SHA256,
                            "first_seen": "2024-03-01 10:00:00",
                            "signature": "AgentTesla",
                            "file_name": "invoice.exe",
                            "tags": ["exe", "AgentTesla"],
                        }
                    ],
                }
            )
        )
        v = abusech.check(SHA256, "sha256")

        self.assertEqual(v.verdict, "вредоносный (AgentTesla)")
        self.assertEqual(v.detections, "AgentTesla")
        self.assertEqual(v.first_seen, "2024-03-01 10:00:00")
        self.assertEqual(v.context, "exe, AgentTesla")

        req = urlopen.call_args.args[0]
        self.assertEqual(req.full_url, abusech.MALWAREBAZAAR_URL)
        self.assertEqual(req.get_header("Auth-key"), "test-key")
        self.assertIn(b"query=get_info", req.data)

    def test_hash_not_found(self):
        self._patch_urlopen(_fake_response({"query_status": "hash_not_found"}))
        v = abusech.check(SHA256, "sha256")
        self.assertEqual(v.verdict, "не найден в MalwareBazaar")
        self.assertIsNone(v.detections)
        self.assertTrue(v.cacheable)

    def test_unknown_status_is_not_cached(self):
        self._patch_urlopen(_fake_response({"query_status": "server_busy"}))
        v = abusech.check(SHA256, "sha256")
        self.assertIn("вернул статус", v.verdict)
        self.assertFalse(v.cacheable)


class UrlhausTests(AbuseChTestCase):
    def test_url_found(self):
        self._patch_urlopen(
            _fake_response(
                {
                    "query_status": "ok",
                    "url_status": "online",
                    "threat": "malware_download",
                    "date_added": "2024-05-02 12:00:00 UTC",
                    "tags": ["elf", "mozi"],
                }
            )
        )
        v = abusech.check("http://1.2.3.4/bin.sh", "url")
        self.assertEqual(v.source, "abuse.ch/URLhaus")
        self.assertEqual(v.verdict, "вредоносный URL (malware_download, online)")
        self.assertEqual(v.first_seen, "2024-05-02 12:00:00 UTC")
        self.assertEqual(v.context, "elf, mozi")

    def test_url_not_found(self):
        self._patch_urlopen(_fake_response({"query_status": "no_results"}))
        v = abusech.check("https://example.com/", "url")
        self.assertEqual(v.verdict, "не найден в URLhaus")


class HostTests(AbuseChTestCase):
    def test_threatfox_hit(self):
        urlopen = self._patch_urlopen(
            _fake_response(
                {
                    "query_status": "ok",
                    "data": [
                        {
                            "ioc": "evil.example:443",
                            "threat_type": "botnet_cc",
                            "malware_printable": "Cobalt Strike",
                            "first_seen": "2024-06-01 08:00:00 UTC",
                            "confidence_level": 100,
                            "tags": ["c2"],
                        }
                    ],
                }
            )
        )
        v = abusech.check("evil.example", "domain")
        self.assertEqual(v.source, "abuse.ch/ThreatFox")
        self.assertEqual(v.verdict, "вредоносный (Cobalt Strike)")
        self.assertEqual(v.detections, "Cobalt Strike (botnet_cc)")
        self.assertEqual(v.context, "ioc=evil.example:443; confidence=100; c2")
        self.assertEqual(urlopen.call_count, 1)

        req = urlopen.call_args.args[0]
        self.assertEqual(json.loads(req.data), {"query": "search_ioc", "search_term": "evil.example"})

    def test_threatfox_miss_falls_back_to_urlhaus_host(self):
        urlopen = self._patch_urlopen(
            _fake_response({"query_status": "no_result"}),
            _fake_response(
                {
                    "query_status": "ok",
                    "firstseen": "2023-01-01 00:00:00 UTC",
                    "blacklists": {"spamhaus_dbl": "not listed"},
                    "urls": [{"url_status": "online"}, {"url_status": "offline"}],
                }
            ),
        )
        v = abusech.check("8.8.4.4", "ip")
        self.assertEqual(urlopen.call_count, 2)
        self.assertEqual(v.source, "abuse.ch/URLhaus")
        self.assertEqual(v.detections, "1/2 активных URL")
        self.assertEqual(v.first_seen, "2023-01-01 00:00:00 UTC")

    def test_threatfox_substring_hits_are_ignored(self):
        self._patch_urlopen(
            _fake_response(
                {
                    "query_status": "ok",
                    "data": [
                        {
                            "ioc": "google-proxy-66-249-88-66.google.com",
                            "threat_type": "payload_delivery",
                            "malware_printable": "php.shin_webshell",
                        }
                    ],
                }
            ),
            _fake_response({"query_status": "no_results"}),
        )
        v = abusech.check("google.com", "domain")
        self.assertEqual(v.verdict, "не найден в ThreatFox")
        self.assertIsNone(v.detections)

    def test_threatfox_ip_port_matches_bare_ip(self):
        self._patch_urlopen(
            _fake_response(
                {
                    "query_status": "ok",
                    "data": [
                        {"ioc": "11.22.33.444:8080", "malware_printable": "Other"},
                        {"ioc": "11.22.33.44:443", "threat_type": "botnet_cc", "malware_printable": "Cobalt Strike"},
                    ],
                }
            )
        )
        v = abusech.check("11.22.33.44", "ip")
        self.assertEqual(v.verdict, "вредоносный (Cobalt Strike)")
        self.assertIn("ioc=11.22.33.44:443", v.context)

    def test_not_found_anywhere(self):
        self._patch_urlopen(
            _fake_response({"query_status": "no_result"}),
            _fake_response({"query_status": "no_results"}),
        )
        v = abusech.check("example.com", "domain")
        self.assertEqual(v.source, "abuse.ch/ThreatFox")
        self.assertEqual(v.verdict, "не найден в ThreatFox")


class ErrorTests(AbuseChTestCase):
    def test_network_error_is_not_raised(self):
        self._patch_urlopen(urllib.error.URLError("Name or service not known"))
        v = abusech.check(SHA256, "sha256")
        self.assertTrue(v.verdict.startswith("ошибка сети"), v.verdict)
        self.assertFalse(v.cacheable)

    def test_timeout_is_not_raised(self):
        self._patch_urlopen(TimeoutError("timed out"))
        v = abusech.check("http://x.example/a", "url")
        self.assertTrue(v.verdict.startswith("ошибка сети"), v.verdict)

    def test_unauthorized(self):
        err = urllib.error.HTTPError(abusech.URLHAUS_URL, 401, "Unauthorized", {}, io.BytesIO(b""))
        self._patch_urlopen(err)
        v = abusech.check("http://x.example/a", "url")
        self.assertIn("HTTP 401", v.verdict)
        self.assertIn("ABUSECH_AUTH_KEY", v.verdict)

    def test_rate_limited(self):
        err = urllib.error.HTTPError(abusech.THREATFOX_URL, 429, "Too Many Requests", {}, io.BytesIO(b""))
        self._patch_urlopen(err)
        v = abusech.check("evil.example", "domain")
        self.assertIn("429", v.verdict)

    def test_invalid_json(self):
        resp = mock.MagicMock()
        resp.read.return_value = b"<html>oops</html>"
        resp.__enter__.return_value = resp
        self._patch_urlopen(resp)
        v = abusech.check(SHA256, "sha256")
        self.assertTrue(v.verdict.startswith("ошибка разбора ответа"), v.verdict)


if __name__ == "__main__":
    unittest.main()
