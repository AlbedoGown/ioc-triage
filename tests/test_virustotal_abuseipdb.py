"""Тесты VirusTotal и AbuseIPDB. HTTP мокается, живых запросов нет."""

import base64
import io
import json
import os
import unittest
import urllib.error
from unittest import mock

from ioc_triage.sources import abuseipdb, virustotal

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _fake_response(payload: dict):
    resp = mock.MagicMock()
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    resp.__enter__.return_value = resp
    return resp


def _http_error(code: int):
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(b""))


class VirusTotalTestCase(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ, {virustotal.API_KEY_ENV: "vt-key", virustotal.RATE_LIMIT_ENV: "4"})
        env.start()
        self.addCleanup(env.stop)
        virustotal._last_request_at = None
        self.sleep = mock.patch("time.sleep").start()
        self.addCleanup(mock.patch.stopall)

    def _patch_urlopen(self, *responses):
        return mock.patch("urllib.request.urlopen", side_effect=list(responses)).start()


class VirusTotalTests(VirusTotalTestCase):
    def test_no_key(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            urlopen = self._patch_urlopen()
            v = virustotal.check(EICAR_SHA256, "sha256")
        urlopen.assert_not_called()
        self.assertEqual(v.verdict, "пропущено (нет VT_API_KEY)")

    def test_file_malicious(self):
        urlopen = self._patch_urlopen(
            _fake_response(
                {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {"malicious": 60, "suspicious": 1, "undetected": 10, "harmless": 0},
                            "first_submission_date": 1148301722,
                            "popular_threat_classification": {"suggested_threat_label": "virus.eicar/test"},
                            "tags": ["text", "attachment"],
                        }
                    }
                }
            )
        )
        v = virustotal.check(EICAR_SHA256, "sha256")

        self.assertEqual(v.detections, "60/71")
        self.assertEqual(v.first_seen, "2006-05-22")
        self.assertEqual(v.verdict, "вредоносный (virus.eicar/test)")
        self.assertEqual(v.context, "virus.eicar/test; suspicious=1; text, attachment")

        req = urlopen.call_args.args[0]
        self.assertEqual(req.full_url, f"{virustotal.API_BASE}/files/{EICAR_SHA256}")
        self.assertEqual(req.get_header("X-apikey"), "vt-key")

    def test_url_id_is_base64url_without_padding(self):
        url = "http://example.com/a?b=1"
        urlopen = self._patch_urlopen(
            _fake_response({"data": {"attributes": {"last_analysis_stats": {"harmless": 70, "undetected": 20}}}})
        )
        v = virustotal.check(url, "url")
        expected_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        self.assertEqual(urlopen.call_args.args[0].full_url, f"{virustotal.API_BASE}/urls/{expected_id}")
        self.assertEqual(v.verdict, "похоже на легитимный")
        self.assertEqual(v.detections, "0/90")

    def test_domain_has_no_first_seen(self):
        self._patch_urlopen(
            _fake_response(
                {"data": {"attributes": {"last_analysis_stats": {"suspicious": 2, "harmless": 60}, "reputation": -5}}}
            )
        )
        v = virustotal.check("example.com", "domain")
        self.assertIsNone(v.first_seen)
        self.assertEqual(v.verdict, "подозрительный")
        self.assertEqual(v.context, "suspicious=2; reputation=-5")

    def test_not_found(self):
        self._patch_urlopen(_http_error(404))
        v = virustotal.check(EICAR_SHA256, "sha256")
        self.assertEqual(v.verdict, "не найден в VirusTotal")

    def test_quota_exceeded(self):
        self._patch_urlopen(_http_error(429))
        v = virustotal.check("8.8.8.8", "ip")
        self.assertIn("429", v.verdict)

    def test_network_error(self):
        self._patch_urlopen(urllib.error.URLError("connection refused"))
        v = virustotal.check("8.8.8.8", "ip")
        self.assertTrue(v.verdict.startswith("ошибка сети"), v.verdict)


class VirusTotalRateLimitTests(VirusTotalTestCase):
    def test_second_request_waits_for_slot(self):
        ok = {"data": {"attributes": {"last_analysis_stats": {"harmless": 1}}}}
        self._patch_urlopen(_fake_response(ok), _fake_response(ok))
        with mock.patch("time.monotonic", side_effect=[100.0, 103.0, 115.0]):
            virustotal.check("8.8.8.8", "ip")
            virustotal.check("1.1.1.1", "ip")
        self.sleep.assert_called_once()
        self.assertAlmostEqual(self.sleep.call_args.args[0], 12.0)

    def test_no_wait_when_interval_passed(self):
        ok = {"data": {"attributes": {"last_analysis_stats": {"harmless": 1}}}}
        self._patch_urlopen(_fake_response(ok), _fake_response(ok))
        with mock.patch("time.monotonic", side_effect=[100.0, 120.0]):
            virustotal.check("8.8.8.8", "ip")
            virustotal.check("1.1.1.1", "ip")
        self.sleep.assert_not_called()


class AbuseIPDBTests(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ, {abuseipdb.API_KEY_ENV: "aipdb-key"})
        env.start()
        self.addCleanup(env.stop)

    def _patch_urlopen(self, *responses):
        patcher = mock.patch("urllib.request.urlopen", side_effect=list(responses))
        self.addCleanup(patcher.stop)
        return patcher.start()

    def test_no_key(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            v = abuseipdb.check("8.8.8.8", "ip")
        self.assertEqual(v.verdict, "пропущено (нет ABUSEIPDB_API_KEY)")

    def test_malicious_ip(self):
        urlopen = self._patch_urlopen(
            _fake_response(
                {
                    "data": {
                        "ipAddress": "185.220.101.1",
                        "abuseConfidenceScore": 100,
                        "totalReports": 1520,
                        "lastReportedAt": "2026-10-19T21:00:00+00:00",
                        "countryCode": "DE",
                        "isp": "Example Hosting",
                        "usageType": "Data Center/Web Hosting/Transit",
                        "isTor": True,
                    }
                }
            )
        )
        v = abuseipdb.check("185.220.101.1", "ip")

        self.assertEqual(v.verdict, "вредоносный")
        self.assertEqual(v.detections, "100% (1520 жалоб)")
        self.assertIsNone(v.first_seen)
        self.assertEqual(
            v.context, "последняя жалоба 2026-10-19; DE; Example Hosting; Data Center/Web Hosting/Transit; Tor"
        )

        req = urlopen.call_args.args[0]
        self.assertIn("ipAddress=185.220.101.1", req.full_url)
        self.assertIn("maxAgeInDays=90", req.full_url)
        self.assertEqual(req.get_header("Key"), "aipdb-key")

    def test_clean_ip(self):
        self._patch_urlopen(_fake_response({"data": {"abuseConfidenceScore": 0, "totalReports": 0, "isWhitelisted": True}}))
        v = abuseipdb.check("8.8.8.8", "ip")
        self.assertEqual(v.verdict, "нет жалоб за 90 дней")
        self.assertEqual(v.context, "в whitelist AbuseIPDB")

    def test_low_and_suspicious_thresholds(self):
        self._patch_urlopen(
            _fake_response({"data": {"abuseConfidenceScore": 10, "totalReports": 2}}),
            _fake_response({"data": {"abuseConfidenceScore": 40, "totalReports": 9}}),
        )
        self.assertEqual(abuseipdb.check("1.2.3.4", "ip").verdict, "низкий риск")
        self.assertEqual(abuseipdb.check("1.2.3.4", "ip").verdict, "подозрительный")

    def test_rate_limited(self):
        self._patch_urlopen(_http_error(429))
        self.assertIn("429", abuseipdb.check("1.2.3.4", "ip").verdict)

    def test_network_error(self):
        self._patch_urlopen(TimeoutError("timed out"))
        self.assertTrue(abuseipdb.check("1.2.3.4", "ip").verdict.startswith("ошибка сети"))

    def test_non_ip_rejected(self):
        with self.assertRaises(ValueError):
            abuseipdb.check("example.com", "domain")


if __name__ == "__main__":
    unittest.main()
