"""Тесты Kaspersky OpenTIP. HTTP мокается, живых запросов нет."""

import io
import json
import os
import unittest
import urllib.error
from unittest import mock

from ioc_triage.sources import opentip

SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _fake_response(payload: dict):
    resp = mock.MagicMock()
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    resp.__enter__.return_value = resp
    return resp


def _http_error(code: int):
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(b""))


class OpenTipTestCase(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ, {opentip.API_KEY_ENV: "ot-key"})
        env.start()
        self.addCleanup(env.stop)
        opentip.limiter.last_request_at = None
        self.sleep = mock.patch("time.sleep").start()
        self.addCleanup(mock.patch.stopall)

    def _patch_urlopen(self, *responses):
        return mock.patch("urllib.request.urlopen", side_effect=list(responses)).start()


class OpenTipTests(OpenTipTestCase):
    def test_no_key(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            urlopen = self._patch_urlopen()
            v = opentip.check(SHA256, "sha256")
        urlopen.assert_not_called()
        self.assertEqual(v.verdict, "пропущено (нет OPENTIP_API_KEY)")

    def test_red_hash(self):
        urlopen = self._patch_urlopen(
            _fake_response(
                {
                    "Zone": "Red",
                    "FileGeneralInfo": {
                        "FileStatus": "Malware",
                        "FirstSeen": "2006-05-22T00:00:00Z",
                        "Type": "COM",
                        "HitsCount": 100,
                    },
                    "DetectionsInfo": [{"DetectionName": "EICAR-Test-File"}, {"DetectionName": "EICAR-Test-File"}],
                }
            )
        )
        v = opentip.check(SHA256.upper(), "sha256")

        self.assertEqual(v.verdict, "вредоносный (EICAR-Test-File)")
        self.assertEqual(v.detections, "EICAR-Test-File")
        self.assertEqual(v.first_seen, "2006-05-22T00:00:00Z")
        self.assertEqual(v.context, "zone=Red; FileStatus=Malware; Type=COM; HitsCount=100")

        req = urlopen.call_args.args[0]
        self.assertEqual(req.full_url, f"{opentip.API_BASE}/search/hash?request={SHA256}")
        self.assertEqual(req.get_header("X-api-key"), "ot-key")

    def test_zone_mapping(self):
        cases = {
            "Orange": "подозрительный",
            "Yellow": "подозрительный",
            "Green": "похоже на легитимный",
            "Grey": "нет данных в OpenTIP",
        }
        self._patch_urlopen(*[_fake_response({"Zone": z, "IpGeneralInfo": {"Status": "x"}}) for z in cases])
        for zone, expected in cases.items():
            with self.subTest(zone=zone):
                self.assertEqual(opentip.check("203.0.113.5", "ip").verdict, expected)

    def test_file_status_fallback_without_zone(self):
        self._patch_urlopen(
            _fake_response({"FileGeneralInfo": {"FileStatus": "NoThreats"}}),
            _fake_response({"FileGeneralInfo": {"FileStatus": "Adware"}}),
        )
        self.assertEqual(opentip.check(SHA256, "sha256").verdict, "похоже на легитимный")
        self.assertEqual(opentip.check(SHA256, "sha256").verdict, "вредоносный")

    def test_ip_general_info(self):
        self._patch_urlopen(
            _fake_response(
                {"Zone": "Green", "IpGeneralInfo": {"Status": "Known", "CountryCode": "US", "FirstSeen": "2015-01-01"}}
            )
        )
        v = opentip.check("8.8.8.8", "ip")
        self.assertEqual(v.first_seen, "2015-01-01")
        self.assertEqual(v.context, "zone=Green; Status=Known; CountryCode=US")
        self.assertIsNone(v.detections)

    def test_url_is_encoded_and_case_preserved(self):
        urlopen = self._patch_urlopen(_fake_response({"Zone": "Grey"}))
        opentip.check("http://Example.com/a?b=1&c=Д", "url")
        full_url = urlopen.call_args.args[0].full_url
        self.assertTrue(full_url.startswith(f"{opentip.API_BASE}/search/url?request=http%3A%2F%2FExample.com%2Fa%3Fb%3D1%26c%3D"))

    def test_not_found(self):
        self._patch_urlopen(_http_error(404))
        self.assertEqual(opentip.check("example.com", "domain").verdict, "не найден в OpenTIP")

    def test_forbidden_mentions_quota(self):
        self._patch_urlopen(_http_error(403))
        v = opentip.check("example.com", "domain")
        self.assertIn("HTTP 403", v.verdict)
        self.assertIn("квота", v.verdict)

    def test_bad_request(self):
        self._patch_urlopen(_http_error(400))
        self.assertIn("HTTP 400", opentip.check("http://x.example/", "url").verdict)

    def test_network_error(self):
        self._patch_urlopen(urllib.error.URLError("connection refused"))
        self.assertTrue(opentip.check("8.8.8.8", "ip").verdict.startswith("ошибка сети"))

    def test_no_pause_by_default(self):
        self._patch_urlopen(_fake_response({"Zone": "Grey"}), _fake_response({"Zone": "Grey"}))
        opentip.check("8.8.8.8", "ip")
        opentip.check("1.1.1.1", "ip")
        self.sleep.assert_not_called()

    def test_configured_pause(self):
        self._patch_urlopen(_fake_response({"Zone": "Grey"}), _fake_response({"Zone": "Grey"}))
        with mock.patch.dict(os.environ, {opentip.RATE_LIMIT_ENV: "10"}), mock.patch(
            "time.monotonic", side_effect=[100.0, 101.0, 106.0]
        ):
            opentip.check("8.8.8.8", "ip")
            opentip.check("1.1.1.1", "ip")
        self.assertAlmostEqual(self.sleep.call_args.args[0], 5.0)


if __name__ == "__main__":
    unittest.main()
