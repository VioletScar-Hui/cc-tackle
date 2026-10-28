#!/usr/bin/env python3
"""ip_judge 的单元测试：多源判定、关键词兜底、缓存。

不测真实网络——所有数据源都注入假 fetcher。
"""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))

import ip_judge  # noqa: E402


def src(name, asn="", org="", hosting=None):
    def fetch(_ip):
        return {"src": name, "as": asn, "org": org, "hosting": hosting, "country": "US"}
    return fetch


class TestJudge(unittest.TestCase):
    def judge(self, *fetchers):
        return ip_judge.judge("1.2.3.4", fetchers=list(fetchers), pause=0)

    def test_hosting_true_wins(self):
        result, _ = self.judge(src("ip-api", "AS979 NetLab", hosting=True))
        self.assertEqual(result, "DATACENTER")

    def test_datacenter_keyword_without_isp_word(self):
        result, info = self.judge(src("ip-api", "AS979 NetLab Global", "NetLab"))
        self.assertEqual(result, "DATACENTER")
        self.assertIn("netlab", info["reason"].lower())

    def test_residential_isp_keyword(self):
        result, info = self.judge(src("ipinfo", "AS701 Verizon Business", "Verizon"))
        self.assertEqual(result, "RESIDENTIAL")
        self.assertIn("verizon", info["reason"].lower())

    def test_isp_word_wins_over_cloud_word(self):
        # 「名字里带 cloud 的家宽」不能判机房
        result, _ = self.judge(src("ip-api", "AS1 Comcast Cloud", "Comcast"))
        self.assertEqual(result, "RESIDENTIAL")

    def test_unknown_owner_is_not_guessed(self):
        result, info = self.judge(src("ip-api", "AS12345 Some Name", "Some Name"))
        self.assertEqual(result, "UNKNOWN")
        self.assertIn("人工", info["reason"])

    def test_all_sources_fail(self):
        def boom(_ip):
            raise ValueError("down")
        result, info = self.judge(boom, boom)
        self.assertEqual(result, "UNKNOWN")
        self.assertTrue(info["errors"])

    def test_partial_source_failure_still_judges(self):
        def boom(_ip):
            raise ValueError("down")
        result, _ = self.judge(boom, src("ipinfo", "AS701 Verizon"))
        self.assertEqual(result, "RESIDENTIAL")

    def test_bogon_like_unknown(self):
        result, _ = self.judge(src("ipinfo", "AS999 Nope"))
        self.assertEqual(result, "UNKNOWN")


class TestCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = ip_judge.CACHE_DIR
        ip_judge.CACHE_DIR = self.tmp.name

    def tearDown(self):
        ip_judge.CACHE_DIR = self.old
        self.tmp.cleanup()

    def test_roundtrip(self):
        payload = {"result": "RESIDENTIAL", "info": {"reason": "x"}}
        ip_judge.cache_put("1.2.3.4", payload)
        self.assertEqual(ip_judge.cache_get("1.2.3.4"), payload)

    def test_version_mismatch_invalidates(self):
        path = pathlib.Path(ip_judge._cache_path("1.2.3.4"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"v": 0, "t": 9e9, "r": {"result": "X"}}))
        self.assertIsNone(ip_judge.cache_get("1.2.3.4"))


if __name__ == "__main__":
    unittest.main()
