#!/usr/bin/env python3
"""Tailscale × Clash 的 hosts 适配：写进 merge、幂等、不碰别的键、能复验。

背景（2026-11-03 真机）：关掉 Tailscale 的 DNS 接管后 `*.ts.net` 在系统里没有解析器，
Clash 把它当普通域名返回 fake-ip，Rex 连过去就 EOF。做法是只让 Clash 本地回答这些
内网名字——把「名字 → 100.x」写进当前订阅 profile 的 merge 文件。
"""

from __future__ import annotations

import json
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))

import tailscale_hosts as ts  # noqa: E402

PROFILES = """\
current: act
items:
- uid: act
  type: remote
  file: act.yaml
  option:
    merge: mrg
- uid: mrg
  type: merge
  file: merge.yaml
"""

MERGE = """\
# Profile Enhancement Merge Template for Clash Verge

dns:
  enable: true
  enhanced-mode: fake-ip

hosts:
  node-a.tail-example.ts.net: 100.64.0.11
"""

STATUS = {
    "self": {"name": "me.tail-example.ts.net", "ip": "100.64.0.10", "online": True},
    "peers": [
        {"name": "node-a.tail-example.ts.net", "ip": "100.64.0.11", "online": True},
        {"name": "node-b.tail-example.ts.net", "ip": "100.64.0.12", "online": True},
    ],
    "tailnet": "tail-example.ts.net",
    "corp_dns": False,
}


class TestHostsEditing(unittest.TestCase):
    def test_read_existing(self):
        self.assertEqual(ts.read_hosts(MERGE),
                         {"node-a.tail-example.ts.net": "100.64.0.11"})

    def test_upsert_updates_and_appends_without_touching_other_keys(self):
        out = ts.upsert_hosts(MERGE, {
            "node-a.tail-example.ts.net": "100.64.0.11",
            "node-b.tail-example.ts.net": "100.64.0.12",
        })
        self.assertIn("  node-b.tail-example.ts.net: 100.64.0.12", out)
        self.assertIn("enhanced-mode: fake-ip", out)
        self.assertEqual(ts.read_hosts(out),
                         {"node-a.tail-example.ts.net": "100.64.0.11",
                          "node-b.tail-example.ts.net": "100.64.0.12"})

    def test_upsert_replaces_a_stale_ip(self):
        out = ts.upsert_hosts(MERGE, {"node-a.tail-example.ts.net": "100.0.0.9"})
        self.assertEqual(ts.read_hosts(out)["node-a.tail-example.ts.net"], "100.0.0.9")
        self.assertNotIn("100.64.0.11", out)

    def test_upsert_is_idempotent(self):
        mapping = {"node-a.tail-example.ts.net": "100.64.0.11"}
        once = ts.upsert_hosts(MERGE, mapping)
        self.assertEqual(ts.upsert_hosts(once, mapping), once)

    def test_creates_hosts_block_when_absent(self):
        text = "dns:\n  enable: true\n"
        out = ts.upsert_hosts(text, {"a.ts.net": "100.1.2.3"})
        self.assertTrue(out.startswith("dns:\n  enable: true\n"))
        self.assertIn("hosts:\n  a.ts.net: 100.1.2.3", out)
        self.assertEqual(ts.read_hosts(out), {"a.ts.net": "100.1.2.3"})

    def test_quoted_keys_are_understood(self):
        text = 'hosts:\n  "a.ts.net": 100.1.2.3\n'
        self.assertEqual(ts.read_hosts(text), {"a.ts.net": "100.1.2.3"})


class TestTailscaleParsing(unittest.TestCase):
    def test_status_keeps_ipv4_peers_and_strips_trailing_dots(self):
        payload = {
            "Self": {"DNSName": "me.tail.ts.net.", "TailscaleIPs": ["100.64.0.10", "fd7a::1"]},
            "Peer": {
                "a": {"DNSName": "a.tail.ts.net.", "TailscaleIPs": ["100.1.1.1"], "Online": True},
                "b": {"DNSName": "b.tail.ts.net.", "TailscaleIPs": ["fd7a::2"], "Online": True},
            },
        }

        def fake(cmd, timeout=20):
            if cmd[1:3] == ["status", "--json"]:
                return 0, json.dumps(payload)
            if cmd[1:3] == ["debug", "prefs"]:
                return 0, '{"CorpDNS": false}'
            return 1, ""
        with mock.patch.object(ts, "run", side_effect=fake):
            status = ts.tailscale_status("/fake/tailscale")
        self.assertEqual(status["peers"], [{"name": "a.tail.ts.net", "ip": "100.1.1.1",
                                            "online": True}])
        self.assertEqual(status["self"]["name"], "me.tail.ts.net")
        self.assertEqual(status["tailnet"], "tail.ts.net")
        self.assertFalse(status["corp_dns"])

    def test_mapping_skips_self_by_default_and_filters_names(self):
        mapping = ts.hosts_mapping(STATUS)
        self.assertEqual(sorted(mapping), ["node-a.tail-example.ts.net",
                                           "node-b.tail-example.ts.net"])
        self.assertIn("me.tail-example.ts.net",
                      ts.hosts_mapping(STATUS, include_self=True))
        only = ts.hosts_mapping(STATUS, names=["node-b.tail-example.ts.net"])
        self.assertEqual(list(only), ["node-b.tail-example.ts.net"])

    def test_missing_cli_is_an_environment_error(self):
        with mock.patch.object(ts, "find_tailscale", return_value=None), \
             mock.patch("builtins.print"):
            self.assertEqual(ts.main(["--status"]), 2)
        with mock.patch.object(ts, "find_tailscale", return_value="/fake/tailscale"), \
             mock.patch.object(ts, "tailscale_status", return_value=None), \
             mock.patch("builtins.print"):
            self.assertEqual(ts.main(["--status"]), 2)


class TestMergeFileAndSync(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ts-hosts-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "profiles").mkdir()
        (self.tmp / "profiles.yaml").write_text(PROFILES, encoding="utf-8")
        (self.tmp / "profiles" / "merge.yaml").write_text(MERGE, encoding="utf-8")
        (self.tmp / "clash-verge.yaml").write_text("mode: rule\n", encoding="utf-8")
        self.verge = mock.patch.object(ts, "VERGE_DIR", self.tmp)
        self.verge.start()
        self.addCleanup(self.verge.stop)

    def test_active_merge_file_is_resolved_from_profiles_yaml(self):
        path, why = ts.active_merge_file()
        self.assertEqual(path, self.tmp / "profiles" / "merge.yaml")
        self.assertEqual(why, "")

    def test_write_merge_backs_up_and_writes(self):
        path, changed = ts.write_merge(self.tmp / "profiles" / "merge.yaml",
                                       {"node-b.tail-example.ts.net": "100.64.0.12"})
        self.assertTrue(changed)
        self.assertTrue(path.name.startswith("merge.yaml.bak-ts-hosts-"))
        self.assertIn("node-b", (self.tmp / "profiles" / "merge.yaml").read_text())

    def test_sync_dry_run_writes_nothing(self):
        before = (self.tmp / "profiles" / "merge.yaml").read_text()
        with mock.patch("builtins.print"):
            code = ts.sync({"node-b.tail-example.ts.net": "100.64.0.12"},
                           self.tmp / "profiles" / "merge.yaml", dry_run=True, reload=False)
        self.assertEqual(code, 0)
        self.assertEqual((self.tmp / "profiles" / "merge.yaml").read_text(), before)
        self.assertEqual(list(self.tmp.glob("profiles/*.bak-*")), [])

    def test_sync_writes_and_verifies(self):
        def fake_run(cmd, timeout=20):
            if cmd[0] == "dig":
                host = cmd[-1]
                if host.endswith(".ts.net"):
                    return 0, "100.64.0.11\n"
                return 0, "198.18.0.34\n"
            if cmd[0] == "scutil":
                return 0, "resolver #1\n  nameserver[0] : 114.114.114.114\n"
            return 1, ""
        with mock.patch.object(ts, "run", side_effect=fake_run), \
             mock.patch("builtins.print"):
            code = ts.sync({"node-a.tail-example.ts.net": "100.64.0.11"},
                           self.tmp / "profiles" / "merge.yaml",
                           dry_run=False, reload=False)
        self.assertEqual(code, 0)
        self.assertIn("node-a", (self.tmp / "profiles" / "merge.yaml").read_text())

    def test_main_sync_dry_run_end_to_end(self):
        with mock.patch.object(ts, "find_tailscale", return_value="/fake/tailscale"), \
             mock.patch.object(ts, "tailscale_status", return_value=STATUS), \
             mock.patch("builtins.print"):
            code = ts.main(["--sync", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertNotIn("node-b",
                         (self.tmp / "profiles" / "merge.yaml").read_text())


class TestVerify(unittest.TestCase):
    def test_verify_checks_private_names_and_public_fake_ip(self):
        def fake_resolve(host):
            return ["100.64.0.11"] if host.endswith(".ts.net") else ["198.18.0.34"]
        with mock.patch.object(ts, "resolve", side_effect=fake_resolve), \
             mock.patch.object(ts, "system_dns_servers", return_value=["114.114.114.114"]):
            out = ts.verify({"node-a.tail-example.ts.net": "100.64.0.11"})
        self.assertTrue(out["hosts_ok"])
        self.assertTrue(out["public_ok"])

    def test_verify_flags_a_public_leak(self):
        def fake_resolve(host):
            return ["100.64.0.11"] if host.endswith(".ts.net") else ["93.184.216.34"]
        with mock.patch.object(ts, "resolve", side_effect=fake_resolve), \
             mock.patch.object(ts, "system_dns_servers", return_value=[]):
            out = ts.verify({"a.ts.net": "100.64.0.11"})
        self.assertFalse(out["public_ok"])


if __name__ == "__main__":
    unittest.main()
