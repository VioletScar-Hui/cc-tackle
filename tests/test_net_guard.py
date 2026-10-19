#!/usr/bin/env python3
"""net_guard 的单元测试：认进程、认路由、认「该不该杀」。

这里不测真实网络——真实连接在 CI 里也没有。测的是三件容易错的事：
  * 谁算 Claude 进程（别把 cc-tackle / DSH 认成 Claude，也别漏掉版本号命名的 CLI）；
  * lsof 的两种地址格式能不能抠对；
  * 什么时候该判直连（en0）什么时候不该（回环、私网、fake-ip、utun、读不到）。
"""

from __future__ import annotations

import io
import ipaddress
import os
import pathlib
import sys
import unittest
from collections import deque
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))

import net_guard as ng  # noqa: E402


class TestProcessMatching(unittest.TestCase):
    def test_desktop_app_and_helpers(self):
        for comm in ("/Applications/Claude.app/Contents/MacOS/Claude",
                     "/Applications/Claude.app/Contents/Frameworks/Claude Helper "
                     "(Renderer).app/Contents/MacOS/Claude Helper (Renderer)"):
            self.assertTrue(ng.is_claude_process(1, comm), comm)

    def test_versioned_native_cli(self):
        # native 安装的 CLI 文件名是版本号，只能靠路径认
        self.assertTrue(ng.is_claude_process(
            1, "/Users/x/.local/share/claude/versions/2.1.296"))

    def test_node_cli_is_recognised_by_entrypoint(self):
        self.assertTrue(ng.is_claude_process(
            1, "/usr/local/bin/node", "node /x/node_modules/@anthropic-ai/claude-code/cli.js"))

    def test_our_own_tools_and_other_hosts_are_not_claude(self):
        for comm, args in (
            ("/Users/x/CC_Project/cc-tackle/scripts/net_guard.py", ""),
            ("/Users/x/CC_Project/cc-tackle/scripts/account_guard.py", ""),
            ("/Applications/DeepSeek Harness.app/Contents/MacOS/DeepSeek Harness",
             "--skill ~/.claude/skills/cc-tackle"),
            ("/usr/bin/curl", "curl https://claude.ai"),
        ):
            self.assertFalse(ng.is_claude_process(1, comm, args), comm)

    def test_matching_is_case_insensitive_for_the_app_name(self):
        self.assertTrue(ng.is_claude_process(9, "/Applications/Claude.app/Contents/MacOS/CLAUDE"))


class TestLsofParsing(unittest.TestCase):
    def test_ipv4_line(self):
        text = ("COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
                "claude  1234  me   5u  IPv4 0x1  0t0 TCP 192.168.1.9:55000->160.79.104.10:443 (ESTABLISHED)\n")
        conns = ng.parse_lsof(text)
        self.assertEqual(len(conns), 1)
        self.assertEqual(str(conns[0]["ip"]), "160.79.104.10")
        self.assertEqual(conns[0]["port"], 443)
        self.assertEqual(conns[0]["state"], "ESTABLISHED")

    def test_ipv6_line_is_unbracketed(self):
        text = "x 1 u 5u IPv6 0x1 0t0 TCP [::1]:55000->[2606:4700::1111]:443 (ESTABLISHED)\n"
        conns = ng.parse_lsof(text)
        self.assertEqual(str(conns[0]["ip"]), "2606:4700::1111")
        self.assertEqual(conns[0]["port"], 443)

    def test_lines_without_arrow_are_ignored(self):
        self.assertEqual(ng.parse_lsof("claude 1 u 5u IPv4 TCP *:8000 (LISTEN)\n"), [])


class TestClassify(unittest.TestCase):
    def test_loopback_and_private_are_local(self):
        for ip in ("127.0.0.1", "192.168.1.5", "10.0.0.9", "169.254.1.1", "192.168.1.9"):
            self.assertEqual(ng.classify(ipaddress.ip_address(ip), "en0"), "local", ip)

    def test_cgnat_counts_as_local(self):
        self.assertEqual(ng.classify(ipaddress.ip_address("100.64.0.9"), "utun3"), "local")

    def test_fake_ip_is_tunnel_even_without_a_route(self):
        self.assertEqual(ng.classify(ipaddress.ip_address("198.18.0.5"), ""), "tunnel")

    def test_utun_route_is_tunnel(self):
        self.assertEqual(ng.classify(ipaddress.ip_address("160.79.104.10"), "utun1024"), "tunnel")

    def test_physical_interface_is_direct(self):
        self.assertEqual(ng.classify(ipaddress.ip_address("160.79.104.10"), "en0"), "direct")
        self.assertEqual(ng.classify(ipaddress.ip_address("2606:4700::1111"), "en1"), "direct")

    def test_unknown_route_is_not_a_kill_reason(self):
        # 路由读不到时宁可漏杀：unknown 既不是 tunnel 也不是 direct
        self.assertEqual(ng.classify(ipaddress.ip_address("160.79.104.10"), ""), "unknown")


class TestScan(unittest.TestCase):
    def _conn(self, ip="160.79.104.10"):
        return {"ip": ipaddress.ip_address(ip), "port": 443, "state": "ESTABLISHED"}

    def test_direct_connection_becomes_an_event(self):
        with mock.patch.object(ng, "claude_pids",
                               return_value=[(4242, "/Applications/Claude.app/Contents/MacOS/Claude")]), \
             mock.patch.object(ng, "connections", return_value=[self._conn()]), \
             mock.patch.object(ng, "route_iface", return_value="en0"):
            events = ng.scan(protected=set())
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["pid"], 4242)
        self.assertEqual(events[0]["iface"], "en0")

    def test_proxied_connection_is_not_an_event(self):
        with mock.patch.object(ng, "claude_pids", return_value=[(4242, "claude")]), \
             mock.patch.object(ng, "connections", return_value=[self._conn()]), \
             mock.patch.object(ng, "route_iface", return_value="utun1024"):
            self.assertEqual(ng.scan(protected=set()), [])

    def test_protected_pids_are_skipped(self):
        with mock.patch.object(ng, "claude_pids", return_value=[(4242, "claude")]), \
             mock.patch.object(ng, "connections", return_value=[self._conn()]), \
             mock.patch.object(ng, "route_iface", return_value="en0"):
            self.assertEqual(ng.scan(protected={4242}), [])


class TestRunOnce(unittest.TestCase):
    EVENT = {"pid": 4242, "comm": "claude", "ip": "160.79.104.10", "port": 443,
             "iface": "en0", "state": "ESTABLISHED", "at": "2026-10-19T22:00:00+08:00"}

    def test_dry_run_never_kills(self):
        with mock.patch.object(ng, "scan", return_value=[self.EVENT]), \
             mock.patch.object(ng, "kill_process") as killer, \
             mock.patch.object(ng, "append_log"), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            rc = ng.run_once(dry_run=True, protected=set(), extra_pattern=None,
                             kills=deque(), verbose=False)
        killer.assert_not_called()
        self.assertEqual(rc, 0)
        self.assertIn("直连", out.getvalue())

    def test_violation_is_killed_and_reported(self):
        written = []
        with mock.patch.object(ng, "scan", return_value=[self.EVENT]), \
             mock.patch.object(ng, "kill_process", return_value=(True, "已终止")) as killer, \
             mock.patch.object(ng, "append_log", side_effect=written.append), \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            rc = ng.run_once(dry_run=False, protected=set(), extra_pattern=None,
                             kills=deque(), verbose=False)
        killer.assert_called_once_with(4242)
        self.assertEqual(rc, 1)
        self.assertTrue(any("action=kill" in line for line in written), written)

    def test_kill_rate_limit_stops_a_loop(self):
        from collections import deque as dq
        kicks = dq([__import__("time").time()] * ng.MAX_KILLS_PER_MIN)
        with mock.patch.object(ng, "scan", return_value=[self.EVENT]), \
             mock.patch.object(ng, "kill_process") as killer, \
             mock.patch.object(ng, "append_log"), \
             mock.patch("sys.stdout", new_callable=io.StringIO), \
             mock.patch("sys.stderr", new_callable=io.StringIO):
            rc = ng.run_once(dry_run=False, protected=set(), extra_pattern=None,
                             kills=kicks, verbose=False)
        killer.assert_not_called()
        self.assertEqual(rc, 0)


class TestKill(unittest.TestCase):
    def test_sigkill_and_confirmation(self):
        calls = []

        def fake_run(cmd, timeout=10):
            calls.append(cmd)
            return (1, "")          # ps -p <pid> 没结果 = 进程不在了

        with mock.patch("os.kill") as os_kill, \
             mock.patch.object(ng, "run", side_effect=fake_run), \
             mock.patch.object(ng.time, "sleep"):
            ok, note = ng.kill_process(4242)
        os_kill.assert_called_once_with(4242, ng.signal.SIGKILL)
        self.assertTrue(ok)
        self.assertEqual(note, "已终止")

    def test_missing_process_is_treated_as_gone(self):
        with mock.patch("os.kill", side_effect=ProcessLookupError), \
             mock.patch.object(ng.time, "sleep"):
            ok, note = ng.kill_process(4242)
        self.assertTrue(ok)
        self.assertIn("不在了", note)


class TestLaunchAgentPlist(unittest.TestCase):
    def test_plist_runs_the_script_every_five_seconds(self):
        data = ng.launch_agent_plist(5)
        self.assertEqual(data["Label"], ng.AGENT_LABEL)
        self.assertEqual(data["ProgramArguments"][-2:], ["--interval", "5"])
        self.assertTrue(data["RunAtLoad"])
        self.assertTrue(data["KeepAlive"])
        self.assertTrue(data["ProgramArguments"][1].endswith("net_guard.py"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
