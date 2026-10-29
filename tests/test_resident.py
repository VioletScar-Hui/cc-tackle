#!/usr/bin/env python3
"""常驻任务清单：launchctl 的三种状态要分清，报告页要把清单印出来。"""

from __future__ import annotations

import os
import pathlib
import plistlib
import tempfile
import shutil
import sys
import unittest
from unittest import mock

# 测试不写页面：--audit 现在默认落一份并打开，别让用例往真实目录里写。
os.environ.setdefault("CLAUDE_GUARD_NO_REPORT", "1")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))

import account_guard as g  # noqa: E402
import report_html as rh  # noqa: E402


def _plist(label: str, *, run_at_load=True, keep_alive=True,
           argv=("/usr/bin/true",), interval=None) -> bytes:
    data = {"Label": label, "ProgramArguments": list(argv),
            "RunAtLoad": run_at_load, "KeepAlive": keep_alive}
    if interval:
        data["StartInterval"] = interval
    return plistlib.dumps(data)


class TestResidentTasks(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="guard-resident-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        agents = self.tmp / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        guard = str(g.SKILL_DIR / "scripts" / "net_guard.py")
        checker = str(g.SKILL_DIR / "scripts" / "account_guard.py")
        (agents / "local.running.plist").write_bytes(
            _plist("local.running", argv=("/usr/bin/python3", guard)))
        (agents / "local.idle.plist").write_bytes(
            _plist("local.idle", run_at_load=False, keep_alive=False,
                   argv=("/usr/bin/python3", guard)))
        (agents / "local.gone.plist").write_bytes(
            _plist("local.gone", argv=("/opt/other/tool.sh",)))
        (agents / "local.every.plist").write_bytes(
            _plist("local.every", run_at_load=False, keep_alive=False, interval=60,
                   argv=("/usr/bin/python3", checker)))
        old_home = g.HOME
        g.HOME = self.tmp
        self.addCleanup(setattr, g, "HOME", old_home)

    def _check(self, list_body: str, disabled_body: str = "") -> dict:
        def fake(cmd, timeout=10):
            if cmd[:2] == ["launchctl", "list"]:
                return 0, list_body
            if cmd[:2] == ["launchctl", "print-disabled"]:
                return 0, disabled_body
            return 1, ""
        with mock.patch.object(g, "run", side_effect=fake):
            return g.check_resident_tasks()

    def test_running_idle_and_disabled_are_distinguished(self):
        out = self._check(
            "PID\tStatus\tLabel\n"
            "123\t0\tlocal.running\n"
            "-\t0\tlocal.idle\n"
            "-\t2\tlocal.every\n",
            '"local.gone" => disabled\n')
        by_label = {item["label"]: item for item in out["items"]}
        self.assertNotIn("local.gone", by_label, "别的软件的 agent 不该进清单")
        self.assertEqual(out["total"], 3)
        self.assertIn("运行中", by_label["local.running"]["state"])
        self.assertIn("已加载，未运行", by_label["local.idle"]["state"])
        self.assertIn("上次退码 2", by_label["local.every"]["state"])
        self.assertEqual(out["running"], 1)
        self.assertEqual(out["failing"], ["local.every"])

    def test_autostart_flags_come_from_the_plist(self):
        # 带上禁用表：被禁用的那个虽然 RunAtLoad=true，但不该算进「会自启」。
        out = self._check("PID\tStatus\tLabel\n", '"local.running" => disabled\n')
        by_label = {item["label"]: item for item in out["items"]}
        self.assertIn("已禁用", by_label["local.running"]["state"])
        self.assertIn("登录时启动", by_label["local.running"]["autostart"])
        self.assertEqual(by_label["local.idle"]["autostart"], "仅手动")
        self.assertIn("每 60 秒", by_label["local.every"]["autostart"])
        self.assertEqual(out["autostart"], 1)   # 只剩 every 会自启

    def test_the_header_line_is_not_an_agent(self):
        out = self._check("PID\tStatus\tLabel\n")
        self.assertNotIn("Label", [item["label"] for item in out["items"]])

    def test_program_is_kept_for_display(self):
        out = self._check("PID\tStatus\tLabel\n123\t0\tlocal.running\n")
        item = [i for i in out["items"] if i["label"] == "local.running"][0]
        self.assertIn("net_guard.py", item["program"])

    def test_protects_says_what_the_guard_covers(self):
        out = self._check("PID\tStatus\tLabel\n123\t0\tlocal.running\n")
        by_label = {item["label"]: item for item in out["items"]}
        guard = by_label["local.running"]["protects"]
        self.assertIsInstance(guard, list)
        self.assertTrue(any("5 秒" in p for p in guard))
        self.assertTrue(any("出口" in p for p in guard))
        self.assertTrue(all(len(p) < 60 for p in guard), "每条都要短")
        checker = by_label["local.every"]["protects"]
        self.assertTrue(any("28 项" in p for p in checker))

    def test_function_groups_are_derived_from_the_script(self):
        out = self._check("PID\tStatus\tLabel\n")
        by_label = {item["label"]: item for item in out["items"]}
        self.assertEqual(by_label["local.running"]["function"], "网络防护")
        self.assertEqual(by_label["local.every"]["function"], "体检与清理")
        names = [group["name"] for group in out["groups"]]
        self.assertEqual(names, ["网络防护", "体检与清理"])


class TestRuntimeState(unittest.TestCase):
    """「在跑」不能只写 pid：还要能看出跑了多久、看门狗上一轮扫描是什么时候。"""

    def test_elapsed_formats(self):
        self.assertEqual(g._human_elapsed("05:23"), "5 小时 23 分")
        self.assertEqual(g._human_elapsed("02-03:04:05"), "2 天 3 小时")
        self.assertEqual(g._human_elapsed("00:00"), "不到 1 分")

    def test_last_scan_reads_the_log_tail(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="guard-scan-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        log = tmp / ".local" / "state" / "claude-guard" / "net-guard.log"
        log.parent.mkdir(parents=True)
        log.write_text("2026-10-27T21:27:50+08:00 scan clean\n", encoding="utf-8")
        old_home = g.HOME
        g.HOME = tmp
        self.addCleanup(setattr, g, "HOME", old_home)
        stamp, age = g._watchdog_last_scan()
        self.assertEqual(stamp, "2026-10-27T21:27:50+08:00")
        self.assertIsNotNone(age)

    def test_missing_log_is_not_an_error(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="guard-noscan-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        old_home = g.HOME
        g.HOME = tmp
        self.addCleanup(setattr, g, "HOME", old_home)
        self.assertEqual(g._watchdog_last_scan(), (None, None))


class TestResidentSectionInHtml(unittest.TestCase):
    def test_section_renders_when_the_report_has_it(self):
        report = {
            "timestamp": "2026-01-01 00:00:00",
            "A30_resident": {
                "total": 2, "autostart": 1, "running": 1, "not_loaded": 0, "disabled": 1,
                "groups": [{"name": "网络防护", "labels": ["local.a", "local.b"]}],
                "items": [
                    {"label": "local.a", "state": "运行中（pid 7）", "autostart": "登录时启动",
                     "function": "网络防护",
                     "protects": ["每 5 秒扫一遍直连", "出口漂移每 30 秒告警"],
                     "program": "/bin/sh /a.sh", "running": True, "loaded": True, "disabled": False},
                    {"label": "local.b", "state": "已禁用（重启也不会自启）", "autostart": "登录时启动",
                     "program": "/bin/sh /b.sh", "running": False, "loaded": False, "disabled": True},
                ],
            },
        }
        rows = [("a", g.S_OK, "")] * rh.BASE_ITEMS
        with mock.patch.object(g, "build_summary", return_value=rows):
            page = rh.render(report)
        self.assertIn("本 skill 的常驻程序", page)
        self.assertIn("local.a", page)
        self.assertIn("已禁用", page)
        self.assertIn("1 个被禁用", page)
        self.assertIn("网络防护", page)
        self.assertIn("这个进程保护什么", page)
        self.assertIn("protects-box", page)
        self.assertIn("<li>每 5 秒扫一遍直连</li>", page)
        self.assertIn("<li>出口漂移每 30 秒告警</li>", page)


if __name__ == "__main__":
    unittest.main(verbosity=2)
