#!/usr/bin/env python3
"""claude-account-guard 的测试。

覆盖三类东西：
  1. 纯函数逻辑（ASN 归类、参数解析）—— 回归曾经真实出过的 bug；
  2. 写操作的安全边界（无备份不改动、模式 0 不落盘、清理后不得变成启用）；
  3. 入口闸门（非 TTY 拒绝、密码与状态由用户掌握）。

跑法：python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))

import account_guard as g  # noqa: E402


class TestClassifyAsn(unittest.TestCase):
    """文章 2.3：出口 ASN 类型必须是 ISP / Residential，不能是 Hosting。"""

    def test_att_with_ampersand_is_isp(self):
        # 这是真实踩过的 bug：ipinfo 返回 "AS7018 AT&T Enterprises, LLC"，
        # 直接匹配小写原文里的 "att" 匹配不到，因为 at&t 没有连续的 att。
        self.assertEqual(g.classify_asn("AS7018 AT&T Enterprises, LLC"), "疑似住宅/ISP")
        self.assertEqual(g.classify_asn("AS7018 At&t Services, Inc."), "疑似住宅/ISP")

    def test_hosting_providers(self):
        for org in ("AS16509 Amazon.com, Inc.", "AS14061 DigitalOcean, LLC",
                    "AS45102 Alibaba (US) Technology Co., Ltd.", "AS24940 Hetzner Online GmbH"):
            self.assertEqual(g.classify_asn(org), "疑似机房 IP（Hosting）", org)

    def test_unknown_is_reported_not_guessed(self):
        # 归不了类时必须如实说归不了，不能猜一个「安全」出来
        self.assertIn("无法归类", g.classify_asn("AS12345 Some Obscure LLC"))
        self.assertIn("无法归类", g.classify_asn(""))

    def test_hosting_wins_over_isp_marker(self):
        # 同时含两类词时，保守判为机房
        self.assertEqual(g.classify_asn("AS1 Cloud Telecom Hosting"), "疑似机房 IP（Hosting）")


class TestPromptHelpers(unittest.TestCase):
    """沿用 claude-cleanup 的 [y/N] 与选项编号约定。"""

    def test_ask_yes_only_accepts_y(self):
        for raw, want in (("y", True), ("Y", True), ("yes", False), ("", False), ("n", False)):
            with mock.patch("builtins.input", return_value=raw):
                self.assertIs(g.ask_yes("q"), want, raw)

    def test_ask_choice_defaults_to_zero(self):
        with mock.patch("builtins.input", return_value=""):
            self.assertEqual(g.ask_choice("q", {0, 1, 2}), 0)

    def test_ask_choice_rejects_out_of_range(self):
        for raw in ("9", "abc", "-1"):
            with mock.patch("builtins.input", return_value=raw):
                with self.assertRaises(ValueError):
                    g.ask_choice("q", {0, 1, 2})


class TestTelemetry(unittest.TestCase):
    """文章 §5 的遥测开关。安全要求：模式 0 绝不落盘，模式 1/2 落盘后必须复验。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.settings = self.tmp / "settings.json"
        self.settings.write_text(json.dumps({"env": {}, "theme": "dark"}), encoding="utf-8")
        self._orig = g.SETTINGS
        g.SETTINGS = self.settings

    def tearDown(self):
        g.SETTINGS = self._orig

    def test_mode0_does_not_touch_disk(self):
        before = self.settings.read_bytes()
        self.assertEqual(g.apply_telemetry(0), "保持")
        self.assertEqual(self.settings.read_bytes(), before, "选择保持时不应改写 settings.json")

    def test_mode1_writes_all_three_and_preserves_other_keys(self):
        g.apply_telemetry(1)
        data = json.loads(self.settings.read_text(encoding="utf-8"))
        for k in g.TELEMETRY_KEYS:
            self.assertEqual(data["env"][k], "1")
        self.assertEqual(data["theme"], "dark", "非 env 的键必须原样保留")

    def test_mode2_writes_two_keys(self):
        g.apply_telemetry(2)
        env = json.loads(self.settings.read_text(encoding="utf-8"))["env"]
        self.assertEqual(env["DISABLE_TELEMETRY"], "1")
        self.assertEqual(env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"], "1")
        self.assertNotIn("DISABLE_ERROR_REPORTING", env)

    def test_existing_env_keys_survive(self):
        self.settings.write_text(json.dumps({"env": {"SOME_KEY": "keep-me"}}), encoding="utf-8")
        g.apply_telemetry(1)
        env = json.loads(self.settings.read_text(encoding="utf-8"))["env"]
        self.assertEqual(env["SOME_KEY"], "keep-me")


class TestBackupSafety(unittest.TestCase):
    """备份是第一个写操作。备份不了就必须停下，不能无备份改动。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self._orig = g.BACKUP_ROOT
        g.BACKUP_ROOT = self.tmp / "backups"

    def tearDown(self):
        g.BACKUP_ROOT = self._orig

    def test_backs_up_regular_file(self):
        f = self.tmp / "settings.json"
        f.write_text("{}", encoding="utf-8")
        dest = g.create_backup([f])
        copied = dest / "files" / str(f).lstrip("/").replace("/", "__")
        self.assertTrue(copied.exists())
        self.assertEqual(copied.read_text(encoding="utf-8"), "{}")

    def test_missing_path_is_skipped_not_faked(self):
        dest = g.create_backup([self.tmp / "nope.json"])
        self.assertEqual(json.loads((dest / "manifest.json").read_text())["items"], [])

    def test_sudo_backup_failure_aborts(self):
        # 读不到 /var/db/locationd 时，若静默跳过备份就等于「无备份改动」，
        # 所以这里必须抛错中止。
        # sudo_alive 要假装已授权：否则 ensure_sudo 会真的去调 sudo -v，
        # 那条命令会阻塞在密码提示上，把整个测试挂住（实测踩过）。
        with mock.patch.object(g, "sudo_alive", return_value=True):
            with mock.patch.object(g, "run", return_value=(1, "sudo: a password is required")):
                with self.assertRaises(RuntimeError) as ctx:
                    g.create_backup([], [pathlib.Path("/var/db/locationd/clients.plist")])
        self.assertIn("备份失败", str(ctx.exception))


class TestProtectedVerify(unittest.TestCase):
    def test_detects_modification(self):
        f = pathlib.Path(tempfile.mkdtemp()) / "x.json"
        f.write_text("a", encoding="utf-8")
        before = {str(f): b"a"}
        f.write_text("b", encoding="utf-8")
        self.assertEqual(g.protected_verify(before, allow=set()), [str(f)])

    def test_allowlist_suppresses_expected_change(self):
        f = pathlib.Path(tempfile.mkdtemp()) / "x.json"
        f.write_text("a", encoding="utf-8")
        before = {str(f): b"a"}
        f.write_text("b", encoding="utf-8")
        self.assertEqual(g.protected_verify(before, allow={str(f)}), [])


class TestProxyResidueSafety(unittest.TestCase):
    """最容易出事的一项：networksetup -set{kind} 会顺带把代理置为启用。"""

    def test_refuses_when_proxy_ends_up_enabled(self):
        residue = [{"service": "Wi-Fi", "kind": "webproxy", "server": "127.0.0.1", "port": "7897"}]

        def fake_run(cmd, timeout=20):
            if "networksetup" in cmd and "-getwebproxy" in cmd:
                return 0, "Enabled: Yes\nServer: 0.0.0.0\nPort: 0\n"
            return 0, ""

        with mock.patch.object(g, "run", side_effect=fake_run):
            with self.assertRaises(RuntimeError) as ctx:
                g.clear_proxy_residue(residue)
        self.assertIn("仍处于启用状态", str(ctx.exception))

    def test_counts_only_when_disabled(self):
        residue = [{"service": "Wi-Fi", "kind": "webproxy", "server": "127.0.0.1", "port": "7897"}]

        def fake_run(cmd, timeout=20):
            if "networksetup" in cmd and "-getwebproxy" in cmd:
                return 0, "Enabled: No\nServer: 0.0.0.0\nPort: 0\n"
            return 0, ""

        with mock.patch.object(g, "run", side_effect=fake_run):
            self.assertEqual(g.clear_proxy_residue(residue), 1)

    def test_empty_residue_is_noop(self):
        self.assertEqual(g.clear_proxy_residue([]), 0)


class TestEntryGates(unittest.TestCase):
    """闸门：非 TTY 不给改，Claude Code 下只能只读。"""

    def test_non_tty_refuses(self):
        with mock.patch.object(g.sys, "stdin", io.StringIO("")):
            with mock.patch.object(g.sys.stdin, "isatty", create=True, return_value=False):
                self.assertEqual(g.main([]), 2)

    def test_under_claude_refuses_non_audit(self):
        with mock.patch.object(g, "running_under_claude", return_value=True):
            self.assertEqual(g.main([]), 2)

    def test_run_survives_missing_binary(self):
        code, body = g.run(["/definitely/not/a/binary"])
        self.assertEqual(code, 1)
        self.assertEqual(body, "")


class TestProjectRoots(unittest.TestCase):
    """A14 的目录不能再写死在某台机器上。"""

    def test_empty_when_unset(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(g.project_roots(), [])

    def test_parses_colon_separated(self):
        with mock.patch.dict("os.environ", {"CLAUDE_GUARD_PROJECT_ROOTS": "/a:/b"}):
            self.assertEqual([str(p) for p in g.project_roots()], ["/a", "/b"])

    def test_skips_blank_segments(self):
        with mock.patch.dict("os.environ", {"CLAUDE_GUARD_PROJECT_ROOTS": "/a::/b:"}):
            self.assertEqual([str(p) for p in g.project_roots()], ["/a", "/b"])


class TestAutoClean(unittest.TestCase):
    """残留类的自动清理：幂等、只动该动的行、清完复验。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self._home = g.HOME
        self._settings = g.SETTINGS
        g.HOME = self.tmp
        g.SETTINGS = self.tmp / ".claude" / "settings.json"
        g.SETTINGS.parent.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        g.HOME = self._home
        g.SETTINGS = self._settings

    def test_rc_lines_removed_and_others_kept(self):
        rc = self.tmp / ".zshrc"
        rc.write_text(
            "# 我的配置\nexport EDITOR=vim\n"
            "export HTTP_PROXY=http://127.0.0.1:7897\n"
            "alias ll='ls -la'\n",
            encoding="utf-8",
        )
        changed = g.clear_rc_proxy_lines({".zshrc": [{"line": 3, "text": "export HTTP_PROXY=..."}]})
        self.assertEqual(changed, [str(rc)])
        text = rc.read_text(encoding="utf-8")
        self.assertNotIn("HTTP_PROXY", text)
        self.assertIn("EDITOR=vim", text, "无关行必须保留")
        self.assertIn("alias ll", text)
        self.assertIn("# 我的配置", text, "注释行必须保留")

    def test_rc_noop_when_nothing_matched(self):
        (self.tmp / ".zshrc").write_text("export EDITOR=vim\n", encoding="utf-8")
        self.assertEqual(g.clear_rc_proxy_lines({".zshrc": []}), [])

    def test_settings_base_url_removed_others_kept(self):
        g.SETTINGS.write_text(
            json.dumps({"env": {"ANTHROPIC_BASE_URL": "http://evil/v1", "SOME_KEY": "keep"}, "theme": "dark"}),
            encoding="utf-8",
        )
        msg = g.clear_anthropic_base_url()
        data = json.loads(g.SETTINGS.read_text(encoding="utf-8"))
        self.assertNotIn("ANTHROPIC_BASE_URL", data["env"])
        self.assertEqual(data["env"]["SOME_KEY"], "keep", "无关 env 键必须保留")
        self.assertEqual(data["theme"], "dark", "非 env 键必须保留")
        self.assertIn("ANTHROPIC_BASE_URL", msg)

    def test_settings_base_url_noop_when_clean(self):
        g.SETTINGS.write_text(json.dumps({"env": {}}), encoding="utf-8")
        self.assertIn("没有需要清掉", g.clear_anthropic_base_url())

    def test_npm_git_clear_verifies(self):
        def fake_run(cmd, timeout=20):
            if cmd[:2] == ["npm", "config"] and cmd[2] in ("get",) if len(cmd) > 2 else False:
                return 0, "undefined\n"
            if cmd[:3] == ["git", "config", "--global"] and "get" in cmd:
                return 0, ""
            return 0, ""

        with mock.patch.object(g, "run", side_effect=fake_run):
            done = g.clear_npm_git_proxy()
        self.assertEqual(len(done), 4, "四个键都该确认清干净")

    def test_plan_marks_other_tools_as_report_only(self):
        report = {
            "A1_proxy_residue": {"residue": []},
            "A1_terminal_env": {"rc_files": {}, "npm": {}, "git": {}, "env_hits": []},
            "A2_anthropic_base_url": {"hits": [{"file": "/Users/x/.dsh/settings.yaml", "line": 10, "text": "x"}]},
        }
        plan = g.auto_clean_plan(report)
        self.assertFalse(plan["settings_base_url"])
        self.assertTrue(any("只报告不代改" in s for s in plan["summary"]))

    def test_plan_flags_claude_code_settings(self):
        report = {
            "A1_proxy_residue": {"residue": [{"service": "Wi-Fi", "kind": "webproxy"}]},
            "A1_terminal_env": {"rc_files": {".zshrc": [{"line": 3, "text": "x"}]}, "npm": {}, "git": {}, "env_hits": []},
            "A2_anthropic_base_url": {"hits": [{"file": str(g.SETTINGS), "line": 3, "text": "x"}]},
        }
        plan = g.auto_clean_plan(report)
        self.assertTrue(plan["settings_base_url"])
        self.assertEqual(len(plan["proxy_residue"]), 1)
        self.assertTrue(any("Claude Code" in s for s in plan["summary"]))


class TestEnvScanPrecision(unittest.TestCase):
    """文章的 grep 太宽，会把正常变量当残留；这里必须分档。"""

    def test_claude_named_var_is_not_residue(self):
        env = {"CLAUDE_GUARD_PROJECT_ROOTS": "/x", "CLAUDE_CODE_SIMPLE": "1"}
        with mock.patch.dict("os.environ", env, clear=True):
            r = g.check_terminal_env()
        self.assertEqual(r["env_hits"], [], "名字里带 claude 的正常变量不该算残留")
        self.assertEqual(len(r["env_info"]), 2)

    def test_proxy_var_is_residue(self):
        with mock.patch.dict("os.environ", {"HTTPS_PROXY": "http://127.0.0.1:7890"}, clear=True):
            r = g.check_terminal_env()
        self.assertEqual(len(r["env_hits"]), 1)
        self.assertIn("HTTPS_PROXY", r["env_hits"][0])

    def test_anthropic_base_url_is_residue(self):
        with mock.patch.dict("os.environ", {"ANTHROPIC_BASE_URL": "http://x/v1"}, clear=True):
            r = g.check_terminal_env()
        self.assertEqual(len(r["env_hits"]), 1)


class TestConsistencyWording(unittest.TestCase):
    """文章 §2.2 推荐台北时区、§3.3 又要求出口同国，两条互斥。
    脚本必须把这处张力陈述出来，而不是拿一条去否定另一条。"""

    def test_taipei_with_us_ip_is_tension_not_error(self):
        ip = {"country": "US"}
        with mock.patch.object(g, "run", return_value=(0, "/var/db/timezone/zoneinfo/Asia/Taipei")):
            r = g.check_consistency(ip)
        self.assertNotIn("verdict", r)
        self.assertTrue(any("张力" in x or "冲突" in x for x in r["tension"]))

    def test_language_is_fact_not_verdict(self):
        ip = {"country": "US"}
        with mock.patch.object(g, "run", return_value=(0, "/var/db/timezone/zoneinfo/Asia/Taipei")):
            with mock.patch.dict("os.environ", {"LANG": "zh_CN.UTF-8"}, clear=True):
                r = g.check_consistency(ip)
        self.assertTrue(any("中文本身不是罪名" in f for f in r["facts"]))
        self.assertFalse(any("矛盾" in f for f in r["facts"]))


class TestIpv6Reporting(unittest.TestCase):
    """关 IPv6 失败时必须报出来，不能打印「已关闭 []」假装成功。"""

    def test_failure_is_reported(self):
        with mock.patch.object(g, "run", return_value=(1, "")):
            r = g.set_ipv6_off(["Wi-Fi"])
        self.assertEqual(r["done"], [])
        self.assertEqual(r["failed"], ["Wi-Fi"])

    def test_success_includes_rollback_command(self):
        def fake_run(cmd, timeout=20):
            if "-getinfo" in cmd:
                return 0, "IPv6: Off\n"
            return 0, ""

        with mock.patch.object(g, "run", side_effect=fake_run):
            r = g.set_ipv6_off(["Wi-Fi"])
        self.assertEqual(r["done"], ["Wi-Fi"])
        self.assertIn("networksetup -setv6automatic 'Wi-Fi'", r["rollback"][0])


class TestDnsPrecision(unittest.TestCase):
    def test_fake_ip_recorded_per_host(self):
        with mock.patch.object(g, "run", return_value=(0, "198.18.0.199\n")):
            r = g.check_dns()
        self.assertTrue(r["fake_ip"])
        self.assertEqual(r["real_ip_hosts"], [])

    def test_real_ip_is_flagged_as_leak_suspect(self):
        def fake_run(cmd, timeout=20):
            if cmd[0] == "dig":
                return 0, "160.79.104.10\n"
            return 0, "nameserver[0] : 223.6.6.6\n"

        with mock.patch.object(g, "run", side_effect=fake_run):
            r = g.check_dns()
        self.assertFalse(r["fake_ip"])
        self.assertTrue(r["real_ip_hosts"])


class TestLocationTimezoneVerification(unittest.TestCase):
    """B5 的复验必须是真复验：读回整份 plist 确认 Authorized 翻成 False。"""

    @staticmethod
    def _on():
        # 初始状态必须是「开着」（Authorized is True），否则走的是「无需改动」分支
        return {"readable": True, "clients": {"k": {"Authorized": True}}, "note": ""}

    @staticmethod
    def _off():
        return {"readable": True, "clients": {"k": {"Authorized": None}}, "note": ""}

    def test_raises_when_verification_fails(self):
        # 写完之后再读还是「开着」→ 必须判未生效，不能假装成功
        with mock.patch.object(g, "location_service_status", side_effect=[self._on(), self._on()]):
            with mock.patch.object(g, "run", return_value=(0, "")):
                with self.assertRaises(RuntimeError) as ctx:
                    g.disable_location_timezone()
        self.assertIn("未生效", str(ctx.exception))

    def test_succeeds_when_authorized_flips(self):
        with mock.patch.object(g, "location_service_status", side_effect=[self._on(), self._off()]):
            with mock.patch.object(g, "run", return_value=(0, "")):
                msg = g.disable_location_timezone()
        self.assertIn("已改写并复验", msg)

    def test_falls_back_to_set_when_add_fails(self):
        # 字段不存在时 Add 会失败，要退回 Set 再试一次
        seen = []

        def fake_run(cmd, timeout=20):
            seen.append(" ".join(cmd))
            return (1 if "Add" in " ".join(cmd) else 0), ""

        with mock.patch.object(g, "location_service_status", side_effect=[self._on(), self._off()]):
            with mock.patch.object(g, "run", side_effect=fake_run):
                g.disable_location_timezone()
        self.assertTrue(any("Add" in c for c in seen))
        self.assertTrue(any("Set" in c for c in seen))


class TestFailureReporting(unittest.TestCase):
    """中途失败或 Ctrl-C 时，已经落盘的改动不会自动回滚，
    必须把备份路径告诉用户，否则用户会以为「中断=没改」。

    两个曾经踩过的坑，写测试时必须避开：
      * 遥测答案必须是 2 —— 选 0 时 main 走 `if telemetry else '保持'` 短路，
        apply_telemetry 根本不会被调用，mock 的 side_effect 永远不触发，
        测试会「通过」但什么都没测到；
      * HOME 必须一起 patch —— targets 里有 HOME/'.claude.json'，
        不 patch 就会去读真实家目录。
    """

    def _run_main(self, tmp, boom):
        report = {
            "A1_proxy_residue": {"residue": [], "enabled": [], "scutil": {}, "network_services": []},
            "A1_terminal_env": {"rc_files": {}, "npm": {}, "git": {}, "env_hits": [], "env_info": []},
            "A2_anthropic_base_url": {"hits": []},
            "A5_ipv6": {"services": {}, "global_addresses": []},
        }
        settings = tmp / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True, exist_ok=True)
        settings.write_text('{"env": {}}', encoding="utf-8")
        (tmp / ".claude.json").write_text('{"userID": "fake"}', encoding="utf-8")
        err = io.StringIO()
        calls = []
        with mock.patch.object(g, "HOME", tmp), \
             mock.patch.object(g, "SETTINGS", settings), \
             mock.patch.object(g, "BACKUP_ROOT", tmp / "backups"), \
             mock.patch.object(g, "audit", return_value=report), \
             mock.patch.object(g, "print_audit"), \
             mock.patch.object(g, "apply_telemetry", side_effect=lambda m: (calls.append(m), boom())[1]), \
             mock.patch.object(g.sys, "stdin", mock.Mock(isatty=lambda: True)), \
             mock.patch("builtins.input", side_effect=["2", "n", "n", "CONFIRM"]), \
             mock.patch.object(g.sys, "stdout", io.StringIO()), \
             mock.patch.object(g.sys, "stderr", err):
            rc = g.main([])
        return rc, err.getvalue(), calls

    def test_apply_is_actually_reached(self):
        # 先确认这个测试场景真的能触发到写入步骤，否则下面两个断言全是空的
        tmp = pathlib.Path(tempfile.mkdtemp())
        _, _, calls = self._run_main(tmp, lambda: None)
        self.assertEqual(calls, [2], "apply_telemetry 必须被调用，否则测试没测到东西")

    def test_runtime_error_after_backup_names_the_backup(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        rc, err, calls = self._run_main(tmp, lambda: (_ for _ in ()).throw(RuntimeError("模拟写入失败")))
        self.assertEqual(calls, [2])
        self.assertEqual(rc, 2)
        self.assertIn("备份（回滚用）", err)
        self.assertIn("停止前已执行的改动会保留", err)

    def test_keyboard_interrupt_is_handled(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        rc, err, calls = self._run_main(tmp, lambda: (_ for _ in ()).throw(KeyboardInterrupt()))
        self.assertEqual(calls, [2])
        self.assertEqual(rc, 2)
        self.assertIn("已中断", err)
        self.assertIn("不会自动回滚", err)

    def test_backup_only_covers_the_patched_home(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        _, out, _ = self._run_main(tmp, lambda: None)
        # 备份清单里不该出现真实家目录
        self.assertNotIn(str(pathlib.Path.home()), str(tmp / "backups") if False else out)
        manifests = list((tmp / "backups").glob("guard-*/manifest.json"))
        self.assertTrue(manifests, "必须产生了备份")
        items = json.loads(manifests[0].read_text(encoding="utf-8"))["items"]
        for item in items:
            self.assertTrue(item.startswith(str(tmp)), f"备份了家目录之外的文件：{item}")

    def test_failure_before_backup_says_nothing_changed(self):
        # 体检本身失败时走的是另一条分支（audit 在 try 之外会抛 traceback，
        # 这个 bug 就是这条测试抓出来的），消息要同时说清失败原因和「没改动」
        tmp = pathlib.Path(tempfile.mkdtemp())
        err = io.StringIO()
        with mock.patch.object(g, "HOME", tmp), \
             mock.patch.object(g, "BACKUP_ROOT", tmp / "backups"), \
             mock.patch.object(g, "audit", side_effect=OSError("模拟体检失败")), \
             mock.patch.object(g, "print_audit"), \
             mock.patch.object(g.sys, "stdin", mock.Mock(isatty=lambda: True)), \
             mock.patch.object(g.sys, "stdout", io.StringIO()), \
             mock.patch.object(g.sys, "stderr", err):
            rc = g.main([])
        self.assertEqual(rc, 2)
        self.assertIn("体检失败", err.getvalue())
        self.assertIn("没有做任何改动", err.getvalue())
        self.assertEqual(list((tmp / "backups").glob("*")) if (tmp / "backups").exists() else [], [],
                         "体检失败时不该产生任何备份")


class TestNetworkServiceList(unittest.TestCase):
    """networksetup 的禁用服务带星号，且可能有前导空格。
    早期版本在未 strip 的行上判断，会把 '*xxx' 当服务名传下去。"""

    def test_skips_header_starred_and_blank(self):
        fake = (
            "An asterisk (*) denotes that a network service is disabled.\n"
            "Thunderbolt Bridge\n"
            "*Disabled Service\n"
            "  * Leading Space Disabled\n"
            "\n"
            "Wi-Fi\n"
        )
        with mock.patch.object(g, "run", return_value=(0, fake)):
            self.assertEqual(g.list_network_services(), ["Thunderbolt Bridge", "Wi-Fi"])

    def test_returns_empty_when_command_fails(self):
        with mock.patch.object(g, "run", return_value=(1, "")):
            self.assertEqual(g.list_network_services(), [])


class TestWebrtcClassification(unittest.TestCase):
    """WebRTC 只有出现公网地址才算泄漏。而且「没测到」绝不能当成「没泄漏」。

    分类逻辑抽成了纯函数 classify_webrtc_candidates，因为采集那半边要真的起
    headless Chrome、没法在单测里跑。早先分类和采集混在一个函数里，测试只能
    mock 命令行输出，改成 POST 回传之后那套 mock 就整片失效了。
    """

    def test_private_addresses_are_not_a_leak(self):
        r = g.classify_webrtc_candidates(["candidate:1 1 udp 1 192.168.1.5 5000 typ host"])
        self.assertEqual(r["candidates"], 1)
        self.assertEqual(r["leaked_public"], [])
        self.assertTrue(r["local_ips"][0]["private"])

    def test_public_address_is_flagged(self):
        r = g.classify_webrtc_candidates(["candidate:1 1 udp 1 203.0.113.9 5000 typ srflx"])
        self.assertEqual(r["leaked_public"], ["203.0.113.9"])

    def test_mdns_hostname_is_recorded_and_not_a_leak(self):
        # 这台机器的真实现象：只有一条 typ host，主机名被 mDNS 混淆成 .local。
        # 这时候 local_ips 是空的而 mdns 为 True——那是「不泄漏」，不是「没测到」。
        r = g.classify_webrtc_candidates(
            ["candidate:1 1 udp 2113937151 abcd-1234.local 50513 typ host"])
        self.assertEqual(r["candidates"], 1)
        self.assertTrue(r["mdns"])
        self.assertEqual(r["local_ips"], [])
        self.assertEqual(r["leaked_public"], [])
        self.assertEqual(r["note"], "", "有候选就不该说结论不可用")

    def test_zero_candidates_is_inconclusive_not_clean(self):
        # 关键口径：0 候选必须标成「结论不可用」，不能当成「没有泄漏」
        r = g.classify_webrtc_candidates([])
        self.assertEqual(r["leaked_public"], [])
        self.assertIn("不可用", r["note"])

    def test_none_is_handled_like_empty(self):
        self.assertIn("不可用", g.classify_webrtc_candidates(None)["note"])

    def test_candidate_string_with_braces_is_fine(self):
        # 旧实现要从 DOM 里正则抠 JSON，候选串里的花括号会把匹配截断；现在结果
        # 走 JSON POST，不该再有这个坑。留着这条盯着「别退回去抠字符串」。
        r = g.classify_webrtc_candidates(["candidate:1 1 udp 1 10.0.0.1 5000 typ host}"])
        self.assertEqual(r["candidates"], 1)
        self.assertEqual(r["leaked_public"], [])

    def test_public_v6_style_address_note(self):
        # 只认 IPv4；纯 IPv6 候选里没有点分地址，会被当作没有 IP 的候选。
        # 这条记的是当前边界，不是「V6 不泄漏」的结论。
        r = g.classify_webrtc_candidates(["candidate:1 1 udp 1 2001:db8::1 5000 typ host"])
        self.assertEqual(r["local_ips"], [])

    def test_no_browser_gives_manual_path(self):
        with mock.patch.object(g, "find_chromium", return_value=None):
            r = g.check_webrtc()
        self.assertFalse(r["available"])
        self.assertIn("browserleaks.com/webrtc", r["note"])

    def test_check_webrtc_feeds_candidates_into_the_classifier(self):
        """采集那半边必须把拿到的候选交给分类函数，不能自己另写一套判断。"""
        seen = {}

        def fake_classify(raw):
            seen["raw"] = raw
            return {"local_ips": [], "leaked_public": [], "note": "",
                    "candidates": len(raw or []), "mdns": False}

        # 让本地服务一收到 POST 就当完成，跳过真的起浏览器
        import http.server as hs

        class FakeServer:
            def __init__(self, *a, **k):
                self.server_address = ("127.0.0.1", 12345)

            def serve_forever(self):
                return None

            def shutdown(self):
                return None

            def server_close(self):
                return None

        with mock.patch.object(g, "find_chromium", return_value="/fake/chrome"), \
             mock.patch.object(g, "classify_webrtc_candidates", side_effect=fake_classify), \
             mock.patch.object(hs, "ThreadingHTTPServer", FakeServer), \
             mock.patch("subprocess.Popen", side_effect=OSError("不真的起浏览器")):
            r = g.check_webrtc()
        # 起不来浏览器时不该崩，而是给出人工路径
        self.assertFalse(r["available"])
        self.assertIn("browserleaks.com/webrtc", r["note"])


class TestAllowedChanges(unittest.TestCase):
    """有意清理的 shell 配置文件必须进允许清单，
    否则 protected_verify 会把它算成「被连带改动」，退出码变成 3。"""

    def test_rc_cleanup_returns_zero(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        (tmp / ".claude").mkdir()
        (tmp / ".claude" / "settings.json").write_text('{"env": {}}', encoding="utf-8")
        (tmp / ".claude.json").write_text('{}', encoding="utf-8")
        (tmp / ".zshrc").write_text(
            "export EDITOR=vim\nexport HTTPS_PROXY=http://127.0.0.1:7897\n", encoding="utf-8"
        )
        report = {
            "A1_proxy_residue": {"residue": [], "enabled": [], "scutil": {}, "network_services": []},
            "A1_terminal_env": {
                "rc_files": {".zshrc": [{"line": 2, "text": "x"}]},
                "npm": {}, "git": {}, "env_hits": [], "env_info": [],
            },
            "A2_anthropic_base_url": {"hits": []},
            "A5_ipv6": {"services": {}, "global_addresses": []},
        }
        with mock.patch.object(g, "HOME", tmp), \
             mock.patch.object(g, "SETTINGS", tmp / ".claude" / "settings.json"), \
             mock.patch.object(g, "BACKUP_ROOT", tmp / "backups"), \
             mock.patch.object(g, "audit", return_value=report), \
             mock.patch.object(g, "print_audit"), \
             mock.patch.object(g.sys, "stdin", mock.Mock(isatty=lambda: True)), \
             mock.patch("builtins.input", side_effect=["0", "n", "n", "CONFIRM"]), \
             mock.patch.object(g.sys, "stdout", io.StringIO()), \
             mock.patch.object(g.sys, "stderr", io.StringIO()):
            rc = g.main([])
        self.assertEqual(rc, 0, "有意清理 .zshrc 不该被报成受保护文件被改动")
        text = (tmp / ".zshrc").read_text(encoding="utf-8")
        self.assertNotIn("HTTPS_PROXY", text)
        self.assertIn("EDITOR=vim", text, "无关行必须保留")


class TestAuditShape(unittest.TestCase):
    """体检报告的键必须齐全，否则依赖它的 print_audit 会 KeyError。"""

    REQUIRED = (
        "A1_export_ip", "A1_proxy_residue", "A1_terminal_env", "A2_anthropic_base_url",
        "A5_ipv6", "A6_dns", "A9_geo_words", "A10_third_party", "A11_client_integrity",
        "A12_clash_groups", "A13_multi_account", "A15_consistency",
        "A21_timezone_layers", "E1_keychain",
    )

    def test_all_checks_present(self):
        report = g.audit()
        for key in self.REQUIRED:
            self.assertIn(key, report, key)

    def test_proxy_check_exposes_enabled_and_residue(self):
        r = g.check_proxy_residue()
        self.assertIn("enabled", r)
        self.assertIn("residue", r)
        self.assertIn("scutil", r)

    def test_clash_check_never_raises_without_socket(self):
        with mock.patch.object(g, "CLASH_SOCK", pathlib.Path("/nonexistent/sock")):
            r = g.check_clash_groups()
        self.assertFalse(r["reachable"])
        self.assertEqual(r["groups"], [])


class TestTimezoneLayers(unittest.TestCase):
    """T10 + P13：时区要每一层都落在台北，控制它的两道闸都要是「已关」。

    这是纯检测，不做任何改写。H4 的决定是脚本不再自动改系统隐私库，
    所以这里只负责把事实摆出来，改不改由人决定。
    """

    @staticmethod
    def _factory(link="Asia/Taipei", node="Asia/Taipei", log_body="", auto_val="0"):
        def fake_run(cmd, timeout=20):
            if cmd[0] == "readlink":
                return 0, f"/var/db/timezone/zoneinfo/{link}\n"
            if cmd[0] == "node":
                return 0, f"{node}\n"
            if cmd[0] == "log":
                return 0, log_body
            if cmd[0] == "defaults":
                return 0, f"{auto_val}\n"
            return 0, ""

        return fake_run

    @staticmethod
    def _loc(authorized):
        return {"readable": True, "clients": {"com.apple.timed": {"Authorized": authorized}}, "note": ""}

    def test_all_layers_taipei_and_both_gates_closed(self):
        with mock.patch.object(g, "run", side_effect=self._factory()):
            with mock.patch.object(g, "location_service_status", return_value=self._loc(False)):
                r = g.check_timezone_layers()
        self.assertTrue(r["all_taipei"])
        self.assertIs(r["gate_auto_plist"], False)
        self.assertIs(r["gate_location"], False)

    def test_link_taipei_but_process_shanghai_fails(self):
        # 符号链接对了不代表应用读到的就是对的，这两层必须分开看
        with mock.patch.object(g, "run", side_effect=self._factory(node="Asia/Shanghai")):
            with mock.patch.object(g, "location_service_status", return_value=self._loc(False)):
                r = g.check_timezone_layers()
        self.assertFalse(r["all_taipei"])
        self.assertEqual(r["layers"]["new_process"], "Asia/Shanghai")

    def test_historical_shanghai_does_not_flip_the_verdict(self):
        # 回归测试（真实踩过）：6 小时窗口里躺着一小时前的 Asia/Shanghai，
        # 而当前两个活读数都是台北。历史不能当现状，否则天天误报。
        log_body = "2026-10-08 17:51:37.438 Df timed[4137:1269e] [com.apple.timed:data] TZ,computed,result,Asia/Shanghai\n"
        with mock.patch.object(g, "run", side_effect=self._factory(log_body=log_body)):
            with mock.patch.object(g, "location_service_status", return_value=self._loc(False)):
                r = g.check_timezone_layers()
        self.assertTrue(r["all_taipei"])
        self.assertEqual(r["timed_last"], "Asia/Shanghai")
        self.assertEqual(r["timed_last_at"], "2026-10-08 17:51:37")

    def test_last_source_event_wins(self):
        # 回归测试（真实踩过）：同一个窗口里 Available 与 Unavailable 都有时，
        # 必须取时间上最后那条，不能「先匹配到 Available 就算 True」。
        log_body = (
            "2026-10-08 17:51:37.438 Df timed[4137:1269e] [com.apple.timed:data] TZ,setSourceAvailable,src,Location\n"
            "2026-10-08 20:55:50.805 Df timed[4137:4e215] [com.apple.timed:data] TZ,setSourceUnavailable,src,Location\n"
        )
        with mock.patch.object(g, "run", side_effect=self._factory(log_body=log_body)):
            with mock.patch.object(g, "location_service_status", return_value=self._loc(False)):
                r = g.check_timezone_layers()
        self.assertIs(r["source_available"], False)
        self.assertEqual(r["source_event_at"], "2026-10-08 20:55:50")

    def test_newest_computed_wins_when_several_present(self):
        log_body = (
            "2026-10-08 10:00:00.000 Df timed[1:1] [com.apple.timed:data] TZ,computed,result,Asia/Taipei\n"
            "2026-10-08 17:51:37.438 Df timed[1:1] [com.apple.timed:data] TZ,computed,result,Asia/Shanghai\n"
            "2026-10-08 21:00:00.000 Df timed[1:1] [com.apple.timed:data] TZ,computed,result,Asia/Taipei\n"
        )
        with mock.patch.object(g, "run", side_effect=self._factory(log_body=log_body)):
            with mock.patch.object(g, "location_service_status", return_value=self._loc(False)):
                r = g.check_timezone_layers()
        self.assertEqual(r["timed_last"], "Asia/Taipei")

    def test_placeholders_do_not_count_as_wrong_timezone(self):
        # 「(node 不可用)」「(6 小时内无记录)」是没有读数，不是读到了错的时区
        with mock.patch.object(g, "run", side_effect=self._factory(node="", log_body="")):
            with mock.patch.object(g, "location_service_status", return_value=self._loc(False)):
                r = g.check_timezone_layers()
        self.assertTrue(r["all_taipei"])
        self.assertTrue(r["layers"]["new_process"].startswith("("))
        self.assertIsNone(r["timed_last"])

    def test_unreadable_gate_is_none_not_false(self):
        # 关键：读不到**且没有 root 实测缓存**时，绝不能当成「已关」。
        # None 与 False 必须区分开——这里把缓存显式清成 None，
        # 否则真机上那份 root 实测缓存会参与进来（那是另一条路径，另有用例覆盖）。
        status = {"readable": False, "clients": {}, "note": "读不到 clients.plist（需要 root）"}
        with mock.patch.object(g, "load_location_gate_cache", return_value=None):
            with mock.patch.object(g, "run", side_effect=self._factory()):
                with mock.patch.object(g, "location_service_status", return_value=status):
                    r = g.check_timezone_layers()
        self.assertIsNone(r["gate_location"])
        self.assertIn("root", r["gate_location_note"])
        self.assertIsNot(r["gate_location"], False)

    def test_location_gate_open_when_authorized_true(self):
        with mock.patch.object(g, "run", side_effect=self._factory()):
            with mock.patch.object(g, "location_service_status", return_value=self._loc(True)):
                r = g.check_timezone_layers()
        self.assertIs(r["gate_location"], True)

    def test_auto_plist_gate_open(self):
        with mock.patch.object(g, "run", side_effect=self._factory(auto_val="1")):
            with mock.patch.object(g, "location_service_status", return_value=self._loc(False)):
                r = g.check_timezone_layers()
        self.assertIs(r["gate_auto_plist"], True)

    def test_source_availability_parsed_from_timed(self):
        log_body = ("2026-10-08 20:55:50.805 Df timed[4137:4e215] [com.apple.timed:data] "
                    "TZ,setSourceUnavailable,src,Location\n")
        with mock.patch.object(g, "run", side_effect=self._factory(log_body=log_body)):
            with mock.patch.object(g, "location_service_status", return_value=self._loc(False)):
                r = g.check_timezone_layers()
        self.assertIs(r["source_available"], False)


class TestKeychainSvceAcct(unittest.TestCase):
    """P15：svce 与 acct 必须分开看，而且只能在同一条目块内配对。

    早期把 Claude Desktop 的 'Claude Safe Storage' 当成了 CLI 的登录凭据，
    实际上 CLI 的凭据是 svce='Claude Code-credentials'，两者是不同的东西。
    """

    # 与真实 dump-keychain 输出同构：第一条是十六进制属性号写法（服务名只在 hex 里），
    # 第二条和第三条是具名写法。两种都必须能解析出来。
    DUMP = (
        'keychain: "/Users/x/Library/Keychains/login.keychain-db"\n'
        "version: 512\n"
        'class: "genp"\n'
        "attributes:\n"
        '    0x00000007 <blob>="Claude Safe Storage"\n'
        '    "acct"<blob>="Claude Key"\n'
        'keychain: "/Users/x/Library/Keychains/login.keychain-db"\n'
        "version: 512\n"
        'class: "genp"\n'
        "attributes:\n"
        '    "svce"<blob>="Claude Code-credentials"\n'
        '    "acct"<blob>="someuser"\n'
        'keychain: "/Users/x/Library/Keychains/login.keychain-db"\n'
        "version: 512\n"
        'class: "genp"\n'
        "attributes:\n"
        '    "svce"<blob>="Unrelated Service"\n'
        '    "acct"<blob>="someone"\n'
    )

    def test_svce_and_acct_reported_separately(self):
        with mock.patch.object(g, "run", return_value=(0, self.DUMP)):
            r = g.check_keychain()
        pairs = {(it["svce"], it["acct"]) for it in r["items"]}
        self.assertIn(("Claude Safe Storage", "Claude Key"), pairs)
        self.assertIn(("Claude Code-credentials", "someuser"), pairs)

    def test_desktop_and_cli_are_classified_differently(self):
        with mock.patch.object(g, "run", return_value=(0, self.DUMP)):
            r = g.check_keychain()
        by_svce = {it["svce"]: it["kind"] for it in r["items"]}
        self.assertIn("Desktop", by_svce["Claude Safe Storage"])
        self.assertIn("CLI", by_svce["Claude Code-credentials"])

    def test_unrelated_items_excluded(self):
        with mock.patch.object(g, "run", return_value=(0, self.DUMP)):
            r = g.check_keychain()
        self.assertNotIn("Unrelated Service", [it["svce"] for it in r["items"]])

    def test_pairing_is_scoped_to_one_block(self):
        # 回归测试：svce 在前一块、acct 在后一块，绝不能跨块拼成一条。
        # 全局抓取 svce/acct 的写法会在这里出错。
        dump = (
            'keychain: "/a"\nversion: 512\nclass: "genp"\nattributes:\n'
            '    0x00000007 <blob>="Claude Safe Storage"\n'
            'keychain: "/a"\nversion: 512\nclass: "genp"\nattributes:\n'
            '    "acct"<blob>="Claude Key"\n'
        )
        with mock.patch.object(g, "run", return_value=(0, dump)):
            r = g.check_keychain()
        self.assertNotIn(("Claude Safe Storage", "Claude Key"),
                         {(it["svce"], it["acct"]) for it in r["items"]})

    def test_acct_alone_is_enough_to_match(self):
        # 只看 svce 会漏掉；acct 里带 claude 的也要算进来
        dump = 'keychain: "/a"\nclass: "genp"\nattributes:\n    "acct"<blob>="claude-cli-user"\n'
        with mock.patch.object(g, "run", return_value=(0, dump)):
            r = g.check_keychain()
        self.assertEqual(len(r["items"]), 1)
        self.assertEqual(r["items"][0]["acct"], "claude-cli-user")

    def test_unreadable_dumpchain_is_reported(self):
        with mock.patch.object(g, "run", return_value=(1, "")):
            r = g.check_keychain()
        self.assertFalse(r["readable"])
        self.assertTrue(r["note"])


class TestFailClosedVerdict(unittest.TestCase):
    """T12：「绝不直连」能不能成立，两种模式看的东西不一样。

    全局模式下 mihomo 一条规则都不执行，全部流量交给 GLOBAL 组，所以判据落在组上；
    规则模式下规则照常跑，判据落在「Claude 域名有没有被引到专用组」加上兜底是不是
    DIRECT。

    第一版只认 global，把 mode=rule 本身判成故障。而 rule 恰恰是国内直连、国外走
    代理所必需的模式——把用户的选择当成故障，是错的。
    """

    @staticmethod
    def _factory(mode="global", global_now="Claude", ctype="Selector", members=None, hc=False):
        if members is None:
            members = ["美国住宅节点 · 主线"]
        cfg = json.dumps({"mode": mode, "tun": {"enable": True, "strict-route": True}})
        claude = {"type": ctype, "now": members[0] if members else None, "all": members}
        if hc:
            claude["url"] = "http://www.gstatic.com/generate_204"
        proxies = json.dumps({
            "proxies": {
                "GLOBAL": {"type": "Selector", "now": global_now, "all": ["Claude"]},
                "Claude": claude,
            }
        })
        calls = {"n": 0}

        def fake_run(cmd, timeout=20):
            calls["n"] += 1
            return (0, cfg) if calls["n"] == 1 else (0, proxies)

        return fake_run

    def _check(self, **kw):
        with mock.patch.object(g, "CLASH_SOCK", pathlib.Path("/tmp")):
            with mock.patch.object(g, "run", side_effect=self._factory(**kw)):
                return g.check_clash_groups()

    def test_global_pointing_at_single_selector_passes(self):
        r = self._check()
        self.assertTrue(r["fail_closed"]["ok"], r["fail_closed"]["reasons"])
        self.assertEqual(r["global_now"], "Claude")
        self.assertEqual(len(r["claude_group"]["members"]), 1)
        self.assertFalse(r["claude_group"]["healthcheck"])

    def test_global_pointing_elsewhere_fails(self):
        r = self._check(global_now="Proxy")
        self.assertFalse(r["fail_closed"]["ok"])
        self.assertTrue(any("GLOBAL" in x for x in r["fail_closed"]["reasons"]))

    def test_rule_mode_is_judged_on_rules_not_on_global(self):
        # 回归：旧版把 mode=rule 本身判成故障。规则模式下 GLOBAL 指向谁不影响 Claude，
        # 该看的是 Claude 域名有没有被引到专用组。
        r = self._check(mode="rule")
        self.assertFalse(r["fail_closed"]["ok"])       # 这条 _factory 不产 rules，所以判不成立
        self.assertFalse(any("不是全局模式" in x for x in r["fail_closed"]["reasons"]),
                         r["fail_closed"]["reasons"])
        self.assertTrue(any("GLOBAL" not in x for x in r["fail_closed"]["reasons"]))

    def test_fallback_group_fails_even_with_one_member(self):
        # select 才不做健康检查切换；fallback 即使只剩一个成员也可能切走
        r = self._check(ctype="Fallback")
        self.assertFalse(r["fail_closed"]["ok"])
        self.assertTrue(any("select" in x for x in r["fail_closed"]["reasons"]))

    def test_multi_member_select_fails(self):
        r = self._check(members=["美国住宅节点 · 主线", "美国住宅节点 · 备用"])
        self.assertFalse(r["fail_closed"]["ok"])
        self.assertTrue(any("成员" in x for x in r["fail_closed"]["reasons"]))

    def test_healthcheck_flag_is_reported(self):
        # select 组带 url/interval 也不会自动切换，这条只作信息展示，不参与判定
        r = self._check(hc=True)
        self.assertTrue(r["claude_group"]["healthcheck"])
        self.assertTrue(r["fail_closed"]["ok"])


class TestSummaryTable(unittest.TestCase):
    """最终总表是跑完 skill 之后用户唯一会看的东西，它必须对齐、必须不说假话。"""

    def test_disp_width_counts_cjk_as_two(self):
        self.assertEqual(g.disp_width("abc"), 3)
        self.assertEqual(g.disp_width("出口 IP"), 7)      # 出=2 口=2 空格=1 I=1 P=1
        self.assertEqual(g.disp_width("✓"), 1)

    def test_every_table_row_has_equal_display_width(self):
        # 按 len() 对齐的话中文行会歪；这个测试守住按显示宽度算这件事
        table = g.render_table(
            ("检查项", "状态", "说明"),
            [("出口 IP 与归属", "✓", "198.51.100.10  Reston/US"),
             ("时区是否锁在台北", "✗", "localtime=Asia/Shanghai"),
             ("短", "·", "x")],
        )
        widths = {g.disp_width(line) for line in table.splitlines()}
        self.assertEqual(len(widths), 1, f"各行显示宽度不一致：{widths}")

    def test_truncate_respects_display_width(self):
        self.assertEqual(g.truncate("abcdef", 10), "abcdef")
        out = g.truncate("中文中文中文中文", 7)
        self.assertLessEqual(g.disp_width(out), 7)
        self.assertTrue(out.endswith("…"))

    def _report(self, **over):
        base = {
            "A1_export_ip": {"ip": "1.2.3.4", "city": "Reston", "country": "US",
                             "verdict": "疑似住宅/ISP"},
            "A1_proxy_residue": {"enabled": [], "residue": [], "scutil": {}},
            "A1_terminal_env": {"env_hits": [], "rc_files": {}, "npm": {}, "git": {}},
            "A2_anthropic_base_url": {"hits": []},
            "A5_ipv6": {"global_addresses": []},
            "A6_dns": {"fake_ip": True, "real_ip_hosts": []},
            "A10_third_party": {"hits": []},
            "A11_client_integrity": {"cli_version": "2.1.293", "version_count": 4,
                                     "stale_count": 0, "stale_bytes": 0},
            "A12_clash_groups": {"reachable": True, "mode": "global", "global_now": "Claude",
                                 "claude_group": {"now": "主线", "members": ["主线"]},
                                 "fail_closed": {"ok": True, "reasons": []}},
            "A13_multi_account": {"identities": []},
            "A15_consistency": {"tension": []},
            "A21_timezone_layers": {"all_taipei": True, "layers": {"localtime": "Asia/Taipei"},
                                    "gate_auto_plist": False, "gate_location": False},
            "E1_keychain": {"readable": True, "items": []},
        }
        base.update(over)
        return base

    @staticmethod
    def _row(rows, name):
        for r in rows:
            if r[0] == name:
                return r
        raise AssertionError(f"表里没有 {name}")

    def test_clean_report_has_no_unresolved(self):
        rows = g.build_summary(self._report())
        bad = [r for r in rows if r[1] is g.S_BAD]
        self.assertEqual(bad, [], bad)

    def test_fail_closed_failure_is_marked_bad(self):
        r = self._report()
        r["A12_clash_groups"]["fail_closed"] = {"ok": False, "reasons": ["GLOBAL 指向 Proxy"]}
        row = self._row(g.build_summary(r), "绝不直连")
        self.assertIs(row[1], g.S_BAD)
        self.assertIn("GLOBAL 指向 Proxy", row[2])

    def test_timezone_not_taipei_is_marked_bad(self):
        r = self._report()
        r["A21_timezone_layers"]["all_taipei"] = False
        row = self._row(g.build_summary(r), "时区是否锁在台北")
        self.assertIs(row[1], g.S_BAD)

    def test_second_gate_unreadable_is_needs_action_not_ok(self):
        # 读不到 ≠ 已关。这一条踩过坑：把 None 当成 False 会报「两道闸都关了」。
        r = self._report()
        r["A21_timezone_layers"]["gate_location"] = None
        row = self._row(g.build_summary(r), "时区两道闸")
        self.assertIs(row[1], g.S_FIX)
        self.assertIn("读不到", row[2])

    def setUp(self):
        # 挡掉真实机器状态：build_summary 会经 load_media_permission() 读
        # ~/.local/state/claude-guard/media-permission.json，这台机器上真跑过一次 --check-media
        # 复核，于是「没跑探测就该报未测到」的用例会读到真实缓存变成 ✓。这里喂的是构造出来的
        # report，结论就不该被本机状态左右——和 TestWebrtcMediaPermissionExposure 同一个坑。
        p = mock.patch.object(g, "load_media_permission", return_value={})
        p.start()
        self.addCleanup(p.stop)

    def test_other_tools_base_url_is_not_promised_as_cleanable(self):
        # 回归测试：~/.dsh/settings.yaml 的 baseURL 属于别的工具，脚本不会碰它，
        # 表里就不能写「自动清理会清掉」。
        r = self._report()
        r["A2_anthropic_base_url"] = {"hits": [
            {"file": "/Users/x/.dsh/settings.yaml", "line": 10, "text": "baseURL: http://a/v1"}]}
        row = self._row(g.build_summary(r), "settings.json 端点与凭据")
        self.assertIs(row[1], g.S_OK)
        self.assertIn("只报告不代改", row[2])

    def test_own_settings_hit_is_marked_cleanable(self):
        r = self._report()
        r["A2_anthropic_base_url"] = {"hits": [
            {"file": "/Users/x/.claude/settings.json", "line": 3, "text": "ANTHROPIC_BASE_URL"}]}
        row = self._row(g.build_summary(r), "settings.json 端点与凭据")
        self.assertIs(row[1], g.S_FIX)

    def test_missing_webrtc_says_how_to_run_it(self):
        row = self._row(g.build_summary(self._report()), "WebRTC 泄漏")
        self.assertIs(row[1], g.S_NA)
        self.assertIn("--webrtc", row[2])

    def test_local_ids_are_not_counted_as_accounts(self):
        r = self._report()
        r["A13_multi_account"] = {"identities": [{"userID": "a"}, {"machineID": "b"}]}
        row = self._row(g.build_summary(r), "多账号痕迹")
        self.assertIs(row[1], g.S_OK)
        self.assertIn("本地标识", row[2])

    def test_table_never_claims_solved_for_missing_data(self):
        # 空报告：所有项都应是「未测到」，不能因为缺字段就默认通过
        rows = g.build_summary({})
        self.assertFalse([r for r in rows if r[1] is g.S_OK and "未" not in r[2]])


class TestManualCheckList(unittest.TestCase):
    """手工核对清单是给用户抄去用的，命令必须完整、结构必须齐、网站不能写错。"""

    def test_every_item_is_complete(self):
        for group, items in g.MANUAL_CHECKS:
            self.assertTrue(group, "分组名不能为空")
            for title, src, cmds, expect in items:
                self.assertTrue(title, f"{group} 里有条目缺标题")
                self.assertTrue(src, f"{title} 缺出处标记")
                self.assertTrue(cmds, f"{title} 没有命令")
                self.assertTrue(all(c.strip() for c in cmds), f"{title} 有空命令")
                self.assertTrue(expect, f"{title} 没写期望值")

    def test_covers_the_eight_proxy_checks_plus_more(self):
        # 本会话手工跑过的那八项必须都在：系统代理开关、网络服务残留、env、
        # shell 配置、npm/git、brew、settings.json，加上出口 IP
        flat = " ".join(
            cmd for _, items in g.MANUAL_CHECKS for _, _, cmds, _ in items for cmd in cmds)
        for needle in ("scutil --proxy", "networksetup -getwebproxy",
                       "env | grep", "grep -inE", "npm config get proxy",
                       "git config --global --get http.proxy", "brew config",
                       "cat ~/.claude/settings.json"):
            self.assertIn(needle, flat, f"清单里缺了 {needle}")

    def test_keeps_the_article_commands(self):
        flat = " ".join(
            cmd for _, items in g.MANUAL_CHECKS for _, _, cmds, _ in items for cmd in cmds)
        # 文章 2.5 给过的原始命令，应当原样保留
        for needle in ('scutil --proxy | grep -E "HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable"',
                       'env | grep -iE "proxy|anthropic|claude"',
                       "readlink /etc/localtime"):
            self.assertIn(needle, flat, f"文章原命令丢了：{needle}")

    def test_ipv6_command_excludes_loopback(self):
        # 回归测试：不排 ::1 的话 loopback 会被当成全局 IPv6 地址，实测踩过
        flat = " ".join(
            cmd for _, items in g.MANUAL_CHECKS for _, _, cmds, _ in items for cmd in cmds)
        ipv6 = [c for c in flat.split("\n") if "inet6" in c]
        self.assertTrue(ipv6)
        for c in ipv6:
            self.assertIn("::1", c, f"这条没排除 loopback：{c}")

    def test_article_sites_are_listed(self):
        sites = " ".join(urls for _, urls, _ in g.MANUAL_SITES)
        for host in ("ipinfo.io", "ping0.cc", "whoer.net", "ippure.com",
                     "browserleaks.com/webrtc", "browserleaks.com/dns",
                     "status.anthropic.com"):
            self.assertIn(host, sites, f"网站漏了 {host}")

    def test_commands_flag_prints_and_exits_zero(self):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = g.main(["--commands"])
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("出口 IP 与归属", out)
        self.assertIn("browserleaks.com/webrtc", out)

    def test_commands_flag_does_not_run_the_audit(self):
        # --commands 只打印清单，不该顺手做体检（否则在别人的机器上会白等一分钟）
        with mock.patch.object(g, "audit") as spy:
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                g.main(["--commands"])
        spy.assert_not_called()


class TestSudoAsksOnce(unittest.TestCase):
    """用户只该输一次密码。授权还在时绝不能再弹提示。"""

    def test_prime_does_not_prompt_when_alive(self):
        with mock.patch.object(g, "sudo_alive", return_value=True):
            with mock.patch("subprocess.run") as spy:
                g.sudo_prime()
        spy.assert_not_called()

    def test_prime_prompts_when_not_alive(self):
        buf = io.StringIO()
        with mock.patch.object(g, "sudo_alive", return_value=False):
            with mock.patch("subprocess.run") as spy:
                with mock.patch("sys.stdout", buf):
                    g.sudo_prime()
        spy.assert_called_once()
        self.assertEqual(spy.call_args[0][0], ["sudo", "-v"])
        # 必须把「只输这一次」讲清楚，否则用户会以为后面每一步都要输
        self.assertIn("输这一次就够", buf.getvalue())

    def test_ensure_sudo_is_quiet_when_alive(self):
        with mock.patch.object(g, "sudo_alive", return_value=True):
            with mock.patch("subprocess.run") as spy:
                g.ensure_sudo("测试")
        spy.assert_not_called()

    def test_ensure_sudo_reprompts_only_when_expired(self):
        buf = io.StringIO()
        with mock.patch.object(g, "sudo_alive", return_value=False):
            with mock.patch("subprocess.run") as spy:
                with mock.patch("sys.stdout", buf):
                    g.ensure_sudo("关闭定位服务")
        spy.assert_called_once()
        self.assertIn("授权已过期", buf.getvalue())

    def test_backup_primes_before_touching_root_files(self):
        # root 文件的备份也要 root；顺序反了就会在无备份的情况下改动
        calls = []

        def fake_run(cmd, timeout=20):
            calls.append(cmd)
            return 0, ""

        with mock.patch.object(g, "ensure_sudo", side_effect=lambda w: calls.append(["ENSURE"])):
            with mock.patch.object(g, "run", side_effect=fake_run):
                with mock.patch.object(g, "BACKUP_ROOT", pathlib.Path(tempfile.mkdtemp())):
                    with mock.patch.object(g, "protected_snapshot", return_value={}):
                        # 这里的 sudo cp 是 mock 的，文件不会真的存在，
                        # 所以 create_backup 必然因为「空文件」中止——这正是我们要的：
                        # 中止之前它必须先确认过授权。
                        with self.assertRaises(RuntimeError):
                            g.create_backup([], [pathlib.Path("/var/db/locationd/clients.plist")])
        self.assertTrue(calls, "create_backup 应当至少尝试过一次备份")
        self.assertEqual(calls[0], ["ENSURE"], "必须在任何 sudo cp 之前先确认授权")


class TestLocationGate(unittest.TestCase):
    """第二道闸的三态。实机核对过：TimeZone.bundle 没有 Authorized 字段，那就是「已关」。"""

    @staticmethod
    def _status(authorized):
        return {"readable": True, "clients": {"root:p/.../TimeZone.bundle:": {"Authorized": authorized}}}

    def test_absent_authorized_means_gate_is_off(self):
        # 回归测试：把「没有这个字段」当成读不到是错的，它本身就是答案
        self.assertIs(g.location_gate_state(self._status(None)), False)

    def test_false_means_gate_is_off(self):
        self.assertIs(g.location_gate_state(self._status(False)), False)

    def test_true_means_gate_is_on(self):
        self.assertIs(g.location_gate_state(self._status(True)), True)

    def test_unreadable_is_none_not_false(self):
        self.assertIsNone(g.location_gate_state({"readable": False, "clients": {}}))
        self.assertIsNone(g.location_gate_state({"readable": True, "clients": {}}))

    def test_already_off_reports_no_change_and_writes_nothing(self):
        # 已经关着的时候不许去写一个不存在的字段，也不许报「未生效」
        status = {"readable": True, "clients": {"root:p/.../TimeZone.bundle:": {"Authorized": None}}, "note": ""}
        with mock.patch.object(g, "location_service_status", return_value=status):
            with mock.patch.object(g, "run") as spy:
                msg = g.disable_location_timezone()
        spy.assert_not_called()
        self.assertIn("已经是关闭状态", msg)

    def test_write_path_still_verifies_and_raises_when_no_flip(self):
        # 真要去关的时候，复验不到翻转必须报错，不能假装成功
        on = {"readable": True, "clients": {"k": {"Authorized": True}}, "note": ""}
        with mock.patch.object(g, "location_service_status", side_effect=[on, on]):
            with mock.patch.object(g, "run", return_value=(0, "")):
                with self.assertRaises(RuntimeError) as ctx:
                    g.disable_location_timezone()
        self.assertIn("未生效", str(ctx.exception))

    def test_probe_uses_plistlib_not_json_conversion(self):
        # 回归测试：plutil -convert json 在这份 plist 上必然失败（里面有原始字节）
        self.assertIn("plistlib", g.LOCATION_PROBE)
        self.assertNotIn("plutil", g.LOCATION_PROBE)


class TestScheduleConsistency(unittest.TestCase):
    """文章 2.3 末尾：出口美西而你在国内白天 = 美国凌晨还在写代码。只报事实。"""

    def _run(self, exit_tz, ip_tz=True):
        ip = {"timezone": exit_tz} if ip_tz else {}
        def fake(cmd, timeout=20):
            if cmd[0] == "node":
                return 0, "Asia/Taipei\n"
            return 0, ""
        with mock.patch.object(g, "run", side_effect=fake):
            return g.check_schedule_consistency(ip)

    def test_reports_both_sides_and_the_gap(self):
        r = self._run("America/New_York")
        self.assertEqual(r["exit_tz"], "America/New_York")
        self.assertIsNotNone(r["exit_time"])
        self.assertIsNotNone(r["local_time"])
        self.assertIsNotNone(r["gap_hours"])

    def test_missing_exit_timezone_is_skipped_not_guessed(self):
        r = self._run(None, ip_tz=False)
        self.assertIn("跳过", r["note"])
        self.assertIsNone(r["exit_time"])

    def test_unknown_timezone_is_skipped(self):
        r = self._run("Nowhere/Fake")
        self.assertIn("认不出", r["note"])

    def test_deep_night_flag_follows_exit_hour(self):
        r = self._run("America/New_York")
        self.assertEqual(r["deep_night"], 0 <= r["exit_hour"] < 6)


class TestLocalGitCheck(unittest.TestCase):
    """文章 §6 第 11 步 / §9 末条：代码别只存在 Claude 里。"""

    def test_without_project_roots_it_says_how_to_enable(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            r = g.check_local_git()
        self.assertEqual(r["repos"], [])
        self.assertIn("CLAUDE_GUARD_PROJECT_ROOTS", r["note"])

    def test_counts_repos_and_dirty(self):
        root = pathlib.Path(tempfile.mkdtemp())
        for name in ("proj_a", "proj_b", "plain"):
            (root / name).mkdir()
        (root / "proj_a" / ".git").mkdir()
        (root / "proj_b" / ".git").mkdir()
        def fake(cmd, timeout=20):
            return (0, " M x.py\n") if cmd[2].endswith("proj_a") else (0, "")
        with mock.patch.dict("os.environ", {"CLAUDE_GUARD_PROJECT_ROOTS": str(root)}):
            with mock.patch.object(g, "run", side_effect=fake):
                r = g.check_local_git()
        self.assertEqual(len(r["repos"]), 2)
        self.assertEqual(len(r["no_git"]), 1)
        self.assertEqual(len(r["dirty"]), 1)

    def test_missing_root_is_reported(self):
        with mock.patch.dict("os.environ", {"CLAUDE_GUARD_PROJECT_ROOTS": "/nope/nonexistent"}):
            r = g.check_local_git()
        self.assertIn("不存在", r["note"])


class TestBrowserProfiles(unittest.TestCase):
    """文章 2.6：浏览器要单独建一个资料专登 Claude。"""

    def _with_chrome(self, profile_dirs):
        home = pathlib.Path(tempfile.mkdtemp())
        base = home / "Library" / "Application Support" / "Google" / "Chrome"
        base.mkdir(parents=True)
        for name in profile_dirs:
            (base / name).mkdir()
        return home

    def test_single_profile_is_counted(self):
        home = self._with_chrome(["Default"])
        with mock.patch.object(g, "HOME", home):
            r = g.check_browser_profiles()
        self.assertEqual(r["total"], 1)
        self.assertIn("Chrome", r["browsers"])

    def test_multiple_profiles_are_counted(self):
        home = self._with_chrome(["Default", "Profile 1", "Profile 2"])
        with mock.patch.object(g, "HOME", home):
            r = g.check_browser_profiles()
        self.assertEqual(r["total"], 3)

    def test_tcc_block_does_not_crash_or_invent_profiles(self):
        # 实测踩过：iterdir() 被 TCC 挡会抛 PermissionError，
        # 但按固定命名探测 is_dir() 是放行的。这里确认不能因此崩掉或乱报。
        home = self._with_chrome([])
        with mock.patch.object(g, "HOME", home):
            r = g.check_browser_profiles()
        self.assertEqual(r["total"], 0)
        self.assertIn("note", r)


class TestManualActions(unittest.TestCase):
    """人工行动清单：文章里那些脚本替不了的项，必须带可执行的点击路径。"""

    def test_every_item_is_complete(self):
        for group, items in g.MANUAL_ACTIONS:
            self.assertTrue(group)
            for title, src, steps, why in items:
                self.assertTrue(title, f"{group} 有条目缺标题")
                self.assertTrue(src, f"{title} 缺出处")
                self.assertTrue(steps, f"{title} 没有步骤")
                self.assertTrue(all(s.strip() for s in steps), f"{title} 有空步骤")
                self.assertTrue(why, f"{title} 没写为什么")

    def test_covers_the_article_gaps(self):
        flat = " ".join(
            " ".join(steps) + " " + title
            for _, items in g.MANUAL_ACTIONS for title, _, steps, _ in items)
        for needle in ("iPhone", "Windows", "浏览器资料", "Active sessions",
                       "data-privacy-controls", "App Store", "reportaproblem.apple.com",
                       "usersafety@anthropic.com", "CLAUDE.md", "OpenClaw"):
            self.assertIn(needle, flat, f"人工清单里缺了：{needle}")

    def test_manual_flag_prints_and_does_not_audit(self):
        buf = io.StringIO()
        with mock.patch.object(g, "audit") as spy:
            with mock.patch("sys.stdout", buf):
                rc = g.main(["--manual"])
        spy.assert_not_called()
        self.assertEqual(rc, 0)
        self.assertIn("人工行动清单", buf.getvalue())

    def test_new_rows_appear_in_the_table(self):
        rows = {r[0] for r in g.build_summary({
            "A14_local_git": {"repos": [], "no_git": [], "dirty": [], "note": ""},
            "A22_schedule": {"exit_time": "10:00", "local_time": "22:00",
                             "local_tz": "Asia/Taipei", "exit_tz": "America/New_York",
                             "deep_night": False},
            "A23_browser_profiles": {"browsers": {"Chrome": {"count": 2, "names": ["Default", "Profile 1"]}},
                                     "total": 2},
        })}
        self.assertIn("代码是否落在本地 Git", rows)
        self.assertIn("作息与出口时区", rows)
        self.assertIn("浏览器资料是否隔离", rows)

    def test_single_browser_profile_is_flagged(self):
        rows = g.build_summary({"A23_browser_profiles": {
            "browsers": {"Chrome": {"count": 1, "names": ["Default"]}}, "total": 1}})
        row = [r for r in rows if r[0] == "浏览器资料是否隔离"][0]
        self.assertIs(row[1], g.S_FIX)

    def test_deep_night_schedule_is_reported_but_not_a_todo(self):
        # 这条原本断言 S_FIX。但那样一来，同一台机器夜里跑是 ⚠、白天跑是 ✓——
        # 一个随时辰翻转的「待处理」不是待办，用户也没法为它做点什么。
        # 现在只把事实写在结果里，状态保持已解决。
        rows = g.build_summary({"A22_schedule": {
            "exit_time": "03:00", "exit_hour": 3, "local_time": "15:00",
            "local_tz": "Asia/Taipei", "exit_tz": "America/Los_Angeles", "deep_night": True}})
        row = [r for r in rows if r[0] == "作息与出口时区"][0]
        self.assertIs(row[1], g.S_OK, "深夜不该把状态翻成待处理")
        self.assertIn("深夜", row[2])


class TestLocationGateCache(unittest.TestCase):
    """第二道闸要 root 才读得到，所以用失效缓存把 root 实测的结论带回来。

    背景是用户的一句反问：root 都测过了还问我干嘛。答案不该因为
    「这次没提权」就丢掉，也不该反过来把已关说成仍开启。
    """

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.cache = self.tmp / "location-gate.json"
        self._orig = g.LOCATION_GATE_CACHE
        g.LOCATION_GATE_CACHE = self.cache

    def tearDown(self):
        g.LOCATION_GATE_CACHE = self._orig

    def test_round_trip_closed(self):
        g.save_location_gate_cache(False)
        got = g.load_location_gate_cache()
        self.assertIsNotNone(got)
        self.assertIs(got["closed"], True)
        self.assertTrue(got.get("checkedAt"))

    def test_round_trip_open(self):
        g.save_location_gate_cache(True)
        self.assertIs(g.load_location_gate_cache()["closed"], False)

    def test_unknown_state_is_not_cached(self):
        g.save_location_gate_cache(None)
        self.assertFalse(self.cache.exists())

    def test_missing_or_corrupt_cache_returns_none(self):
        self.assertIsNone(g.load_location_gate_cache())
        self.cache.parent.mkdir(parents=True, exist_ok=True)
        self.cache.write_text("{ not json", encoding="utf-8")
        self.assertIsNone(g.load_location_gate_cache())
        self.cache.write_text('{"nope": 1}', encoding="utf-8")
        self.assertIsNone(g.load_location_gate_cache())

    def test_cached_closed_reads_back_as_gate_closed(self):
        # 回归：缓存写的是「闸已关」(closed=true)，而 gate_location 的语义是
        # 「闸还开着」。第一版直接取 bool(closed)，把已关读成了仍开启，
        # 表里报成红色 ✗。这里把这个反向钉死。
        g.save_location_gate_cache(False)
        with mock.patch.object(g, "location_service_status",
                               return_value={"readable": False, "clients": {}, "note": "要 root"}):
            r = g.check_timezone_layers()
        self.assertIs(r["gate_location"], False)
        self.assertTrue(r.get("gate_location_cached"))

    def test_cached_open_reads_back_as_gate_open(self):
        g.save_location_gate_cache(True)
        with mock.patch.object(g, "location_service_status",
                               return_value={"readable": False, "clients": {}, "note": "要 root"}):
            r = g.check_timezone_layers()
        self.assertIs(r["gate_location"], True)

    def test_without_cache_it_still_reports_unknown(self):
        with mock.patch.object(g, "location_service_status",
                               return_value={"readable": False, "clients": {}, "note": "要 root"}):
            r = g.check_timezone_layers()
        self.assertIsNone(r["gate_location"])
        self.assertIn("要 root", r.get("gate_location_note", ""))

    def test_summary_marks_cached_result_as_solved_with_timestamp(self):
        rows = g.build_summary({"A21_timezone_layers": {
            "gate_auto_plist": False, "gate_location": False,
            "gate_location_cached": {"closed": True, "checkedAt": "2026-10-08 22:46"}}})
        row = [r for r in rows if r[0] == "时区两道闸"][0]
        self.assertIs(row[1], g.S_OK)
        self.assertIn("2026-10-08 22:46", row[2])

    def test_summary_without_cache_reports_pending(self):
        rows = g.build_summary({"A21_timezone_layers": {
            "gate_auto_plist": False, "gate_location": None, "gate_location_note": "要 root"}})
        row = [r for r in rows if r[0] == "时区两道闸"][0]
        self.assertIs(row[1], g.S_FIX)

    def test_a_successful_root_read_writes_the_cache(self):
        # location_service_status 是跑 `sudo -n python3 <探针>` 再解析它的 stdout，
        # 所以 mock 的位置在 run()，不是 open()/read_bytes()。第一版打错了位置，
        # 结果是「测试通过与否」和真实读取路径无关。
        body = json.dumps({
            "root:p/System/Library/LocationBundles/TimeZone.bundle:": {
                "BundlePath": "/System/Library/LocationBundles/TimeZone.bundle",
                "LocationTimeStopped": True,
            }})
        with mock.patch.object(g, "run", return_value=(0, body)):
            r = g.location_service_status()
        self.assertTrue(r["clients"], "探针输出没被解析出条目，后面的断言就没意义了")
        self.assertTrue(self.cache.exists())
        self.assertIs(g.load_location_gate_cache()["closed"], True)

    def test_a_root_read_showing_open_writes_closed_false(self):
        body = json.dumps({
            "root:p/System/Library/LocationBundles/TimeZone.bundle:": {"Authorized": True}})
        with mock.patch.object(g, "run", return_value=(0, body)):
            g.location_service_status()
        self.assertIs(g.load_location_gate_cache()["closed"], False)

    def test_a_failed_root_read_does_not_write_a_cache(self):
        with mock.patch.object(g, "run", return_value=(1, "")):
            r = g.location_service_status()
        self.assertFalse(r["readable"])
        self.assertFalse(self.cache.exists())


class TestConsistencyIsASettledChoice(unittest.TestCase):
    """文章 §2.2 让你改台北、§2.3 又要求出口与账单同国，两条本身互斥。

    用户已确认按「台北 + 美国出口」走，这是拍板过的选择不是待办，
    所以不能再挂在「待你处理」里。
    """

    def test_tension_is_not_marked_pending(self):
        rows = g.build_summary({"A15_consistency": {
            "facts": {}, "tension": ["时区在东亚、出口在美国"],
            "verdict": None}})
        row = [r for r in rows if r[0] == "时区／出口／语言一致性"][0]
        self.assertIsNot(row[1], g.S_FIX)
        self.assertIn("已确认", row[2])

    def test_no_tension_still_says_no_conflict(self):
        rows = g.build_summary({"A15_consistency": {"facts": {}, "tension": []}})
        row = [r for r in rows if r[0] == "时区／出口／语言一致性"][0]
        self.assertIs(row[1], g.S_OK)
        self.assertIn("无冲突", row[2])


def _git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd)] + list(args),
                          capture_output=True, text=True)


def _make_repo(path):
    """建一个真的 git 仓库，够用来测工作树行为。"""
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q")
    _git(path, "config", "user.email", "t@example.com")
    _git(path, "config", "user.name", "t")
    (path / "f.txt").write_text("x", encoding="utf-8")
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "init")
    return path


class TestProjectClaudeCheck(unittest.TestCase):
    """项目级 .claude：99% 是真实代码，所以只报事实、只清失效注册。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())

    def test_without_roots_it_says_how_to_enable(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            r = g.check_project_claude()
        self.assertIn("CLAUDE_GUARD_PROJECT_ROOTS", r["note"])

    def test_counts_dirs_and_splits_worktrees_from_the_rest(self):
        proj = self.tmp / "proj"
        _make_repo(proj)
        cdir = proj / ".claude"
        (cdir / "skills").mkdir(parents=True)
        (cdir / "skills" / "a.md").write_text("x" * 100, encoding="utf-8")
        wt = cdir / "worktrees" / "feat"
        _git(proj, "worktree", "add", "-q", "-b", "feat", str(wt))
        (wt / "big.bin").write_bytes(b"0" * 5000)

        with mock.patch.dict("os.environ", {"CLAUDE_GUARD_PROJECT_ROOTS": str(self.tmp)}):
            r = g.check_project_claude()
        self.assertEqual(r["dirs"], 1)
        self.assertGreater(r["worktrees_bytes"], r["other_bytes"])
        self.assertGreaterEqual(r["live_worktrees"], 1)
        self.assertEqual(r["stale_total"], 0)

    def test_detects_stale_registration_after_worktree_is_deleted(self):
        proj = self.tmp / "proj"
        _make_repo(proj)
        (proj / ".claude").mkdir()
        wt = proj / ".claude" / "worktrees" / "gone"
        _git(proj, "worktree", "add", "-q", "-b", "gone", str(wt))
        # 直接删目录，模拟临时路径被系统清掉、注册却留着
        shutil.rmtree(wt)

        with mock.patch.dict("os.environ", {"CLAUDE_GUARD_PROJECT_ROOTS": str(self.tmp)}):
            r = g.check_project_claude()
        self.assertEqual(r["stale_total"], 1)
        self.assertEqual(len(r["repos_with_stale"]), 1)

    def test_worktree_git_files_do_not_inflate_the_count(self):
        # 回归：工作树里的 .git 是**文件**不是目录，用 exists() 判断会把每个
        # 工作树都当成一个仓库、把父仓库的列表重复数一遍——实测报出
        # 「活工作树 1464 个」这种明显不对的数。
        proj = self.tmp / "proj"
        _make_repo(proj)
        (proj / ".claude").mkdir()
        for i in range(3):
            _git(proj, "worktree", "add", "-q", "-b", f"b{i}",
                 str(proj / ".claude" / "worktrees" / f"w{i}"))
        with mock.patch.dict("os.environ", {"CLAUDE_GUARD_PROJECT_ROOTS": str(self.tmp)}):
            r = g.check_project_claude()
        # 一个主仓库 + 3 个工作树
        self.assertEqual(r["live_worktrees"], 4)


class TestPruneStaleWorktrees(unittest.TestCase):
    """唯一能自动做的项目级清理：划掉失效的注册记录，工作树一律不碰。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.repo = _make_repo(self.tmp / "repo")

    def test_removes_stale_and_keeps_live(self):
        live = self.repo / ".claude" / "worktrees" / "live"
        live.parent.mkdir(parents=True)
        _git(self.repo, "worktree", "add", "-q", "-b", "live", str(live))
        gone = self.repo / ".claude" / "worktrees" / "gone"
        _git(self.repo, "worktree", "add", "-q", "-b", "gone", str(gone))
        shutil.rmtree(gone)

        done = g.prune_stale_worktrees([str(self.repo)])
        self.assertEqual(len(done), 1)
        self.assertIsNone(done[0]["error"])
        self.assertEqual(len(done[0]["removed"]), 1)
        self.assertEqual(done[0]["after"], done[0]["before"] - 1)
        # 关键：活的工作树目录必须原样还在
        self.assertTrue(live.is_dir())
        self.assertTrue((live / "f.txt").is_file())

    def test_nothing_stale_reports_no_change(self):
        live = self.repo / ".claude" / "worktrees" / "live"
        live.parent.mkdir(parents=True)
        _git(self.repo, "worktree", "add", "-q", "-b", "live", str(live))
        done = g.prune_stale_worktrees([str(self.repo)])
        self.assertEqual(done[0]["before"], done[0]["after"])
        self.assertEqual(done[0]["removed"], [])

    def test_broken_repo_reports_error_not_crash(self):
        done = g.prune_stale_worktrees([str(self.tmp / "not-a-repo")])
        self.assertEqual(len(done), 1)
        self.assertTrue(done[0]["error"])

    def test_empty_list_is_a_noop(self):
        self.assertEqual(g.prune_stale_worktrees([]), [])


class TestProjectRowsInSummary(unittest.TestCase):
    def test_stale_registrations_mark_the_row_pending(self):
        rows = g.build_summary({"A24_project_claude": {
            "dirs": 55, "total_bytes": 9 * 2 ** 30, "worktrees_bytes": 8.9 * 2 ** 30,
            "stale_total": 20, "repos_with_stale": [{"repo": "/x", "stale": 20}]}})
        row = [r for r in rows if r[0] == "项目级 .claude 规模"][0]
        self.assertIs(row[1], g.S_FIX)
        self.assertIn("20 条", row[2])

    def test_clean_state_is_marked_solved(self):
        rows = g.build_summary({"A24_project_claude": {
            "dirs": 55, "total_bytes": 2 ** 30, "worktrees_bytes": 2 ** 30 - 1,
            "stale_total": 0, "repos_with_stale": []}})
        row = [r for r in rows if r[0] == "项目级 .claude 规模"][0]
        self.assertIs(row[1], g.S_OK)

    def test_no_roots_is_not_tested(self):
        rows = g.build_summary({"A24_project_claude": {"dirs": 0, "note": "未指定项目目录"}})
        row = [r for r in rows if r[0] == "项目级 .claude 规模"][0]
        self.assertIs(row[1], g.S_NA)


class TestPlanCarriesStaleWorktrees(unittest.TestCase):
    def test_plan_lists_repos_and_warns_it_only_edits_the_registry(self):
        report = {
            "A1_proxy_residue": {"residue": []},
            "A1_terminal_env": {"npm": {}, "git": {}, "rc_files": {}, "env_hits": []},
            "A2_anthropic_base_url": {"hits": []},
            "A24_project_claude": {"stale_total": 5, "repos_with_stale": [{"repo": "/r", "stale": 5}]},
        }
        plan = g.auto_clean_plan(report)
        self.assertEqual(plan["stale_worktrees"], ["/r"])
        self.assertTrue(any("不删任何工作树" in s for s in plan["summary"]))

    def test_missing_project_report_is_tolerated(self):
        report = {
            "A1_proxy_residue": {"residue": []},
            "A1_terminal_env": {"npm": {}, "git": {}, "rc_files": {}, "env_hits": []},
            "A2_anthropic_base_url": {"hits": []},
        }
        plan = g.auto_clean_plan(report)
        self.assertEqual(plan["stale_worktrees"], [])


class TestClaudeStorageCheck(unittest.TestCase):
    """系统级可清理量：只认「被取代的版本」和「会自己重建的缓存」。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.versions = self.tmp / "versions"
        self.bundled = self.tmp / "bundled"
        self.data = self.tmp / "data"
        for d in (self.versions, self.bundled, self.data):
            d.mkdir(parents=True, exist_ok=True)
        self._p = [
            (g, "CLI_VERSIONS", self.versions),
            (g, "DESKTOP_BUNDLED", self.bundled),
            (g, "DESKTOP_DATA", self.data),
        ]
        self._orig = [(o, n, getattr(o, n)) for o, n, _ in self._p]
        for o, n, v in self._p:
            setattr(o, n, v)

    def tearDown(self):
        for o, n, v in self._orig:
            setattr(o, n, v)

    def _mk(self, base, name, size=10):
        d = base / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "bin").write_bytes(b"x" * size)
        return d

    def test_stale_versions_are_found_by_pointer_not_by_order(self):
        # 版本号大小是会骗人的：2.1.9 比 2.1.100 小，但字符串排序反过来。
        # 判据必须是「当前在跑的那份」的软链接指向。
        self._mk(self.versions, "2.1.9")
        self._mk(self.versions, "2.1.100", 500)
        self._mk(self.bundled, "2.1.9")
        self._mk(self.bundled, "2.1.100", 700)
        with mock.patch.object(g, "current_cli_version", return_value="2.1.100"):
            r = g.check_claude_storage()
        self.assertEqual([x["name"] for x in r["cli"]["stale"]], ["2.1.9"])
        self.assertEqual([x["name"] for x in r["bundled"]["stale"]], ["2.1.9"])
        self.assertEqual(r["cleanable_bytes"], 20)

    def test_current_version_is_never_listed_as_stale(self):
        self._mk(self.versions, "2.1.293", 999)
        with mock.patch.object(g, "current_cli_version", return_value="2.1.293"):
            r = g.check_claude_storage()
        self.assertEqual(r["cli"]["stale"], [])
        self.assertEqual(r["cleanable_bytes"], 0)

    def test_regenerable_caches_are_listed(self):
        for name in ("Code Cache", "Cache", "GPUCache"):
            (self.data / name).mkdir()
            (self.data / name / "f").write_bytes(b"y" * 100)
        with mock.patch.object(g, "current_cli_version", return_value="2.1.293"):
            r = g.check_claude_storage()
        self.assertEqual({c["name"] for c in r["caches"]}, {"Code Cache", "Cache", "GPUCache"})
        self.assertEqual(r["cleanable_bytes"], 300)

    def test_user_data_is_never_listed(self):
        # Local Storage / IndexedDB / Cookies 这些是账号状态的一部分，不是缓存。
        for name in ("Local Storage", "IndexedDB", "Cookies", "Preferences"):
            (self.data / name).mkdir()
            (self.data / name / "d").write_bytes(b"z" * 999)
        with mock.patch.object(g, "current_cli_version", return_value="2.1.293"):
            r = g.check_claude_storage()
        self.assertEqual(r["caches"], [])
        self.assertEqual(r["cleanable_bytes"], 0)

    def test_missing_install_is_reported_not_crashed(self):
        for o, n, _ in self._p:
            setattr(o, n, self.tmp / "nope")
        with mock.patch.object(g, "current_cli_version", return_value=None):
            r = g.check_claude_storage()
        self.assertIn("跳过", r["note"])


class TestCleanClaudeStorage(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.saved = g.CLI_VERSIONS
        g.CLI_VERSIONS = self.tmp / "versions"
        (g.CLI_VERSIONS / "old").mkdir(parents=True)
        (g.CLI_VERSIONS / "old" / "b").write_bytes(b"x" * 50)
        (g.CLI_VERSIONS / "cur").mkdir()

    def tearDown(self):
        g.CLI_VERSIONS = self.saved

    def test_deletes_only_what_was_listed(self):
        report = {"A25_claude_storage": {"cli": {"stale": [
            {"name": "old", "bytes": 50, "path": str(g.CLI_VERSIONS / "old")}]},
            "bundled": {"stale": []}, "caches": []}}
        done = g.clean_claude_storage(report)
        self.assertEqual(len(done), 1)
        self.assertTrue(done[0]["ok"])
        self.assertFalse((g.CLI_VERSIONS / "old").exists())
        self.assertTrue((g.CLI_VERSIONS / "cur").is_dir(), "当前版本被误删了")

    def test_missing_path_reports_instead_of_crashing(self):
        report = {"A25_claude_storage": {"cli": {"stale": [
            {"name": "gone", "bytes": 1, "path": str(self.tmp / "gone")}]},
            "bundled": {"stale": []}, "caches": []}}
        done = g.clean_claude_storage(report)
        self.assertFalse(done[0]["ok"])
        self.assertIn("不在了", done[0]["error"])

    def test_empty_report_is_a_noop(self):
        self.assertEqual(g.clean_claude_storage({}), [])
        self.assertEqual(g.clean_claude_storage({"A25_claude_storage": {}}), [])


class TestProjectClaudeJunk(unittest.TestCase):
    """项目级 .claude 里对应「系统级可清理类别」的那点东西。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        cdir = self.tmp / "proj" / ".claude"
        (cdir / "skills" / "s").mkdir(parents=True)
        (cdir / ".DS_Store").write_text("x", encoding="utf-8")
        (cdir / "skills" / ".DS_Store").write_text("x", encoding="utf-8")
        (cdir / "skills" / "s" / "run.py").write_text("x", encoding="utf-8")
        pyc = cdir / "skills" / "s" / "__pycache__"
        pyc.mkdir()
        (pyc / "a.pyc").write_bytes(b"p" * 400)
        # 关键：eval 夹具里的 .log 看着像日志，实际是测试数据，不能删
        fx = cdir / "skills" / "s" / "evals" / "fixtures"
        fx.mkdir(parents=True)
        (fx / "run.log").write_text("fixture", encoding="utf-8")
        # worktrees 里是真实代码，也不能碰
        wt = cdir / "worktrees" / "w"
        wt.mkdir(parents=True)
        (wt / ".DS_Store").write_text("x", encoding="utf-8")
        (wt / "real.py").write_text("x", encoding="utf-8")
        self.cdir = cdir

    def _run(self):
        with mock.patch.object(g, "project_roots", return_value=[self.tmp / "proj"]):
            return g.clean_project_claude_junk()

    def test_removes_ds_store_and_pycache(self):
        done = self._run()
        kinds = {d["kind"] for d in done}
        self.assertEqual(kinds, {"ds_store", "pycache"})
        self.assertFalse((self.cdir / ".DS_Store").exists())
        self.assertFalse((self.cdir / "skills" / ".DS_Store").exists())
        self.assertFalse((self.cdir / "skills" / "s" / "__pycache__").exists())

    def test_eval_fixture_logs_survive(self):
        # 回归：本机 294 个 *.log 全在 skills/*/evals/fixtures/ 下，是测试夹具。
        # 如果按后缀扫就会连同它们一起删掉，把 skill 的测试弄坏。
        self._run()
        self.assertTrue((self.cdir / "skills" / "s" / "evals" / "fixtures" / "run.log").is_file())

    def test_worktrees_are_untouched(self):
        self._run()
        self.assertTrue((self.cdir / "worktrees" / "w" / "real.py").is_file())
        self.assertTrue((self.cdir / "worktrees" / "w" / ".DS_Store").exists(),
                        "worktrees 里是真实代码树，不进这一项")

    def test_settings_and_skills_survive(self):
        self._run()
        self.assertTrue((self.cdir / "skills" / "s" / "run.py").is_file())


class TestStorageRowInSummary(unittest.TestCase):
    def test_cleanable_bytes_mark_the_row_pending(self):
        rows = g.build_summary({"A25_claude_storage": {
            "cli": {"current": "2.1.293", "stale": [{"name": "2.1.283", "bytes": 1}]},
            "bundled": {"stale": []}, "caches": [], "cleanable_bytes": 200 * 2 ** 20}})
        row = [r for r in rows if r[0] == "系统级可清理量"][0]
        self.assertIs(row[1], g.S_FIX)
        self.assertIn("2.1.293", row[2])

    def test_nothing_to_clean_is_solved(self):
        rows = g.build_summary({"A25_claude_storage": {
            "cli": {"current": "2.1.293", "stale": []},
            "bundled": {"stale": []}, "caches": [], "cleanable_bytes": 0}})
        row = [r for r in rows if r[0] == "系统级可清理量"][0]
        self.assertIs(row[1], g.S_OK)


class TestPermissionRuleShape(unittest.TestCase):
    """权限条目有两种形态，两种都得认，而且不能把用户的格式改掉。"""

    def test_plain_string(self):
        self.assertEqual(g.permission_rule("Bash(git add *)"), "Bash(git add *)")

    def test_two_element_array(self):
        self.assertEqual(g.permission_rule(["Bash(git add *)", None]), "Bash(git add *)")

    def test_junk_returns_none(self):
        for bad in (None, 42, {}, []):
            self.assertIsNone(g.permission_rule(bad), f"{bad!r} 不该被当成规则")

    def test_unrecognized_shapes_are_left_alone_not_guessed(self):
        # 认不出来的形态一律返回 None = 不判死 = 保留。宁可漏判也不能误删：
        # 删错了是用户的权限没了，漏判只是少清一条。
        for odd in ({"rule": "Bash(a)"}, 42, [42, None], [None]):
            self.assertIsNone(g.permission_rule(odd), f"{odd!r} 认不出来就该放过")

    def test_array_length_is_tolerated(self):
        # 数组只要求首元素是字符串，长度不管：真实格式是 [规则, 元数据]，
        # 以后多一个字段不该让整条被判成认不出来。
        self.assertEqual(g.permission_rule(["Bash(a *)"]), "Bash(a *)")
        self.assertEqual(g.permission_rule(["Bash(a *)", None, "extra"]), "Bash(a *)")


class TestPermissionIsDead(unittest.TestCase):
    def test_wildcards_are_always_alive(self):
        for rule in ("Bash(git add *)", "Bash(pnpm *)", "Read(//Users/x/.ssh/**)"):
            self.assertIsNone(g.permission_is_dead(rule), f"{rule} 带通配，应判活")

    def test_one_off_pid_is_dead(self):
        self.assertEqual(g.permission_is_dead("Bash(kill 2220)"), "一次性的 PID")
        self.assertEqual(g.permission_is_dead("Bash(kill -9 47228 47230)"), "一次性的 PID")

    def test_pkill_is_not_mistaken_for_a_pid(self):
        # pkill 里也含 "kill"，但它是按模式杀，不是一次性 PID
        self.assertIsNone(g.permission_is_dead('Bash(pkill -f "vite")'))

    def test_other_machine_path_is_dead(self):
        self.assertEqual(
            g.permission_is_dead("Bash(chmod +x /Users/someoneelse/dev/x.sh)"),
            "别的机器的路径")

    def test_package_scope_is_not_a_path(self):
        # 回归：`Bash(pnpm --filter @acme/schema build)` 里的 /schema 是包名，
        # 朴素正则会把这条**在用**的权限判死。只认 /Users、/home 这类真文件系统根。
        self.assertIsNone(
            g.permission_is_dead("Bash(pnpm --filter @acme/schema build)"))
        self.assertIsNone(g.permission_is_dead("Bash(bash ./list-devices.sh)"))

    def test_relative_or_temp_paths_are_not_judged(self):
        for rule in ("Bash(tee /tmp/run.log)", "Bash(cat ./a/b/c.txt)"):
            self.assertIsNone(g.permission_is_dead(rule), f"{rule} 不该判死")


class TestCleanDeadPermissions(unittest.TestCase):
    """写回时必须原对象原样放回。这条 bug 真发生过。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self._saved = g.HOME
        g.HOME = self.tmp
        self.f = self.tmp / "proj" / ".claude" / "settings.local.json"
        self.f.parent.mkdir(parents=True)

    def tearDown(self):
        g.HOME = self._saved

    def _write(self, allow):
        self.f.write_text(json.dumps({"permissions": {"allow": allow, "deny": ["Bash(rm -rf /)"]}},
                                     ensure_ascii=False, indent=2), encoding="utf-8")

    def _report(self, rules):
        return {"A26_claude_settings": {"dead": [
            {"file": "proj/.claude/settings.local.json", "rule": r, "why": "一次性的 PID"}
            for r in rules]}}

    def test_dead_entries_go_and_the_rest_stay(self):
        self._write(["Bash(git add *)", "Bash(kill 2220)", "Bash(pnpm *)"])
        done = g.clean_dead_permissions(self._report(["Bash(kill 2220)"]))
        self.assertEqual(done[0]["removed"], 1)
        d = json.loads(self.f.read_text(encoding="utf-8"))
        self.assertEqual(d["permissions"]["allow"], ["Bash(git add *)", "Bash(pnpm *)"])
        self.assertEqual(d["permissions"]["deny"], ["Bash(rm -rf /)"], "deny 不该被动")

    def test_string_entries_stay_strings(self):
        # 回归：第一版写成 keep.append((str(x), r))，元组序列化成 JSON 就是数组，
        # 于是 241 条纯字符串被改写成 209 条 ["Bash(...)", null]。JSON 照样能解析、
        # 肉眼也像对的，但格式已经不是用户的格式了。
        self._write(["Bash(git add *)", "Bash(kill 2220)"])
        g.clean_dead_permissions(self._report(["Bash(kill 2220)"]))
        d = json.loads(self.f.read_text(encoding="utf-8"))
        self.assertTrue(all(isinstance(x, str) for x in d["permissions"]["allow"]),
                        "字符串条目被改成了数组")

    def test_array_entries_stay_arrays(self):
        self._write([["Bash(git add *)", None], ["Bash(kill 2220)", None]])
        g.clean_dead_permissions(self._report(["Bash(kill 2220)"]))
        d = json.loads(self.f.read_text(encoding="utf-8"))
        allow = d["permissions"]["allow"]
        self.assertEqual(len(allow), 1)
        self.assertIsInstance(allow[0], list, "数组条目被改成了字符串")
        self.assertEqual(allow[0][0], "Bash(git add *)")

    def test_mixed_shapes_survive_together(self):
        self._write(["Bash(a *)", ["Bash(b *)", None], "Bash(kill 1)"])
        g.clean_dead_permissions(self._report(["Bash(kill 1)"]))
        d = json.loads(self.f.read_text(encoding="utf-8"))
        self.assertEqual(d["permissions"]["allow"], ["Bash(a *)", ["Bash(b *)", None]])

    def test_missing_file_reports_instead_of_crashing(self):
        done = g.clean_dead_permissions(self._report(["Bash(kill 1)"]))
        self.assertEqual(done[0]["removed"], 0)
        self.assertTrue(done[0]["error"])

    def test_nothing_dead_is_a_noop(self):
        self.assertEqual(g.clean_dead_permissions({"A26_claude_settings": {"dead": []}}), [])
        self.assertEqual(g.clean_dead_permissions({}), [])
        self.assertFalse(self.f.exists(), "没有死条目时不该建文件")


class TestRiskyStandingGrants(unittest.TestCase):
    def test_ssh_read_and_pkill_are_flagged(self):
        for rule in ("Read(//Users/x/.ssh/**)", 'Bash(pkill -f "vite")',
                     "Bash(curl:*)", "Bash(kill:*)", "Bash(ssh prod)", "Bash(scp a b)"):
            self.assertTrue(g.RISKY_PERM_RE.search(rule), f"{rule} 应被判为偏危险")

    def test_ordinary_grants_are_not_flagged(self):
        for rule in ("Bash(git add *)", "Bash(pnpm install)", "Read(//Users/x/dev/**)"):
            self.assertIsNone(g.RISKY_PERM_RE.search(rule), f"{rule} 不该被判为危险")


class TestSettingsRowInSummary(unittest.TestCase):
    def test_dead_entries_mark_the_row_pending(self):
        rows = g.build_summary({"A26_claude_settings": {
            "files": 8, "total": 900, "dead": [{"file": "a", "rule": "x", "why": "y"}],
            "risky": []}})
        row = [r for r in rows if r[0] == "settings 失效权限"][0]
        self.assertIs(row[1], g.S_FIX)

    def test_no_dead_entries_is_solved(self):
        rows = g.build_summary({"A26_claude_settings": {
            "files": 15, "total": 987, "dead": [], "risky": [{"file": "a", "rule": "x"}]}})
        row = [r for r in rows if r[0] == "settings 失效权限"][0]
        self.assertIs(row[1], g.S_OK)
        self.assertIn("偏危险", row[2])


class TestFailClosedIsModeAware(unittest.TestCase):
    """绝不直连的判定必须两种模式都认。

    第一版写死「必须 global」，于是 mode=rule 被直接判成故障——而 rule 正是
    「国内直连、国外走代理」所必需的模式。把用户的选择判成问题是错的。
    """

    def _mk(self, mode, proxies, rules=None):
        return (mode, proxies, rules)

    def _patch(self, mode, proxies, rules):
        """把 check_clash_groups 依赖的三个 API 换成固定响应。"""
        import json as _json
        self._calls = []

        def fake_run(cmd, *a, **k):
            target = cmd[-1]
            if target.endswith("/configs"):
                return (0, _json.dumps({"mode": mode, "tun": {}}))
            if target.endswith("/proxies"):
                return (0, _json.dumps({"proxies": proxies}))
            if target.endswith("/rules"):
                return (0, _json.dumps({"rules": rules or []}))
            return (1, "")

        self._orig_run = g.run
        self._orig_sock = g.CLASH_SOCK
        g.run = fake_run
        g.CLASH_SOCK = pathlib.Path("/dev/null")

    def setUp(self):
        self._orig_run = g.run
        self._orig_sock = g.CLASH_SOCK

    def tearDown(self):
        g.run = self._orig_run
        g.CLASH_SOCK = self._orig_sock

    CLAUDE_OK = {"Claude": {"type": "Selector", "now": "N1", "all": ["N1"]},
                 "GLOBAL": {"type": "Selector", "now": "Claude", "all": ["Claude"]}}

    def test_rule_mode_with_dedicated_rules_passes(self):
        rules = [{"type": "DomainSuffix", "payload": "anthropic.com", "proxy": "Claude"},
                 {"type": "Match", "payload": "", "proxy": "Residential"}]
        self._patch("rule", dict(self.CLAUDE_OK), rules)
        self.assertTrue(g.check_clash_groups()["fail_closed"]["ok"])

    def test_rule_mode_is_not_itself_a_problem(self):
        # 回归：旧版把 mode=rule 直接当故障
        rules = [{"type": "DomainSuffix", "payload": "claude.ai", "proxy": "Claude"},
                 {"type": "Match", "payload": "", "proxy": "Residential"}]
        self._patch("rule", dict(self.CLAUDE_OK), rules)
        reasons = g.check_clash_groups()["fail_closed"]["reasons"]
        self.assertFalse([r for r in reasons if "不是全局模式" in r], reasons)

    def test_rule_mode_without_claude_rules_fails(self):
        rules = [{"type": "Match", "payload": "", "proxy": "Residential"}]
        self._patch("rule", dict(self.CLAUDE_OK), rules)
        fc = g.check_clash_groups()["fail_closed"]
        self.assertFalse(fc["ok"])
        self.assertTrue(any("没有" in r and "Claude 域名" in r for r in fc["reasons"]), fc["reasons"])

    def test_rule_mode_with_direct_fallback_fails(self):
        rules = [{"type": "DomainSuffix", "payload": "anthropic.com", "proxy": "Claude"},
                 {"type": "Match", "payload": "", "proxy": "DIRECT"}]
        self._patch("rule", dict(self.CLAUDE_OK), rules)
        fc = g.check_clash_groups()["fail_closed"]
        self.assertFalse(fc["ok"])
        self.assertTrue(any("兜底规则是 DIRECT" in r for r in fc["reasons"]))

    def test_rule_mode_claude_routed_elsewhere_fails(self):
        rules = [{"type": "DomainSuffix", "payload": "anthropic.com", "proxy": "Residential"},
                 {"type": "Match", "payload": "", "proxy": "Residential"}]
        self._patch("rule", dict(self.CLAUDE_OK), rules)
        fc = g.check_clash_groups()["fail_closed"]
        self.assertFalse(fc["ok"])
        self.assertTrue(any("而不是专用组" in r for r in fc["reasons"]))

    def test_global_mode_needs_global_to_point_at_claude(self):
        prox = {"Claude": {"type": "Selector", "now": "N1", "all": ["N1"]},
                "GLOBAL": {"type": "Selector", "now": "N1", "all": ["N1"]}}
        self._patch("global", prox, [])
        fc = g.check_clash_groups()["fail_closed"]
        self.assertFalse(fc["ok"])
        self.assertTrue(any("GLOBAL" in r for r in fc["reasons"]))

    def test_healthcheck_on_a_selector_does_not_break_the_verdict(self):
        # select 组写了 url/interval 只是拿来显示延迟，mihomo 的 select 不做健康检查
        # 切换。所以这条只作信息，不参与判定。（我一度把它写成判据，被旧用例挡下。）
        prox = {"Claude": {"type": "Selector", "now": "N1", "all": ["N1"], "url": "http://x"},
                "GLOBAL": {"type": "Selector", "now": "Claude", "all": ["Claude"]}}
        rules = [{"type": "DomainSuffix", "payload": "claude.ai", "proxy": "Claude"},
                 {"type": "Match", "payload": "", "proxy": "Residential"}]
        self._patch("rule", prox, rules)
        r = g.check_clash_groups()
        self.assertTrue(r["claude_group"]["healthcheck"], "这个标志还是要报出来")
        self.assertTrue(r["fail_closed"]["ok"], r["fail_closed"]["reasons"])

    def test_fallback_type_on_claude_group_fails(self):
        prox = {"Claude": {"type": "Fallback", "now": "N1", "all": ["N1"]},
                "GLOBAL": {"type": "Selector", "now": "Claude", "all": ["Claude"]}}
        rules = [{"type": "DomainSuffix", "payload": "claude.ai", "proxy": "Claude"},
                 {"type": "Match", "payload": "", "proxy": "Residential"}]
        self._patch("rule", prox, rules)
        fc = g.check_clash_groups()["fail_closed"]
        self.assertFalse(fc["ok"])
        self.assertTrue(any("select" in r for r in fc["reasons"]), fc["reasons"])

    def test_multi_member_claude_group_fails(self):
        prox = {"Claude": {"type": "Selector", "now": "N1", "all": ["N1", "N2"]},
                "GLOBAL": {"type": "Selector", "now": "Claude", "all": ["Claude"]}}
        rules = [{"type": "DomainSuffix", "payload": "claude.ai", "proxy": "Claude"},
                 {"type": "Match", "payload": "", "proxy": "Residential"}]
        self._patch("rule", prox, rules)
        fc = g.check_clash_groups()["fail_closed"]
        self.assertFalse(fc["ok"])
        self.assertTrue(any("成员" in r for r in fc["reasons"]))

    def test_statsigapi_is_recognized_as_a_claude_rule(self):
        # 回归：只按域名关键词过滤会漏掉这条——名字里既没有 anthropic 也没有 claude
        rules = [{"type": "DomainSuffix", "payload": "statsigapi.net", "proxy": "Claude"},
                 {"type": "Match", "payload": "", "proxy": "Residential"}]
        self._patch("rule", dict(self.CLAUDE_OK), rules)
        got = g.check_clash_groups()["claude_rules"]
        self.assertEqual([r["payload"] for r in got], ["statsigapi.net"])


class TestGeoSourceConflict(unittest.TestCase):
    """同一个出口 IP 在不同地理库上落在不同城市——这件事必须报出来。"""

    def test_row_shows_conflict_when_two_libraries_disagree(self):
        rows = g.build_summary({"A1_export_ip": {
            "ip": "1.2.3.4", "city": "New York City", "country": "US",
            "verdict": "疑似住宅/ISP", "geo_conflict": "New York City / Dallas"}})
        row = [r for r in rows if r[0] == "出口 IP 与归属"][0]
        self.assertIn("地理库打架", row[2])
        self.assertIn("Dallas", row[2])

    def test_row_has_no_conflict_note_when_libraries_agree(self):
        rows = g.build_summary({"A1_export_ip": {
            "ip": "1.2.3.4", "city": "Dallas", "country": "US",
            "verdict": "疑似住宅/ISP"}})
        row = [r for r in rows if r[0] == "出口 IP 与归属"][0]
        self.assertNotIn("打架", row[2])


class TestScheduleRowIsReportOnly(unittest.TestCase):
    """作息那行只报事实，不翻状态。

    第一版会在「出口当地是深夜」时标成待处理，于是同一台机器隔几个小时跑一次，
    结论就在 ✓ 和 ⚠ 之间来回跳。一个随时辰变化的「待处理」不是待办。
    """

    def _row(self, **kw):
        rep = {"A22_schedule": {"local_tz": "Asia/Taipei", "local_time": "12:00",
                                "exit_tz": "America/New_York", "exit_time": "00:00",
                                "deep_night": False}}
        rep["A22_schedule"].update(kw)
        return [r for r in g.build_summary(rep) if r[0] == "作息与出口时区"][0]

    def test_daytime_at_exit_is_solved(self):
        row = self._row(deep_night=False, exit_time="12:00")
        self.assertIs(row[1], g.S_OK)

    def test_deep_night_at_exit_is_still_solved_but_says_so(self):
        row = self._row(deep_night=True, exit_time="00:00")
        self.assertIs(row[1], g.S_OK, "深夜不该把状态翻成待处理")
        self.assertIn("深夜", row[2])
        self.assertIn("只影响画像", row[2])

    def test_missing_data_is_not_solved(self):
        rows = g.build_summary({"A22_schedule": {"note": "取不到出口时区"}})
        row = [r for r in rows if r[0] == "作息与出口时区"][0]
        self.assertIs(row[1], g.S_NA)


class TestWebrtcMediaPermissionExposure(unittest.TestCase):
    """Chrome 只在页面**没有**摄像头/麦克风权限时才做 mDNS 混淆。

    所以「WebRTC 不泄漏」这句话只对没授权的情况成立。实测同一台机器：
      无权限 -> 1 个候选，全是 .local
      有权限 -> 4 个候选，露出 192.168.1.5（en0）和 198.18.0.1（Clash 的 utun1024）
    """

    def setUp(self):
        # 必须挡掉真实缓存。build_summary 经 load_media_permission() 读
        # ~/.local/state/claude-guard/media-permission.json，机器上真跑过一次 --check-media
        # 复核之后，那两个「没有复核结果就该报待处理」的用例会读到真实缓存变成 S_OK——
        # 它们此前只是**因为缓存不存在**才通过，属于假通过。缓存本来就是这台机器该有的状态，
        # 所以隔离放在这里，而不是反过来把断言改成迁就环境。
        p = mock.patch.object(g, "load_media_permission", return_value={})
        p.start()
        self.addCleanup(p.stop)

    def test_row_turns_green_when_the_browser_confirmed_denied(self):
        # 用户在真实浏览器里复核过、结论是「网站拿不到权限」时，这一行该转绿并注明复核时间；
        # 否则一个已经修好的项会永远挂在「待处理」里。
        with mock.patch.object(g, "load_media_permission",
                               return_value={"ok": True, "checkedAt": "2026-10-09 17:18",
                                             "camera": "denied", "microphone": "denied"}):
            row = self._row({"A7_webrtc": {
                "available": True, "candidates": 1, "mdns": True,
                "local_ips": [], "leaked_public": [], "tun_leak": [],
                "browser": "/x/chromium-1234/Google Chrome for Testing",
                "with_media": {"candidates": 5, "media": "granted",
                               "local_ips": [{"ip": "192.168.1.5", "private": True},
                                             {"ip": "198.18.0.1", "private": True}],
                               "leaked_public": [], "tun_leak": ["198.18.0.1"], "mdns": False}}})
        self.assertIs(row[1], g.S_OK)
        self.assertIn("2026-10-09 17:18", row[2])

    def test_row_uses_the_media_cache_when_the_probe_was_not_run(self):
        # 完整流程不带 --webrtc 时不跑探测，但复核过的结论该直接用来判这一行；
        # 否则用户刚修好的项会在流程末尾的复检表里又退回成「未探测」。
        with mock.patch.object(g, "load_media_permission",
                               return_value={"ok": True, "checkedAt": "2026-10-09 17:18"}):
            row = self._row({})
        self.assertIs(row[1], g.S_OK)
        self.assertIn("2026-10-09 17:18", row[2])

    def test_row_stays_unmeasured_without_probe_and_without_cache(self):
        # setUp 已把缓存挡成空：既没跑探测、也没复核过，就只能如实说未测到
        row = self._row({})
        self.assertIs(row[1], g.S_NA)

    def test_media_candidates_expose_lan_and_tun(self):
        raw = [
            "candidate:1 1 udp 2122260223 192.168.1.5 57543 typ host",
            "candidate:2 1 udp 2122194687 198.18.0.1 58419 typ host",
        ]
        r = g.classify_webrtc_candidates(raw)
        self.assertEqual([e["ip"] for e in r["local_ips"]], ["192.168.1.5", "198.18.0.1"])
        self.assertEqual(r["tun_leak"], ["198.18.0.1"])

    def test_tun_range_follows_the_configured_fake_ip_range(self):
        # 判据读的是 Clash 配置里的 fake-ip-range，不是写死的常数。本机配置是
        # 198.18.0.1/16，所以只有 198.18.x 算 TUN；198.19.x 不在这个段里。
        # （旧版写死 198.18+198.19 覆盖了 /15，比实际配置宽。）
        with mock.patch.object(g, "_FAKE_IP_CACHE", ("198.18.",)):
            r = g.classify_webrtc_candidates([
                "candidate:1 1 udp 1 198.18.0.1 5000 typ host",
                "candidate:2 1 udp 1 198.19.7.7 5000 typ host",
            ])
        self.assertEqual(r["tun_leak"], ["198.18.0.1"])

    def test_tun_range_changes_when_config_changes(self):
        # 换一个 fake-ip 段，判据要跟着走——写死的话这里会漏判，而且漏得静默
        with mock.patch.object(g, "_FAKE_IP_CACHE", ("172.19.",)):
            r = g.classify_webrtc_candidates([
                "candidate:1 1 udp 1 172.19.0.1 5000 typ host",
                "candidate:2 1 udp 1 198.18.0.1 5000 typ host",
            ])
        self.assertEqual(r["tun_leak"], ["172.19.0.1"])

    def test_dns_fake_prefix_follows_config_too(self):
        with mock.patch.object(g, "_FAKE_IP_CACHE", ("172.19.",)):
            self.assertTrue("172.19.5.5".startswith(g.fake_ip_prefixes()))
            self.assertFalse("198.18.0.126".startswith(g.fake_ip_prefixes()))

    def test_ordinary_private_address_is_not_a_tun_leak(self):
        r = g.classify_webrtc_candidates(["candidate:1 1 udp 1 192.168.1.5 5000 typ host"])
        self.assertEqual(r["tun_leak"], [])
        self.assertEqual(r["local_ips"][0]["ip"], "192.168.1.5")

    def test_mdns_only_pass_has_no_tun_leak(self):
        r = g.classify_webrtc_candidates(
            ["candidate:1 1 udp 2113937151 abcd-1234.local 50513 typ host"])
        self.assertEqual(r["tun_leak"], [])
        self.assertEqual(r["local_ips"], [])

    def _row(self, report):
        return [r for r in g.build_summary(report) if r[0] == "WebRTC 泄漏"][0]

    def test_row_flags_tun_leak_as_pending(self):
        row = self._row({"A7_webrtc": {
            "available": True, "candidates": 1, "mdns": True,
            "local_ips": [], "leaked_public": [], "tun_leak": [],
            "browser": "/x/chromium-1234/Google Chrome for Testing",
            "with_media": {"candidates": 4, "media": "granted",
                           "local_ips": [{"ip": "192.168.1.5", "private": True},
                                         {"ip": "198.18.0.1", "private": True}],
                           "leaked_public": [], "tun_leak": ["198.18.0.1"], "mdns": False}}})
        self.assertIs(row[1], g.S_FIX)
        self.assertIn("198.18.0.1", row[2])
        self.assertIn("mDNS", row[2])

    def test_row_flags_plain_lan_leak_as_pending(self):
        row = self._row({"A7_webrtc": {
            "available": True, "candidates": 1, "mdns": True,
            "local_ips": [], "leaked_public": [], "tun_leak": [],
            "browser": "/x/chromium-1234/Google Chrome for Testing",
            "with_media": {"candidates": 4, "media": "granted",
                           "local_ips": [{"ip": "10.0.0.9", "private": True}],
                           "leaked_public": [], "tun_leak": [], "mdns": False}}})
        self.assertIs(row[1], g.S_FIX)
        self.assertIn("10.0.0.9", row[2])

    def test_headless_shell_result_is_marked_as_half_a_conclusion(self):
        # headless shell 给不出真实地址，所以它说「不泄漏」只能算半个结论，必须写明
        row = self._row({"A7_webrtc": {
            "available": True, "candidates": 1, "mdns": True, "local_ips": [],
            "leaked_public": [], "tun_leak": [],
            "browser": "/x/chromium_headless_shell-1234/chrome-headless-shell-mac-arm64/chrome-headless-shell",
            "with_media": {"candidates": 1, "media": "granted", "local_ips": [],
                           "leaked_public": [], "tun_leak": [], "mdns": True}}})
        self.assertIs(row[1], g.S_OK)
        self.assertIn("headless shell", row[2])

    def test_public_leak_still_wins(self):
        row = self._row({"A7_webrtc": {
            "available": True, "candidates": 1, "mdns": False,
            "local_ips": [{"ip": "203.0.113.9", "private": False}],
            "leaked_public": ["203.0.113.9"], "tun_leak": [],
            "browser": "/x/Google Chrome for Testing", "with_media": {}}})
        self.assertIs(row[1], g.S_BAD)


class TestChromiumPreference(unittest.TestCase):
    """完整版要排在 headless shell 前面——后者在 WebRTC 上会漏报。"""

    def test_headless_shell_is_detected(self):
        self.assertTrue(g.chromium_is_headless_shell(
            "/x/chromium_headless_shell-1234/chrome-headless-shell-mac-arm64/chrome-headless-shell"))
        self.assertFalse(g.chromium_is_headless_shell(
            "/x/chromium-1234/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"))
        self.assertFalse(g.chromium_is_headless_shell(None))

    def test_full_chromium_is_preferred_over_headless_shell(self):
        picked = g.find_chromium()
        if picked:
            self.assertFalse(g.chromium_is_headless_shell(picked),
                             f"应当优先完整版，实际选中了 {picked}")


class TestFakeIpPrefixFallback(unittest.TestCase):
    """读不到 Clash 配置时要退回默认值，不能报错也不能返回空。"""

    def test_falls_back_to_mihomo_default(self):
        with mock.patch.object(g, "HOME", pathlib.Path("/nonexistent-home")), \
             mock.patch.object(g, "CLASH_SOCK", pathlib.Path("/nonexistent.sock")), \
             mock.patch.object(g, "_FAKE_IP_CACHE", None):
            self.assertEqual(g.fake_ip_prefixes(), ("198.18.", "198.19."))

    def test_cache_is_reused(self):
        with mock.patch.object(g, "_read_fake_ip_prefixes", side_effect=[("10.9.",)]) as m:
            with mock.patch.object(g, "_FAKE_IP_CACHE", None):
                self.assertEqual(g.fake_ip_prefixes(), ("10.9.",))
                self.assertEqual(g.fake_ip_prefixes(), ("10.9.",))
        self.assertEqual(m.call_count, 1, "第二次该走缓存，不该重复读文件")


class TestClashDnsResolvers(unittest.TestCase):
    """A6 的另一半：Clash 的 DNS 查询交给了谁。

    这一项是补漏。原来的 check_dns 只看「域名有没有解析成 fake-IP」，那只证明 TUN 劫持
    生效，看不到解析器是谁——泄漏恰好藏在后者。2026-10-09 换成 住宅代理订阅后，profile
    自带的主解析器是阿里 223.5.5.5 且 respect-rules 整个丢了；用户拿 browserleaks.com/dns
    查出 25 个解析器里混着阿里杭州和联通北京，而 skill 当时报的是绿灯。
    """

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cdir = (self.tmp / "Library/Application Support"
                     / "io.github.clash-verge-rev.clash-verge-rev")
        self.cdir.mkdir(parents=True)

    def _write(self, cfg):
        import yaml
        (self.cdir / "clash-verge.yaml").write_text(
            yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")

    def test_resolver_classification(self):
        for entry in ("223.5.5.5", "https://dns.alidns.com/dns-query",
                      "tls://223.5.5.5:853", "119.29.29.29", "114.114.114.114",
                      "https://doh.pub/dns-query"):
            self.assertTrue(g._resolver_is_cn(entry), entry)
        for entry in ("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query",
                      "tls://9.9.9.9:853", "2606:4700:4700::1111", ""):
            self.assertFalse(g._resolver_is_cn(entry), entry)

    def test_cn_main_nameserver_is_a_leak(self):
        self._write({"dns": {
            "nameserver": ["https://dns.alidns.com/dns-query", "223.5.5.5"],
            "nameserver-policy": {"geosite:cn,private": ["223.5.5.5"]}}})
        with mock.patch.object(g, "HOME", self.tmp):
            c = g.check_clash_dns()
        self.assertTrue(c["found"])
        self.assertEqual(c["leaking"],
                         ["https://dns.alidns.com/dns-query", "223.5.5.5"])
        self.assertFalse(c["respect_rules"])
        self.assertTrue(c["leak"])

    def test_cn_policy_is_not_a_leak(self):
        # 把 geosite:cn,private 指向国内 DNS 是对的：国内域名本来就不该绕出去解析。
        # 第一版如果把 policy 也算成泄漏，就会把正确的配置报成故障。
        self._write({"dns": {
            "nameserver": list(g.FOREIGN_NAMESERVERS),
            "respect-rules": True,
            "nameserver-policy": {"geosite:cn,private": ["223.5.5.5"]}}})
        with mock.patch.object(g, "HOME", self.tmp):
            c = g.check_clash_dns()
        self.assertEqual(c["leaking"], [])
        self.assertEqual(c["policy_cn"], ["223.5.5.5"])
        self.assertTrue(c["respect_rules"])
        self.assertFalse(c["leak"])

    def test_unreadable_config_reports_not_found(self):
        with mock.patch.object(g, "HOME", self.tmp):
            c = g.check_clash_dns()
        self.assertFalse(c["found"], "读不到配置必须报未检测，不能默认成干净")

    def test_foreign_resolver_without_respect_rules_still_needs_fix(self):
        # 境外解析器 + 没有 respect-rules：查询仍从真实 IP 直发，在墙内还会直接被拦
        rep = {"A6_dns": {"clash": {"found": True, "leaking": [],
                                    "respect_rules": False}}}
        self.assertTrue(g.clash_dns_leaking(rep))

    def test_not_found_never_counts_as_needing_fix(self):
        rep = {"A6_dns": {"clash": {"found": False}}}
        self.assertFalse(g.clash_dns_leaking(rep))


class TestClashDnsEnabledAndHijack(unittest.TestCase):
    """文章 2.5 ③ 给的排查入口是「检查 Clash 配置里 DNS 是否开启、dns-hijack 是否生效」。

    这两条原来是漏的——检查手册里让人查的东西自己没查。2026-10-10 补。
    坑：`dns-hijack` 不在 dns 块里，它是 tun 的子键。
    """

    CLEAN_DNS = {"nameserver": list(g.FOREIGN_NAMESERVERS), "respect-rules": True}

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cdir = (self.tmp / "Library/Application Support"
                     / "io.github.clash-verge-rev.clash-verge-rev")
        self.cdir.mkdir(parents=True)

    def _write(self, cfg):
        import yaml
        (self.cdir / "clash-verge.yaml").write_text(
            yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")

    def _check(self):
        with mock.patch.object(g, "HOME", self.tmp):
            return g.check_clash_dns()

    def _leaking(self, cfg):
        self._write(cfg)
        return g.clash_dns_leaking({"A6_dns": {"clash": self._check()}})

    def test_dns_disabled_is_a_leak(self):
        self._write({"dns": dict(self.CLEAN_DNS, enable=False),
                     "tun": {"enable": True, "dns-hijack": list(g.DNS_HIJACK)}})
        self.assertIs(self._check()["enabled"], False)
        self.assertTrue(g.clash_dns_leaking({"A6_dns": {"clash": self._check()}}))

    def test_enable_absent_is_not_flagged(self):
        # 没写 enable 用的是内核默认，不该被当成「关掉了」
        self._write({"dns": dict(self.CLEAN_DNS)})
        self.assertIsNone(self._check()["enabled"])
        self.assertFalse(g.clash_dns_leaking({"A6_dns": {"clash": self._check()}}))

    def test_tun_without_dns_hijack_is_a_leak(self):
        self.assertTrue(self._leaking({"dns": dict(self.CLEAN_DNS),
                                       "tun": {"enable": True}}))

    def test_hijack_present_is_fine(self):
        self.assertFalse(self._leaking({
            "dns": dict(self.CLEAN_DNS),
            "tun": {"enable": True, "dns-hijack": list(g.DNS_HIJACK)}}))

    def test_hijack_not_required_when_tun_is_off(self):
        # 不走 TUN 的部署（纯系统代理）本来就没有那张虚拟网卡，缺 dns-hijack 是正常的
        self.assertFalse(self._leaking({"dns": dict(self.CLEAN_DNS),
                                        "tun": {"enable": False}}))

    def test_hijack_is_read_from_tun_not_dns(self):
        # dns-hijack 挂在 tun 底下。找错地方会永远报「没配」，这是很容易犯的一个错。
        self._write({"dns": dict(self.CLEAN_DNS, **{"dns-hijack": list(g.DNS_HIJACK)}),
                     "tun": {"enable": True}})
        self.assertEqual(self._check()["hijack"], [], "dns 块里的同名键不是这个设置")
        self.assertTrue(g.clash_dns_leaking({"A6_dns": {"clash": self._check()}}))

    def test_row_flags_disabled_dns(self):
        rows = g.build_summary({"A6_dns": {
            "fake_ip": True, "real_ip_hosts": [], "system_dns": [],
            "clash": {"found": True, "leaking": [], "respect_rules": True,
                      "enabled": False, "nameserver": list(g.FOREIGN_NAMESERVERS)}}})
        row = [r for r in rows if r[0] == "DNS 泄漏"][0]
        self.assertIs(row[1], g.S_FIX)
        self.assertIn("dns.enable", row[2])

    def test_row_flags_missing_hijack(self):
        rows = g.build_summary({"A6_dns": {
            "fake_ip": True, "real_ip_hosts": [], "system_dns": [],
            "clash": {"found": True, "leaking": [], "respect_rules": True,
                      "tun_enabled": True, "hijack": [],
                      "nameserver": list(g.FOREIGN_NAMESERVERS)}}})
        row = [r for r in rows if r[0] == "DNS 泄漏"][0]
        self.assertIs(row[1], g.S_FIX)
        self.assertIn("dns-hijack", row[2])

    def test_row_still_solved_when_tun_off_and_no_hijack(self):
        rows = g.build_summary({"A6_dns": {
            "fake_ip": True, "real_ip_hosts": [], "system_dns": [],
            "clash": {"found": True, "leaking": [], "respect_rules": True,
                      "tun_enabled": False, "hijack": [],
                      "nameserver": list(g.FOREIGN_NAMESERVERS)}}})
        row = [r for r in rows if r[0] == "DNS 泄漏"][0]
        self.assertIs(row[1], g.S_OK)


class TestClearClashDnsLeak(unittest.TestCase):
    """修的时候要改两处，而且写进增强文件的必须是完整的 dns 块。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cdir = (self.tmp / "Library/Application Support"
                     / "io.github.clash-verge-rev.clash-verge-rev")
        (self.cdir / "profiles").mkdir(parents=True)
        self.merge = self.cdir / "profiles" / "mTESTmerge.yaml"

    def _seed(self, with_merge=True):
        import yaml
        (self.cdir / "clash-verge.yaml").write_text(yaml.safe_dump({
            "dns": {
                "enable": True, "enhanced-mode": "fake-ip",
                "fake-ip-range": "198.18.0.1/16",
                "fake-ip-filter": ["*.lan", "+.pool.ntp.org"],
                "nameserver": ["https://dns.alidns.com/dns-query", "223.5.5.5"],
                "nameserver-policy": {"geosite:cn,private": ["223.5.5.5"]},
            },
            "tun": {"enable": True},
        }, allow_unicode=True), encoding="utf-8")
        if with_merge:
            self.merge.write_text(
                "# Profile Enhancement Merge Template for Clash Verge\n", encoding="utf-8")
            (self.cdir / "profiles.yaml").write_text(yaml.safe_dump({
                "current": "PROF1",
                "items": [{"uid": "PROF1", "option": {"merge": "mTESTmerge"}}],
            }), encoding="utf-8")

    def _read(self, p):
        import yaml
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}

    def test_fixes_generated_config(self):
        self._seed()
        with mock.patch.object(g, "HOME", self.tmp), \
             mock.patch.object(g, "run", return_value=(0, "204")):
            msg = g.clear_clash_dns_leak({})
        dns = self._read(self.cdir / "clash-verge.yaml")["dns"]
        self.assertEqual(dns["nameserver"], list(g.FOREIGN_NAMESERVERS))
        self.assertTrue(dns["respect-rules"])
        self.assertIn("内核已重载", msg)

    def test_merge_keeps_the_whole_dns_block(self):
        # Verge 的 Merge 到底是深合并还是浅合并没有公开保证。浅合并时整个 dns 块会被
        # 替换掉，只写 nameserver / respect-rules 会把 enable、fake-ip-range、
        # fake-ip-filter 全打没，DNS 直接废掉。所以必须写完整块。
        self._seed()
        with mock.patch.object(g, "HOME", self.tmp), \
             mock.patch.object(g, "run", return_value=(0, "204")):
            g.clear_clash_dns_leak({})
        mdns = self._read(self.merge)["dns"]
        for key in ("enable", "enhanced-mode", "fake-ip-range", "fake-ip-filter",
                    "nameserver", "nameserver-policy", "respect-rules"):
            self.assertIn(key, mdns, "增强文件里少了 " + key + "——浅合并会把它打没")
        self.assertEqual(mdns["nameserver"], list(g.FOREIGN_NAMESERVERS))
        self.assertEqual(mdns["fake-ip-filter"], ["*.lan", "+.pool.ntp.org"])

    def test_cn_policy_survives_the_fix(self):
        self._seed()
        with mock.patch.object(g, "HOME", self.tmp), \
             mock.patch.object(g, "run", return_value=(0, "204")):
            g.clear_clash_dns_leak({})
        dns = self._read(self.cdir / "clash-verge.yaml")["dns"]
        self.assertEqual(dns["nameserver-policy"],
                         {"geosite:cn,private": ["223.5.5.5"]})

    def test_tun_block_keeps_its_keys_and_gains_hijack(self):
        # 这条原本断言 tun 块原样不动。2026-10-10 补 dns.enable / dns-hijack 之后语义
        # 变了：TUN 开着却没有 dns-hijack 本身就是泄漏，会被补上。tun 里原有的键仍不许动。
        self._seed()
        with mock.patch.object(g, "HOME", self.tmp), \
             mock.patch.object(g, "run", return_value=(0, "204")):
            g.clear_clash_dns_leak({})
        tun = self._read(self.cdir / "clash-verge.yaml")["tun"]
        self.assertIs(tun["enable"], True, "补 hijack 不能把 tun 里原有的键打掉")
        self.assertEqual(tun["dns-hijack"], list(g.DNS_HIJACK))

    def test_clear_adds_dns_hijack_and_persists_the_whole_tun_block(self):
        self._seed()
        with mock.patch.object(g, "HOME", self.tmp), \
             mock.patch.object(g, "run", return_value=(0, "204")):
            msg = g.clear_clash_dns_leak({})
        self.assertIn("dns-hijack", msg)
        # 增强文件里也要写完整的 tun 块：浅合并时只写 dns-hijack 会把 enable 打没，
        # TUN 直接掉线，那比原来的泄漏严重得多。
        mtun = self._read(self.merge)["tun"]
        self.assertEqual(mtun["dns-hijack"], list(g.DNS_HIJACK))
        self.assertIs(mtun["enable"], True)

    def test_clear_does_not_invent_hijack_when_tun_is_off(self):
        # 纯系统代理的部署没有 TUN 网卡，不该被塞一个 dns-hijack 进去
        self._seed()
        cfg = self._read(self.cdir / "clash-verge.yaml")
        cfg["tun"] = {"enable": False}
        import yaml
        (self.cdir / "clash-verge.yaml").write_text(
            yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
        with mock.patch.object(g, "HOME", self.tmp), \
             mock.patch.object(g, "run", return_value=(0, "204")):
            g.clear_clash_dns_leak({})
        self.assertEqual(self._read(self.cdir / "clash-verge.yaml")["tun"],
                         {"enable": False})

    def test_clear_turns_dns_back_on(self):
        self._seed()
        cfg = self._read(self.cdir / "clash-verge.yaml")
        cfg["dns"]["enable"] = False
        import yaml
        (self.cdir / "clash-verge.yaml").write_text(
            yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
        with mock.patch.object(g, "HOME", self.tmp), \
             mock.patch.object(g, "run", return_value=(0, "204")):
            msg = g.clear_clash_dns_leak({})
        self.assertIs(self._read(self.cdir / "clash-verge.yaml")["dns"]["enable"], True)
        self.assertIn("dns.enable", msg)

    def test_clean_config_is_a_noop(self):
        import yaml
        (self.cdir / "clash-verge.yaml").write_text(yaml.safe_dump({
            "dns": {"nameserver": list(g.FOREIGN_NAMESERVERS),
                    "respect-rules": True}}), encoding="utf-8")
        with mock.patch.object(g, "HOME", self.tmp), \
             mock.patch.object(g, "run", return_value=(0, "204")) as m:
            msg = g.clear_clash_dns_leak({})
        self.assertIn("无需改动", msg)
        m.assert_not_called()

    def test_refuses_when_dns_block_absent(self):
        import yaml
        (self.cdir / "clash-verge.yaml").write_text(
            yaml.safe_dump({"tun": {"enable": True}}), encoding="utf-8")
        with mock.patch.object(g, "HOME", self.tmp):
            with self.assertRaises(RuntimeError) as ctx:
                g.clear_clash_dns_leak({})
        self.assertIn("dns", str(ctx.exception))

    def test_refuses_when_config_absent(self):
        with mock.patch.object(g, "HOME", self.tmp):
            with self.assertRaises(RuntimeError) as ctx:
                g.clear_clash_dns_leak({})
        self.assertIn("找不到", str(ctx.exception))


class TestDnsResolverRowInSummary(unittest.TestCase):
    """表里那一行要能反映解析器状态，而不是只看 fake-ip。"""

    def _row(self, dn):
        rows = g.build_summary({"A6_dns": dn})
        return [r for r in rows if r[0] == "DNS 泄漏"][0]

    def test_cn_resolver_marks_the_row_pending(self):
        row = self._row({"fake_ip": True, "real_ip_hosts": [], "system_dns": [],
                         "clash": {"found": True, "leaking": ["223.5.5.5"],
                                   "respect_rules": True,
                                   "nameserver": ["223.5.5.5"]}})
        self.assertIs(row[1], g.S_FIX)
        self.assertIn("223.5.5.5", row[2])

    def test_missing_respect_rules_marks_the_row_pending(self):
        row = self._row({"fake_ip": True, "real_ip_hosts": [], "system_dns": [],
                         "clash": {"found": True, "leaking": [],
                                   "respect_rules": False,
                                   "nameserver": list(g.FOREIGN_NAMESERVERS)}})
        self.assertIs(row[1], g.S_FIX)
        self.assertIn("respect-rules", row[2])

    def test_clean_resolvers_are_solved(self):
        row = self._row({"fake_ip": True, "real_ip_hosts": [], "system_dns": [],
                         "clash": {"found": True, "leaking": [],
                                   "respect_rules": True,
                                   "nameserver": list(g.FOREIGN_NAMESERVERS)}})
        self.assertIs(row[1], g.S_OK)
        self.assertIn("1.1.1.1", row[2])

    def test_real_ip_still_wins_over_resolver_state(self):
        # 解析出真实公网 IP 是更硬的信号，不能被「解析器干净」盖过去
        row = self._row({"fake_ip": False, "real_ip_hosts": ["claude.ai"],
                         "system_dns": [],
                         "clash": {"found": True, "leaking": [],
                                   "respect_rules": True}})
        self.assertIs(row[1], g.S_BAD)

    def test_no_clash_data_still_reports_fake_ip_state(self):
        row = self._row({"fake_ip": True, "real_ip_hosts": [], "system_dns": []})
        self.assertIs(row[1], g.S_OK)


class TestClashDnsFallback(unittest.TestCase):
    """fallback 里的国内解析器同样是泄漏。

    mihomo 是把 nameserver 和 fallback **同时**查的（查完再按 fallback-filter 挑结果），
    所以 fallback 里的国内解析器照样会收到国外域名的查询。只扫 nameserver 会漏掉它。
    """

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cdir = (self.tmp / "Library/Application Support"
                     / "io.github.clash-verge-rev.clash-verge-rev")
        (self.cdir / "profiles").mkdir(parents=True)

    def _write(self, dns):
        import yaml
        (self.cdir / "clash-verge.yaml").write_text(
            yaml.safe_dump({"dns": dns}, allow_unicode=True), encoding="utf-8")

    def test_cn_fallback_is_detected(self):
        self._write({"nameserver": list(g.FOREIGN_NAMESERVERS),
                     "fallback": ["223.5.5.5", "https://dns.alidns.com/dns-query"],
                     "respect-rules": True})
        with mock.patch.object(g, "HOME", self.tmp):
            c = g.check_clash_dns()
        self.assertEqual(c["leaking"], [], "主解析器是干净的")
        self.assertEqual(c["leaking_fallback"],
                         ["223.5.5.5", "https://dns.alidns.com/dns-query"])
        self.assertTrue(c["leak"], "fallback 里放国内解析器同样是泄漏")

    def test_doh_pub_is_recognised_as_cn(self):
        # 腾讯 DNSPod 的 DoH 端点。第一版只写了 dnspod 没写 doh.pub，测试直接抓出来了。
        self.assertTrue(g._resolver_is_cn("https://doh.pub/dns-query"))
        self.assertTrue(g._resolver_is_cn("https://sm2.doh.pub/dns-query"))
        self.assertFalse(g._resolver_is_cn("https://dns.google/dns-query"))

    def test_cn_fallback_marks_row_pending(self):
        rows = g.build_summary({"A6_dns": {
            "fake_ip": True, "real_ip_hosts": [], "system_dns": [],
            "clash": {"found": True, "leaking": [], "leaking_fallback": ["223.5.5.5"],
                      "respect_rules": True,
                      "nameserver": list(g.FOREIGN_NAMESERVERS)}}})
        row = [r for r in rows if r[0] == "DNS 泄漏"][0]
        self.assertIs(row[1], g.S_FIX)
        self.assertIn("fallback", row[2])

    def test_fallback_replaced_when_dirty(self):
        self._write({"enable": True, "nameserver": list(g.FOREIGN_NAMESERVERS),
                     "fallback": ["223.5.5.5"], "respect-rules": True})
        with mock.patch.object(g, "HOME", self.tmp), \
             mock.patch.object(g, "run", return_value=(0, "204")):
            g.clear_clash_dns_leak({})
        import yaml
        dns = yaml.safe_load((self.cdir / "clash-verge.yaml").read_text(
            encoding="utf-8"))["dns"]
        self.assertEqual(dns["fallback"], list(g.FOREIGN_FALLBACK))

    def test_fallback_absent_is_not_invented(self):
        # 订阅本来没配 fallback 时不该凭空加一个键——那是它的机制，不是我们的
        self._write({"enable": True, "nameserver": ["223.5.5.5"]})
        with mock.patch.object(g, "HOME", self.tmp), \
             mock.patch.object(g, "run", return_value=(0, "204")):
            g.clear_clash_dns_leak({})
        import yaml
        dns = yaml.safe_load((self.cdir / "clash-verge.yaml").read_text(
            encoding="utf-8"))["dns"]
        self.assertNotIn("fallback", dns)
        self.assertEqual(dns["nameserver"], list(g.FOREIGN_NAMESERVERS))


class TestHandBackOwnership(unittest.TestCase):
    """sudo 之下写完状态必须把属主还回去。

    背景是真实事故：2026-10-08 22:46 用管理员权限跑定位服务检查，把
    ~/.local/state/claude-guard/ 建成了 root:staff（drwxr-xr-x），用户进程从此
    写不进去。几天后媒体权限复核拿到了正确结果，却在落盘那一步报
    `[Errno 13] Permission denied: .../media-permission.json` 静默丢掉，WebRTC 那一行
    就一直挂在「待处理」上；而 root 拥有的目录连 mv 都搬不动（rename 要改它自己的
    `..` 项），只能再提权一次 chown 回来。这里把这个行为钉住，别再犯。
    """

    def _run(self, euid, env, path_exists=True):
        import account_guard as g
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="guard-owner-"))
        path = tmp / "state" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        if path_exists:
            path.write_text("{}", encoding="utf-8")
        calls = []
        with mock.patch.object(g.os, "geteuid", return_value=euid), \
             mock.patch.object(g.os, "chown",
                               side_effect=lambda p, u, gi: calls.append((str(p), u, gi))), \
             mock.patch.object(g.os, "environ", env):
            g.hand_back_ownership(path)
        return calls, path.parent, tmp

    def test_non_root_does_nothing(self):
        calls, _, tmp = self._run(501, {"SUDO_UID": "501", "SUDO_GID": "20"})
        self.assertEqual(calls, [])
        shutil.rmtree(tmp, ignore_errors=True)

    def test_root_without_sudo_uid_does_nothing(self):
        # 真以 root 登录跑时没有 SUDO_UID，这时不该乱 chown
        calls, _, tmp = self._run(0, {})
        self.assertEqual(calls, [])
        shutil.rmtree(tmp, ignore_errors=True)

    def test_root_with_sudo_uid_hands_both_back(self):
        calls, parent, tmp = self._run(0, {"SUDO_UID": "501", "SUDO_GID": "20"})
        self.assertEqual([(u, gi) for _, u, gi in calls], [(501, 20), (501, 20)])
        self.assertIn(str(parent), [p for p, _, _ in calls])
        shutil.rmtree(tmp, ignore_errors=True)

    def test_missing_file_only_chowns_the_dir(self):
        # 挡住后续写入的是目录本身，即使文件还没生成也要把目录交还
        calls, parent, tmp = self._run(0, {"SUDO_UID": "501", "SUDO_GID": "20"},
                                       path_exists=False)
        self.assertEqual([p for p, _, _ in calls], [str(parent)])
        shutil.rmtree(tmp, ignore_errors=True)

    def test_chown_failure_is_swallowed(self):
        # 交还属主只是善后，失败不能把整个流程炸掉
        import account_guard as g
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="guard-owner-"))
        path = tmp / "state" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
        with mock.patch.object(g.os, "geteuid", return_value=0), \
             mock.patch.object(g.os, "chown", side_effect=PermissionError("nope")), \
             mock.patch.object(g.os, "environ", {"SUDO_UID": "501", "SUDO_GID": "20"}):
            g.hand_back_ownership(path)
        shutil.rmtree(tmp, ignore_errors=True)


class TestIsCnLocale(unittest.TestCase):
    """A27：ippure 那一项只给大陆简体计分。

    港台也讲中文，但 zh-TW / zh-HK 在那一页上不等于「中国用户」。把它们
    判成命中，等于拿一个正确的设置去报错。
    """

    def test_mainland_simplified_is_flagged(self):
        for loc in ("zh-CN", "zh-Hans-CN", "zh-Hans", "zh", "zh_CN", "ZH-CN"):
            self.assertTrue(g.is_cn_locale(loc), loc)

    def test_hongkong_taiwan_are_not_flagged(self):
        for loc in ("zh-TW", "zh-HK", "zh-Hant-TW", "zh-Hant", "zh-MO"):
            self.assertFalse(g.is_cn_locale(loc), loc)

    def test_non_chinese_and_empty(self):
        for loc in ("en-US", "ja-JP", None, ""):
            self.assertFalse(g.is_cn_locale(loc), repr(loc))


class TestPredictIntlLocale(unittest.TestCase):
    """由 AppleLanguages 推 Chrome 会报什么 Intl locale。

    这条映射是实测来的，不是查文档来的：临时资料起真 Chrome，系统
    AppleLanguages=(zh-Hans-US, en-US, en-US) 时 Intl 报的就是 zh-CN。
    """

    def test_real_machine_pair(self):
        self.assertEqual(g.predict_intl_locale("zh-Hans-US"), "zh-CN")
        self.assertEqual(g.predict_intl_locale("en-US"), "en-US")

    def test_traditional_goes_to_taipei(self):
        self.assertEqual(g.predict_intl_locale("zh-Hant-TW"), "zh-TW")

    def test_empty(self):
        self.assertIsNone(g.predict_intl_locale(None))
        self.assertIsNone(g.predict_intl_locale(""))


class TestCheckBrowserLocale(unittest.TestCase):
    """谁是权威、谁只是推定，必须分清楚——推定值不能冒充实测。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cache = self.tmp / "browser-locale.json"
        # 模块级路径常量改不动：测试要直接把 LOCALE_CACHE 换成临时路径，
        # 只 patch HOME 是没用的（它在 import 那一刻就定死了）。
        p = mock.patch.object(g, "LOCALE_CACHE", self.cache)
        p.start()
        self.addCleanup(p.stop)

    def _fake_run(self, app_override=None, system=("zh-Hans-US", "en-US", "en-US")):
        def fake(cmd, **kw):
            if cmd[:3] == ["defaults", "read", "-g"]:
                return 0, json.dumps(list(system))
            if cmd[:2] == ["defaults", "read"]:
                if app_override is None:
                    return 1, ("The domain/default pair of (com.google.Chrome, "
                               "AppleLanguages) does not exist")
                body = "(\n" + ",\n".join(f'    "{t}"' for t in app_override) + "\n)"
                return 0, body
            return 0, ""
        return fake

    def test_prediction_used_when_no_browser_check(self):
        with mock.patch.object(g, "run", side_effect=self._fake_run()):
            out = g.check_browser_locale({"country": "US"})
        self.assertEqual(out["measured"], "zh-CN")
        self.assertIn("推定", out["source"])
        self.assertTrue(out["cn"])
        self.assertEqual(out["target"], "en-US")

    def test_measured_value_beats_the_prediction(self):
        self.cache.write_text(
            json.dumps({"intlLocale": "en-US", "checkedAt": "2026-10-10 12:00"}), encoding="utf-8")
        with mock.patch.object(g, "run", side_effect=self._fake_run()):
            out = g.check_browser_locale({"country": "US"})
        self.assertEqual(out["measured"], "en-US")
        self.assertEqual(out["source"], "浏览器实测")
        self.assertFalse(out["cn"])

    def test_app_override_wins_over_the_system_languages(self):
        with mock.patch.object(g, "run", side_effect=self._fake_run(app_override=["en-US"])):
            out = g.check_browser_locale({"country": "US"})
        self.assertEqual(out["app_override"], ["en-US"])
        self.assertEqual(out["measured"], "en-US")
        self.assertFalse(out["cn"])
        self.assertIn("Chrome 应用语言已被设为", " ".join(out["facts"]))

    def test_nothing_readable_stays_unmeasured(self):
        """读不到就得说没测到，不能默认成干净。"""
        with mock.patch.object(g, "run",
                               side_effect=self._fake_run(app_override=None, system=())):
            out = g.check_browser_locale({"country": "US"})
        self.assertIsNone(out["measured"])
        self.assertIsNone(out["source"])
        self.assertFalse(out["cn"])

    def test_cn_exit_still_gets_a_target_locale(self):
        with mock.patch.object(g, "run", side_effect=self._fake_run(app_override=["zh-CN"])):
            out = g.check_browser_locale({"country": "CN"})
        self.assertTrue(out["cn"])
        self.assertEqual(out["target"], g.DEFAULT_LOCALE)


class TestBrowserLocaleRowInSummary(unittest.TestCase):
    """表里那一行要能反映真实状态，而不是有字段就报绿。"""

    def _row(self, bl):
        rows = g.build_summary({"A27_browser_locale": bl})
        return [r for r in rows if r[0] == "浏览器 Intl 区域设置"][0]

    def test_missing_key_says_not_measured(self):
        rows = g.build_summary({})
        row = [r for r in rows if r[0] == "浏览器 Intl 区域设置"][0]
        self.assertIs(row[1], g.S_NA)
        self.assertIn("未检测", row[2])

    def test_cn_locale_with_us_exit_is_pending(self):
        row = self._row({"measured": "zh-CN", "source": "浏览器实测", "cn": True,
                         "country": "US", "target": "en-US"})
        self.assertIs(row[1], g.S_FIX)
        self.assertIn("zh-CN", row[2])
        self.assertIn("en-US", row[2])

    def test_cn_exit_is_not_pending(self):
        row = self._row({"measured": "zh-CN", "source": "浏览器实测", "cn": True,
                         "country": "CN", "target": "en-US"})
        self.assertIs(row[1], g.S_OK)

    def test_hongkong_locale_is_solved(self):
        row = self._row({"measured": "zh-HK", "source": "浏览器实测", "cn": False,
                         "country": "US", "target": "en-US"})
        self.assertIs(row[1], g.S_OK)

    def test_fixed_but_not_restarted_is_still_pending(self):
        """值改对了、Chrome 没重启，这时浏览器报的还是旧值——不能报绿。"""
        row = self._row({"measured": "en-US", "source": "按 AppleLanguages 推定",
                         "cn": False, "country": "US", "target": "en-US",
                         "needs_restart": True})
        self.assertIs(row[1], g.S_FIX)
        self.assertIn("退出", row[2])

    def test_unmeasured_is_not_solved(self):
        row = self._row({"measured": None, "source": None, "cn": False, "country": "US"})
        self.assertIs(row[1], g.S_NA)
        self.assertIn("没测到", row[2])


class TestClearBrowserLocale(unittest.TestCase):
    """自动修复：只动 Chrome 的应用语言，不动系统语言。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.rollback = self.tmp / "rollback.json"
        for name, val in (("LOCALE_ROLLBACK_FILE", self.rollback),
                          ("LOCALE_CACHE", self.tmp / "cache.json")):
            p = mock.patch.object(g, name, val)
            p.start()
            self.addCleanup(p.stop)

    def test_clean_value_is_a_noop(self):
        with mock.patch.object(g, "run") as m:
            msg = g.clear_browser_locale({"cn": False, "measured": "en-US"})
        self.assertIn("无需改动", msg)
        m.assert_not_called()

    def test_writes_the_domain_and_verifies(self):
        written = {}

        def fake(cmd, **kw):
            if cmd[:2] == ["defaults", "write"]:
                written["args"] = cmd
                return 0, ""
            if cmd[:2] == ["defaults", "read"]:
                return (0, '(\n    "en-US"\n)') if written else (1, "does not exist")
            return 0, ""

        with mock.patch.object(g, "run", side_effect=fake):
            msg = g.clear_browser_locale({"cn": True, "target": "en-US",
                                          "app_override": None, "measured": "zh-CN"})
        self.assertEqual(written["args"][:5], ["defaults", "write",
                                               g.CHROME_APP_DOMAIN, "AppleLanguages", "-array"])
        self.assertEqual(written["args"][5], "en-US")
        self.assertIn("完全退出", msg)
        note = json.loads(self.rollback.read_text(encoding="utf-8"))
        self.assertIsNone(note["before"])
        self.assertIn("defaults delete", note["rollback"])

    def test_existing_override_is_restored_in_the_rollback(self):
        def fake(cmd, **kw):
            if cmd[:2] == ["defaults", "read"]:
                return 0, '(\n    "en-US"\n)'
            return 0, ""

        with mock.patch.object(g, "run", side_effect=fake):
            g.clear_browser_locale({"cn": True, "target": "en-US",
                                    "app_override": ["fr-FR"], "measured": "zh-CN"})
        note = json.loads(self.rollback.read_text(encoding="utf-8"))
        self.assertEqual(note["before"], ["fr-FR"])
        self.assertIn("fr-FR", note["rollback"])

    def test_refuses_when_the_write_does_not_stick(self):
        """写完复查没生效就必须报错，不能返回「已修复」。"""

        def fake(cmd, **kw):
            if cmd[:2] == ["defaults", "read"]:
                return 0, '(\n    "zh-CN"\n)'
            return 0, ""

        with mock.patch.object(g, "run", side_effect=fake):
            with self.assertRaises(RuntimeError):
                g.clear_browser_locale({"cn": True, "target": "en-US",
                                        "app_override": None, "measured": "zh-CN"})


class TestChromeNeedsRestart(unittest.TestCase):
    """应用语言改完之后 Chrome 要重启才吃得到；判定不许猜。"""

    def _pref_home(self, age_seconds: float = 600):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        pref = tmp / "Library/Preferences" / (g.CHROME_APP_DOMAIN + ".plist")
        pref.parent.mkdir(parents=True)
        pref.write_text("x", encoding="utf-8")
        started = g.dt.datetime.fromtimestamp(pref.stat().st_mtime - age_seconds)
        return tmp, started.strftime("%a %b %d %H:%M:%S %Y")

    def test_started_before_the_change_needs_restart(self):
        home, lstart = self._pref_home(age_seconds=600)

        def fake(cmd, **kw):
            if cmd[0] == "pgrep":
                return 0, "711\n"
            if cmd[0] == "env":
                return 0, lstart + "\n"
            return 0, ""

        with mock.patch.object(g, "HOME", home), mock.patch.object(g, "run", side_effect=fake):
            self.assertTrue(g.chrome_needs_restart())

    def test_started_after_the_change_is_already_effective(self):
        home, _ = self._pref_home(age_seconds=-600)  # 进程比改动晚启动

        def fake(cmd, **kw):
            if cmd[0] == "pgrep":
                return 0, "711\n"
            if cmd[0] == "env":
                return 0, g.dt.datetime.now().strftime("%a %b %d %H:%M:%S %Y") + "\n"
            return 0, ""

        with mock.patch.object(g, "HOME", home), mock.patch.object(g, "run", side_effect=fake):
            self.assertFalse(g.chrome_needs_restart())

    def test_no_chrome_running_is_unknown(self):
        with mock.patch.object(g, "run", return_value=(1, "")):
            self.assertIsNone(g.chrome_needs_restart())

    def test_unparsable_lstart_is_unknown(self):
        home, _ = self._pref_home()

        def fake(cmd, **kw):
            if cmd[0] == "pgrep":
                return 0, "711\n"
            if cmd[0] == "env":
                return 0, "周五 10月  9 12:00:00 2026\n"  # 本地化过的 ps 输出
            return 0, ""

        with mock.patch.object(g, "HOME", home), mock.patch.object(g, "run", side_effect=fake):
            self.assertIsNone(g.chrome_needs_restart())


class TestBrowserLocaleInAutoCleanPlan(unittest.TestCase):
    """这一项要真的进自动清理计划，不然修不到。"""

    def _plan(self, bl):
        report = {
            "A1_terminal_env": {"env_hits": [], "rc_files": {}, "npm": {}, "git": {}},
            "A1_proxy_residue": {"residue": []},
            "A2_anthropic_base_url": {"hits": []},
            "A27_browser_locale": bl,
        }
        return g.auto_clean_plan(report)

    def test_cn_locale_with_us_exit_enters_the_plan(self):
        plan = self._plan({"measured": "zh-CN", "cn": True, "country": "US",
                           "target": "en-US", "source": "浏览器实测"})
        self.assertTrue(plan["browser_locale"])
        self.assertTrue(any("Intl" in line for line in plan["summary"]))

    def test_cn_exit_stays_out_of_the_plan(self):
        plan = self._plan({"measured": "zh-CN", "cn": True, "country": "CN",
                           "target": "en-US", "source": "浏览器实测"})
        self.assertFalse(plan["browser_locale"])


class TestArticleProxyChecklist(unittest.TestCase):
    """文章 2.5④ 那批命令有四处出处。2026-10-10 逐条对位时发现三处漏检：

    · brew config 从来没查过 —— 只在 --commands 里当手工命令列着；
    · settings.json 的 env 里放的代理键既不会被报也不会被清，检查手册那句
      `grep -iE "proxy|base_url|anthropic_"` 里 proxy 那半是空的；
    · ~/.npmrc 也从来没直接 grep 过 —— npm config get 看不到带作用域的写法。
    """

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.settings = self.tmp / ".claude" / "settings.json"
        self.settings.parent.mkdir(parents=True)

    def _env(self, brew_body="HOMEBREW_VERSION: 7.0.6\n", brew_code=0,
             npmrc=None, settings_env=None):
        if npmrc is not None:
            (self.tmp / ".npmrc").write_text(npmrc, encoding="utf-8")
        if settings_env is not None:
            self.settings.write_text(json.dumps({"env": settings_env}), encoding="utf-8")

        def fake(cmd, timeout=20):
            if cmd[:2] == ["brew", "config"]:
                return brew_code, brew_body
            if cmd[0] == "npm":
                return 0, "null"
            return 0, ""

        with mock.patch.object(g, "HOME", self.tmp), \
                mock.patch.object(g, "SETTINGS", self.settings), \
                mock.patch.object(g, "run", side_effect=fake):
            return g.check_terminal_env()

    def test_lowercase_proxy_lines_from_brew_are_caught(self):
        out = self._env(brew_body="HOMEBREW_VERSION: 7.0.6\nhttp_proxy: http://127.0.0.1:9\n")
        self.assertEqual(out["brew"]["proxy"], ["http_proxy=http://127.0.0.1:9"])

    def test_uppercase_lines_would_also_be_caught(self):
        # 实测：Homebrew 7 只会打出小写那三种 —— 把大小写六个都设上再 diff，多出来的
        # 只有小写三行，大写那三个它一句不提。匹配仍然刻意不区分大小写：万一哪天
        # brew 开始打大写也能接住，而它只有真设了代理才会打，不存在误报。
        out = self._env(brew_body="HOMEBREW_VERSION: 7.0.6\nHTTP_PROXY: http://127.0.0.1:9\n")
        self.assertEqual(out["brew"]["proxy"], ["http_proxy=http://127.0.0.1:9"])

    def test_all_three_lowercase_forms_are_caught(self):
        out = self._env(brew_body="http_proxy: http://a\nhttps_proxy: http://b\n"
                                  "all_proxy: socks5://c\nno_proxy: localhost\n")
        self.assertEqual(out["brew"]["proxy"],
                         ["http_proxy=http://a", "https_proxy=http://b",
                          "all_proxy=socks5://c", "no_proxy=localhost"])

    def test_missing_brew_is_not_a_failure(self):
        out = self._env(brew_body="", brew_code=127)
        self.assertFalse(out["brew"]["installed"])
        self.assertEqual(out["brew"]["proxy"], [])

    def test_settings_env_proxy_key_is_detected(self):
        out = self._env(settings_env={"HTTPS_PROXY": "http://127.0.0.1:9", "KEEP": "1"})
        self.assertEqual(out["settings_proxy"], ["HTTPS_PROXY"])
        self.assertEqual(out["settings_env"]["KEEP"], "1")

    def test_settings_without_proxy_has_no_proxy_keys(self):
        out = self._env(settings_env={"DISABLE_TELEMETRY": "1"})
        self.assertEqual(out["settings_proxy"], [])

    def test_npmrc_proxy_line_is_detected(self):
        out = self._env(npmrc="registry=https://registry.npmjs.org/\nproxy=http://127.0.0.1:9\n")
        self.assertEqual([h["line"] for h in out["npmrc"]], [2])

    def test_npmrc_comment_is_not_a_hit(self):
        out = self._env(npmrc="# proxy=http://127.0.0.1:9\n")
        self.assertEqual(out["npmrc"], [])

    def test_npmrc_plaintext_token_is_not_a_proxy_hit(self):
        # 明文 token 是另一回事（脚本不碰它），别算成代理残留。
        out = self._env(npmrc="//registry.npmjs.org/:_authToken=npm_abc\n")
        self.assertEqual(out["npmrc"], [])


class TestSettingsEnvProxyCleanup(unittest.TestCase):
    """settings.json 的 env 里放代理键，必须既报得出来又清得掉，且不碰别的键。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.settings = self.tmp / ".claude" / "settings.json"
        self.settings.parent.mkdir(parents=True)

    def _clear(self, env):
        self.settings.write_text(
            json.dumps({"env": env, "theme": "dark"}, ensure_ascii=False), encoding="utf-8")
        with mock.patch.object(g, "SETTINGS", self.settings):
            return g.clear_anthropic_base_url()

    def _after(self):
        return json.loads(self.settings.read_text(encoding="utf-8"))

    def test_proxy_key_is_removed_and_the_rest_survives(self):
        msg = self._clear({"HTTPS_PROXY": "http://127.0.0.1:9", "KEEP": "1"})
        self.assertIn("HTTPS_PROXY", msg)
        after = self._after()
        self.assertEqual(after["env"], {"KEEP": "1"})
        self.assertEqual(after["theme"], "dark")     # env 之外的键原样保留

    def test_endpoint_and_proxy_go_in_one_write(self):
        # 两类一起清，避免两趟写同一个文件互相覆盖。
        msg = self._clear({"ANTHROPIC_BASE_URL": "https://mirror/anthropic",
                           "HTTP_PROXY": "http://127.0.0.1:9", "KEEP": "1"})
        self.assertIn("ANTHROPIC_BASE_URL", msg)
        self.assertIn("HTTP_PROXY", msg)
        self.assertEqual(self._after()["env"], {"KEEP": "1"})

    def test_clean_settings_is_a_noop(self):
        msg = self._clear({"DISABLE_TELEMETRY": "1"})
        self.assertIn("没有需要清掉", msg)
        self.assertEqual(self._after()["env"], {"DISABLE_TELEMETRY": "1"})


class TestProxyRowsInSummary(unittest.TestCase):
    """结果总表那两行要把新证据写出来，别只留一句「没有代理」。"""

    @staticmethod
    def _te(**over):
        base = {"env_hits": [], "env_info": [], "rc_files": {}, "settings_env": {},
                "settings_proxy": [], "npmrc": [],
                "brew": {"installed": True, "proxy": []},
                "npm": {"npm_proxy": "null", "npm_https_proxy": "null"},
                "git": {"http.proxy": "", "https.proxy": ""}}
        base.update(over)
        return base

    def _report(self, terminal=None):
        return {
            "A1_export_ip": {"ip": "1.2.3.4", "city": "Reston", "country": "US",
                             "verdict": "疑似住宅/ISP"},
            "A1_proxy_residue": {"enabled": [], "residue": [], "scutil": {}},
            "A1_terminal_env": terminal or self._te(),
            "A2_anthropic_base_url": {"hits": []},
            "A5_ipv6": {"global_addresses": []},
            "A6_dns": {"fake_ip": True, "real_ip_hosts": []},
            "A10_third_party": {"hits": []},
            "A11_client_integrity": {"cli_version": "2.1.293", "version_count": 4,
                                     "stale_count": 0, "stale_bytes": 0},
            "A12_clash_groups": {"reachable": True, "mode": "rule", "global_now": "Claude",
                                 "claude_group": {"now": "主线", "members": ["主线"]},
                                 "fail_closed": {"ok": True, "reasons": []}},
            "A13_multi_account": {"identities": []},
            "A15_consistency": {"tension": []},
            "A21_timezone_layers": {"all_taipei": True, "layers": {"localtime": "Asia/Taipei"},
                                    "gate_auto_plist": False, "gate_location": False},
            "E1_keychain": {"readable": True, "items": []},
        }

    @staticmethod
    def _row(rows, name):
        for r in rows:
            if r[0] == name:
                return r
        raise AssertionError(f"表里没有 {name}")

    def test_clean_row_names_all_five_places(self):
        row = self._row(g.build_summary(self._report()), "终端 / shell / npm / git 代理")
        self.assertIs(row[1], g.S_OK)
        for word in ("环境变量", "shell 配置", "npm/git", "~/.npmrc", "brew config"):
            self.assertIn(word, row[2])

    def test_npmrc_line_turns_the_row_into_a_fix(self):
        r = self._report(self._te(npmrc=[{"line": 2, "text": "proxy=http://127.0.0.1:9"}]))
        row = self._row(g.build_summary(r), "终端 / shell / npm / git 代理")
        self.assertIs(row[1], g.S_FIX)
        self.assertIn("~/.npmrc 1 行", row[2])

    def test_brew_proxy_turns_the_row_into_a_fix(self):
        r = self._report(self._te(brew={"installed": True,
                                        "proxy": ["http_proxy=http://127.0.0.1:9"]}))
        row = self._row(g.build_summary(r), "终端 / shell / npm / git 代理")
        self.assertIs(row[1], g.S_FIX)
        self.assertIn("Homebrew 1 项", row[2])

    def test_settings_proxy_turns_the_settings_row_into_a_fix(self):
        r = self._report(self._te(settings_proxy=["HTTPS_PROXY"]))
        row = self._row(g.build_summary(r), "settings.json 端点与凭据")
        self.assertIs(row[1], g.S_FIX)
        self.assertIn("HTTPS_PROXY", row[2])

    def test_clean_settings_row_still_says_ok(self):
        row = self._row(g.build_summary(self._report()), "settings.json 端点与凭据")
        self.assertIs(row[1], g.S_OK)


class TestProxyKeysEnterAutoCleanPlan(unittest.TestCase):
    """光报不算修好：settings.json 的代理键必须真的进自动清理计划。"""

    @staticmethod
    def _te(**over):
        base = {"env_hits": [], "env_info": [], "rc_files": {}, "settings_env": {},
                "settings_proxy": [], "npmrc": [], "brew": {"installed": True, "proxy": []},
                "npm": {}, "git": {}}
        base.update(over)
        return base

    def _plan(self, te):
        return g.auto_clean_plan({
            "A1_terminal_env": te,
            "A1_proxy_residue": {"residue": []},
            "A2_anthropic_base_url": {"hits": []},
        })

    def test_settings_proxy_enters_the_plan(self):
        plan = self._plan(self._te(settings_proxy=["HTTPS_PROXY"]))
        self.assertEqual(plan["settings_env_proxy"], ["HTTPS_PROXY"])
        self.assertTrue(any("代理变量" in line for line in plan["summary"]))

    def test_clean_env_stays_out_of_the_plan(self):
        plan = self._plan(self._te())
        self.assertEqual(plan["settings_env_proxy"], [])
        self.assertEqual(plan["npmrc"], [])
        self.assertEqual(plan["brew_proxy"], [])

    def test_npmrc_is_reported_but_not_promised_as_cleanable(self):
        plan = self._plan(self._te(npmrc=[{"line": 2, "text": "proxy=http://127.0.0.1:9"}]))
        self.assertEqual(len(plan["npmrc"]), 1)
        self.assertTrue(any("只报告" in line for line in plan["summary"]))


class TestBeforeAfterTable(unittest.TestCase):
    """收尾那张「修复前 → 修复后」对照表。

    用户的原话是「标识前后通过没通过就行」，所以这一栏只出记号，不出实测值；
    改动明细只在真从「没通过」变成「通过」时才打。
    """

    def _capture(self, before_rows, after_rows):
        with mock.patch.object(g, "build_summary", side_effect=[before_rows, after_rows]), \
                mock.patch.object(g, "render_table", return_value="TABLE") as table:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                g.print_before_after({"A1": {}}, {"A1": {}})
        return table.call_args, buf.getvalue()

    def test_columns_and_marks(self):
        call, _ = self._capture(
            [("出口 IP", g.S_OK, "x")], [("出口 IP", g.S_OK, "x")])
        headers, rows = call[0]
        self.assertEqual(headers, ("检查项", "修复前", "修复后"))
        self.assertEqual(rows, [("出口 IP", "✓", "✓")])

    def test_fixed_item_is_counted_and_listed(self):
        _, out = self._capture(
            [("遥测三键", g.S_FIX, "三项都是 None")],
            [("遥测三键", g.S_OK, "已写入 settings.json 的 env")])
        self.assertIn("修复前没通过 1 项 → 修复后没通过 0 项", out)
        self.assertIn("这次改好的", out)
        self.assertIn("遥测三键", out)
        self.assertIn("已写入 settings.json 的 env", out)  # 明细取的是改完之后那份

    def test_no_change_prints_no_detail_sections(self):
        _, out = self._capture(
            [("出口 IP", g.S_OK, "x")], [("出口 IP", g.S_OK, "x")])
        self.assertIn("修复前没通过 0 项 → 修复后没通过 0 项", out)
        self.assertNotIn("这次改好的", out)
        self.assertNotIn("仍然没通过", out)

    def test_item_absent_from_first_report_shows_dot(self):
        call, _ = self._capture([], [("新项", g.S_OK, "x")])
        self.assertEqual(call[0][1], [("新项", "·", "✓")])

    def test_unmeasured_is_not_counted_as_failed(self):
        # · 是「这次没测到」，不是没通过。曾经把它算进去，复检表凭空多出几项红字。
        _, out = self._capture(
            [("WebRTC 泄漏", g.S_NA, "没跑探测")], [("WebRTC 泄漏", g.S_NA, "没跑探测")])
        self.assertIn("修复前没通过 0 项 → 修复后没通过 0 项", out)
        self.assertIn("另有 1 项这次没测到", out)
        self.assertNotIn("这次改好的", out)

    def test_going_from_failed_to_unmeasured_is_not_a_fix(self):
        _, out = self._capture(
            [("WebRTC 泄漏", g.S_FIX, "有泄漏")], [("WebRTC 泄漏", g.S_NA, "这次没测")])
        self.assertNotIn("这次改好的", out)

    def test_regression_is_listed_as_still_failing(self):
        _, out = self._capture(
            [("两道闸", g.S_OK, "都关着")], [("两道闸", g.S_FIX, "被打开了")])
        self.assertIn("仍然没通过", out)
        self.assertIn("修复前没通过 0 项 → 修复后没通过 1 项", out)


class TestCliSignature(unittest.TestCase):
    """A11 的验签部分：文章 §5「不要改客户端二进制」。

    这段判据的价值全在「能不能真判出来」上，所以每个分支都配一条用例：
    验签通过、没签名、验签失败、签名者不是 Anthropic、读不到签名信息。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="guard-sig-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.binary = pathlib.Path(self.tmp) / "claude"
        self.binary.write_text("#!/bin/sh\n", encoding="utf-8")

    def _sig(self, out, verify_code=0, dv_code=0):
        """把 codesign 的两条调用（-dv 与 --verify）分开喂回去。"""
        def fake_run(cmd, timeout=20):
            if cmd[:2] == ["codesign", "--verify"]:
                return verify_code, ""
            return dv_code, out
        with mock.patch.object(g, "run", side_effect=fake_run):
            return g.check_cli_signature(str(self.binary))

    ANTHROPIC = ("Executable=/x/claude\nIdentifier=com.anthropic.claude-code\n"
                 "Authority=Developer ID Application: Anthropic PBC (Q6L2SF6YDW)\n"
                 "Authority=Developer ID Certification Authority\n")

    # ── 纯函数层 ──

    def test_anthropic_signature_passes(self):
        sig = self._sig(self.ANTHROPIC, verify_code=0)
        self.assertTrue(sig["checked"])
        self.assertTrue(sig["signed"])
        self.assertTrue(sig["verified"])
        self.assertIn("Anthropic", sig["authority"])
        self.assertEqual(sig["note"], "")

    def test_tampered_binary_is_detected(self):
        """签名在、但验签失败 —— 这正是「改了二进制」的样子。"""
        sig = self._sig(self.ANTHROPIC, verify_code=1)
        self.assertTrue(sig["verified"] is False)
        self.assertIn("可能被改过", sig["note"])

    def test_unsigned_binary_is_not_called_tampered(self):
        """没签名的二进制不能让 verify 的失败掩盖掉真实结论。"""
        sig = self._sig("code object is not signed at all\n", verify_code=1)
        self.assertFalse(sig["signed"])
        self.assertEqual(sig["note"], "这份二进制没有签名")

    def test_other_signer_is_flagged(self):
        sig = self._sig("Authority=Developer ID Application: Someone Else (ABCDE12345)\n", verify_code=0)
        self.assertTrue(sig["verified"])
        self.assertIn("不是 Anthropic", sig["note"])

    def test_team_id_falls_back_to_authority(self):
        """-dv --verbose=2 不保证单列 TeamIdentifier，括号里那串要能兜住。"""
        sig = self._sig(self.ANTHROPIC)
        self.assertEqual(sig["team"], "Q6L2SF6YDW")

    def test_explicit_team_identifier_wins(self):
        sig = self._sig(self.ANTHROPIC + "TeamIdentifier=ZZZZZ99999\n")
        self.assertEqual(sig["team"], "ZZZZZ99999")

    def test_codesign_failure_is_not_a_verdict(self):
        """读不到签名信息 ≡ 这一项没测到，不是「没签名」。"""
        sig = self._sig("", dv_code=1)
        self.assertFalse(sig["checked"])
        self.assertIsNone(sig["verified"])
        self.assertIn("跳过验签", sig["note"])

    def test_missing_path_does_not_run_codesign(self):
        with mock.patch.object(g, "run") as m:
            sig = g.check_cli_signature(str(pathlib.Path(self.tmp) / "nope"))
        m.assert_not_called()
        self.assertFalse(sig["checked"])
        self.assertIn("跳过验签", sig["note"])

    def test_no_path_at_all(self):
        with mock.patch.object(g, "run") as m:
            sig = g.check_cli_signature(None)
        m.assert_not_called()
        self.assertIn("跳过验签", sig["note"])

    # ── 接进总表之后 ──

    def _row(self, signature):
        ci = {"cli_version": "2.1.293 (Claude Code)", "version_count": 4, "stale_count": 3,
              "stale_bytes": 668 * 1048576, "signature": signature}
        for name, status, detail in g.build_summary({"A11_client_integrity": ci}):
            if name == "CLI 完整性":
                return status, detail
        self.fail("总表里没有 CLI 完整性这一行")

    def test_row_reports_the_verification(self):
        status, detail = self._row(self._sig(self.ANTHROPIC, verify_code=0))
        self.assertEqual(status, g.S_OK)
        self.assertIn("验签通过", detail)

    def test_row_goes_bad_when_verification_fails(self):
        status, detail = self._row(self._sig(self.ANTHROPIC, verify_code=1))
        self.assertEqual(status, g.S_BAD)
        self.assertIn("可能被改过", detail)

    def test_unsigned_row_is_a_fix_not_a_bad(self):
        """没签名要报待处理、不能报 ✗ —— 这是「先判没签名还是先判验签失败」的守门用例。"""
        status, detail = self._row(self._sig("code object is not signed at all\n", verify_code=1))
        self.assertEqual(status, g.S_FIX)
        self.assertNotIn("可能被改过", detail)

    def test_row_does_not_call_an_unchecked_binary_unsigned(self):
        """codesign 跑不了时 signed 是默认的 False，这一行不能报「没有签名」。"""
        status, detail = self._row(self._sig("", dv_code=1))
        self.assertEqual(status, g.S_OK)
        self.assertIn("未能验签", detail)
        self.assertNotIn("没有签名", detail)

    def test_row_survives_a_report_without_the_signature_key(self):
        """老报告里没有 signature 这个键时，不能让这一行整个消失。"""
        ci = {"cli_version": "2.1.293 (Claude Code)", "version_count": 4}
        rows = dict((n, s) for n, s, _ in g.build_summary({"A11_client_integrity": ci}))
        self.assertEqual(rows.get("CLI 完整性"), g.S_OK)


class TestExportHistory(unittest.TestCase):
    """文章 §2.5① 要求「城市别每次变」、§9 要求「出口国家和上次一致」。

    这两句都只能靠和上一次比才看得出来，所以脚本要把出口记下来。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="guard-exp-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = mock.patch.object(g, "HOME", pathlib.Path(self.tmp))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _info(self, ip="1.2.3.4", city="Paris", country="FR", org="AS1 X"):
        return {"ip": ip, "city": city, "country": country, "org": org}

    def _fake_curl(self, ip="1.2.3.4", city="Paris", country="FR"):
        def fake_run(cmd, timeout=20):
            url = cmd[-1]
            if url.endswith("ipinfo.io/json"):
                return 0, json.dumps({"ip": ip, "city": city, "country": country,
                                      "org": "AS1 X", "timezone": "Europe/Paris"})
            if "ipify" in url:
                return 0, json.dumps({"ip": ip})
            if "ipinfo.io/" in url:
                return 0, json.dumps({"org": "AS1 X", "timezone": "Europe/Paris"})
            if "ip-api.com" in url:
                return 0, json.dumps({"status": "success", "city": city, "regionName": "R",
                                      "timezone": "T", "isp": "I"})
            return 1, ""
        return fake_run

    def _row(self, info):
        for name, status, detail in g.build_summary({"A1_export_ip": info}):
            if name == "出口 IP 与归属":
                return status, detail
        self.fail("总表里没有「出口 IP 与归属」这一行")

    # ── 记录本身 ──

    def test_state_path_follows_home(self):
        """路径必须跟着 HOME 走，否则测试会把记录写到真实家目录。"""
        self.assertTrue(str(g.export_state_path()).startswith(self.tmp))

    def test_first_run_records_without_complaining(self):
        self.assertEqual(g.load_export_history(), {})
        g.save_export_history(self._info())
        self.assertEqual(g.load_export_history()["ip"], "1.2.3.4")

    def test_no_ip_does_not_overwrite_a_good_record(self):
        """取不到出口时不能把上一份好记录冲掉，否则下次就没得比了。"""
        g.save_export_history(self._info())
        g.save_export_history({"ip": None, "city": None})
        self.assertEqual(g.load_export_history()["ip"], "1.2.3.4")

    def test_corrupt_file_counts_as_no_history(self):
        p = g.export_state_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{not json", encoding="utf-8")
        self.assertEqual(g.load_export_history(), {})

    def test_non_dict_json_counts_as_no_history(self):
        p = g.export_state_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("[1, 2, 3]", encoding="utf-8")
        self.assertEqual(g.load_export_history(), {})

    # ── 比对本身 ──

    def test_first_run_has_nothing_to_compare(self):
        with mock.patch.object(g, "run", side_effect=self._fake_curl()):
            info = g.check_export_ip()
        self.assertFalse(info["changed"])
        self.assertIsNone(info["previous"])

    def test_same_exit_second_time_is_not_a_change(self):
        with mock.patch.object(g, "run", side_effect=self._fake_curl()):
            g.check_export_ip()
        with mock.patch.object(g, "run", side_effect=self._fake_curl()):
            info = g.check_export_ip()
        self.assertFalse(info["changed"])
        self.assertEqual(info["previous"]["ip"], "1.2.3.4")

    def test_moved_exit_lists_both_values(self):
        with mock.patch.object(g, "run", side_effect=self._fake_curl(ip="1.2.3.4", city="Paris", country="FR")):
            g.check_export_ip()
        with mock.patch.object(g, "run", side_effect=self._fake_curl(ip="9.9.9.9", city="Tokyo", country="JP")):
            info = g.check_export_ip()
        self.assertTrue(info["changed"])
        self.assertIn("IP 1.2.3.4 → 9.9.9.9", info["changed_fields"])
        self.assertIn("城市 Paris → Tokyo", info["changed_fields"])

    def test_failed_lookup_keeps_the_old_record(self):
        with mock.patch.object(g, "run", side_effect=self._fake_curl()):
            g.check_export_ip()
        with mock.patch.object(g, "run", return_value=(1, "")):
            g.check_export_ip()
        self.assertEqual(g.load_export_history()["ip"], "1.2.3.4")

    # ── 总表那一行 ──

    def test_row_says_consistent(self):
        status, detail = self._row({**self._info(),
                                    "previous": {**self._info(), "checkedAt": "2026-10-10 11:55"},
                                    "changed": False})
        self.assertEqual(status, g.S_OK)
        self.assertIn("与上次一致", detail)

    def test_row_flags_a_moved_exit(self):
        status, detail = self._row({**self._info(ip="9.9.9.9", city="Tokyo", country="JP"),
                                    "previous": self._info(),
                                    "changed": True})
        self.assertEqual(status, g.S_FIX)
        self.assertIn("1.2.3.4", detail)
        self.assertIn("上次", detail)

    def test_row_is_green_on_the_first_record(self):
        status, detail = self._row({**self._info(), "previous": None, "changed": False})
        self.assertEqual(status, g.S_OK)
        self.assertIn("第一次记录", detail)

    def test_old_report_without_history_keys_still_renders(self):
        """老报告里没有 previous/changed 两个键，这一行不能因此崩掉或变色。"""
        status, detail = self._row(self._info())
        self.assertEqual(status, g.S_OK)
        self.assertIn("第一次记录", detail)


if __name__ == "__main__":
    # 这个块必须待在文件最末尾。2026-10-10 发现它一度停在中间（第 2403 行），
    # 于是它后面定义的 6 个类、40 个用例从来没被执行过——`unittest.main()` 在第 2403
    # 行就跑完了收集，而那几个类那时还没被定义。症状是「测试全过」，实际只跑了
    # 227/267。往这个文件里加用例时，务必加在下面这行之上。
    unittest.main(verbosity=2)
