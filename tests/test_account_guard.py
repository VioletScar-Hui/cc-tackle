#!/usr/bin/env python3
"""CC tackle 的测试。

覆盖三类东西：
  1. 纯函数逻辑（ASN 归类、参数解析）—— 回归曾经真实出过的 bug；
  2. 写操作的安全边界（无备份不改动、模式 0 不落盘、清理后不得变成启用）；
  3. 入口闸门（非 TTY 拒绝、密码与状态由用户掌握）。

跑法：python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pathlib
import plistlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))

import account_guard as g  # noqa: E402
import report_html as rh  # noqa: E402
import report_serve as rs  # noqa: E402
import selfcheck as selfcheck_module  # noqa: E402


_SAVED_GUARD_ENV: dict = {}


def setUpModule() -> None:
    """跑测试前把 CLAUDE_GUARD_* 环境变量摘掉。

    这套用例必须与开发机的环境无关。main() 是**按体检结果问不定数量的问题**的：
    多一项可清理就多一问，而 auto_clean_plan 里还有几项是现场读环境的
    （`project_junk` 只看有没有配项目根）。所以开发机 export 了
    CLAUDE_GUARD_PROJECT_ROOTS，交互就多一问，写死答案序列的用例会炸成
    StopIteration —— 那是环境串味，不是代码坏了。2026-10-14 实测：
    带这几个变量跑自检里的单测，5 个用例报 StopIteration，跑 759 秒；
    不带就是 507 个全过、45 秒。
    """
    for key in [k for k in os.environ if k.startswith("CLAUDE_GUARD_")]:
        _SAVED_GUARD_ENV[key] = os.environ.pop(key)
    # report_html 的落盘目录是模块级常量（`pathlib.Path.home() / "ClaudeGuardBackups"`，
    # 在 import 那一刻定死），patch `g.HOME` 或 `g.BACKUP_ROOT` 都带不走它。谁漏了
    # patch `write_html_twin`，谁就把测试夹具写进用户真实的备份目录——2026-10-15
    # 实测抓到一次：跑一遍单测就在 ~/ClaudeGuardBackups 里多出 4 份 36 KB 的假报告。
    # 整个会话把它指到临时目录，漏了也只落在 /tmp。
    global _TEST_REPORT_DIR
    _TEST_REPORT_DIR = pathlib.Path(tempfile.mkdtemp(prefix="guard-report-"))
    rh.BACKUP_DIR = _TEST_REPORT_DIR / "reports"


_TEST_REPORT_DIR = None


def tearDownModule() -> None:
    os.environ.update(_SAVED_GUARD_ENV)
    if _TEST_REPORT_DIR is not None:
        shutil.rmtree(_TEST_REPORT_DIR, ignore_errors=True)


def prompt_answering(telemetry: str = "0", yes: bool = False):
    """按提示语本身作答，不按「第几个问题」作答。

    写死 `side_effect=["0", "n", "n", "CONFIRM"]` 会随环境炸掉（见 setUpModule），
    而且报出来的是 StopIteration，看不出是哪个问题对不上。这里改成读提示语：
    CONFIRM 那一问回 CONFIRM，遥测那一问回选项号，其余问句一律 n（要 yes 就 y）。
    遇到认不出来的提示语直接报错并带上原文，免得又变成看不懂的 StopIteration。
    """
    def answer(prompt: str = "") -> str:
        text = str(prompt)
        if "CONFIRM" in text:
            return "CONFIRM"
        if "遥测开关" in text:
            return telemetry
        if "[y/N]" in text:          # ask_yes 会自己补上 "[y/N]："，别按问号判
            return "y" if yes else "n"
        raise AssertionError(f"测试没准备这个问题的答案：{text!r}")
    return answer


class TestHarnessIsolation(unittest.TestCase):
    """守门：这套用例不能读开发机的 CLAUDE_GUARD_* 环境。

    2026-10-14 出过一次「环境串味」：开发机 export 了 CLAUDE_GUARD_PROJECT_ROOTS，
    main() 的交互就多一问（清项目级 .claude 垃圾），而用例里写死了四段答案，
    于是 5 个用例报 StopIteration，自检跟着变红。代码没坏，是测试继承了环境。
    """

    def test_guard_env_is_scrubbed_for_the_whole_run(self):
        leftovers = [k for k in os.environ if k.startswith("CLAUDE_GUARD_")]
        self.assertEqual(leftovers, [], f"测试期间不该有这些环境变量：{leftovers}")

    def test_prompt_helper_matches_the_three_shapes(self):
        answer = prompt_answering(telemetry="2")
        self.assertEqual(answer("完全理解后输入 CONFIRM 开始；其他输入取消："), "CONFIRM")
        self.assertEqual(answer("遥测开关：0 保持；1 关三项。选择 [0]："), "2")
        self.assertEqual(answer("生成 claude-safe 包装脚本？ [y/N]："), "n")
        self.assertEqual(prompt_answering(yes=True)("随便一问？ [y/N]："), "y")

    def test_prompt_helper_refuses_unknown_prompts(self):
        # 认不出来时必须炸，并且把提示语原文带出来；否则又会退化成一个看不懂的 StopIteration
        with self.assertRaises(AssertionError) as ctx:
            prompt_answering()("裸提示符> ")
        self.assertIn("裸提示符", str(ctx.exception))


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

    def test_ask_yes_accepts_the_obvious_yes(self):
        # 提示写的是 [y/N] / [Y/n]，那 "yes" 就是正常回答：静默把它当成「否」
        # 会让用户以为同意了，实际什么都没做。空回车才走默认值。
        for raw, want in (("y", True), ("Y", True), ("yes", True), ("YES", True),
                          ("", False), ("n", False), ("no", False)):
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


class TestReadJsonFailClosed(unittest.TestCase):
    """已有配置损坏或形状错误时不能按空配置继续审计。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_missing_file_still_uses_default(self):
        self.assertEqual(g.read_json(self.tmp / "missing.json", {}), {})

    def test_malformed_existing_file_raises_value_error(self):
        path = self.tmp / "broken.json"
        path.write_text("{broken", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "JSON 文件损坏"):
            g.read_json(path, {})

    def test_non_object_existing_file_raises_value_error(self):
        path = self.tmp / "wrong-shape.json"
        path.write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "顶层不是对象"):
            g.read_json(path, {})


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
    """CONFIRM 后、目标状态变更前先备份；备份不了就必须停下。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self._orig = g.BACKUP_ROOT
        self._old_home = g.HOME
        g.HOME = self.tmp
        g.BACKUP_ROOT = self.tmp / "backups"

    def tearDown(self):
        g.HOME = self._old_home
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
                return 0, "Enabled: Yes\nServer: 127.0.0.1\nPort: 7897\n"
            return 0, ""

        with mock.patch.object(g, "run", side_effect=fake_run):
            with self.assertRaises(RuntimeError) as ctx:
                g.clear_proxy_residue(residue)
        self.assertIn("变成了启用状态", str(ctx.exception))

    def test_counts_only_when_disabled(self):
        residue = [{"service": "Wi-Fi", "kind": "webproxy", "server": "127.0.0.1", "port": "7897"}]

        calls = {"get": 0}
        def fake_run(cmd, timeout=20):
            if "networksetup" in cmd and "-getwebproxy" in cmd:
                calls["get"] += 1
                if calls["get"] == 1:
                    return 0, "Enabled: No\nServer: 127.0.0.1\nPort: 7897\n"
                return 0, "Enabled: No\nServer: 0.0.0.0\nPort: 0\n"
            return 0, ""

        with mock.patch.object(g, "run", side_effect=fake_run):
            self.assertEqual(g.clear_proxy_residue(residue), 1)

    def test_empty_residue_is_noop(self):
        self.assertEqual(g.clear_proxy_residue([]), 0)

    def test_already_clean_after_audit_is_not_a_failure(self):
        """报告之后被别人清掉了，目标状态已达成，不该报失败。

        2026-10-14 真机点按钮实测撞上的就是这一态：定时脚本
        local.proxy-residue-cleanup 每 5 分钟跑一次，抢在前面把残留清了。
        旧版直接抛「状态已变化」，页面上显示「这几项没成」，行也一直红着。
        """
        residue = [{"service": "Wi-Fi", "kind": "webproxy", "server": "127.0.0.1", "port": "7897"}]
        issued = []

        def fake_run(cmd, timeout=20):
            if "networksetup" in cmd and "-getwebproxy" in cmd:
                return 0, "Enabled: No\nServer: 0.0.0.0\nPort: 0\n"
            issued.append(cmd)
            return 0, ""

        with mock.patch.object(g, "run", side_effect=fake_run):
            self.assertEqual(g.clear_proxy_residue(residue), 0)
        self.assertEqual(g.clear_proxy_residue.skipped, 1)
        self.assertEqual(issued, [], "已经是干净的，一个写操作都不该发")

    def test_refuses_when_residue_changed_after_audit(self):
        residue = [{"service": "Wi-Fi", "kind": "webproxy", "server": "127.0.0.1", "port": "7897"}]

        def fake_run(cmd, timeout=20):
            if "networksetup" in cmd and "-getwebproxy" in cmd:
                return 0, "Enabled: No\nServer: 127.0.0.1\nPort: 7898\n"
            return 0, ""

        with mock.patch.object(g, "run", side_effect=fake_run):
            with self.assertRaisesRegex(RuntimeError, "换成了别的值"):
                g.clear_proxy_residue(residue)


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
    """A14 的目录不能再写死在某台机器上；也不能因为没人设环境变量就少判两项。

    2026-10-15：原来只认 CLAUDE_GUARD_PROJECT_ROOTS，于是直接敲
    `python3 scripts/account_guard.py --audit` 时「代码是否落在本地 Git」与
    「项目级 .claude 规模」两项变成「未测到」——裸跑 6 项未测到、带上就少 2 项。
    selfcheck.py 一直有三级兜底，account_guard.py 没有，两边各说各话。现在对齐。
    """

    def _empty_home(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        return tmp

    def test_falls_back_to_the_repo_the_skill_lives_in(self):
        tmp = self._empty_home()
        with mock.patch.dict("os.environ", {}, clear=True), \
             mock.patch.object(g, "run", return_value=(0, str(tmp) + "\n")):
            roots, source = g.project_roots_default()
        self.assertEqual(roots, [tmp])
        self.assertIn("git 仓", source)

    def test_falls_back_to_the_legacy_home_dir(self):
        tmp = self._empty_home()
        (tmp / "ipe").mkdir()
        with mock.patch.dict("os.environ", {}, clear=True), \
             mock.patch.object(g, "HOME", tmp), \
             mock.patch.object(g, "run", return_value=(1, "")):
            roots, source = g.project_roots_default()
            # 必须连真正的入口一起断言：只测 project_roots_default 的话，
            # 上面那个 return 换成旧写法（只认环境变量）测试照样「通过」。
            self.assertEqual(g.project_roots(), [tmp / "ipe"])
        self.assertEqual(roots, [tmp / "ipe"])
        self.assertIn("~/ipe", source)

    def test_empty_when_unset_and_nothing_to_fall_back_to(self):
        tmp = self._empty_home()
        with mock.patch.dict("os.environ", {}, clear=True), \
             mock.patch.object(g, "HOME", tmp), \
             mock.patch.object(g, "run", return_value=(1, "")):
            self.assertEqual(g.project_roots(), [])

    def test_env_still_wins(self):
        with mock.patch.dict("os.environ", {"CLAUDE_GUARD_PROJECT_ROOTS": "/a:/b"}):
            self.assertEqual([str(x) for x in g.project_roots()], ["/a", "/b"])

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
        changed = g.clear_rc_proxy_lines({".zshrc": [{"line": 3,
                                                       "text": "export HTTP_PROXY=http://127.0.0.1:7897"}]})
        self.assertEqual(changed, [str(rc)])
        text = rc.read_text(encoding="utf-8")
        self.assertNotIn("HTTP_PROXY", text)
        self.assertIn("EDITOR=vim", text, "无关行必须保留")
        self.assertIn("alias ll", text)
        self.assertIn("# 我的配置", text, "注释行必须保留")

    def test_rc_noop_when_nothing_matched(self):
        (self.tmp / ".zshrc").write_text("export EDITOR=vim\n", encoding="utf-8")
        self.assertEqual(g.clear_rc_proxy_lines({".zshrc": []}), [])

    def test_rc_recheck_catches_a_proxy_line_added_after_the_audit(self):
        # 审计之后文件里多出一行代理：它不在计划里，删完必须复验发现，
        # 而不是报告「已清干净」。
        rc = self.tmp / ".zshrc"
        rc.write_text(
            "export HTTPS_PROXY=http://127.0.0.1:7000\n"
            "export EDITOR=vim\n"
            "export HTTP_PROXY=http://127.0.0.1:7897\n",
            encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "仍有代理行"):
            g.clear_rc_proxy_lines({".zshrc": [{
                "line": 3, "text": "export HTTP_PROXY=http://127.0.0.1:7897"}]})

    def test_rc_refuses_inserted_or_changed_line(self):
        rc = self.tmp / ".zshrc"
        rc.write_text("export EDITOR=vim\nexport HTTP_PROXY=http://127.0.0.1:7897\n",
                      encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "已变化"):
            g.clear_rc_proxy_lines({".zshrc": [{
                "line": 2, "text": "export HTTP_PROXY=http://127.0.0.1:7897",
                "sha256": "0" * 64,
            }]})

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

    def _run_main(self, tmp, boom, at: str = "settings"):
        """把中间某一步做成会抛错的，观察 main 的处理。

        三个曾经踩过的坑，写测试时必须避开：
          * 遥测答案必须是 2 —— 选 0 时 main 走 `if telemetry else '保持'` 短路，
            那一步根本不执行，这里也就测不到东西；
          * HOME 必须一起 patch —— targets 里有 HOME/'.claude.json'，
            不 patch 就会去读真实家目录；
          * write_html_twin 必须 patch —— 不 patch 的话，凡是跑到底的用例
            都会真的 `open` 一个 HTML 页面出来。

        2026-10-15 起注入口默认换成了「settings.json 端点」那一步：遥测那一步
        失败已经改成「其余步骤继续」，不再是中止路径的触发点（要测遥测失败，
        传 at="telemetry"，见 test_telemetry_failure_does_not_abort_the_run）。
        """
        settings = tmp / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True, exist_ok=True)
        settings.write_text('{"env": {}}', encoding="utf-8")
        (tmp / ".claude.json").write_text('{"userID": "fake"}', encoding="utf-8")
        report = {
            "A1_proxy_residue": {"residue": [], "enabled": [], "scutil": {},
                                 "network_services": []},
            "A1_terminal_env": {"rc_files": {}, "npm": {}, "git": {},
                                "env_hits": [], "env_info": []},
            # 这一条让「settings 端点」那一笔真的会执行，boom 才有地方抛
            "A2_anthropic_base_url": {"hits": [{"file": str(settings),
                                                "key": "ANTHROPIC_BASE_URL",
                                                "value": "http://example.invalid"}]},
            "A5_ipv6": {"services": {}, "global_addresses": []},
        }
        err, out = io.StringIO(), io.StringIO()
        calls = []
        if at == "telemetry":
            telemetry_patch = mock.patch.object(g, "apply_telemetry", side_effect=boom)
            settings_patch = mock.patch.object(g, "clear_anthropic_base_url",
                                               return_value="（这一步没走到）")
        else:
            telemetry_patch = mock.patch.object(
                g, "apply_telemetry",
                side_effect=lambda m: (calls.append(m), "已写入 DISABLE_TELEMETRY")[1])
            settings_patch = mock.patch.object(g, "clear_anthropic_base_url", side_effect=boom)
        with mock.patch.object(g, "HOME", tmp), \
             mock.patch.object(g, "SETTINGS", settings), \
             mock.patch.object(g, "BACKUP_ROOT", tmp / "backups"), \
             mock.patch.object(g, "audit", return_value=report), \
             mock.patch.object(g, "print_audit"), \
             mock.patch.object(g, "write_html_twin"), \
             telemetry_patch, \
             settings_patch, \
             mock.patch.object(g.sys, "stdin", mock.Mock(isatty=lambda: True)), \
             mock.patch("builtins.input", side_effect=prompt_answering(telemetry="2")), \
             mock.patch.object(g.sys, "stdout", out), \
             mock.patch.object(g.sys, "stderr", err):
            rc = g.main([])
        return rc, err.getvalue(), calls, out.getvalue()

    def test_apply_is_actually_reached(self):
        # 先确认这个测试场景真的能触发到写入步骤，否则下面两个断言全是空的
        tmp = pathlib.Path(tempfile.mkdtemp())
        _, _, calls, _ = self._run_main(tmp, lambda: None)
        self.assertEqual(calls, [2], "apply_telemetry 必须被调用，否则测试没测到东西")

    def test_runtime_error_after_backup_names_the_backup(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        rc, err, calls, _ = self._run_main(
            tmp, lambda: (_ for _ in ()).throw(RuntimeError("模拟写入失败")))
        self.assertEqual(calls, [2])
        self.assertEqual(rc, 2)
        self.assertIn("备份（回滚用）", err)
        self.assertIn("停止前已执行的改动会保留", err)

    def test_telemetry_failure_does_not_abort_the_run(self):
        """2026-10-15：遥测那一步失败不再让整轮停下。

        用户当天就是这么停的（而且那次还是误报），一次失败把 [4/6] 之后的步骤、
        收尾的复检对照表和 HTML 全带走了。现在它只打一行警告，后面照跑。
        """
        tmp = pathlib.Path(tempfile.mkdtemp())
        rc, err, _, out = self._run_main(
            tmp, lambda: (_ for _ in ()).throw(RuntimeError("模拟遥测写入失败")),
            at="telemetry")
        self.assertEqual(rc, 0, f"遥测失败不该让整轮停下：{err}")
        self.assertIn("遥测开关写入失败（其余步骤继续）", out)
        self.assertIn("端点/代理变量", out, "后面的步骤必须照常执行")
        self.assertIn("完成。受保护文件未被动过。", out)

    def test_keyboard_interrupt_is_handled(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        rc, err, calls, _ = self._run_main(
            tmp, lambda: (_ for _ in ()).throw(KeyboardInterrupt()))
        self.assertEqual(calls, [2])
        self.assertEqual(rc, 2)
        self.assertIn("已中断", err)
        self.assertIn("不会自动回滚", err)

    def test_backup_only_covers_the_patched_home(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        _, out, _, _ = self._run_main(tmp, lambda: None)
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
                "rc_files": {".zshrc": [{"line": 2,
                                          "text": "export HTTPS_PROXY=http://127.0.0.1:7897"}]},
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
             mock.patch("builtins.input", side_effect=prompt_answering()), \
             mock.patch.object(g.sys, "stdout", io.StringIO()), \
             mock.patch.object(g.sys, "stderr", io.StringIO()), \
             mock.patch.object(g, "write_html_twin"):
            # 这条会一路跑到收尾，必须挡住最后那份 HTML：report_html 的落盘目录是
            # 模块级常量，patch g.BACKUP_ROOT 拦不住它（抓到过一次真写）。
            rc = g.main([])
        self.assertEqual(rc, 0, "有意清理 .zshrc 不该被报成受保护文件被改动")
        text = (tmp / ".zshrc").read_text(encoding="utf-8")
        self.assertNotIn("HTTPS_PROXY", text)
        self.assertIn("EDITOR=vim", text, "无关行必须保留")


def _pb_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _pb_bytes(field: int, payload: bytes) -> bytes:
    """拼一个 protobuf 的 length-delimited 字段，测试里造 CRX 头用。

    长度要用 varint：公钥 294 字节、签名 256 字节，一个字节装不下。
    """
    return bytes([(field << 3) | 2]) + _pb_varint(len(payload)) + payload


def _fake_crx(public_key: bytes, *, update_url: str = g.WEBRTC_CRX_ENDPOINT,
              name: str = "WebRTC Network Limiter", version: str = "0.2.1.4",
              permissions=("privacy",)) -> bytes:
    """按 CRX3 的格式造一个包：头里放签名块，后面跟一个装 manifest 的 zip。

    扩展 ID 是公钥哈希推出来的，所以调用方只要把 `g.WEBRTC_LIMITER_ID` 换成
    `_crx_id(public_key)`，就能造出「签名对得上」的那种包。
    """
    import io as _io
    import zipfile as _zip
    manifest = json.dumps({"manifest_version": 3, "name": name, "version": version,
                           "update_url": update_url, "permissions": list(permissions)})
    buf = _io.BytesIO()
    with _zip.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", manifest)
    proof = _pb_bytes(1, public_key) + _pb_bytes(2, b"\x00" * 256)
    header = _pb_bytes(2, proof) + _pb_bytes(3, b"signed-header")
    return b"Cr24" + (3).to_bytes(4, "little") + len(header).to_bytes(4, "little") + header + buf.getvalue()


def _crx_id(public_key: bytes) -> str:
    digest = hashlib.sha256(public_key).digest()[:16]
    return "".join("abcdefghijklmnop"[b >> 4] + "abcdefghijklmnop"[b & 15] for b in digest)


class TestWebrtcLimiterDownload(unittest.TestCase):
    """WebRTC Network Limiter 的下载与身份核对。

    这里最要紧的一条是「下到的确实是这个扩展」：判据用签名块里的公钥算出的 ID，
    不是 manifest 里的名字——名字是商店页面显示用的，改一行就行。
    """

    KEY = b"\x30\x82\x01\x22" + bytes(range(256)) + b"\x00" * 34

    def test_crx_url_carries_id_prodversion_and_install_source(self):
        url = g.webrtc_limiter_crx_url("155.0.8059.40")
        self.assertIn("prod=chromiumcrx", url)
        self.assertIn("prodversion=155.0.8059.40", url)
        self.assertIn(g.WEBRTC_LIMITER_ID, url.replace("%3D", "="))
        self.assertIn("installsource%3Dondemand", url)

    def test_id_comes_from_the_signing_key_not_the_name(self):
        blob = _fake_crx(self.KEY)
        self.assertIn(_crx_id(self.KEY), g.crx_public_key_ids(blob))
        with mock.patch.object(g, "WEBRTC_LIMITER_ID", _crx_id(self.KEY)):
            ok, why = g.verify_webrtc_limiter_crx(blob)
        self.assertTrue(ok, why)

    def test_a_package_signed_by_another_key_is_refused(self):
        blob = _fake_crx(b"\x30\x82\x01\x22" + b"other-key" * 30)
        ok, why = g.verify_webrtc_limiter_crx(blob)
        self.assertFalse(ok)
        self.assertIn("扩展 ID 对不上", why)

    def test_a_package_from_somewhere_else_is_refused(self):
        blob = _fake_crx(self.KEY, update_url="https://evil.example/update/crx")
        with mock.patch.object(g, "WEBRTC_LIMITER_ID", _crx_id(self.KEY)):
            ok, why = g.verify_webrtc_limiter_crx(blob)
        self.assertFalse(ok)
        self.assertIn("不是商店的包", why)

    def test_garbage_is_refused_with_a_readable_reason(self):
        for blob in (b"", b"<html>", b"Cr24" + b"\x09\x00\x00\x00" + b"\x00" * 20):
            ok, why = g.verify_webrtc_limiter_crx(blob)
            self.assertFalse(ok)
            self.assertTrue(why)

    def test_download_lands_the_file_and_records_the_hash(self):
        blob = _fake_crx(self.KEY)
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)

        def fake_run(cmd, timeout=20, env=None):
            if "-o" not in cmd:                 # 还有一次是问 Chrome 版本号
                return 0, "155.0.8059.40"
            pathlib.Path(cmd[cmd.index("-o") + 1]).write_bytes(blob)
            return 0, ""

        with mock.patch.object(g, "HOME", tmp), \
             mock.patch.object(g, "WEBRTC_LIMITER_ID", _crx_id(self.KEY)), \
             mock.patch.object(g, "run", side_effect=fake_run):
            got = g.download_webrtc_limiter()
        self.assertTrue(got["ok"], got.get("why"))
        self.assertEqual(got["sha256"], hashlib.sha256(blob).hexdigest())
        self.assertEqual(got["version"], "0.2.1.4")
        self.assertTrue(got["path"].is_file())
        self.assertFalse(list(got["path"].parent.glob("*.part")))

    def test_a_failed_download_leaves_nothing_behind(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        with mock.patch.object(g, "HOME", tmp), mock.patch.object(
                g, "run", return_value=(22, "curl: (22) The requested URL returned error: 404")):
            got = g.download_webrtc_limiter()
        self.assertFalse(got["ok"])
        self.assertIn("下载失败", got["why"])
        # 目录可以建（为了落 .part），但一个包文件都不能留下。
        self.assertFalse(list(tmp.rglob("*.crx")))
        self.assertFalse(list(tmp.rglob("*.part")))

    def test_a_corrupt_download_is_not_kept(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)

        def fake_run(cmd, timeout=20, env=None):
            if "-o" not in cmd:
                return 0, "155.0.8059.40"
            pathlib.Path(cmd[cmd.index("-o") + 1]).write_bytes(b"<html>not a crx</html>")
            return 0, ""

        with mock.patch.object(g, "HOME", tmp), mock.patch.object(g, "run", side_effect=fake_run):
            got = g.download_webrtc_limiter()
        self.assertFalse(got["ok"])
        self.assertIn("没通过校验", got["why"])
        self.assertFalse(list((tmp / ".local").rglob("*.crx")))


class TestWebrtcLimiterState(unittest.TestCase):
    """装没装、设置对不对：读每个资料的 Secure Preferences。"""

    def _home(self, entries):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        for prof, setting in entries:
            d = tmp / "Library" / "Application Support" / "Google" / "Chrome" / prof
            d.mkdir(parents=True)
            (d / "Secure Preferences").write_text(json.dumps({
                "extensions": {"settings": {g.WEBRTC_LIMITER_ID: {
                    "manifest": {"version": "0.2.1.4"}, "from_webstore": True,
                    "preferences": {"webrtc.ip_handling_policy": setting}}}}}) , encoding="utf-8")
        return tmp

    def test_reads_the_setting_out_of_secure_preferences(self):
        tmp = self._home([("Profile 1", g.WEBRTC_LIMITER_SETTING)])
        with mock.patch.object(g, "HOME", tmp):
            state = g.webrtc_limiter_state()
        self.assertTrue(state["readable"])
        self.assertEqual(state["profiles"], ["Profile 1"])
        self.assertEqual(state["setting"], g.WEBRTC_LIMITER_SETTING)

    def test_unreadable_profiles_never_means_not_installed(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        with mock.patch.object(g, "HOME", tmp):
            state = g.webrtc_limiter_state()
        self.assertFalse(state["readable"])
        self.assertIn("读不到", state["why"])
        with mock.patch.object(g, "webrtc_limiter_state", return_value=state), \
             mock.patch.object(g, "download_webrtc_limiter",
                               return_value={"ok": False, "why": "没网"}), \
             mock.patch.object(g, "open_verify_page", return_value={"opened": False}):
            with contextlib.redirect_stdout(io.StringIO()):
                got = g.install_webrtc_limiter()
        self.assertIsNone(got["installed"])

    def test_an_installed_profile_is_reported_as_installed(self):
        tmp = self._home([("Profile 1", g.WEBRTC_LIMITER_SETTING)])
        with mock.patch.object(g, "HOME", tmp):
            with contextlib.redirect_stdout(io.StringIO()):
                got = g.install_webrtc_limiter(
                    open_store=False)
        self.assertIs(got["installed"], True)


class TestWebrtcLimiterCli(unittest.TestCase):
    """--install-webrtc-limiter 不需要 TTY，也不受「Claude Code 只放行只读」限制。"""

    def test_flag_runs_without_a_tty(self):
        with mock.patch.object(sys, "argv", ["account_guard.py", "--install-webrtc-limiter"]), \
             mock.patch.object(g, "install_webrtc_limiter",
                               return_value={"ok": True, "download": {"ok": True}}), \
             mock.patch.object(g, "running_under_claude", return_value=True), \
             mock.patch.object(sys.stdin, "isatty", return_value=False), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(g.main(), 0)

    def test_a_failed_download_exits_two(self):
        with mock.patch.object(sys, "argv", ["account_guard.py", "--install-webrtc-limiter"]), \
             mock.patch.object(g, "install_webrtc_limiter",
                               return_value={"ok": False, "download": {"ok": False}}), \
             mock.patch.object(g, "running_under_claude", return_value=False), \
             mock.patch.object(sys.stdin, "isatty", return_value=False), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(g.main(), 2)


def _no_real_project_scan(case: unittest.TestCase) -> None:
    """让这个用例不要真去扫开发机的项目根。

    项目根的三级兜底会落到 `~/ipe`，本机是 67 个 `.claude` / 13.4 GB，扫一次
    27 秒。用例要的是报告形状与声明读取，不该依赖开发机上有没有那个目录，
    也不该每个跑真 audit 的用例都扫一遍 —— 2026-10-15 就是这么把自检里的
    单测段顶过 900 秒超时的。
    """
    patcher = mock.patch.object(g, "project_roots", return_value=[])
    patcher.start()
    case.addCleanup(patcher.stop)


class TestAuditShape(unittest.TestCase):
    """体检报告的键必须齐全，否则依赖它的 print_audit 会 KeyError。"""

    def setUp(self):
        _no_real_project_scan(self)

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

    def test_probe_preserves_malformed_timezone_shape_without_values(self):
        # 异常 timed/timezone 条目要传到解析端，且只传 null，不泄露原始 plist 值。
        self.assertIn("out[key] = None", g.LOCATION_PROBE)
        self.assertLess(
            g.LOCATION_PROBE.index('if "timed" not in key.lower()'),
            g.LOCATION_PROBE.index("if not isinstance(val, dict)"),
        )


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

    def test_without_project_roots_it_falls_back_to_the_skill_repo(self):
        # 裸跑不再「跳过」：走 project_roots 的兜底（skill 所在的 git 仓）。
        # 以前的用例把整个环境清空，连 PATH 都没了，git 跑不起来才「跳过」——
        # 那不是在测兜底，是在测 manifest 里没 PATH。
        with mock.patch.dict(os.environ, {"CLAUDE_GUARD_PROJECT_ROOTS": ""}, clear=False):
            r = g.check_local_git()
        self.assertTrue(r["roots"], "兜底没生效")
        self.assertFalse(r["note"])
        self.assertTrue(r["repos"], "skill 自己就在一个 git 仓里")

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

    def test_expired_cache_is_not_used(self):
        self.cache.parent.mkdir(parents=True, exist_ok=True)
        self.cache.write_text(json.dumps({"closed": True, "checkedAt": "2020-01-01 00:00"}), encoding="utf-8")
        self.assertIsNone(g.load_location_gate_cache())

    def test_without_cache_it_still_reports_unknown(self):
        with mock.patch.object(g, "location_service_status",
                               return_value={"readable": False, "clients": {}, "note": "要 root"}):
            r = g.check_timezone_layers()
        self.assertIsNone(r["gate_location"])
        self.assertIn("要 root", r.get("gate_location_note", ""))

    def test_summary_marks_cached_result_as_solved_with_timestamp(self):
        checked = g.now_stamp()
        rows = g.build_summary({"A21_timezone_layers": {
            "gate_auto_plist": False, "gate_location": False,
            "gate_location_cached": {"closed": True, "checkedAt": checked}}})
        row = [r for r in rows if r[0] == "时区两道闸"][0]
        self.assertIs(row[1], g.S_OK)
        self.assertIn(checked, row[2])

    def test_summary_does_not_greenlight_expired_cached_result(self):
        rows = g.build_summary({"A21_timezone_layers": {
            "gate_auto_plist": False, "gate_location": False,
            "gate_location_cached": {"closed": True, "checkedAt": "2020-01-01 00:00"}}})
        row = [r for r in rows if r[0] == "时区两道闸"][0]
        self.assertIs(row[1], g.S_NA)

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

    def test_read_probe_does_not_create_temporary_file(self):
        with mock.patch.object(g.tempfile, "mkdtemp") as mkdtemp, \
             mock.patch.object(g.os, "geteuid", return_value=0):
            with mock.patch.object(g, "run", return_value=(1, "")) as run:
                g.location_service_status(persist=False)
        mkdtemp.assert_not_called()
        self.assertIn("-c", run.call_args.args[0])

    def test_non_object_probe_json_is_unknown(self):
        with mock.patch.object(g, "run", return_value=(0, "[]")):
            result = g.location_service_status(persist=True)
        self.assertFalse(result["readable"])
        self.assertIn("不是对象", result["note"])

    def test_malformed_probe_entry_is_unknown_without_traceback(self):
        body = json.dumps({
            "root:p/System/Library/LocationBundles/TimeZone.bundle:": [],
            "valid": {"Authorized": False},
        })
        with mock.patch.object(g, "run", return_value=(0, body)):
            result = g.location_service_status(persist=True)
        self.assertFalse(result["readable"])
        self.assertEqual(result["clients"]["root:p/System/Library/LocationBundles/TimeZone.bundle:"]["state"],
                         "未知（条目格式异常）")
        self.assertIn("格式异常", result["note"])


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
        # 必须把三级兜底全堵死才算「没有项目根」：HOME 下没有 ipe、git 也认不出来。
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        with mock.patch.dict("os.environ", {}, clear=True), \
             mock.patch.object(g, "HOME", tmp), \
             mock.patch.object(g, "run", return_value=(1, "")):
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

    def test_scanned_but_empty_is_a_pass_not_an_unknown(self):
        # 范围扫完了、没有 .claude / 没有权限文件，是结论；标「没测到」会让
        # 全新用户裸跑时永远留两个空行。
        rows = g.build_summary({"A24_project_claude": {"dirs": 0, "roots": ["/tmp/proj"]},
                                "A26_claude_settings": {"files": 0, "roots": ["/tmp/proj"]}})
        for name in ("项目级 .claude 规模", "settings 失效权限"):
            row = [r for r in rows if r[0] == name][0]
            self.assertIs(row[1], g.S_OK, name)
            self.assertIn("proj", row[2])


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
        self._write(["Bash(a *)", ["Bash(b *)", None], "Bash(kill 2220)"])
        g.clean_dead_permissions(self._report(["Bash(kill 2220)"]))
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

    def test_rechecks_rule_before_deleting(self):
        self._write(["Bash(kill 2220)"])
        with mock.patch.object(g, "permission_is_dead", return_value=None):
            done = g.clean_dead_permissions(self._report(["Bash(kill 2220)"]))
        self.assertEqual(done[0]["removed"], 0)
        self.assertIn("状态已变化", done[0]["error"])
        self.assertEqual(json.loads(self.f.read_text())["permissions"]["allow"],
                         ["Bash(kill 2220)"])


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
        self.profile_env = mock.patch.dict(os.environ, {"CLAUDE_GUARD_BROWSER_PROFILE": "test-profile"})
        self.profile_env.start()
        self.addCleanup(self.profile_env.stop)

    def test_row_turns_green_when_the_browser_confirmed_denied(self):
        # 用户在真实浏览器里复核过、结论是「网站拿不到权限」时，这一行该转绿并注明复核时间；
        # 否则一个已经修好的项会永远挂在「待处理」里。
        with mock.patch.object(g, "load_media_permission",
                               return_value={"ok": True, "checkedAt": g.now_stamp(),
                                             "profileScope": "test-profile",
                                             "camera": "denied", "microphone": "denied"}):
            row = self._row({"A7_webrtc": {
                "available": True, "candidates": 1, "mdns": True,
                "local_ips": [], "leaked_public": [], "tun_leak": [],
                "browser": "/x/chromium-1234/Google Chrome for Testing",
                "with_media": {"candidates": 5, "media": "granted",
                               "local_ips": [{"ip": "192.168.1.5", "private": True},
                                             {"ip": "198.18.0.1", "private": True}],
                               "leaked_public": [], "tun_leak": ["198.18.0.1"], "mdns": False}}})
        self.assertIs(row[1], g.S_NA)
        self.assertIn(g.now_stamp(), row[2])

    def test_row_uses_the_media_cache_when_the_probe_was_not_run(self):
        # 完整流程不带 --webrtc 时不跑探测，但复核过的结论该直接用来判这一行；
        # 否则用户刚修好的项会在流程末尾的复检表里又退回成「未探测」。
        with mock.patch.object(g, "load_media_permission",
                               return_value={"ok": True, "checkedAt": g.now_stamp(),
                                             "profileScope": "test-profile"}):
            row = self._row({})
        self.assertIs(row[1], g.S_NA)
        self.assertIn(g.now_stamp(), row[2])

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
        self.assertIs(row[1], g.S_NA)
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
        # 端点探活必须显式关掉。这两个类只 patch 了 run 当夹具，没钉 CLASH_SOCK，
        # 而本机可能真有内核在跑 —— 不钉住的话桩代码会去敲真的内核并真的发 PUT
        # （2026-10-14 合并时踩到：9 个用例因此报 HTTP 400）。
        self.addCleanup(setattr, g, "CLASH_SOCK", g.CLASH_SOCK)
        g.CLASH_SOCK = pathlib.Path("/nonexistent/guard-fixture.sock")
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
        # 端点探活必须显式关掉。这两个类只 patch 了 run 当夹具，没钉 CLASH_SOCK，
        # 而本机可能真有内核在跑 —— 不钉住的话桩代码会去敲真的内核并真的发 PUT
        # （2026-10-14 合并时踩到：9 个用例因此报 HTTP 400）。
        self.addCleanup(setattr, g, "CLASH_SOCK", g.CLASH_SOCK)
        g.CLASH_SOCK = pathlib.Path("/nonexistent/guard-fixture.sock")
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
        self.profile_env = mock.patch.dict(os.environ, {"CLAUDE_GUARD_BROWSER_PROFILE": "test-profile"})
        self.profile_env.start()
        self.addCleanup(self.profile_env.stop)

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
            json.dumps({"intlLocale": "en-US", "checkedAt": g.now_stamp(),
                        "profileScope": "test-profile"}), encoding="utf-8")
        with mock.patch.object(g, "run", side_effect=self._fake_run()):
            out = g.check_browser_locale({"country": "US"})
        self.assertEqual(out["measured"], "en-US")
        self.assertIn("浏览器实测", out["source"])
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


class TestBrowserCacheLoaders(unittest.TestCase):
    """浏览器缓存顶层形状异常时必须收敛为空，不能把 list/null 传给 .get。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.media_cache = self.tmp / "media-permission.json"
        self.locale_cache = self.tmp / "browser-locale.json"
        self.media_path = mock.patch.object(g, "MEDIA_CACHE", self.media_cache)
        self.locale_path = mock.patch.object(g, "LOCALE_CACHE", self.locale_cache)
        self.media_path.start()
        self.locale_path.start()
        self.addCleanup(self.media_path.stop)
        self.addCleanup(self.locale_path.stop)

    def test_media_non_object_json_is_empty(self):
        for payload in ("[]", "null"):
            with self.subTest(payload=payload):
                self.media_cache.write_text(payload, encoding="utf-8")
                self.assertEqual(g.load_media_permission(), {})

    def test_locale_non_object_json_is_empty(self):
        for payload in ("[]", "null"):
            with self.subTest(payload=payload):
                self.locale_cache.write_text(payload, encoding="utf-8")
                self.assertEqual(g.load_browser_locale(), {})


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

    def test_prediction_is_not_green(self):
        row = self._row({"measured": "en-US", "source": "按 AppleLanguages 推定，未跑浏览器复核",
                         "cn": False, "country": "US", "target": "en-US"})
        self.assertIs(row[1], g.S_NA)

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

    def _fake(self, lstart):
        def fake(cmd, **kw):
            if cmd[0] == "pgrep":
                return 0, "711\n"
            if cmd[0] == "env":
                return 0, lstart + "\n"
            return 0, ""
        return fake

    def _lstart(self, when):
        return when.strftime("%a %b %d %H:%M:%S %Y")

    def test_started_before_the_change_needs_restart(self):
        now = g.dt.datetime.now()
        with mock.patch.object(g, "run",
                               side_effect=self._fake(self._lstart(now - g.dt.timedelta(hours=2)))):
            self.assertTrue(
                g.chrome_needs_restart((now - g.dt.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M")))

    def test_started_after_the_change_is_already_effective(self):
        now = g.dt.datetime.now()
        with mock.patch.object(g, "run", side_effect=self._fake(self._lstart(now))):
            self.assertFalse(
                g.chrome_needs_restart((now - g.dt.timedelta(hours=2)).strftime("%Y-%m-%d %H:%M")))

    def test_no_chrome_running_is_unknown(self):
        with mock.patch.object(g, "run", return_value=(1, "")):
            self.assertIsNone(g.chrome_needs_restart("2026-10-01 00:00"))

    def test_unparsable_lstart_is_unknown(self):
        with mock.patch.object(g, "run", side_effect=self._fake("周五 10月  9 12:00:00 2026")):
            self.assertIsNone(g.chrome_needs_restart("2026-10-01 00:00"))

    def test_plist_mtime_alone_is_not_evidence(self):
        """这是被修掉的假阳性：没有「这份值什么时候改的」记录时不许下结论。

        Chrome 运行时会重写它自己那份偏好 plist，mtime 天天动；拿 mtime 判会
        在什么都没改的情况下天天报「要重启」。
        """
        now = g.dt.datetime.now()
        with mock.patch.object(g, "run",
                               side_effect=self._fake(self._lstart(now - g.dt.timedelta(hours=2)))):
            self.assertIsNone(g.chrome_needs_restart(None))
            self.assertIsNone(g.chrome_needs_restart(""))

    def test_unparsable_change_time_is_unknown(self):
        now = g.dt.datetime.now()
        with mock.patch.object(g, "run", side_effect=self._fake(self._lstart(now))):
            self.assertIsNone(g.chrome_needs_restart("昨天"))


class TestLocaleChangeTime(unittest.TestCase):
    """改动的时刻只有「我们亲手改过」才有依据，不许拿启发式凑一个。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="guard-rollback-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._home, self._rb = g.HOME, g.LOCALE_ROLLBACK_FILE
        g.HOME = self.tmp
        g.LOCALE_ROLLBACK_FILE = self.tmp / "state" / "browser-locale-rollback.json"
        self.addCleanup(lambda: setattr(g, "HOME", self._home))
        self.addCleanup(lambda: setattr(g, "LOCALE_ROLLBACK_FILE", self._rb))

    def _rollback(self, payload):
        g.LOCALE_ROLLBACK_FILE.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(payload, str):
            g.LOCALE_ROLLBACK_FILE.write_text(payload, encoding="utf-8")
        else:
            g.LOCALE_ROLLBACK_FILE.write_text(json.dumps(payload), encoding="utf-8")

    def test_no_rollback_file_means_no_evidence(self):
        self.assertIsNone(g.locale_change_time(["en-US"]))

    def test_our_own_edit_is_evidence(self):
        self._rollback({"at": "2026-10-09 22:00", "after": ["en-US"]})
        self.assertEqual(g.locale_change_time(["en-US"]), "2026-10-09 22:00")

    def test_a_different_value_is_not_evidence(self):
        """凭据里改成的是 zh-CN，而现在读出来是 en-US —— 说明这次改动不是我们做的。"""
        self._rollback({"at": "2026-10-09 22:00", "after": ["zh-CN"]})
        self.assertIsNone(g.locale_change_time(["en-US"]))

    def test_corrupt_rollback_file_is_not_evidence(self):
        self._rollback("{ 不是 json")
        self.assertIsNone(g.locale_change_time(["en-US"]))

    def test_non_dict_rollback_file_is_not_evidence(self):
        self._rollback("[1, 2, 3]")
        self.assertIsNone(g.locale_change_time(["en-US"]))

    def test_missing_after_key_is_not_evidence(self):
        self._rollback({"at": "2026-10-09 22:00"})
        self.assertIsNone(g.locale_change_time(["en-US"]))

    def test_missing_at_key_is_not_evidence(self):
        self._rollback({"after": ["en-US"]})
        self.assertIsNone(g.locale_change_time(["en-US"]))

    def test_no_languages_means_no_evidence(self):
        self._rollback({"at": "2026-10-09 22:00", "after": ["en-US"]})
        self.assertIsNone(g.locale_change_time(None))


class TestUndeterminedRestartIsStated(unittest.TestCase):
    """判断不了的时候要在 facts 里说清，不能默默显示成没问题。"""

    def _call(self):
        with mock.patch.object(g, "load_browser_locale", return_value={}), \
             mock.patch.object(g, "chrome_app_languages", return_value=["en-US"]), \
             mock.patch.object(g, "chrome_needs_restart", return_value=None), \
             mock.patch.object(g, "locale_change_time", return_value=None), \
             mock.patch.object(g, "run", return_value=(1, "")), \
             mock.patch.object(g, "check_export_ip", return_value={"country": "US"}):
            return g.check_browser_locale()

    def test_facts_say_it_cannot_be_determined(self):
        out = self._call()
        self.assertIsNone(out["needs_restart"])
        self.assertTrue(any("判断不了" in f for f in out["facts"]))

    def test_unmeasured_restart_does_not_turn_the_row_pending(self):
        """没有依据时表里不许报「待处理」——报绿也不许，要走 measured 那条判定。"""
        with mock.patch.object(g, "check_browser_locale", side_effect=lambda *a, **k: {
                "measured": "en-US", "source": "浏览器实测", "country": "US",
                "target": "en-US", "cn": False, "needs_restart": None, "facts": []}):
            row = None
            for r in g.build_summary({"A27_browser_locale": g.check_browser_locale()}):
                if r[0] == "浏览器 Intl 区域设置":
                    row = r
        self.assertEqual(row[1], g.S_OK)


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

    def test_long_lived_oauth_token_is_never_removed(self):
        # CLAUDE_CODE_OAUTH_TOKEN 里含 auth_token 子串，早先的宽匹配会连它一起删，
        # 结果修完「登录方式」从通过变成待处理——正好和文档推荐的做法相反。
        msg = self._clear({"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat-xxx",
                           "ANTHROPIC_BASE_URL": "https://mirror/anthropic",
                           "KEEP": "1"})
        self.assertIn("ANTHROPIC_BASE_URL", msg)
        self.assertNotIn("OAUTH", msg)
        self.assertEqual(self._after()["env"],
                         {"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat-xxx", "KEEP": "1"})

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

    def test_npmrc_says_it_will_be_removed_with_npm_config(self):
        # npm config delete 会改写 ~/.npmrc，说「只报告、不代改」就是谎报。
        plan = self._plan(self._te(npmrc=[{"line": 2, "text": "proxy=http://127.0.0.1:9"}]))
        self.assertEqual(len(plan["npmrc"]), 1)
        self.assertTrue(any("npm config" in line for line in plan["summary"]))
        self.assertFalse(any("不代改" in line for line in plan["summary"]))


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

    def test_country_from_invalid_ipinfo_is_not_carried_to_ipify(self):
        def mixed(cmd, timeout=20):
            url = cmd[-1]
            if url.endswith("ipinfo.io/json"):
                return 0, json.dumps({"ip": None, "country": "US", "org": "wrong"})
            if "ipify" in url:
                return 0, json.dumps({"ip": "1.2.3.4"})
            return 1, ""
        with mock.patch.object(g, "run", side_effect=mixed):
            info = g.check_export_ip(persist=False)
        self.assertEqual(info["ip"], "1.2.3.4")
        self.assertIsNone(info["country"])
        self.assertEqual(g.expected_exit_result(info, "US")["status"], "unknown")

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


class TestCliInstallMethod(unittest.TestCase):
    """A11：这份 claude 是怎么装上去的。

    口径借自 CCBaga 的 scripts/claude-cli.sh —— 四条通道各自验特征，
    两种「读不出来」分开报，四条都对不上就给 unknown，绝不默认成正常。
    """

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="guard-cli-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._home = g.HOME
        g.HOME = self.tmp
        self.addCleanup(lambda: setattr(g, "HOME", self._home))

    def _native(self, version="1.2.3"):
        """造一份官方安装器的标准形状：versions/<版本> 真文件 + bin/claude 软链。"""
        d = self.tmp / ".local" / "share" / "claude" / "versions"
        d.mkdir(parents=True)
        exe = d / version
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        b = self.tmp / ".local" / "bin"
        b.mkdir(parents=True)
        (b / "claude").symlink_to(exe)
        return exe

    def _quiet(self):
        """让 brew / npm 都探测不到，把干扰隔离掉。"""
        return mock.patch.object(g.shutil, "which", return_value=None)

    def test_native_install_is_identified_with_its_shape(self):
        exe = self._native()
        with self._quiet():
            out = g.detect_cli_install_method(str(self.tmp / ".local" / "bin" / "claude"), str(exe))
        self.assertEqual(out["method"], "native")
        self.assertTrue(out["layout_ok"])
        self.assertEqual(out["probes"]["native_layout"]["launcher_in_versions"], True)
        self.assertEqual(out["error"], "")

    def test_versions_dir_being_a_symlink_is_flagged(self):
        """versions 目录本身是软链，说明文件不在它说自己所在的地方。"""
        real = self.tmp / "elsewhere"
        (real / "versions").mkdir(parents=True)
        d = self.tmp / ".local" / "share"
        d.mkdir(parents=True)
        (d / "claude").symlink_to(real)
        exe = real / "versions" / "1.2.3"
        exe.write_text("x", encoding="utf-8")
        with self._quiet():
            out = g.detect_cli_install_method("/x", str(exe))
        self.assertFalse(out["layout_ok"])

    def test_launcher_pointing_outside_versions_is_flagged(self):
        """bin/claude 是指向别处的软链 —— 形状不对，不是官方安装。"""
        self._native()
        outside = self.tmp / "fake-claude"
        outside.write_text("#!/bin/sh\n", encoding="utf-8")
        b = self.tmp / ".local" / "bin" / "claude"
        b.unlink()
        b.symlink_to(outside)
        with self._quiet():
            out = g.detect_cli_install_method(str(b), str(outside))
        self.assertFalse(out["layout_ok"])
        self.assertEqual(out["probes"]["native_layout"]["launcher_in_versions"], False)

    def test_npm_install_is_identified_by_package_json(self):
        root = self.tmp / "npmroot"
        pkg = root / "@anthropic-ai" / "claude-code"
        pkg.mkdir(parents=True)
        (pkg / "package.json").write_text(
            json.dumps({"name": "@anthropic-ai/claude-code", "version": "9.9.9"}),
            encoding="utf-8")
        with self._quiet(), mock.patch.object(g, "_node_global_roots",
                                              return_value=([root], [])):
            out = g.detect_cli_install_method("/usr/local/bin/claude", "/usr/local/bin/claude")
        self.assertEqual(out["method"], "npm")
        self.assertIn("9.9.9", out["evidence"])

    def test_package_json_with_a_different_name_is_not_evidence(self):
        """同名目录里放着别的包，不算命中。"""
        root = self.tmp / "npmroot"
        pkg = root / "@anthropic-ai" / "claude-code"
        pkg.mkdir(parents=True)
        (pkg / "package.json").write_text(
            json.dumps({"name": "something-else", "version": "1.0.0"}), encoding="utf-8")
        with self._quiet(), mock.patch.object(g, "_node_global_roots",
                                              return_value=([root], [])):
            out = g.detect_cli_install_method("/x/claude", "/x/claude")
        self.assertEqual(out["method"], "unknown")

    def test_bun_install_is_identified(self):
        pkg = (self.tmp / ".bun" / "install" / "global" / "node_modules"
               / "@anthropic-ai" / "claude-code")
        pkg.mkdir(parents=True)
        (pkg / "package.json").write_text(
            json.dumps({"name": "@anthropic-ai/claude-code", "version": "3.3.3"}),
            encoding="utf-8")
        with self._quiet():
            out = g.detect_cli_install_method("/x/claude", "/x/claude")
        self.assertEqual(out["method"], "bun")
        self.assertIn("3.3.3", out["evidence"])

    def test_unknown_install_is_reported_not_guessed(self):
        """PATH 下有 claude，但四条通道一条都对不上 —— 给 unknown，不猜。"""
        with self._quiet():
            out = g.detect_cli_install_method("/opt/whatever/claude", "/opt/whatever/claude")
        self.assertEqual(out["method"], "unknown")
        self.assertIn("一条都对不上", out["evidence"])

    def test_no_cli_at_all_is_also_unknown(self):
        with self._quiet():
            out = g.detect_cli_install_method(None, None)
        self.assertEqual(out["method"], "unknown")
        self.assertIn("没有 claude", out["evidence"])

    def test_probe_failure_is_not_reported_as_not_installed(self):
        """探测本身读不出来，必须单独记在 error 里，不能混成「没装」。"""
        with self._quiet(), mock.patch.object(
                g, "_node_global_roots", return_value=([], ["npm 读不出全局根"])):
            out = g.detect_cli_install_method("/x/claude", "/x/claude")
        self.assertEqual(out["method"], "unknown")
        self.assertIn("npm", out["error"])

    def test_unreadable_shape_is_not_a_verdict(self):
        """什么都读不到时 layout_ok 保持 True —— 没有正面证据就不冤判。"""
        with self._quiet():
            out = g.detect_cli_install_method("/opt/whatever/claude", "/opt/whatever/claude")
        self.assertTrue(out["layout_ok"])


class TestRunEnv(unittest.TestCase):
    """run() 的环境变量是**叠加**不是替换。"""

    def test_env_is_added_on_top_of_os_environ(self):
        code, body = g.run(["bash", "-c", "echo $GUARD_PROBE_X"], env={"GUARD_PROBE_X": "hello"})
        self.assertEqual(code, 0)
        self.assertEqual(body.strip(), "hello")

    def test_existing_environment_survives(self):
        """只传一两个变量，PATH 之类必须还在，否则命令都跑不起来。"""
        code, body = g.run(["bash", "-c", "echo $PATH"], env={"GUARD_PROBE_X": "1"})
        self.assertEqual(code, 0)
        self.assertTrue(body.strip())

    def test_without_env_nothing_is_added(self):
        code, body = g.run(["bash", "-c", "echo ${GUARD_PROBE_X:-unset}"])
        self.assertEqual(body.strip(), "unset")


class TestCliIntegrityRow(unittest.TestCase):
    """表里的「CLI 完整性」一行：签名有效 ≠ 这份就是现在该在用的那份。"""

    def _rep(self, **over):
        ci = {
            "cli_path": "/x/claude", "cli_real": "/x/versions/1.2.3",
            "cli_version": "1.2.3 (Claude Code)", "current_version": "1.2.3",
            "versions": [{"name": "1.2.3", "bytes": 1}], "version_count": 1,
            "stale_count": 0, "stale_bytes": 0, "total_bytes": 1,
            "version_runs": True, "version_ok": True, "current_present": True,
            "install": {"method": "native", "layout_ok": True, "evidence": "x", "error": ""},
            "signature": {"checked": True, "verified": True,
                          "authority": "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)"},
            "note": "",
        }
        ci.update(over)
        return {"A11_client_integrity": ci}

    def _row(self, report):
        for r in g.build_summary(report):
            if r[0] == "CLI 完整性":
                return r
        self.fail("表里没有「CLI 完整性」这一行")

    def test_native_with_verified_signature_stays_green(self):
        row = self._row(self._rep())
        self.assertEqual(row[1], g.S_OK)
        self.assertIn("native 安装", row[2])
        self.assertIn("验签通过", row[2])

    def test_unknown_install_method_is_flagged(self):
        row = self._row(self._rep(install={"method": "unknown", "layout_ok": True,
                                           "evidence": "", "error": ""}))
        self.assertEqual(row[1], g.S_FIX)
        self.assertIn("安装方式未知", row[2])

    def test_binary_that_does_not_run_is_flagged(self):
        row = self._row(self._rep(version_runs=False, version_ok=False))
        self.assertEqual(row[1], g.S_FIX)
        self.assertIn("跑不出 --version", row[2])

    def test_odd_version_string_is_flagged(self):
        row = self._row(self._rep(version_ok=False))
        self.assertEqual(row[1], g.S_FIX)
        self.assertIn("版本号不像正常版本", row[2])

    def test_broken_symlink_target_is_flagged(self):
        row = self._row(self._rep(current_present=False))
        self.assertEqual(row[1], g.S_FIX)
        self.assertIn("不在 versions 目录里", row[2])

    def test_wrong_link_shape_is_flagged(self):
        row = self._row(self._rep(install={"method": "native", "layout_ok": False,
                                           "evidence": "x", "error": ""}))
        self.assertEqual(row[1], g.S_FIX)
        self.assertIn("链接形状不对", row[2])

    def test_problems_outrank_the_unverified_branch(self):
        """这两个毛病同时存在时，不能落到「（未能验签）」那个绿灯分支。"""
        row = self._row(self._rep(install={"method": "unknown", "layout_ok": True,
                                           "evidence": "", "error": ""},
                                  signature={"checked": False}))
        self.assertEqual(row[1], g.S_FIX)
        self.assertNotIn("未能验签", row[2])

    def test_old_report_without_install_key_is_not_accused(self):
        """本次改动之前生成的报告没有 install 键 —— 不能凭空指控「安装方式未知」。"""
        import copy
        rep = copy.deepcopy(self._rep())
        rep["A11_client_integrity"].pop("install")
        row = self._row(rep)
        self.assertEqual(row[1], g.S_OK)
        self.assertNotIn("未知", row[2])

    def test_row_without_cli_is_unmeasured_not_green(self):
        row = self._row(self._rep(cli_path=None, cli_version=None))
        self.assertEqual(row[1], g.S_NA)


class TestVerifyRoute(unittest.TestCase):
    """本地复核服务的令牌路由。"""

    TOKEN = "a" * 48

    def test_token_root_forms(self):
        for path in ("/" + self.TOKEN, "/" + self.TOKEN + "/"):
            self.assertEqual(g._verify_route(path, self.TOKEN), "/")

    def test_token_result_route(self):
        self.assertEqual(g._verify_route("/" + self.TOKEN + "/result", self.TOKEN), "/result")

    def test_wrong_token_is_rejected(self):
        self.assertIsNone(g._verify_route("/" + "b" * 48 + "/", self.TOKEN))
        self.assertIsNone(g._verify_route("/" + "b" * 48 + "/result", self.TOKEN))

    def test_missing_token_is_rejected(self):
        self.assertIsNone(g._verify_route("/", self.TOKEN))
        self.assertIsNone(g._verify_route("/result", self.TOKEN))

    def test_a_longer_segment_is_not_a_token_match(self):
        """令牌只是一段前缀还不够，整段必须完全相等。"""
        self.assertIsNone(g._verify_route("/" + self.TOKEN + "x/", self.TOKEN))

    def test_query_and_fragment_are_ignored(self):
        self.assertEqual(g._verify_route("/" + self.TOKEN + "/?x=1", self.TOKEN), "/")
        self.assertEqual(
            g._verify_route("/" + self.TOKEN + "/result#y", self.TOKEN), "/result")

    def test_extra_segments_are_rejected(self):
        self.assertIsNone(g._verify_route("/" + self.TOKEN + "/result/extra", self.TOKEN))

    def test_tokens_are_random_and_long_enough(self):
        a, b = g._verify_token(), g._verify_token()
        self.assertNotEqual(a, b)
        self.assertEqual(len(a), g.VERIFY_TOKEN_BYTES * 2)


class TestVerifyServerToken(unittest.TestCase):
    """端到端：真起一次本地复核服务，看令牌是不是真的拦得住。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="guard-token-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._home, self._cache = g.HOME, g.MEDIA_CACHE
        g.HOME, g.MEDIA_CACHE = self.tmp, self.tmp / "media.json"

        def restore():
            g.HOME, g.MEDIA_CACHE = self._home, self._cache

        self.addCleanup(restore)

    def test_token_gates_both_the_page_and_the_report(self):
        import http.server
        import threading
        import urllib.error
        import urllib.request

        token = "c" * 48
        buf = io.StringIO()
        box: dict = {}
        bound = threading.Event()

        # Capture readiness after the real server has completed bind/listen.
        # Polling redirected stdout is racy in CI while the worker waits for
        # a browser response.  Keep the production HTTPServer implementation
        # so this still exercises the real socket and token gate.
        real_server = http.server.ThreadingHTTPServer

        class CapturingServer(real_server):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                host, port = self.server_address[:2]
                box["url"] = f"http://{host}:{port}/{token}/"
                bound.set()

        def serve():
            try:
                with contextlib.redirect_stdout(buf):
                    box["out"] = g.verify_media_permission(timeout=8)
            except BaseException as exc:
                box["error"] = f"{type(exc).__name__}: {exc}"
                raise

        with mock.patch.object(g, "_verify_token", return_value=token), \
             mock.patch.object(http.server, "ThreadingHTTPServer", CapturingServer):
            t = threading.Thread(target=serve, daemon=True)
            t.start()
            self.assertTrue(
                bound.wait(timeout=30),
                f"本地复核服务未完成端口绑定（线程存活={t.is_alive()}，错误={box.get('error')!r}）",
            )
            url = box.get("url")
        self.assertIsInstance(url, str)
        bare = url.replace(token + "/", "")

        # ① 不知道令牌的本地进程连页面都取不到
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(bare, timeout=5)
        self.assertEqual(cm.exception.code, 404)

        # ② 带令牌能取到页面，且页面按当前路径回传（不是写死的 /result）
        with urllib.request.urlopen(url, timeout=5) as resp:
            page = resp.read().decode("utf-8")
            self.assertEqual(resp.status, 200)
        self.assertIn("location.pathname.replace", page)

        # ③ 不带令牌投一份「摄像头已拒绝」→ 404，采集器收不到
        body = b'{"camera":"denied","microphone":"denied"}'
        headers = {"Content-Type": "application/json"}
        req_bad = urllib.request.Request(bare + "result", data=body, headers=headers, method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm2:
            urllib.request.urlopen(req_bad, timeout=5)
        self.assertEqual(cm2.exception.code, 404)

        # ④ 带令牌投同一份 → 204，函数确实拿到了
        req_ok = urllib.request.Request(url + "result", data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req_ok, timeout=5) as resp2:
            self.assertEqual(resp2.status, 204)
        t.join(timeout=10)
        self.assertFalse(t.is_alive(), "本地复核服务线程未在回传后退出")
        self.assertEqual(box["out"].get("camera"), "denied")

    def test_oversized_report_is_truncated_not_swallowed_whole(self):
        """声明 200KB，只读前 64KB —— 别让谁塞个巨大 body 把内存吃满。"""
        self.assertEqual(g.VERIFY_MAX_BODY, 65536)

    def test_loopback_server_does_not_reverse_resolve_before_bind(self):
        """CI 的反向 DNS 卡住时，本地复核服务仍须能绑定并关闭。"""
        import http.server
        import socket

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

        with mock.patch.object(socket, "getfqdn", side_effect=AssertionError("reverse DNS")):
            server = g._new_loopback_server(Handler)
        try:
            self.assertEqual(server.server_address[0], "127.0.0.1")
            self.assertGreater(server.server_address[1], 0)
        finally:
            server.server_close()


class TestRunLock(unittest.TestCase):
    """加固流程一次只跑一个（借自 CCBaga 的任务锁）。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="guard-lock-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._home = g.HOME
        g.HOME = self.tmp
        self.addCleanup(lambda: setattr(g, "HOME", self._home))

    def test_second_acquire_is_refused_while_held(self):
        ok, _ = g.acquire_run_lock()
        self.assertTrue(ok)
        ok2, note2 = g.acquire_run_lock()
        self.assertFalse(ok2)
        self.assertIn("已经有另一个加固流程在跑", note2)

    def test_release_frees_the_lock(self):
        g.acquire_run_lock()
        g.release_run_lock()
        self.assertFalse(g.run_lock_path().exists())
        ok, _ = g.acquire_run_lock()
        self.assertTrue(ok)

    def test_lock_file_records_pid_and_is_owner_only(self):
        g.acquire_run_lock()
        path = g.run_lock_path()
        self.assertEqual(path.read_text(encoding="utf-8").split()[0], str(os.getpid()))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_stale_lock_from_a_dead_process_is_taken_over(self):
        """上次 Ctrl-C 或断电留下的锁不能把机器锁死。"""
        path = g.run_lock_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("99999999 2026-01-01 00:00\n", encoding="utf-8")
        ok, _ = g.acquire_run_lock()
        self.assertTrue(ok)
        self.assertEqual(path.read_text(encoding="utf-8").split()[0], str(os.getpid()))

    def test_empty_lock_file_counts_as_stale(self):
        path = g.run_lock_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
        ok, _ = g.acquire_run_lock()
        self.assertTrue(ok)

    def test_release_does_not_remove_someone_elses_lock(self):
        path = g.run_lock_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("99999999 2026-01-01 00:00\n", encoding="utf-8")
        g.release_run_lock()
        self.assertTrue(path.exists(), "不该删掉别人正在用的锁")

    def test_release_without_a_lock_is_a_noop(self):
        g.release_run_lock()  # 不该抛
        self.assertFalse(g.run_lock_path().exists())


class TestBrowserTimezoneFact(unittest.TestCase):
    """A27 顺手把浏览器时区报成事实 —— 只报事实，不下判定。"""

    def setUp(self):
        self.profile_env = mock.patch.dict(os.environ, {"CLAUDE_GUARD_BROWSER_PROFILE": "test-profile"})
        self.profile_env.start()
        self.addCleanup(self.profile_env.stop)

    def _call(self, cached, exit_ip):
        if cached.get("intlLocale"):
            cached = {**cached, "checkedAt": g.now_stamp(), "profileScope": "test-profile"}
        with mock.patch.object(g, "load_browser_locale", return_value=cached), \
             mock.patch.object(g, "run", return_value=(1, "")), \
             mock.patch.object(g, "check_export_ip", return_value=exit_ip):
            return g.check_browser_locale()

    def test_browser_timezone_is_reported(self):
        out = self._call({"intlLocale": "en-US", "timeZone": "Asia/Taipei"},
                         {"country": "US", "timezone": "America/New_York"})
        self.assertEqual(out["browser_timezone"], "Asia/Taipei")
        self.assertTrue(any("Asia/Taipei" in f for f in out["facts"]))

    def test_mismatch_with_the_exit_is_a_stated_combination_not_a_fault(self):
        out = self._call({"intlLocale": "en-US", "timeZone": "Asia/Taipei"},
                         {"country": "US", "timezone": "America/New_York"})
        joined = " ".join(out["facts"])
        self.assertIn("America/New_York", joined)
        self.assertIn("不是故障", joined)
        # 判定只看 locale：时区不一致绝不能把这一项翻成大陆简体
        self.assertFalse(out["cn"])

    def test_matching_timezones_are_reported_as_matching(self):
        out = self._call({"intlLocale": "en-US", "timeZone": "America/New_York"},
                         {"country": "US", "timezone": "America/New_York"})
        self.assertTrue(any("一致" in f for f in out["facts"]))

    def test_no_timezone_in_the_cache_adds_no_timezone_fact(self):
        out = self._call({"intlLocale": "en-US"}, {"country": "US",
                                                   "timezone": "America/New_York"})
        self.assertIsNone(out["browser_timezone"])
        self.assertFalse(any("浏览器时区" in f for f in out["facts"]))

    def test_exit_timezone_unknown_still_reports_the_browser_side(self):
        out = self._call({"intlLocale": "en-US", "timeZone": "Asia/Taipei"}, {"country": "US"})
        self.assertEqual(out["browser_timezone"], "Asia/Taipei")
        self.assertFalse(any("一致" in f for f in out["facts"]))


class TestRedactCredentials(unittest.TestCase):
    """带凭据的代理 URL 不许原样进报告（借自 CCBaga 的 SECURITY 数据流表）。"""

    def test_user_and_password_are_replaced(self):
        self.assertEqual(g.redact_credentials("http://user:pass@1.2.3.4:8080"),
                         "http://***@1.2.3.4:8080")

    def test_all_schemes_are_covered(self):
        for scheme in ("http", "https", "socks5", "socks5h", "socks"):
            self.assertEqual(g.redact_credentials(f"{scheme}://u:p@h:1"),
                             f"{scheme}://***@h:1")

    def test_user_without_a_password_is_also_redacted(self):
        self.assertEqual(g.redact_credentials("http://token@host"), "http://***@host")

    def test_it_works_inside_a_longer_line(self):
        self.assertEqual(
            g.redact_credentials("export HTTPS_PROXY=http://u:p@127.0.0.1:7897"),
            "export HTTPS_PROXY=http://***@127.0.0.1:7897")

    def test_an_email_is_not_mistaken_for_a_credential(self):
        """没有 scheme:// 的 @ 不能抹 —— 否则邮箱、用户名都会被毁掉。"""
        self.assertEqual(g.redact_credentials("user@example.com"), "user@example.com")

    def test_plain_hosts_are_untouched(self):
        for text in ("http://127.0.0.1:7897", "1.2.3.4:8080", ""):
            self.assertEqual(g.redact_credentials(text), text)


class TestTerminalEnvRedactsCredentials(unittest.TestCase):
    """脱敏要发生在**进报告**那一步，不然 JSON 报告里还是明文。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="guard-redact-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._home = g.HOME
        g.HOME = self.tmp
        self.addCleanup(lambda: setattr(g, "HOME", self._home))
        (self.tmp / ".npmrc").write_text(
            "proxy=http://u:p@127.0.0.1:7897\n", encoding="utf-8")
        (self.tmp / ".zshrc").write_text(
            'export HTTPS_PROXY=http://u:p@127.0.0.1:7897\n', encoding="utf-8")

    def _env(self):
        def fake(cmd, **kw):
            if cmd[:3] == ["npm", "config", "get"]:
                return 0, "null\n"
            if cmd[0] == "git":
                return 0, "\n"
            return 1, ""
        with mock.patch.object(g, "run", side_effect=fake), \
             mock.patch.dict(g.os.environ, {"HTTPS_PROXY": "http://u:p@10.0.0.1:3128"}):
            return g.check_terminal_env()

    def test_npmrc_line_is_redacted(self):
        out = self._env()
        self.assertTrue(out["npmrc"])
        self.assertNotIn("u:p@", out["npmrc"][0]["text"])
        self.assertIn("***@", out["npmrc"][0]["text"])

    def test_shell_config_line_is_redacted(self):
        out = self._env()
        for hits in out["rc_files"].values():
            for hit in hits:
                self.assertNotIn("u:p@", hit["text"])

    def test_environment_variable_value_is_redacted(self):
        out = self._env()
        self.assertTrue(out["env_hits"])
        self.assertFalse(any("u:p@" in h for h in out["env_hits"]))

    def test_nothing_secret_survives_a_json_round_trip(self):
        """整份报告序列化一遍，也不许出现明文凭据。"""
        blob = json.dumps(self._env(), ensure_ascii=False)
        self.assertNotIn("u:p@", blob)


class TestGeoWordMatching(unittest.TestCase):
    """地理词不许匹配技术写法 —— `Asia/Shanghai` 不是「写自己人在哪」。"""

    def test_timezone_identifier_is_not_a_hit(self):
        for text in ("业务日按 Asia/Shanghai", "ZoneInfo('Asia/Shanghai')",
                     "TZ=Asia/Shanghai", "America/Chicago 与 Asia/Shanghai"):
            self.assertIsNone(g.GEO_WORD_RE.search(text), text)

    def test_glued_brand_names_are_not_hits(self):
        for text in ("ChinaMobile 的接口", "ShenzhenAirport", "beijing_time"):
            self.assertIsNone(g.GEO_WORD_RE.search(text), text)

    def test_a_plain_mention_is_still_a_hit(self):
        for text in ("我人在北京", "办公地点在上海。", "China.", "based in Shenzhen"):
            self.assertIsNotNone(g.GEO_WORD_RE.search(text), text)

    def test_a_sentence_final_period_does_not_hide_the_hit(self):
        """句号收尾是真命中，尾部不能把点也排除掉。"""
        m = g.GEO_WORD_RE.search("数据中心在 China.")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(0), "China")

    def test_hits_carry_the_line_number(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="guard-geo-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "CLAUDE.md").write_text("第一行\n我人在北京\n", encoding="utf-8")
        with mock.patch.object(g, "HOME", tmp), \
             mock.patch.object(g, "project_roots", return_value=[]):
            out = g.check_geo_words()
        self.assertEqual(len(out["hits"]), 1)
        self.assertEqual(out["hits"][0]["line"], 2)


class TestLocalGitRootMayBeARepo(unittest.TestCase):
    """项目根本身就是一个仓时，必须算它，且不许把子目录报成没版本控制。"""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="guard-git-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_root_that_is_a_repo_is_counted(self):
        repo = self.tmp / "myrepo"
        (repo / ".git").mkdir(parents=True)
        (repo / "backend").mkdir()
        (repo / "docs").mkdir()
        with mock.patch.dict(g.os.environ, {"CLAUDE_GUARD_PROJECT_ROOTS": str(repo)}), \
             mock.patch.object(g, "run", return_value=(0, "")):
            out = g.check_local_git()
        self.assertEqual(out["repos"], [str(repo)])
        self.assertEqual(out["no_git"], [], "子目录不是独立仓库，不该报没版本控制")

    def test_worktree_git_file_also_counts(self):
        """worktree 里的 .git 是文件不是目录 —— 判存在不判目录。"""
        repo = self.tmp / "wt"
        repo.mkdir()
        (repo / ".git").write_text("gitdir: /somewhere/.git/worktrees/wt\n", encoding="utf-8")
        with mock.patch.dict(g.os.environ, {"CLAUDE_GUARD_PROJECT_ROOTS": str(repo)}), \
             mock.patch.object(g, "run", return_value=(0, "")):
            out = g.check_local_git()
        self.assertEqual(out["repos"], [str(repo)])

    def test_container_root_still_scans_children(self):
        """老用法（根是放仓的容器目录）不能改坏。"""
        (self.tmp / "repo-a" / ".git").mkdir(parents=True)
        (self.tmp / "plain").mkdir()
        with mock.patch.dict(g.os.environ, {"CLAUDE_GUARD_PROJECT_ROOTS": str(self.tmp)}), \
             mock.patch.object(g, "run", return_value=(0, "")):
            out = g.check_local_git()
        self.assertEqual(out["repos"], [str(self.tmp / "repo-a")])
        self.assertEqual(out["no_git"], [str(self.tmp / "plain")])


class TestIterationOneSafety(unittest.TestCase):
    """回归本轮四项维护中的边界，不触碰真实主机状态。"""

    def test_proxy_probe_failure_is_unknown(self):
        with mock.patch.object(g, "run", return_value=(1, "")):
            report = g.check_proxy_residue()
        row = [r for r in g.build_summary({"A1_proxy_residue": report})
               if r[0] == "系统代理残留"][0]
        self.assertIs(row[1], g.S_NA)

    def test_dns_mixed_fake_and_real_is_a_leak(self):
        def fake(cmd, timeout=20):
            if cmd[0] == "dig":
                return 0, "198.18.0.2\n1.2.3.4\n"
            return 0, "nameserver[0] : 1.1.1.1\n"
        with mock.patch.object(g, "run", side_effect=fake):
            report = g.check_dns()
        self.assertEqual(report["real_ip_hosts"], ["example.com", "api.anthropic.com", "claude.ai"])

    def test_audit_export_state_is_opt_in(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        old_home = g.HOME
        g.HOME = tmp
        self.addCleanup(setattr, g, "HOME", old_home)
        with mock.patch.object(g, "run", return_value=(1, "")):
            g.check_export_ip(persist=False)
        self.assertFalse((tmp / ".local" / "state" / "claude-guard" / "export-ip.json").exists())

    def test_stale_or_unbound_cache_is_not_fresh(self):
        stale = {"checkedAt": "2020-01-01 00:00", "profileScope": "test"}
        unbound = {"checkedAt": g.now_stamp()}
        self.assertFalse(g.cache_is_fresh(stale)[0])
        self.assertFalse(g.cache_is_fresh(unbound)[0])

    def test_a_fresh_user_gets_a_usable_cache_without_declaring_a_profile(self):
        # 全新用户不会去设 CLAUDE_GUARD_BROWSER_PROFILE：没声明时按默认资料记，
        # 否则跑一轮永远拿不到浏览器 Intl 的结论。
        cache = {"intlLocale": "en-US", "checkedAt": g.now_stamp(),
                 "profileScope": "default", "openedBy": "script"}
        env = {"CLAUDE_GUARD_BROWSER_PROFILE": "", "CLAUDE_GUARD_BROWSER_PROFILE_DIR": ""}
        with mock.patch.dict(os.environ, env, clear=False):
            self.assertTrue(g.cache_is_fresh(cache)[0])

    def test_declaring_a_different_profile_still_invalidates_the_default_cache(self):
        cache = {"intlLocale": "en-US", "checkedAt": g.now_stamp(), "profileScope": "default"}
        with mock.patch.dict(os.environ, {"CLAUDE_GUARD_BROWSER_PROFILE": "work"}, clear=False):
            self.assertFalse(g.cache_is_fresh(cache)[0])

    def test_browser_cache_requires_current_explicit_profile_identity(self):
        cache = {"intlLocale": "en-US", "checkedAt": g.now_stamp(), "profileScope": "profile-a"}
        with mock.patch.dict(os.environ, {"CLAUDE_GUARD_BROWSER_PROFILE": "profile-b"}):
            self.assertFalse(g.cache_is_fresh(cache)[0])

    def test_custom_claude_config_scope_is_out_of_scope_and_not_green(self):
        custom = pathlib.Path(tempfile.mkdtemp()) / "custom-claude"
        self.addCleanup(shutil.rmtree, custom.parent, ignore_errors=True)
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(custom)}, clear=False):
            scope = g.claude_config_scope()
            self.assertTrue(scope["custom"])
            self.assertTrue(scope["out_of_scope"])
            report = {
                "scope_manifest": scope,
                "A1_terminal_env": {"env_hits": [], "rc_files": {}, "npm": {}, "git": {}},
                "A2_anthropic_base_url": {"hits": []},
                "A3_telemetry": {"any_set": False},
            }
            rows = g.build_summary(report)
        for name in ("终端 / shell / npm / git 代理", "settings.json 端点与凭据", "遥测三键"):
            row = [item for item in rows if item[0] == name][0]
            self.assertIs(row[1], g.S_NA, name)

    def test_full_repair_save_flag_does_not_persist_before_confirm(self):
        with mock.patch.object(g, "audit") as audit:
            self.assertEqual(g.main(["--save-audit"]), 2)
        audit.assert_not_called()

    def test_audit_rejects_cache_writing_browser_checks(self):
        with mock.patch.object(g, "verify_media_permission") as media, \
             mock.patch.object(g, "verify_browser_locale") as locale:
            self.assertEqual(g.main(["--audit", "--check-media"]), 2)
            self.assertEqual(g.main(["--audit", "--check-locale"]), 2)
        media.assert_not_called()
        locale.assert_not_called()

    def test_public_webrtc_leak_outranks_media_cache(self):
        report = {"A7_webrtc": {
            "available": True, "leaked_public": ["8.8.8.8"],
            "with_media": {"tun_leak": [], "local_ips": []},
            "browser": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        }}
        with mock.patch.object(g, "load_media_permission", return_value={
            "ok": True, "checkedAt": g.now_stamp(), "profileScope": "test-profile"}), \
             mock.patch.dict(os.environ, {"CLAUDE_GUARD_BROWSER_PROFILE": "test-profile"}), \
             mock.patch.object(g, "chromium_is_headless_shell", return_value=False):
            row = [item for item in g.build_summary(report) if item[0] == "WebRTC 泄漏"][0]
        self.assertIs(row[1], g.S_BAD)

    def test_backup_plan_includes_configuration_targets(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        old_home, old_settings = g.HOME, g.SETTINGS
        g.HOME, g.SETTINGS = tmp, tmp / ".claude" / "settings.json"
        self.addCleanup(setattr, g, "HOME", old_home)
        self.addCleanup(setattr, g, "SETTINGS", old_settings)
        paths, _ = g.backup_paths_for_plan({"rc_files": {".zshrc": []}}, {
            "A26_claude_settings": {"dead": [{"file": ".claude/settings.local.json"}]}
        })
        self.assertIn(tmp / ".npmrc", paths)
        self.assertIn(tmp / ".gitconfig", paths)
        self.assertIn(tmp / ".claude/settings.local.json", paths)
        self.assertIn(tmp / ".local/bin/claude-safe", paths)


class TestExpectedExitAndRecovery(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.old_home, self.old_backup = g.HOME, g.BACKUP_ROOT
        g.HOME, g.BACKUP_ROOT = self.tmp, self.tmp / "backups"
        self.addCleanup(setattr, g, "HOME", self.old_home)
        self.addCleanup(setattr, g, "BACKUP_ROOT", self.old_backup)

    def test_expected_country_and_ip_match_are_structured(self):
        result = g.expected_exit_result(
            {"ip": "1.2.3.4", "country": "us"}, "US", "1.2.3.4")
        self.assertEqual(result["status"], "ok")
        self.assertIs(result["match"], True)
        self.assertEqual(result["actual"]["exit_ip"], "1.2.3.4")

    def test_expected_mismatch_blocks_locale_repair(self):
        expected = g.expected_exit_result({"ip": "1.2.3.4", "country": "JP"}, "US")
        self.assertEqual(expected["status"], "bad")
        rep = {"cn": True, "target": "en-US", "target_blocked": True}
        self.assertIn("预期出口不符", g.clear_browser_locale(rep))
        row = [r for r in g.build_summary({
            "A1_export_ip": {"ip": "1.2.3.4", "country": "JP", "expected": expected},
            "A27_browser_locale": rep}) if r[0] == "浏览器 Intl 区域设置"][0]
        self.assertIs(row[1], g.S_NA)

    def test_declared_but_unknown_exit_also_blocks_locale_repair(self):
        expected = g.expected_exit_result(
            {"ip": "1.2.3.4", "country": "US", "source_conflict": ["1.2.3.4", "2.2.2.2"]},
            "US")
        locale = g.check_browser_locale
        with mock.patch.object(g, "run", return_value=(1, "")), \
             mock.patch.object(g, "load_browser_locale", return_value={}):
            rep = locale({"country": "US"}, expected)
        self.assertTrue(rep["target_blocked"])

    def test_conflict_and_missing_country_are_unknown(self):
        for actual in (
            {"ip": "1.2.3.4", "country": None},
            {"ip": None, "country": "US"},
            {"ip": "not-an-ip", "country": "US"},
            {"ip": "1.2.3.4", "country": "US", "source_conflict": ["1.2.3.4", "2.2.2.2"]},
        ):
            result = g.expected_exit_result(actual, "US")
            self.assertEqual(result["status"], "unknown")
            self.assertIsNone(result["match"])

    def test_restore_existing_and_new_file(self):
        existing, created = self.tmp / "existing", self.tmp / "created"
        existing.write_text("before", encoding="utf-8")
        backup = g.create_backup([existing, created])
        g._refresh_backup_manifest(backup, "before")
        existing.write_text("after", encoding="utf-8")
        created.write_text("new", encoding="utf-8")
        g._refresh_backup_manifest(backup, "after")
        with mock.patch.object(g.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value="CONFIRM"):
            self.assertEqual(g.restore_backup(backup), 0)
        self.assertEqual(existing.read_text(encoding="utf-8"), "before")
        self.assertFalse(created.exists())

    def test_restore_refuses_corrupt_backup_and_external_drift(self):
        target = self.tmp / "target"
        target.write_text("before", encoding="utf-8")
        backup = g.create_backup([target])
        g._refresh_backup_manifest(backup, "before")
        target.write_text("after", encoding="utf-8")
        g._refresh_backup_manifest(backup, "after")
        (backup / "files" / next((p.name for p in (backup / "files").iterdir()))).write_text(
            "corrupted", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "校验失败"):
            g.restore_backup(backup, preview=True)

    def test_restore_refuses_mode_drift_even_when_content_matches(self):
        target = self.tmp / "mode-target"
        target.write_text("before", encoding="utf-8")
        backup = g.create_backup([target])
        g._refresh_backup_manifest(backup, "before")
        target.write_text("after", encoding="utf-8")
        g._refresh_backup_manifest(backup, "after")
        target.chmod(0o600 if (target.stat().st_mode & 0o777) != 0o600 else 0o644)
        with self.assertRaisesRegex(RuntimeError, "漂移"):
            g.restore_backup(backup, preview=True)

    def test_restore_rejects_v1_and_symlink(self):
        old = self.tmp / "v1"
        old.mkdir()
        (old / "manifest.json").write_text(json.dumps({"items": []}), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "备份目录|v2"):
            g.restore_backup(old, preview=True)

    def test_restore_rejects_preexisting_target_symlink(self):
        target, victim = self.tmp / "target", self.tmp / "victim"
        target.write_text("before", encoding="utf-8")
        victim.write_text("keep", encoding="utf-8")
        backup = g.create_backup([target])
        g._refresh_backup_manifest(backup, "before")
        target.write_text("after", encoding="utf-8")
        g._refresh_backup_manifest(backup, "after")
        target.unlink()
        target.symlink_to(victim)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            g.restore_backup(backup, preview=True)

    def test_backup_rejects_home_parent_symlink(self):
        outside = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        linked = self.tmp / "linked"
        linked.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "父目录.*symlink"):
            g.create_backup([linked / "settings.json"])

    def test_backup_rechecks_source_after_copy(self):
        target = self.tmp / "target"
        target.write_text("before", encoding="utf-8")
        real_state = g._file_state(target)
        changed_state = dict(real_state, sha256="f" * 64)
        with mock.patch.object(g, "_file_state", side_effect=[real_state, changed_state]):
            with self.assertRaisesRegex(RuntimeError, "内容发生变化"):
                g.create_backup([target])

    def test_manual_clash_recipe_never_prints_secret_argv(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            g.print_manual_checks()
        rendered = out.getvalue()
        self.assertNotIn("AUTH=", rendered)
        self.assertNotIn("$AUTH", rendered)
        self.assertIn("--audit --json", rendered)

    def test_restore_resume_after_second_target_write_failure(self):
        first, second = self.tmp / "first", self.tmp / "second"
        first.write_text("before-1", encoding="utf-8")
        second.write_text("before-2", encoding="utf-8")
        backup = g.create_backup([first, second])
        g._refresh_backup_manifest(backup, "before")
        first.write_text("after-1", encoding="utf-8")
        second.write_text("after-2", encoding="utf-8")
        g._refresh_backup_manifest(backup, "after")
        real_replace = g.os.replace
        failed = {"done": False}

        def fail_second(src, dst):
            if pathlib.Path(dst) == second and not failed["done"]:
                failed["done"] = True
                raise OSError("injected second target failure")
            return real_replace(src, dst)

        with mock.patch.object(g.os, "replace", side_effect=fail_second), \
             mock.patch.object(g.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value="CONFIRM"):
            with self.assertRaisesRegex(OSError, "second target"):
                g.restore_backup(backup)
        # The first item was journaled before the second failed; retry only
        # handles the remaining post-state item.
        with mock.patch.object(g.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value="CONFIRM"):
            self.assertEqual(g.restore_backup(backup), 0)
        self.assertEqual(first.read_text(), "before-1")
        self.assertEqual(second.read_text(), "before-2")

    def test_restore_new_file_rechecks_link_before_unlink(self):
        created = self.tmp / "created-late"
        backup = g.create_backup([created])
        g._refresh_backup_manifest(backup, "before")
        created.write_text("new", encoding="utf-8")
        g._refresh_backup_manifest(backup, "after")
        # Initial read-only preflight and lock-held preflight pass; the final
        # check immediately before unlink detects the simulated parent swap.
        with mock.patch.object(g, "_unsafe_home_link", side_effect=[False, False, True]), \
             mock.patch.object(g.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value="CONFIRM"):
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                g.restore_backup(backup)
        self.assertEqual(created.read_text(), "new")


class TestClashSocketTransport(unittest.TestCase):
    def test_selfcheck_kernel_uses_safe_python_transport(self):
        selfcheck_module.ROWS.clear()
        with mock.patch.object(selfcheck_module.g, "clash_http",
                               return_value=(200, '{"mode":"rule","tun":{"enable":true,"strict-route":true}}')) as http, \
             mock.patch.object(selfcheck_module, "sh",
                               side_effect=AssertionError("不得经 shell 传递 Clash secret")):
            selfcheck_module.check_kernel()
        self.assertEqual(selfcheck_module.ROWS[-1][0], "Clash 内核")
        self.assertEqual(selfcheck_module.ROWS[-1][1], selfcheck_module.OK)
        http.assert_called_once_with("GET", "/configs", timeout=20)

    def test_http_protocol_keeps_secret_out_of_command_runner(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        sock_path = tmp / "clash.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(sock_path))
        server.listen(2)
        received = []

        def serve():
            for _ in range(2):
                conn, _ = server.accept()
                data = conn.recv(8192)
                received.append(data)
                if data.startswith(b"GET"):
                    conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                  b"18\r\n{\"mode\":\"rule\",\"tun\":{}}\r\n0\r\n\r\n")
                else:
                    conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                conn.close()
            server.close()

        import threading
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        old_sock, old_secret = g.CLASH_SOCK, g.CLASH_SECRET
        g.CLASH_SOCK, g.CLASH_SECRET = sock_path, "test-secret"
        self.addCleanup(setattr, g, "CLASH_SOCK", old_sock)
        self.addCleanup(setattr, g, "CLASH_SECRET", old_secret)
        with mock.patch.object(g, "run", side_effect=AssertionError("不得调用带 secret 的命令")):
            get_code, get_body = g.clash_http("GET", "/configs")
            put_code, put_body = g.clash_http("PUT", "/configs", b'{"force":true}')
        thread.join(timeout=2)
        self.assertEqual(get_code, 200)
        self.assertIn('"mode":"rule"', get_body)
        self.assertEqual(put_code, 204)
        self.assertEqual(put_body, "")
        self.assertEqual(len(received), 2)
        self.assertTrue(all(b"Authorization: Bearer test-secret" in request for request in received))
        self.assertIn(b'{"force":true}', received[1])


class TestClashEndpointDiscovery(unittest.TestCase):
    """控制端点会搬家，检查不能写死路径（2026-10-13 实测踩到）。

    Clash Verge 2.5 起有「服务模式」：内核改由特权服务托管，控制 socket 从
    /tmp/verge/verge-mihomo.sock 搬到 /var/run/clash-verge-service/users/<uid>/。
    写死旧路径时体检会报「控制接口不可达」——读起来像网络坏了，实际只是端点换了地方。
    """

    @staticmethod
    def _fake(ok_sock):
        def fake_run(cmd, timeout=20):
            joined = " ".join(str(c) for c in cmd)
            try:
                sock = cmd[cmd.index("--unix-socket") + 1]
            except (ValueError, IndexError):
                sock = ""
            if "/version" in joined:
                return (0, '{"version":"v1.19.32"}') if (ok_sock and sock == ok_sock) else (1, "")
            if "/configs" in joined:
                return 0, json.dumps({"mode": "rule", "tun": {"enable": True}})
            if "/proxies" in joined:
                return 0, json.dumps({"proxies": {}})
            if "/rules" in joined:
                return 0, json.dumps({"rules": []})
            return 1, ""

        return fake_run

    def _sandbox_home(self, declared=None):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        d = tmp / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev"
        d.mkdir(parents=True)
        if declared is not None:
            (d / "config.yaml").write_text(
                "external-controller-unix: %s\n" % declared, encoding="utf-8")
        return tmp

    def test_declared_socket_comes_first(self):
        home = self._sandbox_home("/tmp/somewhere/mihomo.sock")
        with mock.patch.object(g, "HOME", home):
            paths = [str(p) for p in g.clash_sock_paths()]
        self.assertEqual(paths[0], "/tmp/somewhere/mihomo.sock")
        self.assertIn(
            "/var/run/clash-verge-service/users/%d/verge-mihomo.sock" % os.getuid(), paths)

    def test_defaults_are_listed_without_config(self):
        home = self._sandbox_home()
        with mock.patch.object(g, "HOME", home):
            paths = [str(p) for p in g.clash_sock_paths()]
        self.assertTrue(any("clash-verge-service" in p for p in paths), paths)
        self.assertIn("/tmp/verge/verge-mihomo.sock", paths)

    def test_probe_skips_the_stale_one(self):
        """声明值指向已经消失的旧 socket 时，要能落到真正在用的那个上。"""
        home = self._sandbox_home("/tmp/verge/verge-mihomo.sock")
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        stale = tmp / "stale.sock"
        stale.write_text("", encoding="utf-8")
        live = tmp / "live.sock"
        live.write_text("", encoding="utf-8")
        # 探活实现是纯 socket（不走 run），所以这里直接给探活函数打桩。
        with mock.patch.object(g, "HOME", home), \
             mock.patch.object(g, "CLASH_SOCK_CANDIDATES", (str(stale), str(live))), \
             mock.patch.object(g, "_CLASH_SOCK_CACHE", {}), \
             mock.patch.object(g, "_probe_clash_socket",
                               side_effect=lambda p: str(p) == str(live)):
            self.assertEqual(str(g.clash_socket()), str(live))

    def test_no_socket_anywhere_returns_none(self):
        home = self._sandbox_home("/tmp/verge/verge-mihomo.sock")
        with mock.patch.object(g, "HOME", home), \
             mock.patch.object(g, "CLASH_SOCK_CANDIDATES", ("/nonexistent/a.sock",)), \
             mock.patch.object(g, "_CLASH_SOCK_CACHE", {}), \
             mock.patch.object(g, "_probe_clash_socket", side_effect=lambda p: False):
            self.assertIsNone(g.clash_socket())

    def test_probe_failure_falls_back_to_existing(self):
        """探活本身失败（比如 curl 不可用）时退回第一个存在的端点，不把整项判死。"""
        home = self._sandbox_home()
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        only = tmp / "only.sock"
        only.write_text("", encoding="utf-8")
        with mock.patch.object(g, "HOME", home), \
             mock.patch.object(g, "CLASH_SOCK_CANDIDATES", (str(only),)), \
             mock.patch.object(g, "_CLASH_SOCK_CACHE", {}), \
             mock.patch.object(g, "_probe_clash_socket", side_effect=lambda p: False):
            self.assertEqual(str(g.clash_socket()), str(only))

    def test_check_reports_the_endpoints_it_tried(self):
        home = self._sandbox_home("/tmp/verge/verge-mihomo.sock")
        with mock.patch.object(g, "HOME", home), \
             mock.patch.object(g, "CLASH_SOCK_CANDIDATES", ("/nonexistent/a.sock",)), \
             mock.patch.object(g, "run", side_effect=self._fake(None)):
            r = g.check_clash_groups()
        self.assertFalse(r["reachable"])
        self.assertEqual(r["sock"], "")
        self.assertTrue(r["sock_tried"])

    def test_summary_names_the_endpoints_when_unreachable(self):
        rows = g.build_summary({"A12_clash_groups": {
            "reachable": False, "sock_tried": ["/a.sock", "/b.sock"]}})
        row = [r for r in rows if r[0] == "绝不直连"][0]
        self.assertIs(row[1], g.S_NA)
        self.assertIn("/a.sock", row[2])


class TestReportOnlyFlow(unittest.TestCase):
    """标准调用流程：前测 → 修 → 后测 → 一份 HTML。

    这里钉的是「HTML 一定给得出来」这条：
    - 只读模式加 --report 就出 HTML，且**不写 JSON、不动状态**（--save-audit 会写）；
    - 在 CONFIRM 处取消时也要出 HTML（改动前那份），否则用户拿不到任何东西。
    """

    def _sandbox(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        for name, val in (("HOME", tmp), ("BACKUP_ROOT", tmp / "backups")):
            patcher = mock.patch.object(g, name, val)
            patcher.start()
            self.addCleanup(patcher.stop)
        return tmp

    def test_audit_report_writes_html_and_nothing_else(self):
        tmp = self._sandbox()
        written = []
        with mock.patch.object(g, "audit", return_value={"A1_export_ip": {}}), \
             mock.patch.object(g, "print_audit"), \
             mock.patch.object(g, "print_summary_table"), \
             mock.patch("report_html.write_report",
                        side_effect=lambda *a, **k: written.append(k) or (tmp / "r.html")):
            self.assertEqual(g.main(["--audit", "--report"]), 0)
        self.assertEqual(len(written), 1, "只读模式加 --report 必须落一份 HTML")
        self.assertFalse(list((tmp / "backups").glob("audit-*.json")) if (tmp / "backups").exists() else [],
                         "--report 不该写 audit JSON，那是 --save-audit 的事")

    def test_audit_report_does_not_touch_the_caches(self):
        tmp = self._sandbox()
        with mock.patch.object(g, "audit", return_value={}), \
             mock.patch.object(g, "print_audit"), \
             mock.patch.object(g, "print_summary_table"), \
             mock.patch.object(g, "save_audit_report") as save, \
             mock.patch("report_html.write_report", return_value=tmp / "r.html"):
            g.main(["--audit", "--report"])
        save.assert_not_called()

    def test_cancel_at_confirm_still_hands_over_the_page(self):
        tmp = self._sandbox()
        report = {"A1_terminal_env": {"rc_files": {}, "npm": {}, "git": {},
                                      "env_hits": [], "env_info": []}}
        written = []
        with mock.patch.object(g, "audit", return_value=report), \
             mock.patch.object(g, "print_audit"), \
             mock.patch.object(g, "auto_clean_plan", return_value={
                 "summary": [], "proxy_residue": [], "rc_files": {}, "npm_git": [],
                 "settings_base_url": [], "settings_env_proxy": [], "ipv6": False,
                 "location_timezone": False, "clash_dns": False, "browser_locale": False,
                 "storage_bytes": 0, "dead_permissions": False, "stale_worktrees": [],
                 "project_junk": []}), \
             mock.patch.object(g.sys.stdin, "isatty", create=True, return_value=True), \
             mock.patch("builtins.input", side_effect=["0", "n", "n", "n", "n", "n", "n", "不确认"]), \
             mock.patch("report_html.write_report",
                        side_effect=lambda *a, **k: written.append(k) or (tmp / "r.html")):
            rc = g.main(["--report"])
        self.assertEqual(rc, 1, "在 CONFIRM 处取消仍然是退出码 1")
        self.assertEqual(len(written), 1, "取消时也该把改动前那份 HTML 给出来")


class TestHtmlReport(unittest.TestCase):
    """报告页：自包含、数字与终端同源、用户文字不会被当成 HTML 打出去。

    这三条都不是洁癖。①自包含：这个工具就是查网络痕迹的，报告再往外发请求会自相矛盾；
    ②同源：判定只走 build_summary，页面不另写一套；③转义：DNS 解析器、CLI 路径这些
    字段都是外部输入，直接拼进 HTML 就是把报告页变成注入点。
    """

    def _report(self, **over):
        rep = {
            "timestamp": "2026-10-13 21:00:00",
            "A1_export_ip": {"ip": "203.0.113.9", "country": "US", "city": "Nowhere",
                             "org": "AS7018 Example ISP, LLC", "timezone": "America/Chicago"},
            "A12_clash_groups": {
                "reachable": True, "mode": "rule",
                "tun": {"enable": True, "strict-route": True},
                "claude_group": {"type": "Selector", "now": "N1", "members": ["N1"]},
                "fallback": {"proxy": "Proxy"},
            },
        }
        rep.update(over)
        return rep

    def test_page_carries_no_article_citations(self):
        """页面是结论页：读的人要做什么，不需要知道出自哪篇文章。

        出处与逐条映射留在 references/article-mapping.md 和落盘的报告 JSON 里；
        这一条守着「页面里一个字都不提出处」，免得哪天又把「文章 2.2」渲染回来。
        """
        h = rh.render(self._report())
        self.assertNotIn("文章", h)
        self.assertNotIn("§", h)

    def test_strip_keeps_the_advice_and_drops_the_quote(self):
        self.assertEqual(
            rh.strip_article_refs("文章原话：「两端要对齐」。两道都要关，只关自动设置不够"),
            "两道都要关，只关自动设置不够")
        self.assertEqual(
            rh.strip_article_refs("文章 2.6 把它列进「一号一环境」的必做项。这一步没有本地接口"),
            "这一步没有本地接口")

    def test_strip_keeps_the_half_of_a_parenthetical_that_matters(self):
        self.assertEqual(
            rh.strip_article_refs("时区在东亚、出口在美国（文章两条建议互斥，已确认按此组合走，无需改动）"),
            "时区在东亚、出口在美国（已确认按此组合走，无需改动）")
        self.assertEqual(rh.strip_article_refs("五、使用行为（文章称为「第三层」）"), "五、使用行为")

    def test_strip_repairs_a_dangling_particle(self):
        # 引文夹在句子中间时，删掉会剩下「的说法没有公开依据」这种断头话
        self.assertEqual(
            rh.strip_article_refs("文章原话：「老 Gmail 更稳」的说法没有公开依据"),
            "这种说法没有公开依据")

    def test_strip_leaves_clean_text_alone(self):
        for text in ("没有出处的一句话", "", "出口 IP 与归属"):
            self.assertEqual(rh.strip_article_refs(text), text)

    def test_page_is_self_contained(self):
        h = rh.render(self._report())
        self.assertNotIn('src="http', h)
        self.assertNotIn('href="http', h)
        self.assertNotIn("<link ", h)
        self.assertNotIn("<script", h)          # 整页没有 JS，展开靠 details

    def test_external_text_is_escaped(self):
        h = rh.render(self._report(A6_dns={"clash": {"nameserver": ["<img src=x onerror=1>"]}}))
        self.assertNotIn("<img src=x", h)
        self.assertIn("&lt;img src=x", h)

    def test_unmeasured_counts_as_zero_points(self):
        # 两个通过 + 一个没测到：分母仍是 27 项，所以是 2/27，
        # 而不是把已测到的两项折算成 100——「没测到」就是没拿到分。
        sc = rh._score([("a", g.S_OK, ""), ("b", g.S_NA, ""), ("c", g.S_OK, "")])
        self.assertEqual(sc["score"], round(100 * 2 / rh.BASE_ITEMS))
        self.assertEqual(sc["counts"]["na"], 1)

    def test_attention_items_count_as_half(self):
        self.assertEqual(rh._score([("a", g.S_OK, ""), ("b", g.S_FIX, "")])["score"],
                         round(100 * 1.5 / rh.BASE_ITEMS))
        self.assertEqual(rh._score([("a", g.S_OK, ""), ("b", g.S_BAD, "")])["score"],
                         round(100 / rh.BASE_ITEMS))

    def test_a_duplicated_row_cannot_offset_a_failure(self):
        rows = [("a", g.S_OK, ""), ("b", g.S_OK, ""), ("c", g.S_BAD, ""), ("a", g.S_OK, "")]
        # a 重复一次不能把 c 的失败抵掉：27 项里只有 2 项通过就是 2/27。
        self.assertEqual(rh._score(rows)["score"], round(100 * 2 / rh.BASE_ITEMS))

    def test_all_unmeasured_scores_zero(self):
        sc = rh._score([("a", g.S_NA, "")])
        self.assertEqual(sc["score"], 0)
        self.assertEqual(sc["grade"], "F")

    def test_base_is_27_items_worth_100(self):
        """加分制：27 个基础项合计 100 分，登录方式不算在里面。"""
        self.assertEqual(rh.BASE_ITEMS, 27)
        self.assertEqual(rh.BASE_MAX, 100)
        self.assertAlmostEqual(rh._score([])["per_item"] * rh.BASE_ITEMS, 100)

    def test_every_summary_row_is_either_base_or_bonus(self):
        """表里每一行都要有归属：要么进 27 项计分，要么是那个加分项。

        以后再加检查项，这条会先红——逼着做的人明确新项算基础分还是加分。
        """
        names = [r[0] for r in g.build_summary({})]
        self.assertEqual(len(names), rh.BASE_ITEMS + 1)
        self.assertEqual(names.count(rh.BONUS_ROW), 1)

    def _full_base(self, over: str | None = None):
        """27 项基础分全过的底稿；给 over 时把第一项替换成那个状态。"""
        rows = [(f"r{i}", g.S_OK, "") for i in range(rh.BASE_ITEMS)]
        if over:
            rows[0] = ("r0", over, "")
        return rows

    def test_bonus_row_is_scored_on_top_of_the_base(self):
        rows = self._full_base() + [(rh.BONUS_ROW, g.S_OK, "")]
        sc = rh._score(rows)
        self.assertEqual(sc["score"], 100)                 # 27 项基础分全过
        self.assertEqual(sc["bonus"], rh.BONUS_POINTS)
        self.assertEqual(sc["total"], 100 + rh.BONUS_POINTS)
        self.assertEqual(sc["grade"], "A+")

    def test_bonus_row_stays_out_of_the_base_denominator(self):
        # 登录方式若被算进那 27 项，这里会变成 26/27 而不是 100
        rows = self._full_base() + [(rh.BONUS_ROW, g.S_OK, "")]
        self.assertEqual(rh._score(rows)["score"], 100)

    def test_bonus_row_earns_nothing_unless_it_passes(self):
        for status in (g.S_FIX, g.S_BAD, g.S_NA):
            sc = rh._score(self._full_base() + [(rh.BONUS_ROW, status, "")])
            self.assertEqual(sc["bonus"], 0, status)
            self.assertEqual(sc["total"], 100, status)

    def test_base_and_bonus_add_up_to_the_total(self):
        sc = rh._score(self._full_base(over=g.S_FIX) + [(rh.BONUS_ROW, g.S_OK, "")])
        self.assertEqual(sc["score"], 98)      # 26 满 + 1 半 = 26.5 / 27
        self.assertEqual(sc["bonus"], rh.BONUS_POINTS)
        self.assertEqual(sc["total"], 98 + rh.BONUS_POINTS)

    def test_page_shows_the_bonus_note_and_the_new_max(self):
        rows = [("出口 IP 与归属", g.S_OK, ""), (rh.BONUS_ROW, g.S_OK, "")]
        with mock.patch.object(g, "build_summary", return_value=rows):
            h = rh.render({"timestamp": "2026-01-01 00:00:00"})
        self.assertIn(f"/ {rh.MAX_SCORE}", h)
        self.assertIn("加分项", h)
        self.assertIn(f"+{rh.BONUS_POINTS}", h)

    def test_without_the_bonus_row_the_page_never_claims_extra_points(self):
        with mock.patch.object(g, "build_summary", return_value=[("a", g.S_OK, "")]):
            h = rh.render({"timestamp": "2026-01-01 00:00:00"})
        self.assertNotIn("已通过 +", h)

    def test_before_after_shows_delta_and_the_whole_comparison(self):
        before = [("绝不直连", g.S_BAD, "不成立"), ("出口 IP 与归属", g.S_OK, "好")]
        after = [("绝不直连", g.S_OK, "成立"), ("出口 IP 与归属", g.S_OK, "好")]
        with mock.patch.object(g, "build_summary", side_effect=[after, before]):
            h = rh.render({"timestamp": "x"}, before={"timestamp": "y"})
        self.assertIn("修复前", h)                       # 分数行
        self.assertIn("修复前 → 修复后", h)               # 逐项对照那节的标题
        section = h.split("修复前 → 修复后")[1]
        self.assertIn("绝不直连", section)
        self.assertIn("出口 IP 与归属", section)          # 没变的那行也要摆出来
        self.assertIn("class=\'cmp-mark bad\'>✗", section)   # 修复前是 ✗
        self.assertIn("class=\'cmp-mark ok\'>✓", section)  # 修复后是 ✓

    def test_items_and_evidence_come_from_the_report(self):
        h = rh.render(self._report())
        self.assertIn("203.0.113.9", h)          # 关键实测那张卡
        self.assertIn("203.0.113.9", h.split("看依据")[1])  # 依据里也要有原始读数
        self.assertIn("N1", h)                   # Claude 专用组

    def test_write_report_lands_in_the_given_dir(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        p = rh.write_report(self._report(), out_dir=tmp, report_path="/tmp/x.json")
        self.assertTrue(p.exists())
        body = p.read_text(encoding="utf-8")
        self.assertIn("/tmp/x.json", body)
        self.assertIn("<!DOCTYPE html>", body)


class TestFixButtonBacksUpFirst(unittest.TestCase):
    """点页面上的修复按钮时，备份必须是「改动之前」的那一份。

    2026-10-14 实测抓到过顺序反的那版：State.fix 先 apply 再 create_backup，
    于是备份目录里的 .zshrc 已经没有那行代理了——照着它回滚，等于把改完的状态
    再写一遍，等于没有备份。终端流程一直是「备份先拍」，两边现在一致。
    """

    def _sandbox(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / ".zshrc").write_text(
            "# 注释要保留\nexport EDITOR=vim\nexport HTTPS_PROXY=http://127.0.0.1:7897\n",
            encoding="utf-8")
        report = {
            "A1_terminal_env": {
                "rc_files": {".zshrc": [{"line": 3,
                                         "text": "export HTTPS_PROXY=http://127.0.0.1:7897"}]},
                "npm": {}, "git": {}, "env_hits": [], "env_info": [],
            },
            "A2_anthropic_base_url": {"hits": []},
            "A1_proxy_residue": {"residue": [], "enabled": [], "scutil": {}, "network_services": []},
        }
        patcher = mock.patch.object(g, "HOME", tmp)
        patcher.start()
        self.addCleanup(patcher.stop)
        bp = mock.patch.object(g, "BACKUP_ROOT", tmp / "backups")
        bp.start()
        self.addCleanup(bp.stop)
        return tmp, report

    def test_backup_holds_the_pre_fix_content(self):
        tmp, report = self._sandbox()
        rs.State(report).fix("rc_proxy")
        copies = list((tmp / "backups").glob("guard-*/files/*.zshrc"))
        self.assertTrue(copies, "必须留下备份")
        self.assertIn("HTTPS_PROXY", copies[0].read_text(encoding="utf-8"),
                      "备份里必须是改动前的原文，否则回滚等于把改完的状态再写一遍")
        self.assertNotIn("HTTPS_PROXY", (tmp / ".zshrc").read_text(encoding="utf-8"),
                         "线上那份要真的清干净")
        self.assertIn("EDITOR=vim", (tmp / ".zshrc").read_text(encoding="utf-8"))

    def test_backup_failure_leaves_everything_alone(self):
        tmp, report = self._sandbox()
        boom = mock.patch.object(g, "create_backup", side_effect=RuntimeError("备份不了"))
        boom.start()
        self.addCleanup(boom.stop)
        with self.assertRaises(RuntimeError):
            rs.State(report).fix("rc_proxy")
        self.assertIn("HTTPS_PROXY", (tmp / ".zshrc").read_text(encoding="utf-8"),
                      "备份失败时一个字符都不该改")


class TestDeadPermsFixIsBackedUp(unittest.TestCase):
    """settings 失效权限这一笔也必须先备份。

    2026-10-14 实测抓到：报告里 dead[].file 存的是相对家目录的路径
    （account_guard.py 里 rel = str(f).replace(str(HOME) + "/", "")），而
    _paths_dead_perms 原来直接 pathlib.Path(f)，相对路径 is_file() 为假，
    于是这一笔在没有备份的情况下改了文件。修法：g.HOME / f（pathlib 对
    绝对路径返回 f 本身，两种形态都对）。
    """

    def _sandbox(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        settings = tmp / "ipe" / "demo" / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(json.dumps(
            {"permissions": {"allow": ["Bash(git status)", "Bash(kill 4321)"]}}),
            encoding="utf-8")
        report = {
            "A1_terminal_env": {"rc_files": {}, "npm": {}, "git": {},
                                "env_hits": [], "env_info": []},
            "A2_anthropic_base_url": {"hits": []},
            "A1_proxy_residue": {"residue": [], "enabled": [],
                                 "scutil": {}, "network_services": []},
            "A26_claude_settings": {"dead": [
                {"file": "ipe/demo/.claude/settings.json",
                 "rule": "Bash(kill 4321)", "why": "一次性的 PID"}]},
        }
        patcher = mock.patch.object(g, "HOME", tmp)
        patcher.start()
        self.addCleanup(patcher.stop)
        bp = mock.patch.object(g, "BACKUP_ROOT", tmp / "backups")
        bp.start()
        self.addCleanup(bp.stop)
        return tmp, settings, report

    def test_relative_report_path_is_resolved_and_backed_up(self):
        tmp, settings, report = self._sandbox()
        message = rs.State(report).fix("dead_permissions")
        copies = list((tmp / "backups").glob("guard-*/files/*settings.json"))
        self.assertTrue(copies, "报告存相对路径时也要解析到家目录下再备份")
        self.assertIn("Bash(kill 4321)", copies[0].read_text(encoding="utf-8"),
                      "备份里必须是删之前的原文")
        self.assertIn("备份", message)

    def test_live_file_keeps_the_good_rule(self):
        tmp, settings, report = self._sandbox()
        rs.State(report).fix("dead_permissions")
        live = settings.read_text(encoding="utf-8")
        self.assertNotIn("kill 4321", live, "一次性 PID 的授权要真的删掉")
        self.assertIn("Bash(git status)", live, "正常授权要留着")


class TestReportServe(unittest.TestCase):
    """报告页的按钮：只认白名单动作、只认带令牌的请求、静态页不出按钮。

    这个进程能删文件，所以它的门必须比别的检查严：令牌在路径里、自定义头在 POST 上、
    动作名对不上就 400。三条都要有用例，不然哪天「顺手放宽一点」就没人拦得住。
    """

    REPORT = {
        "timestamp": "2026-10-13 22:00:00",
        # 这里必须留一项「未启用但存着值」的残留：按钮只挂在待处理的行上，
        # 全绿的报告页是没有任何修复按钮的（2026-10-14 改成按行状态出按钮）。
        "A1_proxy_residue": {"residue": [{"service": "Wi-Fi", "kind": "web",
                                          "server": "127.0.0.1", "port": 7897}],
                             "enabled": {}},
        "A12_clash_groups": {"reachable": True, "mode": "rule",
                             "tun": {"enable": True, "strict-route": True},
                             "claude_group": {"type": "Selector", "now": "N1", "members": ["N1"]},
                             "fallback": {"proxy": "Proxy"}},
    }

    def _serve(self):
        from http.server import ThreadingHTTPServer
        srv = ThreadingHTTPServer(("127.0.0.1", 0), rs.Handler)
        tok = "a" * 48
        st = rs.State(json.loads(json.dumps(self.REPORT)))
        srv.state = st
        srv.token = tok
        rs.Handler.token = tok
        rs.Handler.state = st
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_address[1]}/{tok}", tok

    @staticmethod
    def _get(url, timeout=10):
        """返回 (状态码, 正文或已解析的 JSON)。/state 这种直接给 dict，省得每处都 parse。"""
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                raw = r.read().decode("utf-8")
                code = r.status
        except urllib.error.HTTPError as e:
            raw, code = e.read().decode("utf-8"), e.code
        try:
            return code, json.loads(raw)
        except ValueError:
            return code, raw

    @staticmethod
    def _post(url, body, token=None, timeout=30):
        # token 必须显式传：之前从 url 末段取，而对 /fix 来说末段是 "fix"，
        # 于是「带令牌」的用例全被判成 403（自己写测试踩的坑）。
        req = urllib.request.Request(
            url, data=json.dumps(body).encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json",
                     **({"X-Guard-Token": token} if token else {})})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    def test_live_page_has_buttons_and_static_page_does_not(self):
        base, _ = self._serve()
        status, html = self._get(base + "/")
        self.assertEqual(status, 200)
        self.assertIn("data-all='1'", html)
        self.assertIn("data-rescan='1'", html)
        self.assertIn("data-rows='系统代理残留'", html)
        self.assertIn("<script", html)            # 服务模式才有脚本
        static = rh.render(json.loads(json.dumps(self.REPORT)))
        self.assertNotIn("data-rows=", static)
        self.assertNotIn("<script", static)

    def test_wrong_token_gets_404(self):
        base, _ = self._serve()
        port = base.split("/")[2]
        code, _ = self._get(f"http://{port}/deadbeef/")
        self.assertEqual(code, 404)

    def test_post_without_custom_header_is_refused(self):
        base, _ = self._serve()
        code, body = self._post(base + "/fix", {"rows": ["系统代理残留"]})
        self.assertEqual(code, 403)
        self.assertFalse(body["ok"])

    def test_unknown_row_is_refused(self):
        base, token = self._serve()
        code, body = self._post(base + "/fix", {"rows": ["不存在的行"]}, token=token)
        self.assertEqual(code, 400)
        self.assertFalse(body["ok"])

    def test_fix_runs_only_the_whitelisted_action(self):
        base, token = self._serve()
        called = []

        def fake_apply(rep, plan):
            called.append("proxy_residue")
            return "清掉 1 项"

        with mock.patch.dict(rs.ACTIONS["proxy_residue"], {"apply": fake_apply}), \
             mock.patch.object(rs.g, "auto_clean_plan", return_value={}), \
             mock.patch.object(rs.g, "create_backup", return_value=pathlib.Path("/tmp/fake-backup")):
            code, body = self._post(base + "/fix", {"rows": ["系统代理残留"]}, token=token)
        self.assertEqual(code, 200, body)
        self.assertEqual(called, ["proxy_residue"])
        self.assertTrue(body["ok"])
        self.assertIn("清掉 1 项", body["messages"][0])

    def test_state_endpoint_returns_rows(self):
        base, _ = self._serve()
        code, body = self._get(base + "/state")
        self.assertEqual(code, 200)
        self.assertTrue(body["rows"])
        self.assertEqual(len(body["rows"][0]), 3)

    def test_ledger_records_what_was_deleted(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        with mock.patch.object(g, "BACKUP_ROOT", tmp):
            p = g.write_cleanup_manifest("测试", [
                {"path": "/tmp/a", "bytes": 100, "ok": True},
                {"path": "/tmp/b", "bytes": 50, "ok": False},
            ], extra={"source": "test"})
            body = json.loads(p.read_text(encoding="utf-8"))
        self.assertTrue(str(p).startswith(str(tmp)))
        self.assertEqual(body["totalBytes"], 100)     # 没删成的那些不计入
        self.assertEqual(body["items"][1]["ok"], False)
        self.assertEqual(body["source"], "test")


class TestDeclaredExpected(unittest.TestCase):
    """预期出口是你自己的声明：命令行优先，其次环境变量，都没有才算没声明。"""

    def setUp(self):
        _no_real_project_scan(self)
        for name in (g.EXPECTED_COUNTRY_ENV, g.EXPECTED_EXIT_IP_ENV):
            self.addCleanup(os.environ.pop, name, None)
            os.environ.pop(name, None)

    def _fake_ip(self):
        return {"ip": "198.51.100.10", "country": "US", "city": "Springfield",
                "org": "Example ISP", "sources": {}, "verdict": "疑似住宅/ISP"}

    def test_command_line_wins_over_the_environment(self):
        os.environ[g.EXPECTED_COUNTRY_ENV] = "JP"
        self.assertEqual(g.declared_expected("US", None), ("US", None))

    def test_environment_supplies_it_when_the_flag_is_absent(self):
        os.environ[g.EXPECTED_COUNTRY_ENV] = "US"
        os.environ[g.EXPECTED_EXIT_IP_ENV] = "203.0.113.9"
        self.assertEqual(g.declared_expected(None, None), ("US", "203.0.113.9"))

    def test_blank_environment_value_is_not_a_declaration(self):
        os.environ[g.EXPECTED_COUNTRY_ENV] = "   "
        self.assertEqual(g.declared_expected(None, None), (None, None))

    def test_nothing_anywhere_stays_undeclared(self):
        self.assertEqual(g.declared_expected(None, None), (None, None))

    def test_blank_cli_value_falls_back_to_the_environment(self):
        os.environ[g.EXPECTED_COUNTRY_ENV] = "US"
        self.assertEqual(g.declared_expected("   ", None), ("US", None))

    def test_bad_environment_value_names_the_variable(self):
        os.environ[g.EXPECTED_COUNTRY_ENV] = "USA"
        with self.assertRaises(ValueError) as caught:
            g.declared_expected(None, None)
        self.assertIn(g.EXPECTED_COUNTRY_ENV, str(caught.exception))

    def test_audit_reads_the_environment_declaration(self):
        """守着「声明换个入口就没了」那个坑：命令行拿不到参数时也得认。"""
        os.environ[g.EXPECTED_COUNTRY_ENV] = "US"
        with mock.patch.object(g, "check_export_ip", return_value=self._fake_ip()):
            report = g.audit()
        got = report["A1_export_ip"].get("expected") or {}
        # 注意层级：这里是 expected_exit_result 的整个返回值，
        # 声明的国家在它自己的 expected 下面（2026-10-14 在这里读错过一次）。
        self.assertEqual((got.get("expected") or {}).get("country"), "US")
        self.assertEqual(got.get("status"), "ok")

    def test_audit_explicit_argument_beats_the_environment(self):
        os.environ[g.EXPECTED_COUNTRY_ENV] = "US"
        with mock.patch.object(g, "check_export_ip", return_value=self._fake_ip()):
            report = g.audit(expected_country="JP")
        self.assertEqual((report["A1_export_ip"].get("expected") or {}).get("status"), "bad")

    def test_help_renders(self):
        """--help 曾经因为 help= 后面写了花括号（那是 set，不是字符串拼接）而崩掉。"""
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as caught:
                g.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        text = buf.getvalue()
        self.assertIn(g.EXPECTED_COUNTRY_ENV, text)
        self.assertIn(g.EXPECTED_EXIT_IP_ENV, text)

    def test_runner_sits_at_the_very_end_exactly_once(self):
        """这个文件踩过两次同一个坑：runner 停在中间，后面的用例静默不跑。"""
        text = pathlib.Path(__file__).read_text(encoding="utf-8")
        # 只数整行，别数子串：下面那行断言本身也含这个字面量。
        runners = [n for n, line in enumerate(text.splitlines(), 1)
                   if line.startswith('if __name__ == "__main__":')]
        self.assertEqual(len(runners), 1, f"runner 出现在这些行：{runners}")
        tail = text.rstrip().splitlines()[-1]
        self.assertEqual(tail.strip(), "unittest.main(verbosity=2)")


class TestStorageThreshold(unittest.TestCase):
    """可清理量那一行不该为 0.4 MB 一直挂着「待处理」。"""

    def _row(self, state):
        rows = g.build_summary({"A25_claude_storage": state})
        return [r for r in rows if r[0] == "系统级可清理量"][0]

    def test_human_bytes_speaks_kb_below_one_megabyte(self):
        self.assertEqual(g.human_bytes(0), "0 KB")
        self.assertEqual(g.human_bytes(450355), "440 KB")
        self.assertEqual(g.human_bytes(1 << 20), "1.0 MB")
        self.assertEqual(g.human_bytes(int(43.8 * (1 << 20))), "43.8 MB")
        self.assertEqual(g.human_bytes(2 << 30), "2.00 GB")
        self.assertEqual(g.human_bytes(-5), "0 KB")
        self.assertEqual(g.human_bytes(None), "未知")

    def test_small_cache_is_not_worth_cleaning(self):
        self.assertFalse(g.storage_worth_cleaning(
            {"cleanable_bytes": 450355, "caches": [{"name": "Cache", "bytes": 450355}],
             "cli": {"stale": []}, "bundled": {"stale": []}}))

    def test_big_cache_is_worth_cleaning(self):
        self.assertTrue(g.storage_worth_cleaning(
            {"cleanable_bytes": 45 * (1 << 20), "caches": [{"name": "Cache", "bytes": 1}],
             "cli": {"stale": []}, "bundled": {"stale": []}}))

    def test_a_stale_version_is_always_worth_cleaning(self):
        self.assertTrue(g.storage_worth_cleaning(
            {"cleanable_bytes": 10, "caches": [], "cli": {"stale": ["2.1.293"]},
             "bundled": {"stale": []}}))

    def test_accepts_a_whole_report_too(self):
        self.assertTrue(g.storage_worth_cleaning(
            {"A25_claude_storage": {"cleanable_bytes": 99 * (1 << 20), "caches": [],
                                    "cli": {"stale": []}, "bundled": {"stale": []}}}))

    def test_row_is_green_when_only_a_small_cache_remains(self):
        status, detail = self._row({"cleanable_bytes": 450355,
                                    "caches": [{"name": "Cache"}, {"name": "Code Cache"}],
                                    "cli": {"current": "2.1.296", "stale": []},
                                    "bundled": {"current": "2.1.293", "stale": []}})[1:]
        self.assertIs(status, g.S_OK)
        self.assertIn("440 KB", detail)
        self.assertNotIn("0 MB", detail)

    def test_row_is_pending_for_a_real_amount(self):
        status, detail = self._row({"cleanable_bytes": 45 * (1 << 20),
                                    "caches": [{"name": "Cache"}],
                                    "cli": {"current": "2.1.296", "stale": []},
                                    "bundled": {"current": "2.1.293", "stale": []}})[1:]
        self.assertIs(status, g.S_FIX)
        self.assertIn("45.0 MB", detail)


class TestFixButtonsFollowRowStatus(unittest.TestCase):
    """报绿的行上不该还挂着「清理」按钮。"""

    def _actions_for(self, row):
        state = {"cleanable_bytes": 450355, "caches": [{"name": "Cache"}],
                 "cli": {"current": "2.1.296", "stale": []},
                 "bundled": {"current": "2.1.293", "stale": []}}
        if row == "big":
            state["cleanable_bytes"] = 45 * (1 << 20)
        return rs.ui_actions({"A25_claude_storage": state})

    def test_button_disappears_once_the_row_is_green(self):
        self.assertNotIn("系统级可清理量", self._actions_for("small"))

    def test_button_stays_while_the_row_is_pending(self):
        actions = self._actions_for("big")
        self.assertIn("系统级可清理量", actions)
        self.assertEqual(actions["系统级可清理量"][0]["id"], "claude_storage")

    def test_no_report_keeps_the_old_behaviour(self):
        """不给报告时保持原样：静态报告走的是另一条路。"""
        self.assertIn("系统级可清理量", rs.ui_actions())


class TestManualActionsAreWellFormed(unittest.TestCase):
    """人工清单的「步骤」必须真是一串步骤。

    写成 `("先把本机残留清干净")` 就是少了逗号——在 Python 里那是**字符串**不是元组，
    于是 `for step in steps` 按字符迭代：终端一行一个字，报告页一个 <li> 一个字。
    2026-10-15 真出现过，是用户看报告时问「这个怎么这样排版」才发现。
    """

    def _entries(self):
        for group, items in g.MANUAL_ACTIONS:
            for entry in items:
                yield group, entry

    def test_steps_are_a_sequence_not_a_string(self):
        for group, (title, _src, steps, _why) in self._entries():
            self.assertIsInstance(steps, (tuple, list), f"{group}／{title} 的步骤不是序列")
            self.assertTrue(steps, f"{group}／{title} 没有步骤")

    def test_no_step_is_a_single_character(self):
        for group, (title, _src, steps, _why) in self._entries():
            for step in steps:
                self.assertIsInstance(step, str, f"{group}／{title}")
                self.assertGreaterEqual(len(step.strip()), 4,
                                        f"{group}／{title} 的步骤太短（像是被按字符拆过）：{step!r}")

    def test_titles_sources_and_notes_are_filled(self):
        for group, (title, src, _steps, why) in self._entries():
            for field, value in (("标题", title), ("出处", src), ("说明", why)):
                self.assertIsInstance(value, str, f"{group} 的{field}")
                self.assertTrue(value.strip(), f"{group} 的{field}是空的")

    def test_report_page_shows_steps_one_per_line(self):
        """报告页里那份清单的 <li> 数要等于步骤总数，且没有单字条目。"""
        page = rh.render({})
        section = page.split("必须人工做的")[1].split("自己再核一遍")[0]
        items = re.findall(r"<li>(.*?)</li>", section, re.S)
        total = sum(len(steps) for _g, (_t, _s, steps, _w) in self._entries())
        self.assertEqual(len(items), total)
        for item in items:
            self.assertGreaterEqual(len(re.sub(r"<[^>]+>", "", item).strip()), 4, item)


class TestDetectionSiteLinks(unittest.TestCase):
    """报告页末尾那组自查入口。用户要自己点开核对的东西，脚本不代跑。"""

    URLS = (
        "https://ippure.com/", "https://ippure.com/claude.html", "https://ipinfo.io/",
        "https://browserleaks.com/webrtc", "https://browserleaks.com/dns",
        "https://ping0.cc/", "https://ip.net.coffee/", "https://ip.net.coffee/claude/",
        "https://cleanip.io/",
    )

    def _page(self):
        return rh.render({})

    def test_every_link_is_on_the_page(self):
        page = self._page()
        for url in self.URLS:
            self.assertIn(url, page, url)

    def test_links_open_in_a_new_tab_without_a_referrer(self):
        page = self._page()
        for url in self.URLS:
            i = page.index(url)
            chunk = page[i - 80:i + len(url) + 80]
            self.assertIn('target=\'_blank\'', chunk)
            self.assertIn("noopener", chunk)

    def test_each_link_says_what_it_answers(self):
        for _group, sites in rh.DETECTION_SITES:
            for url, note in sites:
                self.assertTrue(note.strip(), url)
                self.assertLess(len(note), 60, url)

    def test_page_still_loads_nothing_from_those_sites(self):
        """页面上只放链接：没有外链图片、脚本或样式表，离线打开也不会去连它们。"""
        page = self._page()
        for bad in ("src=\'http", 'src="http', "<script src=", "<link rel=\"stylesheet\" href=\"http"):
            self.assertNotIn(bad, page)
        self.assertNotIn("<img", page.split("自己再核一遍")[1])

    def test_no_article_citation_leaks_into_the_new_section(self):
        section = self._page().split("自己再核一遍")[1]
        self.assertNotIn("文章", section)


class TestReportGroupsCoverEveryRow(unittest.TestCase):
    """HTML 页面按组分通过率，漏掉的行在按项列表里还在、但不进任何一组——
    看起来就会比实际干净。这条用 build_summary 的实际行名逐个核对。"""

    def test_groups_cover_every_summary_row(self):
        names = sorted(r[0] for r in g.build_summary({}))
        grouped = sorted(n for _group, members in rh.GROUPS for n in members)
        self.assertEqual(names, grouped)

    def test_no_row_is_listed_twice(self):
        grouped = [n for _group, members in rh.GROUPS for n in members]
        self.assertEqual(len(grouped), len(set(grouped)))


class TestProxyBackendDetection(unittest.TestCase):
    """代理后端识别：认出是谁、以及脚本对它能做到什么。

    这一层存在的理由：26 项里有 2 项原本直接读 mihomo 的 socket 与 clash-verge.yaml，
    用别家代理的人只会看到「未测到」，分不清是脚本不认识还是网络真有问题。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="guard-backend-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for name, value in (("HOME", pathlib.Path(self.tmp)),):
            patcher = mock.patch.object(g, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _patch(self, **kwargs):
        for name, value in kwargs.items():
            patcher = mock.patch.object(g, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _write(self, rel, text):
        path = pathlib.Path(self.tmp) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_mihomo_from_socket(self):
        self._write("Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/"
                    "clash-verge.yaml", "mode: rule\ndns:\n  enable: true\n")
        self._patch(clash_socket=lambda: pathlib.Path("/tmp/verge/verge-mihomo.sock"),
                    _path_exists=lambda p: True,
                    _probe_clash_socket=lambda p: True,
                    _running_process_names=lambda: ["verge-mihomo"])
        info = g.check_proxy_backend()
        self.assertEqual(info["backend"], "mihomo")
        self.assertTrue(info["controller_ok"])
        self.assertEqual(info["controller"]["kind"], g.CONTROLLER_UNIX)
        self.assertTrue(info["capabilities"]["verify_after_write"])

    def test_clashx_tcp_controller_is_parsed(self):
        """ClashX 走 TCP（8080），不是 unix socket —— 只认 socket 的写法会漏掉它。"""
        self._write(".config/clash/config.yaml",
                    "external-controller: 127.0.0.1:8080\nsecret: mysecret\n")
        self._patch(clash_socket=lambda: None,
                    _running_process_names=lambda: ["clashx"],
                    controller_reachable=lambda c: False)
        info = g.check_proxy_backend()
        self.assertEqual(info["backend"], "mihomo")
        self.assertEqual(info["controller"]["port"], 8080)
        self.assertEqual(info["controller"]["secret"], "mysecret")
        self.assertIn("process", [e["kind"] for e in info["evidence"]])

    def test_port_only_external_controller_gets_loopback_host(self):
        self._write(".config/mihomo/config.yaml", "external-controller: :9090\n")
        self._patch(clash_socket=lambda: None, _running_process_names=lambda: ["mihomo"],
                    controller_reachable=lambda c: False)
        info = g.check_proxy_backend()
        self.assertEqual(info["backend"], "mihomo")
        self.assertEqual(info["controller"]["host"], "127.0.0.1")
        self.assertEqual(info["controller"]["port"], 9090)

    def test_singbox_without_external_controller_has_no_controller(self):
        """官方文档：external_controller 为空时 Clash API 是关闭的。
        这里绝不能默认 9090 —— 那会把「没开」说成「连不上」，两回事。"""
        path = self._write("Library/Application Support/sing-box/config.json",
                           json.dumps({"experimental": {"clash_api": {"external_controller": ""}}}))
        self.assertIsNone(g._singbox_controller(path))

    def test_singbox_controller_reads_address_and_secret(self):
        path = self._write("Library/Application Support/sing-box/config.json", json.dumps({
            "experimental": {"clash_api": {"external_controller": "127.0.0.1:19090",
                                           "secret": "s3cret"}}}))
        ctrl = g._singbox_controller(path)
        self.assertEqual((ctrl["host"], ctrl["port"], ctrl["secret"]), ("127.0.0.1", 19090, "s3cret"))
        self.assertEqual(ctrl["auth"], "bearer")

    def test_surge_http_api_line(self):
        path = self._write("Library/Application Support/Surge/Profiles/Work.conf",
                           "[General]\nhttp-api = mykey@127.0.0.1:6171\n")
        ctrl = g._surge_controller(path)
        self.assertEqual(ctrl["secret"], "mykey")
        self.assertEqual(ctrl["port"], 6171)
        self.assertEqual(ctrl["auth"], "x-key")

    def test_surge_wildcard_host_becomes_loopback(self):
        path = self._write("Library/Application Support/Surge/Profiles/W.conf",
                           "http-api = k@0.0.0.0:6171\n")
        self.assertEqual(g._surge_controller(path)["host"], "127.0.0.1")

    def test_surge_without_http_api_has_no_controller(self):
        path = self._write("Library/Application Support/Surge/Profiles/W.conf", "[General]\n")
        self.assertIsNone(g._surge_controller(path))

    def test_unknown_process_lands_in_other(self):
        self._patch(clash_socket=lambda: None, _running_process_names=lambda: ["shadowsocksx-ng"])
        info = g.check_proxy_backend()
        self.assertEqual(info["backend"], "other")
        self.assertEqual(info["capabilities"]["read_dns"], False)

    def test_flclash_is_recognized_as_mihomo_process(self):
        """FlClash 内核是 mihomo，但控制接口是它自己的 JSON-RPC，不是 Clash API。
        认得出进程、但没有控制接口 —— 这正是事实。"""
        self._patch(clash_socket=lambda: None, _running_process_names=lambda: ["flclash"])
        info = g.check_proxy_backend()
        self.assertEqual(info["backend"], "mihomo")
        self.assertFalse(info["controller_ok"])

    def test_system_proxy_only(self):
        self._patch(clash_socket=lambda: None, _running_process_names=lambda: [],
                    system_proxy_enabled=lambda: ["HTTP"])
        info = g.check_proxy_backend()
        self.assertEqual(info["backend"], "system")
        self.assertIn("system-proxy", [e["kind"] for e in info["evidence"]])

    def test_vpn_when_only_a_tunnel(self):
        self._patch(clash_socket=lambda: None, _running_process_names=lambda: [],
                    system_proxy_enabled=lambda: [], vpn_tunnels=lambda: ["WireGuard"])
        self.assertEqual(g.check_proxy_backend()["backend"], "vpn")

    def test_nothing_running(self):
        self._patch(clash_socket=lambda: None, _running_process_names=lambda: [],
                    system_proxy_enabled=lambda: [], vpn_tunnels=lambda: [])
        self.assertEqual(g.check_proxy_backend()["backend"], "none")


class TestSingboxFacts(unittest.TestCase):
    """sing-box 的 DNS 与 route 读成事实。元素形态有三种，都要认。"""

    def test_new_object_and_legacy_string_servers(self):
        cfg = {"dns": {"servers": ["223.5.5.5", {"type": "udp", "server": "8.8.8.8"}]}}
        facts = g.read_singbox_facts(cfg)
        self.assertEqual(facts["dns_servers"], ["223.5.5.5", "8.8.8.8"])
        self.assertEqual(facts["dns_cn"], ["223.5.5.5"])

    def test_detour_makes_a_cn_resolver_routed(self):
        cfg = {"dns": {"servers": [{"type": "udp", "server": "223.5.5.5", "detour": "proxy"}]}}
        facts = g.read_singbox_facts(cfg)
        self.assertEqual(facts["dns_no_detour"], [])
        self.assertEqual(facts["dns_cn"], ["223.5.5.5"])

    def test_claude_rule_carries_policy_key(self):
        cfg = {"route": {"rules": [{"domain_suffix": ["claude.ai"], "outbound": "proxy"}]}}
        facts = g.read_singbox_facts(cfg)
        self.assertEqual(facts["claude_rules"][0]["policy"], "proxy")

    def test_urltest_outbound_is_auto_switching(self):
        cfg = {"outbounds": [{"type": "urltest", "tag": "auto", "outbounds": ["a", "b"]}]}
        self.assertIn("auto", g.read_singbox_facts(cfg)["auto_switch"])

    def test_tun_inbound_detected(self):
        cfg = {"inbounds": [{"type": "tun", "tag": "tun-in"}]}
        self.assertTrue(g.read_singbox_facts(cfg)["tun"])


class TestSurgeFacts(unittest.TestCase):
    def _conf(self):
        return "\n".join([
            "[General]",
            "dns-server = 223.5.5.5, 8.8.8.8",
            "http-api = k@127.0.0.1:6171",
            "[Proxy Group]",
            "Proxy = select, NodeA",
            "Auto = url-test, NodeA, NodeB",
            "[Rule]",
            "DOMAIN-SUFFIX,claude.ai,Proxy",
            "IP-CIDR,160.79.104.0/21,Proxy,no-resolve",
            "FINAL,Auto",
        ])

    def test_dns_and_groups(self):
        facts = g.read_surge_facts(self._conf())
        self.assertEqual(facts["dns_servers"], ["223.5.5.5", "8.8.8.8"])
        self.assertEqual(facts["dns_cn"], ["223.5.5.5"])
        self.assertEqual(facts["auto_switch"], ["Auto"])
        self.assertEqual(facts["final"], "Auto")

    def test_no_resolve_modifier_is_not_taken_as_policy(self):
        """IP-CIDR 那行的策略后面还跟着 no-resolve，直接取最后一个字段会取错。"""
        rules = g.read_surge_facts(self._conf())["claude_rules"]
        self.assertTrue(any(r["policy"] == "Proxy" for r in rules))

    def test_comments_are_ignored(self):
        facts = g.read_surge_facts("# dns-server = 1.2.3.4\n[General]\ndns-server = 8.8.8.8\n")
        self.assertEqual(facts["dns_servers"], ["8.8.8.8"])


class TestV2rayFacts(unittest.TestCase):
    def test_dns_servers_strings_and_objects(self):
        cfg = {"dns": {"servers": ["223.5.5.5", {"address": "8.8.8.8", "domains": ["geosite:cn"]}]}}
        facts = g.read_v2ray_facts(cfg)
        self.assertEqual(facts["dns_servers"], ["223.5.5.5", "8.8.8.8"])
        self.assertEqual(facts["dns_cn"], ["223.5.5.5"])

    def test_routing_rule_outbound_and_freedom(self):
        cfg = {"outbounds": [{"protocol": "freedom", "tag": "direct"},
                             {"protocol": "vless", "tag": "proxy"}],
               "routing": {"rules": [{"domain": ["claude.ai"], "outboundTag": "proxy"}]}}
        facts = g.read_v2ray_facts(cfg)
        self.assertEqual(facts["claude_rules"][0]["policy"], "proxy")
        self.assertEqual(facts["direct_tags"], ["direct"])
        self.assertEqual(facts["final"], "direct")  # 没有规则命中时走第一个出站

    def test_balancer_is_auto_switching(self):
        cfg = {"routing": {"balancers": [{"tag": "bal"}]}}
        self.assertEqual(g.read_v2ray_facts(cfg)["auto_switch"], ["bal"])


class TestProxyFactsJudgement(unittest.TestCase):
    def _info(self, backend="singbox", controller_ok=False):
        return {"backend": backend, "config": {"path": "/x/config"}, "controller_ok": controller_ok,
                "capabilities": g._capabilities(backend, controller_ok, True)}

    def test_singbox_cn_resolver_without_detour_is_a_reason(self):
        judged = g.judge_proxy_facts(self._info(), g.read_singbox_facts(
            {"dns": {"servers": [{"type": "udp", "server": "223.5.5.5"}]}}))
        self.assertTrue(judged["dns"]["evaluated"])
        self.assertIn("223.5.5.5", judged["dns"]["unrouted_cn"])
        self.assertIn("直发", "".join(judged["dns"]["reasons"]))

    def test_surge_does_not_claim_a_leak_it_cannot_see(self):
        """Surge 的解析请求走哪条线路读不到运行时证据，所以只报事实 + 说清边界。"""
        judged = g.judge_proxy_facts(self._info("surge"), g.read_surge_facts(
            "[General]\ndns-server = 223.5.5.5\n"))
        self.assertIn("223.5.5.5", judged["dns"]["reasons"][0])
        self.assertTrue(any("browserleaks" in x for x in judged["dns"]["limits"]))

    def test_claude_to_direct_outbound_is_flagged(self):
        cfg = {"outbounds": [{"type": "direct", "tag": "direct"}],
               "route": {"rules": [{"domain_suffix": ["claude.ai"], "outbound": "direct"}],
                         "final": "direct"}}
        judged = g.judge_proxy_facts(self._info(), g.read_singbox_facts(cfg))
        self.assertTrue(judged["routing"]["direct"])
        self.assertTrue(any("直连" in x for x in judged["routing"]["reasons"]))

    def test_claude_to_urltest_is_auto_switching(self):
        cfg = {"outbounds": [{"type": "urltest", "tag": "auto", "outbounds": ["a"]}],
               "route": {"rules": [{"domain_suffix": ["anthropic.com"], "outbound": "auto"}]}}
        judged = g.judge_proxy_facts(self._info(), g.read_singbox_facts(cfg))
        self.assertTrue(judged["routing"]["auto_for_claude"])
        self.assertFalse(judged["routing"]["direct"])

    def test_claude_to_single_member_selector_is_pinned(self):
        cfg = {"outbounds": [{"type": "selector", "tag": "proxy", "outbounds": ["a"]}],
               "route": {"rules": [{"domain_suffix": ["claude.ai"], "outbound": "proxy"}]}}
        judged = g.judge_proxy_facts(self._info(), g.read_singbox_facts(cfg))
        self.assertEqual(judged["routing"]["kind"], "selector")
        self.assertIn("钉死", "".join(judged["routing"]["reasons"]))

    def test_missing_claude_rules_say_it_follows_the_fallback(self):
        cfg = {"outbounds": [{"type": "selector", "tag": "proxy", "outbounds": ["a", "b"]}],
               "route": {"final": "proxy"}}
        judged = g.judge_proxy_facts(self._info(), g.read_singbox_facts(cfg))
        self.assertTrue(any("兜底" in x for x in judged["routing"]["limits"]))

    def test_unknown_outbound_name_is_reported_not_guessed(self):
        cfg = {"outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "ghost"}}
        judged = g.judge_proxy_facts(self._info(), g.read_singbox_facts(cfg))
        self.assertEqual(judged["routing"]["kind"], "unknown")
        self.assertTrue(any("找不到" in x for x in judged["routing"]["limits"]))

    def test_unreadable_config_is_not_evaluated(self):
        judged = g.judge_proxy_facts(self._info(), {"found": False})
        self.assertFalse(judged["dns"]["evaluated"])
        self.assertFalse(judged["routing"]["evaluated"])


class TestTrafficCapture(unittest.TestCase):
    """「有没有真的被接管」对任何后端都成立 —— 认不出配置时这是唯一还能说的实话。"""

    def _patch(self, route_iface="utun1024", ifconfig="", netstat="", ports=()):
        patches = {
            "_route_interface": lambda ip="1.1.1.1": route_iface,
            "_utun_ipv4": (lambda: [{"name": "utun1024", "addr": "198.18.0.1"}]
                           if "utun1024" in ifconfig else []),
            "_tunnel_routes": lambda: ([{"dest": "1", "iface": "utun1024"}] if netstat else []),
            "_local_listen_ports": lambda: list(ports),
        }
        for name, value in patches.items():
            patcher = mock.patch.object(g, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_tunnel_capture_needs_ipv4_on_the_utun(self):
        self._patch(ifconfig="utun1024", netstat="yes")
        cap = g.check_traffic_capture()
        self.assertTrue(cap["captured"])
        self.assertIn("确实进了隧道", "".join(cap["notes"]))

    def test_system_utun_without_ipv4_is_not_counted(self):
        """系统自带的 utun 只有链路本地 v6，不能当成代理接管。"""
        self._patch(route_iface="utun0", ifconfig="")
        cap = g.check_traffic_capture()
        self.assertFalse(cap["captured"])
        self.assertIn("系统自带", "".join(cap["notes"]))

    def test_plain_interface_is_not_captured(self):
        self._patch(route_iface="en0")
        self.assertFalse(g.check_traffic_capture()["captured"])

    def test_socks_port_detection(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        self.addCleanup(server.close)

        def serve():
            try:
                conn, _ = server.accept()
                conn.recv(3)
                conn.sendall(b"\x05\x00")
                conn.close()
            except OSError:
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.assertTrue(g.socks5_alive(port))
        self.assertFalse(g.socks5_alive(port + 1) if port < 65000 else False)

    def test_http_port_is_not_mistaken_for_socks(self):
        """本机实测过反例：端口开着，但收到 SOCKS 握手回的是 HTTP 400。"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        self.addCleanup(server.close)

        def serve():
            try:
                conn, _ = server.accept()
                conn.recv(3)
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                conn.close()
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()
        self.assertFalse(g.socks5_alive(port))


class TestOtherProxyDnsFix(unittest.TestCase):
    """别家后端的 DNS 修复：只换解析器地址，别的键一个都不许动。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="guard-otherdns-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = mock.patch.object(g, "HOME", pathlib.Path(self.tmp))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _info(self, backend, path):
        return {"backend": backend, "config": {"path": str(path)},
                "capabilities": g._capabilities(backend, False, True)}

    def test_singbox_keeps_every_other_key(self):
        path = pathlib.Path(self.tmp) / "config.json"
        path.write_text(json.dumps({
            "log": {"level": "warn"},
            "dns": {"servers": [{"type": "udp", "tag": "ali", "server": "223.5.5.5"},
                                {"type": "udp", "tag": "goog", "server": "8.8.8.8", "detour": "proxy"}]},
            "inbounds": [{"type": "mixed", "tag": "in"}],
            "experimental": {"clash_api": {"external_controller": "127.0.0.1:19090"}},
        }, indent=2), encoding="utf-8")
        info = self._info("singbox", path)
        facts = g.proxy_facts_for(info)
        with mock.patch.object(g, "reload_backend", lambda i, p: "（测试里不重载）"):
            message = g.clear_other_proxy_dns(info, facts)
        after = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(after["dns"]["servers"][0]["server"], "1.1.1.1")
        self.assertEqual(after["dns"]["servers"][0]["tag"], "ali")  # tag 不能被改掉
        self.assertEqual(after["dns"]["servers"][1]["server"], "8.8.8.8")
        self.assertEqual(after["log"], {"level": "warn"})
        self.assertEqual(after["experimental"]["clash_api"]["external_controller"], "127.0.0.1:19090")
        self.assertIn("已把 1 个国内解析器", message)

    def test_v2ray_split_dns_entry_is_left_alone(self):
        """带 domains 的解析器是分流用的，语义特殊，不碰。"""
        path = pathlib.Path(self.tmp) / "config.json"
        path.write_text(json.dumps({
            "dns": {"servers": [{"address": "223.5.5.5", "domains": ["geosite:cn"]},
                                "119.29.29.29"]},
            "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        }, indent=2), encoding="utf-8")
        info = self._info("v2ray", path)
        with mock.patch.object(g, "reload_backend", lambda i, p: "（测试里不重载）"):
            g.clear_other_proxy_dns(info, g.proxy_facts_for(info))
        after = json.loads(path.read_text(encoding="utf-8"))["dns"]["servers"]
        self.assertEqual(after[0]["address"], "223.5.5.5")   # 带 domains，没动
        self.assertEqual(after[1], "1.1.1.1")                # 没带 domains，换了

    def test_surge_line_edit_keeps_other_lines(self):
        path = pathlib.Path(self.tmp) / "Work.conf"
        path.write_text("# 我的配置\n[General]\ndns-server = 223.5.5.5, 8.8.8.8\n"
                        "encrypted-dns-server = https://1.1.1.1/dns-query\n"
                        "[Rule]\nDOMAIN-SUFFIX,claude.ai,Proxy\n", encoding="utf-8")
        info = self._info("surge", path)
        with mock.patch.object(g, "reload_backend", lambda i, p: "（测试里不重载）"):
            g.clear_other_proxy_dns(info, g.proxy_facts_for(info))
        text = path.read_text(encoding="utf-8")
        self.assertIn("dns-server = 1.1.1.1, 8.8.8.8", text)
        self.assertIn("# 我的配置", text)
        self.assertIn("DOMAIN-SUFFIX,claude.ai,Proxy", text)

    def test_refuses_when_there_is_no_dns_block(self):
        path = pathlib.Path(self.tmp) / "config.json"
        path.write_text(json.dumps({"log": {"level": "warn"}}), encoding="utf-8")
        info = self._info("singbox", path)
        with self.assertRaises(RuntimeError):
            g.clear_other_proxy_dns(info, {"config": str(path)})

    def test_refuses_unknown_backend(self):
        path = pathlib.Path(self.tmp) / "x.conf"
        path.write_text("whatever", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            g.clear_other_proxy_dns({"backend": "other", "config": {"path": str(path)}},
                                    {"config": str(path)})

    def test_clean_config_is_a_noop(self):
        path = pathlib.Path(self.tmp) / "config.json"
        path.write_text(json.dumps({"dns": {"servers": [{"type": "udp", "server": "1.1.1.1"}]}}),
                        encoding="utf-8")
        before = path.read_text(encoding="utf-8")
        info = self._info("singbox", path)
        facts = g.proxy_facts_for(info)
        with mock.patch.object(g, "run", side_effect=AssertionError("不该调用 run")) as fake:
            message = g.clear_other_proxy_dns(info, facts)
        self.assertIn("无需改动", message)
        self.assertEqual(path.read_text(encoding="utf-8"), before)
        self.assertFalse(fake.called)


class TestReloadBackend(unittest.TestCase):
    """重载是这里最危险的一步：xray/v2ray 收到 SIGHUP 会被直接杀掉。"""

    def test_singbox_gets_sighup_when_it_runs_that_config(self):
        calls = []

        def fake_run(cmd, timeout=20, env=None):
            calls.append(cmd)
            if cmd[:2] == ["pgrep", "-f"]:
                return 0, "4242\n"
            return 0, ""

        with mock.patch.object(g, "run", fake_run), \
             mock.patch.object(g, "running_config_for", lambda b: "/tmp/c/config.json"):
            note = g.reload_backend({"backend": "singbox"}, "/tmp/c/config.json")
        self.assertIn("SIGHUP", note)
        self.assertIn(["kill", "-HUP", "4242"], calls)

    def test_singbox_is_not_touched_when_it_runs_another_config(self):
        calls = []
        with mock.patch.object(g, "run", lambda cmd, timeout=20, env=None: (calls.append(cmd), (0, ""))[1]), \
             mock.patch.object(g, "running_config_for", lambda b: "/somewhere/else/config.json"):
            note = g.reload_backend({"backend": "singbox"}, "/tmp/c/config.json")
        self.assertIn("不是刚改的这份", note)
        self.assertEqual([c for c in calls if c[:1] == ["kill"]], [])

    def test_v2ray_never_gets_sighup(self):
        calls = []
        with mock.patch.object(g, "run", lambda cmd, timeout=20, env=None: (calls.append(cmd), (0, ""))[1]), \
             mock.patch.object(g, "running_config_for", lambda b: ""):
            note = g.reload_backend({"backend": "v2ray"}, "/tmp/x/config.json")
        self.assertIn("杀掉进程", note)
        self.assertEqual(calls, [])

    def test_surge_uses_the_reload_endpoint(self):
        calls = []

        def fake_api(controller, method, path, body=None, timeout=8.0):
            calls.append((method, path))
            return 200, "{}"

        with mock.patch.object(g, "api_call", fake_api), \
             mock.patch.object(g, "running_config_for", lambda b: ""):
            note = g.reload_backend(
                {"backend": "surge", "controller": {"kind": "http", "host": "127.0.0.1",
                                                    "port": 6171, "secret": "k", "auth": "x-key"}},
                "/tmp/surge/Work.conf")
        self.assertEqual(calls, [("POST", "/v1/profiles/reload")])
        self.assertIn("重新载入", note)


class TestProxyBackendRows(unittest.TestCase):
    """三行文案：代理后端 / 绝不直连 / DNS 泄漏，在别家后端下各自该说什么。"""

    def _singbox_report(self, **over):
        facts = {"dns": {"evaluated": True, "servers": ["223.5.5.5"], "cn": ["223.5.5.5"],
                         "unrouted_cn": ["223.5.5.5"], "reasons": ["国内解析器没有配 detour"],
                         "limits": [], "fixable": True},
                 "routing": {"evaluated": True, "claude_outbound": "proxy", "kind": "selector",
                             "auto_switch": [], "direct": False, "auto_for_claude": False,
                             "matched": "claude.ai",
                             "reasons": ["Claude 走 proxy，只有 1 个成员，钉死在一个节点上"],
                             "limits": []},
                 "config": "/x/config.json", "runtime_verified": False,
                 "verify_hint": "正在跑的进程命令行里没写配置文件路径"}
        facts.update(over)
        return {"backend": "singbox", "label": "sing-box", "evidence": [{"kind": "process", "value": "sing-box"}],
                "controller_ok": False, "controller": None, "config": {"path": "/x/config.json"},
                "capabilities": g._capabilities("singbox", False, True), "facts": facts,
                "capture": {"captured": True, "notes": ["去 1.1.1.1 走 utun1024（198.18.0.1），流量确实进了隧道"]},
                "notes": ["没有开 clash_api —— 分流与 DNS 只能静态读配置文件"]}

    def test_backend_row_names_the_backend(self):
        status, detail = g.backend_row(self._singbox_report())
        self.assertIn("sing-box", detail)
        self.assertIn("进了隧道", detail)

    def test_backend_row_says_when_it_cannot_tell(self):
        status, detail = g.backend_row({"backend": "none", "label": "没有发现代理",
                                        "capture": {"captured": True,
                                                    "notes": ["去 1.1.1.1 走 utun1024（198.18.0.1），流量确实进了隧道"]}})
        self.assertEqual(status, g.S_NA)
        self.assertIn("没认出", detail)

    def test_backend_row_for_unknown_process(self):
        status, detail = g.backend_row({"backend": "other", "label": "认得出在跑",
                                        "evidence": [{"kind": "process", "value": "shadowsocksx-ng"}]})
        self.assertIn("shadowsocksx-ng", detail)
        self.assertIn("不认识", detail)

    def test_routing_row_flags_a_direct_fallback(self):
        pb = self._singbox_report()
        pb["facts"]["routing"].update(direct=True, reasons=["Claude 流量最后落到直连出口（direct）"])
        status, detail = g.backend_routing_row(pb)
        self.assertEqual(status, g.S_BAD)
        self.assertIn("直连", detail)

    def test_routing_row_is_grey_without_runtime_evidence(self):
        status, detail = g.backend_routing_row(self._singbox_report())
        self.assertEqual(status, g.S_NA)
        self.assertIn("配置层面", detail)

    def test_routing_row_green_when_runtime_is_verified(self):
        pb = self._singbox_report(runtime_verified=True)
        status, detail = g.backend_routing_row(pb)
        self.assertEqual(status, g.S_OK)
        self.assertIn("钉死", detail)

    def test_routing_row_returns_none_for_mihomo(self):
        self.assertIsNone(g.backend_routing_row({"backend": "mihomo"}))
        self.assertIsNone(g.backend_dns_row({"backend": "mihomo"}))

    def test_dns_row_offers_the_fix_for_other_backends(self):
        status, detail = g.backend_dns_row(self._singbox_report())
        self.assertEqual(status, g.S_FIX)
        self.assertIn("--fix-unverified", detail)

    def test_dns_row_for_surge_points_at_the_ui(self):
        pb = self._singbox_report()
        pb["backend"] = "surge"
        pb["label"] = "Surge"
        pb["facts"]["dns"]["fixable"] = False
        status, detail = g.backend_dns_row(pb)
        self.assertEqual(status, g.S_FIX)
        self.assertIn("界面", detail)

    def test_summary_gains_the_backend_row(self):
        report = {"A28_proxy_backend": self._singbox_report()}
        rows = dict((name, (status, detail)) for name, status, detail in g.build_summary(report))
        self.assertIn("代理后端", rows)
        status, detail = rows["绝不直连"]
        self.assertIn("配置层面", detail)

    def test_missing_backend_report_keeps_the_old_rows(self):
        """旧报告里没有 A28 时，两行必须回落到原来的 Clash 判据，不能被新代码带偏。"""
        rows = g.build_summary({"A12_clash_groups": {"reachable": False, "sock_tried": ["/tmp/x.sock"]}})
        detail = dict((n, d) for n, _s, d in rows)
        self.assertIn("未检测", detail["代理后端"])
        self.assertIn("Clash 控制接口不可达", detail["绝不直连"])
        self.assertIn("未检测", detail["DNS 泄漏"])


class TestApplyTelemetryIsIdempotent(unittest.TestCase):
    """2026-10-15 实测的误报：三个遥测键本来就是 1，脚本却报
    「遥测键写入后复验未生效」并停在 [3/6]，后面几步全没跑。

    根因是复验拿「改动前的状态」当基准：键本来就是目标值时，这次写入不产生
    任何变化，after == before 成立，于是把「已经是对的」判成「没写进去」。
    正确基准是「目标状态」。
    """

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.settings = self.tmp / "settings.json"
        patcher = mock.patch.object(g, "SETTINGS", self.settings)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _seed(self, env: dict) -> None:
        self.settings.write_text(json.dumps({"env": env}, ensure_ascii=False), encoding="utf-8")

    def test_already_at_target_is_not_an_error(self):
        self._seed({k: "1" for k in g.TELEMETRY_KEYS})
        before = self.settings.read_bytes()
        message = g.apply_telemetry(1)          # 修复前这里抛 RuntimeError
        self.assertIn("无需改动", message)
        self.assertEqual(self.settings.read_bytes(), before, "没有变化时不该改写文件")

    def test_partial_state_is_completed_and_other_keys_survive(self):
        self._seed({"DISABLE_TELEMETRY": "1", "KEEP_ME": "1"})
        message = g.apply_telemetry(1)
        self.assertIn("DISABLE_ERROR_REPORTING", message)
        env = json.loads(self.settings.read_text(encoding="utf-8"))["env"]
        self.assertEqual(env["KEEP_ME"], "1", "env 里别的键一个都不能动")
        for key in g.TELEMETRY_KEYS:
            self.assertEqual(env[key], "1")

    def test_write_that_does_not_take_is_still_an_error(self):
        self._seed({})
        with mock.patch.object(g, "write_json", lambda *a, **k: None):
            with self.assertRaises(RuntimeError) as caught:
                g.apply_telemetry(1)
        self.assertIn("复验未生效", str(caught.exception))

    def test_mode_zero_never_touches_the_file(self):
        self._seed({"KEEP_ME": "1"})
        before = self.settings.read_bytes()
        self.assertEqual(g.apply_telemetry(0), "保持")
        self.assertEqual(self.settings.read_bytes(), before)


class TestNoBackupWhenNothingToWrite(unittest.TestCase):
    """一个写操作都不会发生的运行不该留下备份目录。

    用户 2026-10-15 的原话：「正常跑完的话就不需要备份了」。
    开工前没人知道会不会顺利跑完，所以有写入时备份一步都不能省；
    但「全选保持」这种零写入的运行，备份里没有任何可回滚的东西。
    """

    def _run(self, telemetry: str):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        report = {
            "A1_proxy_residue": {"residue": [], "enabled": [], "scutil": {},
                                 "network_services": []},
            "A1_terminal_env": {"rc_files": {}, "npm": {}, "git": {},
                                "env_hits": [], "env_info": []},
            "A2_anthropic_base_url": {"hits": []},
            "A5_ipv6": {"services": {}, "global_addresses": []},
        }
        settings = tmp / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True, exist_ok=True)
        settings.write_text('{"env": {}}', encoding="utf-8")
        (tmp / ".claude.json").write_text('{"userID": "fake"}', encoding="utf-8")
        backups = tmp / "backups"
        with mock.patch.object(g, "HOME", tmp), \
             mock.patch.object(g, "SETTINGS", settings), \
             mock.patch.object(g, "BACKUP_ROOT", backups), \
             mock.patch.object(g, "audit", return_value=report), \
             mock.patch.object(g, "print_audit"), \
             mock.patch.object(g, "write_html_twin"), \
             mock.patch.object(g.sys, "stdin", mock.Mock(isatty=lambda: True)), \
             mock.patch("builtins.input", side_effect=prompt_answering(telemetry=telemetry)), \
             mock.patch.object(g.sys, "stdout", io.StringIO()), \
             mock.patch.object(g.sys, "stderr", io.StringIO()):
            rc = g.main([])
        created = sorted(d.name for d in backups.iterdir()) if backups.exists() else []
        return rc, created

    def test_zero_write_run_leaves_no_backup(self):
        rc, created = self._run("0")
        self.assertEqual(rc, 0)
        self.assertEqual(created, [], f"没有任何改动却建了备份：{created}")

    def test_a_real_write_still_gets_a_backup(self):
        rc, created = self._run("2")
        self.assertEqual(rc, 0)
        self.assertTrue([n for n in created if n.startswith("guard-")],
                        f"有写入时必须仍然建备份，实际：{created}")


class TestRememberedExpectedExit(unittest.TestCase):
    """声明的预期出口要记住。

    声明的内容（我期望从哪个国家出去）不会因为换了一天就失效；每次都要重新声明，
    就等于每次都可能忘了声明、那一项永远停在「未测到」。落盘只发生在允许写状态的
    调用里 —— 只读审计仍然一个字都不写。
    """

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        for name, value in (("HOME", self.tmp),
                            ("EXPECTED_COUNTRY_ENV", "CLAUDE_GUARD_EXPECTED_COUNTRY"),
                            ("EXPECTED_EXIT_IP_ENV", "CLAUDE_GUARD_EXPECTED_EXIT_IP")):
            patcher = mock.patch.object(g, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        env = mock.patch.dict(os.environ, {}, clear=True)
        env.start()
        self.addCleanup(env.stop)

    def test_state_path_follows_home(self):
        self.assertEqual(g.expected_state_path(),
                         self.tmp / ".local" / "state" / "claude-guard" / "expected-exit.json")

    def test_saved_declaration_is_used_when_nothing_is_declared_now(self):
        # 用文档保留段（RFC 5737）的地址，别把本机真实出口写进公开仓
        g.remember_declared_expected("US", "203.0.113.9")
        self.assertEqual(g.declared_expected(), ("US", "203.0.113.9"))

    def test_a_fresh_declaration_wins_over_the_saved_one(self):
        g.remember_declared_expected("US", None)
        self.assertEqual(g.declared_expected("JP", None)[0], "JP")

    def test_reading_never_writes(self):
        g.declared_expected()
        self.assertFalse(g.expected_state_path().exists())

    def test_broken_state_file_is_ignored(self):
        path = g.expected_state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{ not json", encoding="utf-8")
        self.assertEqual(g.declared_expected(), (None, None))

    def test_invalid_saved_values_do_not_fail_the_run(self):
        path = g.expected_state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"country": "!!", "exitIp": "not-an-ip"}), encoding="utf-8")
        self.assertEqual(g.declared_expected(), (None, None))


class TestReportShowsBeforeAndAfter(unittest.TestCase):
    """最后那份 HTML 要能逐项看出修复前后，不能只报一句「改好了几项」。"""

    AFTER = {"__which": "after"}
    BEFORE = {"__which": "before"}

    def _render(self, before_rows, after_rows):
        def fake_build(report):
            return after_rows if report is self.AFTER else before_rows
        with mock.patch.object(g, "build_summary", side_effect=fake_build):
            return rh.render(self.AFTER, before=self.BEFORE)

    def test_every_row_gets_both_marks_not_just_the_fixed_ones(self):
        before_rows = [("出口 IP 与归属", g.S_OK, "没变"),
                       ("系统代理残留", g.S_FIX, "有两处"),
                       ("时区两道闸", g.S_FIX, "读不到")]
        after_rows = [("出口 IP 与归属", g.S_OK, "没变"),
                      ("系统代理残留", g.S_OK, "清干净了"),
                      ("时区两道闸", g.S_FIX, "读不到")]
        page = self._render(before_rows, after_rows)
        self.assertIn("修复前 → 修复后", page)
        self.assertIn("这一轮改好 1 项", page)
        # 三行都要摆出来，包括没变的和没改动的那些
        self.assertEqual(page.count("<div class='cmp'>"), 3)

    def test_never_measured_is_not_a_regression(self):
        """从「没测到」变成「已解决」是这次量到了，绝不能报成比动手前差。"""
        before_rows = [("WebRTC 泄漏", g.S_NA, "没测"), ("出口 IP 与归属", g.S_NA, "没测")]
        after_rows = [("WebRTC 泄漏", g.S_OK, "量到了"), ("出口 IP 与归属", g.S_OK, "量到了")]
        page = self._render(before_rows, after_rows)
        self.assertNotIn("比动手前差", page)
        self.assertIn("2 项有一边是「没测到」，不计入对比", page)

    def test_a_row_that_got_worse_is_called_out(self):
        before_rows = [("WebRTC 泄漏", g.S_OK, "好")]
        after_rows = [("WebRTC 泄漏", g.S_BAD, "漏了")]
        page = self._render(before_rows, after_rows)
        self.assertIn("比动手前差", page)
        self.assertIn("WebRTC 泄漏", page)

    def test_without_a_before_report_there_is_no_comparison_section(self):
        with mock.patch.object(g, "build_summary", return_value=[("出口 IP 与归属", g.S_OK, "x")]):
            page = rh.render({})
        self.assertNotIn("修复前 → 修复后", page)


class TestFullFlowEndsWithExactlyOneReport(unittest.TestCase):
    """整轮加固只在最后落一份 HTML，而且那一份必须带「动手前」那份报告。"""

    def test_one_html_at_the_end_carrying_the_before_report(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        before = {"A1_terminal_env": {"rc_files": {}, "npm": {}, "git": {},
                                      "env_hits": [], "env_info": []}}
        after = {"A1_terminal_env": {"rc_files": {}, "npm": {}, "git": {},
                                     "env_hits": [], "env_info": []}, "复检": True}
        calls = []
        reports = [before, after]
        # 空计划下只会问四个：遥测、包装脚本、管理员两项、然后 CONFIRM。答案个数必须与
        # 问的个数对得上，多给一个就会把 CONFIRM 顶掉（实测踩过，rc 变成 1）。
        with mock.patch.object(g, "HOME", tmp), \
             mock.patch.object(g, "BACKUP_ROOT", tmp / "backups"), \
             mock.patch.object(g, "audit", side_effect=lambda **kw: reports.pop(0)), \
             mock.patch.object(g, "print_audit"), \
             mock.patch.object(g, "print_summary_table"), \
             mock.patch.object(g, "print_before_after"), \
             mock.patch.object(g, "auto_clean_plan", return_value={
                 "summary": [], "proxy_residue": [], "rc_files": {}, "npm_git": [],
                 "settings_base_url": [], "settings_env_proxy": [], "ipv6": False,
                 "location_timezone": False, "clash_dns": False, "browser_locale": False,
                 "storage_bytes": 0, "dead_permissions": False, "stale_worktrees": [],
                 "project_junk": []}), \
             mock.patch.object(g, "create_backup", return_value=(tmp / "backups" / "guard-x", [])), \
             mock.patch.object(g.sys.stdin, "isatty", create=True, return_value=True), \
             mock.patch("builtins.input", side_effect=["0", "n", "n", "CONFIRM"]), \
             mock.patch("report_html.write_report",
                        side_effect=lambda *a, **k: calls.append(k) or (tmp / "r.html")), \
             contextlib.redirect_stdout(io.StringIO()):
            rc = g.main([])
        self.assertEqual(rc, 0)
        self.assertEqual(len(calls), 1, f"整轮该只落一份 HTML，实际 {len(calls)} 份")
        self.assertIs(calls[0].get("before"), before, "最后那一份必须带着动手前那份报告")
        self.assertTrue(calls[0].get("open_it"), "最后那份要直接打开给用户看")


# auto_clean_plan 的完整键集合。缺键会让 main 在 plan["..."] 上 KeyError，
# 所以这里给一份空计划当桩——改 main 的取值面时，这个常量也要跟着补。
EMPTY_PLAN = {
    "summary": [], "proxy_residue": [], "rc_files": {}, "npm_git": [],
    "settings_base_url": [], "settings_env_proxy": [], "ipv6": False,
    "location_timezone": False, "clash_dns": False, "browser_locale": False,
    "storage_bytes": 0, "dead_permissions": False, "stale_worktrees": [],
    "project_junk": [],
}


class TestElevationIsAskedBeforeTheWork(unittest.TestCase):
    """提权提前到动手之前一次做完，而不是等写 root 文件时才弹密码。

    背景：sudo 只缓存 5 分钟。原来的做法是懒加载——[1/6] 要备份 root 文件、
    或 [6/6] 要关定位闸时才问，而那时前面已经跑了几分钟清理，出去接杯水
    回来授权就过期了，带 -n 的那一步只会静默失败。
    """

    def _answers(self, *, ipv6="y", loc="n"):
        def answer(prompt=""):
            p = prompt.strip()
            if "CONFIRM" in p:
                return "CONFIRM"
            if "遥测开关" in p:
                return "0"
            if "两项" in p:
                return "y"
            if "关闭所有网络服务的 IPv6" in p:
                return ipv6
            if "读取定位服务状态" in p:
                return loc
            return "n"
        return answer

    def _main(self, answer, *, prime_raises=False, calls=None):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        report = {
            "A1_terminal_env": {"rc_files": {}, "npm": {}, "git": {},
                                "env_hits": [], "env_info": []},
            "A2_anthropic_base_url": {"hits": []},
            "A5_ipv6": {"services": {"Wi-Fi": {"ipv6": "Automatic"}}, "global_addresses": []},
        }
        calls = calls if calls is not None else []

        def fake_prime():
            calls.append("prime")
            if prime_raises:
                raise RuntimeError("没拿到授权")

        def fake_read(**kw):
            calls.append(("read", kw.get("persist")))
            return {"readable": True, "clients": {"TimeZone.bundle": {}}, "note": ""}

        def fake_ipv6(services):
            calls.append("ipv6")
            return {"done": list(services), "failed": [], "rollback": []}

        out = io.StringIO()
        with mock.patch.object(g, "HOME", tmp), \
             mock.patch.object(g, "SETTINGS", tmp / ".claude" / "settings.json"), \
             mock.patch.object(g, "BACKUP_ROOT", tmp / "backups"), \
             mock.patch.object(g, "audit", return_value=report), \
             mock.patch.object(g, "auto_clean_plan", return_value={**EMPTY_PLAN, "ipv6": True}), \
             mock.patch.object(g, "print_audit"), \
             mock.patch.object(g, "print_summary_table"), \
             mock.patch.object(g, "print_before_after"), \
             mock.patch.object(g, "write_html_twin"), \
             mock.patch.object(g, "sudo_prime", side_effect=fake_prime), \
             mock.patch.object(g, "location_service_status", side_effect=fake_read), \
             mock.patch.object(g, "set_ipv6_off", side_effect=fake_ipv6), \
             mock.patch.object(g, "ensure_sudo"), \
             mock.patch.object(g.sys, "stdin", mock.Mock(isatty=lambda: True)), \
             mock.patch("builtins.input", side_effect=answer), \
             mock.patch.object(g.sys, "stdout", out), \
             mock.patch.object(g.sys, "stderr", io.StringIO()):
            rc = g.main([])
        return rc, calls, out.getvalue()

    def test_password_comes_before_the_first_root_step(self):
        rc, calls, out = self._main(self._answers())
        self.assertEqual(rc, 0)
        self.assertIn("prime", calls)
        self.assertIn("ipv6", calls)
        self.assertLess(calls.index("prime"), calls.index("ipv6"),
                        "授权必须在动手之前拿到")
        self.assertLess(out.index("[0/6]"), out.index("[1/6]"),
                        "授权那一步要排在六步之前")

    def test_declining_to_close_the_gate_still_reads_the_plist(self):
        """答「不关」也要读一次：不读这一项永远只有「读不到（要 root）」。"""
        rc, calls, _out = self._main(self._answers(loc="n"))
        self.assertEqual(rc, 0)
        self.assertIn(("read", True), calls)
        self.assertNotIn(("read", False), calls, "提权后这一次要落缓存，不能只读不记")

    def test_no_authorization_skips_the_root_steps_and_finishes(self):
        rc, calls, out = self._main(self._answers(), prime_raises=True)
        self.assertEqual(rc, 0, "没输密码是用户的选择，不该让整轮失败")
        self.assertIn("没有拿到管理员授权", out)
        self.assertNotIn("ipv6", calls)
        self.assertNotIn(("read", True), calls)

    def test_the_plan_says_authorization_will_be_asked(self):
        _rc, _calls, out = self._main(self._answers())
        self.assertIn("9. 管理员授权", out)


class TestSuiteNeverWritesIntoTheRealReportDir(unittest.TestCase):
    """真实备份目录不该被测试碰到，哪怕某个用例忘了 patch。"""

    def test_report_output_dir_points_somewhere_temporary(self):
        self.assertIn("guard-report-", str(rh.BACKUP_DIR),
                      "setUpModule 该把 report_html.BACKUP_DIR 指到临时目录")
        self.assertNotEqual(pathlib.Path(rh.BACKUP_DIR),
                            pathlib.Path.home() / "ClaudeGuardBackups")

    def test_writing_without_out_dir_does_not_touch_the_home_backup_dir(self):
        before = set((pathlib.Path.home() / "ClaudeGuardBackups").glob("report-*.html"))
        rh.write_report({"timestamp": "x"}, report_path="")
        after = set((pathlib.Path.home() / "ClaudeGuardBackups").glob("report-*.html"))
        self.assertEqual(before, after, "没给 out_dir 的写入绝不能落到真实备份目录")


class TestSelfcheckLeavesTheReportToTheEnd(unittest.TestCase):
    """自检不该每跑一次就弹一个页面：一流程只留加固收尾那一份前后对照。"""

    def test_the_self_check_opens_no_html(self):
        with mock.patch.object(sys, "argv", ["selfcheck.py", "--fast"]), \
             mock.patch.object(selfcheck_module, "project_roots_default",
                               return_value=([], "测试")), \
             mock.patch.object(selfcheck_module, "check_files"), \
             mock.patch.object(selfcheck_module, "check_compile"), \
             mock.patch.object(selfcheck_module, "check_guards"), \
             mock.patch.object(selfcheck_module, "check_kernel"), \
             mock.patch.object(selfcheck_module, "check_system_proxy"), \
             mock.patch.object(selfcheck_module, "check_audit",
                               return_value=("", {"A1_export_ip": {}})), \
             mock.patch("report_html.write_report") as writer, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            selfcheck_module.ROWS.clear()
            selfcheck_module.main()
        writer.assert_not_called()
        self.assertIn("--audit --report", out.getvalue())


class TestSelfcheckParsesStdoutOnly(unittest.TestCase):
    """自检解析体检 JSON 时只能看 stdout。

    踩过的坑：selfcheck 的 sh() 把 stdout 与 stderr 合并返回，而 --verify-browser
    的复核进度走在 stderr 上；合起来就让整份 JSON 解析不了，自检那一项报
    「没读出 JSON 报告（退出码 0）」——退出码是好的，问题在解析。
    """

    def _fake_run(self, seen, payload, err):
        def run(cmd, **kwargs):
            seen.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, payload, err)
        return run

    def test_progress_lines_on_stderr_do_not_break_the_report(self):
        report = {"A1_export_ip": {"ip": "203.0.113.10", "country": "US"}}
        payload = json.dumps(report, ensure_ascii=False)
        seen = []
        with mock.patch.object(selfcheck_module.subprocess, "run",
                              side_effect=self._fake_run(seen, payload, "噪音：已替你打开复核页")), \
             mock.patch.object(selfcheck_module, "add") as add_row:
            _path, got = selfcheck_module.check_audit(browser=True)
        self.assertEqual(got, report)
        self.assertIn("--verify-browser", seen[0])
        statuses = [call.args[1] for call in add_row.call_args_list if len(call.args) > 1]
        self.assertNotIn(selfcheck_module.BAD, statuses)

    def test_browser_can_be_left_out(self):
        seen = []
        with mock.patch.object(selfcheck_module.subprocess, "run",
                              side_effect=self._fake_run(seen, "{}", "")), \
             mock.patch.object(selfcheck_module, "add"):
            selfcheck_module.check_audit(browser=False)
        self.assertNotIn("--verify-browser", seen[0])


class TestJsonStdoutStaysClean(unittest.TestCase):
    """--json 的 stdout 只能是那一个 JSON 文档，别人靠它解析。

    踩过的坑：--verify-browser 的复核进度是直接 print 的，自检脚本拿
    `--audit --json --verify-browser` 调过去就解析不了，整项被判失败，
    而退出码还是 0 —— 只能靠这条用例钉住。
    """

    def _run(self, argv):
        report = {"A1_export_ip": {"ip": "203.0.113.10", "country": "US"}}
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["account_guard.py"] + argv), \
             mock.patch.object(g, "audit", return_value=report), \
             mock.patch.object(g, "check_webrtc", return_value={}), \
             mock.patch.object(g, "verify_browser_locale") as locale_probe, \
             mock.patch.object(g, "verify_media_permission") as media_probe, \
             mock.patch.object(g, "running_under_claude", return_value=False), \
             contextlib.redirect_stdout(out):
            locale_probe.side_effect = lambda *a, **k: print("噪音：复核页已打开 http://127.0.0.1:1/x")
            media_probe.side_effect = lambda *a, **k: print("噪音：结果已存")
            code = g.main()
        return code, out.getvalue()

    def test_json_mode_emits_only_json_even_when_the_probes_are_chatty(self):
        code, out = self._run(["--audit", "--json", "--verify-browser"])
        self.assertEqual(code, 0)
        parsed = json.loads(out)          # 解析不了就是回归
        self.assertEqual(parsed["A1_export_ip"]["ip"], "203.0.113.10")

    def test_human_mode_still_shows_the_progress_on_stdout(self):
        code, out = self._run(["--audit", "--json"])
        self.assertEqual(code, 0)
        json.loads(out)                   # 不带复核时本来也干净


class TestBrowserVerifyAutoOpen(unittest.TestCase):
    """复核页由脚本自己打开，并把「这次是谁开的」记进缓存。

    为什么必须这样：结论要归到某个浏览器资料上，而页面自己报不出资料身份。
    只发一条链接让用户在别处打开的话，这一项永远停在「资料身份未由脚本验证」，
    也就是永远测不完 —— 用户 2026-10-15 问的正是这件事。
    """

    def test_opens_chrome_with_the_declared_profile(self):
        seen = []
        env = {"CLAUDE_GUARD_BROWSER_PROFILE": "Claude",
               "CLAUDE_GUARD_BROWSER_PROFILE_DIR": "Profile 1"}
        with mock.patch.dict(os.environ, env), \
             mock.patch.object(g, "run",
                               side_effect=lambda cmd, timeout=20: (seen.append(cmd), (0, ""))[1]):
            out = g.open_verify_page("http://127.0.0.1:1/tok/", "复核页")
        self.assertTrue(out["opened"])
        self.assertIn("Google Chrome", seen[0])
        self.assertIn("--profile-directory=Profile 1", seen[0])
        self.assertEqual(seen[0][-1], "http://127.0.0.1:1/tok/")

    def test_failure_is_reported_not_faked(self):
        with mock.patch.object(g, "run", return_value=(1, "no such app")):
            out = g.open_verify_page("http://127.0.0.1:1/tok/", "复核页")
        self.assertFalse(out["opened"])
        self.assertIn("no such app", out.get("reason", ""))

    def _locale_cache(self, **extra):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        cache = tmp / "browser-locale.json"
        data = {"intlLocale": "en-US", "language": "en-US", "checkedAt": "2026-10-15 13:00",
                "profileScope": "Claude"}
        data.update(extra)
        cache.write_text(json.dumps(data), encoding="utf-8")
        return cache

    def test_check_trusts_a_cache_the_script_opened(self):
        """缓存里记着「复核页是脚本按 Profile 1 开的」，就不再算「身份未验证」。"""
        cache = self._locale_cache(openedBy="script", openedProfileDir="Profile 1")
        with mock.patch.object(g, "LOCALE_CACHE", cache), \
             mock.patch.object(g, "cache_is_fresh", return_value=(True, "")):
            out = g.check_browser_locale()
        self.assertFalse(out.get("scope_unverified"))
        self.assertTrue(out.get("opened_by_script"))
        self.assertIn("Profile 1", out.get("source") or "")

    def test_check_still_flags_a_cache_opened_by_hand(self):
        cache = self._locale_cache(openedBy="user")
        with mock.patch.object(g, "LOCALE_CACHE", cache), \
             mock.patch.object(g, "cache_is_fresh", return_value=(True, "")):
            out = g.check_browser_locale()
        self.assertTrue(out.get("scope_unverified"))

    def _locale_report(self, **extra):
        # 判定读的是 check_browser_locale() 组装出来的 measured，不是缓存里的 intlLocale。
        bl = {"measured": "en-US", "intlLocale": "en-US", "language": "en-US",
              "country": "US", "cn": False, "checked_at": "2026-10-15 13:00"}
        bl.update(extra)
        return {"A27_browser_locale": bl}

    def test_locale_row_greens_for_a_script_opened_page(self):
        report = self._locale_report(opened_by_script=True,
                                     source="浏览器实测（脚本打开的复核页，资料 Profile 1）")
        rows = dict((n, s) for n, s, _ in g.build_summary(report))
        self.assertIs(rows["浏览器 Intl 区域设置"], g.S_OK)

    def test_locale_row_stays_unknown_without_that_proof(self):
        report = self._locale_report(scope_unverified=True,
                                     source="浏览器实测（用户声明资料：Claude；资料身份未由脚本验证）")
        rows = dict((n, s) for n, s, _ in g.build_summary(report))
        self.assertIs(rows["浏览器 Intl 区域设置"], g.S_NA)

    def test_webrtc_row_greens_for_a_script_opened_page(self):
        report = {"A7_webrtc": {"available": False, "note": "未探测"}}
        media = {"ok": True, "camera": "denied", "microphone": "denied",
                 "detail": "NotAllowedError", "checkedAt": "2026-10-15 13:00",
                 "openedBy": "script"}
        with mock.patch.object(g, "load_media_permission", return_value=media), \
             mock.patch.object(g, "cache_is_fresh", return_value=(True, "")):
            rows = dict((n, s) for n, s, _ in g.build_summary(report))
        self.assertIs(rows["WebRTC 泄漏"], g.S_OK)

    def test_webrtc_row_stays_unknown_for_a_hand_opened_page(self):
        report = {"A7_webrtc": {"available": False, "note": "未探测"}}
        media = {"ok": True, "camera": "denied", "microphone": "denied",
                 "checkedAt": "2026-10-15 13:00", "openedBy": "user"}
        with mock.patch.object(g, "load_media_permission", return_value=media), \
             mock.patch.object(g, "cache_is_fresh", return_value=(True, "")):
            rows = dict((n, s) for n, s, _ in g.build_summary(report))
        self.assertIs(rows["WebRTC 泄漏"], g.S_NA)


class TestCliLogin(unittest.TestCase):
    """登录方式：不要在 Claude Code 里做网页授权登录（用户口径 2026-10-15）。

    这条是「防风险操作」而不是环境残留——脚本改不了它，只能如实报出现在用的是
    哪种凭据，并把 setup-token 的做法指出来。
    """

    def _env(self, **extra):
        base = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE_GUARD_")}
        base.pop(g.CLI_LOGIN_TOKEN_ENV, None)
        base.update(extra)
        return base

    def _row(self, report):
        return dict((n, (s, d, )) for n, s, d in g.build_summary(report))["登录方式"]

    def test_env_token_counts_as_long_lived(self):
        env = self._env(**{g.CLI_LOGIN_TOKEN_ENV: "sk-ant-oat01-not-a-real-token"})
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(g.long_lived_token_sources(), ["环境变量"])
            with mock.patch.object(g, "run", return_value=(1, '{"loggedIn": false}')):
                r = g.check_cli_login("/usr/bin/claude")
            status, detail = self._row({"A29_cli_login": r})
        self.assertIs(status, g.S_OK)
        self.assertIn("长期 token", detail)
        # token 本体不进报告、不进那一行——报告会被贴进聊天、存成 JSON
        self.assertNotIn("sk-ant-oat01", json.dumps(r, ensure_ascii=False))
        self.assertNotIn("sk-ant-oat01", detail)

    def test_settings_env_token_counts_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = pathlib.Path(tmp) / "settings.json"
            settings.write_text(json.dumps({"env": {g.CLI_LOGIN_TOKEN_ENV: "x"}}), encoding="utf-8")
            with mock.patch.dict(os.environ, self._env(), clear=True), \
                 mock.patch.object(g, "HOME", pathlib.Path(tmp)), \
                 mock.patch.object(g, "SETTINGS", settings):
                self.assertEqual(g.long_lived_token_sources(), ["settings.json 的 env"])

    def test_shell_rc_token_counts_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = pathlib.Path(tmp)
            (home / ".zshrc").write_text(f'export {g.CLI_LOGIN_TOKEN_ENV}="x"\n', encoding="utf-8")
            with mock.patch.dict(os.environ, self._env(), clear=True), \
                 mock.patch.object(g, "HOME", home), \
                 mock.patch.object(g, "SETTINGS", home / "missing.json"):
                self.assertEqual(g.long_lived_token_sources(), [".zshrc"])

    def test_interactive_login_is_flagged(self):
        payload = json.dumps({"loggedIn": True, "authMethod": "oauth"})
        with mock.patch.dict(os.environ, self._env(), clear=True), \
             mock.patch.object(g, "HOME", pathlib.Path("/nonexistent-guard-home")), \
             mock.patch.object(g, "SETTINGS", pathlib.Path("/nonexistent-guard-home/s.json")), \
             mock.patch.object(g, "run", return_value=(0, payload)):
            r = g.check_cli_login("/usr/bin/claude")
        self.assertEqual(r["state"], "interactive")
        status, detail = self._row({"A29_cli_login": r})
        self.assertIs(status, g.S_FIX)
        self.assertIn("setup-token", detail)

    def test_signed_out_is_flagged_with_the_same_advice(self):
        payload = json.dumps({"loggedIn": False, "authMethod": "none"})
        with mock.patch.dict(os.environ, self._env(), clear=True), \
             mock.patch.object(g, "HOME", pathlib.Path("/nonexistent-guard-home")), \
             mock.patch.object(g, "SETTINGS", pathlib.Path("/nonexistent-guard-home/s.json")), \
             mock.patch.object(g, "run", return_value=(1, payload)):
            r = g.check_cli_login("/usr/bin/claude")
        self.assertEqual(r["state"], "none")
        status, detail = self._row({"A29_cli_login": r})
        self.assertIs(status, g.S_FIX)
        self.assertIn("setup-token", detail)

    def test_unreadable_output_is_not_guessed(self):
        with mock.patch.object(g, "run", return_value=(1, "boom")):
            r = g.check_cli_login("/usr/bin/claude")
        self.assertEqual(r["state"], "unknown")
        self.assertIn("读不懂", r["error"])
        status, _ = self._row({"A29_cli_login": r})
        self.assertIs(status, g.S_NA)

    def test_missing_cli_is_not_guessed(self):
        # 空字符串是假值，会回落到 shutil.which——那样这台开发机上有 claude，
        # 用例就变成在测真 CLI。要真模拟「没装」，必须把 which 也钉住。
        with mock.patch.object(g.shutil, "which", return_value=None), \
             mock.patch.object(g, "run") as spy:
            r = g.check_cli_login()
        self.assertEqual(r["state"], "unknown")
        self.assertIn("没找到", r["error"])
        spy.assert_not_called()

    def test_row_is_not_measured_without_the_report_key(self):
        status, detail = self._row({})
        self.assertIs(status, g.S_NA)
        self.assertEqual(detail, "未检测")

    def test_manual_checklist_carries_the_setup_token_recipe(self):
        groups = dict((name, items) for name, items in g.MANUAL_ACTIONS)
        target = [name for name in groups if name.startswith("八、")]
        self.assertEqual(len(target), 1, "人工清单里少了「八、登录方式」那一组")
        flat = " ".join(" ".join(steps) for _, _, steps, _ in groups[target[0]])
        self.assertIn("claude setup-token", flat)
        self.assertIn(g.CLI_LOGIN_TOKEN_ENV, flat)


class TestFixAuto(unittest.TestCase):
    """--fix-auto：体检之后当场修四类残留，动手前确认一次，收尾必须给 HTML。

    这一组守的是「一轮跑完」的边界：没有 --yes 就不许在管道里改东西；
    有 --yes 也必须先备份；不管修没修、取没取消，页面都得给出来。
    """

    EMPTY_PLAN = {
        "summary": [], "proxy_residue": [], "rc_files": {}, "npm_git": [],
        "settings_base_url": False, "settings_env_proxy": [], "clash_dns": False,
        "browser_locale": False, "storage_bytes": 0, "dead_permissions": 0,
        "stale_worktrees": [], "project_junk": False, "other_proxy_dns": {},
        "npmrc": [], "brew_proxy": [],
    }

    def _plan(self, **over):
        plan = dict(self.EMPTY_PLAN)
        plan.update(over)
        return plan

    def test_yes_without_fix_auto_is_refused(self):
        self.assertEqual(g.main(["--yes"]), 2, "--yes 只能配合 --fix-auto")

    def test_fix_auto_refuses_json(self):
        self.assertEqual(g.main(["--fix-auto", "--json"]), 2,
                         "--fix-auto 会写状态，不能混进纯 JSON 输出")

    def test_fix_auto_without_yes_needs_a_real_tty(self):
        written = []
        with mock.patch.object(g, "audit", return_value={}), \
             mock.patch.object(g, "print_audit"), \
             mock.patch.object(g, "print_summary_table"), \
             mock.patch.object(g, "auto_clean_plan",
                               return_value=self._plan(proxy_residue=[{"service": "Wi-Fi"}])), \
             mock.patch.object(g.sys.stdin, "isatty", create=True, return_value=False), \
             mock.patch("report_html.write_report",
                        side_effect=lambda *a, **k: written.append(k) or pathlib.Path("/tmp/r.html")):
            self.assertEqual(g.main(["--fix-auto"]), 2)
        self.assertEqual(written, [], "被拒绝时不该顺手出页面")

    def test_nothing_to_fix_still_hands_over_a_page(self):
        written = []
        with mock.patch.object(g, "audit", return_value={}), \
             mock.patch.object(g, "print_audit"), \
             mock.patch.object(g, "print_summary_table"), \
             mock.patch.object(g, "auto_clean_plan", return_value=self._plan()), \
             mock.patch.object(g, "create_backup") as backup, \
             mock.patch("report_html.write_report",
                        side_effect=lambda *a, **k: written.append(k) or pathlib.Path("/tmp/r.html")):
            self.assertEqual(g.main(["--fix-auto", "--yes"]), 0)
        backup.assert_not_called()
        self.assertEqual(len(written), 1, "没有可修项也要给一份只有体检结果的页面")

    def test_cancel_at_the_inline_confirm_keeps_the_machine_untouched(self):
        written = []
        report = {"scope_manifest": {}}
        with mock.patch.object(g, "audit", return_value=report), \
             mock.patch.object(g, "print_audit"), \
             mock.patch.object(g, "print_summary_table"), \
             mock.patch.object(g, "auto_clean_plan",
                               return_value=self._plan(proxy_residue=[{"service": "Wi-Fi"}])), \
             mock.patch.object(g, "create_backup") as backup, \
             mock.patch.object(g.sys.stdin, "isatty", create=True, return_value=True), \
             mock.patch("builtins.input", return_value="n"), \
             mock.patch("report_html.write_report",
                        side_effect=lambda *a, **k: written.append(k) or pathlib.Path("/tmp/r.html")):
            self.assertEqual(g.main(["--fix-auto"]), 1)
        backup.assert_not_called()
        self.assertEqual(len(written), 1, "取消时也要把改动前那份页面给出来")

    def test_preflight_asks_before_the_audit_and_only_once(self):
        args = mock.Mock(verify_browser=False, webrtc=False, expected_country=None,
                         expected_exit_ip=None, json=False)
        with mock.patch.object(g.sys.stdin, "isatty", create=True, return_value=True), \
             mock.patch("builtins.input", side_effect=["", "", "n"]):
            g.run_preflight(args)
        self.assertTrue(args.verify_browser, "空的默认回答应当按「要测」处理")
        self.assertTrue(args.webrtc, "WebRTC 探测也要在体检之前问，否则这一项必然未测到")

    def test_preflight_stays_out_of_the_way_without_a_tty(self):
        args = mock.Mock(verify_browser=False, webrtc=False, expected_country=None,
                         expected_exit_ip=None, json=False)
        stderr = io.StringIO()
        with mock.patch.object(g.sys.stdin, "isatty", create=True, return_value=False), \
             mock.patch("builtins.input") as ask, \
             contextlib.redirect_stderr(stderr):
            g.run_preflight(args)
        ask.assert_not_called()
        self.assertFalse(args.verify_browser)
        self.assertIn("--verify-browser", stderr.getvalue())


class TestShellResidueMatcher(unittest.TestCase):
    """shell 配置里只删「代理/端点赋值」，不碰别名和路径配置。

    2026-10-19 独立复测发现：旧实现按 `proxy|ANTHROPIC|CLAUDE` 匹配整行，
    `.zshrc` 里的 `alias claude=...` 与 `CLAUDE_CONFIG_DIR` 会被当代理行删掉。
    """

    def test_proxy_and_endpoint_assignments_are_residue(self):
        for line in ("export HTTPS_PROXY=http://127.0.0.1:7897",
                     "https_proxy=http://127.0.0.1:7897",
                     "export ALL_PROXY=socks5://127.0.0.1:7897",
                     "export NO_PROXY=localhost,127.0.0.1",
                     "declare -x ANTHROPIC_BASE_URL=https://relay.example.com"):
            self.assertTrue(g.shell_line_is_residue(line), line)

    def test_claude_alias_and_path_config_are_not_residue(self):
        for line in ("alias claude='claude --verbose'",
                     'export CLAUDE_CONFIG_DIR="$HOME/.claude-alt"',
                     "export ANTHROPIC_MODEL=claude-opus-4",
                     # 长期 token 是文档让用户放的，删了等于把登录方式从 ✓ 变 !。
                     "export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-xxx",
                     "# export HTTPS_PROXY=http://127.0.0.1:7897",
                     "export PATH=$PATH:$HOME/.local/bin"):
            self.assertFalse(g.shell_line_is_residue(line), line)

    def test_the_scan_uses_this_matcher(self):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="guard-rc-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        home = g.HOME
        g.HOME = tmp
        self.addCleanup(lambda: setattr(g, "HOME", home))
        (tmp / ".zshrc").write_text(
            "alias claude='claude --verbose'\n"
            "export CLAUDE_CONFIG_DIR=$HOME/.alt\n"
            "export HTTPS_PROXY=http://127.0.0.1:7897\n", encoding="utf-8")
        with mock.patch.object(g, "run", return_value=(1, "")):
            out = g.check_terminal_env()
        hits = out["rc_files"][".zshrc"]
        self.assertEqual([h["line"] for h in hits], [3], "只有第 3 行是代理行")


class TestFixAutoSafety(unittest.TestCase):
    """--fix-auto 的备份/日志边界：改之前先记，失败也能看出改过。"""

    PLAN = {"summary": [], "proxy_residue": [], "rc_files": {}, "npm_git": [],
            "settings_base_url": False, "settings_env_proxy": [], "clash_dns": False,
            "browser_locale": False, "storage_bytes": 0, "dead_permissions": 0,
            "stale_worktrees": [], "project_junk": False, "other_proxy_dns": {},
            "npmrc": [], "brew_proxy": []}

    def _run(self, plan, backup=None, mark=None, page=None):
        backup_mock = backup or mock.Mock(return_value=pathlib.Path("/tmp/bk"))
        mark_mock = mark or mock.Mock()
        page_mock = page or mock.Mock(return_value=pathlib.Path("/tmp/r.html"))
        with mock.patch.object(g, "audit", return_value={"scope_manifest": {}}), \
             mock.patch.object(g, "print_audit"), \
             mock.patch.object(g, "print_summary_table"), \
             mock.patch.object(g, "auto_clean_plan", return_value=plan), \
             mock.patch.object(g, "create_backup", backup_mock), \
             mock.patch.object(g, "_refresh_backup_manifest"), \
             mock.patch.object(g, "_mark_backup_in_progress", mark_mock), \
             mock.patch.object(g, "backup_paths_for_plan", return_value=([], [])), \
             mock.patch.object(g, "acquire_run_lock", return_value=(True, "locked")), \
             mock.patch.object(g, "release_run_lock"), \
             mock.patch.object(g, "print_before_after"), \
             mock.patch.object(g, "write_html_twin", page_mock):
            return g.main(["--fix-auto", "--yes"])

    def test_the_mutation_is_journalled_before_it_runs(self):
        plan = dict(self.PLAN, rc_files={".zshrc": [{"line": 1, "text": "x"}]})
        mark = mock.Mock()
        with mock.patch.object(g, "clear_rc_proxy_lines", return_value=[".zshrc"]):
            self.assertEqual(self._run(plan, mark=mark), 0)
        mark.assert_called_with(mock.ANY, "shell-rc")

    def test_under_claude_defers_the_settings_write(self):
        # 在 Claude Code 里跑时不能改它正在用的 settings.json：跳过这一项，
        # 但页面照出、其余项照修。
        plan = dict(self.PLAN, settings_base_url=True)
        args = mock.Mock(yes=True, expected_country=None, expected_exit_ip=None)
        with mock.patch.object(g, "auto_clean_plan", return_value=plan), \
             mock.patch.object(g, "write_html_only") as page, \
             mock.patch.object(g, "clear_anthropic_base_url") as clear:
            self.assertEqual(g.run_fix_auto({"scope_manifest": {}}, args, under_claude=True), 0)
        clear.assert_not_called()
        page.assert_called_once()

    def test_a_failed_report_is_not_reported_as_success(self):
        # 收尾页面是这条流程的交付物：没写成还返回 0，调用方会以为拿到了报告。
        plan = dict(self.PLAN, rc_files={".zshrc": [{"line": 1, "text": "x"}]})
        with mock.patch.object(g, "clear_rc_proxy_lines", return_value=[".zshrc"]):
            self.assertEqual(self._run(plan, page=mock.Mock(return_value=None)), 2)

    def test_proxy_residue_is_recorded_as_a_manual_boundary(self):
        plan = dict(self.PLAN, proxy_residue=[{"service": "Wi-Fi", "kind": "webproxy",
                                              "server": "127.0.0.1", "port": "7897"}])
        backup = mock.Mock(return_value=pathlib.Path("/tmp/bk"))
        with mock.patch.object(g, "clear_proxy_residue", return_value=1):
            self.assertEqual(self._run(plan, backup=backup), 0)
        boundaries = backup.call_args.kwargs.get("manual_boundaries") or []
        self.assertTrue(any("系统代理" in b for b in boundaries), boundaries)


class TestHtmlHonesty(unittest.TestCase):
    """页面不能一边给 0 分一边说「全部通过」；上下文备注要印在页面上。"""

    def test_all_unmeasured_never_claims_everything_passed(self):
        rows = [(f"r{i}", g.S_NA, "") for i in range(rh.BASE_ITEMS)]
        with mock.patch.object(g, "build_summary", return_value=rows):
            page = rh.render({"timestamp": "2026-01-01 00:00:00"})
        self.assertNotIn("项全部通过", page, "0 分和「全部通过」不能同时出现")
        self.assertIn("没测到", page)

    def test_the_note_is_printed_on_the_page(self):
        rows = [("a", g.S_OK, "")] * rh.BASE_ITEMS
        with mock.patch.object(g, "build_summary", return_value=rows):
            page = rh.render({"timestamp": "2026-01-01 00:00:00"},
                             note="已取消，这是改动前的状态")
        self.assertIn("已取消，这是改动前的状态", page)


if __name__ == "__main__":
    # 这个块必须待在文件最末尾。2026-10-10 发现它一度停在中间（第 2403 行），
    # 于是它后面定义的 6 个类、40 个用例从来没被执行过——`unittest.main()` 在第 2403
    # 行就跑完了收集，而那几个类那时还没被定义。症状是「测试全过」，实际只跑了
    # 227/267。往这个文件里加用例时，务必加在下面这行之上。
    unittest.main(verbosity=2)
