#!/usr/bin/env python3
"""住宅链路锁定：整包吸收后的入口不能空转。

测的是三件容易坏的事：
  * 吸收进来的脚本还在不在（别只搬了包装壳）；
  * 动作到命令的映射对不对（--root-* 必须带 sudo，--dry-run 要透传）；
  * 参数文件允许用环境变量覆盖（测试别写进真实用户目录）。
"""

from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))

import residential_lock as rl  # noqa: E402


class TestVendoredScripts(unittest.TestCase):
    def test_every_absorbed_script_is_present(self):
        for name in ("guard.sh", "guard-install.sh", "lib-common.sh", "expand.py",
                     "dns-guard.py", "harden-root.sh", "pf-update.sh", "install.sh",
                     "selfcheck.sh", "discover.sh", "judge-ip.py",
                     "merge-gen.py", "claude-residential.env.example"):
            self.assertTrue(rl.script(name).exists(), name)

    def test_shell_scripts_are_executable(self):
        for name in ("guard.sh", "guard-install.sh", "harden-root.sh", "pf-update.sh",
                     "install.sh", "selfcheck.sh", "discover.sh"):
            self.assertTrue(rl.script(name).stat().st_mode & 0o111, name)

    def test_no_bare_variable_before_multibyte(self):
        """bash 3.2 的坑：`$VAR` 紧跟全角括号会被当成变量名的一部分。

        原脚本在本机 /bin/bash 3.2 上直接报 unbound variable。吸收时统一改成
        `${VAR}`，这里守一道回归。
        """
        import re
        pat = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*(?=[^\x00-\x7F])")
        for path in sorted(rl.SCRIPTS.glob("*.sh")):
            for line_no, line in enumerate(path.read_text().splitlines(), 1):
                self.assertIsNone(pat.search(line),
                                  f"{path.name}:{line_no} 少了花括号：{line.strip()}")

    def test_reference_docs_are_present(self):
        root = pathlib.Path(__file__).resolve().parent.parent
        self.assertTrue((root / "references" / "residential-lock.md").exists())
        self.assertTrue((root / "references" / "residential-pitfalls.md").exists())


class TestCommands(unittest.TestCase):
    def test_user_level_actions(self):
        expected = {
            "init": "install.sh",
            "install": "guard-install.sh",
            "uninstall": "guard-install.sh",
            "check": "guard.sh",
            "discover": "discover.sh",
            "selfcheck": "selfcheck.sh",
        }
        for action, script_name in expected.items():
            cmd = rl.build_command(action)
            self.assertEqual(cmd[0], "/bin/bash", action)
            self.assertIn(script_name, " ".join(cmd), action)

    def test_root_actions_use_sudo(self):
        for action in ("root-install", "root-uninstall"):
            cmd = rl.build_command(action)
            self.assertEqual(cmd[0], "sudo")
            self.assertIn("harden-root.sh", " ".join(cmd))

    def test_dry_run_is_passed_through(self):
        self.assertIn("--dry-run", rl.build_command("init", dry_run=True))
        self.assertIn("--dry-run", rl.build_command("root-install", dry_run=True))
        self.assertNotIn("--dry-run", rl.build_command("install"))

    def test_unknown_action(self):
        self.assertIsNone(rl.build_command("nope"))


class TestEnvFile(unittest.TestCase):
    def test_default_points_at_library_scripts(self):
        with mock.patch.dict("os.environ", {}, clear=False):
            os_env = dict(__import__("os").environ)
            os_env.pop("CLAUDE_RESIDENTIAL_ENV", None)
            with mock.patch.dict("os.environ", os_env, clear=True):
                self.assertIn("Library/Scripts/claude-residential.env",
                              str(rl.env_file()))

    def test_override_wins(self):
        with mock.patch.dict("os.environ", {"CLAUDE_RESIDENTIAL_ENV": "/tmp/x.env"}):
            self.assertEqual(str(rl.env_file()), "/tmp/x.env")


class TestStatus(unittest.TestCase):
    def test_root_status_without_plists(self):
        with mock.patch.object(rl, "run", return_value=(1, "")), \
             mock.patch.object(rl.pathlib.Path, "exists", return_value=False), \
             mock.patch.object(rl.pathlib.Path, "is_dir", return_value=False):
            out = rl.root_status()
        self.assertFalse(out["pf_plist"])
        self.assertFalse(out["dns_plist"])
        self.assertIsNone(out["pf_rules"])

    def test_pf_rule_count_when_sudo_works(self):
        def fake(cmd, timeout=60):
            if cmd[:2] == ["sudo", "-n"]:
                return 0, "pass in quick on en0\nblock drop on en0\n"
            return 1, ""
        with mock.patch.object(rl, "run", side_effect=fake), \
             mock.patch.object(rl.pathlib.Path, "exists", return_value=True), \
             mock.patch.object(rl.pathlib.Path, "is_dir", return_value=True):
            out = rl.root_status()
        self.assertEqual(out["pf_rules"], 2)

    def test_status_returns_zero(self):
        with mock.patch.object(rl, "run", return_value=(1, "")), \
             mock.patch.object(rl.pathlib.Path, "exists", return_value=False), \
             mock.patch.object(rl.pathlib.Path, "is_dir", return_value=False), \
             mock.patch("builtins.print"):
            self.assertEqual(rl.main(["--status"]), 0)

    def test_bare_invocation_is_status(self):
        with mock.patch.object(rl, "status", return_value=0) as fake:
            rl.main([])
        fake.assert_called_once()


if __name__ == "__main__":
    unittest.main()
