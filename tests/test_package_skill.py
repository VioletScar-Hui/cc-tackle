#!/usr/bin/env python3
"""可复现技能打包器：只装运行时、两遍字节相同、不许把输出写进包内。

用临时目录现造一棵迷你技能树（不碰真仓库、不碰网络），直接调
`tools/package_skill.py` 的函数和 `main()`，守四类容易坏的事：

  * 该进的进（SKILL.md / scripts / references），该排除的排除（__pycache__、
    *.pyc、.DS_Store、*.bak、tests/、docs/、tools/、.github/、README*）；
  * 同一份内容两次构建、两个不同根目录构建，zip 逐字节相同，元数据固定；
  * 清单里的 sha256 就是 zip 文件的 sha256，路径全是相对 POSIX 路径；
  * 输出落在打包树里要拒绝，软链指向根目录外不能跟进包。
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest
import zipfile

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "package_skill.py"

SKILL_MD = (
    "---\n"
    "name: x\n"
    "metadata:\n"
    '  version: "1.2.3"\n'
    "---\n"
    "\n"
    "# x\n"
)
SCRIPT_A = "print('a')\n"
SCRIPT_NESTED = "print('nested')\n"
REFERENCE_B = "# b\n"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "cc_tackle_package_skill", str(TOOL_PATH))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pkg = _load_tool()


def _write(path, data):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    path.write_bytes(data)


def _make_repo(tmp_root, name="repo"):
    """造一棵含运行时文件与各类本机垃圾的迷你技能树。"""
    root = pathlib.Path(tmp_root) / name
    _write(root / "SKILL.md", SKILL_MD)
    _write(root / "scripts" / "a.py", SCRIPT_A)
    _write(root / "scripts" / "sub" / "nested.py", SCRIPT_NESTED)
    _write(root / "references" / "b.md", REFERENCE_B)
    # 以下都不该进包。
    _write(root / "references" / "README.md", "readme\n")
    _write(root / "scripts" / "__pycache__" / "x.cpython-39.pyc", b"\x00\x01")
    _write(root / "scripts" / ".DS_Store", b"\x00")
    _write(root / "scripts" / "a.py.bak", "old\n")
    _write(root / "scripts" / "a.pyc", b"\x00")
    _write(root / "tests" / "ignored.py", "raise AssertionError('不该执行')\n")
    _write(root / "docs" / "note.md", "doc\n")
    _write(root / "tools" / "other.py", "X = 1\n")
    _write(root / ".github" / "workflows" / "ci.yml", "on: push\n")
    _write(root / "README.md", "readme\n")
    return root


def _run_main(args):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = pkg.main(list(args))
    return code, stdout.getvalue(), stderr.getvalue()


def _sha256_file(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


class TestBuildTree(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)
        self.root = _make_repo(self.tmp)

    def test_only_runtime_files_included(self):
        files, dirs, _skipped = pkg.collect_runtime_entries(self.root)
        self.assertEqual(
            [rel for rel, _disk in files],
            ["SKILL.md", "references/b.md", "scripts/a.py", "scripts/sub/nested.py"])
        self.assertEqual(dirs, ["references", "scripts", "scripts/sub"])

    def test_excluded_entries_absent_from_zip(self):
        payload, manifest = pkg.build_archive(self.root)
        names = zipfile.ZipFile(io.BytesIO(payload)).namelist()
        joined = "\n".join(names)
        for forbidden in ("__pycache__", ".DS_Store", ".pyc", ".bak",
                          "tests/", "docs/", "tools/", ".github/", "README"):
            self.assertNotIn(forbidden, joined, forbidden)
        self.assertNotIn("README.md", [item["path"] for item in manifest["files"]])

    def test_manifest_version_and_counts(self):
        payload, manifest = pkg.build_archive(self.root)
        self.assertEqual(manifest["version"], "1.2.3")
        self.assertEqual(manifest["name"], "x")
        self.assertEqual(manifest["file_count"], 4)
        self.assertEqual(manifest["dir_count"], 3)
        self.assertEqual(manifest["entry_count"], len(zipfile.ZipFile(
            io.BytesIO(payload)).namelist()))
        self.assertEqual(manifest["zip_bytes"], len(payload))

    def test_manifest_sha_matches_zip_file(self):
        output = self.tmp / "out" / "skill.zip"
        manifest = pkg.package(self.root, output)
        self.assertEqual(manifest["sha256"], _sha256_file(output))
        self.assertEqual(manifest["zip_bytes"], output.stat().st_size)

    def test_per_file_sha_matches_contents(self):
        payload, manifest = pkg.build_archive(self.root)
        expected = {
            "SKILL.md": SKILL_MD.encode("utf-8"),
            "references/b.md": REFERENCE_B.encode("utf-8"),
            "scripts/a.py": SCRIPT_A.encode("utf-8"),
            "scripts/sub/nested.py": SCRIPT_NESTED.encode("utf-8"),
        }
        paths = [item["path"] for item in manifest["files"]]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(len(paths), manifest["file_count"])
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for item in manifest["files"]:
                self.assertEqual(item["sha256"],
                                 hashlib.sha256(expected[item["path"]]).hexdigest(),
                                 item["path"])
                self.assertEqual(archive.read(item["path"]), expected[item["path"]])

    def test_zip_metadata_is_fixed(self):
        payload, _manifest = pkg.build_archive(self.root)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            self.assertEqual(archive.namelist(), sorted(archive.namelist()))
            for info in archive.infolist():
                self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0), info.filename)
                self.assertEqual(info.create_system, 3, info.filename)
                if info.filename.endswith("/"):
                    self.assertEqual(info.external_attr, 0o755 << 16 | 0x10)
                else:
                    self.assertEqual(info.external_attr, 0o644 << 16)

    def test_entry_names_are_relative_posix_paths(self):
        payload, _manifest = pkg.build_archive(self.root)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for name in archive.namelist():
                self.assertFalse(name.startswith("/"), name)
                self.assertNotIn("\\", name)
                self.assertNotIn("..", name.split("/"))
                self.assertNotIn(str(self.root), name)
        # 绝对路径/主机信息不该出现在包体里。
        self.assertNotIn(str(self.root).encode("utf-8"), payload)


class TestDeterminism(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)
        self.root = _make_repo(self.tmp, "repo")

    def test_two_builds_are_byte_identical(self):
        first_dir = self.tmp / "build1"
        second_dir = self.tmp / "build2"
        first_dir.mkdir()
        second_dir.mkdir()
        first = pkg.package(self.root, first_dir / "skill.zip")
        second = pkg.package(self.root, second_dir / "skill.zip")
        self.assertEqual(_sha256_file(first_dir / "skill.zip"),
                         _sha256_file(second_dir / "skill.zip"))
        self.assertEqual(first["sha256"], second["sha256"])

    def test_same_content_different_root_is_identical(self):
        """换一个根目录（内容相同）也必须是同一份字节，不能带进绝对路径。"""
        twin = _make_repo(self.tmp, "repo-twin")
        out_a = self.tmp / "a.zip"
        out_b = self.tmp / "b.zip"
        pkg.package(self.root, out_a)
        pkg.package(twin, out_b)
        self.assertEqual(out_a.read_bytes(), out_b.read_bytes())

    def test_check_command_exits_zero_for_good_tree(self):
        code, out, err = _run_main(["--root", str(self.root), "--check"])
        self.assertEqual(code, 0, err)
        manifest = pkg.check_reproducible(self.root)
        self.assertIn("sha256={0}".format(manifest["sha256"]), out)
        self.assertIn("可复现", out)

    def test_check_command_json_manifest(self):
        code, out, err = _run_main(
            ["--root", str(self.root), "--check", "--json"])
        self.assertEqual(code, 0, err)
        manifest = json.loads(out)
        self.assertTrue(manifest["reproducible"])
        self.assertEqual(manifest["version"], "1.2.3")
        self.assertGreater(manifest["entry_count"], 0)

    def test_cli_json_manifest_matches_output_file(self):
        output = self.tmp / "json" / "skill.zip"
        code, out, err = _run_main(
            ["--root", str(self.root), "--output", str(output), "--json"])
        self.assertEqual(code, 0, err)
        manifest = json.loads(out)
        self.assertEqual(manifest["sha256"], _sha256_file(output))
        self.assertEqual(manifest["version"], "1.2.3")
        self.assertTrue(output.is_file())


class TestSafety(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)
        self.root = _make_repo(self.tmp, "repo")

    def test_output_inside_packaged_tree_is_rejected(self):
        for target in (self.root / "scripts" / "bundle.zip",
                       self.root / "references" / "bundle.zip",
                       self.root / "SKILL.md"):
            with self.assertRaises(pkg.PackageError, msg=str(target)):
                pkg.package(self.root, target)

    def test_output_inside_packaged_tree_exits_2(self):
        code, _out, err = _run_main([
            "--root", str(self.root),
            "--output", str(self.root / "scripts" / "bundle.zip"),
        ])
        self.assertEqual(code, 2)
        self.assertIn("打包", err)

    def test_output_directory_is_rejected(self):
        (self.tmp / "existing-dir").mkdir()
        for target in (self.root, self.tmp / "existing-dir"):
            with self.assertRaises(pkg.PackageError, msg=str(target)):
                pkg.package(self.root, target)

    def test_output_elsewhere_inside_root_is_allowed(self):
        """默认输出 dist/ 就在仓库里，只要不在打包树里就允许。"""
        output = self.root / "dist" / "cc-tackle-skill.zip"
        manifest = pkg.package(self.root, output)
        self.assertTrue(output.is_file())
        self.assertEqual(manifest["sha256"], _sha256_file(output))
        self.assertNotIn("dist", [item["path"] for item in manifest["files"]])

    def test_symlink_outside_root_is_skipped(self):
        if not hasattr(os, "symlink"):
            self.skipTest("本机不支持软链")
        secret = self.tmp / "outside-secret.txt"
        _write(secret, b"outside-secret")
        outside_dir = self.tmp / "outside-dir"
        outside_dir.mkdir()
        _write(outside_dir / "leak.py", b"outside-secret")
        os.symlink(secret, self.root / "scripts" / "leak.py")
        os.symlink(outside_dir, self.root / "scripts" / "extdir")
        os.symlink(self.root / "scripts" / "gone.py",
                   self.root / "scripts" / "broken.py")

        files, _dirs, skipped = pkg.collect_runtime_entries(self.root)
        paths = [rel for rel, _disk in files]
        self.assertNotIn("scripts/leak.py", paths)
        self.assertIn("scripts/leak.py", skipped)
        self.assertIn("scripts/extdir", skipped)
        self.assertIn("scripts/broken.py", skipped)

        payload, manifest = pkg.build_archive(self.root)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            names = archive.namelist()
        for name in names:
            self.assertFalse(name.endswith("leak.py"), name)
            self.assertNotIn("extdir/", name)
        self.assertNotIn(b"outside-secret", payload)
        self.assertEqual(sorted(manifest["skipped"]),
                         ["scripts/broken.py", "scripts/extdir", "scripts/leak.py"])

    def test_symlink_inside_root_is_followed(self):
        if not hasattr(os, "symlink"):
            self.skipTest("本机不支持软链")
        os.symlink(self.root / "scripts" / "a.py",
                   self.root / "scripts" / "alias.py")
        payload, manifest = pkg.build_archive(self.root)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            self.assertEqual(archive.read("scripts/alias.py"), SCRIPT_A.encode())

    def test_missing_required_entry_exits_1(self):
        code, _out, err = _run_main([
            "--root", str(self.root),
            "--output", str(self.tmp / "required.zip"),
            "--require", "SKILL.md",
            "--require", "scripts/missing.py",
        ])
        self.assertEqual(code, 1)
        self.assertIn("scripts/missing.py", err)
        self.assertFalse((self.tmp / "required.zip").exists())

    def test_missing_skill_md_exits_2(self):
        bare = self.tmp / "bare"
        _write(bare / "scripts" / "a.py", SCRIPT_A)
        code, _out, err = _run_main(["--root", str(bare), "--check"])
        self.assertEqual(code, 2)
        self.assertIn("SKILL.md", err)

    def test_unreadable_file_reports_clear_error(self):
        if not hasattr(os, "geteuid") or os.geteuid() == 0:
            self.skipTest("root 用户不受文件读权限位限制")
        unreadable = self.root / "scripts" / "unreadable.py"
        _write(unreadable, "x = 1\n")
        os.chmod(unreadable, 0)
        self.addCleanup(os.chmod, unreadable, 0o644)
        with self.assertRaises(pkg.PackageError) as ctx:
            pkg.build_archive(self.root)
        self.assertIn("unreadable.py", str(ctx.exception))
        code, _out, err = _run_main([
            "--root", str(self.root),
            "--output", str(self.tmp / "unreadable.zip"),
        ])
        self.assertEqual(code, 2)
        self.assertIn("unreadable.py", err)
        self.assertFalse((self.tmp / "unreadable.zip").exists())


class TestFrontmatter(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)

    def _metadata(self, text, name="SKILL.md"):
        path = self.tmp / name
        _write(path, text)
        return pkg.read_skill_metadata(path)

    def test_quoted_version(self):
        self.assertEqual(self._metadata(SKILL_MD)["version"], "1.2.3")
        self.assertEqual(self._metadata(SKILL_MD)["name"], "x")

    def test_unquoted_version(self):
        text = "---\nname: y\nmetadata:\n  version: 2.0.0\n---\n"
        self.assertEqual(self._metadata(text)["version"], "2.0.0")

    def test_missing_version_returns_empty_string(self):
        text = "---\nname: z\n---\n\n# z\n"
        meta = self._metadata(text)
        self.assertEqual(meta["version"], "")
        self.assertEqual(meta["name"], "z")


if __name__ == "__main__":
    unittest.main()
