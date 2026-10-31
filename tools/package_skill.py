#!/usr/bin/env python3
"""把技能打包成可复现的 zip 分发包。

只装用户真正要拷走的运行时：`SKILL.md`、`scripts/`、`references/`。仓库里
的 `tests/`、`docs/`、`tools/`、`.github/`、`README*`，以及 `__pycache__`、
`*.pyc`、`.DS_Store`、`*.bak` 这类本机垃圾，一律不进包——分发的是技能，不是
整个仓库。

「可复现」指同一份内容无论跑多少次、从哪个 `--root` 跑，产出的 zip 都逐字节
相同：路径排序、时间戳固定成 1980-01-01、权限位固定、压缩参数固定，不写主机
名、绝对路径和任何会因机器不同而变化的东西。`--check` 会真的建两遍再比
sha256，不一致就以退出码 1 结束。

用法：
    python3 tools/package_skill.py                    打包到 dist/cc-tackle-skill.zip
    python3 tools/package_skill.py --output /tmp/x.zip 换个输出路径
    python3 tools/package_skill.py --json             打包并以 JSON 打印清单
    python3 tools/package_skill.py --check            建两遍比对，打印 sha256
    python3 tools/package_skill.py --check --require scripts/account_guard.py
                                                      顺带验收必须进包的条目

退出码：0 成功；1 不可复现或缺少 `--require` 指定的条目；2 打包环境有问题
（根目录不像技能、输出路径落在打包树里、文件读不出来等）。
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_ROOT = HERE.parent
DEFAULT_OUTPUT = "dist/cc-tackle-skill.zip"

#: 根目录下必须进包的文件（SKILL.md 也提供 metadata.version）。
RUNTIME_FILES = ("SKILL.md",)
#: 根目录下整棵进包的目录。
RUNTIME_DIRS = ("scripts", "references")

#: 这些目录名、文件名在打包树里整层跳过。
EXCLUDED_DIR_NAMES = frozenset({
    "__pycache__",
    ".git",
    "tests",
    "docs",
    "tools",
    ".github",
    ".venv",
    ".pytest_cache",
    ".mypy_cache",
})
EXCLUDED_FILE_SUFFIXES = (".pyc", ".pyo", ".bak", ".swp", ".orig", ".rej")
EXCLUDED_FILE_PREFIXES = ("README",)

#: 固定元数据：可复现的关键。1980-01-01 是 zip 能表示的最早时间。
ZIP_DATE_TIME = (1980, 1, 1, 0, 0, 0)
FILE_MODE = 0o644
DIR_MODE = 0o755
CREATE_SYSTEM = 3  # Unix，配合 external_attr 的权限位
COMPRESS_LEVEL = 9

_INLINE_VERSION_RE = re.compile(r"""version\s*:\s*["']?([^"',}\s]+)""")


class PackageError(RuntimeError):
    """打包环境有问题（退出码 2）。"""


class MissingRequirementsError(PackageError):
    """缺 `--require` 指定的条目（退出码 1）。"""

    def __init__(self, missing):
        self.missing = list(missing)
        super().__init__("缺少必须的条目：{0}".format(", ".join(self.missing)))


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _is_relative_to(path, base):
    try:
        Path(path).relative_to(Path(base))
    except ValueError:
        return False
    return True


def _resolved_inside(path, root):
    """把软链解析成真实路径；落在 root 外、断链或成环时返回 None。"""
    try:
        target = Path(path).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if target == Path(root) or _is_relative_to(target, root):
        return target
    return None


def _is_excluded_dir(name):
    return name in EXCLUDED_DIR_NAMES or name.startswith(".")


def _is_excluded_file(name):
    if name.startswith("."):
        return True
    if name.upper().startswith(EXCLUDED_FILE_PREFIXES):
        return True
    return name.endswith(EXCLUDED_FILE_SUFFIXES)


def _clean_scalar(value):
    """取 YAML 标量的值：去引号、去行尾注释。只处理 SKILL.md 里这几种写法。"""
    value = value.strip()
    if not value:
        return ""
    if value[0] in "\"'":
        quote = value[0]
        end = value.find(quote, 1)
        return value[1:end] if end > 0 else value[1:]
    comment = value.find(" #")
    if comment > 0:
        value = value[:comment].strip()
    return value


def read_skill_metadata(skill_md):
    """读 SKILL.md frontmatter 里的 name 与 metadata.version。

    只用标准库，所以不引 PyYAML，只认本仓库实际会写的缩进块写法；读不到就返回
    空串，不把「缺版本号」升级成打包失败。
    """
    path = Path(skill_md)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PackageError("读不出 {0}：{1}".format(path, exc))
    meta = {"name": "", "version": ""}
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return meta
    try:
        end = lines.index("---", 1)
    except ValueError:
        return meta
    in_metadata = False
    for line in lines[1:end]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            in_metadata = False
            if stripped.startswith("name:") and not meta["name"]:
                meta["name"] = _clean_scalar(stripped[len("name:"):])
            elif stripped.startswith("metadata:"):
                rest = stripped[len("metadata:"):].strip()
                if rest:
                    match = _INLINE_VERSION_RE.search(rest)
                    if match:
                        meta["version"] = match.group(1)
                else:
                    in_metadata = True
            continue
        if in_metadata and stripped.startswith("version:"):
            meta["version"] = _clean_scalar(stripped[len("version:"):])
    return meta


# ---------------------------------------------------------------------------
# 收集要进包的条目
# ---------------------------------------------------------------------------


def _walk_runtime_dir(root, base, top):
    """递归收集 `base` 下要进包的文件与目录。

    返回 (files, dirs, skipped)：files 是 [(相对 POSIX 路径, 磁盘路径)]，dirs
    只留确实有文件落进去的目录（空目录不进包），skipped 是跳过的软链等。
    """
    files = []
    dirs = []
    skipped = []

    def visit(dir_path, prefix):
        before = len(files)
        try:
            children = sorted(dir_path.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise PackageError("读不出目录 {0}：{1}".format(dir_path, exc))
        for child in children:
            rel = prefix + "/" + child.name
            if child.is_symlink():
                target = _resolved_inside(child, root)
                if target is None or target.is_dir():
                    # 指向根目录外、断链、或目录软链：一律不跟进包。
                    skipped.append(rel)
                    continue
                files.append((rel, target))
                continue
            if child.is_dir():
                if _is_excluded_dir(child.name):
                    continue
                visit(child, rel)
            elif child.is_file():
                if _is_excluded_file(child.name):
                    continue
                files.append((rel, child))
            else:
                skipped.append(rel)
        if len(files) > before:
            dirs.append(prefix)

    visit(Path(base), top)
    return files, dirs, skipped


def collect_runtime_entries(root):
    """收集打包树；返回 (files, dirs, skipped)，files 按相对路径排序。"""
    root = Path(root).resolve()
    files = []
    dirs = []
    skipped = []

    skill_md = root / "SKILL.md"
    if skill_md.is_symlink():
        target = _resolved_inside(skill_md, root)
        if target is None or not target.is_file():
            raise PackageError(
                "SKILL.md 必须是根目录内的真实文件：{0}".format(skill_md))
        files.append(("SKILL.md", target))
    elif skill_md.is_file():
        files.append(("SKILL.md", skill_md))
    else:
        raise PackageError("根目录里没有 SKILL.md：{0}".format(root))

    for top in RUNTIME_DIRS:
        base = root / top
        if base.is_symlink():
            skipped.append(top)
            continue
        if not base.is_dir():
            continue
        top_files, top_dirs, top_skipped = _walk_runtime_dir(root, base, top)
        files.extend(top_files)
        dirs.extend(top_dirs)
        skipped.extend(top_skipped)

    files.sort(key=lambda item: item[0])
    dirs.sort()
    return files, dirs, skipped


# ---------------------------------------------------------------------------
# 打包
# ---------------------------------------------------------------------------


def _make_zip_info(name, mode):
    """构造元数据完全固定的 ZipInfo，保证跨运行逐字节一致。"""
    info = zipfile.ZipInfo(filename=name, date_time=ZIP_DATE_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = CREATE_SYSTEM
    info.create_version = 20
    info.extract_version = 20
    info.internal_attr = 0
    info.external_attr = (mode << 16) | (0x10 if name.endswith("/") else 0)
    return info


def _build_manifest(version, name, payloads, dir_count, payload, skipped):
    files = [
        {"path": rel, "bytes": len(data), "sha256": _sha256_hex(data)}
        for rel, data in payloads
    ]
    files.sort(key=lambda item: item["path"])
    return {
        "name": name,
        "version": version,
        "entry_count": len(files) + dir_count,
        "file_count": len(files),
        "dir_count": dir_count,
        "bytes": sum(item["bytes"] for item in files),
        "zip_bytes": len(payload),
        "sha256": _sha256_hex(payload),
        "files": files,
        "skipped": sorted(skipped),
    }


def build_archive(root):
    """在内存里建 zip；返回 (zip 字节, 清单 dict)。不落盘，便于测试与 --check。"""
    root = Path(root).resolve()
    files, dirs, skipped = collect_runtime_entries(root)
    meta = read_skill_metadata(root / "SKILL.md")

    payloads = []
    for rel, disk_path in files:
        try:
            payloads.append((rel, disk_path.read_bytes()))
        except OSError as exc:
            raise PackageError("读不出 {0}（{1}）：{2}".format(rel, disk_path, exc))
    payloads.sort(key=lambda item: item[0])
    data_by_name = dict(payloads)
    dir_set = set(dirs)

    buffer = io.BytesIO()
    with zipfile.ZipFile(
            buffer, "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=COMPRESS_LEVEL) as archive:
        for name in sorted(set(data_by_name) | dir_set):
            if name in dir_set:
                archive.writestr(
                    _make_zip_info(name + "/", DIR_MODE), b"",
                    compress_type=zipfile.ZIP_STORED)
            else:
                archive.writestr(
                    _make_zip_info(name, FILE_MODE), data_by_name[name],
                    compress_type=zipfile.ZIP_DEFLATED,
                    compresslevel=COMPRESS_LEVEL)
    payload = buffer.getvalue()
    manifest = _build_manifest(
        meta["version"], meta["name"], payloads, len(dir_set), payload, skipped)
    return payload, manifest


def _validate_output(root, output):
    """输出不能是目录，也不能落在会被打包的树里（否则会把自己装进去）。"""
    root = Path(root).resolve()
    output = Path(output).expanduser()
    try:
        out_abs = output.resolve()
    except (OSError, RuntimeError) as exc:
        raise PackageError("解析输出路径失败：{0}（{1}）".format(output, exc))
    if output.exists() and output.is_dir():
        raise PackageError("输出路径是个目录，不能当 zip：{0}".format(output))
    if out_abs == root:
        raise PackageError("输出路径不能是技能根目录：{0}".format(output))
    packed = [root / name for name in RUNTIME_FILES]
    packed.extend(root / name for name in RUNTIME_DIRS)
    for candidate in packed:
        candidate_abs = candidate.resolve()
        if out_abs == candidate_abs or _is_relative_to(out_abs, candidate_abs):
            raise PackageError(
                "输出路径不能落在被打包的技能树里：{0}".format(output))


def missing_requirements(manifest, required):
    """返回 required 里没进包的条目（顺序保持传入顺序）。"""
    present = {item["path"] for item in manifest["files"]}
    missing = []
    for name in required:
        normalized = name.replace("\\", "/").strip("/")
        if normalized not in present:
            missing.append(name)
    return missing


def package(root, output, required=()):
    """打包写到 output；缺 required 条目时先抛错、不落盘。返回清单 dict。"""
    root = Path(root).resolve()
    _validate_output(root, output)
    payload, manifest = build_archive(root)
    missing = missing_requirements(manifest, required)
    if missing:
        raise MissingRequirementsError(missing)
    output = Path(output).expanduser()
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(payload)
    except OSError as exc:
        raise PackageError("写不出 {0}：{1}".format(output, exc))
    return manifest


def check_reproducible(root, required=()):
    """在两个临时目录里各建一遍再比字节；不一致抛 PackageError。"""
    root = Path(root).resolve()
    with tempfile.TemporaryDirectory(prefix="cc-tackle-package-") as first_dir, \
            tempfile.TemporaryDirectory(prefix="cc-tackle-package-") as second_dir:
        first_path = Path(first_dir) / "first" / "skill.zip"
        second_path = Path(second_dir) / "second" / "skill.zip"
        manifest = package(root, first_path, required)
        second_manifest = package(root, second_path, required)
        first_bytes = first_path.read_bytes()
        second_bytes = second_path.read_bytes()
    if first_bytes != second_bytes or manifest["sha256"] != second_manifest["sha256"]:
        raise PackageError(
            "两次构建的 zip 不一致（{0} != {1}），打包不可复现".format(
                manifest["sha256"], second_manifest["sha256"]))
    return manifest


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _announce_skipped(manifest):
    skipped = manifest.get("skipped") or []
    if skipped:
        print("已跳过（软链/特殊项）：{0}".format(", ".join(skipped)),
              file=sys.stderr)


def _print_manifest(manifest):
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))


def _print_summary(manifest, output):
    version = manifest["version"] or "（SKILL.md 未声明 metadata.version）"
    print("打包完成：{0}".format(output))
    print("  名称：{0}".format(manifest["name"] or "（未声明 name）"))
    print("  版本：{0}".format(version))
    print("  条目：{0}（文件 {1}，目录 {2}）".format(
        manifest["entry_count"], manifest["file_count"], manifest["dir_count"]))
    print("  原始字节：{0}".format(manifest["bytes"]))
    print("  zip 字节：{0}".format(manifest["zip_bytes"]))
    print("  sha256：{0}".format(manifest["sha256"]))


def _print_check_summary(manifest):
    print("可复现：sha256={0}  条目={1}  字节={2}".format(
        manifest["sha256"], manifest["entry_count"], manifest["zip_bytes"]))


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="package_skill.py",
        description="把技能（SKILL.md + scripts/ + references/）打成可复现的 zip。")
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT,
        help="zip 输出路径（默认：{0}）".format(DEFAULT_OUTPUT))
    parser.add_argument(
        "--root", default=None,
        help="技能根目录（默认：本脚本所在目录的上一级）")
    parser.add_argument(
        "--json", action="store_true",
        help="把 manifest 以 JSON 打印到 stdout（仍按 --output 落盘）")
    parser.add_argument(
        "--check", action="store_true",
        help="在两个临时目录各建一遍，比对 sha256；不可复现则退出码 1")
    parser.add_argument(
        "--require", action="append", default=[],
        metavar="PATH", help="必须进包的相对路径，可重复；缺失则退出码 1")
    return parser


def main(argv=None):
    args = _build_parser().parse_args(argv)
    root = Path(args.root).expanduser() if args.root else DEFAULT_ROOT
    try:
        if args.check:
            manifest = check_reproducible(root, args.require)
            _announce_skipped(manifest)
            if args.json:
                manifest = dict(manifest)
                manifest["reproducible"] = True
                _print_manifest(manifest)
            else:
                _print_check_summary(manifest)
            return 0
        output = Path(args.output).expanduser()
        manifest = package(root, output, args.require)
        _announce_skipped(manifest)
        if args.json:
            _print_manifest(manifest)
        else:
            _print_summary(manifest, output)
        return 0
    except MissingRequirementsError as exc:
        print("打包校验失败：{0}".format(exc), file=sys.stderr)
        return 1
    except PackageError as exc:
        print("打包失败：{0}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
