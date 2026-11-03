#!/usr/bin/env python3
"""公开仓库的隐私红线：不许写进本机标识与真实凭据。

用户要求（2026-11-03）：不要泄露本地的信息在 GitHub 中。这条用例扫仓库里的文本文件，
出现下面这些形状就失败：

  * `/Users/<真实用户名>/` 这种绝对家目录（占位 `x` / `someone` / `someoneelse` 除外）；
  * 真实 Tailscale tailnet 名（`tail` + 6 位以上十六进制 + `.ts.net`；占位
    `tail-example.ts.net` 不算）；
  * Tailscale 的 `100.64.0.0/10` 地址——只允许 `100.64.0.0/24` 示例段与 MagicDNS 的
    `100.100.100.100`；
  * 本机内网网段 `192.168.31.x`；
  * 真实长期 token 的形状（`sk-ant-oat0` 后面跟足够长的十六进制）。

示例一律用文档保留地址：`198.51.100.x`、`203.0.113.x`、`100.64.0.x`，主机名用
`node-a` / `<tailnet>` 这类占位。
"""

from __future__ import annotations

import ipaddress
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "__pycache__", "dist", "docs"}     # docs 里只有图片
TEXT_SUFFIXES = {".md", ".py", ".yml", ".yaml", ".json", ".txt", ".js", ".cjs",
                 ".toml", ".sh"}

PATTERNS = (
    (re.compile(r"/Users/(?!x/|someone/|someoneelse/|example/)[A-Za-z0-9._-]+/"), "绝对家目录"),
    (re.compile(r"\btail[0-9a-f]{6,}\.ts\.net\b"), "真实 tailnet 名"),
    (re.compile(r"\b192\.168\.31\.\d{1,3}\b"), "本机内网网段"),
    (re.compile(r"\bsk-ant-oat0[0-9a-f]{8,}"), "真实 token 形状"),
)
CGNAT = re.compile(r"\b100\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
TS_NET = ipaddress.ip_network("100.64.0.0/10")
EXAMPLE_NET = ipaddress.ip_network("100.64.0.0/24")
MAGIC_DNS = "100.100.100.100"


class TestNoLocalIdentifiers(unittest.TestCase):
    def _files(self):
        for path in ROOT.rglob("*"):
            if not path.is_file() or (set(path.parts) & SKIP_DIRS):
                continue
            if path.suffix.lower() in TEXT_SUFFIXES:
                yield path

    def test_text_files_have_no_local_identifiers(self):
        problems: list[str] = []
        for path in self._files():
            rel = path.relative_to(ROOT)
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for pattern, label in PATTERNS:
                for match in pattern.finditer(text):
                    problems.append(f"{rel}: {label}：{match.group(0)}")
            for match in CGNAT.finditer(text):
                ip = ipaddress.ip_address(match.group(0))
                if ip not in TS_NET:
                    continue
                if ip in EXAMPLE_NET or str(ip) == MAGIC_DNS:
                    continue
                problems.append(f"{rel}: Tailscale 地址不是占位：{match.group(0)}")
        self.assertEqual([], problems,
                         "发现本机标识，换成文档保留地址/占位再提交：\n" + "\n".join(problems[:20]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
