#!/usr/bin/env python3
"""文档完整性：仓库地图与文档导航不许和实际文件脱节。

这一组用例守的是「README 说有什么，仓库里就真的有什么」：
文件清单、相对链接、锚点、SKILL.md 的体量上限，以及版本号在三处保持一致。

不联网、不读用户目录，只读仓库自己的文件。
"""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILL = ROOT / "SKILL.md"
README = ROOT / "README.md"

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
ANCHOR_RE = re.compile(r'<a id="([^"]+)"></a>')
HREF_RE = re.compile(r'href="#([^"]+)"')
VERSION_RE = re.compile(r'^\s+version:\s*"([^"]+)"\s*$', re.M)

# SKILL.md 只放判据与调用方式；细节放 references/。超过这个行数说明该拆了。
MAX_SKILL_LINES = 500

REQUIRED_DOCS = [
    "AGENTS.md",
    "CHANGELOG.md",
    "README.en.md",
    "README.md",
    "SKILL.md",
    "docs/decisions.md",
    "tests/README.md",
    "references/article-mapping.md",
    "references/maintenance-notes.md",
    "references/manual-checklist.md",
    "references/net-guard.md",
    "references/proxy-backends.md",
    "references/proxy-guard.md",
    "references/client-adapters.md",
    "references/report-page.md",
    "references/residential-lock.md",
    "references/residential-pitfalls.md",
    "references/scripts-index.md",
    "references/verification-status.md",
    "references/webrtc.md",
]


def read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def skill_version() -> str:
    m = VERSION_RE.search(read(SKILL))
    return m.group(1) if m else ""


class TestRepositoryMap(unittest.TestCase):
    def test_required_docs_exist(self):
        missing = [p for p in REQUIRED_DOCS if not (ROOT / p).is_file()]
        self.assertEqual([], missing, "缺少文档：" + "、".join(missing))

    def test_every_reference_is_linked_from_readme(self):
        """references/ 下每一份都要在 README 里出现，否则等于藏起来了。"""
        refs = sorted(p.name for p in (ROOT / "references").glob("*.md"))
        readme = read(README)
        missing = [n for n in refs if n not in readme]
        self.assertEqual([], missing, "README 没提到：" + "、".join(missing))

    def test_every_top_level_script_is_linked(self):
        scripts = sorted(p.name for p in (ROOT / "scripts").glob("*.py"))
        haystack = read(README) + read(SKILL)
        missing = [n for n in scripts if n not in haystack]
        self.assertEqual([], missing, "README/SKILL 没提到：" + "、".join(missing))

    def test_relative_links_resolve(self):
        """README/SKILL/英文 README 里的相对链接必须指向真实文件（外链与锚点不算）。"""
        for doc in (README, ROOT / "README.en.md", SKILL):
            text = read(doc)
            broken = []
            for target in LINK_RE.findall(text):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                path = target.split("#", 1)[0]
                if not path:
                    continue
                if not (doc.parent / path).exists():
                    broken.append(target)
            self.assertEqual([], broken, f"{doc.name} 有断链：" + "、".join(broken))

    def test_readme_anchors_exist(self):
        """目录里的 #锚点 必须有对应的 <a id="...">，否则点不动。"""
        for doc in (README, ROOT / "README.en.md"):
            text = read(doc)
            ids = set(ANCHOR_RE.findall(text))
            missing = sorted({a for a in HREF_RE.findall(text) if a not in ids})
            self.assertEqual([], missing, f"{doc.name} 缺锚点：" + "、".join(missing))

    def test_english_readme_tracks_chinese_structure(self):
        """中英文两份 README 的二级标题数量要一致，别一边加了节另一边没跟。"""
        zh = [l for l in read(README).splitlines() if l.startswith("## ")]
        en = [l for l in read(ROOT / "README.en.md").splitlines() if l.startswith("## ")]
        self.assertEqual(len(zh), len(en), f"中文 {len(zh)} 节，英文 {len(en)} 节")


class TestSkillSize(unittest.TestCase):
    def test_skill_md_stays_small_enough_to_load(self):
        lines = read(SKILL).splitlines()
        self.assertLessEqual(
            len(lines), MAX_SKILL_LINES,
            f"SKILL.md 有 {len(lines)} 行，超过 {MAX_SKILL_LINES} 行上限；"
            "把细节移到 references/，只留下判据与调用方式",
        )

    def test_frontmatter_name_matches_directory(self):
        text = read(SKILL)
        m = re.search(r"^name:\s*(\S+)\s*$", text, re.M)
        self.assertIsNotNone(m, "SKILL.md 缺少 frontmatter name")
        self.assertEqual(m.group(1), ROOT.name)


class TestVersionConsistency(unittest.TestCase):
    def test_changelog_documents_current_version(self):
        version = skill_version()
        self.assertRegex(version, r"^\d+\.\d+\.\d+$", "SKILL.md 缺少 metadata.version")
        changelog = read(ROOT / "CHANGELOG.md")
        self.assertIn(
            f"[{version}]", changelog,
            f"CHANGELOG.md 里没有 {version} 的条目，版本号三处要保持一致",
        )

    def test_readme_badge_matches_version(self):
        version = skill_version()
        self.assertIn(
            f"version-{version}-", read(README),
            "README 的版本徽章与 SKILL.md 的 version 不一致",
        )


if __name__ == "__main__":
    unittest.main()
