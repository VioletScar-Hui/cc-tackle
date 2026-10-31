#!/usr/bin/env python3
"""Claude 出口体检：规则找得对、单点组能报出来、各家片段写得对。

2026-10-30 的故障是「Claude 组只有一条线路，线路挂了但其它网站正常」，
这里把那一次的症状固化成用例，防止以后改回去。
"""

from __future__ import annotations

import json
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))

import client_adapters as ca  # noqa: E402
import proxy_guard as pg  # noqa: E402


def rule(typ, payload, proxy):
    return {"type": typ, "payload": payload, "proxy": proxy}


def node(alive=True, delay=100):
    return {"alive": alive, "history": [{"delay": delay}] if delay is not None else []}


class TestAdapters(unittest.TestCase):
    def test_mihomo_has_group_rules_and_multiple_nodes(self):
        text = ca.emit("mihomo", policy="Claude", nodes=("line1", "line2"))
        self.assertIn("name: Claude", text)
        self.assertIn("- line1", text)
        self.assertIn("- line2", text)
        for domain in ("claude.ai", "claude.com", "anthropic.com"):
            self.assertIn(f"DOMAIN-SUFFIX,{domain},Claude", text)

    def test_sing_box_is_valid_json(self):
        doc = json.loads(ca.emit("sing-box"))
        self.assertEqual(doc["outbounds"][0]["type"], "selector")
        self.assertEqual(doc["route"]["rules"][0]["outbound"],
                         doc["outbounds"][0]["tag"])

    def test_surge_and_shadowrocket_have_rules(self):
        for client in ("surge", "shadowrocket"):
            text = ca.emit(client)
            self.assertIn("DOMAIN-SUFFIX,claude.ai", text)
            self.assertIn("FINAL,DIRECT", text)

    def test_unknown_client_raises(self):
        with self.assertRaises(KeyError):
            ca.emit("not-a-client")

    def test_notes_explain_where_to_paste(self):
        for client in ("clash-verge", "flclash", "sing-box", "surge", "shadowrocket"):
            self.assertTrue(ca.notes(client), client)


class TestDiagnose(unittest.TestCase):
    def test_healthy_group(self):
        proxies = {"Claude": {"type": "Selector", "now": "line1", "all": ["line1", "line2"]},
                   "line1": node(), "line2": node()}
        rules = [rule("DomainSuffix", "claude.ai", "Claude")]
        diag = pg.diagnose(proxies, rules)
        self.assertEqual(diag["target"], "Claude")
        self.assertEqual(diag["problems"], [])
        self.assertFalse(diag["fixable_by_selection"])

    def test_single_member_group_is_flagged(self):
        # 2026-10-30 的现场：组里只有一条线路，而且它已经挂了
        proxies = {"Claude": {"type": "Selector", "now": "line1", "all": ["line1"]},
                   "line1": node(alive=False, delay=0)}
        rules = [rule("DomainSuffix", "claude.ai", "Claude")]
        diag = pg.diagnose(proxies, rules)
        self.assertTrue(any("只有 1 个成员" in p for p in diag["problems"]))
        self.assertTrue(any("没有任何可用节点" in p for p in diag["problems"]))

    def test_dead_selection_but_alive_siblings_is_fixable(self):
        proxies = {"Claude": {"type": "Selector", "now": "line1", "all": ["line1", "line4"]},
                   "line1": node(alive=False, delay=0), "line4": node()}
        diag = pg.diagnose(proxies, [rule("DomainSuffix", "claude.ai", "Claude")])
        self.assertTrue(diag["fixable_by_selection"])
        self.assertEqual(diag["alive"], ["line4"])

    def test_no_rule_is_reported(self):
        diag = pg.diagnose({}, [rule("DomainSuffix", "google.com", "Proxy")])
        self.assertTrue(any("没有找到 Claude" in p for p in diag["problems"]))

    def test_target_missing_from_config(self):
        diag = pg.diagnose({}, [rule("DomainSuffix", "claude.ai", "Claude")])
        self.assertTrue(any("没有这个名字" in p for p in diag["problems"]))


class TestGroupEditing(unittest.TestCase):
    YAML_2 = [
        "proxy-groups:",
        "- name: Claude",
        "  type: select",
        "  proxies:",
        "  - line1",
        "  - line2",
        "- name: Other",
        "  type: select",
        "  proxies:",
        "  - line9",
    ]

    YAML_6 = [
        "prepend:",
        "  - name: Claude",
        "    type: select",
        "    proxies:",
        "      - line1",
        "",
        "append: []",
    ]

    def test_group_bounds_and_members(self):
        self.assertEqual(pg.group_members(self.YAML_2, "Claude"), ["line1", "line2"])
        self.assertEqual(pg.group_members(self.YAML_6, "Claude"), ["line1"])

    def test_insert_missing_members_keeps_indent(self):
        out = pg.insert_members(list(self.YAML_6), "Claude", ["line1", "line2", "line3"])
        text = "\n".join(out)
        self.assertIn("      - line2", text)
        self.assertIn("      - line3", text)
        self.assertEqual(text.count("- line1"), 1, "已有的不能重复插")

    def test_insert_is_idempotent(self):
        once = pg.insert_members(list(self.YAML_2), "Claude", ["line2", "line3"])
        twice = pg.insert_members(list(once), "Claude", ["line2", "line3"])
        self.assertEqual(once, twice)

    def test_unknown_group_is_untouched(self):
        self.assertEqual(pg.insert_members(list(self.YAML_2), "Nope", ["x"]),
                         self.YAML_2)


class TestCommands(unittest.TestCase):
    def test_clients_lists_surge_and_shadowrocket_notes(self):
        with mock.patch.object(pg, "detect_clients",
                               return_value={"shadowrocket": {"installed": False,
                                                              "note": "iOS"}}), \
             mock.patch("builtins.print"):
            self.assertEqual(pg.main(["--clients"]), 0)

    def test_emit_unknown_client(self):
        with mock.patch("builtins.print"):
            self.assertEqual(pg.main(["--emit", "nope"]), 2)

    def test_fix_members_requires_two_nodes(self):
        with mock.patch("builtins.print"):
            self.assertEqual(pg.main(["--fix-members", "--nodes", "only-one"]), 2)

    def test_fix_members_refuses_non_verge(self):
        with mock.patch.object(pg, "VERGE_DIR", pathlib.Path("/nonexistent")), \
             mock.patch("builtins.print"):
            self.assertEqual(pg.main(["--fix-members", "--nodes", "a,b"]), 2)


if __name__ == "__main__":
    unittest.main()
