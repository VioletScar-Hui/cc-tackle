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


class TestSubscriptionSync(unittest.TestCase):
    """Claude 组要放订阅里的全部线路，而不是只放一条。

    2026-10-30 的修法先是手工往组里补了四条名字；这里把「从当前订阅同步」这件事
    固化下来：读订阅 profile 的 proxies 列表，只改当前订阅的组增强文件与运行时配置，
    别把别的订阅的模板一起改坏。
    """

    PROFILES = (
        "# Profiles Config for Clash Verge\n"
        "current: act1\n"
        "items:\n"
        "- uid: Merge\n"
        "  type: merge\n"
        "  file: Merge.yaml\n"
        "- uid: act1\n"
        "  type: remote\n"
        "  name: 住宅订阅\n"
        "  file: act1.yaml\n"
        "  selected:\n"
        "- name: Claude\n"
        "  now: line1\n"
        "  option:\n"
        "    groups: grp1\n"
        "- uid: grp1\n"
        "  type: groups\n"
        "  file: grp1.yaml\n"
        "- uid: old1\n"
        "  type: remote\n"
        "  file: old1.yaml\n"
        "  option:\n"
        "    groups: oldgrp\n"
        "- uid: oldgrp\n"
        "  type: groups\n"
        "  file: oldgrp.yaml\n"
    )

    PROFILE = (
        "mixed-port: 7890\n"
        "proxies:\n"
        '  - name: "line1"\n'
        "    type: vless\n"
        "    server: 1.1.1.1\n"
        "  - name: line2\n"
        "    type: vless\n"
        "    server: 2.2.2.2\n"
        "  - {name: line3, type: vless, server: 3.3.3.3}\n"
        "proxy-groups:\n"
        "- name: IpEqual\n"
        "  type: select\n"
        "  proxies:\n"
        "  - line1\n"
        "  - DIRECT\n"
    )

    RUNTIME = [
        "proxy-groups:",
        "- name: Claude",
        "  type: select",
        "  proxies:",
        "  - line1",
        "- name: IpEqual",
        "  type: select",
        "  proxies:",
        "  - line1",
    ]

    GROUPS = [
        "prepend:",
        "  - name: Claude",
        "    type: select",
        "    proxies:",
        "      - line1",
        "",
        "append: []",
    ]

    OLD_GROUPS = [
        "prepend:",
        "  - name: Claude",
        "    type: select",
        "    proxies:",
        "      - old-line",
        "",
        "append: []",
    ]

    def make_verge(self):
        """造一个最小的 Verge 目录：profiles.yaml + 当前订阅 + 两份组文件 + 运行时。"""
        import shutil
        import tempfile
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="proxy-guard-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "profiles").mkdir()
        (tmp / "profiles.yaml").write_text(self.PROFILES, encoding="utf-8")
        (tmp / "profiles" / "act1.yaml").write_text(self.PROFILE, encoding="utf-8")
        (tmp / "profiles" / "grp1.yaml").write_text("\n".join(self.GROUPS) + "\n", encoding="utf-8")
        (tmp / "profiles" / "oldgrp.yaml").write_text(
            "\n".join(self.OLD_GROUPS) + "\n", encoding="utf-8")
        (tmp / "profiles" / "Merge.yaml").write_text("prepend: []\n", encoding="utf-8")
        (tmp / "clash-verge.yaml").write_text(
            "\n".join(self.RUNTIME) + "\n", encoding="utf-8")
        return tmp

    def test_parse_profiles_reads_current_and_enhancement(self):
        doc = pg.parse_profiles(self.PROFILES)
        self.assertEqual(doc["current"], "act1")
        item = doc["items"]["act1"]
        self.assertEqual(item["file"], "act1.yaml")
        self.assertEqual(item["groups"], "grp1")
        self.assertEqual(item["name"], "住宅订阅")

    def test_subscription_nodes_keeps_order_and_skips_groups(self):
        self.assertEqual(pg.subscription_nodes(self.PROFILE), ["line1", "line2", "line3"])

    def test_subscription_nodes_flow_style(self):
        text = "proxies: [{name: a, type: ss}, {name: 'b', type: ss}]\n"
        self.assertEqual(pg.subscription_nodes(text), ["a", "b"])

    def test_subscription_nodes_missing_block_is_empty(self):
        self.assertEqual(pg.subscription_nodes("mode: rule\n"), [])

    def test_verge_profile_maps_the_enhancement_file(self):
        tmp = self.make_verge()
        with mock.patch.object(pg, "VERGE_DIR", tmp):
            profile = pg.verge_profile()
            self.assertEqual(profile["uid"], "act1")
            self.assertEqual(profile["groups_file"], tmp / "profiles" / "grp1.yaml")
            self.assertEqual(pg.subscription_nodes_from_verge(),
                             ["line1", "line2", "line3"])

    def test_sync_targets_only_touches_the_active_subscription(self):
        tmp = self.make_verge()
        with mock.patch.object(pg, "VERGE_DIR", tmp):
            targets, skipped = pg.sync_targets("Claude")
        self.assertEqual(targets, [tmp / "clash-verge.yaml", tmp / "profiles" / "grp1.yaml"])
        self.assertEqual(skipped, [tmp / "profiles" / "oldgrp.yaml"])

    def test_fix_members_all_writes_active_files_only(self):
        tmp = self.make_verge()
        old_before = (tmp / "profiles" / "oldgrp.yaml").read_text(encoding="utf-8")
        with mock.patch.object(pg, "VERGE_DIR", tmp), \
             mock.patch.object(pg, "find_socket", return_value=None), \
             mock.patch("builtins.print"):
            self.assertEqual(pg.fix_members(["line1", "line2", "line3"], hot_reload=False), 0)
        runtime = (tmp / "clash-verge.yaml").read_text(encoding="utf-8")
        groups = (tmp / "profiles" / "grp1.yaml").read_text(encoding="utf-8")
        for text in (runtime, groups):
            self.assertIn("- line2", text)
            self.assertIn("- line3", text)
        self.assertEqual((tmp / "profiles" / "oldgrp.yaml").read_text(encoding="utf-8"),
                         old_before, "别的订阅的模板不能被写")
        self.assertTrue((tmp / "profiles" / "grp1.yaml.bak-20261102").exists())
        self.assertTrue((tmp / "clash-verge.yaml.bak-20261102").exists())

    def test_fix_members_dry_run_writes_nothing(self):
        tmp = self.make_verge()
        runtime_before = (tmp / "clash-verge.yaml").read_text(encoding="utf-8")
        with mock.patch.object(pg, "VERGE_DIR", tmp), mock.patch("builtins.print"):
            self.assertEqual(pg.fix_members(["line1", "line2"], dry_run=True), 0)
        self.assertEqual((tmp / "clash-verge.yaml").read_text(encoding="utf-8"),
                         runtime_before)
        self.assertFalse(list(tmp.glob("*.bak-*")))

    def test_fix_members_all_without_verge_is_an_error(self):
        with mock.patch.object(pg, "VERGE_DIR", pathlib.Path("/nonexistent")), \
             mock.patch("builtins.print"):
            self.assertEqual(pg.main(["--fix-members", "--all"]), 2)

    def test_all_and_nodes_are_mutually_exclusive(self):
        with mock.patch("builtins.print"):
            self.assertEqual(pg.main(["--fix-members", "--all", "--nodes", "a,b"]), 2)

    def test_main_syncs_all_subscription_lines(self):
        tmp = self.make_verge()
        with mock.patch.object(pg, "VERGE_DIR", tmp), \
             mock.patch.object(pg, "find_socket", return_value=None), \
             mock.patch("builtins.print"):
            self.assertEqual(pg.main(["--fix-members", "--all", "--no-reload"]), 0)
        runtime = (tmp / "clash-verge.yaml").read_text(encoding="utf-8")
        self.assertIn("- line2", runtime)
        self.assertIn("- line3", runtime)


class TestDiagnoseSubscription(unittest.TestCase):
    def _proxies(self, members):
        out = {"Claude": {"type": "Selector", "now": members[0], "all": list(members)}}
        for m in members:
            out[m] = node()
        return out

    def test_missing_subscription_lines_are_reported(self):
        diag = pg.diagnose(self._proxies(["line1"]),
                           [rule("DomainSuffix", "claude.ai", "Claude")],
                           subscription=["line1", "line2", "line3"])
        self.assertTrue(diag["fixable_by_sync"])
        self.assertIn("缺 2 条", " ".join(diag["problems"]))
        self.assertEqual(diag["subscription"]["missing"], ["line2", "line3"])

    def test_synced_group_has_no_sync_problem(self):
        diag = pg.diagnose(self._proxies(["line1", "line2"]),
                           [rule("DomainSuffix", "claude.ai", "Claude")],
                           subscription=["line1", "line2"])
        self.assertFalse(diag["fixable_by_sync"])
        self.assertEqual(diag["subscription"]["missing"], [])

    def test_stale_names_from_an_old_subscription_are_reported(self):
        diag = pg.diagnose(self._proxies(["old-line1", "line1"]),
                           [rule("DomainSuffix", "claude.ai", "Claude")],
                           subscription=["line1", "line2"])
        joined = " ".join(diag["problems"])
        self.assertIn("不在当前订阅里", joined)
        self.assertEqual(diag["subscription"]["extra"], ["old-line1"])


if __name__ == "__main__":
    unittest.main()
