#!/usr/bin/env python3
"""Claude 出口体检 + 修复：规则指向谁、这个组的节点还活着吗、组里是不是只有一条线路。

2026-10-30 踩过的坑：Claude 组里只有一个「连接线路1」，线路挂掉后 claude.ai 的 TLS
握到手一半就断，其它网站全部正常（它们走的是另一个组）。这种「单点组」在
Clash Verge Rev、FlClash、Mihomo Party 上都可能出现——订阅换了节点名，组里的
旧名字失效，最后只剩一条或全挂。

2026-11-02 补的口径：Claude 组不该只放一条，而应该是**订阅里的全部线路**。
修法是 `--fix-members --all`：从当前订阅的 profile 读出所有节点名，同步进组里；
订阅换了线路再跑一次即可。`--check` 会比对「订阅有几条、组里有几条、缺哪几条」。

它做四件事：
  1. --check        读 mihomo API，指出 Claude 规则的目标组、成员数、选中节点是否可用，
                    并比对订阅线路是否都已经在组里
  2. --fix          在组内切到一个活着的成员（不动配置，只改选择）
  3. --emit <client> 生成 mihomo / sing-box / Surge / Shadowrocket 的组+规则片段
  4. --fix-members  给组里补线路：`--nodes` 手工列名字，`--all` 同步当前订阅的全部线路
                    （Clash Verge Rev：改该订阅的组增强文件 + 运行时配置，然后热载）

没有 mihomo 内核的客户端（Surge、Shadowrocket）只做适配片段，不探测。
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import client_adapters as adapters  # noqa: E402

VERGE_DIR = pathlib.Path.home() / "Library/Application Support" / "io.github.clash-verge-rev.clash-verge-rev"
FLCLASH_DIR = pathlib.Path.home() / "Library/Application Support" / "FlClash"
PARTY_DIR = pathlib.Path.home() / "Library" / "Application Support" / "mihomo-party"
SOCK_CANDIDATES = [
    f"/var/run/clash-verge-service/users/{__import__('os').getuid()}/verge-mihomo.sock",
    "/tmp/verge/verge-mihomo.sock",
    "/tmp/mihomo-party.sock",
]
CLAUDE_HINTS = ("claude", "anthropic")


def run(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        return 1, f"{type(error).__name__}: {error}"
    return proc.returncode, (proc.stdout or b"").decode("utf-8", "replace") + \
        (proc.stderr or b"").decode("utf-8", "replace")


def find_socket() -> str | None:
    for path in SOCK_CANDIDATES:
        if not pathlib.Path(path).exists():
            continue
        code, _ = run(["curl", "-s", "--max-time", "3", "--unix-socket", path,
                       "http://localhost/version"])
        if code == 0:
            return path
    return None


def api(sock: str, path: str, method: str = "GET", body: dict | None = None) -> dict | None:
    cmd = ["curl", "-s", "--max-time", "8", "--unix-socket", sock, "-X", method,
           f"http://localhost{path}"]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(body, ensure_ascii=False)]
    code, out = run(cmd)
    if code != 0:
        return None
    try:
        return json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        return None


def detect_clients() -> dict[str, dict]:
    """能探测的写状态，探测不到的写「不可探测」——别假装知道。"""
    out: dict[str, dict] = {}
    if VERGE_DIR.exists() or pathlib.Path("/Applications/Clash Verge.app").exists():
        out["clash-verge"] = {"installed": True, "note": "Clash Verge Rev（mihomo 内核）"}
    if FLCLASH_DIR.exists() or pathlib.Path("/Applications/FlClash.app").exists():
        out["flclash"] = {"installed": True, "note": "FlClash（mihomo 内核）"}
    if PARTY_DIR.exists() or pathlib.Path("/Applications/Mihomo Party.app").exists():
        out["mihomo-party"] = {"installed": True, "note": "Mihomo Party（mihomo 内核）"}
    sock = find_socket()
    if sock:
        out["mihomo"] = {"installed": True, "note": f"内核在跑，控制 socket：{sock}"}
    if pathlib.Path("/Applications/Surge.app").exists():
        out["surge"] = {"installed": True, "note": "Surge（不提供本地 API，只能给配置片段）"}
    if shutil.which("sing-box") or pathlib.Path("/Applications/sing-box.app").exists() \
            or (pathlib.Path.home() / ".config" / "sing-box").exists():
        out["sing-box"] = {"installed": True, "note": "sing-box（配置片段，不探测）"}
    out["shadowrocket"] = {"installed": False, "note": "iOS 客户端，Mac 上探测不到，只给片段"}
    return out


# ── 订阅线路：Claude 组要放订阅里的全部线路，而不是一条 ────────────

GROUP_TYPES = frozenset({"Selector", "Fallback", "URLTest", "LoadBalance",
                         "Relay", "Compatible", "Direct"})
NON_NODES = frozenset({"DIRECT", "REJECT", "REJECT-DROP", "PASS", "GLOBAL"})


def parse_profiles(text: str) -> dict:
    """从 `profiles.yaml` 文本里读出 current 与每个 profile 的 uid/file/groups。

    只解析我们真的用到的键（不引 YAML 依赖，核心脚本保持标准库）。列表项以
    `- uid:` 开头；其它顶层 `- ` 行（比如 selected 里的 `- name:`）属于当前项，
    不能当成新项——第一版就是在这里把 option 块截断、读不到增强组文件的。
    """
    doc: dict = {"current": None, "items": {}}
    cur: dict | None = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        stripped = line.strip()
        if not line[0].isspace():
            if stripped.startswith("- uid:"):
                uid = stripped.split(":", 1)[1].strip()
                cur = {"uid": uid}
                doc["items"][uid] = cur
            elif stripped.startswith("current:"):
                doc["current"] = stripped.split(":", 1)[1].strip() or None
            elif stripped in ("items:",) or stripped.startswith("items:"):
                cur = None
            # 其它顶层键（selected 等）属于当前项，不动 cur
            continue
        if cur is None:
            continue
        for key in ("groups", "file", "type", "name"):
            if stripped.startswith(key + ":"):
                cur[key] = stripped.split(":", 1)[1].strip() or None
                break
    return doc


def verge_profile() -> dict:
    """当前订阅的 uid/file/名称，以及它的组增强文件（option.groups 指向的那份）。"""
    path = VERGE_DIR / "profiles.yaml"
    if not path.exists():
        return {}
    doc = parse_profiles(path.read_text(encoding="utf-8", errors="replace"))
    uid = doc.get("current")
    item = doc.get("items", {}).get(uid) or {}
    groups_uid = item.get("groups")
    groups_item = doc.get("items", {}).get(groups_uid) or {}
    profiles_dir = VERGE_DIR / "profiles"

    def _p(name):
        return (profiles_dir / name) if name else None

    return {
        "uid": uid,
        "name": item.get("name"),
        "type": item.get("type"),
        "file": item.get("file"),
        "profile_path": _p(item.get("file")),
        "groups_uid": groups_uid,
        "groups_file": _p(groups_item.get("file")),
    }


def _yaml_name_value(raw: str) -> str:
    """从 `name: xxx` 或 `{name: xxx, type: ss}` 里取出节点名。"""
    value = raw.strip()
    if value.startswith(("'", '"')):
        quote = value[0]
        end = value.find(quote, 1)
        return value[1:end] if end > 0 else value[1:]
    # flow style：`name: xxx, type: ss`
    return value.split(",", 1)[0].split("}", 1)[0].strip()


def subscription_nodes(text: str) -> list[str]:
    """从订阅的 profile 文本里按顺序读出 `proxies:` 下的全部节点名。

    只认 top-level `proxies:` 块；块结束于下一个 top-level 键。组名（proxy-groups
    里的）不会混进来，`DIRECT`/`REJECT` 也不会——它们不是线路。
    """
    lines = text.splitlines()
    names: list[str] = []
    in_block = False
    for line in lines:
        if not in_block:
            if re.match(r"^proxies:\s*$", line):
                in_block = True
            elif re.match(r"^proxies:\s*\[", line):
                # flow style 的整块列表：`proxies: [{name: a, ...}, {name: b, ...}]`
                for match in re.findall(r"name:\s*(['\"]?)([^'\",}\]]+)\1", line):
                    _add_node(names, match[1].strip())
                return names
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indent == 0 and not stripped.startswith("-"):
            break  # 下一个 top-level 键，proxies 块结束
        match = re.match(r"^-\s*(?:\{\s*)?name:\s*(.+)$", stripped)
        if match:
            _add_node(names, _yaml_name_value(match.group(1)))
    return names


def _add_node(names: list[str], name: str) -> None:
    name = (name or "").strip()
    if not name or name in names:
        return
    if name.upper() in NON_NODES:
        return
    names.append(name)


def subscription_nodes_from_verge() -> list[str]:
    """当前订阅的全部线路名；读不到订阅文件时返回空列表（不猜）。"""
    profile = verge_profile()
    path = profile.get("profile_path")
    if not path or not path.exists():
        return []
    return subscription_nodes(path.read_text(encoding="utf-8", errors="replace"))


def nodes_from_api(proxies: dict) -> list[str]:
    """兜底：从运行中的 mihomo `/proxies` 里取节点名（排除组与 DIRECT/REJECT）。"""
    names = []
    for name, info in proxies.items():
        if (info or {}).get("type") in GROUP_TYPES:
            continue
        _add_node(names, name)
    return names


# ── 诊断 ──────────────────────────────────────────────────────────

def find_claude_target(rules: list[dict]) -> dict | None:
    """规则里第一条覆盖 Claude 域名的，返回 {type,payload,proxy}。"""
    for rule in rules:
        payload = str(rule.get("payload") or "").lower()
        typ = str(rule.get("type") or "")
        if typ.startswith("Domain") and any(h in payload for h in CLAUDE_HINTS):
            return rule
        if typ == "IPCIDR" and payload.startswith("160.79.104."):
            return rule
    return None


def diagnose(proxies: dict, rules: list[dict],
             subscription: list[str] | None = None) -> dict:
    """纯函数：给 /proxies + /rules 的返回，判断 Claude 出口健不健康。

    `subscription` 是当前订阅的全部线路名。给了就顺带比对组里缺哪几条——Claude
    组应当覆盖订阅里的全部线路，而不是只放一条。
    """
    out: dict = {"target": None, "group": None, "members": [], "now": None,
                 "problems": [], "fixable_by_selection": False, "fixable_by_sync": False}
    rule = find_claude_target(rules)
    if not rule:
        out["problems"].append("没有找到 Claude 域名规则：这些流量会走 MATCH 兜底")
        return out
    target = rule.get("proxy")
    out["target"] = target
    info = proxies.get(target)
    if not info:
        out["problems"].append(f"规则指向「{target}」，但当前配置里没有这个名字")
        return out
    out["group"] = target
    out["now"] = info.get("now")
    members = list(info.get("all") or [])
    out["members"] = members
    if len(members) <= 1:
        out["problems"].append(
            f"「{target}」组里只有 {len(members)} 个成员：节点一挂 Claude 就整体不可用"
            "（其它网站仍正常，很难第一时间想到是这里）")
    alive = []
    for name in members:
        node = proxies.get(name) or {}
        history = node.get("history") or []
        delay = history[-1].get("delay") if history else None
        if node.get("alive") and (delay is None or delay > 0):
            alive.append(name)
    out["alive"] = alive
    if out["now"] and alive and out["now"] not in alive:
        out["problems"].append(f"当前选中的「{out['now']}」不可用，但组内还有 {len(alive)} 个可用成员")
        out["fixable_by_selection"] = True
    if not alive:
        out["problems"].append("组内没有任何可用节点：先检查订阅/住宅线路本身")
    if subscription is not None:
        missing = [n for n in subscription if n not in members]
        extra = [n for n in members if n not in subscription]
        out["subscription"] = {"nodes": list(subscription),
                               "missing": missing, "extra": extra}
        if missing:
            shown = "、".join(missing[:6]) + ("…" if len(missing) > 6 else "")
            out["problems"].append(
                f"订阅里有 {len(subscription)} 条线路，组里只有 {len(members)} 条；"
                f"缺 {len(missing)} 条（{shown}）——用 --fix-members --all 同步")
            out["fixable_by_sync"] = True
        if extra:
            shown = "、".join(extra[:6]) + ("…" if len(extra) > 6 else "")
            out["problems"].append(
                f"组里有 {len(extra)} 个名字不在当前订阅里（{shown}），"
                "可能是换订阅后的旧名字；选中它们会连不上")
    return out


def check(sock: str | None, verbose: bool = True,
          subscription: list[str] | None = None) -> tuple[int, dict]:
    proxies_doc = api(sock, "/proxies") if sock else None
    rules_doc = api(sock, "/rules") if sock else None
    if not proxies_doc or not rules_doc:
        print("没有可用的 mihomo 控制接口：只能给配置片段（--emit），没法探测。",
              file=sys.stderr)
        return 2, {}
    diag = diagnose(proxies_doc.get("proxies") or {}, rules_doc.get("rules") or [],
                    subscription=subscription)
    if verbose:
        print(f"Claude 规则目标：{diag.get('target')}")
        profile = verge_profile()
        if subscription:
            source = profile.get("name") or profile.get("uid") or "当前订阅"
            print(f"订阅线路：{source} 共 {len(subscription)} 条"
                  f"（{profile.get('type') or '未知类型'}）")
        elif profile:
            print("订阅线路：读不到当前订阅的节点列表（只能查组内成员）")
        if diag.get("group"):
            print(f"组内成员：{len(diag['members'])} 个；当前选中：{diag['now']}")
            for name in diag["members"]:
                mark = "✓" if name in diag.get("alive", []) else "✗"
                print(f"  {mark} {name}")
        if diag["problems"]:
            print("\n问题：")
            for problem in diag["problems"]:
                print(f"  - {problem}")
        else:
            print("\nClaude 出口正常")
    return (1 if diag["problems"] else 0), diag


def fix_selection(sock: str, diag: dict) -> int:
    group = diag.get("group")
    candidates = [n for n in diag.get("alive") or [] if n != diag.get("now")]
    if not group or not candidates:
        print("没有可切换的存活成员，改不了选择。", file=sys.stderr)
        return 1
    name = candidates[0]
    code, out = run(["curl", "-s", "--max-time", "8", "--unix-socket", sock, "-X", "PUT",
                     "-H", "Content-Type: application/json",
                     "-d", json.dumps({"name": name}, ensure_ascii=False),
                     f"http://localhost/proxies/{group}"])
    if code != 0:
        print(f"切换失败：{out}", file=sys.stderr)
        return 1
    print(f"已把「{group}」切到「{name}」")
    return 0


# ── 补成员（Clash Verge Rev：改 profile 组文件 + 运行时热载）────────

def group_block_bounds(lines: list[str], group: str) -> tuple[int, int] | None:
    """在 YAML 文本里找 `- name: <group>` 到下一个同级 `- name:` 的行号。"""
    start = None
    indent = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == f"- name: {group}":
            start = i
            indent = len(line) - len(line.lstrip())
            break
    if start is None:
        return None
    for j in range(start + 1, len(lines)):
        cur = lines[j]
        if not cur.strip():
            continue
        cur_indent = len(cur) - len(cur.lstrip())
        if cur_indent == indent and cur.lstrip().startswith("- name:"):
            return start, j
    return start, len(lines)


def group_members(lines: list[str], group: str) -> list[str]:
    bounds = group_block_bounds(lines, group)
    if not bounds:
        return []
    start, end = bounds
    members, collect = [], False
    for line in lines[start:end]:
        stripped = line.strip()
        if stripped.startswith("proxies:"):
            collect = True
            continue
        if collect and stripped.startswith("- "):
            members.append(stripped[2:].strip())
        elif collect and not stripped.startswith("- "):
            collect = False
    return members


def insert_members(lines: list[str], group: str, nodes: list[str]) -> list[str]:
    """把 nodes 补进组的 proxies 列表（已存在的跳过），保留缩进。"""
    bounds = group_block_bounds(lines, group)
    if not bounds:
        return lines
    start, end = bounds
    existing = set(group_members(lines, group))
    missing = [n for n in nodes if n not in existing]
    if not missing:
        return lines
    insert_at = None
    indent = "  "
    for i in range(start, end):
        if lines[i].strip().startswith("- "):
            member_line = lines[i]
            indent = member_line[: len(member_line) - len(member_line.lstrip())]
            insert_at = i + 1
    if insert_at is None:
        return lines
    new_lines = [f"{indent}- {n}" for n in missing]
    return lines[:insert_at] + new_lines + lines[insert_at:]


def sync_targets(group: str) -> tuple[list[pathlib.Path], list[pathlib.Path]]:
    """要同步的文件：运行时配置 + 当前订阅的组增强文件。返回 (targets, skipped)。

    只认当前订阅的那一份增强组文件。以前是把所有含 `- name: <group>` 的 profile
    都改一遍，结果会把当前订阅的线路名写进别的订阅的模板里——那个订阅没有这些
    节点，真用起来就是坏配置。
    """
    targets = [VERGE_DIR / "clash-verge.yaml"]
    profile = verge_profile()
    groups_file = profile.get("groups_file")
    if groups_file and groups_file.exists() and \
            f"- name: {group}" in groups_file.read_text(encoding="utf-8", errors="replace"):
        targets.append(groups_file)
    candidates = [p for p in sorted((VERGE_DIR / "profiles").glob("*.yaml")) if p not in targets]
    skipped = [p for p in candidates
               if f"- name: {group}" in p.read_text(encoding="utf-8", errors="replace")]
    return targets, skipped


def fix_members(nodes: list[str], group: str = "Claude", hot_reload: bool = True,
                dry_run: bool = False) -> int:
    """把 nodes 补进 Clash Verge Rev 的组文件与运行时配置，然后热载。"""
    if not (VERGE_DIR / "profiles.yaml").exists():
        print("不是 Clash Verge Rev 的目录，--fix-members 只支持它；其它客户端用 --emit。",
              file=sys.stderr)
        return 2
    targets, skipped = sync_targets(group)
    profile = verge_profile()
    if profile.get("groups_file") is None:
        print("提示：当前订阅还没有「组增强文件」（Clash Verge → 订阅 → 编辑 → 全局扩展 → 组），"
              "这次只改运行时；订阅一更新就会被覆盖。", file=sys.stderr)
    elif profile["groups_file"] not in targets:
        print(f"提示：订阅的组增强文件 {profile['groups_file'].name} 里没有「{group}」组，"
              "这次只改运行时；订阅一更新就会被覆盖。", file=sys.stderr)
    if skipped:
        names = "、".join(p.name for p in skipped)
        print(f"跳过 {len(skipped)} 份其它订阅/模板的组文件（它们没有这些线路名）：{names}")

    changed = []
    planned = []
    for path in targets:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        new_lines = insert_members(lines, group, nodes)
        if new_lines == lines:
            continue
        planned.append((path, group_members(lines, group), group_members(new_lines, group)))
        if dry_run:
            continue
        backup = path.with_suffix(path.suffix + ".bak-20261102")
        backup.write_text("\n".join(lines) + "\n", encoding="utf-8")
        path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        changed.append(str(path))

    if dry_run:
        if not planned:
            print(f"组里已经包含这些线路（{len(nodes)} 条），没有要改的。")
            return 0
        print("--dry-run：会写入这些文件（未改动）")
        for path, before, after in planned:
            added = [n for n in after if n not in before]
            print(f"  {path}")
            print(f"    成员 {len(before)} -> {len(after)}，新增 {len(added)} 条：{'、'.join(added)}")
        return 0

    if not changed:
        print("组定义没变（节点已经在里面，或没找到组）。")
        return 0
    print("已写入：")
    for path in changed:
        print(f"  {path}（原文件 .bak-20261102）")

    if hot_reload:
        sock = find_socket()
        if sock:
            payload = (VERGE_DIR / "clash-verge.yaml").read_text(encoding="utf-8")
            code, out = run(["curl", "-s", "--max-time", "15", "--unix-socket", sock,
                             "-X", "PUT", "-H", "Content-Type: application/json",
                             "-d", json.dumps({"payload": payload, "force": True}),
                             "http://localhost/configs"])
            print(f"热载：{'成功' if code == 0 else '失败 ' + out[:120]}")
    print("下次订阅换了线路，再跑一次 `proxy_guard.py --fix-members --all` 即可重新同步。")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Claude 出口体检：规则目标、节点存活、单点组")
    ap.add_argument("--check", action="store_true", help="只检查（默认）")
    ap.add_argument("--fix", action="store_true", help="在组内切到可用节点")
    ap.add_argument("--fix-members", action="store_true", help="给组里补线路（Clash Verge Rev）")
    ap.add_argument("--emit", metavar="CLIENT",
                    help="输出配置片段：mihomo / clash-verge / flclash / mihomo-party / "
                         "sing-box / surge / shadowrocket")
    ap.add_argument("--all", action="store_true",
                    help="--fix-members 用：把当前订阅的全部线路同步进组里")
    ap.add_argument("--nodes", help="逗号分隔的线路名（--fix-members / --emit 用）")
    ap.add_argument("--policy", default="Claude", help="组名（默认 Claude）")
    ap.add_argument("--clients", action="store_true", help="列出检测到的客户端")
    ap.add_argument("--no-reload", action="store_true", help="--fix-members 不触发热载")
    ap.add_argument("--dry-run", action="store_true", help="--fix-members 只打印要改什么，不写文件")
    ap.add_argument("--json", action="store_true", help="--check 输出 JSON")
    args = ap.parse_args(argv)

    if args.clients:
        for key, info in detect_clients().items():
            state = "检测到" if info.get("installed") else "未检测到"
            print(f"  {key:14s} {state}  {info.get('note')}")
        return 0

    if args.emit:
        try:
            snippet = adapters.emit(args.emit, policy=args.policy,
                                    nodes=tuple(args.nodes.split(",")) if args.nodes
                                    else adapters.DEFAULT_NODES)
        except KeyError:
            print(f"不认识的客户端：{args.emit}", file=sys.stderr)
            return 2
        print(snippet)
        note = adapters.notes(args.emit)
        if note:
            print(f"\n# {note}")
        return 0

    nodes = [n.strip() for n in (args.nodes or "").split(",") if n.strip()]
    if args.fix_members:
        if args.all and nodes:
            print("--nodes 与 --all 只能二选一：--all 是同步订阅里的全部线路", file=sys.stderr)
            return 2
        if args.all:
            nodes = subscription_nodes_from_verge()
            if not nodes:
                print("读不到当前订阅的线路列表（不是 Clash Verge Rev，或订阅文件还没生成）；"
                      "可以先用 --nodes 手工列，或确认 profiles.yaml 的 current 指向一个远程订阅。",
                      file=sys.stderr)
                return 2
            print(f"订阅里的全部线路（{len(nodes)} 条）：{'、'.join(nodes)}")
        if len(nodes) < 2:
            print("--fix-members 至少要两条线路（只有一条正是要修的单点组）", file=sys.stderr)
            return 2
        return fix_members(nodes, group=args.policy, hot_reload=not args.no_reload,
                           dry_run=args.dry_run)

    subscription = subscription_nodes_from_verge()
    sock = find_socket()
    code, diag = check(sock, verbose=not args.json, subscription=subscription or None)
    if args.json:
        print(json.dumps(diag, ensure_ascii=False, indent=2))
    if args.fix:
        if not sock:
            print("没有 mihomo 控制接口，没法切节点。", file=sys.stderr)
            return 2
        return fix_selection(sock, diag)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
