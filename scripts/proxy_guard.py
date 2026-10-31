#!/usr/bin/env python3
"""Claude 出口体检 + 修复：规则指向谁、这个组的节点还活着吗、组里是不是只有一条线路。

2026-10-30 踩过的坑：Claude 组里只有一个「连接线路1」，线路挂掉后 claude.ai 的 TLS
握到手一半就断，其它网站全部正常（它们走的是另一个组）。这种「单点组」在
Clash Verge Rev、FlClash、Mihomo Party 上都可能出现——订阅换了节点名，组里的
旧名字失效，最后只剩一条或全挂。

它做三件事：
  1. --check        读 mihomo API，指出 Claude 规则的目标组、成员数、选中节点是否可用
  2. --fix          在组内切到一个活着的成员（不动配置，只改选择）
  3. --emit <client> 生成 mihomo / sing-box / Surge / Shadowrocket 的组+规则片段
  4. --fix-members  给组里补上其它入口线路（Clash Verge Rev：改 profile 组文件 + 热载）

没有 mihomo 内核的客户端（Surge、Shadowrocket）只做适配片段，不探测。
"""

from __future__ import annotations

import argparse
import json
import pathlib
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


def diagnose(proxies: dict, rules: list[dict]) -> dict:
    """纯函数：给 /proxies + /rules 的返回，判断 Claude 出口健不健康。"""
    out: dict = {"target": None, "group": None, "members": [], "now": None,
                 "problems": [], "fixable_by_selection": False}
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
    return out


def check(sock: str | None, verbose: bool = True) -> tuple[int, dict]:
    proxies_doc = api(sock, "/proxies") if sock else None
    rules_doc = api(sock, "/rules") if sock else None
    if not proxies_doc or not rules_doc:
        print("没有可用的 mihomo 控制接口：只能给配置片段（--emit），没法探测。",
              file=sys.stderr)
        return 2, {}
    diag = diagnose(proxies_doc.get("proxies") or {}, rules_doc.get("rules") or [])
    if verbose:
        print(f"Claude 规则目标：{diag.get('target')}")
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


def fix_members(nodes: list[str], group: str = "Claude", hot_reload: bool = True) -> int:
    """把 nodes 写进 Clash Verge Rev 的 profile 组文件和运行时配置，然后热载。"""
    if not (VERGE_DIR / "profiles.yaml").exists():
        print("不是 Clash Verge Rev 的目录，--fix-members 只支持它；其它客户端用 --emit。",
              file=sys.stderr)
        return 2
    targets = [VERGE_DIR / "clash-verge.yaml"]
    for path in sorted((VERGE_DIR / "profiles").glob("*.yaml")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if f"- name: {group}" in text:
            targets.append(path)

    changed = []
    for path in targets:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        new_lines = insert_members(lines, group, nodes)
        if new_lines != lines:
            backup = path.with_suffix(path.suffix + ".bak-20261031")
            backup.write_text("\n".join(lines) + "\n", encoding="utf-8")
            path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            changed.append(str(path))
    if not changed:
        print("组定义没变（节点已经在里面，或没找到组）。")
        return 0
    print("已写入：")
    for path in changed:
        print(f"  {path}（原文件 .bak-20261031）")

    if hot_reload:
        sock = find_socket()
        if sock:
            payload = (VERGE_DIR / "clash-verge.yaml").read_text(encoding="utf-8")
            code, out = run(["curl", "-s", "--max-time", "15", "--unix-socket", sock,
                             "-X", "PUT", "-H", "Content-Type: application/json",
                             "-d", json.dumps({"payload": payload, "force": True}),
                             "http://localhost/configs"])
            print(f"热载：{'成功' if code == 0 else '失败 ' + out[:120]}")
    print("提示：Clash Verge Rev 下还要在「订阅 → 编辑 → 全局扩展」里确认组定义，"
          "否则下次订阅更新会被覆盖。")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Claude 出口体检：规则目标、节点存活、单点组")
    ap.add_argument("--check", action="store_true", help="只检查（默认）")
    ap.add_argument("--fix", action="store_true", help="在组内切到可用节点")
    ap.add_argument("--fix-members", action="store_true", help="给组里补入口线路（Clash Verge Rev）")
    ap.add_argument("--emit", metavar="CLIENT",
                    help="输出配置片段：mihomo / clash-verge / flclash / mihomo-party / "
                         "sing-box / surge / shadowrocket")
    ap.add_argument("--nodes", help="逗号分隔的线路名（--fix-members / --emit 用）")
    ap.add_argument("--policy", default="Claude", help="组名（默认 Claude）")
    ap.add_argument("--clients", action="store_true", help="列出检测到的客户端")
    ap.add_argument("--no-reload", action="store_true", help="--fix-members 不触发热载")
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
        if len(nodes) < 2:
            print("--fix-members 至少给两个 --nodes（单线路正是要修的问题）", file=sys.stderr)
            return 2
        return fix_members(nodes, group=args.policy, hot_reload=not args.no_reload)

    sock = find_socket()
    code, diag = check(sock, verbose=not args.json)
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
