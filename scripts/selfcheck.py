#!/usr/bin/env python3
"""claude-account-guard 一键自检。

把散在 SKILL.md 和桌面指令文档各节的复核命令串成一条。检查七件事：技能文件
齐全 → 语法编译 → 全部单元测试 → 三个守护脚本 → Clash 内核状态 → 系统代理四
开关 → 完整环境体检，跑完出两张表：先一张七项自检的结论表，再把最后那项
「完整环境体检」的 25 项逐条展开（明细取自体检自己输出的 JSON，判定不在
这里重写一遍，免得两处各说各话）。

用法：
    python3 scripts/selfcheck.py            全部跑，约 1.5 分钟
    python3 scripts/selfcheck.py --fast     跳过单元测试，约 20 秒
    python3 scripts/selfcheck.py --no-audit 跳过最后的环境体检（也就没有展开表）

退出码：0 全过（可能带 ! 提示）；1 有项目失败；2 脚本自己的运行环境有问题。

只读：本脚本不改任何配置，也不依赖审计隐式写出的文件。需要保存报告时，单独给
account_guard.py 传 --save-audit。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKILL = HERE.parent
sys.path.insert(0, str(HERE))

try:
    import account_guard as g
except Exception as exc:  # pragma: no cover - 只在 skill 被拆散时发生
    print(f"读不到 account_guard.py（{type(exc).__name__}: {exc}）", file=sys.stderr)
    print(f"预期位置：{HERE / 'account_guard.py'}", file=sys.stderr)
    sys.exit(2)

OK, HINT, BAD = "✓", "!", "✗"
ROWS: list[tuple[str, str, str]] = []


def add(name: str, state: str, detail: str) -> None:
    ROWS.append((name, state, detail))


def sh(cmd, timeout=60, cwd=None, env=None):
    """跑一条命令，返回 (退出码, 合并输出)。异常降级成退出码 1，不让自检自己崩掉。"""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(cwd) if cwd else None, env=env, check=False,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, f"{type(exc).__name__}: {exc}"


def tail(text: str, n: int = 300) -> str:
    text = " ".join(text.split())
    return text[-n:] if len(text) > n else text


# ── 1. 技能文件齐全，且 SKILL.md 的 name 与目录名逐字符相等 ──────────────
def check_files() -> None:
    need = [
        "SKILL.md",
        "scripts/account_guard.py",
        "tests/test_account_guard.py",
        "references/article-mapping.md",
    ]
    missing = [p for p in need if not (SKILL / p).exists()]
    if missing:
        add("技能文件齐全", BAD, "缺少 " + "、".join(missing))
        return
    text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    m = re.search(r"^name:\s*(\S+)\s*$", text, re.M)
    fname = m.group(1) if m else ""
    if fname != SKILL.name:
        add("技能文件齐全", BAD,
            f"frontmatter name={fname or '(缺失)'} 与目录名 {SKILL.name} 不一致，"
            "进仓时校验器会拒")
        return
    add("技能文件齐全", OK, f"4 个文件都在；name={fname} 与目录名一致")


# ── 2. 语法 ─────────────────────────────────────────────────────────
def check_compile() -> None:
    code, out = sh([sys.executable, "-m", "py_compile", str(HERE / "account_guard.py")])
    add("语法编译", OK if code == 0 else BAD,
        "account_guard.py 通过" if code == 0 else tail(out))


# ── 3. 全部单元测试 ──────────────────────────────────────────────────
def check_tests() -> None:
    code, out = sh([sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                   timeout=900, cwd=SKILL)
    m = re.search(r"Ran (\d+) tests?", out)
    n = m.group(1) if m else "?"
    passed = code == 0 and re.search(r"^OK", out, re.M) is not None
    if passed:
        add("单元测试", OK, f"{n} 个用例全部通过")
        return
    # 失败时把断言行捞出来。曾经出过「跑一半就收集结束、还报 OK」的假通过，
    # 所以这里既看退出码也看末尾的 OK。
    fails = [ln.strip() for ln in out.splitlines()
             if ln.startswith(("FAIL:", "ERROR:", "AssertionError"))]
    add("单元测试", BAD, f"{n} 个用例里有失败：" + ("；".join(fails[:3]) or tail(out)))


# ── 4. 三个 LaunchAgent 守护 ─────────────────────────────────────────
GUARDS = {
    "local.clash-mode-guard": "把内核 mode 拉回 rule，防止重算后回 global",
    "local.clash-dns-guard": "配置文件重算带进国内 DNS 时就地修掉",
    "local.proxy-residue-cleanup": "清掉关闭状态下残留的系统代理值",
}


def check_guards() -> None:
    code, out = sh(["launchctl", "list"], timeout=20)
    if code != 0:
        add("守护脚本", BAD, "launchctl list 跑不动")
        return
    seen: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[2].strip() in GUARDS:
            seen[parts[2].strip()] = parts[1].strip() or "0"
    missing = [k for k in GUARDS if k not in seen]
    crashed = [f"{k}(退出码 {v})" for k, v in seen.items() if v != "0"]
    if crashed:
        add("守护脚本", BAD, "在跑但最近一次退出非 0：" + "、".join(crashed))
    elif missing:
        add("守护脚本", HINT,
            f"{len(seen)}/3 在跑，缺 " + "、".join(missing)
            + "（plist 在 ~/Library/LaunchAgents/，用 launchctl bootstrap gui/$(id -u) 装载）")
    else:
        add("守护脚本", OK, "3 个都在跑，最近一次退出都是 0")


# ── 5. Clash 内核：mode / TUN / 严格路由 ──────────────────────────────
def check_kernel() -> None:
    cmd = [
        "curl", "-s", "--unix-socket", str(g.CLASH_SOCK),
        "-H", f"Authorization: Bearer {g.CLASH_SECRET}",
        "http://localhost/configs",
    ]
    code, out = sh(cmd, timeout=20)
    if code != 0 or not out.lstrip().startswith("{"):
        add("Clash 内核", BAD,
            f"控制接口读不到（内核没跑、socket 或 secret 变了）：{tail(out, 120)}")
        return
    try:
        cfg = json.loads(out)
    except ValueError:
        add("Clash 内核", BAD, "控制接口返回的不是 JSON")
        return
    mode = cfg.get("mode")
    tun = cfg.get("tun") or {}
    ten, strict = bool(tun.get("enable")), bool(tun.get("strict-route"))
    if mode == "rule":
        state = OK
        note = "规则模式（三个守护的目标状态）"
    elif mode == "global":
        state = HINT
        note = "全局模式：所有流量走 GLOBAL 选择项，规则不生效，mode 守护会在 30 秒内拉回 rule"
    else:
        state = BAD
        note = f"mode={mode}，既不是规则也不是全局"
    if not ten:
        state, note = BAD, note + "；TUN 没开，流量不经内核"
    add("Clash 内核", state, f"mode={mode}，TUN={ten}，strict-route={strict}；{note}")


# ── 6. 系统代理四开关 ────────────────────────────────────────────────
def check_system_proxy() -> None:
    code, out = sh(["scutil", "--proxy"], timeout=20)
    if code != 0:
        add("系统代理四开关", BAD, "scutil --proxy 跑不动")
        return
    hot = []
    for key in ("HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable"):
        m = re.search(rf"{key}\s*:\s*(\d+)", out)
        v = m.group(1) if m else "读不到"
        if v != "0":
            hot.append(f"{key}={v}")
    if hot:
        add("系统代理四开关", BAD,
            "有开关不是 0：" + "、".join(hot) + "（跑 python3 scripts/account_guard.py 会自动清）")
    else:
        add("系统代理四开关", OK, "四个全为 0，走 TUN 接管")


# ── 7. 完整环境体检 ──────────────────────────────────────────────────
SUMMARY_RE = re.compile(
    r"共 (\d+) 项：\S+ 已解决 (\d+)\s+\S+ 待处理 (\d+)\s+\S+ 未解决 (\d+)\s+\S+ 未测到 (\d+)"
)


def project_roots_default() -> tuple:
    """A14 / A24 要扫的项目根：环境变量没给时按什么来。

    三级兜底，选中的那一级会打出来 —— 扫描范围静默换掉比不扫更糟：
      1. 环境变量 CLAUDE_GUARD_PROJECT_ROOTS 已经给了，用它的；
      2. 本 skill 装在某个 git 仓里（形如 `.claude/skills/<名字>/`），就用那个仓的根，
         这正是 A14「代码有没有落在本地 Git」要问的那个仓；
      3. 老位置 `~/ipe`（本机一直这么跑，保留以免换个默认值就少判两项）。
    三级都读不到就留空，体检自己会说明怎么开。
    """
    given = os.environ.get("CLAUDE_GUARD_PROJECT_ROOTS", "").strip()
    if given:
        return given, "环境变量指定"
    code, out = sh(["git", "-C", str(SKILL), "rev-parse", "--show-toplevel"], timeout=20)
    top = out.strip().splitlines()[0].strip() if out.strip() else ""
    if code == 0 and top.startswith("/"):
        return top, f"本 skill 所在的 git 仓 {top}"
    legacy = Path.home() / "ipe"
    if legacy.is_dir():
        return str(legacy), f"默认位置 {legacy}"
    return "", "没有可用的项目根，这一项会被跳过"


def check_audit(project_roots: str = ""):
    """跑完整体检，返回 (报告路径, 报告字典)。

    第二项留给调用方展开成逐条明细。读不出来时为 None —— 那种情况下汇总行已经
    打印了，不值得为了展开不了而把整项判成失败。
    """
    env = dict(os.environ)
    if project_roots:
        env["CLAUDE_GUARD_PROJECT_ROOTS"] = project_roots
    else:
        env.pop("CLAUDE_GUARD_PROJECT_ROOTS", None)
    code, out = sh([sys.executable, str(HERE / "account_guard.py"), "--audit", "--json"],
                   timeout=900, cwd=SKILL, env=env)
    try:
        report = json.loads(out)
    except (ValueError, TypeError):
        add("完整环境体检", BAD, f"没读出 JSON 报告（退出码 {code}）：{tail(out)}")
        return "", None
    rows = g.build_summary(report)
    total = len(rows)
    solved = sum(1 for _n, status, _d in rows if status == g.S_OK)
    todo = sum(1 for _n, status, _d in rows if status == g.S_FIX)
    bad = sum(1 for _n, status, _d in rows if status == g.S_BAD)
    na = sum(1 for _n, status, _d in rows if status == g.S_NA)
    detail = f"{total} 项：已解决 {solved}、待处理 {todo}、未解决 {bad}、未测到 {na}"
    if bad:
        add("完整环境体检", BAD, detail + "；有未解决项，跑不带参数的 account_guard.py 处理")
    elif todo or na:
        add("完整环境体检", HINT, detail + "；有待处理的，跑不带参数的 account_guard.py 处理")
    else:
        add("完整环境体检", OK, detail)
    return "", report


def main() -> int:
    ap = argparse.ArgumentParser(description="claude-account-guard 一键自检（只读）")
    ap.add_argument("--fast", action="store_true", help="跳过单元测试")
    ap.add_argument("--no-audit", action="store_true", help="跳过完整环境体检")
    args = ap.parse_args()

    # 项目根先定下来：它会决定体检里 A14 / A24 扫哪儿，选中的那一级要打出来。
    roots, roots_source = project_roots_default()

    print(f"claude-account-guard 一键自检  ——  {SKILL}")
    print("只读，不改任何配置。\n")

    check_files()
    check_compile()
    if args.fast:
        add("单元测试", HINT, "--fast 跳过了")
    else:
        check_tests()
    check_guards()
    check_kernel()
    check_system_proxy()

    report_path, report = "", None
    if args.no_audit:
        add("完整环境体检", HINT, "--no-audit 跳过了")
    else:
        report_path, report = check_audit(roots)

    # 逐条展开用报告自己算，不把判定重写一遍 —— 否则展开和 --audit 迟早各说各话。
    sub_rows = g.build_summary(report) if report else []

    print(g.render_table(("自检项", "结果", "说明"),
                         [(n, s, t) for n, s, t in ROWS]))
    n_ok = sum(1 for _, s, _ in ROWS if s == OK)
    n_hint = sum(1 for _, s, _ in ROWS if s == HINT)
    n_bad = sum(1 for _, s, _ in ROWS if s == BAD)
    print()
    print(f"  {len(ROWS)} 项：{OK} 通过 {n_ok}    {HINT} 提示 {n_hint}    {BAD} 失败 {n_bad}")

    if sub_rows:
        print()
        print(f"  完整环境体检的 {len(sub_rows)} 项（上面最后那一行的展开）：")
        print()
        print(g.render_table(("检查项", "状态", "实测结果"),
                             [(n, s.strip(), g.truncate(d, 72)) for n, s, d in sub_rows]))
    if report_path:
        print()
        print(f"  完整体检报告（未截断的全文在里面）：{report_path}")
    print(f"  项目根（A14 / A24 扫这里）：{roots or '未指定'}　—　{roots_source}")
    if n_bad:
        print(f"\n  有 {n_bad} 项没过。逐项看：python3 scripts/account_guard.py --commands")
    else:
        print("\n  全部通过。要复核某一项的具体命令：python3 scripts/account_guard.py --commands")
    return 1 if n_bad else 0


if __name__ == "__main__":
    sys.exit(main())
