#!/usr/bin/env python3
"""住宅链路锁定：统一入口。

这一套是从 claude-residential-lock 整包吸收进来的，脚本原样放在
`scripts/residential/`，这里只做三件事：

  1. 把散落的 shell 脚本收成一个命令，别让人记 8 个文件名；
  2. `--status` 把「用户级守护 / root 层 / 依赖 / 配置」一次说清楚；
  3. root 层（pf 防火墙 + DNS 守卫）单独拆出来，明确告诉你什么时候要 sudo。

它保护什么（和 net_guard 的分工）：
  net_guard      —— 发现 Claude 直连就 SIGKILL（每 5 秒）
  guard.sh       —— Clash 规则丢了/被订阅覆盖就自愈（用户级，30 秒 + WatchPaths）
  dns-guard.py   —— 代理不健康时 Claude 域名直接 NXDOMAIN（root 级）
  pf 防火墙      —— 物理网卡上禁止直连 Anthropic/CDN，fail-closed（root 级）

用法：
  python3 scripts/residential_lock.py --status
  python3 scripts/residential_lock.py --init          # 交互生成参数文件
  python3 scripts/residential_lock.py --install       # 装用户级自愈守护
  python3 scripts/residential_lock.py --check         # 只检查规则健康
  python3 scripts/residential_lock.py --discover      # 探测哪个节点是住宅
  python3 scripts/residential_lock.py --selfcheck     # 真发流量验证
  sudo python3 scripts/residential_lock.py --root-install     # pf + DNS 守卫
  sudo python3 scripts/residential_lock.py --root-uninstall

前置：Clash Verge（service 模式）、`/usr/bin/python3` + pyyaml（expand.py 要用）。
"""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
SCRIPTS = HERE / "residential"
GUARD_DAEMON = "local.claude-residential-guard"
PF_DAEMON = "local.claude-residential-pf"
DNS_DAEMON = "local.claude-residential-dns"
PF_ANCHOR = "claude-residential"
ROOT_ETC = pathlib.Path("/usr/local/etc/claude-residential")
BASH = "/bin/bash"


def env_file() -> pathlib.Path:
    """参数文件位置；允许用 CLAUDE_RESIDENTIAL_ENV 覆盖（测试与多套配置用）。"""
    override = os.environ.get("CLAUDE_RESIDENTIAL_ENV", "").strip()
    if override:
        return pathlib.Path(override).expanduser()
    return pathlib.Path.home() / "Library" / "Scripts" / "claude-residential.env"


def script(name: str) -> pathlib.Path:
    return SCRIPTS / name


def run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        return 1, f"{type(error).__name__}: {error}"
    # 别用 text=True：launchctl 的输出偶尔夹非 UTF-8 字节，直接解码会抛。
    out = (proc.stdout or b"").decode("utf-8", "replace")
    err = (proc.stderr or b"").decode("utf-8", "replace")
    return proc.returncode, out + err


def have_pyyaml() -> bool:
    try:
        import yaml  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def build_command(action: str, *, dry_run: bool = False) -> list[str] | None:
    """把动作映射到要执行的命令。返回 None 表示未知动作。"""
    dry = ["--dry-run"] if dry_run else []
    table = {
        "init": [BASH, str(script("install.sh")), *dry],
        "install": [BASH, str(script("guard-install.sh")), *dry],
        "uninstall": [BASH, str(script("guard-install.sh")), "--uninstall"],
        "check": [BASH, str(script("guard.sh")), "--check"],
        "discover": [BASH, str(script("discover.sh")), *dry],
        "selfcheck": [BASH, str(script("selfcheck.sh")), *dry],
        "root-install": ["sudo", BASH, str(script("harden-root.sh")), *dry],
        "root-uninstall": ["sudo", BASH, str(script("harden-root.sh")), "--uninstall"],
    }
    return table.get(action)


def _launchd_loaded(label: str, domain: str) -> bool:
    code, _ = run(["launchctl", "print", f"{domain}/{label}"], timeout=20)
    return code == 0


def root_status() -> dict:
    """root 层现状；不用 sudo 也能看出「装没装」。"""
    out = {
        "pf_plist": pathlib.Path(f"/Library/LaunchDaemons/{PF_DAEMON}.plist").exists(),
        "dns_plist": pathlib.Path(f"/Library/LaunchDaemons/{DNS_DAEMON}.plist").exists(),
        "etc": ROOT_ETC.is_dir(),
        "pf_rules": None,
    }
    code, body = run(
        ["sudo", "-n", "/sbin/pfctl", "-a", PF_ANCHOR, "-s", "rules"], timeout=15)
    if code == 0:
        out["pf_rules"] = len([l for l in body.splitlines() if l.strip()])
    return out


def status() -> int:
    print("== 住宅链路锁定 ==")
    cfg = env_file()
    print(f"参数文件：{cfg}（{'存在' if cfg.exists() else '不存在，先跑 --init'}）")

    print("\n-- 用户级自愈守护（guard.sh）--")
    code, body = run([BASH, str(script("guard-install.sh")), "--status"], timeout=30)
    print(body.strip() or "（无输出）")

    print("\n-- 依赖 --")
    print(f"pyyaml：{'有' if have_pyyaml() else '缺（/usr/bin/python3 -m pip install --user pyyaml）'}")

    print("\n-- root 层（pf 防火墙 + DNS 守卫）--")
    root = root_status()
    print(f"pf LaunchDaemon：{'已安装' if root['pf_plist'] else '未安装'}")
    print(f"DNS 守卫 LaunchDaemon：{'已安装' if root['dns_plist'] else '未安装'}")
    print(f"root 配置目录：{'存在' if root['etc'] else '不存在'}")
    if root["pf_rules"] is None:
        print("pf 规则条数：需要 sudo 才看得到（sudo python3 ... --root-install 会装）")
    else:
        print(f"pf 规则条数：{root['pf_rules']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="住宅链路锁定：Clash 规则自愈 + pf 防火墙 + DNS 守卫")
    for action, help_text in (
        ("init", "交互生成参数文件（会问住宅节点、出口 IP 等）"),
        ("install", "安装/更新用户级自愈守护（LaunchAgent，30 秒 + WatchPaths）"),
        ("uninstall", "卸载用户级自愈守护"),
        ("check", "只检查规则健康，不修复"),
        ("discover", "逐个节点探测出口，找出住宅节点"),
        ("selfcheck", "真发流量验证出口 / UDP 泄漏 / 直连是否被挡"),
        ("root-install", "安装 root 层：pf 防火墙 + DNS 守卫（需要 sudo）"),
        ("root-uninstall", "卸载 root 层（需要 sudo）"),
    ):
        ap.add_argument(f"--{action}", action="store_true", help=help_text)
    ap.add_argument("--status", action="store_true", help="看用户级/root 层/依赖/参数文件状态")
    ap.add_argument("--dry-run", action="store_true", help="传给脚本：只打印不执行")
    args = ap.parse_args(argv)

    if args.status or not any(vars(args).values()):
        return status()

    for action in ("init", "install", "uninstall", "check", "discover", "selfcheck",
                   "root-install", "root-uninstall"):
        if getattr(args, action):
            cmd = build_command(action, dry_run=args.dry_run)
            if cmd is None:
                print(f"未知动作 {action}", file=sys.stderr)
                return 2
            if action.startswith("root") and os.geteuid() != 0 and cmd[0] == "sudo":
                print(f"即将执行（会要密码）：{' '.join(cmd)}")
            if args.dry_run and action not in ("root-install", "init", "discover", "selfcheck"):
                print(f"dry-run：{' '.join(cmd)}")
                return 0
            return run(cmd)[0]
    return status()


if __name__ == "__main__":
    raise SystemExit(main())
