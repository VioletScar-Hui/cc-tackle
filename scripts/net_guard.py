#!/usr/bin/env python3
"""Claude 直连看门狗：每 5 秒看一遍 Claude 相关进程的对外连接，直连就杀。

判据（为什么这么判，见 references/net-guard.md）：
  * 只盯 Claude 自己的进程（CLI、桌面版及其 helper），别的一概不碰；
  * 目标地址是回环 / 私网 / 链路本地 → 不算直连（本机代理、局域网代理都在这）；
  * 目标落在 fake-ip 段，或到它的路由走 utun/tun/ppp/ipsec → 说明进了隧道，放行；
  * 路由落在 en0/en1 这类物理接口 → 直连，立刻 SIGKILL 那个进程。

macOS 没有「只杀一个线程」的接口：线程随进程一起死，所以这里杀的是进程。
杀之前把 pid、进程名、目标地址、出口接口写进日志，事后能查是谁、连了哪。

安全边界：不杀自己、父进程链、pid 1；每分钟最多杀 N 个（默认 12），
避免某个守护进程把 Claude 拉起来又被杀、形成循环。拿不准（路由读不到）时
只记日志不动手——宁可漏杀，不可误杀。
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
import pathlib
import plistlib
import re
import signal
import subprocess
import sys
import time
from collections import deque

HOME = pathlib.Path.home()
STATE_DIR = HOME / ".local" / "state" / "claude-guard"
LOG_PATH = STATE_DIR / "net-guard.log"
PID_PATH = STATE_DIR / "net-guard.pid"
AGENT_LABEL = "com.violetscarhui.claude-net-guard"
AGENT_PLIST = HOME / "Library" / "LaunchAgents" / f"{AGENT_LABEL}.plist"

FAKE_IP_NETS = (ipaddress.ip_network("198.18.0.0/15"),)
TUN_IFACE_PREFIXES = ("utun", "tun", "ppp", "ipsec")
PHYSICAL_IFACE_PREFIXES = ("en", "bridge", "awdl", "llw")
MAX_KILLS_PER_MIN = 12

# 这些名字里带 claude，但不是要盯的对象：本工具自己、以及别的 agent 宿主。
EXCLUDE_MARKERS = ("cc-tackle", "claude-guard", "net_guard", "net-guard")


def run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def is_claude_process(pid: int, comm: str, args: str = "") -> bool:
    """这个进程是不是 Claude 自己。只认可执行路径，不按参数里的 claude 字样猜。"""
    if any(marker in comm.lower() for marker in EXCLUDE_MARKERS):
        return False
    base = os.path.basename(comm).strip().lower()
    if base in ("claude", "claude-code"):
        return True
    # 桌面版的 helper 进程：`Claude Helper (Renderer)` 之类
    if base.startswith("claude ") or base.startswith("claude-"):
        return True
    lowered = comm.lower()
    # native 安装的 CLI 是 `~/.local/share/claude/versions/2.1.296`，文件名只是版本号
    if "/.local/share/claude/" in lowered or "/claude.app/contents/" in lowered:
        return True
    # node 版 CLI：可执行文件是 node，靠入口脚本认
    if "claude-code/cli.js" in args or "/.local/share/claude/" in args:
        return True
    return False


def _pid_table() -> list[tuple[int, str, str]]:
    """(pid, comm, args)。分两次 ps：comm 里可能有空格，混在一行里没法可靠切。"""
    _, comms = run(["ps", "-axo", "pid=,comm="])
    _, cmds = run(["ps", "-axo", "pid=,args="])
    args_by_pid: dict[int, str] = {}
    for line in cmds.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            args_by_pid[int(parts[0])] = parts[1]
    table = []
    for line in comms.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        pid = int(parts[0])
        table.append((pid, parts[1], args_by_pid.get(pid, "")))
    return table


def claude_pids(extra_pattern: str | None = None) -> list[tuple[int, str]]:
    pattern = re.compile(extra_pattern, re.I) if extra_pattern else None
    found = []
    for pid, comm, args in _pid_table():
        if pid <= 1 or pid == os.getpid():
            continue
        matched = is_claude_process(pid, comm, args) or bool(
            pattern and pattern.search(f"{comm} {args}"))
        if matched:
            found.append((pid, comm))
    return found


def ancestors(pid: int, depth: int = 16) -> set[int]:
    seen = set()
    current = pid
    for _ in range(depth):
        code, out = run(["ps", "-o", "ppid=", "-p", str(current)])
        if code or not out.strip().isdigit():
            break
        current = int(out.strip())
        if current <= 1 or current in seen:
            break
        seen.add(current)
    return seen


def parse_lsof(text: str) -> list[dict]:
    """从 lsof 输出里抠出「本端 -> 对端 (状态)」。"""
    conns = []
    for line in text.splitlines():
        if "->" not in line:
            continue
        remote, _, state = line.partition("->")[2].partition(" (")
        remote = remote.strip().rstrip(")")
        addr, _, port = remote.rpartition(":")
        if not addr or not port.isdigit():
            continue
        addr = addr.strip("[]")
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        conns.append({"ip": ip, "port": int(port), "state": state.strip(") ")})
    return conns


def connections(pid: int) -> list[dict]:
    code, out = run(["lsof", "-nP", "-iTCP", "-a", "-p", str(pid)], timeout=10)
    if code not in (0, 1):          # lsof 没结果时返回 1
        return []
    return parse_lsof(out)


_route_cache: dict[str, tuple[float, str]] = {}


def route_iface(ip: str, ttl: int = 30) -> str:
    """到某个地址走哪个接口；读不到返回空串（调用方按「不确定」处理）。"""
    hit = _route_cache.get(ip)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    code, out = run(["route", "-n", "get", ip], timeout=5)
    iface = ""
    if code == 0:
        for line in out.splitlines():
            if line.strip().startswith("interface:"):
                iface = line.split(":", 1)[1].strip()
                break
    _route_cache[ip] = (time.time(), iface)
    return iface


def is_fake_ip(ip: ipaddress._BaseAddress) -> bool:
    return any(ip in net for net in FAKE_IP_NETS)


def classify(ip: ipaddress._BaseAddress, iface: str) -> str:
    """local / tunnel / direct / unknown。

    local  ：回环、私网、链路本地 —— 本机代理或局域网，不算直连；
    tunnel ：fake-ip 段，或路由走隧道接口；
    direct ：路由落在物理接口上；
    unknown：路由读不到，只记日志不动手（宁可漏杀，不可误杀）。
    """
    # 先看 fake-ip：198.18.0.0/15 在 Python 眼里也算 private，顺序反了会把它当成本机地址。
    if is_fake_ip(ip):
        return "tunnel"
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast:
        return "local"
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return "local"                # CGNAT，常见于 Tailscale 之类的叠层
    if not iface:
        return "unknown"
    lowered = iface.lower()
    if lowered.startswith(TUN_IFACE_PREFIXES):
        return "tunnel"
    if lowered.startswith(PHYSICAL_IFACE_PREFIXES):
        return "direct"
    return "unknown"


LOG_MAX_BYTES = 2 * 1024 * 1024


def append_log(line: str) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        if LOG_PATH.exists() and LOG_PATH.stat().st_size > LOG_MAX_BYTES:
            # 每 5 秒一行，不轮转会一直长；留一份上一版够查了。
            LOG_PATH.replace(LOG_PATH.with_suffix(".log.1"))
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(line.rstrip() + "\n")
    except OSError:
        pass


def scan(protected: set[int], extra_pattern: str | None = None) -> list[dict]:
    """扫一遍，返回发现直连的事件（不杀）。"""
    events = []
    for pid, comm in claude_pids(extra_pattern):
        if pid in protected:
            continue
        for conn in connections(pid):
            iface = route_iface(str(conn["ip"]))
            verdict = classify(conn["ip"], iface)
            if verdict != "direct":
                continue
            events.append({"pid": pid, "comm": comm, "ip": str(conn["ip"]),
                           "port": conn["port"], "iface": iface, "state": conn["state"],
                           "at": now()})
    return events


def kill_process(pid: int) -> tuple[bool, str]:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return True, "进程已经不在了"
    except PermissionError:
        return False, "没有权限（换 sudo 或看 SIP）"
    except OSError as error:
        return False, f"{type(error).__name__}: {error}"
    time.sleep(0.3)
    code, _ = run(["ps", "-p", str(pid), "-o", "pid="])
    return (code != 0, "已终止" if code != 0 else "还活着")


def describe(event: dict) -> str:
    return (f"{event['at']} pid={event['pid']} comm={event['comm']} "
            f"remote={event['ip']}:{event['port']} iface={event['iface']} "
            f"state={event['state']}")


def run_once(*, dry_run: bool, protected: set[int], extra_pattern: str | None,
             kills: deque, verbose: bool) -> int:
    events = scan(protected, extra_pattern)
    stamp = now()
    if not events:
        if verbose:
            print(f"{stamp} 扫描完成：没有发现 Claude 进程的直连")
        append_log(f"{stamp} scan clean")
        return 0
    killed = 0
    for event in events:
        line = describe(event)
        if dry_run:
            append_log(line + " verdict=direct action=dry-run")
            print(f"{line}  直连（dry-run，未处理）")
            continue
        while kills and time.time() - kills[0] > 60:
            kills.popleft()
        if len(kills) >= MAX_KILLS_PER_MIN:
            append_log(line + " verdict=direct action=skipped-rate-limit")
            print(f"{line}  直连，但一分钟内已杀 {MAX_KILLS_PER_MIN} 个，暂停处理", file=sys.stderr)
            continue
        ok, note = kill_process(event["pid"])
        kills.append(time.time())
        append_log(line + f" verdict=direct action={'kill' if ok else 'kill-failed'} note={note}")
        print(f"{line}  直连 → SIGKILL {note}")
        killed += 1
    return 1 if killed else 0


def acquire_pidfile() -> bool:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        pid = int(PID_PATH.read_text().strip())
        if pid > 1 and run(["ps", "-p", str(pid), "-o", "pid="])[1].strip() == str(pid):
            return False
    except (OSError, ValueError):
        pass
    PID_PATH.write_text(str(os.getpid()), encoding="utf-8")
    return True


def release_pidfile() -> None:
    try:
        if PID_PATH.read_text().strip() == str(os.getpid()):
            PID_PATH.unlink()
    except OSError:
        pass


def launch_agent_plist(interval: int) -> dict:
    script = pathlib.Path(__file__).resolve()
    return {
        "Label": AGENT_LABEL,
        "ProgramArguments": [sys.executable, str(script), "--interval", str(interval)],
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": str(STATE_DIR / "net-guard.out"),
        "StandardErrorPath": str(STATE_DIR / "net-guard.err"),
        "ProcessType": "Background",
    }


def install_agent(interval: int) -> int:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    AGENT_PLIST.parent.mkdir(parents=True, exist_ok=True)
    AGENT_PLIST.write_bytes(plistlib.dumps(launch_agent_plist(interval)))
    uid = os.getuid()
    code, out = run(["launchctl", "bootstrap", f"gui/{uid}", str(AGENT_PLIST)], timeout=20)
    if code != 0:
        code, out = run(["launchctl", "load", "-w", str(AGENT_PLIST)], timeout=20)
    print(f"已安装：{AGENT_PLIST}")
    if code != 0:
        print(f"launchctl 返回 {code}：{out.strip()[:200]}", file=sys.stderr)
        return 2
    print(f"已启动：每 {interval} 秒扫描一次；日志 {LOG_PATH}")
    return 0


def uninstall_agent() -> int:
    uid = os.getuid()
    run(["launchctl", "bootout", f"gui/{uid}/{AGENT_LABEL}"], timeout=20)
    run(["launchctl", "unload", "-w", str(AGENT_PLIST)], timeout=20)
    try:
        AGENT_PLIST.unlink()
        print(f"已卸载：{AGENT_PLIST}")
    except FileNotFoundError:
        print("没有安装过")
    return 0


def agent_status() -> int:
    uid = os.getuid()
    code, out = run(["launchctl", "print", f"gui/{uid}/{AGENT_LABEL}"], timeout=20)
    running = "pid = " in out
    print(f"LaunchAgent：{'已加载' if code == 0 else '未加载'}"
          + (f"，{out.split('pid = ')[1].splitlines()[0].strip()}" if running else ""))
    print(f"plist：{AGENT_PLIST}（{'存在' if AGENT_PLIST.exists() else '不存在'}）")
    print(f"日志：{LOG_PATH}（{LOG_PATH.stat().st_size if LOG_PATH.exists() else 0} 字节）")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Claude 直连看门狗：发现直连就杀掉那个进程")
    ap.add_argument("--interval", type=int, default=5, help="扫描间隔秒数（默认 5）")
    ap.add_argument("--once", action="store_true", help="只扫一次就退出（调试用）")
    ap.add_argument("--dry-run", action="store_true", help="只记录不杀")
    ap.add_argument("--process-regex", help="额外匹配的进程名正则（调试用，默认只认 Claude）")
    ap.add_argument("--install", action="store_true", help="装成 LaunchAgent 常驻（每 5 秒）")
    ap.add_argument("--uninstall", action="store_true", help="卸载 LaunchAgent")
    ap.add_argument("--status", action="store_true", help="看 LaunchAgent 与日志状态")
    ap.add_argument("--yes", action="store_true", help="配合 --install：跳过确认")
    args = ap.parse_args(argv)

    if args.uninstall:
        return uninstall_agent()
    if args.status:
        return agent_status()
    if args.install:
        if not args.yes:
            print("--install 会装一个每 5 秒把 Claude 直连进程 SIGKILL 的常驻任务：")
            print(f"  plist：{AGENT_PLIST}")
            print(f"  日志 ：{LOG_PATH}")
            print("确认加 --yes 再执行。")
            return 1
        return install_agent(args.interval)
    if args.interval < 1:
        print("--interval 至少 1 秒", file=sys.stderr)
        return 2
    if args.once:
        return run_once(dry_run=args.dry_run, protected={os.getpid()} | ancestors(os.getpid()),
                        extra_pattern=args.process_regex, kills=deque(), verbose=True)
    if not acquire_pidfile():
        print("已经有一个看门狗在跑（pid 文件指向活着的进程）", file=sys.stderr)
        return 2
    protected = {os.getpid()} | ancestors(os.getpid())
    kills: deque = deque()
    print(f"{now()} 看门狗启动：每 {args.interval} 秒扫一次"
          f"{'（dry-run）' if args.dry_run else ''}；日志 {LOG_PATH}")

    def stop(signum, _frame):
        print(f"\n{now()} 收到信号 {signum}，退出")
        release_pidfile()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    append_log(f"{now()} watchdog start interval={args.interval} dry_run={args.dry_run}")
    try:
        while True:
            run_once(dry_run=args.dry_run, protected=protected,
                     extra_pattern=args.process_regex, kills=kills, verbose=False)
            time.sleep(args.interval)
    finally:
        release_pidfile()
        append_log(f"{now()} watchdog stop")


if __name__ == "__main__":
    raise SystemExit(main())
