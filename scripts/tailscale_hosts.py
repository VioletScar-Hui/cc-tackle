#!/usr/bin/env python3
"""Tailscale × Clash 共存的 DNS 适配：在 Clash 本地回答 `*.ts.net`。

背景（2026-11-03 在真机上踩过）：

- mihomo 的 fake-ip + `dns-hijack` 要求系统 DNS 落在 mihomo 上。Tailscale 默认会
  接管系统 DNS（`100.100.100.100`），于是 Clash 的劫持失效：Claude 域名被解析成
  真实公网 IP，「DNS 泄漏」体检变红。
- 关掉 Tailscale 的 DNS 接管（`tailscale set --accept-dns=false`）之后，MagicDNS 名字
  （`node-a.tail-example.ts.net` 这类）在系统里就没解析器了；Clash 会把它当普通域名
  返回 fake-ip，Rex 之类的工具拿到 `198.18.x` 连过去直接失败。

做法：只让 Clash 在本地回答这些内网名字——把 Tailscale 的对端名与 `100.x` 地址写进
**当前订阅 profile 的 merge 文件**（`hosts:` 块），再热载一次。公共 DNS 一个字节不查，
系统级 DNS 设置一点不动。

用法：
  python3 scripts/tailscale_hosts.py --status        # 现状与解析检查
  python3 scripts/tailscale_hosts.py --sync --dry-run  # 看会写什么，不动文件
  python3 scripts/tailscale_hosts.py --sync          # 写 merge（先备份）+ 热载 + 复验
  python3 scripts/tailscale_hosts.py --sync --no-reload

退出码：0 正常；1 写了但复验没通过；2 环境问题（没装 Tailscale / 找不到 merge 文件）。
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import pathlib
import re
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from proxy_guard import parse_profiles  # noqa: E402

VERGE_DIR = pathlib.Path.home() / "Library" / "Application Support" / "io.github.clash-verge-rev.clash-verge-rev"
TAILSCALE_CANDIDATES = (
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    "/opt/homebrew/bin/tailscale",
    "/usr/local/bin/tailscale",
)
# Tailscale 的 MagicDNS 解析器地址（v4 与 v6）；scutil --dns 里看到它们就说明
# Tailscale 正在接管系统 DNS。
TS_RESOLVERS = ("100.100.100.100", "fd7a:115c:a1e0::53")
FAKE_IP_NET = ipaddress.ip_network("198.18.0.0/15")
IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def run(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        return 1, f"{type(error).__name__}: {error}"
    out = (proc.stdout or b"").decode("utf-8", "replace")
    err = (proc.stderr or b"").decode("utf-8", "replace")
    return proc.returncode, out + err


def find_tailscale() -> str | None:
    for candidate in TAILSCALE_CANDIDATES:
        if pathlib.Path(candidate).exists():
            return candidate
    return shutil.which("tailscale")


def tailscale_status(cli: str) -> dict | None:
    """`tailscale status --json` 的裁剪版；读不到返回 None。"""
    code, body = run([cli, "status", "--json"])
    if code != 0:
        return None
    try:
        doc = json.loads(body)
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None

    def entry(node: dict) -> dict | None:
        name = str(node.get("DNSName") or "").rstrip(".")
        ips = [str(ip) for ip in (node.get("TailscaleIPs") or [])]
        v4 = [ip for ip in ips if IPV4.match(ip)]
        if not name or not v4:
            return None
        return {"name": name, "ip": v4[0], "online": bool(node.get("Online", True))}

    self_entry = entry(doc.get("Self") or {})
    peers = []
    for peer in (doc.get("Peer") or {}).values():
        item = entry(peer or {})
        if item:
            peers.append(item)
    peers.sort(key=lambda p: p["name"])
    tailnet = ""
    if self_entry:
        parts = self_entry["name"].split(".", 1)
        tailnet = parts[1] if len(parts) > 1 else ""
    corp_dns = None
    code_p, prefs = run([cli, "debug", "prefs"])
    if code_p == 0:
        match = re.search(r'"CorpDNS"\s*:\s*(true|false)', prefs)
        if match:
            corp_dns = match.group(1) == "true"
    return {"self": self_entry, "peers": peers, "tailnet": tailnet, "corp_dns": corp_dns}


def active_merge_file() -> tuple[pathlib.Path | None, str]:
    """当前订阅的 merge（全局扩展）文件；返回 (路径, 原因)。"""
    profiles_yaml = VERGE_DIR / "profiles.yaml"
    if not profiles_yaml.exists():
        return None, "不是 Clash Verge Rev 的目录（找不到 profiles.yaml）"
    doc = parse_profiles(profiles_yaml.read_text(encoding="utf-8", errors="replace"))
    uid = doc.get("current")
    item = (doc.get("items") or {}).get(uid) or {}
    merge_uid = item.get("merge")
    if not merge_uid:
        return None, f"当前订阅 {uid or '(未知)'} 没有 merge 文件（Verge → 订阅 → 编辑 → 全局扩展 → Merge）"
    merge_item = (doc.get("items") or {}).get(merge_uid) or {}
    name = merge_item.get("file")
    if not name:
        return None, f"merge uid {merge_uid} 找不到对应文件"
    path = VERGE_DIR / "profiles" / name
    if not path.exists():
        return None, f"merge 文件不存在：{path}"
    return path, ""


def hosts_mapping(status: dict, names: list[str] | None = None,
                  include_self: bool = False) -> dict:
    """要写进 hosts 的 {名字: IPv4}，按 Tailscale 对端顺序。

    默认只写对端，不写本机自己的 MagicDNS 名字——本机名字解析到自己的 100.x
    没有实际用途，少一条少一个要维护的项。
    """
    out: dict = {}
    entries = list(status.get("peers") or [])
    if include_self and status.get("self"):
        entries.append(status["self"])
    wanted = set(names or [])
    for item in entries:
        if wanted and item["name"] not in wanted:
            continue
        out[item["name"]] = item["ip"]
    return out


def _hosts_block(lines: list[str]) -> tuple[int, int] | None:
    """找到 top-level `hosts:` 块的 [start, end) 行号。"""
    start = None
    for i, line in enumerate(lines):
        if re.match(r"^hosts:\s*$", line):
            start = i
            break
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        line = lines[j]
        if line and not line[0].isspace() and not line.lstrip().startswith("#"):
            end = j
            break
    return start, end


def read_hosts(text: str) -> dict:
    """从 merge 文本里读出已有的 hosts 映射（保持顺序）。"""
    lines = text.splitlines()
    bounds = _hosts_block(lines)
    if not bounds:
        return {}
    start, end = bounds
    out: dict = {}
    for line in lines[start + 1:end]:
        match = re.match(r"^\s+['\"]?([^'\":]+)['\"]?\s*:\s*(\S+)\s*$", line)
        if match:
            out[match.group(1).strip()] = match.group(2)
    return out


def upsert_hosts(text: str, mapping: dict) -> str:
    """把 mapping 写进 top-level `hosts:` 块；已有项原地更新，缺的追加。

    没有 hosts 块就在文件末尾新建。其它键、注释、顺序一律不动。
    """
    lines = text.splitlines()
    bounds = _hosts_block(lines)
    if bounds is None:
        block = ["hosts:"] + [f"  {name}: {ip}" for name, ip in mapping.items()]
        tail = lines[:]
        while tail and not tail[-1].strip():
            tail.pop()
        return "\n".join(tail + [""] + block) + "\n"
    start, end = bounds
    body = lines[start + 1:end]
    indent = "  "
    for line in body:
        if line.strip():
            indent = line[: len(line) - len(line.lstrip())]
            break
    remaining = dict(mapping)
    new_body = []
    for line in body:
        match = re.match(r"^(\s+)['\"]?([^'\":]+)['\"]?\s*:\s*(\S+)\s*$", line)
        if match and match.group(2).strip() in remaining:
            name = match.group(2).strip()
            new_body.append(f"{match.group(1)}{name}: {remaining.pop(name)}")
        else:
            new_body.append(line)
    for name, ip in remaining.items():
        new_body.append(f"{indent}{name}: {ip}")
    return "\n".join(lines[:start + 1] + new_body + lines[end:]) + "\n"


def system_dns_servers() -> list[str]:
    code, body = run(["scutil", "--dns"])
    if code != 0:
        return []
    out = []
    for match in re.finditer(r"nameserver\[\d+\]\s*:\s*(\S+)", body):
        if match.group(1) not in out:
            out.append(match.group(1))
    return out


def resolve(host: str) -> list[str]:
    code, body = run(["dig", "+short", host], timeout=10)
    if code != 0:
        return []
    return [ip for ip in body.split() if IPV4.match(ip) or ":" in ip]


def verify(mapping: dict) -> dict:
    """复验：内网名字应解析成 100.x，公共域名应解析成 fake-ip。"""
    out = {"hosts": {}, "public_ok": None, "dns_servers": system_dns_servers()}
    for name in list(mapping)[:3]:
        ips = resolve(name)
        out["hosts"][name] = ips
        out.setdefault("hosts_ok", True)
        if not ips or not any(ip.startswith("100.") for ip in ips):
            out["hosts_ok"] = False
    public = resolve("example.com")
    out["public"] = public
    if public:
        out["public_ok"] = any(ipaddress.ip_address(ip) in FAKE_IP_NET
                               for ip in public if IPV4.match(ip))
    return out


def hot_reload(mapping: dict) -> tuple[bool, str]:
    """把 hosts 塞进运行时配置并 PUT /configs，让内核立刻认这些名字。"""
    runtime = VERGE_DIR / "clash-verge.yaml"
    if not runtime.exists():
        return False, f"找不到运行时配置：{runtime}"
    text = runtime.read_text(encoding="utf-8", errors="replace")
    payload = upsert_hosts(text, mapping)
    try:
        import proxy_guard as pg
        sock = pg.find_socket()
    except Exception:  # noqa: BLE001
        sock = None
    if not sock:
        return False, "没有可用的 mihomo 控制接口（热载跳过；重启 Clash Verge 后生效）"
    code, out = run(["curl", "-s", "--max-time", "15", "--unix-socket", sock,
                     "-X", "PUT", "-H", "Content-Type: application/json",
                     "-d", json.dumps({"payload": payload, "force": True}),
                     "http://localhost/configs"])
    return code == 0, ("成功" if code == 0 else out[:200])


def write_merge(path: pathlib.Path, mapping: dict) -> tuple[pathlib.Path, bool]:
    """备份后写 merge 文件；返回 (备份路径, 是否有改动)。"""
    text = path.read_text(encoding="utf-8", errors="replace")
    new_text = upsert_hosts(text, mapping)
    if new_text == text:
        return path, False
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(path.name + f".bak-ts-hosts-{stamp}")
    shutil.copy2(path, backup)
    path.write_text(new_text, encoding="utf-8")
    return backup, True


def collect(names: list[str] | None = None, include_self: bool = False
            ) -> tuple[int, dict | None, dict, pathlib.Path | None]:
    """收齐环境信息；返回 (退出码, status, mapping, merge_path)。"""
    cli = find_tailscale()
    if not cli:
        print("没找到 Tailscale CLI（/Applications/Tailscale.app 或 PATH 里都没有）。",
              file=sys.stderr)
        return 2, None, {}, None
    status = tailscale_status(cli)
    if status is None:
        print(f"读不到 Tailscale 状态：{cli} status --json 失败（App 没登录或没在跑？）",
              file=sys.stderr)
        return 2, None, {}, None
    mapping = hosts_mapping(status, names, include_self)
    merge_path, why = active_merge_file()
    if merge_path is None:
        print(f"找不到当前订阅的 merge 文件：{why}", file=sys.stderr)
        return 2, status, mapping, None
    return 0, status, mapping, merge_path


def show_status(status: dict, mapping: dict, merge_path: pathlib.Path) -> int:
    print("== Tailscale × Clash DNS 适配 ==")
    print(f"tailnet      ：{status.get('tailnet') or '(未知)'}")
    print(f"CorpDNS      ：{'开（Tailscale 正在接管系统 DNS）' if status.get('corp_dns') else '关' if status.get('corp_dns') is not None else '读不到'}")
    print(f"系统解析器   ：{', '.join(system_dns_servers()[:3]) or '(读不到)'}")
    print(f"merge 文件   ：{merge_path}")
    existing = read_hosts(merge_path.read_text(encoding="utf-8", errors="replace"))
    print(f"已有的 hosts ：{len(existing)} 条")
    for item in (status.get("peers") or []) + ([status["self"]] if status.get("self") else []):
        name, ip = item["name"], item["ip"]
        now = existing.get(name)
        mark = "✓" if now == ip else ("!" if now else "·")
        print(f"  {mark} {name:42s} {ip:16s} {'' if now is None else ('已写成 ' + now if now != ip else '')}")
    first = mapping and next(iter(mapping))
    if first:
        print(f"\n解析检查：dig {first} -> {resolve(first) or '(无结果)'}")
    return 0


def sync(mapping: dict, merge_path: pathlib.Path, dry_run: bool,
         reload: bool) -> int:
    if not mapping:
        print("Tailscale 里没有可映射的 IPv4 对端。", file=sys.stderr)
        return 2
    text = merge_path.read_text(encoding="utf-8", errors="replace")
    existing = read_hosts(text)
    missing = {k: v for k, v in mapping.items() if existing.get(k) != v}
    print(f"要写 {len(mapping)} 条 hosts（新增/更新 {len(missing)} 条）：")
    for name, ip in mapping.items():
        old = existing.get(name)
        if old is None:
            print(f"  + {name}: {ip}")
        elif old != ip:
            print(f"  ~ {name}: {old} -> {ip}")
    if not missing:
        print("merge 里的 hosts 已经是最新的。")
    if dry_run:
        print("\n--dry-run：没有写文件。")
        return 0
    backup, changed = write_merge(merge_path, mapping)
    if changed:
        print(f"已写入 merge：{merge_path}\n备份：{backup}")
    else:
        print("merge 文件没有变化（已是最新），不重复写。")
    if reload:
        ok, msg = hot_reload(mapping)
        print(f"热载：{msg}")
    else:
        print("提示：merge 文件要等 Clash Verge 重新生成配置才生效（重启 Verge，或在 Verge 里重新应用该订阅）。")
    result = verify(mapping)
    print("\n复验：")
    for name, ips in result["hosts"].items():
        print(f"  dig {name} -> {ips or '(无结果)'}")
    print(f"  dig example.com -> {result.get('public') or '(无结果)'}")
    ok_hosts = result.get("hosts_ok")
    ok_public = result.get("public_ok")
    if ok_hosts and ok_public:
        print("✓ 内网名字由 Clash 本地回答，公共域名仍然走 fake-ip。")
        return 0
    print("⚠ 复验没通过：确认 Clash Verge 正在运行、该订阅的 merge 已生效，再跑一次 --status。")
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Tailscale × Clash：给 *.ts.net 在 Clash 写本地 hosts")
    ap.add_argument("--status", action="store_true", help="看现状（默认动作）")
    ap.add_argument("--sync", action="store_true", help="把 Tailscale 对端同步进 merge 的 hosts")
    ap.add_argument("--dry-run", action="store_true", help="只打印要写什么，不动文件")
    ap.add_argument("--no-reload", action="store_true", help="--sync 不热载运行时配置")
    ap.add_argument("--names", help="逗号分隔，只同步这些 Tailscale 名字")
    ap.add_argument("--include-self", action="store_true",
                    help="连本机的 MagicDNS 名字一起写（默认只写对端）")
    args = ap.parse_args(argv)

    names = [n.strip() for n in (args.names or "").split(",") if n.strip()]
    code, status, mapping, merge_path = collect(names or None, args.include_self)
    if code != 0 or status is None or merge_path is None:
        return code
    if args.sync:
        return sync(mapping, merge_path, args.dry_run, not args.no_reload)
    return show_status(status, mapping, merge_path)


if __name__ == "__main__":
    raise SystemExit(main())
