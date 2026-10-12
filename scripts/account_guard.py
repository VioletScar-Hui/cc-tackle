#!/usr/bin/env python3
"""claude-account-guard —— 按《你的 Claude 账号是怎么被封的》四层防线做本机体检与加固。

设计沿用 skills/claude-cleanup 的安全约定：
  * 只读审计永远安全，任何写操作都要真实 TTY + 逐项询问 + 最终 CONFIRM；
  * 第一个写操作是备份，失败即停；
  * 需要 root 时只在终端原生 sudo 隐藏提示里输密码，脚本从不读取或保存密码；
  * 每项改动之后立刻复验，验证失败即报错并保留备份。

用法：
  python3 scripts/account_guard.py --audit      # 只读体检，输出报告
  python3 scripts/account_guard.py              # 交互式加固
  python3 scripts/account_guard.py --audit --json   # 机器可读
"""

from __future__ import annotations

import argparse
import datetime as dt
import hmac
import json
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import unicodedata
import zoneinfo
import sys
import tempfile

HOME = pathlib.Path.home()
SETTINGS = HOME / ".claude" / "settings.json"
BACKUP_ROOT = HOME / "ClaudeGuardBackups"

TELEMETRY_KEYS = (
    "DISABLE_TELEMETRY",
    "DISABLE_ERROR_REPORTING",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
)

# 三方客户端痕迹：文章 §1 点名「把订阅接到第三方工具」是国庆这轮的高发类
THIRD_PARTY_MARKERS = (
    ".openclaw", ".opencode", ".cline", ".roo", ".sub2api", ".new-api",
    ".claude-code-router", ".llm", ".claude-devtools", ".aider",
    "Library/Application Support/OpenClaw",
    "Library/Application Support/claude-code-router",
)

# 文章 §4：别在 system prompt 或 CLAUDE.md 里写自己人在哪
GEO_WORDS = (
    "北京", "上海", "深圳", "广州", "杭州", "成都", "中国", "大陆", "国内",
    "Beijing", "Shanghai", "Shenzhen", "China", "mainland",
)

CLASH_SOCK = pathlib.Path("/tmp/verge/verge-mihomo.sock")
# Clash Verge 出厂就带这个 secret，没改过的话它适用于所有本机部署；
# 改过就用环境变量 CLASH_SECRET 覆盖，别把某个人的 secret 写进代码。
CLASH_SECRET = os.environ.get("CLASH_SECRET", "set-your-secret")


def clash_dir() -> pathlib.Path:
    """Clash Verge 的配置目录。

    故意做成函数而不是模块级常量：测试会把 HOME 指到沙箱目录，而常量在 import 那一刻
    就定死了，改不动。测试里那条「备份不许跑出临时家目录」的断言正是这么抓到它的。
    """
    return HOME / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev"


def clash_config() -> pathlib.Path:
    """Clash Verge 生成的那份运行配置（订阅 + 增强文件合成后的产物）。"""
    return clash_dir() / "clash-verge.yaml"

# 国内解析器。出现在 Clash 的主 nameserver 列表里，就意味着「解析国外域名的请求交给
# 国内服务器处理」；而 Clash 自己的 DNS 查询默认不跟规则走（respect-rules 缺省为 false），
# 是从真实 IP 直发的。两个条件叠在一起，结果是国外域名的解析动作暴露给了国内解析器。
# 放在 nameserver-policy 的 geosite:cn,private 底下则是正常的——国内域名本来就该走国内。
CN_RESOLVER_IPS = (
    "223.5.5.5", "223.6.6.6", "119.29.29.29", "119.28.28.28",
    "114.114.114.114", "114.114.115.115", "180.76.76.76",
)
CN_RESOLVER_MARKERS = (
    "alidns", "dnspod", "doh.pub", "114dns", "baidu", "qihui", "360.cn", "tencentdns",
)

# 修好之后主解析器该长什么样：全在境外，且随规则走代理
FOREIGN_NAMESERVERS = ("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query")
# fallback 另给一组，免得和 nameserver 完全重合
FOREIGN_FALLBACK = ("https://1.0.0.1/dns-query", "https://8.8.4.4/dns-query")

# TUN 起来时要把到达虚拟网卡的 DNS 查询接管过来。这个键在主流的 mihomo 配置里写作
# `tun.dns-hijack: [any:53]`（注意它挂在 tun 底下，不在 dns 块里）。缺了它，发往
# 任意解析器 53 端口的查询会被原样转出去，落到系统配的那个解析器上——本机是北京联通
# 与阿里，等于国内域名之外的东西也跟着一起暴露。
DNS_HIJACK = ("any:53",)

# 文章 §2.2「很多人漏这一步」的那个开关所在的位置。非 root 连读都读不到。
LOCATIOND_PLIST = pathlib.Path("/var/db/locationd/clients.plist")

# 文章 §2.5 ④ 点名的代理残留端口
PROXY_RESIDUE_PORTS = {"7890", "7897", "1080", "8118", "6152"}

# 文章 2.3 要区分的两类 ASN。归一化后再匹配，见 classify_asn()。
HOSTING_MARKERS = (
    "hosting", "cloud", "vps", "datacenter", "data center", "amazon", "aws",
    "google", "digitalocean", "vultr", "ovh", "hetzner", "linode", "alibaba",
    "tencent", "oracle", "choopa", "leaseweb", "colocation", "server",
)
ISP_MARKERS = (
    "att", "verizon", "comcast", "isp", "telecom", "unicom", "mobile",
    "broadband", "cable", "communication", "enterprise", "charter", "cox",
    "frontier", "centurylink", "spectrum", "residential",
)


def classify_asn(org: str) -> str:
    """把 ipinfo 的 org 字段归类成机房 / 住宅 / 未知。纯函数，便于测试。

    归一化是必须的：ipinfo 的 org 形如 "AS7018 AT&T Enterprises, LLC"，
    直接拿小写原文匹配 "att" 会漏，因为 "at&t" 里并没有连续的 att。
    先把 & - , 去掉再比，才能命中。
    """
    low = (org or "").lower().replace("&", "").replace("-", " ").replace(",", " ")
    if any(k in low for k in HOSTING_MARKERS):
        return "疑似机房 IP（Hosting）"
    if any(k in low for k in ISP_MARKERS):
        return "疑似住宅/ISP"
    return "无法归类，需人工看 ipinfo 页面的 AS Type"


# ────────────────────────── 基础工具 ──────────────────────────

def run(cmd: list[str], timeout: int = 20, env: dict | None = None) -> tuple[int, str]:
    """执行命令，返回 (退出码, 合并输出)。任何异常都降级为退出码 1。

    env 是**叠加**在现有环境上的变量，不是替换。体检时调 CLI 必须传
    DISABLE_AUTOUPDATER=1（见 check_client_integrity）：不传的话这次体检会
    顺手把 CLI 升到最新，而同一个函数下面正要数 versions 目录里留了几份、
    占多少空间 —— 等于一边量一边把被测对象改了。
    """
    full = {**os.environ, **env} if env else None
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           check=False, env=full)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""


VERIFY_TOKEN_BYTES = 24
VERIFY_MAX_BODY = 65536


def _verify_token() -> str:
    """本地复核服务的一次性令牌。

    为什么需要：media / WebRTC / Intl 这三处复核各自起一个本地 HTTP 服务，
    绑在 127.0.0.1、端口随机。**端口随机不等于有鉴权** —— 本机任何进程都能
    扫到这个端口，往上 POST 一份「摄像头=denied」，表就会把没测过的东西
    报成已解决。令牌当 URL 路径前缀，不知道令牌就取不到页面、也投不进结果。
    """
    return secrets.token_hex(VERIFY_TOKEN_BYTES)


def _verify_route(path: str, token: str) -> str | None:
    """把请求路径归一化成路由名；令牌不对一律返回 None（调用方回 404）。

    用 compare_digest 而不是 == ：都是本机的东西，但比较令牌不该有短路。
    """
    clean = path.split("?", 1)[0].split("#", 1)[0]
    parts = [seg for seg in clean.split("/") if seg]
    if not parts or not hmac.compare_digest(parts[0], token):
        return None
    if len(parts) == 1:
        return "/"
    if len(parts) == 2 and parts[1] == "result":
        return "/result"
    return None


# 带凭据的 URL：scheme://user:pass@host。要求必须有 scheme://，
# 免得把邮箱（user@example.com）也当成凭据抹掉。
URL_CRED_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/@\s]*@")


def redact_credentials(text: str) -> str:
    """把 URL 里的用户名密码抹掉：scheme://user:pass@host → scheme://***@host。

    为什么要做：这些字符串会同时进终端输出**和** audit JSON 报告，而报告会被
    贴进聊天、存进备份目录、也可能被当成附件发出去。`proxy=http://user:pass@1.2.3.4:8080`
    是很常见的写法，照原样打出来等于把凭据又抄了一份到别处。
    先抹再截断 —— 反过来的话凭据可能被截成半截，正则就匹配不上了。
    """
    if not text:
        return text
    return URL_CRED_RE.sub(lambda m: m.group(1) + "***@", text)


def running_under_claude() -> bool:
    """向上追溯父进程，判断是否由 Claude Code 启动。"""
    pid = os.getpid()
    for _ in range(12):
        code, out = run(["ps", "-o", "ppid=,comm=", "-p", str(pid)])
        if code or not out.strip():
            return False
        parts = out.strip().split(None, 1)
        if len(parts) < 2:
            return False
        ppid, comm = parts[0], parts[1].lower()
        if "claude" in comm and "claude-" not in comm:
            return True
        if ppid in ("0", "1"):
            return False
        pid = int(ppid)
    return False


def list_network_services() -> list[str]:
    """列出所有网络服务名，跳过表头和已禁用的服务。

    注意先 strip 再判断 "*"：networksetup 对禁用服务加星号，
    早期版本在未 strip 的原始行上判断 startswith("*")，
    遇到带前导空格的输出就漏掉过滤，把 "*xxx" 当成服务名传下去。
    """
    code, body = run(["networksetup", "-listallnetworkservices"])
    if code:
        return []
    names = []
    for line in body.splitlines()[1:]:          # 第一行是星号说明
        name = line.strip()
        if not name or name.startswith("*"):
            continue
        names.append(name)
    return names


def read_json(path: pathlib.Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def write_json(path: pathlib.Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".guard.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def protected_snapshot() -> dict[str, bytes]:
    """记录受保护文件的内容，用于事后比对是否被误改。"""
    keep = {}
    for p in (SETTINGS, HOME / ".claude.json", HOME / ".zshrc", HOME / ".zprofile", HOME / ".npmrc"):
        try:
            keep[str(p)] = p.read_bytes()
        except OSError:
            pass
    return keep


def protected_verify(before: dict[str, bytes], allow: set[str]) -> list[str]:
    """返回被意外改动的受保护文件列表（allow 中的除外）。"""
    changed = []
    for path, blob in before.items():
        if path in allow:
            continue
        try:
            if pathlib.Path(path).read_bytes() != blob:
                changed.append(path)
        except OSError:
            changed.append(path + " (读取失败)")
    return changed


# ────────────────────────── A 类：只读体检 ──────────────────────────

def export_state_path() -> pathlib.Path:
    """上一次记下的出口放在哪。

    写成函数而不是模块级常量：模块级常量在 import 那一刻就把 HOME 定死了，
    测试把 HOME 指到沙箱也带不走它，会写到真实家目录里去。
    """
    return HOME / ".local" / "state" / "claude-guard" / "export-ip.json"


def load_export_history() -> dict:
    """读上一次记下的出口。没记录过、或文件坏了，一律当成没有历史。"""
    try:
        data = json.loads(export_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_export_history(info: dict) -> None:
    """记下这次的出口，供下次体检比对。写不进去就算了，不能因此让体检失败。"""
    if not info.get("ip"):
        return  # 取不到出口时不要把上一份好记录冲掉
    path = export_state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "ip": info.get("ip"), "country": info.get("country"), "city": info.get("city"),
            "org": info.get("org"), "checkedAt": now_stamp(),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        return
    hand_back_ownership(path)


def check_export_ip() -> dict:
    """A8 出口 IP 与 ASN 类型。文章 2.3、2.5①。"""
    out = {"ip": None, "org": None, "country": None, "city": None, "timezone": None,
           "verdict": "未知", "sources": {}}
    for name, url in (("ipinfo", "https://ipinfo.io/json"), ("ipify", "https://api.ipify.org?format=json")):
        code, body = run(["curl", "-s", "--max-time", "10", "--noproxy", "*", url])
        if code or not body.strip():
            continue
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            continue
        out["sources"][name] = data.get("ip")
        if name == "ipinfo":
            out.update(
                ip=data.get("ip"), org=data.get("org"), country=data.get("country"),
                city=data.get("city"), timezone=data.get("timezone"),
            )
    ip = out.get("ip")
    if not ip:
        out["verdict"] = "取不到出口 IP"
        return out
    code, body = run(["curl", "-s", "--max-time", "10", "--noproxy", "*", f"https://ipinfo.io/{ip}/json"])
    if not code and body.strip():
        try:
            d = json.loads(body)
            org = (d.get("org") or "")
            out["org"] = org
            out["timezone"] = d.get("timezone") or out.get("timezone")
            out["verdict"] = classify_asn(org)
        except json.JSONDecodeError:
            pass

    # 交叉核对第二个地理库。同一个 IP 在不同库上可能落在不同城市——实测
    # 同一个出口 IP 在 ipinfo 是 New York City、在 ip-api 却是 Dallas。这个分歧本身
    # 就是信号：出口的地理归属不稳定，检测方按哪个库判都不奇怪。只看一个库会
    # 把这件事吞掉，所以显式记下来。
    code, body = run([
        "curl", "-s", "--max-time", "10", "--noproxy", "*",
        f"http://ip-api.com/json/{ip}?fields=status,city,regionName,timezone,isp",
    ])
    if not code and body.strip():
        try:
            d2 = json.loads(body)
            if d2.get("status") == "success":
                out["geo_second"] = {
                    "city": d2.get("city"), "region": d2.get("regionName"),
                    "timezone": d2.get("timezone"), "isp": d2.get("isp"),
                }
                if d2.get("city") and out.get("city") and d2["city"] != out["city"]:
                    out["geo_conflict"] = f"{out['city']} / {d2['city']}"
        except json.JSONDecodeError:
            pass
    # 文章 §2.5① 要求「城市别每次变」、§9 要求「出口国家和上次一致」，而这一条只能靠
    # 和上一次比才看得出来，单看这一次永远是「现在的出口是谁」。所以把这次的出口记下来。
    # 变了不等于错——换订阅、服务商换 IP 都会变——但它是文章里排最前面的信号，得让人看见。
    prev = load_export_history()
    out["previous"] = prev or None
    out["changed"] = False
    out["changed_fields"] = []
    if prev.get("ip") and prev.get("ip") != out.get("ip"):
        out["changed"] = True
        for key, label in (("ip", "IP"), ("country", "国家"), ("city", "城市"), ("org", "org")):
            if prev.get(key) and out.get(key) and str(prev[key]) != str(out[key]):
                out["changed_fields"].append(f"{label} {prev[key]} → {out[key]}")
    save_export_history(out)
    return out


def check_proxy_residue() -> dict:
    """A1 + B4 系统代理残留。文章 2.5④，文章称『Mac 很关键』。

    区分两种情形：
      * residue —— 未启用但存了 127.0.0.1:7897 一类值，Clean Verge 关掉系统代理后留下的；
      * enabled —— 系统代理仍处于启用状态，与文章 2.4「开 TUN 后关掉系统代理」相悖。
    """
    out = {"scutil": {}, "enabled": [], "network_services": [], "residue": []}
    code, body = run(["scutil", "--proxy"])
    for key in ("HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable"):
        m = re.search(rf"{key}\s*:\s*(\d+)", body)
        out["scutil"][key] = int(m.group(1)) if m else None
        if out["scutil"][key] == 1:
            out["enabled"].append(key)
    for svc in list_network_services():
        for getter, setter in (
            ("getwebproxy", "webproxy"),
            ("getsecurewebproxy", "securewebproxy"),
            ("getsocksfirewallproxy", "socksfirewallproxy"),
        ):
            code, body = run(["networksetup", f"-{getter}", svc])
            if code:
                continue
            enabled = re.search(r"Enabled:\s*(\w+)", body)
            server = re.search(r"Server:\s*(\S+)", body)
            port = re.search(r"Port:\s*(\d+)", body)
            entry = {
                "service": svc,
                "kind": setter,
                "enabled": (enabled.group(1) if enabled else "?"),
                "server": server.group(1) if server else "",
                "port": port.group(1) if port else "",
            }
            out["network_services"].append(entry)
            # 只在「未启用但存了值」时算残留；启用中的一律不动
            if entry["enabled"].lower() == "no" and entry["port"] in PROXY_RESIDUE_PORTS:
                out["residue"].append(entry)
    return out


def check_terminal_env() -> dict:
    """A1 终端代理与中转残留。文章 2.5⑤ 的四条：环境变量、shell 启动文件、
    npm/git 配置、settings.json；另加一条 Homebrew（文章里没有，属补充项）。

    文章给的命令是 `env | grep -iE "proxy|anthropic|claude"`，但这条正则会
    把任何名字里带 claude 的变量都算成残留（例如本 skill 自己的
    CLAUDE_GUARD_PROJECT_ROOTS、以及 CLAUDE_CODE_* 一堆正常变量），
    所以这里拆成三档：真正需要处理的代理与端点变量、只需知会的其它变量。

    补掉三处很容易漏的：settings.json 的 env 里放的代理键（文章 2.5⑤ 只让
    `cat` 这个文件、没让人 grep，proxy 那半原来既不会报也不会清）、直接看
    ~/.npmrc（npm config get 看不到带作用域的写法）、以及 brew config。
    """
    out = {"env_hits": [], "env_info": [], "rc_files": {}, "settings_env": {},
           "settings_proxy": [], "npmrc": [], "brew": {}, "npm": {}, "git": {}}
    route_keys = re.compile(r"base_url|auth_token|api_key", re.I)
    for k, v in os.environ.items():
        kl = k.lower()
        if "proxy" in kl:
            out["env_hits"].append(f"{k}={redact_credentials(v)[:80]}")   # 代理变量：要处理
        elif k.startswith(("ANTHROPIC_", "CLAUDE_", "CLAUDE_CODE_")) and route_keys.search(k):
            out["env_hits"].append(f"{k}={redact_credentials(v)[:80]}")   # 端点/凭据：要处理
        elif "claude" in kl or "anthropic" in kl:
            out["env_info"].append(f"{k}={v[:60]}")          # 其余同名变量：仅知会
    for name in (".zshrc", ".zprofile", ".profile", ".bashrc", ".zshenv", ".bash_profile", ".zlogin"):
        p = HOME / name
        if not p.exists():
            continue
        # 存结构化行号，清理时才能精确定位；只存字符串的话没法安全删除
        hits = []
        for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
            if re.search(r"proxy|ANTHROPIC|CLAUDE", line, re.I) and not line.strip().startswith("#"):
                hits.append({"line": n,
                             "text": redact_credentials(line.strip())[:120]})
        out["rc_files"][name] = hits
    data = read_json(SETTINGS, {})
    out["settings_env"] = dict(data.get("env", {}) or {})
    # 文章 2.5⑤ 只让人 `cat ~/.claude/settings.json`，清单里那条第 6 项更细，是
    # `grep -iE "proxy|base_url|anthropic_"`。端点/凭据那半由
    # check_anthropic_base_url 管，proxy 这半原先没人管 —— env 里放一个 HTTPS_PROXY
    # 既不会被报出来也不会被清掉，等于漏了一整类。
    out["settings_proxy"] = sorted(k for k in out["settings_env"] if "proxy" in k.lower())
    # ~/.npmrc 也要直接看：npm config get 读的是生效值，带作用域的写法
    # （//registry/:xxx 那种）它反映不出来。文章 2.5⑤ 没列这一条，是后加的。
    npmrc = HOME / ".npmrc"
    if npmrc.exists():
        for n, line in enumerate(npmrc.read_text(errors="replace").splitlines(), 1):
            if re.search(r"proxy", line, re.I) and not line.strip().startswith(("#", ";")):
                out["npmrc"].append({"line": n,
                                     "text": redact_credentials(line.strip())[:120]})
    for key, cmd in (
        ("npm_proxy", ["npm", "config", "get", "proxy"]),
        ("npm_https_proxy", ["npm", "config", "get", "https-proxy"]),
    ):
        code, body = run(cmd)
        out["npm"][key] = body.strip()
    for key, cmd in (
        ("http.proxy", ["git", "config", "--global", "--get", "http.proxy"]),
        ("https.proxy", ["git", "config", "--global", "--get", "https.proxy"]),
    ):
        code, body = run(cmd)
        out["git"][key] = body.strip()
    # Homebrew 这一条不在文章里（全文搜 brew 零命中），是清单里补的。
    # 实测 Homebrew 7 只把（小写的）http_proxy / https_proxy / all_proxy 打进 config
    # —— 把大小写六个都设上再跑 diff，多出来的只有小写那三行，大写那三个它一句不提。
    # 所以这条的能量是 env | grep -i proxy 的子集。照文章原样实现是为了对齐，
    # 不是把它当成独立的一层。匹配不区分大小写：brew 真打出大写也接得住，而它
    # 只有真设了代理才会打，不存在误报。
    code, body = run(["brew", "config"], timeout=30)
    out["brew"] = {"installed": code == 0, "proxy": []}
    if code == 0:
        for line in body.splitlines():
            m = re.match(r"\s*((?:https?|all|no)_proxy)\s*:\s*(\S.*?)\s*$", line, re.I)
            if m:
                out["brew"]["proxy"].append(
                    f"{m.group(1).lower()}={redact_credentials(m.group(2))}")
    return out


def check_anthropic_base_url() -> dict:
    """A2 ANTHROPIC_BASE_URL 与中转端点残留。文章 2.5⑤ 重点。"""
    out = {"hits": [], "searched": []}
    targets = [
        SETTINGS,
        HOME / ".claude.json",
        HOME / ".claude" / "settings.local.json",
        HOME / ".codex" / "config.toml",
        HOME / ".dsh" / "settings.yaml",
        HOME / ".zshrc",
        HOME / ".zprofile",
        HOME / ".profile",
    ]
    pat = re.compile(r"ANTHROPIC_BASE_URL|anthropic_base_url|baseURL|base_url|api\.deepseek|8\.211\.146|/v1\b", re.I)
    for p in targets:
        out["searched"].append(str(p))
        if not p.exists():
            continue
        for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
            if pat.search(line):
                safe = re.sub(r"(sk-[A-Za-z0-9]{6})[A-Za-z0-9_\-]*", r"\1…", line.strip())
                out["hits"].append({"file": str(p), "line": n, "text": safe[:160]})
    return out


def check_ipv6() -> dict:
    """A5 IPv6 泄漏。文章 2.5 可选加固。"""
    out = {"global_addresses": [], "services": {}}
    code, body = run(["ifconfig"])
    for line in body.splitlines():
        s = line.strip()
        if s.startswith("inet6") and "fe80" not in s and "::1" not in s:
            out["global_addresses"].append(s.split()[0])
    for svc in list_network_services():
        code, info = run(["networksetup", "-getinfo", svc])
        m = re.search(r"IPv6:\s*(\S+)", info)
        out["services"][svc] = m.group(1) if m else "?"
    return out


_FAKE_IP_CACHE: tuple | None = None


def _read_fake_ip_prefixes() -> tuple:
    """从 Clash 配置读出 fake-IP 段前缀，读不到就退回 mihomo 的默认值。

    原来这里把 `198.18.` / `198.19.` 写死在两处（DNS 判定和 WebRTC 的 TUN 判定）。
    问题是 fake-ip-range 是可配的：一旦改了段，两处判定会同时失效，而且**静默**
    失效——DNS 会报「出现真实公网 IP」，WebRTC 会漏掉 TUN 地址。所以改成读实际配置。
    """
    for p in (
        HOME / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml",
        CLASH_SOCK,
    ):
        try:
            if p.suffix in (".yaml", ".yml"):
                import yaml as _yaml
                cfg = _yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            else:
                continue
        except Exception:
            continue
        rng = ((cfg.get("dns") or {}).get("fake-ip-range") or "").strip()
        if "/" in rng:
            base = rng.split("/")[0].split(".")
            if len(base) >= 2:
                return (f"{base[0]}.{base[1]}.",)
    return ("198.18.", "198.19.")


def fake_ip_prefixes() -> tuple:
    """fake-IP 段的前缀，例如 `("198.18.",)`。第一次调用时读配置并缓存。"""
    global _FAKE_IP_CACHE
    if _FAKE_IP_CACHE is None:
        _FAKE_IP_CACHE = _read_fake_ip_prefixes()
    return _FAKE_IP_CACHE


def check_dns() -> dict:
    """A6 DNS 泄漏。文章 2.5③。

    判据要精确：真正的泄漏信号是「某个域名解析出了真实公网 IP」，
    而不是「fake-ip 生效了」。两者都说成 fake-ip 一个词会掩盖问题，
    所以这里按域名分别记录，把解析到真实 IP 的域名单独列出来。
    """
    out = {"resolved": [], "fake_ip": False, "real_ip_hosts": [], "system_dns": []}
    for host in ("example.com", "api.anthropic.com", "claude.ai"):
        code, body = run(["dig", "+short", host], timeout=10)
        ips = [ip for ip in body.split() if re.match(r"^[0-9a-fA-F:.]+$", ip)]
        for ip in ips:
            is_fake = ip.startswith(fake_ip_prefixes())
            out["resolved"].append({"host": host, "ip": ip, "fake": is_fake})
            if is_fake:
                out["fake_ip"] = True
        if ips and not any(i.startswith(fake_ip_prefixes()) for i in ips):
            out["real_ip_hosts"].append(host)
        if not ips:
            out["real_ip_hosts"].append(f"{host}(无解析结果)")
    code, body = run(["scutil", "--dns"])
    for m in re.finditer(r"nameserver\[\d+\]\s*:\s*(\S+)", body):
        if m.group(1) not in out["system_dns"]:
            out["system_dns"].append(m.group(1))
    return out


def _resolver_is_cn(entry: str) -> bool:
    """一条 nameserver 条目是不是国内的（认厂商域名，也认裸 IP）。"""
    s = (entry or "").strip().lower()
    if not s:
        return False
    if any(m in s for m in CN_RESOLVER_MARKERS):
        return True
    host = s.split("//")[-1].split("/")[0].split(":")[0]
    return host in CN_RESOLVER_IPS


def check_clash_dns() -> dict:
    """A6 的另一半：谁在替这台机器解析域名。

    2026-10-09 补。原来的 check_dns 只看「域名有没有解析成 fake-IP」，那只能证明
    TUN 劫持生效——劫持生效和解析器是谁完全是两件事。真正的泄漏就藏在后者：换成
    住宅代理订阅后，profile 自带的主解析器是阿里 `223.5.5.5`，而且 `respect-rules`
    整个丢了。browserleaks.com/dns 实测看到 25 个解析器里混着阿里杭州与联通北京的
    国内解析器，而 skill 当时报的是「全部落进
    fake-ip 段，TUN 劫持生效」——绿灯。这个漏检是用户自己发现的，不是工具发现的，
    所以补成独立检查项。

    信号分开报，因为它们的后果不一样：
      * `leaking`      —— 主 nameserver 里有国内解析器，国外域名的解析直接交给它们；
      * `leaking_fallback` —— fallback 里有国内解析器。这条容易漏：mihomo 是把
        nameserver 和 fallback **同时**查的（查完再按 fallback-filter 挑结果），
        所以 fallback 里的国内解析器照样会收到国外域名的查询；
      * `respect_rules` —— 缺这个键时 Clash 自己的 DNS 查询不跟规则走，是从真实 IP
        直发的（配的如果是境外解析器，还会被墙掉导致解析失败）；
      * `enabled`      —— `dns.enable` 被显式关掉时整个 DNS 模块不跑；
      * `hijack`       —— `tun.dns-hijack`，缺它时到达 TUN 的 53 端口查询不被接管，
        会照原样落到系统配的解析器上。只在 TUN 开着时才要求。

    读不到配置（没装 Clash、配置还没生成）时返回 found=False，让上层报「未检测」，
    绝不默认成干净。
    """
    out = {
        "config": str(clash_config()), "found": False, "nameserver": [],
        "fallback": [], "respect_rules": False, "policy_cn": [],
        "leaking": [], "leaking_fallback": [], "leak": False,
        "enabled": None, "tun_enabled": False, "hijack": [],
    }
    try:
        import yaml as _yaml
        cfg = _yaml.safe_load(clash_config().read_text(encoding="utf-8")) or {}
    except Exception:
        return out
    dns = cfg.get("dns") or {}
    if not dns:
        return out
    out["found"] = True
    ns = [str(x) for x in (dns.get("nameserver") or [])]
    out["nameserver"] = ns
    out["respect_rules"] = dns.get("respect-rules") is True
    for key, val in (dns.get("nameserver-policy") or {}).items():
        k = str(key).lower()
        if "cn" in k or "private" in k:
            out["policy_cn"] = [str(x) for x in (val or [])]
    fb = [str(x) for x in (dns.get("fallback") or [])]
    out["fallback"] = fb
    out["leaking"] = [x for x in ns if _resolver_is_cn(x)]
    out["leaking_fallback"] = [x for x in fb if _resolver_is_cn(x)]
    # 2026-10-10 补。文章 2.5 ③ 给的排查入口原话是「仍然看到国内 DNS，就检查 Clash
    # 配置里 DNS 是否开启、dns-hijack 是否生效」，而原来的检查只看了 nameserver、
    # fallback、respect-rules 三个键，恰好把这两个入口漏掉了——排查手册里让人查的东西
    # 自己没查，是最不该出现的一种漏。
    out["enabled"] = dns.get("enable")
    tun = cfg.get("tun") or {}
    out["tun_enabled"] = bool(tun.get("enable"))
    out["hijack"] = [str(x) for x in (tun.get("dns-hijack") or [])]
    out["leak"] = bool(out["leaking"] or out["leaking_fallback"])
    return out


def clash_dns_leaking(rep: dict) -> bool:
    """A6 里的 Clash 解析器检查是否处于「需要修」的状态。

    五条信号任一成立就算需要修：主 nameserver 或 fallback 里有国内解析器、
    respect-rules 没开、dns.enable 被显式关掉、或者 TUN 开着却没配 dns-hijack。
    后两条是 2026-10-10 按文章 2.5 ③ 的排查入口补的。

    dns-hijack 只在 TUN 开着时才要求：不走 TUN 的部署（纯系统代理）本来就没有这张
    虚拟网卡，那里缺 dns-hijack 是正常的，不该误报。

    没读到配置时报 False（未检测不等于有问题）。
    """
    c = (rep.get("A6_dns") or {}).get("clash") or {}
    if not c.get("found"):
       return False
    return (bool(c.get("leaking")) or bool(c.get("leaking_fallback"))
           or not c.get("respect_rules")
           or c.get("enabled") is False
           or (bool(c.get("tun_enabled")) and not c.get("hijack")))


def check_clash_groups() -> dict:
    """A12 Claude 流量有没有一条不自动切换、不直连的专用线路。

    两种模式都要能判，但要求不同——它们在 mihomo 里的行为完全不是一回事：

      * global 模式下内核一条规则都不执行，所有流量都交给 GLOBAL 组。所以这个
        模式里「绝不直连」看的是 GLOBAL 是不是指向 Claude 专用组；
      * rule 模式下规则照常执行（国内直连、其余走代理）。这时候 GLOBAL 指向谁
        根本不影响 Claude，该看的是 Claude 那几个域名有没有指向专用组的规则，
        以及兜底那一条会不会落到 DIRECT。

    第一版只认 global，把「mode=rule」直接判成问题——而 rule 正是国内直连、国外
    走代理所必需的模式。那等于把用户的选择当成故障，和之前把「台北时区 + 美国出口」
    判成矛盾的毛病是同一个。

    两种模式共同的要求：Claude 组必须是 select（不做健康检查、不自动切换）、
    只有一个成员、没有可切换的对象。
    """
    out = {
        "reachable": False, "mode": None, "tun": {}, "groups": [], "auto_switching": [],
        "global_now": None, "claude_group": {}, "fail_closed": {},
        "claude_rules": [], "fallback": None,
    }
    if not CLASH_SOCK.exists():
        return out

    def api(path):
        code, body = run([
            "curl", "-s", "--max-time", "8", "--unix-socket", str(CLASH_SOCK),
            "-H", f"Authorization: Bearer {CLASH_SECRET}", f"http://localhost{path}",
        ])
        if code or not body.strip():
            return None
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return None

    cfg = api("/configs")
    if cfg is None:
        return out
    out["reachable"] = True
    out["mode"] = cfg.get("mode")
    out["tun"] = cfg.get("tun", {})

    pj = api("/proxies")
    if pj is None:
        return out
    proxies = pj.get("proxies", {})
    for name, v in proxies.items():
        if v.get("type") in ("Selector", "Fallback", "URLTest", "LoadBalance"):
            entry = {"name": name, "type": v.get("type"), "now": v.get("now"),
                     "members": len(v.get("all", []))}
            if name != "GLOBAL":
                entry["healthcheck"] = bool(v.get("url") or v.get("interval"))
            out["groups"].append(entry)
            if v.get("type") in ("Fallback", "URLTest", "LoadBalance"):
                out["auto_switching"].append(name)

    gnow = proxies.get("GLOBAL", {}).get("now")
    claude = proxies.get("Claude", {})
    out["global_now"] = gnow
    members = claude.get("all", [])
    out["claude_group"] = {
        "name": "Claude",
        "type": claude.get("type"),
        "now": claude.get("now"),
        "members": members,
        "healthcheck": bool(claude.get("url") or claude.get("interval")),
    }

    # rule 模式下还要知道规则怎么写的
    rj = api("/rules")
    if rj is not None:
        rules = rj.get("rules") or []
        for x in rules:
            payload = str(x.get("payload") or "")
            # 两条都算：域名像 Claude 的，以及目标直接就是 Claude 组的。
            # 只按域名关键词匹配会漏掉 statsigapi.net 这种——它名字里既没有
            # anthropic 也没有 claude，但确实是一条喂给专用组的规则。
            by_name = payload and any(
                k in payload.lower() for k in ("anthropic", "claude", "160.79.104")
            )
            if by_name or x.get("proxy") == "Claude":
                out["claude_rules"].append(
                    {"type": x.get("type"), "payload": payload, "proxy": x.get("proxy")}
                )
        if rules:
            out["fallback"] = {"type": rules[-1].get("type"), "proxy": rules[-1].get("proxy")}

    reasons = []
    mode = out["mode"]
    if mode not in ("global", "rule"):
        reasons.append(f"mode={mode}，既不是 global 也不是 rule")
    elif mode == "global":
        # 全局模式下规则不执行，全部流量看 GLOBAL 指向谁
        if gnow != "Claude":
            reasons.append(f"全局模式下所有流量都走 GLOBAL，而 GLOBAL 指向 {gnow}")
    else:
        # 规则模式下看 Claude 域名有没有被引到专用组
        to_claude = [r for r in out["claude_rules"] if r.get("proxy") == "Claude"]
        if not to_claude:
            if out["claude_rules"]:
                targets = sorted({str(r.get("proxy")) for r in out["claude_rules"]})
                reasons.append(f"Claude 域名有规则，但指向的是 {targets} 而不是专用组")
            else:
                reasons.append("规则里没有任何一条把 Claude 域名引到专用组")
        fb = out.get("fallback") or {}
        if str(fb.get("proxy") or "").upper() == "DIRECT":
            reasons.append("兜底规则是 DIRECT，没被上面规则接住的 Claude 流量会直连")

    if claude.get("type") != "Selector":
        reasons.append(f"Claude 组类型是 {claude.get('type')}，只有 select 才不做健康检查切换")
    if len(members) != 1:
        reasons.append(f"Claude 组有 {len(members)} 个成员，存在切换可能")
    # 不判 healthcheck：select 组即使写了 url/interval 也只是拿来显示延迟，
    # mihomo 的 select 不做健康检查切换。真正会自己换的是 Fallback/URLTest，
    # 那种情况上面的类型判据已经拦住了。
    out["fail_closed"] = {"ok": not reasons, "reasons": reasons}
    return out


def check_third_party() -> dict:
    """A10 是否接了第三方客户端。文章 §1 高发类。"""
    out = {"hits": []}
    for marker in THIRD_PARTY_MARKERS:
        p = HOME / marker
        if p.exists():
            out["hits"].append(str(p))
    return out


def check_cli_signature(cli_real) -> dict:
    """A11 的一部分：CLI 二进制有没有被动过。文章 §5「不要改客户端二进制」。

    官方 CLI 带 Developer ID 签名（实测 Authority=Developer ID Application:
    Anthropic PBC），签名里存着整个二进制每一页的哈希，改一个字节签名就废。
    所以「codesign --verify --strict 通过」等价于「这份还是官方发出来的那份」。
    """
    out = {"checked": False, "signed": False, "authority": None, "team": None,
           "verified": None, "note": ""}
    if not cli_real:
        out["note"] = "不知道 CLI 路径，跳过验签"
        return out
    if not pathlib.Path(cli_real).exists():
        out["note"] = f"CLI 路径不存在（{cli_real}），跳过验签"
        return out
    code, body = run(["codesign", "-dv", "--verbose=2", cli_real], timeout=60)
    if code != 0:
        # 不是 Mach-O、或者本机没有 codesign，都会走到这里。别当成「没签名」下结论。
        out["note"] = "读不到签名信息，跳过验签"
        return out
    out["checked"] = True
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("Authority=") and not out["authority"]:
            out["authority"] = line.split("=", 1)[1].strip()
        elif line.startswith("TeamIdentifier=") and not out["team"]:
            out["team"] = line.split("=", 1)[1].strip() or None
    # -dv --verbose=2 里 TeamIdentifier 不一定单列一行，从 Authority 的括号里兜底取
    if not out["team"] and out["authority"] and out["authority"].endswith(")"):
        out["team"] = out["authority"].rsplit("(", 1)[1].rstrip(")").strip()
    out["signed"] = bool(out["authority"])
    vcode, _ = run(["codesign", "--verify", "--strict", cli_real], timeout=180)
    out["verified"] = (vcode == 0)
    if not out["signed"]:
        out["note"] = "这份二进制没有签名"
    elif not out["verified"]:
        out["note"] = "签名校验没通过，二进制可能被改过"
    elif "anthropic" not in (out["authority"] or "").lower():
        out["note"] = f"签名者不是 Anthropic（{out['authority']}），确认一下来源"
    return out


VERSION_RE = re.compile(r"^\d+\.\d+\.\d+")
CLAUDE_PKG = "@anthropic-ai/claude-code"


def _claude_pkg_version(path: pathlib.Path) -> str | None:
    """读 npm/bun 全局包目录里的 package.json。名字对得上才算数。"""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if isinstance(data, dict) and data.get("name") == CLAUDE_PKG:
        v = data.get("version")
        return v if isinstance(v, str) else ""
    return None


def _node_global_roots() -> tuple[list, list]:
    """找出本机所有 node 全局根，以及探测过程中的读取失败。

    npm 装在全局时命令不一定在 PATH 里（nvm 的版本目录常不在），所以除了
    which("npm") 还要按 nvm 的固定布局兜一遍；同一个根只算一次。
    返回 (根列表, 错误列表)——读不出来和「没装」必须分开。
    """
    roots: list = []
    errors: list = []
    seen: set = set()
    cands: list = []
    npm = shutil.which("npm")
    if npm:
        cands.append(npm)
    nvm = HOME / ".nvm" / "versions" / "node"
    if nvm.is_dir():
        try:
            for d in sorted(nvm.iterdir()):
                cand = d / "bin" / "npm"
                if cand.exists():
                    cands.append(str(cand))
        except OSError:
            errors.append("nvm 版本目录读不出来")
    for npm_bin in cands:
        code, body = run([npm_bin, "root", "-g"], timeout=30)
        root = body.strip().splitlines()[0].strip() if body.strip() else ""
        if code != 0 or not root.startswith("/"):
            errors.append(f"{npm_bin} 读不出全局根")
            continue
        if root in seen:
            continue
        seen.add(root)
        roots.append(pathlib.Path(root))
    return roots, errors


def _native_link_shape() -> dict:
    """官方安装器的链接形状。

    正常长这样：~/.local/share/claude 是真目录，~/.local/bin/claude 是指向
    versions/<版本> 的软链。任何一环被换成别的东西，只凭「路径里含 versions」
    下结论就不牢 —— 先看形状，再谈版本。
    """
    out = {"dir_is_symlink": None, "launcher_is_symlink": None,
           "launcher_parent_is_symlink": None, "launcher_in_versions": None,
           "launcher_target": None}
    d = HOME / ".local" / "share" / "claude"
    if d.exists() or d.is_symlink():
        out["dir_is_symlink"] = d.is_symlink()
    b = HOME / ".local" / "bin" / "claude"
    if b.exists() or b.is_symlink():
        out["launcher_parent_is_symlink"] = b.parent.is_symlink()
        out["launcher_is_symlink"] = b.is_symlink()
        if b.is_symlink():
            try:
                tgt = os.readlink(b)
            except OSError:
                tgt = ""
            out["launcher_target"] = tgt
            if tgt:
                real = pathlib.Path(tgt)
                if not real.is_absolute():
                    real = b.parent / real
                out["launcher_in_versions"] = "versions" in real.parts
    return out


def detect_cli_install_method(cli_path, cli_real) -> dict:
    """A11：这份 claude 是怎么装上去的。

    四条通道各自有可验证的特征，不靠 PATH 里的名字猜：native 认官方安装器的
    versions 目录，npm / bun 认包管理器自己的全局根里那份 package.json，
    Homebrew 认 cask 清单。

    两种「读不出来」必须分开报 —— 探测通道自己报错（brew list 跑不起来）
    和「确实没装」是两回事，混在一起会把探测失败说成环境干净。
    四条都识别不出来时给 unknown，交回上层写进表里，绝不默认成正常。
    """
    real = str(cli_real or "")
    native_dir = HOME / ".local" / "share" / "claude"
    native_bin = HOME / ".local" / "bin" / "claude"
    native_present = native_dir.exists() or native_bin.exists()
    layout = _native_link_shape()
    probes: dict = {"native": native_present, "native_layout": layout}

    def shape_ok() -> bool:
        # 只有拿到「形状确实不对」的正面证据才判 False；读不到（None）不冤判。
        return not (layout.get("dir_is_symlink") is True
                    or layout.get("launcher_parent_is_symlink") is True
                    or layout.get("launcher_in_versions") is False)

    if real and f"{os.sep}versions{os.sep}" in real and native_present:
        # 已经认出来了，不再去问 brew / npm —— 那两个各要起一个子进程，白等。
        return {"method": "native", "layout_ok": shape_ok(), "probes": probes, "error": "",
                "evidence": f"可执行文件在官方 versions 目录下（{real}）"}

    errors: list = []
    roots, npm_errors = _node_global_roots()
    errors += npm_errors
    npm_hits = []
    for r in roots:
        v = _claude_pkg_version(r / CLAUDE_PKG / "package.json")
        if v is not None:
            npm_hits.append({"root": str(r), "version": v})
    probes["npm_roots"] = [str(r) for r in roots]
    probes["npm"] = npm_hits

    bun_pkg = HOME / ".bun" / "install" / "global" / "node_modules" / CLAUDE_PKG / "package.json"
    bun_v = _claude_pkg_version(bun_pkg)
    probes["bun"] = bun_v

    brew_hits: list = []
    if sys.platform == "darwin":
        if shutil.which("brew"):
            code, body = run(["brew", "list", "--cask"], timeout=60)
            if code != 0:
                errors.append("brew list --cask 读不出来")
            else:
                brew_hits = [ln.strip() for ln in body.splitlines()
                             if ln.strip() in ("claude-code", "claude-code@latest")]
        probes["brew"] = brew_hits

    if npm_hits:
        hit = npm_hits[0]
        method = "npm"
        evidence = f"全局 npm 根 {hit['root']} 里有 {CLAUDE_PKG}（{hit['version']}）"
    elif bun_v is not None:
        method, evidence = "bun", f"bun 全局包目录里有 {CLAUDE_PKG}（{bun_v}）"
    elif brew_hits:
        method, evidence = "homebrew", f"Homebrew cask 已安装：{'、'.join(brew_hits)}"
    elif cli_path:
        method, evidence = "unknown", "PATH 下能找到 claude，但四条通道一条都对不上"
    else:
        method, evidence = "unknown", "PATH 下没有 claude"
    return {"method": method, "evidence": evidence, "layout_ok": shape_ok(),
            "probes": probes, "error": "；".join(errors)}


def check_client_integrity() -> dict:
    """A11 Claude Code 客户端完整性。文章 §5「不要改客户端二进制，不要用魔改版」。

    本 skill 的范围是 Claude Code，所以主角是 CLI：可执行文件在哪、真实路径是什么、
    版本号是多少、versions 目录里留了几份，以及**这份二进制有没有被动过**——
    最后一项靠 codesign 验签（见 check_cli_signature）。
    Claude Desktop 只作附带信息，不参与判定。
    """
    out = {
        "cli_path": None, "cli_real": None, "cli_version": None, "current_version": None,
        "versions": [], "version_count": 0, "stale_count": 0, "stale_bytes": 0, "total_bytes": 0,
        "desktop_present": pathlib.Path("/Applications/Claude.app").exists(),
        "version_runs": False, "version_ok": None,
        "install": {}, "current_present": None,
        "signature": {},
        "note": "",
    }
    cli = shutil.which("claude")
    out["cli_path"] = cli
    if cli:
        try:
            out["cli_real"] = str(pathlib.Path(cli).resolve())
        except OSError:
            out["cli_real"] = None
        code, body = run([cli, "--version"], timeout=30, env={"DISABLE_AUTOUPDATER": "1"})
        line = body.strip().splitlines()[0][:80] if body.strip() else None
        if line:
            out["cli_version"] = line
        # 「文件在」和「跑起来报的版本正常」是两件事，分开记：
        # 前者只证明磁盘上有这个文件，后者才证明它还能用、还是那个东西。
        out["version_runs"] = bool(line)
        out["version_ok"] = bool(line and VERSION_RE.match(line))
    vdir = HOME / ".local" / "share" / "claude" / "versions"
    if vdir.is_dir():
        # 官方安装在这里放的是**可执行文件**（每个 200MB 上下），不是子目录；
        # 只按 is_dir() 过滤会数出 0 份，早前就是这么错的。
        entries = []
        for p in vdir.iterdir():
            try:
                entries.append({"name": p.name, "bytes": p.stat().st_size})
            except OSError:
                entries.append({"name": p.name, "bytes": 0})
        entries.sort(key=lambda e: e["name"], reverse=True)
        out["versions"] = entries
        out["version_count"] = len(entries)
        out["total_bytes"] = sum(e["bytes"] for e in entries)
        out["current_version"] = pathlib.Path(out["cli_real"]).name if out["cli_real"] else None
        stale = [e for e in entries if e["name"] != out["current_version"]]
        out["stale_count"] = len(stale)
        out["stale_bytes"] = sum(e["bytes"] for e in stale)
        # 软链指向的那个版本必须真的在目录里；不在说明链接断了或被人改过，
        # 这时候「版本号」是从一个不存在的路径名里读出来的，不能当证据用。
        if out["current_version"]:
            out["current_present"] = out["current_version"] in {e["name"] for e in entries}
    out["signature"] = check_cli_signature(out["cli_real"])
    out["install"] = detect_cli_install_method(cli, out["cli_real"])
    notes: list = []
    if not cli:
        notes.append("PATH 下找不到 claude 命令，无法校验 CLI 完整性")
    elif out["cli_real"] and str(vdir) not in out["cli_real"]:
        notes.append(f"claude 不在官方版本目录下（真实路径 {out['cli_real']}），"
                     f"请确认不是魔改版或手工替换的二进制")
    inst = out["install"]
    if cli and inst.get("method") == "unknown":
        notes.append("四条安装通道（native / Homebrew / npm / bun）一条都对不上，"
                     "安装方式未知 —— 不猜，请人工确认这份 claude 是哪来的")
    if inst.get("error"):
        notes.append(f"安装探测本身有读不出来的地方：{inst['error']}（这与「没装」不是一回事）")
    if cli and not out["version_runs"]:
        notes.append("二进制在，但跑不出 --version，没法确认它还能用")
    elif cli and out["version_ok"] is False:
        notes.append(f"版本号看着不像正常版本：{out['cli_version']!r}")
    if out["current_present"] is False:
        notes.append(f"软链指向的 {out['current_version']} 不在 versions 目录里，链接可能已断或被改")
    out["note"] = "；".join(notes)
    return out


def check_geo_words() -> dict:
    """A9 别在 CLAUDE.md 或系统提示里写地理位置。文章 §4。

    文章原话是「别在系统提示或 CLAUDE.md 里写自己人在北京」——
    项目级的 CLAUDE.md 才是重点，所以除了家目录那几份，还要扫项目目录，
    但有深度和数量上限，避免把整棵源码树读一遍。
    """
    out = {"hits": [], "scanned": 0, "note": ""}
    candidates = [
        HOME / ".claude" / "CLAUDE.md",
        HOME / "CLAUDE.md",
        HOME / ".claude.json",
        HOME / ".claude" / "settings.json",
    ]
    for root in project_roots():
        if not root.is_dir():
            continue
        try:
            for depth, d in enumerate([root, *root.glob("*"), *root.glob("*/*")]):
                if depth > 2 or not d.is_dir():
                    continue
                for name in ("CLAUDE.md", "AGENTS.md"):
                    candidates.append(d / name)
                candidates.append(d / ".claude" / "CLAUDE.md")
        except OSError:
            continue
    seen = set()
    for p in candidates:
        sp = str(p)
        if sp in seen or not p.is_file():
            continue
        seen.add(sp)
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        out["scanned"] += 1
        for w in GEO_WORDS:
            if w in text:
                out["hits"].append({"file": sp, "word": w})
    if not project_roots():
        out["note"] = "只扫了家目录；设置 CLAUDE_GUARD_PROJECT_ROOTS 可连项目级 CLAUDE.md 一起扫"
    return out


def project_roots() -> list[pathlib.Path]:
    """A14 要扫描的项目目录。

    刻意不猜：skill 不该把某台机器的目录结构写死。用环境变量
    CLAUDE_GUARD_PROJECT_ROOTS（冒号分隔）指定；没指定就跳过这一项并说明怎么开。
    """
    raw = os.environ.get("CLAUDE_GUARD_PROJECT_ROOTS", "")
    if not raw.strip():
        return []
    return [pathlib.Path(p).expanduser() for p in raw.split(os.pathsep) if p.strip()]


def check_consistency(ip: dict | None = None) -> dict:
    """A15 一致性：系统时区 vs 出口 IP 国家 vs 语言。文章 2.2 + 3.3。

    ip 由调用方传入，避免重复发起网络请求。
    """
    out = {"timezone": None, "offset": None, "country": None, "lang": None,
           "apple_locale": None, "facts": [], "tension": []}
    code, body = run(["readlink", "/etc/localtime"])
    out["timezone"] = body.strip().split("zoneinfo/")[-1] if "zoneinfo/" in body else body.strip()
    code, body = run(["date", "+%z"])
    out["offset"] = body.strip()
    ip = ip if ip is not None else check_export_ip()
    out["country"] = ip.get("country")
    out["lang"] = os.environ.get("LANG")
    code, body = run(["defaults", "read", "-g", "AppleLocale"])
    out["apple_locale"] = body.strip()
    tz = out["timezone"] or ""
    country = (out["country"] or "").upper()
    lang = out["lang"] or ""
    loc = out["apple_locale"] or ""
    east_asia_tz = tz.startswith(("Asia/Taipei", "Asia/Shanghai", "Asia/Singapore", "Asia/Hong_Kong"))
    out["facts"] = [
        f"系统时区 {tz}",
        f"出口国家 {country or '未知'}",
        f"系统语言 {lang}",
        f"AppleLocale {loc}",
    ]
    # 注意：下面这些只作为「事实 + 张力」陈述，不作对错判定。
    # 文章 §2.2 明确让你把时区改成台北，§2.3/§3.3 又要求出口与账单同国，
    # 两条同时照做必然产出「时区在东亚、出口在美国」——这是文章自身的设计，
    # 不是用户的错。把它标成「矛盾」等于拿文章的建议去否定文章的建议。
    if east_asia_tz and country and country not in ("TW", "HK", "MO", "CN", "SG"):
        out["tension"].append(
            f"时区 {tz} 在东亚，出口国家是 {country}。文章 §2.2 推荐用台北时区，"
            f"§2.3 与 §3.3 又要求出口、账单、卡发行国同属一国，这两条本身就冲突，由你权衡"
        )
    if not east_asia_tz and country in ("US",):
        out["facts"].append(f"提示：时区 {tz} 与出口 {country} 同属美洲，符合文章 §3.3 的『同国』口径")
    if country in ("US",) and lang.startswith("zh"):
        out["facts"].append(
            f"语言仍为 {lang}。文章 §4 的原话是「中文本身不是罪名」，不用假装只会说英语，"
            f"所以这一条只作陈述，不建议为它改系统语言"
        )
    if country in ("US",) and "Hans" not in loc and loc:
        out["facts"].append(f"AppleLocale={loc} 与 LANG={lang} 的地区标记不一致，属常见配置，仅记录")
    return out


def check_multi_account() -> dict:
    """A13 本机多账号痕迹。文章 §1『同一台设备登多个 Claude 账号』是这轮最扎眼的特征。"""
    out = {"identities": [], "backups": 0, "note": ""}
    data = read_json(HOME / ".claude.json", {})
    for key in ("userID", "machineID"):
        if data.get(key):
            out["identities"].append({key: data[key][:16] + "…"})
    acct = data.get("oauthAccount")
    if acct:
        out["identities"].append({"oauthAccount": acct.get("emailAddress", "(无邮箱)")})
    else:
        out["note"] = "~/.claude.json 当前无 oauthAccount（封号后 OAuth 缓存已被清空）"
    bdir = HOME / ".claude" / "backups"
    if bdir.is_dir():
        out["backups"] = len(list(bdir.iterdir()))
    return out


WEBRTC_PROBE_HTML = """<!doctype html><meta charset="utf-8"><body><pre id="out">pending</pre>
<script>
const raw=[];let done=false,err="",media="not-requested";
function finish(){
 if(done)return;done=true;
 const payload={count:raw.length,raw:raw,error:err,media:media};
 document.getElementById("out").textContent=JSON.stringify(payload);
 fetch(location.pathname.replace(/\/+$/,"")+"/result",{method:"POST",headers:{"Content-Type":"application/json"},
                  body:JSON.stringify(payload)}).catch(()=>{});
}
async function go(){
 // 带 #media 时先要一次麦克风权限。Chrome 的 mDNS 候选混淆只在页面**没有**
 // 媒体权限时生效；拿到权限后真实内网地址会直接出现在候选里。这条路径必须测，
 // 否则「不泄漏」的结论只覆盖了一半场景。
 if(location.hash==="#media"){
   try{ await navigator.mediaDevices.getUserMedia({audio:true}); media="granted"; }
   catch(e){ media="denied:"+(e&&e.name||"unknown"); }
 }
 try{
  const pc=new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"},
                                              {urls:"stun:stun.cloudflare.com:3478"}]});
  pc.onicecandidate=e=>{if(!e.candidate){finish();return;}raw.push(e.candidate.candidate);};
  pc.createDataChannel("x");
  const o=await pc.createOffer(); await pc.setLocalDescription(o);
  setTimeout(finish,8000);
 }catch(e){err=String(e);finish();}
}
go();
</script></body>"""




def find_chromium() -> str | None:
    """找一个能跑无头 WebRTC 探测的 chromium。

    刻意不依赖 node 侧 playwright 模块：这台机器上浏览器二进制装好了、模块却没有，
    旧实现因此永远测不出结果。把浏览器当普通命令行工具用，只要有 chromium 就能试。

    **完整版排在 headless shell 前面，这一点反过一次。** 旧版是 headless shell 优先，
    理由是完整版 Chrome 配 `--dump-dom` 会挂死不返回。但探测早就换成本地服务 + POST
    回传了，完整版不会挂；而 headless shell 在 WebRTC 上会给出**假阴性**——实测同一台
    机器、同样给了媒体权限：

        headless shell    1 个候选，全是 mDNS，看不到任何 IP
        完整 Chromium     4 个候选，露出内网地址和 198.18.0.1

    也就是说用 headless shell 测，「拿到摄像头权限后会不会露内网地址」这个问题永远
    答「不会」。宁可慢一点也要用完整版。
    """
    found: list[str] = []
    cache = HOME / "Library" / "Caches" / "ms-playwright"
    if cache.is_dir():
        # 完整版优先
        found += sorted(str(p) for p in cache.glob(
            "chromium-*/chrome-mac-*/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"))
        found += sorted(str(p) for p in cache.glob(
            "chromium-*/chrome-mac/Chromium.app/Contents/MacOS/Chromium"))
    found += [
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ]
    if cache.is_dir():
        # headless shell 垫底：能跑，但 WebRTC 上看不到真实地址
        found += sorted(str(p) for p in cache.glob(
            "chromium_headless_shell-*/chrome-headless-shell-mac-*/chrome-headless-shell"))
    for path in found:
        p = pathlib.Path(path)
        if p.is_file() and os.access(path, os.X_OK):
            return path
    return None


def chromium_is_headless_shell(path: str | None) -> bool:
    """这个浏览器是不是 headless shell。

    headless shell 在 WebRTC 上会漏报（拿不到真实内网地址），所以结果里要标明
    用的是哪个，免得把一个不可靠的「不泄漏」当结论。
    """
    return bool(path) and "chrome-headless-shell" in path


def classify_webrtc_candidates(raw: list) -> dict:
    """把 ICE 候选分成「泄漏」和「不泄漏」。纯函数，不碰浏览器。

    真正的泄漏是候选里出现了非私网地址——那意味着对方的 STUN 直接看到了你的
    公网出口。内网地址（10/172.16-31/192.168/169.254/127）属正常，浏览器本来
    就会报本地网卡地址，不必惊动用户。

    实测 macOS 上候选主机名会被 mDNS 混淆成 `<uuid>.local`，连内网地址都看不到，
    这时候 local_ips 是空的而 mdns 为 True——那也是「不泄漏」，不是「没测到」。
    """
    out = {"local_ips": [], "leaked_public": [], "tun_leak": [], "note": "",
           "candidates": 0, "mdns": False}
    raw = raw or []
    out["candidates"] = len(raw)
    out["mdns"] = any(".local" in c for c in raw)
    for cand in raw:
        hit = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})", cand)
        if not hit:
            continue
        addr = hit.group(1)
        octets = [int(x) for x in addr.split(".")]
        private = (
            octets[0] in (10, 127, 0)
            or (octets[0] == 192 and octets[1] == 168)
            or (octets[0] == 172 and 16 <= octets[1] <= 31)
            or (octets[0] == 169 and octets[1] == 254)
        )
        if addr not in [e["ip"] for e in out["local_ips"]]:
            out["local_ips"].append({"ip": addr, "private": private})
    out["leaked_public"] = [e["ip"] for e in out["local_ips"] if not e["private"]]
    # 198.18.0.0/15 是 RFC 2544 的基准测试保留段。Clash / mihomo 的 fake-IP 模式
    # 默认就用它，TUN 接口地址也跟着落在这里。所以候选里出现这个段，等于对着网站
    # 自报「我在用 Clash 类代理」——这不是内网信息，是代理的招牌。
    out["tun_leak"] = [
        e["ip"] for e in out["local_ips"]
        if e["ip"].startswith(fake_ip_prefixes())
    ]
    if out["candidates"] == 0:
        out["note"] = "探测跑起来了但一个候选都没拿到，结论不可用；用 browserleaks.com/webrtc 人工确认"
    return out


MEDIA_VERIFY_PAGE = """<!doctype html><meta charset="utf-8">
<title>Claude Guard · 媒体权限复核</title>
<style>
 body{font:15px/1.7 -apple-system,system-ui,sans-serif;max-width:680px;margin:40px auto;padding:0 20px;color:#111}
 h1{font-size:19px;margin:0 0 4px}
 .sub{color:#666;margin-bottom:20px;font-size:13px}
 table{border-collapse:collapse;width:100%;margin:14px 0}
 td,th{border-bottom:1px solid #e5e5e5;padding:9px 6px;text-align:left}
 th{font-weight:600;font-size:13px;color:#555}
 .ok{color:#0a7c2f;font-weight:600}.bad{color:#c0392b;font-weight:600}.warn{color:#b26a00;font-weight:600}
 code{background:#f4f4f4;padding:1px 5px;border-radius:4px;font-size:13px}
 #verdict{margin-top:20px;padding:14px;border-radius:8px;font-weight:600}
 .v-ok{background:#e8f6ec;color:#0a7c2f}.v-bad{background:#fdecea;color:#c0392b}
</style>
<h1>Claude Guard · 媒体权限复核</h1>
<div class="sub">这个页面只在本机跑，结果只回传给本机脚本，不出这台机器。用你日常那个 Chrome 打开。</div>
<table>
 <tr><th style="width:46%">项目</th><th>结果</th></tr>
 <tr><td>摄像头权限</td><td id="cam">检测中…</td></tr>
 <tr><td>麦克风权限</td><td id="mic">检测中…</td></tr>
 <tr><td>真去申请一次的结果</td><td id="req">检测中…</td></tr>
 <tr><td>WebRTC 候选里出现的 IP</td><td id="ips">检测中…</td></tr>
</table>
<div id="verdict">检测中…</div>
<script>
const $ = id => document.getElementById(id);
const perm = async n => { try { return (await navigator.permissions.query({name:n})).state } catch(e){ return "查不到("+e.name+")" } };
const fmt = s => s==="denied" ? '<span class="bad">denied（已禁止）</span>'
               : s==="granted" ? '<span class="warn">granted（已允许）</span>'
               : s==="prompt" ? '<span class="warn">prompt（每次询问）</span>'
               : '<span class="warn">'+s+'</span>';
(async () => {
  const cam = await perm("camera"), mic = await perm("microphone");
  $("cam").innerHTML = fmt(cam); $("mic").innerHTML = fmt(mic);

  let req = "granted", detail = "";
  try {
    const s = await navigator.mediaDevices.getUserMedia({audio:true, video:true});
    s.getTracks().forEach(t => t.stop());
    detail = "拿到了媒体流";
  } catch (e) { req = "denied"; detail = e.name; }
  $("req").innerHTML = req==="denied"
    ? '<span class="ok">被拒绝</span> <code>'+detail+'</code>'
    : '<span class="bad">拿到了</span> <code>'+detail+'</code>';

  const raw = [];
  const pc = new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]});
  pc.onicecandidate = e => { if (e.candidate) raw.push(e.candidate.candidate); };
  pc.createDataChannel("x");
  await pc.setLocalDescription(await pc.createOffer());
  await new Promise(r => setTimeout(r, 5000));
  pc.close();

  const ips = [];
  raw.forEach(c => { const m = c.match(/\\b(\\d{1,3}(?:\\.\\d{1,3}){3})\\b/); if (m && !ips.includes(m[1])) ips.push(m[1]); });
  const mdns = raw.some(c => c.includes(".local"));
  $("ips").innerHTML = ips.length ? '<span class="bad">'+ips.join(", ")+'</span>'
    : '<span class="ok">无'+(mdns?'（候选被 mDNS 混淆成 .local）':'')+'</span>';

  const v = $("verdict");
  const good = req === "denied" && ips.length === 0;
  v.className = good ? "v-ok" : "v-bad";
  v.textContent = good
    ? "✓ 已闭合：拿不到摄像头/麦克风权限，WebRTC 候选里看不到任何真实地址。"
    : req === "denied"
      ? "⚠ 权限挡住了但仍出现 IP：" + ips.join(", ") + " —— 这不该发生，请把结果发我。"
      : "✗ 仍能拿到媒体权限，mDNS 混淆会关掉，候选里露出了：" + (ips.join(", ") || "(无)");

  fetch(location.pathname.replace(/\/+$/,"")+"/result", {method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({camera:cam, microphone:mic, request:req, detail:detail,
                          candidates:raw, ips:ips, mdns:mdns, ok:good})}).catch(()=>{});
})();
</script>"""


MEDIA_CACHE = HOME / ".local" / "state" / "claude-guard" / "media-permission.json"


def load_media_permission() -> dict:
    """读上次的媒体权限复核结果。没跑过就是空的。"""
    try:
        return json.loads(MEDIA_CACHE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def verify_media_permission(timeout: int = 240) -> dict:
    """起一个本地页面，请用户用日常浏览器打开，把真实权限状态收回来。

    为什么要用户配合：Chrome 的资料文件受 TCC 保护，读内容会报
    `PermissionError: Operation not permitted`（元数据能读，内容读不了）。所以
    「摄像头/麦克风到底允不允许」这件事，脚本自己问不出来，只能让浏览器自己答。

    为什么值得单独做一次：WebRTC 的探测是**强制授权**的（--use-fake-ui-for-media-stream），
    量的是「如果网站拿到权限会怎样」。用户把权限禁掉之后，那个能力就不可达了，
    但探测结果不会变——不加这一步，表里会永远挂着一个已经修好的「待处理」。
    """
    import http.server
    import threading

    got: dict = {}
    ready = threading.Event()
    token = _verify_token()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if _verify_route(self.path, token) != "/":
                # 不认的路径就是 404：不知道这次令牌的本地进程连页面都取不到，
                # 也就拿不到页面里那段回传逻辑。
                self.send_error(404)
                return
            body = MEDIA_VERIFY_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if _verify_route(self.path, token) != "/result":
                self.send_error(404)
                return
            # 上限 64KB：回传的就那么几个字段，别让谁塞个几百兆进来把内存吃满。
            n = min(int(self.headers.get("Content-Length") or 0), VERIFY_MAX_BODY)
            try:
                got.update(json.loads(self.rfile.read(n) or b"{}"))
            except (json.JSONDecodeError, ValueError):
                got["error"] = "回传解析失败"
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            ready.set()

    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except OSError as e:
        print(f"  本地服务起不来：{e}")
        return {}
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # flush 是必须的：这个函数会阻塞等待浏览器回传，而 Python 在 stdout 不是
    # TTY 时（后台跑、管道接出去）会缓冲——不刷新的话 URL 根本打不出来，
    # 用户看不到要打开哪个地址，就一直等到超时。
    print(f"\n  用你日常那个 Chrome 打开：\n", flush=True)
    print(f"      http://127.0.0.1:{port}/{token}/\n", flush=True)
    print(f"  链接里那串是本次随机令牌，别改也别分享；页面会自动检测并回传，最多等 {timeout} 秒（Ctrl-C 可取消）...",
          flush=True)
    try:
        ready.wait(timeout=timeout)
    except KeyboardInterrupt:
        print("\n  已取消。")
        server.shutdown()
        server.server_close()
        return {}
    server.shutdown()
    server.server_close()

    if not ready.is_set():
        print("\n  没等到浏览器回传——页面没打开，或者打开的不是这台机器上的浏览器。")
        return {}

    got["checkedAt"] = now_stamp()
    try:
        MEDIA_CACHE.parent.mkdir(parents=True, exist_ok=True)
        MEDIA_CACHE.write_text(json.dumps(got, ensure_ascii=False, indent=2), encoding="utf-8")
        hand_back_ownership(MEDIA_CACHE)
        print(f"\n  结果已存：{str(MEDIA_CACHE).replace(str(HOME) + '/', '')}")
    except OSError as e:
        print(f"\n  结果存不下来（{e}），但下面的结论有效")

    ok = bool(got.get("ok"))
    mark = "✓" if ok else "✗"
    print(f"\n  {mark} 摄像头={got.get('camera')}  麦克风={got.get('microphone')}"
          f"  实际申请={got.get('request')}（{got.get('detail')}）")
    print(f"    候选里出现的 IP：{got.get('ips') or '（无）'}")
    if ok:
        print("\n  这表示：网站拿不到摄像头/麦克风权限 → mDNS 混淆一直生效 → WebRTC 不泄漏。")
    else:
        print("\n  这表示：仍能拿到媒体权限，mDNS 混淆会被关掉，真实内网地址会出现在候选里。")
        print("  修法：Chrome 设置 → 隐私和安全 → 网站设置 → 摄像头/麦克风 → 不允许网站使用。")
    return got


def check_webrtc() -> dict:
    """A7 WebRTC 泄漏。文章 2.5②。

    ICE 收集是异步的，几秒才齐。所以不能用 `--dump-dom`——它在页面 load 完就
    取 DOM，那时候一个候选都还没有。三种 dump-dom 组合都试过，没有一种能拿到
    真实候选（完整版 Chrome 挂死；headless shell 配 --virtual-time-budget 会被
    虚拟时钟提前触发，稳定给 0 个候选；配 --timeout 在 load 时就取了 DOM）。

    现在的做法见 `_webrtc_run`：起一个本地 HTTP 服务，探测页跑完把结果 POST 回来。

    **要跑两遍，这一点很关键。** Chrome 只在页面**没有**摄像头/麦克风权限时才把
    本地候选混淆成 mDNS（`<uuid>.local`）。一旦页面拿到媒体权限，混淆就关掉，
    真实内网地址直接出现。只测第一遍会得出「不泄漏」——实测本机第一遍只有一条
    `.local`，第二遍露出了内网地址（en0）和 `198.18.0.1`（Clash 的 utun1024）。
    后者落在 RFC 2544 保留段，是 Clash 类代理的招牌，等于对网站自报用了什么。

    结论口径，绝不把「拿到 0 个候选」当成「没有泄漏」：
      候选里有非私网 IP        -> 泄漏
      有候选但全是私网/mDNS    -> 这个场景不泄漏
      有媒体权限时露出内网/TUN -> 算暴露，写进结果
      没有候选或没跑起来        -> 结论不可用，给出人工路径
    """
    out = {
        "available": False, "local_ips": [], "leaked_public": [], "tun_leak": [],
        "note": "", "candidates": 0, "mdns": False, "browser": None,
        "media": None, "with_media": {},
        "manual": "https://browserleaks.com/webrtc",
    }
    browser = find_chromium()
    if not browser:
        out["note"] = "没找到可用的 chromium；用 browserleaks.com/webrtc 人工看，不影响其它检查"
        return out
    out["browser"] = browser

    plain = _webrtc_run(browser, media=False)
    if plain is None:
        out["note"] = (
            "探测页没把结果回传（浏览器起不来，或 ICE 没跑完）。"
            "用 browserleaks.com/webrtc 人工看，不影响其它检查"
        )
        return out

    out["available"] = True
    out.update(classify_webrtc_candidates(plain.get("raw") or []))
    out["media"] = plain.get("media")

    # 第二遍：带媒体权限。这一步才是「网站拿到摄像头权限之后会怎样」。
    with_media = _webrtc_run(browser, media=True)
    if with_media is not None:
        out["with_media"] = classify_webrtc_candidates(with_media.get("raw") or [])
        out["with_media"]["media"] = with_media.get("media")
    return out


def _webrtc_run(browser: str, media: bool = False) -> dict | None:
    """跑一次探测，返回页面回传的原始数据。跑不起来或超时返回 None。"""
    import http.server
    import threading

    collected: dict = {}
    ready = threading.Event()
    token = _verify_token()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if _verify_route(self.path, token) != "/":
                # 不认的路径就是 404：不知道这次令牌的本地进程连页面都取不到，
                # 也就拿不到页面里那段回传逻辑。
                self.send_error(404)
                return
            body = WEBRTC_PROBE_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if _verify_route(self.path, token) != "/result":
                self.send_error(404)
                return
            n = min(int(self.headers.get("Content-Length") or 0), VERIFY_MAX_BODY)
            try:
                collected.update(json.loads(self.rfile.read(n) or b"{}"))
            except (json.JSONDecodeError, ValueError):
                collected["error"] = "回传内容解析失败"
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            ready.set()

    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except OSError:
        return None
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="guard-webrtc-"))
    proc = None
    try:
        argv = [
            browser, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run",
            "--disable-dev-shm-usage", f"--user-data-dir={tmpdir / 'profile'}",
        ]
        if media:
            # 假设备 + 自动同意，避免弹窗；测的是「拿到权限之后会怎样」
            argv += ["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream"]
        argv.append(f"http://127.0.0.1:{port}/{token}/" + ("#media" if media else ""))
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as e:
            collected["_launch_error"] = f"{type(e).__name__}: {e}"
            return None
        ready.wait(timeout=25)
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        server.shutdown()
        server.server_close()
        shutil.rmtree(tmpdir, ignore_errors=True)

    return collected if ready.is_set() else None


def check_telemetry() -> dict:
    """A3 遥测三键的当前状态。只读。

    文章 §5 的写法是把这三个键写进 settings.json 的 env。这里只报有没有设，
    改不改由用户决定——关掉它们会连带关掉功能旗标，Remote Control 可能失效。
    """
    out = {"keys": {k: None for k in TELEMETRY_KEYS}, "any_set": False, "note": ""}
    try:
        data = json.loads(SETTINGS.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        out["note"] = "读不到或解析不了 settings.json（文件不存在也算这一种）"
        return out
    env = data.get("env") if isinstance(data.get("env"), dict) else {}
    for k in TELEMETRY_KEYS:
        out["keys"][k] = env.get(k)
    out["any_set"] = any(v is not None for v in out["keys"].values())
    return out


# ────────────────────────── 结果总表 ──────────────────────────

S_OK = "✓"
S_FIX = "! "
S_BAD = "✗"
S_NA = "·"


def disp_width(text) -> int:
    """显示宽度：东亚全角字符占 2 格，其余占 1 格。

    表格对齐必须按这个算——按 len() 算的话「出口 IP」会被当成 5 个字宽，
    实际渲染是 8 格，整个表就歪了。
    """
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in str(text))


def truncate(text, width: int) -> str:
    """按显示宽度截断，超出补省略号。不按字符数截，否则中文行会算错长度。"""
    text = str(text)
    if disp_width(text) <= width:
        return text
    out, used = "", 0
    for ch in text:
        w = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if used + w > width - 1:
            break
        out += ch
        used += w
    return out + "…"


def render_table(headers, rows) -> str:
    """画一个按显示宽度对齐的方框表格。"""
    widths = [disp_width(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], disp_width(cell))

    def bar(left, mid, right):
        return left + mid.join("─" * (w + 2) for w in widths) + right

    def line(cells):
        parts = []
        for cell, w in zip(cells, widths):
            parts.append(" " + str(cell) + " " * (w - disp_width(cell) + 1))
        return "│" + "│".join(parts) + "│"

    out = [bar("┌", "┬", "┐"), line(headers), bar("├", "┼", "┤")]
    out += [line(r) for r in rows]
    out.append(bar("└", "┴", "┘"))
    return "\n".join(out)


# ── 浏览器 Intl 区域设置 ─────────────────────────────────────────────
#
# ippure.com/claude.html 六项指纹里的第 4 项（权重 10），量的是浏览器做日期 /
# 数字格式化用的 locale，也就是 Intl.DateTimeFormat().resolvedOptions().locale。
# 那页只给大陆简体计分：报 en-US 是 0 分，报 zh-CN 计满。
#
# 谁在控制这个值 —— 实测结论（临时资料起真 Chrome，连 CDP 读真值，不是查文档）：
#   · Chrome 的 --lang=en-US 启动参数**完全无效**，Intl 仍是 zh-CN；
#   · 资料里的 intl.accept_languages 只改 navigator.language，不动 Intl；
#   · 应用域的 AppleLanguages 一给（启动参数 -AppleLanguages "(en-US)" 或
#     defaults write com.google.Chrome AppleLanguages -array en-US），
#     Intl.DateTimeFormat / NumberFormat / Collator / navigator.language 全部
#     变成 en-US，日期样例从 2026/10/9 变成 10/9/2026。
# 所以持久开关是**应用域的 AppleLanguages**：只作用在 Chrome 身上，不动系统语言，
# 一条 defaults delete 就能还原。代价是 Chrome 要完全退出再打开才生效。
CHROME_APP_DOMAIN = "com.google.Chrome"
LOCALE_CACHE = HOME / ".local" / "state" / "claude-guard" / "browser-locale.json"
LOCALE_ROLLBACK_FILE = HOME / ".local" / "state" / "claude-guard" / "browser-locale-rollback.json"

# 出口国家 → 该国常规 locale。只在命中大陆简体时才用得上；没列到的国家退回 en-US。
LOCALE_BY_COUNTRY = {
    "US": "en-US", "GB": "en-GB", "CA": "en-CA", "AU": "en-AU", "NZ": "en-NZ",
    "IE": "en-IE", "SG": "en-SG", "JP": "ja-JP", "KR": "ko-KR", "DE": "de-DE",
    "FR": "fr-FR", "NL": "nl-NL", "ES": "es-ES", "IT": "it-IT", "SE": "sv-SE",
    "TW": "zh-TW", "HK": "zh-HK",
}
DEFAULT_LOCALE = "en-US"


def is_cn_locale(loc: str | None) -> bool:
    """这个 locale 是不是「大陆简体」——ippure 只给这一类计分。

    港台也讲中文，但那两地的 locale 不等于「中国用户」，不能一竿子打死，
    否则会把一个正确的设置报成待处理。
    """
    if not loc:
        return False
    parts = loc.strip().replace("_", "-").lower().split("-")
    if parts[0] != "zh":
        return False
    return not any(p in ("tw", "hk", "mo", "hant") for p in parts[1:])


def predict_intl_locale(tag: str | None) -> str | None:
    """由 AppleLanguages 的第一项推测 Chrome 会报什么 Intl locale。

    这只是推测：没跑过浏览器复核时给个方向，实测值永远优先。
    实测对照：AppleLanguages=(zh-Hans-US, en-US, en-US) → Chrome 报 zh-CN。
    """
    if not tag:
        return None
    tag = tag.strip()
    low = tag.replace("_", "-").lower()
    if low == "zh" or low.startswith("zh-hans"):
        return "zh-CN"
    if low.startswith("zh-hant"):
        return "zh-TW"
    return tag.replace("_", "-")


def load_browser_locale() -> dict:
    """读上次的浏览器 Intl 复核结果。没跑过就是空的。"""
    try:
        return json.loads(LOCALE_CACHE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def chrome_app_languages() -> list | None:
    """读 Chrome 应用域里的 AppleLanguages；没设过返回 None。

    这是唯一能持久影响 Chrome ICU locale 的开关，而且只作用在 Chrome 身上。
    """
    code, body = run(["defaults", "read", CHROME_APP_DOMAIN, "AppleLanguages"])
    if code != 0:
        return None
    tags = re.findall(r'"([^"]+)"', body)
    if tags:
        return tags
    bare = body.strip().strip("()").strip()
    return [bare] if bare else None


def locale_change_time(languages) -> str | None:
    """这份 Chrome 应用语言是什么时候被改的 —— **只有我们亲手改过才有依据**。

    依据来自 clear_browser_locale 写下的回滚凭据（里面记着改动时刻和改成什么）。
    对得上就返回那个时刻；对不上（用户自己在系统设置里改的、或者状态目录被清过）
    就返回 None，不猜。

    早前试过「自己记一份值 + 发现值变了就记当前时间」，那个规则本身会误判：
    上次跑是两天前、Chrome 昨天重启过，就会把「两次巡检之间变了」当成「刚刚变的」，
    报出根本不存在的「要重启」。宁可说不判断，也不给一个看着像证据的猜。
    """
    try:
        data = json.loads(LOCALE_ROLLBACK_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not languages:
        return None
    after = data.get("after")
    if not after or list(after) != list(languages):
        return None
    at = data.get("at")
    return at if isinstance(at, str) else None


def chrome_needs_restart(changed_at: str | None = None) -> bool | None:
    """Chrome 正在跑，但它启动得比「应用语言改动的时刻」早 —— 那要重启才生效。

    changed_at 由 locale_change_time() 给出：只有我们亲手改过才有这个时刻。**没有这个时刻就返回 None**：
    偏好文件的 mtime 不是证据（Chrome 自己会重写它），拿它判会误报。判断不了
    就说不判断，让人用 --check-locale 看浏览器自己报的读数。
    """
    code, body = run(["pgrep", "-x", "Google Chrome"])
    if code != 0 or not body.strip():
        return None
    pid = body.split()[0]
    # LC_ALL=C 是必须的：本机 LANG=zh_CN.UTF-8，ps 会按本地化打印月份，
    # strptime 用 C 格式解析会直接失败。
    code, body = run(["env", "LC_ALL=C", "ps", "-o", "lstart=", "-p", pid])
    if code != 0 or not body.strip():
        return None
    try:
        started = dt.datetime.strptime(body.strip(), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None
    if not changed_at:
        return None
    try:
        changed = dt.datetime.strptime(changed_at, "%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return None
    return started < changed


def check_browser_locale(ip: dict | None = None) -> dict:
    """A27 浏览器 Intl 区域设置（ippure 权重 10）。

    优先用浏览器复核回来的实测值；没有就用 AppleLanguages 推定，并在 source 里
    写明是推定 —— 不能拿推定值冒充实测。
    """
    out = {"measured": None, "source": None, "checked_at": None, "predicted": None,
           "app_override": None, "system_languages": None, "country": None,
           "target": None, "cn": False, "needs_restart": None, "facts": [],
           "browser_timezone": None, "exit_timezone": None}
    ip = ip if ip is not None else check_export_ip()
    out["country"] = (ip.get("country") or "").upper() or None
    out["target"] = LOCALE_BY_COUNTRY.get(out["country"] or "", DEFAULT_LOCALE)

    code, body = run(["defaults", "read", "-g", "AppleLanguages"])
    out["system_languages"] = re.findall(r'"([^"]+)"', body) if code == 0 else None
    out["app_override"] = chrome_app_languages()

    chain = out["app_override"] or out["system_languages"] or []
    out["predicted"] = predict_intl_locale(chain[0] if chain else None)

    cached = load_browser_locale()
    if cached.get("intlLocale"):
        out["measured"] = cached["intlLocale"]
        out["checked_at"] = cached.get("checkedAt")
        out["source"] = "浏览器实测"
        # 时区是同一张复核页顺手带回来的（页面本来就在收 timeZone），
        # 以前收了没用。这里只报事实、不下判定 —— 见下面 facts 里的说明。
        if cached.get("timeZone"):
            out["browser_timezone"] = cached["timeZone"]
    elif out["predicted"]:
        out["measured"] = out["predicted"]
        out["source"] = "按 AppleLanguages 推定，未跑浏览器复核"

    out["cn"] = is_cn_locale(out["measured"])
    if out["measured"]:
        out["facts"].append(f"Intl 区域设置 {out['measured']}（{out['source']}）")
    else:
        out["facts"].append("既没跑过浏览器复核，也读不到 AppleLanguages，这一项没测到")
    if out["app_override"]:
        out["facts"].append("Chrome 应用语言已被设为 " + "、".join(out["app_override"]))
        out["needs_restart"] = chrome_needs_restart(locale_change_time(out["app_override"]))
        if out["needs_restart"]:
            out["facts"].append(
                "Chrome 现在这个进程是这份值改之前启动的，要完全退出再打开才生效")
        elif out["needs_restart"] is None:
            out["facts"].append(
                "判断不了 Chrome 这个进程有没有吃上这份值（没有「它是什么时候改的」"
                "记录）；要确认就跑 --check-locale，看浏览器自己报的读数")
    btz = out.get("browser_timezone")
    if btz:
        out["facts"].append(f"浏览器时区 {btz}（实测）")
        extz = (ip or {}).get("timezone")
        out["exit_timezone"] = extz
        if extz and btz != extz:
            # 故意不判对错：文章 §2.2 让你把时区改台北，§2.3 又要求系统时区
            # 跟出口同国，两条互斥。用户已经拍板按「台北 + 美国出口」走，
            # 那这是决定不是故障，表里翻转成待处理等于替用户推翻他自己的决定。
            out["facts"].append(
                f"出口时区是 {extz}，两者不同 —— 这是「时区在东亚、出口在美国」的"
                f"组合，文章 §2.2 与 §2.3 本身互相矛盾，按你拍板的走，不是故障")
        elif extz:
            out["facts"].append(f"与出口所在地时区一致（{extz}）")
    out["facts"].append(f"出口国家 {out['country'] or '未知'}，对应目标 locale {out['target']}")
    if out["cn"] and out["country"] and out["country"] != "CN":
        out["facts"].append(
            f"大陆简体 locale 配上 {out['country']} 出口，ippure 那一项会按中国用户计分"
        )
    return out


LOCALE_VERIFY_PAGE = """<!doctype html><meta charset="utf-8">
<title>Intl 区域设置复核</title>
<body style="font:15px -apple-system,system-ui;padding:24px;line-height:1.7">
<h3 style="margin:0 0 8px">Intl 区域设置复核</h3>
<div id="s">正在读取…</div>
<p style="color:#666">读到的就是 ippure.com/claude.html 那一项用的同一个值。
看到「已回传」就可以关掉本页。</p>
<script>
(() => {
  const d = Intl.DateTimeFormat().resolvedOptions();
  const payload = {
    intlLocale: d.locale,
    calendar: d.calendar,
    numberingSystem: d.numberingSystem,
    numberLocale: Intl.NumberFormat().resolvedOptions().locale,
    collator: new Intl.Collator().resolvedOptions().locale,
    language: navigator.language,
    languages: navigator.languages || [],
    timeZone: d.timeZone,
    offsetMinutes: new Date().getTimezoneOffset(),
    sampleDate: new Date(Date.UTC(2026, 9, 9, 12, 0, 0)).toLocaleDateString(),
    sampleCurrency: (99).toLocaleString(undefined, {style:"currency", currency:"USD"}),
  };
  document.getElementById("s").textContent =
    "Intl 区域设置 = " + payload.intlLocale + "    日期样例 = " + payload.sampleDate;
  fetch(location.pathname.replace(/\/+$/,"")+"/result", {method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify(payload)}).then(() => {
      document.getElementById("s").textContent += "    ✓ 已回传，可以关掉这一页";
    }).catch(() => {
      document.getElementById("s").textContent += "    ✗ 回传失败，请把这一行发给 Claude";
    });
})();
</script>"""


def verify_browser_locale(timeout: int = 240) -> dict:
    """起一个本地页面，请用户用日常浏览器打开，把真实的 Intl 区域设置收回来。

    为什么不自己测：Chrome 的资料文件受 TCC 保护，读不到 Profile 里的设置；而
    临时资料测出来的是「这台机器上新装 Chrome 的默认值」，不是用户那个资料的
    实测值 —— 这正是 WebRTC 那次踩过的假阴性。
    """
    import http.server
    import threading

    got: dict = {}
    ready = threading.Event()
    token = _verify_token()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if _verify_route(self.path, token) != "/":
                # 不认的路径就是 404：不知道这次令牌的本地进程连页面都取不到，
                # 也就拿不到页面里那段回传逻辑。
                self.send_error(404)
                return
            body = LOCALE_VERIFY_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if _verify_route(self.path, token) != "/result":
                self.send_error(404)
                return
            # 上限 64KB：回传的就那么几个字段，别让谁塞个几百兆进来把内存吃满。
            n = min(int(self.headers.get("Content-Length") or 0), VERIFY_MAX_BODY)
            try:
                got.update(json.loads(self.rfile.read(n) or b"{}"))
            except (json.JSONDecodeError, ValueError):
                got["error"] = "回传解析失败"
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            ready.set()

    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except OSError as e:
        print(f"  本地服务起不来：{e}")
        return {}
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # flush 必须加：这里会阻塞等浏览器回传，而 Python 在 stdout 不是 TTY 时
    # 会缓冲 —— 不刷新的话 URL 根本打不出来，用户不知道开哪个地址，只能等到超时。
    print("\n  用你要检查的那个 Chrome 资料打开：\n", flush=True)
    print(f"      http://127.0.0.1:{port}/{token}/\n", flush=True)
    print(f"  链接里那串是本次随机令牌，别改也别分享；页面会自动回传，最多等 {timeout} 秒（Ctrl-C 可取消）...",
          flush=True)
    try:
        ready.wait(timeout=timeout)
    except KeyboardInterrupt:
        print("\n  已取消。")
        server.shutdown()
        server.server_close()
        return {}
    server.shutdown()
    server.server_close()

    if not ready.is_set():
        print("\n  没等到回传 —— 页面没打开，或者打开的不是这台机器上的浏览器。")
        return {}

    got["checkedAt"] = now_stamp()
    try:
        LOCALE_CACHE.parent.mkdir(parents=True, exist_ok=True)
        LOCALE_CACHE.write_text(json.dumps(got, ensure_ascii=False, indent=2), encoding="utf-8")
        hand_back_ownership(LOCALE_CACHE)
        print(f"\n  结果已存：{str(LOCALE_CACHE).replace(str(HOME) + '/', '')}")
    except OSError as e:
        print(f"\n  结果存不下来（{e}），但下面的结论有效")

    loc = got.get("intlLocale") or "(没读到)"
    mark = "✗" if is_cn_locale(got.get("intlLocale")) else "✓"
    print(f"\n  {mark} Intl 区域设置 = {loc}；navigator.language = {got.get('language')}"
          f"；时区 {got.get('timeZone')}（offset {got.get('offsetMinutes')}）")
    print(f"      日期样例 {got.get('sampleDate')}；货币样例 {got.get('sampleCurrency')}")
    return got


def clear_browser_locale(rep: dict) -> str:
    """把 Chrome 的应用语言对到出口国家上。只影响 Chrome，不动系统语言。"""
    if not rep.get("cn"):
        return "浏览器 Intl 区域设置不是大陆简体，无需改动"
    target = rep.get("target") or DEFAULT_LOCALE
    before = rep.get("app_override")
    rollback = (f"defaults delete {CHROME_APP_DOMAIN} AppleLanguages" if before is None
                else f"defaults write {CHROME_APP_DOMAIN} AppleLanguages -array " + " ".join(before))
    try:
        LOCALE_ROLLBACK_FILE.parent.mkdir(parents=True, exist_ok=True)
        LOCALE_ROLLBACK_FILE.write_text(json.dumps({
            "at": now_stamp(), "domain": CHROME_APP_DOMAIN,
            "before": before, "after": [target], "rollback": rollback,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        hand_back_ownership(LOCALE_ROLLBACK_FILE)
    except OSError:
        pass

    code, body = run(
        ["defaults", "write", CHROME_APP_DOMAIN, "AppleLanguages", "-array", target], timeout=20
    )
    if code != 0:
        raise RuntimeError(f"defaults write 失败：{body.strip()}")
    after = chrome_app_languages()
    if not after or after[0] != target:
        raise RuntimeError(f"写完复查没生效，读到 {after}")
    return (
        f"已把 Chrome 的应用语言设为 {target} —— 只影响 Chrome，系统语言没动。"
        f"注意 Chrome 的界面语言也会跟着变成英文；"
        f"**要完全退出 Chrome 再打开才生效**。回滚：{rollback}"
    )


def build_summary(report: dict) -> list:
    """把体检报告压成「哪些解决了、哪些没有」的行。

    每一行的判定都来自报告里的实测字段，没有写死的结论——
    报告里没有的值一律当「没测到」，不假装通过。
    """
    ip = report.get("A1_export_ip") or {}
    pr = report.get("A1_proxy_residue") or {}
    te = report.get("A1_terminal_env") or {}
    ab = report.get("A2_anthropic_base_url") or {}
    tm = report.get("A3_telemetry") or {}
    v6 = report.get("A5_ipv6") or {}
    dn = report.get("A6_dns") or {}
    wr = report.get("A7_webrtc") or {}
    gg = report.get("A9_geo_words") or {}
    th = report.get("A10_third_party") or {}
    ci = report.get("A11_client_integrity") or {}
    cg = report.get("A12_clash_groups") or {}
    ma = report.get("A13_multi_account") or {}
    co = report.get("A15_consistency") or {}
    tl = report.get("A21_timezone_layers") or {}
    bl = report.get("A27_browser_locale") or {}
    kc = report.get("E1_keychain") or {}
    rows = []

    def add(name, status, detail):
        rows.append((name, status, detail))

    def missing(key) -> bool:
        """这一项这次根本没测到。

        缺字段绝不能默认成「干净」——那等于没测也说没问题。表里的每一行
        要么基于实测值，要么明确标成「未测到」。
        """
        return key not in report

    # ── 出口与身份 ──
    if missing("A1_export_ip"):
        add("出口 IP 与归属", S_NA, "未检测")
    elif ip.get("ip"):
        detail = f"{ip['ip']}  {ip.get('city')}/{ip.get('country')}"
        if ip.get("geo_conflict"):
            detail += f"（两个地理库打架：{ip['geo_conflict']}）"
        prev = ip.get("previous") or {}
        if ip.get("changed"):
            detail += (f"；⚠ 与上次不同：上次 {prev.get('ip')}"
                       f"（{prev.get('city')}/{prev.get('country')}，记于 {prev.get('checkedAt')}）")
            add("出口 IP 与归属", S_FIX, detail)
        elif prev:
            detail += f"；与上次一致（上次记于 {prev.get('checkedAt')}）"
            add("出口 IP 与归属", S_OK, detail)
        else:
            detail += "；第一次记录，下次体检就能比对"
            add("出口 IP 与归属", S_OK, detail)
    else:
        add("出口 IP 与归属", S_BAD, "取不到出口 IP，代理可能没在工作")

    verdict = ip.get("verdict") or ""
    if "住宅" in verdict or "ISP" in verdict:
        add("出口 ASN 类型", S_OK, verdict)
    elif verdict:
        add("出口 ASN 类型", S_BAD, f"{verdict}——机房 IP 是文章 2.3 明确要避开的")
    else:
        add("出口 ASN 类型", S_NA, "未取到 ASN 判定")

    # ── 泄漏面 ──
    if missing("A1_proxy_residue"):
        add("系统代理残留", S_NA, "未检测")
    elif pr.get("enabled"):
        add("系统代理残留", S_BAD, f"系统代理处于启用状态：{pr['enabled']}（TUN 与系统代理不该叠着）")
    elif pr.get("residue"):
        add("系统代理残留", S_FIX, f"{len(pr['residue'])} 项未启用但存着值，自动清理会清掉")
    else:
        add("系统代理残留", S_OK, "四个开关全为 0，网络服务也没有存值")

    cdc = dn.get("clash") or {}
    if missing("A6_dns"):
        add("DNS 泄漏", S_NA, "未检测")
    elif (dn.get("real_ip_hosts") or []):
        add("DNS 泄漏", S_BAD, f"这些域名解析到了真实公网 IP：{(dn.get('real_ip_hosts') or [])[:3]}")
    elif cdc.get("leaking") or cdc.get("leaking_fallback"):
        bad = list(cdc.get("leaking") or []) + list(cdc.get("leaking_fallback") or [])
        where = "主解析器" if cdc.get("leaking") else "fallback"
        add("DNS 泄漏", S_FIX,
            where + "含国内服务器（" + "、".join(bad[:2]) + "），"
            "国外域名的解析交给了它们；自动清理会换成境外解析器")
    elif cdc.get("found") and not cdc.get("respect_rules"):
        add("DNS 泄漏", S_FIX,
            "没开 respect-rules —— Clash 自己的 DNS 查询不跟规则走，是从真实 IP 直发的；"
            "自动清理会打开")
    elif cdc.get("enabled") is False:
        add("DNS 泄漏", S_FIX,
            "Clash 配置里 dns.enable 是关的，DNS 模块根本没在跑；自动清理会打开")
    elif cdc.get("tun_enabled") and not cdc.get("hijack"):
        add("DNS 泄漏", S_FIX,
            "TUN 开着但没配 dns-hijack —— 发往 53 端口的查询不会被内核接管，"
            "会照原样落到系统配的解析器上；自动清理会补上")
    elif dn.get("fake_ip"):
        ns = cdc.get("nameserver") or []
        tail = "全部落进 fake-ip 段，TUN 劫持生效"
        if cdc.get("hijack"):
            tail += "（dns-hijack：" + "、".join(cdc["hijack"]) + "）"
        add("DNS 泄漏", S_OK,
            ("解析器 " + "、".join(ns[:2]) + "，" if ns else "")
            + "无国内解析器，" + tail)
    else:
        add("DNS 泄漏", S_NA, "未取到解析结果，无法判断")

    # ippure 权重 10 的那一项。判据只认大陆简体：港台 locale 不算。
    if missing("A27_browser_locale"):
        add("浏览器 Intl 区域设置", S_NA, "未检测")
    elif not bl.get("measured"):
        add("浏览器 Intl 区域设置", S_NA,
            "没测到：既没跑过 --check-locale，也读不到 AppleLanguages")
    elif bl.get("cn") and (bl.get("country") or "") not in ("", "CN"):
        add("浏览器 Intl 区域设置", S_FIX,
            f"{bl['measured']} 是大陆简体；出口是 {bl.get('country')}，"
            f"ippure 会按中国用户计分，应改成 {bl.get('target')}")
    elif bl.get("needs_restart"):
        # 值已经改对了，但正在跑的那个 Chrome 进程还没吃到——它报出来仍是旧值。
        # 这种情况报绿等于替浏览器撒谎，必须留着让用户点一下。
        add("浏览器 Intl 区域设置", S_FIX,
            f"应用语言已设为 {bl.get('target')}，但 Chrome 是改之前启动的，"
            f"完全退出再打开才生效")
    else:
        add("浏览器 Intl 区域设置", S_OK,
            f"{bl['measured']}（{bl.get('source')}），出口 {bl.get('country') or '未知'}")
    if wr.get("available"):
        wm = wr.get("with_media") or {}
        tun = wm.get("tun_leak") or []
        media_ips = [e["ip"] for e in (wm.get("local_ips") or [])]
        shell = chromium_is_headless_shell(wr.get("browser"))
        # 探测是强制授权的，量的是「拿到权限会怎样」。如果用户已经把权限禁掉
        # （--check-media 复核过），那条路径就不可达了——这时候再报「待处理」
        # 就是挂着一个已经修好的项。所以先看复核结果。
        mp = load_media_permission()
        if mp.get("ok") and (tun or media_ips):
            add("WebRTC 泄漏", S_OK,
                f"授权后会露出 {tun[0] if tun else media_ips[0]}，但已经在浏览器里禁掉了"
                f"摄像头/麦克风（复核于 {mp.get('checkedAt')}），网站拿不到权限，"
                f"mDNS 混淆一直生效")
            _webrtc_row_done = True
        else:
            _webrtc_row_done = False
        if _webrtc_row_done:
            pass
        elif wr.get("leaked_public"):
            add("WebRTC 泄漏", S_BAD, f"探测到公网地址：{wr['leaked_public']}")
        elif tun:
            # 最要紧的一种：网站拿到摄像头/麦克风权限后，候选里会带上 Clash 的 TUN 地址。
            # 198.18.0.0/15 是 RFC 2544 保留段，出现它等于自报在用 Clash 类代理。
            add("WebRTC 泄漏", S_FIX,
                f"没授权时只有 mDNS 候选；一旦网站拿到摄像头/麦克风权限，会露出内网地址"
                f"（含 Clash 的 TUN 地址 {tun[0]}，属于代理招牌）。"
                f"修法是别让网站拿到权限：Chrome 设置 → 隐私和安全 → 网站设置 → 摄像头/麦克风 → 不允许")
        elif media_ips and not shell:
            add("WebRTC 泄漏", S_FIX,
                f"没授权时不泄漏；拿到媒体权限后会露出内网地址 {media_ips}。"
                f"修法是在 Chrome 里把摄像头/麦克风设成不允许")
        elif wr.get("candidates"):
            extra = "，候选均为 mDNS 混淆的主机名" if wr.get("mdns") else ""
            if shell:
                extra += "；但这次用的 headless shell，它看不到真实地址，结论只覆盖一半"
            add("WebRTC 泄漏", S_OK, f"取到 {wr['candidates']} 个候选，无公网地址{extra}")
        else:
            add("WebRTC 泄漏", S_NA, wr.get("note") or "探测未取到候选，结论不可用")
    else:
        # 没跑探测时，如果用户在真实浏览器里复核过（--check-media --webrtc 之外的那条路），
        # 就以那次结论为准。这一行要的东西其实是「网站能不能拿到摄像头/麦克风」，
        # 那次复核已经答了；再挂一个「未探测」等于让人以为必须重跑两分钟的探测。
        # 注意：这条分支只在**没有**探测结果时走，探测跑过时以探测为准。
        mp = load_media_permission()
        if mp.get("ok"):
            add("WebRTC 泄漏", S_OK,
                f"这次没跑探测；但已在浏览器里复核过摄像头与麦克风都拿不到"
                f"（复核于 {mp.get('checkedAt')}），授权那条路径不可达，mDNS 混淆一直生效")
        else:
            add("WebRTC 泄漏", S_NA, wr.get("note") or "未探测；加 --webrtc 参数可跑")

    v6g = v6.get("global_addresses") or []
    if missing("A5_ipv6"):
        add("IPv6 全局地址", S_NA, "未检测")
    elif v6g:
        add("IPv6 全局地址", S_FIX, f"{len(v6g)} 个全局地址；关掉可少一条绕过代理的路径")
    else:
        add("IPv6 全局地址", S_OK, "没有全局地址，只有链路本地")

    # ── 时区 ──
    if tl.get("all_taipei"):
        add("时区是否锁在台北", S_OK, "  ".join(f"{k}={v}" for k, v in (tl.get("layers") or {}).items()))
    elif tl:
        add("时区是否锁在台北", S_BAD, "  ".join(f"{k}={v}" for k, v in (tl.get("layers") or {}).items()))
    else:
        add("时区是否锁在台北", S_NA, "未检测")

    g1, g2 = tl.get("gate_auto_plist"), tl.get("gate_location")
    cached = tl.get("gate_location_cached") or {}
    if g1 is False and g2 is False:
        if cached:
            add("时区两道闸", S_OK,
                f"按位置自动设定=已关，定位服务设定时区=已关（root 实测于 {cached.get('checkedAt')}，之后没再复核）")
        else:
            add("时区两道闸", S_OK, "按位置自动设定=已关，定位服务设定时区=已关")
    elif g1 is False and g2 is None:
        # 读不到那道闸时，timed 对定位源的处理是个有用的旁证，一起报出来。
        # 但它只是旁证，不能当成「已关」——判定仍然是「未测到」。
        hint = ""
        if tl.get("source_available") is False:
            hint = f"；旁证：timed 在 {tl.get('source_event_at')} 记录定位源不可用"
        add("时区两道闸", S_FIX,
            f"按位置自动设定=已关；定位服务那道读不到（要 root）{hint}")
    elif g1 is True or g2 is True:
        tail = f"（其中定位服务那道来自 root 实测于 {cached.get('checkedAt')}）" if cached else ""
        add("时区两道闸", S_BAD,
            f"按位置自动设定={gate_text(g1)}，定位服务设定时区={gate_text(g2)}{tail}")
    else:
        add("时区两道闸", S_NA, f"按位置自动设定={gate_text(g1)}，定位服务设定时区={gate_text(g2)}")

    # ── 代理与线路 ──
    fc = cg.get("fail_closed") or {}
    if not cg.get("reachable"):
        add("绝不直连", S_NA, "Clash 控制接口不可达，这一项没测到")
    elif fc.get("ok"):
        # 两种模式下「成立」的理由不同，说明文字也得跟着变，否则会写出让人误解的链路
        grp = cg.get("claude_group") or {}
        n_rules = len([r for r in (cg.get("claude_rules") or []) if r.get("proxy") == "Claude"])
        if cg.get("mode") == "global":
            detail = (f"全局模式，全部流量走 GLOBAL → {cg.get('global_now')} → {grp.get('now')}")
        else:
            detail = (f"规则模式，{n_rules} 条规则把 Claude 域名交给专用组 → {grp.get('now')}"
                      f"；兜底 {(cg.get('fallback') or {}).get('proxy')}")
        add("绝不直连", S_OK, detail + "（单成员、无健康检查、不自动切换）")
    else:
        add("绝不直连", S_BAD, "；".join(fc.get("reasons") or ["判据不成立"]))

    # ── 本地 Git（文章 §6 第 11 步、§9 清单末条）──
    lg = report.get("A14_local_git") or {}
    if missing("A14_local_git"):
        add("代码是否落在本地 Git", S_NA, "未检测")
    elif lg.get("note"):
        add("代码是否落在本地 Git", S_NA, lg["note"])
    else:
        repos = lg.get("repos") or []
        dirty = lg.get("dirty") or []
        if not repos:
            # 一个仓库都没有才是文章说的那种情况：代码只活在 Claude 的会话里
            add("代码是否落在本地 Git", S_FIX,
                f"扫到的目录里一个 git 仓库都没有，{len(lg.get('no_git') or [])} 个目录没做版本控制")
        else:
            detail = f"{len(repos)} 个仓库在做版本控制"
            if dirty:
                detail += f"，其中 {len(dirty)} 个有未提交改动"
            add("代码是否落在本地 Git", S_OK, detail)

    # ── 作息（文章 §2.3 末）──
    sc = report.get("A22_schedule") or {}
    if missing("A22_schedule") or sc.get("note"):
        add("作息与出口时区", S_NA, sc.get("note") or "未检测")
    elif sc.get("exit_time"):
        detail = f"本地 {sc.get('local_time')}（{sc.get('local_tz')}）／出口 {sc.get('exit_time')}（{sc.get('exit_tz')}）"
        # 只报事实，不翻状态。这条判据第一版会在出口当地是深夜时标成待处理，于是
        # 同一台机器隔几个小时跑，结论就在 ✓ 和 ⚠ 之间来回跳——一个随时辰变化的
        # 「待处理」不是待办。文章 2.3 末尾也把它排在固定出口后面（「只影响画像」），
        # 所以事实照报，状态保持已解决。
        if sc.get("deep_night"):
            detail += "；出口当地是深夜，与本地白天对不上（文章 2.3 说这条只影响画像，优先级排在固定出口后面）"
        add("作息与出口时区", S_OK, detail)
    else:
        add("作息与出口时区", S_NA, "未取到出口时区")

    # ── 浏览器资料（文章 2.6）──
    bp = report.get("A23_browser_profiles") or {}
    if missing("A23_browser_profiles"):
        add("浏览器资料是否隔离", S_NA, "未检测")
    elif not bp.get("browsers"):
        add("浏览器资料是否隔离", S_NA, bp.get("note") or "没找到浏览器资料")
    elif bp.get("total", 0) <= 1:
        add("浏览器资料是否隔离", S_FIX,
            f"只有 {bp['total']} 个资料，没有给 Claude 单独建（文章 2.6）")
    else:
        names = "、".join(f"{k} {v['count']} 个" for k, v in bp["browsers"].items())
        add("浏览器资料是否隔离", S_OK, f"{names}；脚本判断不了哪个是给 Claude 用的，自己确认一次")

    # ── 项目级 .claude（文章 2.6 只提家目录，项目级这块是实测出来的）──
    pc = report.get("A24_project_claude") or {}
    if missing("A24_project_claude") or pc.get("note"):
        add("项目级 .claude 规模", S_NA, pc.get("note") or "未检测")
    elif not pc.get("dirs"):
        add("项目级 .claude 规模", S_NA, "扫到的项目里没有 .claude 目录")
    else:
        wt_pct = pc["worktrees_bytes"] / max(pc["total_bytes"], 1) * 100
        detail = (f"{pc['dirs']} 个目录 {pc['total_bytes'] / 2 ** 30:.1f} GB，"
                  f"其中 worktrees 占 {wt_pct:.0f}%（真实代码，不清理）")
        stale = pc.get("stale_total") or 0
        if stale:
            detail += f"；另有 {stale} 条已失效的工作树注册可划掉"
            add("项目级 .claude 规模", S_FIX, detail)
        else:
            detail += "；没有失效的工作树注册"
            add("项目级 .claude 规模", S_OK, detail)

    # ── 系统级占用（旧版本 + 可再生缓存）──
    st = report.get("A25_claude_storage") or {}
    if missing("A25_claude_storage") or st.get("note"):
        add("系统级可清理量", S_NA, st.get("note") or "未检测")
    else:
        n_stale = len(st.get("cli", {}).get("stale") or []) + len(st.get("bundled", {}).get("stale") or [])
        n_cache = len(st.get("caches") or [])
        cur = st.get("cli", {}).get("current") or "?"
        if st.get("cleanable_bytes"):
            add("系统级可清理量", S_FIX,
                f"当前 CLI {cur}；有 {st['cleanable_bytes'] / 2 ** 20:.0f} MB 可清"
                f"（旧版本 {n_stale} 份 + 可再生缓存 {n_cache} 个）")
        else:
            add("系统级可清理量", S_OK,
                f"当前 CLI {cur}；没有攒下旧版本，缓存目录也是空的")

    # ── 项目级 settings 的权限条目 ──
    cs = report.get("A26_claude_settings") or {}
    if missing("A26_claude_settings"):
        add("settings 失效权限", S_NA, "未检测")
    elif not cs.get("files"):
        add("settings 失效权限", S_NA, "扫到的项目里没有带权限的 settings")
    else:
        dead, risky = len(cs.get("dead") or []), len(cs.get("risky") or [])
        detail = f"{cs['files']} 个文件共 {cs['total']} 条授权"
        # 危险条目那段必须在 add() 之前拼完——第一版写在 add() 后面，
        # 结果永远显示不出来（用例抓到的）。
        if risky:
            detail += f"；另有 {risky} 条偏危险的长期授权（只报告，不代删）"
        if dead:
            detail += f"；其中 {dead} 条已证明失效可清"
            add("settings 失效权限", S_FIX, detail)
        else:
            detail += "；没有失效条目"
            add("settings 失效权限", S_OK, detail)

    # ── 残留与完整性 ──
    if missing("A1_terminal_env"):
        add("终端 / shell / npm / git 代理", S_NA, "未检测")
        env_n = rc_n = 0
        npmgit = []
    else:
        env_n = len(te.get("env_hits") or [])
        rc_n = sum(len(v) for v in (te.get("rc_files") or {}).values())
        npmgit = [v for v in list((te.get("npm") or {}).values()) + list((te.get("git") or {}).values())
                  if v and v.strip().lower() not in ("null", "undefined", "none")]
    rc_n = sum(len(v) for v in (te.get("rc_files") or {}).values())
    npmgit = [v for v in list((te.get("npm") or {}).values()) + list((te.get("git") or {}).values())
              if v and v.strip().lower() not in ("null", "undefined", "none")]
    npmrc_n = len(te.get("npmrc") or [])
    brew_n = len(((te.get("brew") or {}).get("proxy")) or [])
    if missing("A1_terminal_env"):
        pass
    elif env_n or rc_n or npmgit or npmrc_n or brew_n:
        extra = []
        if npmrc_n:
            extra.append(f"~/.npmrc {npmrc_n} 行")
        if brew_n:
            extra.append(f"Homebrew {brew_n} 项")
        add("终端 / shell / npm / git 代理", S_FIX,
            f"env {env_n} 条，rc {rc_n} 条，npm/git {len(npmgit)} 项"
            + ("；" + "、".join(extra) if extra else "") + "，自动清理会清掉")
    else:
        # 文章 2.5④ 那批命令有五处出处，一处一处写进证据里，别只说一句「没有代理」。
        add("终端 / shell / npm / git 代理", S_OK,
            "没有任何一处写着代理（环境变量、shell 配置、npm/git、~/.npmrc、brew config 都查过）")

    # 必须区分「Claude Code 自己的 settings.json」和「别的工具的配置」：
    # 前者会自动清掉，后者按范围约定只报告不代改。混在一起报会让用户以为
    # 那处残留会被处理掉，实际上脚本根本不会碰它。
    hits = ab.get("hits") or []
    own = [h for h in hits if "/.claude/" in str(h.get("file", ""))]
    if missing("A2_anthropic_base_url"):
        add("settings.json 端点与凭据", S_NA, "未检测")
        own = []
    other = [h for h in hits if "/.claude/" not in str(h.get("file", ""))]
    sp = te.get("settings_proxy") or []
    if missing("A1_terminal_env"):
        sp = []
    if missing("A2_anthropic_base_url"):
        pass
    elif own or sp:
        bits2 = []
        if own:
            bits2.append(f"{len(own)} 处指向别处")
        if sp:
            bits2.append("env 里的代理变量 " + "、".join(sp))
        add("settings.json 端点与凭据", S_FIX, "、".join(bits2) + "，自动清理会清掉")
    elif other:
        names = "、".join(sorted({pathlib.Path(h["file"]).name for h in other}))
        add("settings.json 端点与凭据", S_OK,
            f"Claude Code 自身没有残留；{len(other)} 处属其它工具（{names}），只报告不代改")
    else:
        add("settings.json 端点与凭据", S_OK, "没有 ANTHROPIC_BASE_URL、代理变量之类的残留")

    if missing("A3_telemetry"):
        add("遥测三键", S_NA, "未检测")
    elif tm.get("any_set"):
        add("遥测三键", S_OK, "已写入 settings.json 的 env")
    elif tm.get("note"):
        add("遥测三键", S_NA, tm["note"])
    else:
        add("遥测三键", S_FIX, "未设置；要不要关由你决定（会连带关功能旗标）")

    ges = gg.get("hits") or []
    if missing("A9_geo_words"):
        add("CLAUDE.md 地理位置词", S_NA, "未检测")
    else:
        add("CLAUDE.md 地理位置词", S_OK if not ges else S_FIX,
            "没发现" if not ges else f"{len(ges)} 处，会随 prompt 一起送给模型")

    if missing("A10_third_party"):
        add("第三方客户端", S_NA, "未检测")
    else:
        add("第三方客户端", S_OK if not th.get("hits") else S_BAD,
            "未发现" if not th.get("hits") else str(th["hits"]))

    if ci.get("cli_version"):
        stale = ci.get("stale_count", 0)
        inst = ci.get("install") or {}
        # method 缺失＝这份报告里根本没记（本次改动之前生成的报告），
        # 跟「探测过、四条通道都对不上」是两回事 —— 老报告不能被指控成未知安装。
        method = inst.get("method")
        detail = (f"CLI {ci['cli_version']}"
                  + (f"（{method} 安装）" if method else "")
                  + f"，versions 留 {ci.get('version_count', 0)} 份")
        if stale:
            detail += f"，非当前版本 {stale} 份占 {ci.get('stale_bytes', 0) // 1048576} MB"
        # 先收集「这份二进制本身有没有说不通的地方」，任一条命中就不报绿 ——
        # 签名有效只说明「这份是官方发的那份」，不等于「它就是现在该在用的那份」。
        problems = []
        if method == "unknown":
            problems.append("安装方式未知，四条通道一条都对不上")
        elif method is None:
            pass  # 没记过就不下结论，交给下面的签名判定
        if ci.get("version_runs") is False:
            problems.append("二进制在但跑不出 --version")
        elif ci.get("version_ok") is False:
            problems.append("版本号不像正常版本")
        if ci.get("current_present") is False:
            problems.append(f"软链指向的 {ci.get('current_version')} 不在 versions 目录里")
        if inst.get("layout_ok") is False:
            problems.append("官方安装的链接形状不对")
        sig = ci.get("signature") or {}
        authority = sig.get("authority") or ""
        if problems:
            add("CLI 完整性", S_FIX, detail + "；" + "、".join(problems))
        elif sig.get("verified") and "anthropic" in authority.lower():
            add("CLI 完整性", S_OK, detail + f"；签名 {authority}，验签通过")
        elif not sig.get("checked"):
            # 没跑成 codesign（本机没有、或不是 Mach-O）时，signed 是默认的 False，
            # 不看 checked 就会把「没测到」报成「没签名」。这一条必须排在前面。
            add("CLI 完整性", S_OK, detail + "（未能验签）")
        elif sig.get("signed") is False:
            # 先判没签名，再判验签失败 —— 没签名时 verify 必然也失败，
            # 顺序反了会把「官方安装流程之外的二进制」误报成「被改过」。
            add("CLI 完整性", S_FIX, detail + "；这份二进制没有签名，确认是不是官方装的")
        elif sig.get("verified") is False:
            add("CLI 完整性", S_BAD, detail + "；签名校验没通过，二进制可能被改过")
        elif authority:
            add("CLI 完整性", S_FIX, detail + f"；签名者是 {authority}，不是 Anthropic")
        else:
            add("CLI 完整性", S_OK, detail + "（未能验签）")
    else:
        add("CLI 完整性", S_NA, "没找到 claude 命令")

    if missing("E1_keychain"):
        add("钥匙串条目", S_NA, "未检测")
    elif kc.get("readable") and kc.get("items"):
        first = kc["items"][0]
        add("钥匙串条目", S_OK,
            f"{len(kc['items'])} 项：svce={first['svce']!r} acct={first['acct']!r}")
    elif kc.get("readable"):
        add("钥匙串条目", S_OK, kc.get("note") or "没有 Claude 相关项")
    else:
        add("钥匙串条目", S_NA, kc.get("note") or "未读到")

    # 只有带邮箱的身份才算「一个账号」；userID / machineID 是每台机器都有的本地标识，
    # 把它们算成账号会让「1 个账号」被误报成「2 个身份」。
    if missing("A13_multi_account"):
        add("多账号痕迹", S_NA, "未检测")
        identities = []
    else:
        identities = ma.get("identities") or []
    accounts = [i for i in identities if "@" in json.dumps(i, ensure_ascii=False)]
    if accounts:
        label = f"{len(accounts)} 个账号身份"
    elif identities:
        label = f"未发现账号身份（只有本地标识 {len(identities)} 项）"
    else:
        label = "未发现"
    if not missing("A13_multi_account"):
        add("多账号痕迹", S_OK if len(accounts) <= 1 else S_FIX, label)

    tension = co.get("tension") or []
    if missing("A15_consistency"):
        add("时区／出口／语言一致性", S_NA, "未检测")
    else:
        # 文章 §2.2 让你改台北、§2.3 又要求出口与账单同国，两条本身互斥。
        # 用户已确认按「台北时区 + 美国出口」这个组合走，这是拍板过的选择不是待办，
        # 所以不标成待处理，只在文字里说清楚。
        add("时区／出口／语言一致性", S_OK,
            "无冲突" if not tension else "时区在东亚、出口在美国（文章两条建议互斥，已确认按此组合走，无需改动）")

    return rows


def print_summary_table(report: dict) -> None:
    """打印最终结果总表。这是跑完之后用户唯一需要看的东西。"""
    rows = build_summary(report)
    solved = sum(1 for r in rows if r[1] is S_OK)
    todo = sum(1 for r in rows if r[1] is S_FIX)
    bad = sum(1 for r in rows if r[1] is S_BAD)
    na = sum(1 for r in rows if r[1] is S_NA)
    print()
    print(render_table(
        ("检查项", "状态", "实测结果"),
        [(name, status.strip(), truncate(detail, 58)) for name, status, detail in rows],
    ))
    print()
    print(f"  共 {len(rows)} 项：{S_OK} 已解决 {solved}    {S_FIX.strip()} 待处理 {todo}    "
          f"{S_BAD} 未解决 {bad}    {S_NA} 未测到 {na}")
    print("  ✓ = 已经没问题  ! = 能自动处理的或需要你点一下  ✗ = 有问题  · = 这次没测到")




def print_before_after(before: dict, after: dict) -> None:
    """收尾的「修复前 → 修复后」对照：只标通过没通过，不给实测值。

    before 是本次运行**动手之前**那份体检，after 是做完之后的复检。两遍都是真读数，
    所以这一栏不是回忆出来的，而是同一次运行里的前后。改动明细只在真发生变化时打，
    没变的项只留一个记号——跑完一堆步骤之后用户要看的是「哪些从没过变成过了」。
    """
    # 「没通过」只算 ! 与 ✗。· 是「这次没测到」（例如没跑 --webrtc、没给项目根目录），
    # 把它算进没通过会让复检表凭空多出几项红字。
    # 注意 S_FIX 是 "! "（带尾空格），判定一律拿原始常量比，只有打表时才 strip；
    # 两套混用会静默判错——这里踩过：逻辑用去空格的值，结果永远不相等。
    failed_marks = (S_FIX, S_BAD)
    was = {name: status for name, status, _ in build_summary(before)}
    rows, raw, fixed, still = [], [], [], []
    for name, status, detail in build_summary(after):
        old = was.get(name, S_NA)
        rows.append((name, old.strip(), status.strip()))
        raw.append((old, status))
        if old == status or status == S_NA:
            continue
        if status is S_OK and old in failed_marks:
            fixed.append((name, status, detail))
        elif status in failed_marks:
            still.append((name, status, detail))

    print()
    print(render_table(("检查项", "修复前", "修复后"), rows))
    print()
    failed_before = sum(1 for old, _ in raw if old in failed_marks)
    failed_after = sum(1 for _, new in raw if new in failed_marks)
    missed = sum(1 for _, new in raw if new == S_NA)
    line = f"  共 {len(rows)} 项：修复前没通过 {failed_before} 项 → 修复后没通过 {failed_after} 项"
    if missed:
        line += f"；另有 {missed} 项这次没测到（{S_NA}）"
    print(line)
    if fixed:
        print("  这次改好的：")
        for name, status, detail in fixed:
            print(f"    {status.strip()} {name} —— {truncate(detail, 60)}")
    if still:
        print("  仍然没通过（要你处理）：")
        for name, status, detail in still:
            print(f"    {status.strip()} {name} —— {truncate(detail, 60)}")

def check_schedule_consistency(ip: dict | None = None) -> dict:
    """A22 作息与出口时区对不对得上。文章 2.3 末尾那段。

    文章原话：「你在国内白天高强度写代码，换到美西就是凌晨三四点。有人特意挂夏威夷，
    时差一倒，看起来更像熬夜的本地开发者。不过这条只影响画像，优先级排在固定出口后面。」

    所以这条只报事实，不下判定：出口当地现在几点、你本地几点，差多少。
    出口当地是深夜而你在本地白天高频使用，就是一个不自然的作息信号。
    """
    out = {
        "local_tz": None, "local_time": None, "exit_tz": None,
        "exit_time": None, "exit_hour": None, "gap_hours": None,
        "deep_night": False, "note": "",
    }
    code, body = run(
        ["node", "-e", "console.log(Intl.DateTimeFormat().resolvedOptions().timeZone)"], timeout=20
    )
    if code == 0 and body.strip():
        out["local_tz"] = body.strip()
        try:
            out["local_time"] = dt.datetime.now(zoneinfo.ZoneInfo(out["local_tz"])).strftime("%H:%M")
        except Exception:
            pass

    exit_tz = (ip or {}).get("timezone")
    if not exit_tz:
        out["note"] = "出口 IP 没带回时区信息，这一项跳过"
        return out
    out["exit_tz"] = exit_tz
    try:
        now_exit = dt.datetime.now(zoneinfo.ZoneInfo(exit_tz))
    except Exception:
        out["note"] = f"认不出出口时区 {exit_tz}，这一项跳过"
        return out
    out["exit_time"] = now_exit.strftime("%H:%M")
    out["exit_hour"] = now_exit.hour
    # 当地时间与出口当地的时差。用 UTC 差算，跨日也对
    try:
        local_off = dt.datetime.now(zoneinfo.ZoneInfo(out["local_tz"])).utcoffset() if out["local_tz"] else None
        exit_off = now_exit.utcoffset()
        if local_off is not None and exit_off is not None:
            out["gap_hours"] = (exit_off - local_off).total_seconds() / 3600
    except Exception:
        pass
    # 出口当地凌晨 0 到 6 点，而你这边是白天——就是不自然的作息窗口
    out["deep_night"] = 0 <= now_exit.hour < 6
    return out


def check_local_git() -> dict:
    """A14 代码有没有落在本地 Git。文章 §6 第 11 步、§9 清单最后一条。

    文章原话「代码放本地 Git，别让项目只存在 Claude 里」。
    这一条既是保号习惯（别把 Claude 当唯一存储），也是号出问题时的退路。

    目录不猜，用 CLAUDE_GUARD_PROJECT_ROOTS 指定，冒号分隔；不设就跳过并说明怎么开。
    """
    out = {"roots": [], "repos": [], "no_git": [], "dirty": [], "note": ""}
    roots = [p for p in (os.environ.get("CLAUDE_GUARD_PROJECT_ROOTS") or "").split(":") if p.strip()]
    if not roots:
        out["note"] = (
            "未指定项目目录，这一项跳过。用 "
            "CLAUDE_GUARD_PROJECT_ROOTS=\"$HOME/CC_Project\" 指定（冒号分隔可写多个）"
        )
        return out
    for raw in roots:
        root = pathlib.Path(raw).expanduser()
        if not root.is_dir():
            out["note"] = f"目录不存在：{root}"
            continue
        out["roots"].append(str(root))
        # 只看一到两层，避免在大仓库里扫穿
        for child in sorted(root.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            if (child / ".git").exists():
                out["repos"].append(str(child))
                code, body = run(["git", "-C", str(child), "status", "--porcelain"], timeout=30)
                if code == 0 and body.strip():
                    out["dirty"].append({"repo": str(child), "changed": len(body.strip().splitlines())})
            else:
                out["no_git"].append(str(child))
    return out


def check_browser_profiles() -> dict:
    """A23 有没有给 Claude 单独建浏览器资料。文章 2.6。

    文章原话：「浏览器单独建一个资料（Chrome 右上角头像 → 添加），只用来登 Claude」，
    还提醒「环境配得再干净，在日常浏览器里点一下 Claude 的登录链接，真实 IP 就交出去了」。

    实现说明：Chrome 的 Local State 被 macOS 的 TCC 挡住了读不到（实测
    PermissionError: Operation not permitted），但**列目录不受限**，所以改用数资料目录。
    代价是拿不到资料的自定义名字，只能报数量——判断「哪个是给 Claude 用的」本来也判断不了，
    所以只报事实加建议，不判对错。
    """
    out = {"browsers": {}, "total": 0, "note": ""}
    for label, base in (
        ("Chrome", HOME / "Library" / "Application Support" / "Google" / "Chrome"),
        ("Edge", HOME / "Library" / "Application Support" / "Microsoft Edge"),
        ("Brave", HOME / "Library" / "Application Support" / "BraveSoftware" / "Brave-Browser"),
    ):
        if not base.is_dir():
            continue
        # 不能列目录：macOS 的 TCC 会让 iterdir() 报
        # PermissionError: Operation not permitted，但**对已知路径的 is_dir() 是放行的**。
        # 所以按浏览器固定的资料命名去探：Default、Profile 1、Profile 2……
        candidates = ["Default"] + [f"Profile {i}" for i in range(1, 10)]
        dirs = [name for name in candidates if (base / name).is_dir()]
        if not dirs:
            continue
        item = {"count": len(dirs), "names": sorted(dirs)}
        # Local State 能读就读，读得到就有自定义名字；读不到不影响数量
        try:
            data = json.loads((base / "Local State").read_text(encoding="utf-8", errors="replace"))
            cache = (data.get("profile") or {}).get("info_cache") or {}
            named = {k: (v.get("name") or "") for k, v in cache.items()}
            if named:
                item["labels"] = named
        except (OSError, json.JSONDecodeError, AttributeError):
            item["labels_note"] = "Local State 读不到（TCC 限制），只报数量"
        out["browsers"][label] = item
        out["total"] += len(dirs)
    if not out["browsers"]:
        out["note"] = "没找到 Chrome / Edge / Brave 的资料目录"
    return out


DESKTOP_CACHE_DIRS = (
    "Code Cache", "Cache", "GPUCache",
    "DawnWebGPUCache", "DawnGraphiteCache", "DawnCache",
)
DESKTOP_DATA = HOME / "Library" / "Application Support" / "Claude"
DESKTOP_BUNDLED = DESKTOP_DATA / "claude-code"
CLI_VERSIONS = HOME / ".local" / "share" / "claude" / "versions"


def _entry_size(p: pathlib.Path) -> int:
    return _dir_size(p) if p.is_dir() else (p.stat().st_size if p.is_file() else 0)


def current_cli_version() -> str | None:
    """查当前实际在用的 CLI 版本。

    走 `command -v claude` 再解析软链接——不能靠「版本号最大」来猜，
    官方安装器把每个版本放成独立可执行文件，指针才是唯一的真相。
    """
    code, body = run(["bash", "-lc", "command -v claude"], timeout=20)
    target = body.strip()
    if not target:
        return None
    code, body = run(["readlink", "-f", target], timeout=20)
    real = body.strip() or target
    name = pathlib.Path(real).name
    return name or None


def check_claude_storage() -> dict:
    """A25 系统级 Claude 占用里**可清理**的部分。

    口径与 claude-cleanup 一致：只清两类东西。

      1. 被取代的旧版本 —— CLI 自己留的历史版本，还有桌面版内置的那份。
         官方安装器本来就会清，卡住时就会攒着。实测本机攒了 4 份共 862 MB。
      2. 会自己重建的缓存 —— Electron 的 Code Cache / Cache / GPUCache / Dawn*。

    **用户数据一律不列**：Local Storage、IndexedDB、Cookies、Preferences、
    配置、会话、用量历史。这些都可能是账号状态的一部分，不是缓存。

    判断「哪份是旧的」用的是当前在跑的那份（软链接的指向），不是版本号大小——
    版本号比大小在 2.1.99 和 2.1.100 之间就会出错。
    """
    out = {
        "cli": {"current": None, "all": [], "stale": []},
        "bundled": {"current": None, "all": [], "stale": []},
        "caches": [], "cleanable_bytes": 0, "note": "",
    }
    cur = current_cli_version()
    out["cli"]["current"] = cur

    # CLI 版本目录
    if CLI_VERSIONS.is_dir():
        try:
            names = sorted(p.name for p in CLI_VERSIONS.iterdir())
        except OSError:
            names = []
        out["cli"]["all"] = names
        for name in names:
            if cur and name == cur:
                continue
            p = CLI_VERSIONS / name
            out["cli"]["stale"].append({"name": name, "bytes": _entry_size(p), "path": str(p)})

    # 桌面版内置的 CLI 副本
    if DESKTOP_BUNDLED.is_dir():
        try:
            names = sorted(p.name for p in DESKTOP_BUNDLED.iterdir() if p.is_dir())
        except OSError:
            names = []
        out["bundled"]["all"] = names
        out["bundled"]["current"] = cur if cur in names else (names[-1] if names else None)
        for name in names:
            if name == out["bundled"]["current"]:
                continue
            p = DESKTOP_BUNDLED / name
            out["bundled"]["stale"].append({"name": name, "bytes": _entry_size(p), "path": str(p)})

    # Electron 可再生缓存
    if DESKTOP_DATA.is_dir():
        for name in DESKTOP_CACHE_DIRS:
            p = DESKTOP_DATA / name
            if p.is_dir():
                out["caches"].append({"name": name, "bytes": _entry_size(p), "path": str(p)})

    out["cleanable_bytes"] = (
        sum(x["bytes"] for x in out["cli"]["stale"])
        + sum(x["bytes"] for x in out["bundled"]["stale"])
        + sum(x["bytes"] for x in out["caches"])
    )
    if not out["cli"]["all"] and not out["bundled"]["all"]:
        out["note"] = "没找到 Claude CLI 的安装目录，这一项跳过"
    return out


def clean_claude_storage(report: dict) -> list[dict]:
    """按 check_claude_storage 的结果执行清理。

    每一项都先确认路径存在、再删，并逐个回报删了多少。删之前不另做整份复制——
    这些东西要么是可再下载的旧版本，要么是会自己重建的缓存，整份备份反而比它们大。
    真正的账本写在调用方生成的清单文件里。
    """
    st = (report or {}).get("A25_claude_storage") or {}
    done = []
    groups = (
        ("cli-stale-version", st.get("cli", {}).get("stale") or []),
        ("bundled-stale-cli", st.get("bundled", {}).get("stale") or []),
        ("regenerable-cache", st.get("caches") or []),
    )
    for kind, items in groups:
        for item in items:
            p = pathlib.Path(item["path"])
            if not p.exists():
                done.append({"kind": kind, "path": str(p), "bytes": 0, "ok": False,
                             "error": "已经不在了"})
                continue
            try:
                if p.is_dir():
                    shutil.rmtree(p)
                else:
                    p.unlink()
                done.append({"kind": kind, "path": str(p), "bytes": item.get("bytes", 0), "ok": True})
            except OSError as e:
                done.append({"kind": kind, "path": str(p), "bytes": 0, "ok": False,
                             "error": f"{type(e).__name__}: {e}"})
    return done


def clean_project_claude_junk() -> list[dict]:
    """项目级 .claude 里对应「系统级可清理类别」的那点东西。

    实测只有两类，而且都很小：Finder 留下的 .DS_Store，和 skill 脚本跑出来的
    __pycache__。**不碰** skills/、settings*.json、agents/、hooks/、commands/——
    那些是配置和资产，对应系统级的 PROTECTED 名单；worktrees/ 里是真实代码，
    更不碰。

    有一个坑要避开：skill 目录下的 `*.log` 看着像日志，实际是 eval 的测试夹具
    （本机 294 个，全在 skills/*/evals/fixtures/ 下），删了会把测试弄坏。
    所以这里按「精确文件名」清，不按后缀扫。
    """
    done = []
    for root in project_roots():
        if not root.is_dir():
            continue
        for dp, dns, fns in os.walk(root, onerror=lambda e: None):
            p = pathlib.Path(dp)
            # 不下到 worktrees 里——那是真实代码树
            if "worktrees" in p.parts or "node_modules" in p.parts:
                dns[:] = []
                continue
            if ".claude" not in p.parts:
                continue
            for f in fns:
                if f == ".DS_Store":
                    fp = p / f
                    try:
                        fp.unlink()
                        done.append({"kind": "ds_store", "path": str(fp), "ok": True})
                    except OSError as e:
                        done.append({"kind": "ds_store", "path": str(fp), "ok": False, "error": str(e)})
            for d in list(dns):
                if d == "__pycache__":
                    dpth = p / d
                    size = _entry_size(dpth)
                    try:
                        shutil.rmtree(dpth)
                        done.append({"kind": "pycache", "path": str(dpth), "bytes": size, "ok": True})
                    except OSError as e:
                        done.append({"kind": "pycache", "path": str(dpth), "ok": False, "error": str(e)})
                    dns.remove(d)
    return done


SETTINGS_NAMES = ("settings.json", "settings.local.json")
ABS_PATH_RE = re.compile(r"(/(?:Users|home|opt|var|etc|usr|Applications)/[A-Za-z0-9_./\-\u4e00-\u9fff]{2,})")
# 信号量既可能是名字（-TERM）也可能是编号（-9），两边都要认。只写 [A-Za-z]+ 时
# `Bash(kill -9 47228 47230)` 会漏判——实测被用例抓出来。
PID_KILL_RE = re.compile(r"\bkill\s+(?:-[A-Za-z0-9]+\s+)?(\d{2,})\b")
# 站得住的「通用」权限是带通配的，比如 Bash(git add *)。下面这些即使带通配也偏危险。
RISKY_PERM_RE = re.compile(
    r"(Read\([^)]*\.ssh|Bash\([^)]*\bssh\b|Bash\(scp|Bash\(wget|Bash\(curl:?\*|"
    r"Bash\(kill:?\*|Bash\(pkill|Bash\(rm |Bash\(rm:|Bash\(chmod|Bash\(sudo|"
    r"Bash\(mysql \*|Bash\(docker \*|ssh-keygen)",
    re.I,
)


def permission_rule(entry) -> str | None:
    """取出权限条目的规则字符串，**不改它的类型**。

    条目有两种形态，两种都会遇到：
      "Bash(git add *)"            —— 纯字符串
      ["Bash(git add *)", null]    —— 两元数组，第二项是元数据
    只看第一种、把第二种漏掉会漏一半；把两者统一成字符串写回去，会把用户的
    文件格式改掉——实测踩过：241 条纯字符串被写成 209 条 ["...", null]，
    JSON 能解析、肉眼也像对的，但格式已经不是我该改的那个了。
    """
    # 数组只要求「第一个元素是字符串」，对长度宽容：真实格式是 [规则, 元数据]，
    # 以后多塞一个字段不该让整条被判成认不出来。
    if isinstance(entry, list) and entry and isinstance(entry[0], str):
        return entry[0]
    return entry if isinstance(entry, str) else None


def permission_is_dead(rule: str | None) -> str | None:
    """判断一条权限是不是**不可能再命中**了。返回原因，活着就返回 None。

    判据故意收得很紧，只认三种能证明的：

      * 一次性的 PID —— `Bash(kill 2220)`，那个进程早没了，这个号也不会再用；
      * 别的机器的路径 —— `/Users/别人/...`，这台机器上根本不存在；
      * 指向已消失的路径 —— 绝对路径连同父目录都没了。

    带通配的一律当活着。这里有个坑：`Bash(pnpm --filter @acme/schema build)`
    里的 `/schema` 会被朴素的正则当成路径，于是这条**在用的**权限被判死。
    所以只认 `/Users`、`/home`、`/opt` 这类真正的文件系统根开头。
    """
    if rule is None:
        return None
    if any(ch in rule for ch in ("*", "$", "?")):
        return None
    if PID_KILL_RE.search(rule):
        return "一次性的 PID"
    if OTHER_HOME_RE.search(rule):
        return "别的机器的路径"
    paths = ABS_PATH_RE.findall(rule)
    if paths and not any(
        pathlib.Path(p).exists() or pathlib.Path(p).parent.exists() for p in paths
    ):
        return "已消失的路径"
    return None


def check_claude_settings() -> dict:
    """A26 项目级 settings 里攒下的失效权限，以及偏危险的长期授权。

    Claude Code 每同意一次「总是允许」就往 `permissions.allow` 里加一条。日积月累
    会攒下大量一次性授权——实测本机 25 个文件 1127 条，其中 140 条可以证明不可能
    再命中（`Bash(kill 2220)` 这种）。

    这一项分成两半，处理方式不同：
      * `dead`   —— 证明失效的，可以自动清；
      * `risky`  —— 还活着但偏危险的（`Read(**/.ssh/**)`、`Bash(pkill ...)`），
                    **只报告不代删**。删了会让 Claude 多弹确认，是用户的取舍。
    """
    out = {"files": 0, "total": 0, "dead": [], "risky": [], "roots": []}
    for root in project_roots():
        if not root.is_dir():
            continue
        out["roots"].append(str(root))
        root_depth = len(root.parts)
        for dp, dns, fns in os.walk(root, onerror=lambda e: None):
            p = pathlib.Path(dp)
            if len(p.parts) - root_depth > MAX_PROJECT_DEPTH:
                dns[:] = []
                continue
            dns[:] = [d for d in dns if d not in ("node_modules", ".git", "worktrees")]
            if ".claude" not in p.parts:
                continue
            for name in SETTINGS_NAMES:
                f = p / name
                if not f.is_file():
                    continue
                try:
                    d0 = json.loads(f.read_text(encoding="utf-8", errors="replace"))
                except (OSError, json.JSONDecodeError):
                    continue
                allow = (d0.get("permissions") or {}).get("allow")
                if not isinstance(allow, list) or not allow:
                    continue
                out["files"] += 1
                out["total"] += len(allow)
                rel = str(f).replace(str(HOME) + "/", "")
                for entry in allow:
                    rule = permission_rule(entry)
                    if rule is None:
                        continue
                    why = permission_is_dead(rule)
                    if why:
                        out["dead"].append({"file": rel, "rule": rule, "why": why})
                    elif RISKY_PERM_RE.search(rule):
                        out["risky"].append({"file": rel, "rule": rule})
    return out


def clean_dead_permissions(report: dict) -> list[dict]:
    """清掉证明失效的权限条目。危险的长期授权不在这里处理。

    写回时**原对象原样放回**，不重建、不归一化——条目是字符串就还是字符串，
    是两元数组就还是两元数组。备份由调用方在动之前做。
    """
    st = (report or {}).get("A26_claude_settings") or {}
    dead_rules = {d["rule"] for d in (st.get("dead") or [])}
    if not dead_rules:
        return []
    by_file: dict[str, set[str]] = {}
    for d in st["dead"]:
        by_file.setdefault(d["file"], set()).add(d["rule"])

    done = []
    for rel, rules in by_file.items():
        f = HOME / rel
        if not f.is_file():
            done.append({"file": rel, "removed": 0, "error": "文件已不在"})
            continue
        try:
            d0 = json.loads(f.read_text(encoding="utf-8"))
            allow = (d0.get("permissions") or {}).get("allow")
            if not isinstance(allow, list):
                done.append({"file": rel, "removed": 0, "error": "allow 不是列表"})
                continue
            keep = [e for e in allow if permission_rule(e) not in rules]
            removed = len(allow) - len(keep)
            if not removed:
                done.append({"file": rel, "removed": 0, "error": None})
                continue
            d0["permissions"]["allow"] = keep
            f.write_text(json.dumps(d0, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            done.append({"file": rel, "removed": removed, "error": None})
        except (OSError, json.JSONDecodeError) as e:
            done.append({"file": rel, "removed": 0, "error": f"{type(e).__name__}: {e}"})
    return done


OTHER_HOME_RE = re.compile(
    r"/Users/(?!" + re.escape(HOME.name) + r"/)([A-Za-z0-9_.\-]+)/"
    r"|/home/([A-Za-z0-9_.\-]+)/"
)

MAX_PROJECT_DEPTH = 6


def _dir_size(p: pathlib.Path) -> int:
    """算目录实际占用。遇到读不到的条目跳过，不抛。"""
    total = 0
    for dp, _dns, fns in os.walk(p, onerror=lambda e: None):
        for f in fns:
            try:
                total += os.lstat(os.path.join(dp, f)).st_size
            except OSError:
                pass
    return total


def _worktree_registrations(repo: pathlib.Path) -> tuple[list[dict], int]:
    """读 git 的工作树注册表，返回 (全部条目, 其中指向已消失路径的条数)。"""
    code, body = run(["git", "-C", str(repo), "worktree", "list", "--porcelain"], timeout=30)
    if code:
        return [], 0
    entries, stale = [], 0
    for block in body.split("\n\n"):
        if not block.strip():
            continue
        d = {}
        for line in block.splitlines():
            if line.startswith("worktree "):
                d["path"] = line[9:]
            elif line.startswith("branch "):
                d["branch"] = line[7:]
        if not d:
            continue
        d["missing"] = not pathlib.Path(d["path"]).exists()
        if d["missing"]:
            stale += 1
        entries.append(d)
    return entries, stale


def check_project_claude() -> dict:
    """A24 项目级 .claude 的规模与健康状况。

    文章的 §2.6 只提了家目录的三处残留（`~/.claude`、钥匙串、应用支持目录），
    但真正占地方的是**项目里的** `.claude/worktrees`。

    这一项**只报事实，绝不自动删**。原因是实测出来的：本项目 53 个项目级
    `.claude` 合计 8.5 GB，其中 99% 是 `worktrees/`——那是 Claude Code 的
    git 工作树，里面是真实代码和 `backend/.env` 这类文件。按体积排序去清，
    删的正好是你还在用的东西。
    真正能安全清的是另一种：指向已消失路径的**过期注册**（只剩 `.git` 里
    一条记录，工作树目录早就没了），用 `git worktree prune` 处理。
    """
    out = {
        "roots": [], "dirs": 0, "total_bytes": 0, "worktrees_bytes": 0, "other_bytes": 0,
        "repos_with_stale": [], "stale_total": 0, "live_worktrees": 0, "note": "",
        "biggest": [],
    }
    roots = project_roots()
    if not roots:
        out["note"] = (
            "未指定项目目录，这一项跳过。用 "
            "CLAUDE_GUARD_PROJECT_ROOTS=\"$HOME/你的项目根\" 指定（冒号分隔可写多个）"
        )
        return out
    seen_repos = set()
    sizes = []
    for root in roots:
        if not root.is_dir():
            continue
        out["roots"].append(str(root))
        root_depth = len(root.parts)
        for dp, dns, _fns in os.walk(root, onerror=lambda e: None):
            p = pathlib.Path(dp)
            if len(p.parts) - root_depth > MAX_PROJECT_DEPTH:
                dns[:] = []
                continue
            # node_modules 里几乎每个包都带自己的 .git，不排掉会把注册数
            # 数成上千个——实测踩过，报出「活工作树 1464 个」这种明显不对的数。
            dns[:] = [d for d in dns if d not in ("node_modules", ".git")]
            if p.name == ".claude" and "node_modules" not in dp:
                dns[:] = []          # 不往 .claude 里面再找嵌套的
                out["dirs"] += 1
                size = _dir_size(p)
                out["total_bytes"] += size
                wt = p / "worktrees"
                wt_size = _dir_size(wt) if wt.is_dir() else 0
                out["worktrees_bytes"] += wt_size
                sizes.append((size, wt_size, p))
            # 顺路看看这个仓库有没有过期的工作树注册。
            # 这里必须用 is_dir() 而不是 exists()：工作树里的 `.git` 是个**文件**
            # （里面写着 gitdir: ...），exists() 一样为真，于是每个工作树都会把
            # 父仓库的整份列表再数一遍——实测报出「活工作树 1464 个」这种数。
            # 主工作树的 `.git` 是目录，只认它。
            if (p / ".git").is_dir() and p not in seen_repos:
                seen_repos.add(p)
                entries, stale = _worktree_registrations(p)
                out["live_worktrees"] += len(entries) - stale
                if stale:
                    out["stale_total"] += stale
                    out["repos_with_stale"].append({"repo": str(p), "stale": stale})
    out["other_bytes"] = out["total_bytes"] - out["worktrees_bytes"]
    sizes.sort(reverse=True)
    out["biggest"] = [
        {"path": str(p), "bytes": s, "worktrees_bytes": w} for s, w, p in sizes[:5]
    ]
    return out


def prune_stale_worktrees(repos: list[str]) -> list[dict]:
    """清掉指向已消失路径的工作树**注册**。这是项目级唯一安全的自动清理。

    `git worktree prune` 只删 `.git/worktrees/<name>` 里那条记录，条件是它指向的
    目录已经不存在。工作树本身、分支、提交都不动——数据的消失发生在更早，
    这一步只是把登记表上已经作废的条目划掉。

    活的工作树一律不碰：那是真实代码，删了就找不回来。
    """
    done = []
    for repo in repos:
        code, before = run(["git", "-C", repo, "worktree", "list", "--porcelain"], timeout=30)
        if code:
            done.append({"repo": repo, "error": "读不到工作树列表"})
            continue
        before_n = before.count("\nworktree ") + (1 if before.startswith("worktree ") else 0)
        code, body = run(["git", "-C", repo, "worktree", "prune", "-v"], timeout=60)
        if code:
            done.append({"repo": repo, "error": body.strip() or "prune 失败"})
            continue
        removed = [ln.split(":", 1)[0].replace("Removing ", "").strip()
                   for ln in body.splitlines() if ln.startswith("Removing ")]
        code, after = run(["git", "-C", repo, "worktree", "list", "--porcelain"], timeout=30)
        after_n = after.count("\nworktree ") + (1 if after.startswith("worktree ") else 0)
        done.append({"repo": repo, "before": before_n, "after": after_n,
                     "removed": removed, "error": None})
    return done


# ────────────────────────── 手工核对清单 ──────────────────────────
#
# 脚本能自动判的都在总表里。下面是「不想跑脚本、或者想自己复核一遍」时用的
# 原始命令，按面的顺序排。每条都写明期望值，对不上就是有问题。
#
# 其中带「文章 2.5」标记的是《你的 Claude 账号是怎么被封的》原文给的命令，
# 原样保留（包括它那条 grep 会把任何名字带 claude 的变量都算成残留，这里补了说明）。
# 其余是本机排查时补的，都在真机上跑通过。

SOCK_HINT = 'SOCK=/tmp/verge/verge-mihomo.sock; AUTH="Authorization: Bearer ${CLASH_SECRET:-<你的 secret>}"'

MANUAL_ACTIONS = (
    ("一、手机与其它设备（脚本碰不到）", (
        ("iPhone 时区", "文章 2.2",
         ("设置 → 通用 → 日期与时间 → 关掉「自动设置」→ 时区选台北",
          "设置 → 隐私与安全性 → 定位服务 → 系统服务 → 关掉「设定时区」"),
         "文章原话：「两端要对齐，电脑说自己在台北，手机说自己在上海，这本身就是一对矛盾信号」。两道都要关，只关自动设置不够"),
        ("Windows 端时区", "文章 2.2",
         ("设置 → 时间和语言 → 日期和时间 → 关闭「自动设置时区」",
          "时区选 (UTC+08:00) 台北"),
         "有第二台机器在同一个号上用时才需要；只有 Mac 就跳过"),
    )),
    ("二、浏览器与设备隔离", (
        ("给 Claude 单独建一个浏览器资料", "文章 2.6",
         ("Chrome 右上角头像 → 添加，建一个新资料，只用来登 Claude",
          "把这个资料固定到 Dock；日常那个资料里不要登 claude.ai",
          "claude.ai 发来的验证邮件，只在这个专用资料里点开"),
         "文章原话：「环境配得再干净，在日常浏览器里点一下 Claude 的登录链接，真实 IP 就交出去了」。注册阶段翻车最多的就是这一步"),
        ("Claude Code 的授权链接走哪打开", "文章 2.6",
         ("用 BROWSER=false claude 启动，它会打印授权链接而不唤起默认浏览器",
          "把链接复制到上面那个专用资料里打开"),
         "本 skill 可以帮你生成 claude-safe 包装脚本，走的就是这个方式"),
        ("一个号只在一台设备、一个资料里登录", "文章 2.6",
         ("不要借给同事、不要在第二台电脑上登同一个号",
          "登录信息、API Key、凭据都不要分享给任何人——条款里这一条和「不借号」是并列的",
          "手机端能不用就不用，社区复盘里有人只在电脑上用"),
         "文章把「同一台设备登多个账号」列为国庆这轮最扎眼的特征。注意方向：是一个号一台设备，不是多个号共用一台"),
    )),
    ("三、网页端设置（脚本读不到，只能手点）", (
        ("检查并踢掉陌生登录设备", "文章 2.6",
         ("打开 claude.ai → 左下角头像 → Settings → Account → Active sessions",
          "看到不认识的登录点，右边 ⋮ → Terminate"),
         "文章 2.6 把它列进「一号一环境」的必做项。这一步没有本地接口，只能进网页看"),
        ("关掉「帮助改进 Claude」", "文章 3.4",
         ("打开 claude.ai/settings/data-privacy-controls",
          "按你的意愿关掉帮助改进 Claude 的开关"),
         "官方文档写明：关掉后会话保留 30 天，开着是 5 年。它防不了封号，只是少交一份样本；被安全分类器判定违规的对话仍可能进安全审查"),
    )),
    ("四、账号与支付节奏（全是人的决定）", (
        ("邮箱与手机号", "文章 3.1",
         ("用自己能长期控制的 Gmail / Outlook / Proton，别用一次性邮箱",
          "别买二手谷歌邮箱；有条件用能长期控制的支持地区号码"),
         "文章原话：「老 Gmail 更稳」的说法没有公开依据，谷歌不会把账号年龄告诉 Anthropic"),
        ("验证邮件在哪点开", "文章 3.1",
         ("确认这封邮件只在上面的专用浏览器、且当前挂着的就是那条固定线路时点开",),
         "文章原话：「注册阶段翻车最多的，就是这一步」"),
        ("新号节奏", "文章 3.2 + 附 14",
         ("第 1～3 天：Free，每天正常聊几次、写点小东西，别立刻绑卡、开 Max、接 CLI 高并发",
          "第 4～7 天：出口仍然固定，再开 Pro",
          "第 2～3 周：真不够用再升 Max，周额度留余量",
          "第一次续费后：按真实工作量用，仍然不共享、不接第三方"),
         "文章把「新号加新卡直接开 Max 20x」列为风控里最显眼的一类，观察窗口大致在注册或充值后 24～72 小时"),
        ("额度见黄就停", "文章 3.2",
         ("看 Settings → Usage 里五小时窗口和周额度的重置时间",
          "进度条变黄就停下，别硬刷"),
         "文章原话：「限额不等于封号，换号绕过限制才像滥用」。这条零成本，来自被封过多个号的人"),
        ("付款渠道", "文章 3.3 + 附 7",
         ("第一次开会员能走 App Store 就走：iPhone 装官方 Claude App → 用同一个 Anthropic 账号登录 → 在 App 里升级",
          "别跳回网页绑卡"),
         "官网退款说明第一句就是「除条款明确规定或法律要求外，所有付款不退」。走 App Store 至少还能找 reportaproblem.apple.com"),
    )),
    ("五、使用行为（文章称为「第三层」）", (
        ("别把地理位置写进提示", "文章 §4",
         ("检查系统提示、CLAUDE.md、AGENTS.md 里有没有「我在北京」「国内用户」这类措辞",),
         "本 skill 的 A9 会自动扫本地能找到的 CLAUDE.md；但你自己写进 prompt 的内容它看不到"),
        ("别像脚本", "文章 §4",
         ("别 24 小时挂着跑、别连续把周额度刮干、别高并发",
          "新号前两周先用桌面端里的 Claude Code，收着点"),
         "中文本身不是罪名——文章原话「语言不是判决指标，网络指纹和调用频率才是」"),
        ("只用官方客户端", "文章 §5 + 附 5",
         ("不要接 OpenClaw、OpenCode、Cline、Roo Code、Sub2API、New API 这类第三方",
          "不要用带设备指纹伪装功能的 CAC"),
         "4 月 4 日起订阅额度已不覆盖第三方工具。本 skill 的 A10 会查本机有没有装这些"),
        ("内容不要碰红线", "文章 §4 + 附 5",
         ("反编译、大规模渗透、勒索代码这类，不要拿个人订阅硬刚",
          "正当的安全研究走官方的 Cyber Verification Program"),
         "实践哥的复盘里两个号同一天没，一个提示登录国家不对、一个是违反 usage policy——内容走的是另一条封禁通道，网络配得再干净也挡不住。官方对 Opus / Sonnet 有实时网络安全护栏"),
    )),
    ("六、被封之后", (
        ("确认是哪种情况再动手", "文章 §7 + 附 11",
         ("回复变敷衍 / 变慢 = 可能 IP 被标记，先查出口；额度用完 = 限额不是封号；服务繁忙 = 看 status.anthropic.com",
          "清 Cookie 后仍提示 disabled / restricted = 账号被限制，走申诉"),
         "文章附 11 那张表把五种表现的处置方式分开了，别把限额当成封号"),
        ("申诉只写事实", "文章 §7",
         ("登录 claude.ai，受限页面上就能打开申诉表",
          "先导出数据再决定删不删账号",
          "申诉写：账号邮箱、看到的提示原文、开始时间（带时区）、用的是网页 / Claude Code / API",
          "只是收到警告还没封：发邮件到 usersafety@anthropic.com"),
         "申诉推翻率大约十分之一，当成最后一块补丁"),
        ("处理退款与续费", "文章 §7",
         ("App Store 订阅去 reportaproblem.apple.com 申请",
          "官网订阅走左下角头像 → Get help → Send us a message → Claude Refund Request",
          "申请退款不会自动取消续费，记得同时取消"),
         "这是唯一一处「钱」的操作，本 skill 不代做"),
        ("别在同一台没清理过的电脑上秒开新号", "文章 §7 + §2.6",
         ("先把本机残留清干净再考虑下一步"),
         "文章原话「不要马上用同一台没清理过的电脑开新号硬冲」。条款也写明用新号绕过封禁本身违规——清残留是为了少被连坐，不是给开新号铺路"),
        ("被要求身份验证时，只能用本人真实证件", "文章 §1 九月新变化",
         ("按页面提示走官方身份验证流程，用本人真实证件",
          "不要找人代过验证，也不要用别人的证件"),
         "文章原话「用别人的证件、找人代过验证属于欺诈，后果比封号严重得多」。9 月的威胁情报报告写明，疑似在不受支持地区运行或疑似转售的账号会被要求身份验证，不通过就封——这一关环境配得再好也绕不过去"),
    )),
    ("七、出口这个节点本身（脚本只看得到 ASN，看不到纯净度）", (
        ("买完节点先自己验一遍类型和独享", "文章 2.3、§6 第 2 步",
         ("打开 ping0.cc 与 ippure.com：国家对不对、类型是不是家庭宽带 / ISP、共享人数多不多",
          "看到 Hosting / 机房就先找客服换，别急着登 Claude",
          "购买页通常会公示在售的 IP 段，下单前就能先查一次"),
         "本 skill 的 A1 与 A8 会自动报出口 IP 和 ASN 类型，但纯净度与共享人数它看不到——那两项只有检测站能给。文章原话：「共享是便宜，可共用的人里只要有谁去蒸馏、接第三方客户端，你都会被连坐」"),
        ("自建 VPS 要避开国内大厂的海外区", "文章 2.3",
         ("阿里云国际、腾讯云海外、火山引擎海外：不要用",
          "要自建就选搬瓦工、DMIT、Vultr 这类独立主机商"),
         "文章原话「IP 显示在美国，hostname 和 ASN 却还带着国内大厂」——这类出口比普通机房 IP 更扎眼，ASN 那一栏直接把来源写在脸上。另外自建 VPS 无论选谁都是 Hosting，风险高于住宅 IP"),
    )),
)


def print_manual_actions() -> None:
    """打印必须人工做的清单。这些没有本地接口，脚本替不了。"""
    print("\n" + "=" * 78)
    print("人工行动清单 —— 这些脚本碰不到，只能你自己做")
    print("=" * 78)
    print("  每一项都给出具体点击路径。做完打勾，下次换环境再走一遍。\n")
    total = 0
    for group, items in MANUAL_ACTIONS:
        print(f"\n【{group}】")
        for title, src, steps, why in items:
            total += 1
            print(f"\n  ☐ {title}   〔{src}〕")
            for step in steps:
                print(f"      · {step}")
            print(f"      为什么：{why}")
    print("\n" + "─" * 78)
    print(f"  共 {total} 项。换节点、重装系统、换电脑之后都该重走一遍（文章 2.5 的原话）。")
    print("─" * 78)


MANUAL_CHECKS = (
    ("一、出口与泄漏面", (
        ("出口 IP 与归属", "文章 2.5①",
         ("curl -s --noproxy '*' https://api.ipify.org",
          "curl -s ipinfo.io"),
         "国家固定、城市别每次变、org 不是一眼能认出是机房的名字。加 --noproxy 是为了走 TUN 而不是 7897 那个混合端口"),
        ("出口 ASN 类型", "文章 2.3",
         ('curl -s "https://ipinfo.io/$(curl -s --noproxy \'*\' https://api.ipify.org)/org"',
          "# 再拿前缀去 ARIN 查一遍归属，whois 见得多"),
         "住宅 ISP 与机房 IP 的区别就在这一栏；机房段容易被判定为代理"),
        ("WebRTC 泄漏", "文章 2.5②",
         ("# 修：Chrome 设置 → 隐私和安全 → 网站设置 → 摄像头 → 不允许网站使用",
          "#     同一页把「麦克风」也设成不允许",
          "# 验：https://browserleaks.com/webrtc，看 Media Devices 里权限显示不是 Prompt"),
         "浏览器里没有开关能「授权之后仍藏住内网 IP」——mDNS 混淆只在页面没有摄像头/"
         "麦克风权限时生效，这是设计如此（P2P 媒体流需要真实局域网地址）。四个 "
         "webRTCIPHandlingPolicy 取值实测都没效果，它们是扩展 API 的参数不是命令行开关。"
         "所以只能从权限下手：不让网站拿到权限，混淆就一直生效。"),
        ("DNS 泄漏", "文章 2.5③",
         ("dig example.com +short",
          "# 浏览器打开 https://browserleaks.com/dns"),
         "解析结果应落在 198.18.0.0/16（Clash 的 fake-ip-range 实测是 198.18.0.1/16）。出现真实公网 IP 说明劫持没生效"),
        ("IPv6 直连漏出", "文章 2.5 可选加固",
         ("ifconfig | grep inet6 | grep -vE 'fe80|::1'",
          "networksetup -getinfo Wi-Fi | grep -i ipv6"),
         "应无输出。必须排掉 ::1，否则 loopback 会被误报成全局地址（实测踩过）；只有 fe80 开头的链路本地地址也属正常"),
    )),
    ("二、系统与终端残留", (
        ("系统代理开关", "文章 2.5④",
         ('scutil --proxy | grep -E "HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable"',),
         "四个值都应是 0。出现 1 说明系统代理还开着，与 TUN 叠在一起"),
        ("网络服务里的残留值", "本会话补",
         ('networksetup -listallnetworkservices',
          'networksetup -getwebproxy Wi-Fi; networksetup -getsecurewebproxy Wi-Fi; networksetup -getsocksfirewallproxy Wi-Fi'),
         "Enabled 应为 No，Server 应为 0.0.0.0、Port 为 0。注意列表第一行是说明文字、被禁用的服务名字前面带星号，按名字操作时要去掉"),
        ("终端环境变量", "文章 2.5⑤",
         ('env | grep -iE "proxy|anthropic|claude"',),
         "应无输出。原文这条写得太宽：只要当前目录名里带 claude（比如就站在 claude-account-guard 目录下），PWD 就会被命中，实测踩过。真要看代理就把它拆成 env | grep -i proxy"),
        ("shell 配置里的代理行", "文章 2.5⑤",
         ('grep -inE "proxy|ANTHROPIC" ~/.zshrc ~/.bashrc ~/.profile ~/.zshenv ~/.zprofile 2>/dev/null',),
         "应无输出"),
        ("npm / git 的全局代理", "文章 2.5⑤",
         ("npm config get proxy; npm config get https-proxy",
          "git config --global --get http.proxy; git config --global --get https.proxy",
          "cat ~/.npmrc"),
         "npm 两项应输出 null；git 两条应无输出。.npmrc 要直接 grep 文件："
         "npm config get 读的是生效值，带作用域的写法它反映不出来"),
        ("Homebrew 的代理", "补充项（文章里没有）",
         ("brew config | grep -i proxy",),
         "应无输出。文章全文里搜不到这一条（2.5④ 的代码块只有 scutil 那一行），是清单补的。"
         "实测 Homebrew 7 只把小写的 http_proxy / https_proxy / all_proxy 打进 config"
         " —— 把大小写六个都设上再 diff，多出来的只有小写那三行，大写那三个它一个字都不提。"
         "所以这条能测出来的是 env | grep -i proxy 的子集，不是独立的一层"),
        ("settings.json 内容", "文章 2.5⑤",
         ("cat ~/.claude/settings.json 2>/dev/null",),
         "重点看 env 里有没有 ANTHROPIC_BASE_URL。用过镜像站或各种中转的这里常有残留，服务端一看请求就知道没走官方"),
    )),
    ("三、Clash 线路与绝不直连", (
        ("当前模式", "文章 2.4",
         (SOCK_HINT,
          'curl -s --unix-socket $SOCK -H "$AUTH" http://localhost/configs | python3 -c "import json,sys;print(json.load(sys.stdin)[\'mode\'])"'),
         "应为 global。规则模式下有 GeoSite,cn,DIRECT 这类分支，不是「绝不直连」的形态"),
        ("GLOBAL 指向哪个组", "本会话补",
         (SOCK_HINT,
          'curl -s --unix-socket $SOCK -H "$AUTH" http://localhost/proxies | python3 -c "import json,sys;p=json.load(sys.stdin)[\'proxies\'];print(p[\'GLOBAL\'][\'now\'], \'|\', p[\'Claude\'][\'all\'])"'),
         "应指向 Claude 专用组，且该组只有一个成员。只有 select 类型才不做健康检查切换"),
        ("实际走哪条链", "本会话补",
         (SOCK_HINT,
          'curl -s --unix-socket $SOCK -H "$AUTH" http://localhost/connections | python3 -c "import json,sys;from collections import Counter;print(Counter(\' -> \'.join(reversed(c[\'chains\'])) for c in json.load(sys.stdin)[\'connections\']))"',
          "# 切模式之后老连接的链是旧的，先清一下再看：| curl -X DELETE ... http://localhost/connections"),
         "链里应只有 GLOBAL → Claude → 节点。出现 DIRECT 或 自动切换 就是漏了"),
        ("Claude 规则排在最前", "本会话补",
         (SOCK_HINT,
          'curl -s --unix-socket $SOCK -H "$AUTH" http://localhost/rules | python3 -c "import json,sys;[print(r[\'payload\'],\'->\',r[\'proxy\']) for r in json.load(sys.stdin)[\'rules\'][:7]]"'),
         "前 7 条应是 anthropic.com / claude.ai / claude.com / claudeusercontent.com / statsigapi.net 与 160.79.104.0/21，全部指向 Claude 组"),
        ("订阅会不会把规则改回去", "本会话补",
         ("grep -nE \'^mode:\' ~/Library/Application\\ Support/io.github.clash-verge-rev.clash-verge-rev/profiles/*.yaml",
          "tail -5 ~/Library/Logs/clash-mode-guard.log"),
         "订阅本体写的是 mode: rule，每次更新都会带进来；靠守护脚本每 30 秒拉回 global，日志里能看到 restored to global"),
    )),
    ("四、时区与定位", (
        ("系统时区", "文章 2.2",
         ("readlink /etc/localtime",
          'node -e "console.log(Intl.DateTimeFormat().resolvedOptions().timeZone)"'),
         "两条都应指向 Asia/Taipei。第二条才是应用和浏览器实际读到的值"),
        ("定位驱动时区有没有关", "文章 2.2",
         ("defaults read /Library/Preferences/com.apple.timezone.auto.plist Active",
          "log show --last 2h --style compact --predicate 'process == \"timed\" AND eventMessage CONTAINS \"TZ,computed\"' | tail -3"),
         "第一道闸应为 0；第二道闸在「定位服务 → 系统服务 → 设定时区」，要看 timed 日志里 setSourceUnavailable 是否已出现"),
    )),
    ("五、客户端与账号", (
        ("Claude Code 版本与占用", "文章 §5",
         ("which claude; claude --version",
          "ls -la ~/.local/share/claude/versions/",
          "du -sh ~/.local/share/claude/versions/"),
         "versions 目录每份 200 MB 上下，安装器会自行清理旧版本；想腾空间可手动删非当前版本"),
        ("钥匙串条目", "文章 2.6",
         ('security dump-keychain 2>/dev/null | grep -E \'"(svce|acct)"\' | sort -u',),
         "要分开看：svce='Claude Safe Storage' + acct='Claude Key' 是桌面版的加密存储；CLI 的凭据是 svce='Claude Code-credentials'"),
        ("遥测三键", "文章 §5",
         ('python3 -c "import json;print(json.load(open(\'$HOME/.claude/settings.json\')).get(\'env\',{}))"',),
         "想关就在这里加 DISABLE_TELEMETRY 与 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC 为 1；有副作用，Remote Control 可能失效"),
    )),
)

MANUAL_SITES = (
    ("出口 IP", "ipinfo.io、ping0.cc、whoer.net", "看 country / city / org。国家要固定、城市别每次变"),
    ("IP 纯净度", "ippure.com", "文章 2.3 附的来源，看是不是住宅段"),
    ("社区检测页", "ip.net.coffee/claude", "文章原话「只作参考」，不当作判据"),
    ("WebRTC", "browserleaks.com/webrtc", "不能出现真实公网 IP"),
    ("DNS", "browserleaks.com/dns", "不应出现中国的 DNS 服务器"),
    ("Claude 服务状态", "status.anthropic.com", "怀疑是服务端问题时先看这里，别急着怀疑自己环境"),
)


def print_manual_checks() -> None:
    """打印手工核对清单。这是脚本之外自己复核一遍用的原始命令。"""
    print("\n" + "=" * 78)
    print("手工核对清单 —— 不想跑脚本、或者想把上面总表自己复核一遍时用")
    print("=" * 78)
    for group, items in MANUAL_CHECKS:
        print(f"\n【{group}】")
        for title, src, cmds, expect in items:
            print(f"\n  {title}   〔{src}〕")
            for cmd in cmds:
                print(f"    $ {cmd}")
            print(f"    期望：{expect}")

    print("\n" + "─" * 78)
    print("文章里给的检测网站")
    print("─" * 78)
    for what, urls, note in MANUAL_SITES:
        print(f"  {what:<12} {urls}")
        print(f"               {note}")

    print("\n" + "─" * 78)
    print("先用哪几条")
    print("─" * 78)
    print("  只想知道「现在干不干净」，跑这三条就够：")
    print("    $ scutil --proxy | grep -E \"HTTPEnable|HTTPSEnable|SOCKSEnable\"")
    print("    $ curl -s --noproxy '*' https://api.ipify.org")
    print(f"    $ {SOCK_HINT}")
    print('    $ curl -s --unix-socket $SOCK -H "$AUTH" http://localhost/configs \\')
    print("        | python3 -c \"import json,sys;print(json.load(sys.stdin)['mode'])\"")
    print("  第一条全 0、第二条是预期出口、第三条是 global，就没大问题。")
    print("  注意这些都要在新开的终端里跑——老窗口可能还带着启动时的旧代理变量。")


# ────────────────────────── 写操作 ──────────────────────────

def run_lock_path() -> pathlib.Path:
    """加固流程的互斥锁文件。

    做成函数不是模块级常量：常量在 import 那一刻就把 HOME 定死了，
    测试里改不动（这个坑踩过一次）。
    """
    return HOME / ".local" / "state" / "claude-guard" / "run.lock"


def acquire_run_lock() -> tuple:
    """取加固流程的互斥锁，返回 (拿到没, 说明)。

    为什么要锁：这个流程里有备份、有删除、有改配置三件事，并发跑会互相踩 ——
    一边把文件删了，另一边正拿它当回滚凭据；两个备份目录的内容也会交错。
    用 O_CREAT|O_EXCL 原子建文件，不用「先看存在再写」那种有竞态的写法。

    锁里记 pid。**进程已经不在的锁是遗留锁**，直接接管并说明 —— 否则上次
    Ctrl-C 或断电之后，同一台机器就再也跑不起来了。
    """
    path = run_lock_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return False, f"建不了状态目录 {path.parent}：{e}"
    for attempt in (0, 1):
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if attempt:
                return False, f"已经有另一个加固流程在跑（锁文件 {path}）"
            try:
                holder = path.read_text(encoding="utf-8").strip()
            except OSError:
                holder = ""
            pid = holder.split()[0] if holder else ""
            if pid.isdigit() and run(["kill", "-0", pid])[0] == 0:
                return False, f"已经有另一个加固流程在跑（pid {pid}，锁文件 {path}）"
            try:
                path.unlink()
            except OSError as e:
                return False, f"发现遗留锁但删不掉（{path}）：{e}"
            continue
        except OSError as e:
            return False, f"建不了锁文件 {path}：{e}"
        os.write(fd, f"{os.getpid()} {now_stamp()}\n".encode("utf-8"))
        os.close(fd)
        return True, f"已加互斥锁（{path}）"
    return False, "取锁失败"


def release_run_lock() -> None:
    """放锁。只删 pid 还是自己的那份，不碰别人正在用的锁。"""
    path = run_lock_path()
    try:
        holder = path.read_text(encoding="utf-8").strip()
    except OSError:
        return
    if holder.split()[0] != str(os.getpid()):
        return
    try:
        path.unlink()
    except OSError:
        pass


def create_backup(paths: list[pathlib.Path], sudo_paths: list[pathlib.Path] | None = None) -> pathlib.Path:
    """第一个写操作：把要动的文件复制到带时间戳的备份目录。

    sudo_paths 里的文件普通用户读不到（例如 /var/db/locationd/clients.plist），
    必须用 sudo cp；调用前要先 sudo_prime()。任何一项备份失败都直接抛错，
    绝不在没有备份的情况下继续改动 —— 对 root 文件尤其重要，
    因为 p.exists() 对不可读路径返回 False，会把「备份不了」静默变成「不用备份」。
    """
    if sudo_paths:
        ensure_sudo("备份 root 文件")
    # 带微秒，避免同秒内并发运行把两次备份写进同一个目录互相覆盖
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    dest = BACKUP_ROOT / f"guard-{stamp}"
    (dest / "files").mkdir(parents=True, exist_ok=True)
    manifest: dict = {"created": dt.datetime.now().isoformat(), "items": [], "sudo_items": []}
    for p in paths:
        if not p.exists():
            continue
        target = dest / "files" / str(p).lstrip("/").replace("/", "__")
        try:
            if p.is_dir():
                shutil.copytree(p, target)
            else:
                shutil.copy2(p, target)
        except OSError as e:
            raise RuntimeError(f"备份失败 {p}: {e}") from e
        manifest["items"].append(str(p))
    for p in (sudo_paths or []):
        target = dest / "files" / str(p).lstrip("/").replace("/", "__")
        code, err = run(["sudo", "-n", "cp", "-p", str(p), str(target)], timeout=60)
        if code or not target.exists() or target.stat().st_size == 0:
            raise RuntimeError(
                f"需要 root 的备份失败：{p}（{err.strip()[:120] or '空文件'}），已中止以免在无备份的情况下改动"
            )
        manifest["sudo_items"].append(str(p))
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return dest


def sudo_alive() -> bool:
    """sudo 的时间戳还在不在。在就不用再问密码。"""
    try:
        return subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def sudo_prime() -> None:
    """只在终端原生提示里让用户输密码；脚本不读不存。

    整个流程**只需要输这一次**：之后所有提权调用都带 -n，吃 sudo 的时间戳缓存。
    """
    if sudo_alive():
        return
    print("[人工步骤] 终端会隐藏提示输入一次 Mac 开机密码；脚本不读取也不保存。")
    print("           输这一次就够，后面所有需要 root 的步骤都复用它的缓存。")
    subprocess.run(["sudo", "-v"], check=True)


def ensure_sudo(what: str) -> None:
    """执行提权操作前确认授权还在，只有过期了才重新问。

    sudo 默认只缓存 5 分钟，中途走开就可能过期。此时必须重新问，
    否则后面那些带 -n 的调用会静默失败，用户会以为步骤执行过了。
    """
    if sudo_alive():
        return
    print(f"\n[人工步骤] 授权已过期（sudo 默认缓存 5 分钟），{what} 需要再输一次密码。")
    subprocess.run(["sudo", "-v"], check=True)


def apply_telemetry(mode: int) -> str:
    """A3 遥测开关。文章 §5。mode: 0 保持 / 1 关三键 / 2 只关上报与下载流量。"""
    if mode == 0:
        return "保持"                      # 选择保持时绝不落盘，避免无谓改写 settings.json
    data = read_json(SETTINGS, {})
    env = dict(data.get("env", {}) or {})
    before = dict(env)
    if mode == 1:
        for k in TELEMETRY_KEYS:
            env[k] = "1"
    else:
        env["DISABLE_TELEMETRY"] = "1"
        env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    data["env"] = env
    write_json(SETTINGS, data)
    after = dict(read_json(SETTINGS, {}).get("env", {}))
    if after == before:
        raise RuntimeError("遥测键写入后复验未生效")
    return f"已写入 {', '.join(k for k in env if k not in before)}"


def apply_browser_wrapper() -> str:
    """A4 生成 BROWSER=false 的 claude 包装脚本。文章 2.6。

    两个必须检查的点，否则生成的脚本是废的：
      * 目标目录在不在 PATH 里 —— 不在的话用户敲 claude-safe 找不到；
      * claude 本体在不在 —— 不在的话包装脚本一执行就报 command not found。
    """
    bindir = HOME / ".local" / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    wrapper = bindir / "claude-safe"
    wrapper.write_text(
        "#!/bin/sh\n"
        "# claude-account-guard: 文章 2.6 —— 授权链接不交给默认浏览器\n"
        "# 用 BROWSER=false 让 Claude Code 只打印链接，你再复制到专用浏览器资料里打开。\n"
        "BROWSER=false exec claude \"$@\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    notes = [str(wrapper)]
    path_dirs = [pathlib.Path(p).expanduser() for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    if bindir not in path_dirs:
        notes.append(f"注意：{bindir} 不在 PATH 里，需要先 export PATH=\"{bindir}:$PATH\" 才能直接敲 claude-safe")
    if not shutil.which("claude"):
        notes.append("注意：当前 PATH 下找不到 claude 命令，包装脚本会执行失败；请确认 Claude Code CLI 已安装并在 PATH 中")
    return "；".join(notes)


def clear_proxy_residue(residue: list[dict]) -> int:
    """B4 清掉「未启用但存了值」的系统代理。文章 2.5④。实测非提权即可写。

    陷阱（已实测确认）：`networksetup -set{kind}` 在写入服务器值时会**顺带把代理置为启用**。
    所以清完必须再执行一次 set{kind}state off，并且复验 Enabled 为 No 才算成功；
    否则会把一条「未启用的残留」变成「已启用的代理」，正好造成文章最担心的后果。
    只处理 residue（Enabled=No）条目，正在启用的代理一律不碰。
    """
    cleared = 0
    for item in residue:
        svc, kind = item["service"], item["kind"]
        code, _ = run(["networksetup", f"-set{kind}", svc, "0.0.0.0", "0"])
        if code:
            continue
        run(["networksetup", f"-set{kind}state", svc, "off"])
        run(["networksetup", f"-set{kind}state", svc, "off"])   # 二次确认，抵消 set 带来的启用
        code, body = run(["networksetup", f"-get{kind}", svc])
        enabled = re.search(r"Enabled:\s*(\w+)", body)
        server = re.search(r"Server:\s*(\S*)", body)
        if not enabled or enabled.group(1).lower() != "no":
            raise RuntimeError(f"{svc}/{kind} 清理后仍处于启用状态，已停止以免留下开启的代理")
        if server and server.group(1) == item["server"]:
            raise RuntimeError(f"{svc}/{kind} 清理后服务器值仍是 {item['server']}，没有真正清掉")
        cleared += 1
    return cleared


def clear_rc_proxy_lines(rc_files: dict) -> list[str]:
    """A1 清掉 shell 配置里的代理行。

    只删命中的那几行，保留文件其余内容和换行风格；调用方必须先把这些文件备份。
    返回被改动的文件列表，没有改动就返回空。
    """
    changed = []
    for name, hits in rc_files.items():
        if not hits:
            continue
        p = HOME / name
        if not p.is_file():
            continue
        drop = {h["line"] for h in hits}
        lines = p.read_text(errors="replace").splitlines(keepends=True)
        kept = [ln for i, ln in enumerate(lines, 1) if i not in drop]
        if len(kept) == len(lines):
            continue
        p.write_text("".join(kept), encoding="utf-8")
        changed.append(str(p))
    return changed


def clear_npm_git_proxy() -> list[str]:
    """A1 清掉 npm 与 git 的全局代理配置，清完复验。"""
    done = []
    for key in ("proxy", "https-proxy"):
        run(["npm", "config", "delete", key])
        _, left = run(["npm", "config", "get", key])
        if left.strip().lower() in ("", "undefined", "null"):
            done.append(f"npm:{key}")
    for key in ("http.proxy", "https.proxy"):
        run(["git", "config", "--global", "--unset", key])
        _, left = run(["git", "config", "--global", "--get", key])
        if not left.strip():
            done.append(f"git:{key}")
    return done


def clear_anthropic_base_url() -> str:
    """A2 删掉 Claude Code settings.json 里指向别处的端点、凭据与代理变量。

    只动 env 里的这几类键，其余键原样保留。清单里那条第 6 项是
    `grep -iE "proxy|base_url|anthropic_"`（文章 2.5⑤ 只让人 cat 这个文件）：
    端点/凭据按名字前缀加关键词判，
    代理键按名字里有没有 proxy 判 —— 三类一起覆盖，别漏了 proxy 那一类。
    并成一趟写，避免两次写同一个文件互相覆盖。
    ~/.codex 与 ~/.dsh 属于别的工具，只报告不代改 —— 本 skill 的范围是 Claude Code。
    """
    data = read_json(SETTINGS, {})
    env = dict(data.get("env", {}) or {})
    removed = [
        k for k in env
        if (k.startswith(("ANTHROPIC_", "CLAUDE_"))
            and re.search(r"base_url|auth_token|api_key", k, re.I))
        or "proxy" in k.lower()
    ]
    if not removed:
        return "Claude Code 的 settings.json 里没有需要清掉的端点或代理变量"
    for k in removed:
        env.pop(k)
    data["env"] = env
    write_json(SETTINGS, data)
    after = read_json(SETTINGS, {}).get("env", {})
    still = [k for k in removed if k in after]
    if still:
        raise RuntimeError("端点变量删除后复验未生效：" + ", ".join(still))
    return "已从 settings.json 的 env 移除：" + ", ".join(removed)


def _active_merge_enhancement():
    """当前 profile 挂的 Merge 增强文件路径，没有则 None。

    为什么要连它一起看：Clash Verge 每次重算配置都是拿「订阅本体 + 增强文件」重算的。
    只改生成物 clash-verge.yaml，下次订阅更新（本机订阅是每 180 分钟一次）就会被订阅
    自带的阿里 DNS 覆盖回来，漏得悄无声息。
    """
    try:
        import yaml as _yaml
        pf = _yaml.safe_load((clash_dir() / "profiles.yaml").read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    uid = pf.get("current")
    for it in pf.get("items") or []:
        if it.get("uid") == uid:
            m = (it.get("option") or {}).get("merge")
            if m:
                p = clash_dir() / "profiles" / (str(m) + ".yaml")
                if p.is_file():
                    return p
    return None


def clear_clash_dns_leak(rep: dict) -> str:
    """A6 把 Clash 的主解析器从国内换成境外，并打开 respect-rules。

    只动 dns 块里的两个键，其余原样保留——fake-ip 段、fake-ip-filter 过滤表、以及把
    `geosite:cn,private` 指向国内 DNS 的策略都不碰。国内域名继续走国内解析，这条本来
    就是对的，不该改。

    两处一起写：
      * 生成物 clash-verge.yaml —— 立刻生效，写完 PUT /configs 重载内核；
      * 当前 profile 挂的 Merge 增强文件 —— 写**完整的** dns 块而不是只写两个键。
        因为 Verge 的 Merge 到底是深合并还是浅合并没有公开保证；如果它整体替换 dns，
        只写两个键会把 enable / fake-ip-range / fake-ip-filter 全打没，DNS 直接废掉。
        写完整块则两种语义结果一致。

    改完复验，仍不合格就抛错——不假装成功。
    """
    try:
        import yaml as _yaml
    except ImportError as e:                       # pragma: no cover - 环境缺依赖
        raise RuntimeError("缺少 pyyaml，无法读写 Clash 配置：" + str(e)) from e

    if not clash_config().is_file():
        raise RuntimeError("找不到 Clash 配置：" + str(clash_config()))

    cfg = _yaml.safe_load(clash_config().read_text(encoding="utf-8")) or {}
    dns = cfg.get("dns") or {}
    if not dns:
        raise RuntimeError("配置里没有 dns 块，不敢盲写")

    def _dirty(block) -> list:
        """这个 dns 块哪里不合格，返回人话描述的列表。"""
        why = []
        bad_ns = [x for x in (block.get("nameserver") or []) if _resolver_is_cn(str(x))]
        bad_fb = [x for x in (block.get("fallback") or []) if _resolver_is_cn(str(x))]
        if bad_ns:
            why.append("主解析器含 " + "、".join(str(x) for x in bad_ns))
        if bad_fb:
            why.append("fallback 含 " + "、".join(str(x) for x in bad_fb))
        if block.get("respect-rules") is not True:
            why.append("没开 respect-rules")
        if block.get("enable") is False:
            why.append("dns.enable 是关的，DNS 根本没在跑")
        return why

    def _harden(block) -> None:
        """就地加固。fallback 只在它真的含国内解析器时才动——
        fallback 是订阅用来做「国内解析被污染时改问境外」的机制，本来就没有这个键的
        配置不该被凭空加一个。enable 同理：只在它被显式关掉时才打开。"""
        block["nameserver"] = list(FOREIGN_NAMESERVERS)
        if [x for x in (block.get("fallback") or []) if _resolver_is_cn(str(x))]:
            block["fallback"] = list(FOREIGN_FALLBACK)
        block["respect-rules"] = True
        if block.get("enable") is False:
            block["enable"] = True

    changed = []
    tun = cfg.get("tun") or {}
    # TUN 开着却没有 dns-hijack：发往 53 端口的查询不会被内核接管，会照原样出去问
    # 系统配的解析器。这和「主解析器含国内服务器」是两条独立的路径，得分开补。
    hijack_missing = bool(tun.get("enable")) and not (tun.get("dns-hijack") or [])
    if _dirty(dns) or hijack_missing:
        reasons = list(_dirty(dns))
        if hijack_missing:
            reasons.append("TUN 开着但没配 dns-hijack")
            tun["dns-hijack"] = list(DNS_HIJACK)
            cfg["tun"] = tun
        changed.append("生成物（" + "；".join(reasons) + "）")
        _harden(dns)
        cfg["dns"] = dns
        clash_config().write_text(
            _yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False, width=4096),
            encoding="utf-8")

    merge = _active_merge_enhancement()
    if merge is not None:
        try:
            m = _yaml.safe_load(merge.read_text(encoding="utf-8")) or {}
        except Exception:
            m = {}
        if _dirty(m.get("dns") or {}) or hijack_missing:
            m["dns"] = dict(dns)                   # 完整块，浅合并也不会丢键
            if hijack_missing:
                m["tun"] = dict(tun)               # 同理，tun 也写整块
            merge.write_text(
                "# Profile Enhancement Merge Template for Clash Verge\n\n"
                + _yaml.safe_dump(m, allow_unicode=True, sort_keys=False, width=4096),
                encoding="utf-8")
            changed.append("增强文件 " + merge.name)

    if not changed:
        return "Clash 的 DNS 已经不含国内解析器，无需改动"

    _, body = run([
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-X", "PUT",
        "--max-time", "10", "--unix-socket", str(CLASH_SOCK),
        "-H", f"Authorization: Bearer {CLASH_SECRET}",
        "-H", "Content-Type: application/json",
        "-d", '{"path":"' + str(clash_config()) + '","force":true}',
        "http://localhost/configs",
    ], timeout=25)
    code_s = (body or "").strip()

    after = check_clash_dns()
    # 复验条件直接复用 clash_dns_leaking，不再自己列一遍——两处各写一份迟早会漂移，
    # 补了 dns.enable 与 dns-hijack 之后这边如果不跟着改，就会「检查报待处理、清理报成功」。
    if clash_dns_leaking({"A6_dns": {"clash": after}}):
        raise RuntimeError(
            "改完复验仍不合格：leaking=" + repr(after.get("leaking"))
            + " respect-rules=" + repr(after.get("respect_rules"))
            + " enable=" + repr(after.get("enabled"))
            + " dns-hijack=" + repr(after.get("hijack")))
    tail = "内核已重载" if code_s in ("200", "204") else \
        ("但内核重载返回 HTTP " + code_s + "，配置已改但可能还没生效")
    return "已清掉国内解析器（" + "；".join(changed) + "），" + tail


def set_ipv6_off(services: list[str]) -> dict:
    """B3 关闭网络服务的 IPv6。文章 2.5 可选加固。需要 root。

    返回 {done, failed, rollback}。失败必须如实报出来：没有 root 时
    `networksetup -setv6off` 会直接失败，早期版本 continue 掉，
    结果 main 打印「已关闭 []」，看起来像成功。
    """
    done, failed = [], []
    for svc in services:
        code, _ = run(["networksetup", "-setv6off", svc])
        if code:
            failed.append(svc)
            continue
        code, body = run(["networksetup", "-getinfo", svc])
        if re.search(r"IPv6:\s*Off", body):
            done.append(svc)
        else:
            failed.append(svc)
    rollback = [f"networksetup -setv6automatic '{s}'" for s in done]
    return {"done": done, "failed": failed, "rollback": rollback}


LOCATION_PROBE = '''
import plistlib, json, sys
with open("/var/db/locationd/clients.plist", "rb") as fh:
    data = plistlib.load(fh)
out = {}
for key, val in data.items():
    if not isinstance(val, dict):
        continue
    if "timed" in key.lower() or "timezone" in key.lower():
        out[key] = {k: v for k, v in val.items() if k != "ClientStorageToken"}
sys.stdout.write(json.dumps(out, default=str))
'''


def location_service_status() -> dict:
    """B5 读定位服务里「设定时区」的状态。

    只用 sudo -n（非交互）：读不到就如实报「读不到」并给出 UI 路径，
    绝不在只读探测阶段弹密码框。调用方必须先 sudo_prime()。

    为什么不用 plutil -convert json：实测这份 plist 里带 ClientStorageToken
    这种原始字节，转 JSON 会直接报
    "Invalid object in plist for JSON format"，整份读不出来。
    改成 plistlib 在 root 下解析、字节字段跳过，实测可读。

    字段语义（实机核对过，`Authorized` 三种状态都要分开看）：
      Authorized = True   闸开着            例如 com.apple.Maps、com.google.Chrome
      Authorized = False  被显式拒绝        例如 WifiCalling.bundle
      没有 Authorized    系统服务未获授权   TimeZone.bundle 就是这种，这就是「已关」
    把「没有这个字段」当成「读不到」是错的——它本身就是答案。
    """
    out = {"readable": False, "clients": {}, "timed_present": False, "note": ""}
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="guard-loc-")) / "probe.py"
    try:
        tmp.write_text(LOCATION_PROBE, encoding="utf-8")
        code, body = run(["sudo", "-n", "python3", str(tmp)], timeout=30)
    finally:
        shutil.rmtree(tmp.parent, ignore_errors=True)
    if code:
        out["note"] = "读不到 /var/db/locationd/clients.plist（需要 root；先 sudo_prime 再执行）"
        return out
    try:
        data = json.loads(body or "{}")
    except json.JSONDecodeError:
        out["note"] = "clients.plist 解析失败，格式与预期不符，已放弃自动处理"
        return out
    out["readable"] = True
    for key, val in data.items():
        authorized = val.get("Authorized")
        out["clients"][key] = {
            # 三态如实保留：True / False / None（None 表示这条没有该字段）
            "Authorized": authorized,
            "state": ("已关" if authorized is not True else "仍开启"),
            "stopped": val.get("LocationTimeStopped") or val.get("ReceivingLocationInformationTimeStopped"),
            "BundlePath": val.get("BundlePath"),
        }
        if "timed" in key.lower():
            out["timed_present"] = True
    if out["clients"]:
        # 这次读到了（也就是带 root 跑的），把结论记下来供不带 root 时参考
        save_location_gate_cache(
            any(v.get("Authorized") is True for v in out["clients"].values())
        )
    if not out["clients"]:
        out["note"] = (
            "未识别出与「设定时区」对应的客户端条目，请改用 UI："
            "系统设置 → 隐私与安全性 → 定位服务 → 系统服务 → 详细信息 → 设定时区"
        )
    return out


LOCATION_GATE_CACHE = HOME / ".local" / "state" / "claude-guard" / "location-gate.json"


def now_stamp() -> str:
    """人看得懂的时间戳，用于「什么时候实测的」这类标注。"""
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M")


def hand_back_ownership(path: pathlib.Path) -> None:
    """在 sudo 下写完状态文件后，把属主交还给真实用户。

    这条是踩出来的，代价是静默丢数据：2026-10-08 22:46 用管理员权限跑定位服务
    检查时，`~/.local/state/claude-guard/` 被建成 root:staff（drwxr-xr-x），于是
    **用户自己的进程从此写不进这个目录**。几天后媒体权限复核明明拿到了正确结果
    （摄像头/麦克风都是 denied、候选里没有任何 IP），却在落盘那一步报
    `[Errno 13] Permission denied: .../media-permission.json` 丢掉，WebRTC 那一行
    就一直挂在「待处理」上。而且这个目录 root 拥有时连 mv 都搬不动（rename 要改
    它自己的 `..` 项），只能再提权一次 chown 回来。

    root 只在读 /var/db/locationd/clients.plist 那一步出现，所以就在写完缓存之后
    立刻把属主还回去。非 root、或没有 SUDO_UID（比如真以 root 登录）时什么都不做。
    """
    if os.geteuid() != 0:
        return
    try:
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    except (KeyError, ValueError):
        return
    for p in (path.parent, path):
        try:
            if p.exists():
                os.chown(p, uid, gid)
        except OSError:
            pass


def save_location_gate_cache(state, source: str = "root") -> None:
    """把 root 读到的第二道闸状态记下来。

    为什么需要这个：/var/db/locationd/clients.plist 非 root 真的读不到（实测
    PermissionError: Permission denied），所以每次不带 root 跑 --audit 都会看到
    「读不到」，然后这一项就永远挂在「待你处理」里——即使答案早就用 root 拿到过。
    记成缓存之后，不带 root 也能报出真实结论，并注明是何时实测的。
    """
    if state is None:
        return
    try:
        LOCATION_GATE_CACHE.parent.mkdir(parents=True, exist_ok=True)
        LOCATION_GATE_CACHE.write_text(
            json.dumps({"checkedAt": now_stamp(), "closed": state is False, "source": source},
                       ensure_ascii=False),
            encoding="utf-8",
        )
        hand_back_ownership(LOCATION_GATE_CACHE)
    except OSError:
        pass


def load_location_gate_cache() -> dict | None:
    """读回上次 root 实测的第二道闸状态。返回 None 表示没有可用缓存。"""
    try:
        d = json.loads(LOCATION_GATE_CACHE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(d, dict) or "closed" not in d:
        return None
    return d


def location_gate_state(status: dict) -> bool | None:
    """把 location_service_status 的结果收敛成闸门三态。

    True = 还开着，False = 已关，None = 读不到（读不到不能当成已关）。
    """
    if not status.get("readable") or not status.get("clients"):
        return None
    # 只要有一条还是 True 就算开着；全不是 True（含「没有该字段」）算已关
    return any(v.get("Authorized") is True for v in status["clients"].values())


def disable_location_timezone() -> str:
    """B5 关闭定位服务里的「设定时区」。由用户同意后才调用。

    先把当前状态读出来，已经是关的直接如实回复「无需改动」，不去写一个
    本来就不存在的字段。真正要改时逐个候选尝试，然后**重新读一遍整份 plist**
    确认 Authorized 真的翻成 False 才算成功；验不到就判定未生效并退回 UI。
    绝不做「写不进去却报成功」这种事，也不做「本来就好却报失败」这种事。
    """
    status = location_service_status()
    if not status["readable"]:
        raise RuntimeError(status["note"] or "无法读取定位服务配置")
    if not status["clients"]:
        raise RuntimeError(status["note"])

    state = location_gate_state(status)
    if state is False:
        names = ", ".join(status["clients"])
        return (
            f"定位服务里的「设定时区」已经是关闭状态，无需改动（条目：{names}）。"
            "判定依据是该条目的 Authorized 不是 True——系统服务未获授权时不会带这个字段"
        )

    plist = str(LOCATIOND_PLIST)
    attempted = []
    for key in status["clients"]:
        code, _ = run(
            ["sudo", "-n", "/usr/libexec/PlistBuddy", "-c", f"Add :{key}:Authorized bool false", plist], timeout=30
        )
        if code:
            # 字段不存在时 Add 会失败，退回 Set
            code, _ = run(
                ["sudo", "-n", "/usr/libexec/PlistBuddy", "-c", f"Set :{key}:Authorized false", plist], timeout=30
            )
        attempted.append(f"{key}:{'写入成功' if code == 0 else '写入失败'}")

    after = location_service_status()
    if not after["readable"]:
        raise RuntimeError("写入后无法重新读取配置，无法复验；请用备份还原后改用 UI")
    if location_gate_state(after) is not False:
        raise RuntimeError(
            "改写后复验不到状态翻转，判定为未生效。请改用 UI："
            "系统设置 → 隐私与安全性 → 定位服务 → 系统服务 → 详细信息 → 设定时区"
        )
    return (
        f"已改写并复验（{', '.join(after['clients'])}）；尝试明细 {attempted}。"
        "若时区仍被 locationd 覆盖，请改用 UI 关闭「设定时区」"
    )


def check_timezone_layers() -> dict:
    """T10 + P13：时区是不是每一层都落在台北，以及控制它的两道闸关了没有。

    只读，不写任何东西。B5 那类「自动改写系统隐私库」已按 H4 的决定去掉，
    这里只负责把事实摆出来。

    判定「现在是不是台北」只用两个活读数：/etc/localtime 的指向，以及新起进程
    实际拿到的时区。timed 的日志是历史，单独报出来并带时间戳，不参与判定。
    这里踩过两个坑，都是把历史当现状：
      1. 6 小时窗口里同时躺着 17:51 的 TZ,computed,result,Asia/Shanghai 和
         20:55 的 TZ,setSourceUnavailable，直接取「窗口里出现过 Shanghai」
         会把稳定的台北判成没锁住，天天误报。
      2. 同一个窗口里 Available 与 Unavailable 都有时，「先匹配到 Available
         就算 True」会把最新的 Unavailable 盖掉，得出相反的结论。
    正确做法是按时间戳排序取最后一条事件。

    两道闸都要看，因为关掉「按位置自动设定时区」不等于关掉了定位：
      第一道 /Library/Preferences/com.apple.timezone.auto.plist 的 Active
      第二道 定位服务 → 系统服务 → 设定时区（对应 locationd 里 timed 那条）
    """
    out = {
        "layers": {},
        "all_taipei": False,
        "timed_last": None,
        "timed_last_at": None,
        "gate_auto_plist": None,
        "gate_location": None,
        "gate_location_detail": {},
        "gate_location_note": "",
        "source_available": None,
        "source_event_at": None,
        "note": "",
    }

    # 活读数一：符号链接指向哪个 zoneinfo
    code, body = run(["readlink", "/etc/localtime"])
    link = body.strip()
    out["layers"]["localtime"] = link.split("zoneinfo/")[-1] if "zoneinfo/" in link else (link or "(读不到)")

    # 活读数二：新起的进程实际拿到什么。这才是应用眼里的时区，
    # 也是浏览器指纹读到的那个值。符号链接对了不代表进程就一定对。
    code, body = run(
        ["node", "-e", "console.log(Intl.DateTimeFormat().resolvedOptions().timeZone)"], timeout=20
    )
    out["layers"]["new_process"] = body.strip() if code == 0 and body.strip() else "(node 不可用)"

    # 历史：timed 的日志逐条带时间戳解析，取最后一条事件，而不是「出现过就算」
    code, body = run(
        ["log", "show", "--last", "6h", "--style", "compact",
         "--predicate", 'process == "timed" AND eventMessage CONTAINS "TZ,"'],
        timeout=150,
    )
    if code == 0:
        events = []
        for line in body.splitlines():
            m = re.match(
                r"\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.\d+\s+\S+\s+timed\[.*?\](.*)$", line
            )
            if not m:
                continue
            for token in re.findall(r"TZ,\S+", m.group(2)):
                events.append((m.group(1), token))
        events.sort()
        computed = [(t, p) for t, p in events if p.startswith("TZ,computed,result,")]
        if computed:
            out["timed_last_at"] = computed[-1][0]
            out["timed_last"] = computed[-1][1].split("TZ,computed,result,", 1)[1]
        src = [
            (t, p) for t, p in events
            if p in ("TZ,setSourceAvailable,src,Location", "TZ,setSourceUnavailable,src,Location")
        ]
        if src:
            out["source_event_at"] = src[-1][0]
            out["source_available"] = src[-1][1] == "TZ,setSourceAvailable,src,Location"

    # 第一道闸：按位置自动设定时区
    code, body = run(["defaults", "read", "/Library/Preferences/com.apple.timezone.auto.plist", "Active"])
    val = body.strip().lower()
    if code == 0:
        if val in ("0", "false", "no"):
            out["gate_auto_plist"] = False
        elif val in ("1", "true", "yes"):
            out["gate_auto_plist"] = True

    # 判定只看活读数。括号开头的是「没读到」的占位，不算数。
    live = [v for v in out["layers"].values() if not v.startswith("(")]
    out["all_taipei"] = bool(live) and all(v == "Asia/Taipei" for v in live)

    # 第二道闸：定位服务里的「设定时区」。读 /var/db/locationd/clients.plist 要 root，
    # 非 root 时如实报读不到，并给出定位源可用性作为旁证。
    loc = location_service_status()
    out["gate_location"] = location_gate_state(loc)
    if out["gate_location"] is None:
        # 读不到就回退到上次 root 实测的结果，并如实标明是缓存
        cached = load_location_gate_cache()
        if cached is not None:
            # 缓存的 closed 字段语义是「闸已关」，而 gate_location 的语义是
            # 「闸还开着」，两者相反。直接取值会把已关读成仍开启——实测踩过：
            # 缓存写着 closed:true，表里却报「仍开启」并标红。
            out["gate_location"] = not bool(cached.get("closed"))
            out["gate_location_cached"] = {
                "closed": bool(cached.get("closed")),
                "checkedAt": cached.get("checkedAt"),
            }
        else:
            out["gate_location_note"] = loc["note"]
    else:
        out["gate_location_detail"] = {
            k: v.get("Authorized") for k, v in loc["clients"].items()
        }
    return out


KEYCHAIN_KIND = (
    ("Claude Safe Storage", "Claude Desktop 的加密存储（随桌面版重装必然重建，删了没意义）"),
    ("Claude Code", "Claude Code CLI 的登录凭据"),
)


def check_keychain() -> dict:
    """P15 钥匙串里与 Claude 相关的项，svce 与 acct 分开报。

    这两者必须分开看，因为它们是两个不同的东西：
      svce="Claude Safe Storage" / acct="Claude Key"  → Claude Desktop
      svce="Claude Code-credentials"                  → Claude Code CLI
    早期把两者混为一谈，看到 Safe Storage 就以为 CLI 有凭据，结论是错的。
    """
    out = {"items": [], "readable": True, "note": ""}
    code, body = run(["security", "dump-keychain"], timeout=60)
    if code and not body.strip():
        out["readable"] = False
        out["note"] = "security dump-keychain 没有返回内容（可能要在钥匙串访问里授权）"
        return out
    # dump-keychain 会把每个条目列两遍：一遍用十六进制属性号，一遍用具名属性。
    # genp（通用密码）里服务名在这两遍里分别写作 0x00000007 和 "svce"，
    # 账号名两遍都写作 "acct"。只认具名的那遍会漏掉一半条目——实测过，
    # Claude Safe Storage 正好只出现在十六进制那遍里，结果拼出 ('', 'Claude Key')。
    # 按 keychain: 切块而不是按 class:，这样块内还留得住 class 行，才能判断是不是 genp。
    for block in body.split("keychain:"):
        is_genp = 'class: "genp"' in block
        m_svce = re.search(r'"svce"<blob>="([^"]*)"', block)
        if not m_svce and is_genp:
            # genp 的 kSecAttrService 就是属性号 0x00000007
            m_svce = re.search(r'0x00000007 <blob>="([^"]*)"', block)
        m_acct = re.search(r'"acct"<blob>="([^"]*)"', block)
        svce = m_svce.group(1) if m_svce else ""
        acct = m_acct.group(1) if m_acct else ""
        if not svce and not acct:
            continue
        if not re.search(r"claude|anthropic", svce + " " + acct, re.I):
            continue
        kind = "其它 Claude 相关项"
        for prefix, label in KEYCHAIN_KIND:
            if svce.startswith(prefix):
                kind = label
                break
        out["items"].append({"svce": svce, "acct": acct, "kind": kind})
    if not out["items"]:
        out["note"] = "钥匙串里没有 Claude / Anthropic 相关项"
    return out


# ────────────────────────── 报告与交互 ──────────────────────────

def audit() -> dict:
    ip = check_export_ip()          # 出口 IP 只查一次，一致性检查复用同一结果
    return {
        "timestamp": dt.datetime.now().isoformat(),
        "A1_export_ip": ip,
        "A1_proxy_residue": check_proxy_residue(),
        "A1_terminal_env": check_terminal_env(),
        "A2_anthropic_base_url": check_anthropic_base_url(),
        "A5_ipv6": check_ipv6(),
        "A6_dns": {**check_dns(), "clash": check_clash_dns()},
        "A9_geo_words": check_geo_words(),
        "A10_third_party": check_third_party(),
        "A11_client_integrity": check_client_integrity(),
        "A12_clash_groups": check_clash_groups(),
        "A13_multi_account": check_multi_account(),
        "A15_consistency": check_consistency(ip),
        "A3_telemetry": check_telemetry(),
        "A14_local_git": check_local_git(),
        "A21_timezone_layers": check_timezone_layers(),
        "A22_schedule": check_schedule_consistency(ip),
        "A23_browser_profiles": check_browser_profiles(),
        "A24_project_claude": check_project_claude(),
        "A25_claude_storage": check_claude_storage(),
        "A26_claude_settings": check_claude_settings(),
        "A27_browser_locale": check_browser_locale(ip),
        "E1_keychain": check_keychain(),
    }


def gate_text(v) -> str:
    """闸门三元状态转人话。None 表示读不到，绝不能当成「已关」。"""
    if v is False:
        return "已关"
    if v is True:
        return "仍开启"
    return "读不到"


def print_audit(r: dict) -> None:
    ip = r["A1_export_ip"]
    print("\n═══ 出口与身份 ═══")
    print(f"  出口 IP ：{ip.get('ip')}  {ip.get('city')}/{ip.get('country')}  {ip.get('org')}")
    print(f"  ASN 判定：{ip.get('verdict')}")
    c = r["A15_consistency"]
    print(f"  时区    ：{c.get('timezone')}  (UTC{c.get('offset')})")
    print(f"  语言    ：LANG={c.get('lang')}  AppleLocale={c.get('apple_locale')}")
    bl = r.get("A27_browser_locale") or {}
    if bl:
        extra = "，Chrome 这个进程要重启才生效" if bl.get("needs_restart") else ""
        print(f"  浏览器  ：Intl 区域设置 {bl.get('measured') or '没测到'}"
              f"（{bl.get('source') or '—'}）{extra}")
        for fact in bl.get("facts") or []:
            print(f"    · {fact}")
    for fact in c.get("facts", []):
        print(f"    · {fact}")
    for t in c.get("tension", []):
        print(f"    ⚖ 张力：{t}")
    if not c.get("tension"):
        print("    一致性：无冲突")

    tl = r.get("A21_timezone_layers") or {}
    if tl:
        layers = tl.get("layers", {})
        print("  时区分层：" + "  |  ".join(f"{k}={v}" for k, v in layers.items()))
        if tl.get("all_taipei"):
            print("    ✓ 读到的每一层都是 Asia/Taipei")
        else:
            print("    ⚠ 有层不是 Asia/Taipei，时区没锁住")
        print(f"    双闸：按位置自动设定={gate_text(tl.get('gate_auto_plist'))}"
              f"  定位服务设定时区={gate_text(tl.get('gate_location'))}")
        if tl.get("gate_location") is None and tl.get("gate_location_note"):
            print(f"      · {tl['gate_location_note']}")
        if tl.get("timed_last"):
            print(f"    · timed 最近一次算出 {tl['timed_last']}（{tl.get('timed_last_at')}）")
        if tl.get("source_available") is True:
            print(f"    ⚠ timed 眼里定位源仍可用（{tl.get('source_event_at')}），还可能再覆盖一次时区")
        elif tl.get("source_available") is False:
            print(f"    · timed 已记录 setSourceUnavailable（{tl.get('source_event_at')}），定位源不再驱动时区")

    print("\n═══ 泄漏面 ═══")
    p = r["A1_proxy_residue"]
    flags = ", ".join(f"{k}={v}" for k, v in p["scutil"].items())
    print(f"  系统代理：{flags}")
    if p["enabled"]:
        print(f"    ⚠ 系统代理处于启用状态：{p['enabled']}（文章 2.4 要求开 TUN 后关掉系统代理，两套代理不该叠着）")
    print(f"  网络服务残留：{len(p['residue'])} 项" + (f" -> {[x['service'] + '/' + x['kind'] for x in p['residue']]}" if p["residue"] else ""))
    v6 = r["A5_ipv6"]
    print(f"  IPv6    ：全局地址 {len(v6['global_addresses'])} 个；服务状态 {v6['services']}")
    d = r["A6_dns"]
    print(f"  DNS     ：系统 DNS {d['system_dns']}")
    cdc = d.get("clash") or {}
    if cdc.get("found"):
        print("    Clash 主解析器：" + ("、".join(cdc.get("nameserver") or []) or "（空）")
              + "；respect-rules " + ("已开" if cdc.get("respect_rules") else "未开")
              + "；dns.enable " + ("开着" if cdc.get("enabled") is not False else "关着"))
        if cdc.get("hijack"):
            print("    dns-hijack    ：" + "、".join(cdc["hijack"]) + "（TUN 里的 DNS 查询会被接管）")
        elif cdc.get("tun_enabled"):
            print("    ⚠ TUN 开着但没配 dns-hijack：发往 53 端口的查询不会被接管，"
                  "会落到系统解析器上")
        if cdc.get("policy_cn"):
            print("    国内域名策略   ：" + "、".join(cdc["policy_cn"])
                  + "（正常，国内域名本来就该走国内解析）")
        for _label, _key in (("主解析器", "leaking"), ("fallback", "leaking_fallback")):
            if cdc.get(_key):
                print("    ⚠ " + _label + "里有国内服务器：" + "、".join(cdc[_key])
                      + " —— 国外域名的解析交给了它们，自动清理会换掉")
        if not cdc.get("leaking") and not cdc.get("leaking_fallback") \
                and not cdc.get("respect_rules"):
            print("    ⚠ 没有 respect-rules：Clash 自己的 DNS 查询不跟规则走，是从真实 IP 直发的")
    if d["real_ip_hosts"]:
        print(f"    ⚠ 解析到真实公网 IP 的域名（可能是泄漏）：{d['real_ip_hosts']}")
    elif d["fake_ip"]:
        print("    全部落进 fake-ip 段，未发现真实 IP 解析，TUN 劫持生效")
    else:
        print("    ⚠ 未取到任何解析结果，无法判断")
    if "A7_webrtc" in r:
        w = r["A7_webrtc"]
        if w["available"]:
            if w["leaked_public"]:
                print(f"  WebRTC  ：⚠ 探测到公网地址，可能是真实 IP 泄漏：{w['leaked_public']}")
            else:
                print(f"  WebRTC  ：未发现公网地址泄漏（共探测到 {len(w['local_ips'])} 个地址）")
        else:
            print(f"  WebRTC  ：未测（{w['note']}）")
    g = r["A12_clash_groups"]
    if g["reachable"]:
        print(f"  Clash   ：mode={g['mode']}  tun={g['tun'].get('enable')}  strict-route={g['tun'].get('strict-route')}")
        for grp in g["groups"]:
            print(f"    · {grp['name']:<10} {grp['type']:<10} now={grp['now']}  成员={grp['members']}")
        if g["auto_switching"]:
            if g.get("mode") == "global":
                print(f"    · 存在自动切换组 {g['auto_switching']}，但全局模式下流量不经过它们，不在路径里")
            else:
                print(f"    ⚠ 仍在自动切换的组：{g['auto_switching']}")
        fc = g.get("fail_closed") or {}
        cg = g.get("claude_group") or {}
        if fc.get("ok"):
            n_rule = len([r for r in (g.get("claude_rules") or []) if r.get("proxy") == "Claude"])
            if g.get("mode") == "global":
                path = f"全部流量走 GLOBAL → {g.get('global_now')} → {cg.get('now')}"
            else:
                path = (f"{n_rule} 条规则把 Claude 域名交给专用组 → {cg.get('now')}"
                        f"，兜底 {(g.get('fallback') or {}).get('proxy')}")
            print(f"    ✓ 绝不直连成立（{g.get('mode')} 模式）：{path}"
                  f"（{len(cg.get('members', []))} 个成员，无健康检查）")
        elif fc:
            print("    ⚠ 绝不直连不成立：" + "；".join(fc.get("reasons", [])))
    else:
        print("  Clash   ：控制接口不可达，跳过")

    print("\n═══ 残留与完整性 ═══")
    b = r["A2_anthropic_base_url"]
    print(f"  BASE_URL 残留：{len(b['hits'])} 处")
    for h in b["hits"]:
        print(f"    · {h['file']}:{h['line']}  {h['text']}")
    t = r["A1_terminal_env"]
    npm_git = [
        v for v in list(t["npm"].values()) + list(t["git"].values())
        if v and v.strip().lower() not in ("null", "undefined", "none")
    ]
    rc_hits = sum(len(v) for v in t["rc_files"].values())
    br = t.get("brew") or {}
    print(
        f"  终端/rc/npm/git 残留：env {len(t['env_hits'])} 条，rc 命中 {rc_hits} 条"
        + (f"，npm/git: {npm_git}" if npm_git else "，npm/git 无代理设置")
        + f"，~/.npmrc {len(t.get('npmrc') or [])} 行"
        + ("，brew config: " + "、".join(br["proxy"]) if br.get("proxy")
           else "，brew config 无代理" if br.get("installed")
           else "，未装 Homebrew")
    )
    for h in t.get("npmrc") or []:
        print(f"    ⚠ ~/.npmrc:{h['line']}  {h['text']}")
    if t.get("settings_proxy"):
        print(f"    ⚠ settings.json 的 env 里有代理变量：{'、'.join(t['settings_proxy'])}")
    for h in t["env_hits"]:
        print(f"    ⚠ {h}")
    if t.get("env_info"):
        print(f"    · 其余含 claude/anthropic 的环境变量 {len(t['env_info'])} 条，属正常配置，未计入残留")
    kc = r.get("E1_keychain") or {}
    if kc:
        if not kc.get("readable"):
            print(f"  钥匙串    ：未读到（{kc.get('note')}）")
        elif kc.get("items"):
            print(f"  钥匙串    ：{len(kc['items'])} 项 Claude 相关（svce 与 acct 分开看）")
            for it in kc["items"]:
                print(f"    · svce={it['svce']!r}  acct={it['acct']!r}")
                print(f"      {it['kind']}")
        else:
            print(f"  钥匙串    ：{kc.get('note')}")
    tp = r["A10_third_party"]
    print(f"  第三方客户端：{'未发现' if not tp['hits'] else tp['hits']}")
    ci = r["A11_client_integrity"]
    if ci["cli_path"]:
        print(f"  Claude Code：{ci['cli_version'] or '版本未知'}")
        print(f"    路径 {ci['cli_real'] or ci['cli_path']}")
        inst = ci.get("install") or {}
        if inst.get("evidence"):
            print(f"    安装方式 {inst.get('method')}：{inst['evidence']}")
        if ci.get("version_runs") and ci.get("version_ok"):
            print("    实跑 --version 通过（已传 DISABLE_AUTOUPDATER=1，体检不会顺手自升级）")
        else:
            print("    ⚠ 实跑 --version 没通过，或版本号看着不正常")
        if ci.get("current_present") is False:
            print(f"    ⚠ 软链指向的 {ci.get('current_version')} 不在 versions 目录里")
        sig = ci.get("signature") or {}
        if sig.get("verified"):
            print(f"    签名 {sig.get('authority')}，验签通过")
        elif sig.get("checked"):
            print(f"    ⚠ 验签：{sig.get('note')}")
        mb = ci["total_bytes"] / 1024 / 1024
        names = [e["name"] for e in ci["versions"]]
        print(f"    versions 目录留存 {ci['version_count']} 份（{mb:.0f} MB）：{names}")
        if ci["stale_count"]:
            print(f"      其中非当前版本 {ci['stale_count']} 份，占 {ci['stale_bytes'] / 1024 / 1024:.0f} MB；"
                  f"官方安装器会自行清理，如需腾空间可手动删旧版本")
    else:
        print(f"  Claude Code：{ci['note']}")
    if ci["note"] and ci["cli_path"]:
        print(f"    ⚠ {ci['note']}")
    gw = r["A9_geo_words"]
    if gw["hits"]:
        print(f"  地理位置词：⚠ 命中 {gw['hits']}")
    else:
        print(f"  地理位置词：未命中（扫了 {gw['scanned']} 份 CLAUDE.md / AGENTS.md / settings）")
    if gw.get("note"):
        print(f"    · {gw['note']}")
    ma = r["A13_multi_account"]
    print(f"  账号痕迹：{ma['identities'] or ma['note']}；本地备份 {ma['backups']} 份")


def auto_clean_plan(report: dict) -> dict:
    """残留类项目的自动清理计划。

    这几类都幂等、可逆、有备份，所以不再逐项询问，直接清：
      * 未启用但存了值的系统代理；
      * shell 配置里的代理行；
      * npm / git 的全局代理；
      * Claude Code settings.json 里的端点变量。
    真正有副作用的（遥测开关、IPv6、定位服务）仍然逐项询问。
    范围限定在 Claude Code：其它工具（~/.codex、~/.dsh 等）只报告，不代改。
    """
    env = report["A1_terminal_env"]
    npm_git = [
        k for k, v in list(env["npm"].items()) + list(env["git"].items())
        if v and v.strip().lower() not in ("", "undefined", "null")
    ]
    rc = {k: v for k, v in env["rc_files"].items() if v}
    npmrc = env.get("npmrc") or []
    brew_proxy = (env.get("brew") or {}).get("proxy") or []
    settings_env_proxy = env.get("settings_proxy") or []
    base_url_files = {h["file"] for h in report["A2_anthropic_base_url"]["hits"]}
    other_files = sorted(f for f in base_url_files if f != str(SETTINGS))

    summary = []
    if report["A1_proxy_residue"]["residue"]:
        summary.append(f"系统代理残留 {len(report['A1_proxy_residue']['residue'])} 项（只清 Enabled=No 的）")
    if env["env_hits"]:
        summary.append(
            f"当前 shell 环境里的代理/端点变量 {len(env['env_hits'])} 条 —— 只报告，"
            f"进程环境无法由脚本代改，请在新终端里确认"
        )
    if rc:
        summary.append("shell 配置里的代理行：" + "、".join(f"{k} {len(v)} 行" for k, v in rc.items()))
    if npm_git:
        summary.append("npm / git 全局代理：" + "、".join(npm_git))
    if npmrc:
        # 只报告：.npmrc 没进备份清单，脚本不代改别人的配置文件。
        summary.append(f"~/.npmrc 里 {len(npmrc)} 行代理配置（只报告，脚本不代改）")
    if brew_proxy:
        summary.append(
            "Homebrew 报出代理 " + "、".join(brew_proxy)
            + "（来源是环境变量，进程环境脚本改不了，请在新终端里确认）"
        )
    if settings_env_proxy:
        summary.append(
            "Claude Code 的 settings.json env 里有代理变量：" + "、".join(settings_env_proxy)
        )
    if str(SETTINGS) in base_url_files:
        summary.append(f"Claude Code 的 {SETTINGS} 里指向别处的端点变量")
    if other_files:
        summary.append("属于其它工具、只报告不代改：" + "、".join(other_files))

    st = report.get("A25_claude_storage") or {}
    st_bytes = st.get("cleanable_bytes") or 0
    if st_bytes:
        n_stale = len(st.get("cli", {}).get("stale") or []) + len(st.get("bundled", {}).get("stale") or [])
        summary.append(
            f"系统级可清理 {st_bytes / 2 ** 20:.0f} MB："
            f"被取代的旧版本 {n_stale} 份 + 可再生缓存 {len(st.get('caches') or [])} 个"
        )

    cs = report.get("A26_claude_settings") or {}
    if cs.get("dead"):
        summary.append(
            f"项目级 settings 里失效的权限条目 {len(cs['dead'])} 条"
            f"（涉及 {len({d['file'] for d in cs['dead']})} 个文件）"
        )
    if cs.get("risky"):
        summary.append(
            f"偏危险的长期授权 {len(cs['risky'])} 条 —— 只报告，删不删由你定"
        )

    # 项目级 .claude 只有这一件事能自动做：把指向已消失路径的工作树**注册**划掉。
    # 工作树本身一律不碰——实测 99% 的体积是真实代码，按体积去清等于删项目。
    pc = report.get("A24_project_claude") or {}
    stale_repos = [x["repo"] for x in (pc.get("repos_with_stale") or [])]
    if stale_repos:
        summary.append(
            f"项目级过期的工作树注册 {pc.get('stale_total')} 条，涉及 {len(stale_repos)} 个仓库"
            f"（只划掉登记记录，不删任何工作树）"
        )

    # Clash 自己的解析器。之前这块漏检，是用户装了检测站才发现的：主 nameserver
    # 是阿里 223.5.5.5 时，国外域名的解析请求直接交给国内解析器；再叠上没有
    # respect-rules，Clash 的 DNS 查询还是从真实 IP 直发的。
    cd = (report.get("A6_dns") or {}).get("clash") or {}
    if clash_dns_leaking(report):
        bits = []
        if cd.get("leaking"):
            bits.append("主解析器含 " + "、".join(cd["leaking"]))
        if cd.get("leaking_fallback"):
            bits.append("fallback 含 " + "、".join(cd["leaking_fallback"]))
        if not cd.get("respect_rules"):
            bits.append("没开 respect-rules，DNS 查询不走代理")
        if cd.get("enabled") is False:
            bits.append("dns.enable 是关的，DNS 模块没在跑")
        if cd.get("tun_enabled") and not cd.get("hijack"):
            bits.append("TUN 开着但没配 dns-hijack，53 端口的查询不会被接管")
        summary.append("Clash DNS 泄漏：" + "；".join(bits))

    bl = report.get("A27_browser_locale") or {}
    browser_locale = bool(bl.get("cn") and (bl.get("country") or "") not in ("", "CN"))
    if browser_locale:
        summary.append(
            f"浏览器 Intl 区域设置是 {bl.get('measured')}（大陆简体），出口却是 "
            f"{bl.get('country')} —— 会把 Chrome 的应用语言设为 {bl.get('target')}"
            f"（只影响 Chrome，系统语言不动；要重启 Chrome 才生效）"
        )

    return {
        "proxy_residue": report["A1_proxy_residue"]["residue"],
        "rc_files": rc,
        "npm_git": npm_git,
        "npmrc": npmrc,
        "brew_proxy": brew_proxy,
        "settings_env_proxy": settings_env_proxy,
        "settings_base_url": str(SETTINGS) in base_url_files,
        "clash_dns": clash_dns_leaking(report),
        "browser_locale": browser_locale,
        "stale_worktrees": stale_repos,
        "storage_bytes": st_bytes,
        "dead_permissions": len(cs.get("dead") or []),
        "summary": summary,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="按四层防线做 Claude 本机体检与加固")
    ap.add_argument("--audit", action="store_true", help="只读体检，不做任何修改")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出体检结果")
    ap.add_argument("--webrtc", action="store_true", help="附加 WebRTC 泄漏探测（需要 Node + Playwright）")
    ap.add_argument("--check-media", action="store_true",
                    help="起一个本地页面，用你日常浏览器确认摄像头/麦克风权限（WebRTC 那一项靠它转正）")
    ap.add_argument("--check-locale", action="store_true",
                    help="起一个本地页面，用你日常浏览器把 Intl 区域设置回传回来")
    ap.add_argument("--commands", action="store_true", help="只打印手工核对用的终端命令清单，不体检")
    ap.add_argument("--manual", action="store_true", help="只打印必须人工做的行动清单（带点击路径），不体检")
    args = ap.parse_args(argv)

    if args.check_media:

        verify_media_permission()

        return 0

    if args.check_locale:

        verify_browser_locale()

        return 0


    if args.commands:
        print_manual_checks()
        return 0
    if args.manual:
        print_manual_actions()
        return 0

    under_claude = running_under_claude()
    if under_claude and not args.audit:
        print("拒绝执行：当前脚本由 Claude Code 启动。加固步骤会改本机状态，请改用普通终端；这里只允许 --audit。", file=sys.stderr)
        return 2
    # 加固模式必须在真实 TTY 下运行；放在体检之前，管道里调用就立刻失败，不必先跑完全套只读检查
    if not args.audit and not sys.stdin.isatty():
        print("拒绝执行：需要真实 TTY 完成知情确认。", file=sys.stderr)
        return 2

    try:
        report = audit()
        if args.webrtc:
            report["A7_webrtc"] = check_webrtc()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        # 只读体检也必须干净报错：早期版本把 audit() 放在 try 之外，
        # 任何一处探测失败都会抛 traceback，用户看到一堆栈帧却不知道发生了什么。
        print(f"体检失败：{error}\n本次没有做任何改动。", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    print("claude-account-guard —— 四层防线的本机体检")
    print_audit(report)
    if args.audit:
        # 只读模式：体检完直接给总表
        print_summary_table(report)
        print("\n  想自己复核上面每一项：python3 scripts/account_guard.py --commands")
        print("  必须人工做的那些（带点击路径）：python3 scripts/account_guard.py --manual")
        outdir = BACKUP_ROOT
        outdir.mkdir(parents=True, exist_ok=True)
        # 用单引号包内层格式串：Python 3.9/3.10/3.11 的 f-string 不允许内层
        # 与外层同用双引号，写成 strftime("%Y...") 会直接 SyntaxError。
        p = outdir / f"audit-{dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f')}.json"
        p.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n报告已存：{p}")
        return 0

    if not sys.stdin.isatty():
        print("拒绝执行：需要真实 TTY 完成知情确认。", file=sys.stderr)
        return 2

    backup: pathlib.Path | None = None
    try:
        plan = auto_clean_plan(report)
        print("\n── 残留类：自动清理，不逐项询问 ──")
        if plan["summary"]:
            for line in plan["summary"]:
                print(f"  · {line}")
        else:
            print("  · 没检测到需要清理的残留")
        print("\n── 配置类：有副作用，仍由你决定 ──")
        telemetry = ask_choice(
            "遥测开关：0 保持；1 关三项；2 只关上报与下载流量。选择 [0]：", {0, 1, 2}
        )
        do_wrapper = ask_yes("生成 BROWSER=false 的 claude-safe 包装脚本？")

        # 需要 root 的两项必须在这里一次性提前授权，原因有两个：
        #   1) location_service_status() 要读 /var/db/locationd/clients.plist，非 root 读不到，
        #      放在 sudo 之前问会永远显示「读不到」，这一项等于永远选不了；
        #   2) 备份是第一个写操作，而 root 文件的备份也要 root，顺序反了就会无备份改动。
        do_ipv6 = do_loc = False
        loc = {"readable": False, "clients": {}, "note": "未处理（本轮未请求管理员权限）"}
        if ask_yes("处理需要管理员权限的两项（关闭 IPv6、关闭定位服务「设定时区」）？"):
            sudo_prime()
            do_ipv6 = ask_yes("关闭所有网络服务的 IPv6（文章 2.5 可选加固）？")
            loc = location_service_status()
            gate = location_gate_state(loc)
            if gate is False:
                # 本来就是关的，不必再问一次，也不必去写一个不存在的字段
                print(f"  定位服务里的「设定时区」已经是关闭状态，无需改动：{list(loc['clients'])}")
            elif gate is True:
                print(f"  已识别的定位服务条目：{list(loc['clients'])}")
                print("  说明：这是非官方改动路径，key 名在不同 macOS 版本上可能不同；")
                print("        脚本会逐个尝试，并在改写后重新读取整份 plist 复验，验不到就判定未生效。")
                print("        更稳的做法是走 UI：系统设置 → 隐私与安全性 → 定位服务 → 系统服务 → 详细信息 → 设定时区")
                do_loc = ask_yes("要由脚本关闭定位服务里的「设定时区」吗？")
            else:
                print(f"  {loc['note']}")

        if telemetry == 1:
            print("\n⚠ 文章 §5 写明：关掉这些键会同时关掉功能旗标，Remote Control 可能用不了。")

        targets = [SETTINGS, HOME / ".claude.json"]
        sudo_targets = [LOCATIOND_PLIST] if do_loc else []
        print("\n最终执行清单：")
        print(f"  1. 第一个写操作：备份 {[str(t) for t in targets + sudo_targets]}")
        print(f"  2. 自动清理残留：系统代理 {len(plan['proxy_residue'])} 项，"
              f"shell 配置 {sum(len(v) for v in plan['rc_files'].values())} 行，"
              f"npm/git {len(plan['npm_git'])} 项，"
              f"端点/代理变量 {'是' if (plan['settings_base_url'] or plan.get('settings_env_proxy')) else '无'}，"
              f"过期工作树注册 {len(plan.get('stale_worktrees') or [])} 个仓库，"
              f"系统级可清理 {plan.get('storage_bytes', 0) / 2 ** 20:.0f} MB")
        print(f"  3. 遥测开关：{telemetry}")
        print(f"  4. 生成包装脚本：{'是' if do_wrapper else '否'}")
        print(f"  5. 关闭 IPv6：{'是' if do_ipv6 else '否'}")
        print(f"  6. 关闭定位服务「设定时区」：{'是' if do_loc else '否'}")
        print("  绝不改动：session、project、history、skill、plugin、hook、command、agent、MCP 配置等受保护数据。")
        if input("完全理解后输入 CONFIRM 开始；其他输入取消：").strip() != "CONFIRM":
            print("已取消，没有修改任何内容。")
            return 1

        # 锁取在 CONFIRM 之后：这之前一个字节都没写，不需要拦并发。
        locked, lock_note = acquire_run_lock()
        if not locked:
            print(f"停止：{lock_note}", file=sys.stderr)
            print("等它跑完再来；若确认那个进程已经不在了，删掉锁文件即可。", file=sys.stderr)
            return 2
        print(f"  {lock_note}")

        before = protected_snapshot()
        # Clash 配置也进备份：DNS 那一项要改生成物和 profile 的 Merge 增强文件两处，
        # 增强文件改错会让下次重算生成出坏配置。
        clash_files = [clash_config()] if clash_config().is_file() else []
        merge_file = _active_merge_enhancement()
        if merge_file is not None:
            clash_files.append(merge_file)
        backup = create_backup(
            [t for t in targets if t.exists()]
            + [HOME / name for name in plan["rc_files"] if (HOME / name).is_file()]
            + clash_files,
            sudo_targets,
        )
        print(f"\n[1/6] 备份完成：{backup}")

        n = clear_proxy_residue(plan["proxy_residue"]) if plan["proxy_residue"] else 0
        rc_changed = clear_rc_proxy_lines(plan["rc_files"]) if plan["rc_files"] else []
        npm_git_done = clear_npm_git_proxy() if plan["npm_git"] else []
        print(f"[2/6] 自动清理：系统代理 {n} 项，shell 配置 {len(rc_changed)} 个文件，npm/git {len(npm_git_done)} 项")
        if plan.get("clash_dns"):
            try:
                print(f"       Clash DNS：{clear_clash_dns_leak(report)}")
            except Exception as e:
                print(f"       ⚠ Clash DNS 清理失败（其余步骤继续）：{e}")
        if plan.get("browser_locale"):
            try:
                print(f"       浏览器 Intl：{clear_browser_locale(report['A27_browser_locale'])}")
            except Exception as e:
                print(f"       ⚠ 浏览器 Intl 清理失败（其余步骤继续）：{e}")

        print(f"[3/6] 遥测开关：{apply_telemetry(telemetry) if telemetry else '保持'}")
        if plan["settings_base_url"] or plan.get("settings_env_proxy"):
            print(f"       端点/代理变量：{clear_anthropic_base_url()}")

        for d in clean_claude_storage(report):
            label = d["path"].replace(str(HOME) + "/", "")
            if d.get("ok"):
                print(f"       已清 {label}  ({d.get('bytes', 0) / 2 ** 20:.0f} MB)")
            else:
                print(f"       跳过 {label} —— {d.get('error')}")

        for d in clean_dead_permissions(report):
            if d.get("error"):
                print(f"       权限条目 {d['file']}：跳过 —— {d['error']}")
            elif d.get("removed"):
                print(f"       权限条目 {d['file']}：删掉 {d['removed']} 条失效授权")

        for d in clean_project_claude_junk():
            label = d["path"].replace(str(HOME) + "/", "")
            if d.get("ok"):
                size = f"  ({d['bytes'] / 1024:.0f} KB)" if d.get("bytes") else ""
                print(f"       项目级 {label}{size}")
            else:
                print(f"       项目级跳过 {label} —— {d.get('error')}")

        for d in prune_stale_worktrees(plan.get("stale_worktrees") or []):
            name = d["repo"].replace(str(HOME) + "/", "")
            if d.get("error"):
                print(f"       工作树注册 {name}：跳过 —— {d['error']}")
            else:
                print(f"       工作树注册 {name}：{d['before']} -> {d['after']}"
                      f"（划掉 {len(d['removed'])} 条，工作树没动）")

        if do_wrapper:
            print(f"[4/6] 包装脚本：{apply_browser_wrapper()}")
        else:
            print("[4/6] 包装脚本：未生成")

        if do_ipv6:
            res = set_ipv6_off(list(report["A5_ipv6"]["services"]))
            print(f"[5/6] IPv6：已关闭 {res['done']}")
            if res["failed"]:
                print(f"       未能关闭：{res['failed']}（没有 root 时 networksetup 会直接失败）")
            if res["rollback"]:
                print("       恢复命令：" + "；".join(res["rollback"]))
        else:
            print("[5/6] IPv6：保持不变")

        if do_loc:
            ensure_sudo("关闭定位服务里的「设定时区」")
            print(f"[6/6] 定位服务「设定时区」：{disable_location_timezone()}")
        else:
            print("[6/6] 定位服务「设定时区」：保持不变")

        # 允许清单要包含本次有意改动的文件，否则 zshrc 的自动清理会被误报成「被连带改动」
        allow = {str(SETTINGS)} | {str(HOME / name) for name in plan["rc_files"]}
        changed = protected_verify(before, allow)
        if changed:
            # 这里刻意不走 raise：写操作已经执行完了，报成「停止」会让用户以为什么都没发生。
            # 必须同时说清三件事——哪些文件被连带改动、改动已完成、回滚路径在哪。
            print(
                "\n注意：本次加固已完成，但检测到受保护文件被连带改动：\n  "
                + "\n  ".join(changed)
                + f"\n这些改动不是脚本发起的，备份（回滚用）：{backup}",
                file=sys.stderr,
            )
            return 3
        print(f"\n完成。受保护文件未被动过。\n备份（回滚用）：{backup}")

        # 总表必须是改完之后的状态，不能拿加固前的报告充数——否则刚清掉的残留
        # 在表里还显示「待处理」，用户会以为没生效。重新体检一次。
        try:
            print("\n重新体检一次，下面是改动前后的对照（同一次运行里的两遍真读数）：")
            # 复检要带上这次真测过的 WebRTC 结果，否则 --webrtc 跑完的结论会在复检表里
            # 退回成「未探测」，用户刚看到的 ✓ 又变成 ·，等于白跑一次两分钟的探测。
            fresh = audit()
            if "A7_webrtc" in report:
                fresh["A7_webrtc"] = report["A7_webrtc"]
            print_before_after(report, fresh)
        except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
            print(f"复检失败（{error}），上面 [1/6]–[6/6] 的结果仍然有效。", file=sys.stderr)
        return 0
    except KeyboardInterrupt:
        # 中途 Ctrl-C：之前几步可能已经写完，必须告诉用户备份在哪，
        # 否则用户会以为「中断了就等于什么都没发生」。
        print("\n已中断。", file=sys.stderr)
        if backup:
            print(f"中断前已执行的改动不会自动回滚；备份（回滚用）：{backup}", file=sys.stderr)
        else:
            print("中断发生在第一个写操作之前，没有改动任何内容。", file=sys.stderr)
        return 2
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"停止：{error}", file=sys.stderr)
        if backup:
            print(f"注意：停止前已执行的改动会保留，未执行的不会发生；备份（回滚用）：{backup}", file=sys.stderr)
        else:
            print("停止发生在第一个写操作之前，没有改动任何内容。", file=sys.stderr)
        return 2
    finally:
        # 放锁放在 finally：中断、出错、正常跑完三条路都要放，
        # 否则一次 Ctrl-C 就会把这台机器锁到用户自己来删文件为止。
        release_run_lock()


def ask_yes(prompt: str) -> bool:
    return input(f"{prompt} [y/N]：").strip().lower() == "y"


def ask_choice(prompt: str, allowed: set[int]) -> int:
    value = input(prompt).strip() or "0"
    if not value.isdigit() or int(value) not in allowed:
        raise ValueError("输入不在允许范围内，已停止且未修改")
    return int(value)


if __name__ == "__main__":
    raise SystemExit(main())
