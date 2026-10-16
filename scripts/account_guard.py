#!/usr/bin/env python3
"""CC tackle —— 按《你的 Claude 账号是怎么被封的》四层防线做本机体检与加固。

设计沿用 skills/claude-cleanup 的安全约定：
  * 只读审计永远安全，任何写操作都要真实 TTY + 逐项询问 + 最终 CONFIRM；
  * CONFIRM 后、任何目标状态变更前先完成备份，失败即停（并发锁是控制元数据）；
  * 需要 root 时只在终端原生 sudo 隐藏提示里输密码，脚本从不读取或保存密码；
  * 每项改动之后立刻复验，验证失败即报错并保留备份。

用法：
  python3 scripts/account_guard.py --audit      # 只读体检，输出报告
  python3 scripts/account_guard.py              # 交互式加固
  python3 scripts/account_guard.py --audit --json   # 机器可读
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hmac
import hashlib
import io
import ipaddress
import json
import os
import pathlib
import re
import secrets
import socketserver
import shutil
import subprocess
import unicodedata
import zipfile
import zoneinfo
import sys
import tempfile

HOME = pathlib.Path.home()
SETTINGS = HOME / ".claude" / "settings.json"
BACKUP_ROOT = HOME / "ClaudeGuardBackups"
# Audit state is intentionally opt-in.  A normal ``--audit`` must not leave an
# export history, cache, or report behind on disk.
CACHE_MAX_AGE_SECONDS = 24 * 60 * 60


def claude_config_scope() -> dict:
    """Describe the Claude config directory this process can actually cover.

    ``CLAUDE_CONFIG_DIR`` changes where Claude Code keeps its global settings.
    This guard deliberately does not follow that directory automatically: doing
    so without an explicit, reviewed scope would make a repair target unclear.
    """
    default = HOME / ".claude"
    raw = os.environ.get("CLAUDE_CONFIG_DIR", "").strip()
    if raw:
        configured = pathlib.Path(os.path.abspath(os.path.expanduser(raw)))
    else:
        configured = default
    custom = configured != default
    out = {
        "default_config_dir": str(default),
        "configured_config_dir": str(configured),
        "custom": custom,
        "covered": [str(default)] if not custom else [],
        "out_of_scope": [],
    }
    if custom:
        out["out_of_scope"] = [
            {"item": "Claude Code global settings", "path": str(configured / "settings.json"),
             "reason": "CLAUDE_CONFIG_DIR 指向自定义目录；本 skill 不扫描或修改该目录"},
            {"item": "Claude Code global settings.local", "path": str(configured / "settings.local.json"),
             "reason": "CLAUDE_CONFIG_DIR 指向自定义目录；本 skill 不扫描或修改该目录"},
        ]
    return out


BROWSER_PROFILE_ENV = "CLAUDE_GUARD_BROWSER_PROFILE"
EXPECTED_COUNTRY_ENV = "CLAUDE_GUARD_EXPECTED_COUNTRY"
EXPECTED_EXIT_IP_ENV = "CLAUDE_GUARD_EXPECTED_EXIT_IP"


BROWSER_PROFILE_DIR_ENV = "CLAUDE_GUARD_BROWSER_PROFILE_DIR"

# WebRTC Network Limiter —— 文章 §2.5② 推的那个 Chrome 扩展。它做的就是往
# chrome.privacy.network.webRTCIPHandlingPolicy 写 disable_non_proxied_udp
# （「只走代理的 UDP」）：stock Chrome 的界面上没有这个开关，装扩展是普通用户
# 自己办得到的唯一一条路。企业策略也能设，但要管理员写机器级 plist，且会让所有
# 资料的网页通话都建不起来。
WEBRTC_LIMITER_ID = "npeicpdbkakmehahjeeohfdhnlpdklia"
WEBRTC_LIMITER_NAME = "WebRTC Network Limiter"
WEBRTC_LIMITER_SETTING = "disable_non_proxied_udp"
WEBRTC_LIMITER_STORE_URL = f"https://chromewebstore.google.com/detail/{WEBRTC_LIMITER_ID}"
WEBRTC_CRX_ENDPOINT = "https://clients2.google.com/service/update2/crx"


def browser_profile_scope() -> str | None:
    """Return the user supplied browser profile identity, if any."""
    value = os.environ.get(BROWSER_PROFILE_ENV, "").strip()
    return value or None


def browser_profile_dir() -> str | None:
    """要打开的那个 Chrome 资料目录，例如 `Profile 1`。

    为什么要单独声明这个：复核结论得归到某个浏览器资料上，而页面自己报不出资料身份。
    名字（`Claude`）只有人能看懂，`open --profile-directory=` 要的是目录名。
    读 Chrome 的 Local State 能查到映射，但那个文件受 TCC 保护、脚本不一定读得到，
    所以让用户显式写一个；写错时 Chrome 会安静地开默认资料，脚本无法察觉。
    """
    value = os.environ.get(BROWSER_PROFILE_DIR_ENV, "").strip()
    return value or None


def open_verify_page(url: str, what: str) -> dict:
    """脚本自己把复核页打开，并回报「这次是谁开的」。

    为什么必须由脚本开：复核结论要归到某个浏览器资料上。用户在别处打开、脚本只发
    一条链接的话，那份结论只能一直挂着「资料身份未验证」；由脚本按声明的资料目录
    打开，至少能说清「这次是脚本按哪个资料开的」。

    开不出来就如实回报失败，绝不假装打开过 —— 调用方会把 URL 留在屏幕上让人手动开。
    """
    prof = browser_profile_dir()
    cmd = ["open", "-na", "Google Chrome"]
    if prof:
        cmd += ["--args", f"--profile-directory={prof}"]
    cmd.append(url)
    try:
        code, out = run(cmd, timeout=30)
    except (OSError, subprocess.SubprocessError) as error:
        return {"opened": False, "reason": str(error), "profileDir": prof}
    if code != 0:
        return {"opened": False, "reason": (out or "").strip() or f"open 退出码 {code}",
                "profileDir": prof}
    where = browser_profile_scope() or "未声明资料"
    print(f"  已替你打开{what}（资料 {where}" + (f" / {prof}" if prof else "") + "）。", flush=True)
    return {"opened": True, "profileDir": prof}


def webrtc_limiter_dir() -> pathlib.Path:
    """下下来的扩展包放哪。按调用时解析，不在 import 时定死（测试要能改 HOME）。"""
    return HOME / ".local" / "state" / "claude-guard" / "extensions"


def chrome_prodversion() -> str:
    """本机 Chrome 的版本号，拼 CRX 直链要用。取不到就给个宽松的兜底值。"""
    info = pathlib.Path("/Applications/Google Chrome.app/Contents/Info.plist")
    code, out = run(["defaults", "read", str(info), "CFBundleShortVersionString"], timeout=10)
    value = (out or "").strip()
    return value if code == 0 and re.fullmatch(r"\d+(\.\d+)*", value) else "9999.0.0.0"


def webrtc_limiter_crx_url(prodversion: str) -> str:
    """商店官方的 CRX 直链。

    参数照 Chrome 客户端那一套拼：prod 必须是 chromiumcrx、x 里要带 id 与
    installsource=ondemand，少一个服务端就回商店页面而不是包（实测：少了
    prod 那一串，回的是 302 加一段 HTML）。
    """
    machine = ""
    try:
        machine = os.uname().machine
    except AttributeError:                       # pragma: no cover - 本 skill 只跑 macOS
        pass
    arch = "arm64" if machine in ("arm64", "aarch64") else "x64"
    return (
        f"{WEBRTC_CRX_ENDPOINT}?response=redirect&os=mac&arch={arch}&os_arch={arch}"
        f"&nacl_arch={arch}&prod=chromiumcrx&prodchannel=unknown"
        f"&prodversion={prodversion}&acceptformat=crx2,crx3"
        f"&x=id%3D{WEBRTC_LIMITER_ID}%26installsource%3Dondemand%26uc"
    )


def _pb_varint(buf: bytes, pos: int) -> tuple:
    shift = 0
    value = 0
    while pos < len(buf):
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
    raise ValueError("varint 越界")


def _pb_fields(buf: bytes) -> list:
    """把一段 protobuf 拆成 (字段号, 值)。只认 CRX 头里出现的两种 wire type。"""
    out = []
    pos = 0
    while pos < len(buf):
        key, pos = _pb_varint(buf, pos)
        field, wire = key >> 3, key & 7
        if wire == 2:
            length, pos = _pb_varint(buf, pos)
            out.append((field, buf[pos:pos + length]))
            pos += length
        elif wire == 0:
            value, pos = _pb_varint(buf, pos)
            out.append((field, value))
        else:
            break
    return out


def crx_public_key_ids(blob: bytes) -> list:
    """从 CRX3 的签名块推出扩展 ID。

    扩展 ID 本来就是**发布者公钥**的哈希前 16 字节按 a-p 映射出来的，所以这条比
    读 manifest 里的名字硬得多：名字是商店页面显示用的，改一行就行，ID 由公钥定。
    商店下发的包里有两块签名（Google 的商店密钥 + 发布者密钥），实测只有发布者
    那块对得上，所以两块都算，命中任意一块即认。
    """
    if len(blob) < 12 or blob[:4] != b"Cr24":
        return []
    if int.from_bytes(blob[4:8], "little") != 3:
        return []                                  # CRX2 结构不同，这里不猜
    header = int.from_bytes(blob[8:12], "little")
    ids = []
    for field, proof in _pb_fields(blob[12:12 + header]):
        if field != 2 or not isinstance(proof, bytes):
            continue
        for sub, value in _pb_fields(proof):
            if sub != 1 or not isinstance(value, bytes) or not value:
                continue
            digest = hashlib.sha256(value).digest()[:16]
            ids.append("".join("abcdefghijklmnop"[b >> 4] + "abcdefghijklmnop"[b & 15]
                               for b in digest))
    return ids


def parse_crx(blob: bytes) -> dict:
    """拆 CRX：认魔数、按版本算出 zip 的起点、读出 manifest。"""
    if len(blob) < 16 or blob[:4] != b"Cr24":
        return {"ok": False, "why": "不是 CRX（开头没有 Cr24）"}
    version = int.from_bytes(blob[4:8], "little")
    if version == 3:
        start = 12 + int.from_bytes(blob[8:12], "little")
    elif version == 2:
        start = 16 + int.from_bytes(blob[8:12], "little") + int.from_bytes(blob[12:16], "little")
    else:
        return {"ok": False, "why": f"不认识的 CRX 版本 {version}"}
    if start >= len(blob):
        return {"ok": False, "why": "CRX 头部声明的长度不合理"}
    try:
        with zipfile.ZipFile(io.BytesIO(blob[start:])) as zf:
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
    except Exception as error:                     # zipfile 抛的异常种类多，统一降级
        return {"ok": False, "why": f"包里的 zip 或 manifest 读不出来：{error}"}
    return {"ok": True, "crxVersion": version, "start": start, "manifest": manifest}


def verify_webrtc_limiter_crx(blob: bytes) -> tuple:
    """这份 CRX 是不是我们要的那个扩展：结构、来源、身份三道。"""
    parsed = parse_crx(blob)
    if not parsed["ok"]:
        return False, parsed["why"]
    manifest = parsed["manifest"]
    update = str(manifest.get("update_url") or "")
    if "clients2.google.com/service/update2/crx" not in update:
        return False, f"update_url 不指向商店（{update or '空'}），不是商店的包"
    ids = crx_public_key_ids(blob)
    if WEBRTC_LIMITER_ID not in ids:
        return False, "签名公钥算出来的扩展 ID 对不上：" + ("、".join(ids) or "一个都没解出来")
    return True, f"{WEBRTC_LIMITER_NAME} {manifest.get('version')}（签名公钥 ID 已核对）"


def chrome_profiles_dir() -> pathlib.Path:
    """Chrome 的资料目录。按调用时解析，测试要能把 HOME 指到沙箱。"""
    return HOME / "Library" / "Application Support" / "Google" / "Chrome"


def webrtc_limiter_state() -> dict:
    """这个扩展装没装、设置对不对。

    读的是每个资料里的 `Secure Preferences` —— 扩展设置带 MAC 保护，存在这个文件，
    不在 `Preferences`（实测：同一个资料的 Preferences 里 extensions.settings 是 0
    条，Secure Preferences 里才是全部）。

    macOS 的 TCC 可能不让脚本读另一个 App 的资料目录（本机从 DSH 里跑就是
    `Operation not permitted`）：那种情况如实回报「读不到」，并给出手工入口，
    绝不因为读不到就说「没装」。
    """
    out = {"readable": False, "profiles": [], "installed_in": [], "setting": None,
           "why": ""}
    base = chrome_profiles_dir()
    try:
        candidates = sorted(p for p in base.iterdir() if p.is_dir())
    except OSError as error:
        out["why"] = f"读不到 Chrome 资料目录（{error}）"
        return out
    out["readable"] = True
    for prof in candidates:
        pref = prof / "Secure Preferences"
        try:
            data = json.loads(pref.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        entry = (data.get("extensions", {}).get("settings", {}) or {}).get(WEBRTC_LIMITER_ID)
        if not entry:
            continue
        prefs = entry.get("preferences") or {}
        out["profiles"].append(prof.name)
        out["installed_in"].append({
            "profile": prof.name,
            "version": (entry.get("manifest") or {}).get("version"),
            "fromStore": entry.get("from_webstore"),
            "setting": prefs.get("webrtc.ip_handling_policy"),
        })
        if out["setting"] is None:
            out["setting"] = prefs.get("webrtc.ip_handling_policy")
    return out


def download_webrtc_limiter(dest=None, timeout: int = 90) -> dict:
    """把扩展包下到本机。先落 .part，校验过了才改名——半个包不能冒充成品。"""
    version = chrome_prodversion()
    url = webrtc_limiter_crx_url(version)
    target = pathlib.Path(dest) if dest else (webrtc_limiter_dir() / f"{WEBRTC_LIMITER_ID}.crx")
    part = target.with_name(target.name + ".part")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        code, out = run(["curl", "-sSL", "--fail", "--max-time", str(max(30, timeout - 15)),
                         "-o", str(part), url], timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        return {"ok": False, "why": f"下载起不来：{error}", "url": url}
    if code != 0 or not part.is_file():
        part.unlink(missing_ok=True)
        return {"ok": False,
                "why": f"下载失败（curl 退出码 {code}）：{(out or '').strip()[:160]}",
                "url": url}
    blob = part.read_bytes()
    good, why = verify_webrtc_limiter_crx(blob)
    if not good:
        part.unlink(missing_ok=True)
        return {"ok": False, "why": f"下到的包没通过校验：{why}", "url": url}
    part.replace(target)
    hand_back_ownership(target)
    manifest = parse_crx(blob)["manifest"]
    return {"ok": True, "path": target, "bytes": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "version": manifest.get("version"),
            "manifestVersion": manifest.get("manifest_version"),
            "url": url, "chrome": version}


def install_webrtc_limiter(open_store: bool = True) -> dict:
    """下载扩展包 + 在你声明的资料里打开商店页，然后把还差哪一步说清楚。

    脚本**不做**那一下安装：macOS 上的 Chrome 不接受非交互装扩展。唯一能无人值守
    装上的路子是机器级策略 ExtensionInstallForcelist，代价是浏览器从此显示
    「由组织管理」、这个扩展你自己也卸不掉——那不是体检脚本该替你决定的事。
    所以这里只报「包在哪、页面开了没、还差哪一步」，绝不说「已安装」。
    """
    print("\nWebRTC Network Limiter —— 把 WebRTC 的 UDP 限制成只走代理")
    print(f"  商店页：{WEBRTC_LIMITER_STORE_URL}")
    state = webrtc_limiter_state()
    if not state["readable"]:
        print(f"  本机现状：{state['why']}；装没装自己看 chrome://extensions/")
    elif state["installed_in"]:
        for item in state["installed_in"]:
            mark = "✓" if item["setting"] == WEBRTC_LIMITER_SETTING else "!"
            print(f"  {mark} 资料 {item['profile']} 里已经装了 v{item['version']}"
                  f"（商店来源 {item['fromStore']}），设置 "
                  f"webrtc.ip_handling_policy={item['setting']}")
        need = [i for i in state["installed_in"] if i["setting"] != WEBRTC_LIMITER_SETTING]
        if not need:
            print("    这台机器不用再装；下面这一步只在别的机器或别的资料上才需要。")
    else:
        print(f"  本机现状：{len(state['profiles'])} 个资料里都没读到它")
    got = download_webrtc_limiter()
    if got["ok"]:
        print(f"  ✓ 扩展包已下到：{got['path']}")
        print(f"    版本 {got['version']}（manifest v{got['manifestVersion']}），"
              f"{got['bytes']} 字节，sha256 {got['sha256'][:16]}…")
        print(f"    直链（按本机 Chrome {got['chrome']} 拼的）：{got['url']}")
    else:
        print(f"  ✗ 没下下来：{got['why']}")
    opened = {"opened": False, "reason": "没有自动打开"}
    if open_store and not os.environ.get("CLAUDE_GUARD_NO_OPEN"):
        opened = open_verify_page(WEBRTC_LIMITER_STORE_URL, "扩展商店页")
    if not opened.get("opened"):
        print("  商店页没能自动打开，上面那条链接自己点开。")
    print("\n  还差你点两下（Chrome 不允许脚本替你装扩展）：")
    print("    1. 在商店页点「添加至 Chrome」，弹窗里点「添加扩展程序」")
    print(f"    2. 装完到 chrome://extensions/ 确认列表里有它，ID 是 {WEBRTC_LIMITER_ID}")
    print("  它没有选项页，装好即生效：写的是 webRTCIPHandlingPolicy="
          f"{WEBRTC_LIMITER_SETTING}（「只走代理的 UDP」）。")
    if got["ok"]:
        print(f"  装不上或没网时的后备：把 {got['path']} 拖到 chrome://extensions/，"
              "需要先打开右上角的开发者模式。")
    print("  想彻底免手工（要管理员，且浏览器从此显示「由组织管理」）：")
    print('    $ sudo defaults write "/Library/Managed Preferences/com.google.Chrome" \\')
    print(f'        ExtensionInstallForcelist -array "{WEBRTC_LIMITER_ID};{WEBRTC_CRX_ENDPOINT}"')
    return {"ok": got["ok"], "download": got, "opened": opened,
            "state": state, "store": WEBRTC_LIMITER_STORE_URL,
            # 读得到就说读到的，读不到就是 None —— 不把「读不到」说成「没装」。
            "installed": bool(state["installed_in"]) if state["readable"] else None}


def expected_state_path() -> pathlib.Path:
    """记住「用户声明的预期出口」的状态文件。按调用时解析，不在 import 时定死。"""
    return HOME / ".local" / "state" / "claude-guard" / "expected-exit.json"


def load_declared_expected() -> dict:
    try:
        data = json.loads(expected_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def remember_declared_expected(country: str | None, exit_ip: str | None) -> None:
    """把这次声明下来的目标记下来，供下次没有声明时使用。"""
    if not country and not exit_ip:
        return
    try:
        path = expected_state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"country": country, "exitIp": exit_ip,
                                    "declaredAt": now_stamp()},
                                   ensure_ascii=False, indent=2), encoding="utf-8")
        hand_back_ownership(path)
    except OSError:
        pass          # 记不住不影响这次判定，只是下次要重新声明


def declared_expected(country: str | None = None,
                      exit_ip: str | None = None) -> tuple[str | None, str | None]:
    """把「你自己声明的预期出口」收敛成一个入口：命令行优先，其次环境变量。

    为什么要认环境变量：预期出口是用户自己的声明，不是脚本推断出来的事实。
    但 selfcheck.py、报告服务、桌面启动器这些调用点走的是 audit()，拿不到命令行
    参数；只认命令行的话，同一次声明换个入口就没了，那一项会在「已解决」和
    「未测到」之间来回跳。所以命令行给不出时读环境变量。

    再往下还有第三级：**上次声明过的值**。声明的内容（我期望从哪个国家/哪个 IP
    出去）不会因为换了一天就失效，而每次都要重新声明就等于每次都可能忘了声明、
    那一项永远停在「未测到」。落盘只发生在允许写状态的调用里（见 audit 的 persist），
    只读审计仍然一个字都不写。
    """
    saved = load_declared_expected()
    picked = []
    for cli_value, env_name, normalize in (
        (country, EXPECTED_COUNTRY_ENV, normalize_expected_country),
        (exit_ip, EXPECTED_EXIT_IP_ENV, normalize_expected_ip),
    ):
        # 命令行里给了空串也算没给；环境变量里的空白（export X=" "）同样不算声明，
        # 否则它会一路走到校验那步，把一次体检整个判成失败。
        value = cli_value if (cli_value or "").strip() else os.environ.get(env_name)
        value = (value or "").strip() or None
        if value is None:
            picked.append(None)
            continue
        try:
            picked.append(normalize(value))
        except ValueError as error:
            # 命令行那侧由 argparse 自己校验；能走到这里的基本都是环境变量写错了，
            # 报错要指名是哪个变量，不然用户只看到「--expected-country 不合法」。
            raise ValueError(f"{env_name} 的值不合法：{error}") from error
    for i, (value, key) in enumerate(((picked[0], "country"), (picked[1], "exitIp"))):
        if value is None and saved.get(key):
            try:
                picked[i] = (normalize_expected_country(saved[key]) if key == "country"
                             else normalize_expected_ip(saved[key]))
            except ValueError:
                # 存下来的值不合法就当没有：状态文件坏掉不该让一次体检整个失败。
                picked[i] = None
    return (picked[0], picked[1])

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

# 地理词的匹配式：前后不许紧挨着斜杠或字母数字。
# 因为 `Asia/Shanghai`、`ZoneInfo('Asia/Shanghai')`、`ChinaMobile` 这类是技术写法，
# 字面含地名却跟「写自己人在哪」无关 —— 实测撞过一次：某个仓的 CLAUDE.md 里写着
# 「业务日按 Asia/Shanghai」，被报成「地理位置词 1 处，会随 prompt 送给模型」。
# 尾部的点不能排除（句号收尾的 China. 是真命中），所以只排除字母数字和下划线。
GEO_WORD_RE = re.compile(
    r"(?<![A-Za-z0-9_/])(?:" + "|".join(re.escape(w) for w in GEO_WORDS) + r")(?![A-Za-z0-9_])"
)

DEFAULT_CLASH_SOCK = pathlib.Path("/tmp/verge/verge-mihomo.sock")
# 兼容旧调用方与测试缝：它们会把 CLASH_SOCK 指到 /dev/null 或某个夹具 socket 上。
# 只要它不等于默认值，下面的探活就完全不介入（见 clash_socket）。
CLASH_SOCK = DEFAULT_CLASH_SOCK
# 控制接口的地址不是固定的，别写死：
#   非服务模式            /tmp/verge/verge-mihomo.sock
#   2.5 起的「服务模式」  /var/run/clash-verge-service/users/<uid>/verge-mihomo.sock
# 2026-10-13 实测踩到：Clash Verge 2.5.8 重装特权服务后内核改由服务托管，端点换成后者，
# 而 GUI 那份 config.yaml 里仍写着前者。写死旧路径的体检会报「控制接口不可达」——
# 读起来像网络坏了，实际只是端点搬了家。
CLASH_SOCK_CANDIDATES = (
    "/var/run/clash-verge-service/users/{uid}/verge-mihomo.sock",
    "/tmp/verge/verge-mihomo.sock",
)
# Mihomo Party 的 socket 名字里带着它自己的 pid（/tmp/mihomo-party-<uid>-<pid>.sock），
# 写不成固定路径，只能按 glob 找。写进上面那张表会在 format(uid=...) 时炸 KeyError ——
# 2026-10-15 真炸过，5 个用例一起报错。
CLASH_SOCK_GLOBS = ("/tmp/mihomo-party-*.sock",)
# 别家的 mihomo 发行版端口各不相同，写下来免得漏认：
#   ClashX / ClashX Pro   127.0.0.1:8080（可在菜单里改）
#   Stash                 127.0.0.1:9090（官方声明兼容 Clash 控制接口）
#   mihomo 原版默认        127.0.0.1:9090
MIHOMO_TCP_PORTS = (9090, 8080, 9097)
# FlClash 用的是自己的 JSON-RPC socket，不是 Clash API —— 端口在监听着，
# 但按 Clash API 去问会 404。认出来是为了说清「这家脚本只能读配置」。
FLCLASH_SOCK_GLOB = "/tmp/FlClashSocket_*.sock"
# Clash Verge 出厂就带这个 secret，没改过的话它适用于所有本机部署；
# 改过就用环境变量 CLASH_SECRET 覆盖，别把某个人的 secret 写进代码。
CLASH_SECRET = os.environ.get("CLASH_SECRET", "set-your-secret")

_CLASH_SOCK_CACHE: dict = {}


def clash_sock_paths() -> list:
    """按优先级列出候选端点。

    CLASH_SOCK 被显式改过时（测试夹具或调用方指定）只认它 —— 那是这套代码的测试缝，
    夹具服务收到几个请求是被断言过的，探活多打一次 /version 会让用例失败。
    """
    if CLASH_SOCK != DEFAULT_CLASH_SOCK:
        return [CLASH_SOCK]
    cands = []
    try:
        cfg = (clash_dir() / "config.yaml").read_text(encoding="utf-8")
    except OSError:
        cfg = ""
    for line in cfg.splitlines():
        if line.startswith("external-controller-unix:"):
            value = line.split(":", 1)[1].strip().strip("\"'")
            if value:
                cands.append(pathlib.Path(value))
    cands += [pathlib.Path(p.format(uid=os.getuid())) for p in CLASH_SOCK_CANDIDATES]
    for pattern in CLASH_SOCK_GLOBS:
        try:
            cands += sorted(pathlib.Path(pattern).parent.glob(pathlib.Path(pattern).name))
        except OSError:
            continue
    out = []
    for c in cands:
        if c not in out:
            out.append(c)
    return out


def _path_exists(p) -> bool:
    try:
        return bool(p.exists())
    except OSError:
        return False


def _probe_clash_socket(path) -> bool:
    """只读探活：连上问一句 /version。不经过 clash_http，避免递归。"""
    import http.client
    import socket as _socket
    sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect(str(path))
        sock.sendall(("GET /version HTTP/1.1\r\nHost: localhost\r\n"
                      f"Authorization: Bearer {CLASH_SECRET}\r\n"
                      "Connection: close\r\n\r\n").encode())
        response = http.client.HTTPResponse(sock)
        response.begin()
        ok = response.status == 200
        response.read()
        return ok
    except (OSError, ValueError, http.client.HTTPException):
        return False
    finally:
        sock.close()


def clash_socket():
    """返回该用的控制端点；一个都不存在时返回 None。

    默认路径下按候选逐个探活，挑第一个真能应答的；全都探不通时退回「第一个存在的端点」，
    让真实请求去定夺（探活本身失败不该把整项判成不可达）。被显式改过时直接用它，不探活。
    """
    paths = clash_sock_paths()
    key = tuple(str(p) for p in paths)
    if key in _CLASH_SOCK_CACHE:
        return _CLASH_SOCK_CACHE[key]
    if CLASH_SOCK != DEFAULT_CLASH_SOCK:
        chosen = CLASH_SOCK if _path_exists(CLASH_SOCK) else None
        _CLASH_SOCK_CACHE[key] = chosen
        return chosen
    existing = [p for p in paths if _path_exists(p)]
    chosen = None
    for p in existing:
        if _probe_clash_socket(p):
            chosen = p
            break
    if chosen is None and existing:
        chosen = existing[0]
    _CLASH_SOCK_CACHE[key] = chosen
    return chosen


def _new_loopback_server(handler):
    """Create a loopback HTTP server without a reverse DNS lookup.

    ``http.server.HTTPServer.server_bind`` calls ``socket.getfqdn`` after the
    socket is already bound.  On a CI runner with broken or slow reverse DNS,
    that can stall construction even though the loopback socket is ready.
    Keep the currently installed ``ThreadingHTTPServer`` so tests and callers
    can replace it, but use the lower-level bind implementation that does not
    perform the lookup.  Non-server fakes used by unit tests keep their old
    constructor contract.
    """
    import http.server

    base = http.server.ThreadingHTTPServer
    if not isinstance(base, type) or not issubclass(base, socketserver.TCPServer):
        return base(("127.0.0.1", 0), handler)

    class LoopbackServer(base):
        def server_bind(self):
            socketserver.TCPServer.server_bind(self)
            self.server_name = self.server_address[0]
            self.server_port = self.server_address[1]

    return LoopbackServer(("127.0.0.1", 0), handler)


def clash_http(method: str, path: str, body: bytes | None = None,
               timeout: float = 10.0) -> tuple[int, str]:
    """Talk to Clash over its Unix socket without putting the secret in argv.

    The old curl based implementation exposed ``Authorization`` in the process
    list.  This keeps the same HTTP API while keeping the header inside Python's
    memory and never including it in command output or exception text.
    """
    import http.client
    import socket
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("Clash API 路径必须以 / 开头")
    if any(ord(ch) < 0x20 for ch in CLASH_SECRET) or "\r" in CLASH_SECRET or "\n" in CLASH_SECRET:
        raise ValueError("Clash secret 含非法控制字符，拒绝发送")
    # 端点会搬家（服务模式在 /var/run，非服务模式在 /tmp），先挑一个能用的。
    target = clash_socket() or CLASH_SOCK
    # Unit tests use /dev/null as a socket sentinel and replace ``run`` with a
    # response fixture.  Keep that seam secret-free; real sockets always use
    # the stdlib path below.
    if target == pathlib.Path("/dev/null") or not target.is_socket():
        code, response = run(["__claude_guard_clash_fixture__", method.upper(), path], timeout=timeout)
        if method.upper() != "GET" and code == 0 and (response or "").strip().isdigit():
            return int(response.strip()), ""
        return code, response
    payload = body or b""
    request = (f"{method.upper()} {path} HTTP/1.1\r\n"
               "Host: localhost\r\n"
               f"Authorization: Bearer {CLASH_SECRET}\r\n"
               "Connection: close\r\n"
               f"Content-Length: {len(payload)}\r\n\r\n").encode() + payload
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(str(target))
        sock.sendall(request)
        try:
            response = http.client.HTTPResponse(sock)
            response.begin()
            status = response.status
            response_body = response.read()
        except (http.client.HTTPException, OSError) as error:
            raise RuntimeError("Clash HTTP 响应无效或不完整") from error
    finally:
        sock.close()
    return status, response_body.decode("utf-8", "replace")


def clash_dir() -> pathlib.Path:
    """Clash Verge 的配置目录。

    故意做成函数而不是模块级常量：测试会把 HOME 指到沙箱目录，而常量在 import 那一刻
    就定死了，改不动。测试里那条「备份不许跑出临时家目录」的断言正是这么抓到它的。
    """
    return HOME / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev"


def clash_config() -> pathlib.Path:
    """Clash Verge 生成的那份运行配置（订阅 + 增强文件合成后的产物）。"""
    return clash_dir() / "clash-verge.yaml"

# ───────────────────────── 代理后端识别 ─────────────────────────
# 2026-10-15 补。体检里原有 87 行是 Clash 专有的：26 项里「绝不直连」与「DNS 泄漏」
# 直接读 mihomo 的 socket 与 clash-verge.yaml。用别的代理软件的人打开报告只会看到
# 两行「未测到」，分不清是「脚本不认识你这家」还是「网络真有问题」。
#
# 这一层做三件事：认出跑的是哪一家 → 说清这家能查到什么、查不到什么 →
# 只对「改完能复验」的后端动手（不能复验的降级成报告 + 精确步骤）。
# 不认识的软件明说「脚本不认识它的配置格式」，不静默留白。

PROXY_BACKEND_LABELS = {
    "mihomo": "mihomo 内核（Clash Verge / ClashX / Mihomo Party / FlClash 等）",
    "singbox": "sing-box",
    "surge": "Surge",
    "v2ray": "v2ray / Xray",
    "system": "只有系统代理，没有规则引擎",
    "vpn": "VPN 隧道",
    "other": "认得出在跑，但脚本不认识它的配置格式",
    "none": "没有发现代理",
}

# 短名字：终端与报告页都从这里取，免得两处各写一份、日后改一处漏一处。
PROXY_BACKEND_SHORT = {
    "mihomo": "mihomo 内核",
    "singbox": "sing-box",
    "surge": "Surge",
    "v2ray": "v2ray / Xray",
    "system": "只有系统代理",
    "vpn": "VPN 隧道",
    "other": "认不出的后端",
    "none": "没有代理",
}

# 进程名（小写、取 basename 后子串匹配）。顺序即探测优先级。
PROXY_PROCESS_HINTS = (
    ("mihomo", ("verge-mihomo", "mihomo", "clash-meta", "clash-verge", "clashx", "clash", "flclash")),
    ("singbox", ("sing-box",)),
    ("surge", ("surge",)),
    ("v2ray", ("xray", "v2ray", "v2box")),
    ("other", ("shadowsocksx-ng", "shadowsocksx", "shadowsocks-libev", "outline",
               "stash", "loon", "quantumult", "trojan", "naive", "hysteria", "tun2socks")),
)

# 配置文件候选（相对家目录的写相对路径，绝对路径原样）。
# 放在这里是为了「这台机器上跑的是谁」有据可查——每条都要能在证据里说出来源。
MIHOMO_CONFIG_CANDIDATES = (
    "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml",
    ".config/clash/config.yaml",
    ".config/mihomo/config.yaml",
    ".config/clash.meta/config.yaml",
    "Library/Application Support/com.west2online.ClashX/config.yaml",
)
SINGBOX_CONFIG_CANDIDATES = (
    "Library/Application Support/sing-box/config.json",
    "Library/Application Support/io.nekohasekai.sfam/config.json",
    "/opt/homebrew/etc/sing-box/config.json",
    "/usr/local/etc/sing-box/config.json",
    ".config/sing-box/config.json",
)
SURGE_PROFILE_DIRS = ("Library/Application Support/Surge/Profiles",)
V2RAY_CONFIG_CANDIDATES = (
    "/opt/homebrew/etc/xray/config.json",
    "/usr/local/etc/xray/config.json",
    "/opt/homebrew/etc/v2ray/config.json",
    "/usr/local/etc/v2ray/config.json",
    ".config/xray/config.json",
    ".config/v2ray/config.json",
    "Library/Application Support/V2RayX/config.json",
)

# 控制接口的形态。secret 一律从本机配置里读，不从命令行传（命令行会进 ps）。
CONTROLLER_UNIX = "unix"
CONTROLLER_HTTP = "http"


def _resolve_candidate(path_text: str) -> pathlib.Path:
    """候选路径：以 / 开头当绝对路径，否则相对家目录。"""
    if str(path_text).startswith("/"):
        return pathlib.Path(path_text)
    return HOME / path_text


def _first_existing(paths) -> pathlib.Path | None:
    for p in paths:
        try:
            if pathlib.Path(p).is_file():
                return pathlib.Path(p)
        except OSError:
            continue
    return None


def _running_process_names() -> list:
    """当前在跑的进程名（小写 basename）。读不到就返回空表——
    「读不到进程表」和「没有进程」是两件事，调用方要看 proc_ok 区分。"""
    code, out = run(["ps", "-axo", "comm="], timeout=15)
    if code != 0:
        return []
    names = []
    for line in out.splitlines():
        name = line.strip()
        if not name:
            continue
        base = name.rsplit("/", 1)[-1].strip().lower()
        if base:
            names.append(base)
    return names


def _match_processes(procs, hints) -> list:
    hits = []
    for hint in hints:
        for name in procs:
            if hint in name and name not in hits:
                hits.append(name)
    return hits


def _read_text_limited(path, limit: int = 2_000_000) -> str:
    try:
        data = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return data[:limit]


def _controller_from_unix(path, secret: str) -> dict:
    return {"kind": CONTROLLER_UNIX, "path": str(path), "secret": secret or ""}


def _controller_from_http(host: str, port: int, secret: str, auth: str) -> dict:
    return {"kind": CONTROLLER_HTTP, "host": host or "127.0.0.1", "port": int(port),
            "secret": secret or "", "auth": auth}


def api_call(controller, method: str, path: str, body: bytes | None = None,
             timeout: float = 8.0) -> tuple:
    """对任意后端的控制接口发一次请求。

    两种形态：unix socket（mihomo 默认）与 http（ClashX 的 external-controller、
    sing-box 的 clash_api、Surge 的 http-api）。鉴权头按后端不同：
    mihomo 与 sing-box 用 Authorization: Bearer，Surge 用 X-Key。
    secret 只在内存里拼，不进 argv、不进日志。
    """
    if not controller:
        raise ValueError("没有可用的控制接口")
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("控制接口路径必须以 / 开头")
    secret = str(controller.get("secret") or "")
    if any(ord(ch) < 0x20 for ch in secret):
        raise ValueError("控制接口密钥含非法控制字符，拒绝发送")
    payload = body or b""
    if controller.get("kind") == CONTROLLER_UNIX:
        import http.client
        import socket
        target = pathlib.Path(str(controller.get("path") or ""))
        request = (f"{method.upper()} {path} HTTP/1.1\r\n"
                   "Host: localhost\r\n"
                   + (f"Authorization: Bearer {secret}\r\n" if secret else "")
                   + "Connection: close\r\n"
                   f"Content-Length: {len(payload)}\r\n\r\n").encode() + payload
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(str(target))
            sock.sendall(request)
            try:
                response = http.client.HTTPResponse(sock)
                response.begin()
                status = response.status
                response_body = response.read()
            except (http.client.HTTPException, OSError) as error:
                raise RuntimeError("控制接口响应无效或不完整") from error
        finally:
            sock.close()
        return status, response_body.decode("utf-8", "replace")
    import http.client
    conn = http.client.HTTPConnection(str(controller.get("host") or "127.0.0.1"),
                                      int(controller.get("port") or 0), timeout=timeout)
    try:
        headers = {}
        if secret:
            if controller.get("auth") == "x-key":
                headers["X-Key"] = secret
            else:
                headers["Authorization"] = "Bearer " + secret
        headers["Content-Length"] = str(len(payload))
        conn.request(method.upper(), path, body=payload, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", "replace")
    finally:
        conn.close()


def controller_reachable(controller) -> bool:
    """只读探活：问一句 /version。连不上就是连不上，不猜测。"""
    if not controller:
        return False
    for path in ("/version", "/configs"):
        try:
            code, body = api_call(controller, "GET", path, timeout=3)
        except (OSError, ValueError, TimeoutError, RuntimeError):
            continue
        if code and 200 <= code < 300:
            return True
    return False


def _capabilities(backend: str, controller_ok: bool, has_config: bool) -> dict:
    """这家后端脚本能做什么。

    verify_after_write 是这里唯一重要的字段：写操作只有它成立才允许自动执行。
    改完读不回来，就等于「改了什么不知道、改坏了也不知道」。
    """
    caps = {
        "read_dns": False, "read_routing": False, "pin_node": False,
        "fix_dns": False, "verify_after_write": False, "fix_mode": "report",
    }
    if backend == "mihomo":
        caps.update(read_dns=has_config, fix_dns=has_config, read_routing=controller_ok,
                    pin_node=controller_ok, verify_after_write=has_config,
                    fix_mode="auto")
    elif backend == "singbox":
        # 配置是 JSON，能读能写能复读；但改完要不要重启才生效不由我们决定，
        # 所以 pin_node 走 clash_api（可复验），改 DNS 走文件（要用户重启）。
        caps.update(read_dns=has_config, read_routing=controller_ok, pin_node=controller_ok,
                    fix_dns=has_config, verify_after_write=False, fix_mode="file")
    elif backend == "surge":
        # Surge 的配置归 App 管，改文件要它在 UI 里重载；能复验的是策略组切换。
        caps.update(read_dns=has_config, read_routing=controller_ok, pin_node=controller_ok,
                    fix_dns=False, verify_after_write=False, fix_mode="report")
    elif backend == "v2ray":
        # 没有控制接口时只能静态读配置；改文件要重启进程才生效。
        caps.update(read_dns=has_config, read_routing=has_config,
                    fix_dns=has_config, verify_after_write=False, fix_mode="file")
    return caps


def _proxy_backend_report() -> dict:
    """识别一次、判读一次。体检与两行判定共用这一份结果，避免两处各说各话。"""
    info = check_proxy_backend()
    info["facts"] = proxy_facts_for(info)
    info["capture"] = check_traffic_capture()
    return info


def check_proxy_backend() -> dict:
    """认出这台机器上的代理后端，并说清脚本对它了解到什么程度。

    探测顺序是有讲究的：先看能不能真连上控制接口（那是运行时事实），再看进程，
    最后才看磁盘上的配置文件。只看到配置文件就说「你在用 X」是不准的——卸载了
    但配置还在的机器到处都是。
    """
    out = {
        "backend": "none", "label": PROXY_BACKEND_LABELS["none"], "evidence": [],
        "controller": None, "controller_ok": False, "config": {}, "capabilities": {},
        "other_backends": [], "notes": [], "proc_ok": True,
    }
    procs = _running_process_names()
    if not procs:
        out["proc_ok"] = False
    matched = {}
    for backend, hints in PROXY_PROCESS_HINTS:
        hits = _match_processes(procs, hints)
        if hits:
            matched[backend] = hits

    # 1) mihomo：先试控制接口（包括服务模式搬走的那个 socket）
    sock = clash_socket()
    if sock is not None and _path_exists(sock) and _probe_clash_socket(sock):
        cfg = _first_existing([_resolve_candidate(p) for p in MIHOMO_CONFIG_CANDIDATES])
        out.update(backend="mihomo", label=PROXY_BACKEND_LABELS["mihomo"], controller_ok=True)
        out["controller"] = _controller_from_unix(sock, CLASH_SECRET)
        out["evidence"].append({"kind": "socket", "value": str(sock)})
        out["config"] = {"path": str(cfg) if cfg else "", "format": "yaml"} if cfg else {}
    elif "mihomo" in matched:
        cfg = _first_existing([_resolve_candidate(p) for p in MIHOMO_CONFIG_CANDIDATES])
        # ClashX 这类用 TCP 的 external-controller；从配置里读地址与 secret。
        ctrl = _mihomo_tcp_controller(cfg)
        out.update(backend="mihomo", label=PROXY_BACKEND_LABELS["mihomo"])
        out["evidence"].append({"kind": "process", "value": "、".join(matched["mihomo"])})
        if ctrl:
            out["controller"] = ctrl
            out["controller_ok"] = controller_reachable(ctrl)
            if out["controller_ok"]:
                out["evidence"].append({"kind": "controller", "value": f"{ctrl['host']}:{ctrl['port']}"})
        out["config"] = {"path": str(cfg) if cfg else "", "format": "yaml"} if cfg else {}

    # 2) sing-box
    elif "singbox" in matched or _first_existing([_resolve_candidate(p) for p in SINGBOX_CONFIG_CANDIDATES]):
        cfg = _first_existing([_resolve_candidate(p) for p in SINGBOX_CONFIG_CANDIDATES])
        out.update(backend="singbox", label=PROXY_BACKEND_LABELS["singbox"])
        if matched.get("singbox"):
            out["evidence"].append({"kind": "process", "value": "、".join(matched["singbox"])})
        ctrl = _singbox_controller(cfg)
        if ctrl:
            out["controller"] = ctrl
            out["controller_ok"] = controller_reachable(ctrl)
            if out["controller_ok"]:
                out["evidence"].append({"kind": "controller", "value": f"{ctrl['host']}:{ctrl['port']}"})
        out["config"] = {"path": str(cfg) if cfg else "", "format": "json"} if cfg else {}

    # 3) Surge
    elif "surge" in matched or _surge_profiles():
        out.update(backend="surge", label=PROXY_BACKEND_LABELS["surge"])
        if matched.get("surge"):
            out["evidence"].append({"kind": "process", "value": "、".join(matched["surge"])})
        profile = _surge_active_profile()
        ctrl = _surge_controller(profile)
        if ctrl:
            out["controller"] = ctrl
            out["controller_ok"] = controller_reachable(ctrl)
            if out["controller_ok"]:
                out["evidence"].append({"kind": "controller", "value": f"{ctrl['host']}:{ctrl['port']}"})
        out["config"] = {"path": str(profile) if profile else "", "format": "conf"} if profile else {}

    # 4) v2ray / xray
    elif "v2ray" in matched or _first_existing([_resolve_candidate(p) for p in V2RAY_CONFIG_CANDIDATES]):
        cfg = _first_existing([_resolve_candidate(p) for p in V2RAY_CONFIG_CANDIDATES])
        out.update(backend="v2ray", label=PROXY_BACKEND_LABELS["v2ray"])
        if matched.get("v2ray"):
            out["evidence"].append({"kind": "process", "value": "、".join(matched["v2ray"])})
        out["config"] = {"path": str(cfg) if cfg else "", "format": "json"} if cfg else {}

    # 5) 认得出在跑、但脚本不认识它的配置格式
    elif "other" in matched:
        out.update(backend="other", label=PROXY_BACKEND_LABELS["other"])
        out["evidence"].append({"kind": "process", "value": "、".join(matched["other"])})

    # 6) 没有代理进程：看是不是只有系统代理，或者挂着 VPN 隧道
    else:
        enabled = system_proxy_enabled()
        if enabled:
            out.update(backend="system", label=PROXY_BACKEND_LABELS["system"])
            out["evidence"].append({"kind": "system-proxy", "value": "、".join(enabled)})
        else:
            vpn = vpn_tunnels()
            if vpn:
                out.update(backend="vpn", label=PROXY_BACKEND_LABELS["vpn"])
                out["evidence"].append({"kind": "tunnel", "value": "、".join(vpn)})

    out["short"] = PROXY_BACKEND_SHORT.get(out["backend"], out["backend"])
    out["other_backends"] = sorted(b for b in matched if b != out["backend"])
    out["capabilities"] = _capabilities(
        out["backend"], out["controller_ok"], bool(out["config"].get("path")))
    out["notes"] = _backend_notes(out)
    return out


def _route_interface(ip: str = "1.1.1.1") -> str:
    """去这个地址走哪个网卡。这是判断「流量有没有被接管」最硬的一条信号——
    scutil --proxy 四个开关全 0 的时候，流量照样可能被 utun 接管。"""
    code, out = run(["route", "-n", "get", ip], timeout=10)
    if code != 0:
        return ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            return line.split(":", 1)[1].strip()
    return ""


def _utun_ipv4() -> list:
    """带 inet4 的 utun 接口。系统自带的 utun 只有链路本地 v6，代理的才有 v4 —— 
    这是区分「系统的」和「代理的」唯一可靠办法（flags 和 status 都判不出来）。"""
    code, out = run(["ifconfig"], timeout=10)
    if code != 0:
        return []
    found = []
    current = ""
    for line in out.splitlines():
        if line and not line[0].isspace():
            current = line.split(":", 1)[0].strip()
            continue
        s = line.strip()
        if s.startswith("inet ") and current.startswith("utun"):
            found.append({"name": current, "addr": s.split()[1]})
    return found


def _tunnel_routes() -> list:
    """路由表里指向 utun 的条目。代理插的是一串覆盖全网的具体路由
    （1、2/7、4/6……128.0/1），不是改 default。"""
    code, out = run(["netstat", "-rn", "-f", "inet"], timeout=15)
    if code != 0:
        return []
    entries = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        if parts[-1].startswith("utun") or (len(parts) >= 4 and parts[3].startswith("utun")):
            entries.append({"dest": parts[0], "iface": parts[3] if len(parts) > 3 else ""})
    return entries


def _local_listen_ports() -> list:
    """本机在监听的回环端口（只用当前用户能看到的）。"""
    code, out = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=25)
    if code != 0 or not out.strip():
        return []
    ports = []
    for line in out.splitlines()[1:]:
        m = re.search(r"(?:127\.0\.0\.1|\*|\[::1\]):(\d+)\s*\(LISTEN\)", line)
        if m:
            port = int(m.group(1))
            if port not in ports:
                ports.append(port)
    return ports


def socks5_alive(port: int, timeout: float = 2.0) -> bool:
    """端口开着不等于它是代理：本机实测过一对反例（60114 收 SOCKS 握手回 400）。

    只发最小握手（VER=5, NMETHODS=1, NOAUTH），看回来的第一字节是不是 0x05。
    """
    import socket
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout) as sock:
            sock.sendall(b"\x05\x01\x00")
            data = sock.recv(2)
    except OSError:
        return False
    return len(data) == 2 and data[0] == 0x05


def check_traffic_capture() -> dict:
    """流量到底有没有被接管。对任何后端都成立——这也正是「不认识的后端」唯一
    还能说点实话的地方：认不出它的配置，但能看出流量有没有进隧道。"""
    out = {"route_iface": "", "tun_ipv4": [], "tunnel_routes": [], "listen_ports": [],
           "socks_ports": [], "captured": False, "notes": []}
    iface = _route_interface()
    out["route_iface"] = iface
    out["tun_ipv4"] = _utun_ipv4()
    out["tunnel_routes"] = _tunnel_routes()
    tun_names = {u["name"] for u in out["tun_ipv4"]}
    if iface.startswith("utun") and iface in tun_names:
        addr = next((u["addr"] for u in out["tun_ipv4"] if u["name"] == iface), "")
        out["captured"] = True
        out["notes"].append(f"去 1.1.1.1 走 {iface}（{addr}），流量确实进了隧道")
    elif iface.startswith("utun"):
        out["notes"].append(f"去 1.1.1.1 走 {iface}，但这个接口没有 IPv4 地址，"
                            "看着像系统自带的隧道而不是代理")
    elif iface:
        out["notes"].append(f"去 1.1.1.1 走 {iface}，没有进隧道")
    if out["tunnel_routes"]:
        dests = [e["dest"] for e in out["tunnel_routes"]]
        out["notes"].append(f"路由表里有 {len(dests)} 条指向隧道的具体路由（{dests[:3]}…）")
    ports = _local_listen_ports()
    out["listen_ports"] = ports
    # 只探那些「像代理」的端口，避免把每个监听端口都摸一遍
    candidates = [p for p in ports if p in (1080, 1081, 1086, 7890, 7891, 7897, 8889, 10808, 20171)]
    for port in candidates[:8]:
        if socks5_alive(port):
            out["socks_ports"].append(port)
    if out["socks_ports"]:
        out["notes"].append("本机有活着的 SOCKS5 端口：" + "、".join(str(x) for x in out["socks_ports"]))
    if not out["captured"] and out["socks_ports"]:
        out["notes"].append("没有走隧道，但有一个真能握手的本地代理端口——"
                            "这种部署靠应用自己设代理，规则与 DNS 都不一定跟着走")
    return out


def _backend_notes(info: dict) -> list:
    """给这一家人话，说清脚本对它了解到哪儿、哪儿是边界。"""
    backend = info["backend"]
    notes = []
    if backend == "mihomo":
        notes.append("Clash API " + ("可用" if info["controller_ok"] else "连不上，分流这一项只能看配置文件"))
    elif backend == "singbox":
        if info["controller_ok"]:
            notes.append("clash_api 可用，能读分组、能切节点")
        elif info["controller"]:
            notes.append("配置里写了 clash_api，但连不上（服务可能没在跑）")
        else:
            notes.append("没有开 clash_api —— 分流与 DNS 只能静态读配置文件，看到的是配置而不是运行时")
    elif backend == "surge":
        notes.append("HTTP API " + ("可用" if info["controller_ok"] else "连不上或没开 http-api"))
    elif backend == "v2ray":
        notes.append("默认没有运行时接口，只能静态读 config.json")
    elif backend == "system":
        notes.append("系统代理没有分流概念：所有流量一个出口，也就没有「规则写错漏出去」这回事")
    elif backend == "vpn":
        notes.append("隧道类工具不做域名分流；DNS 由隧道推送还是本机决定，要单独看")
    elif backend == "other":
        names = "、".join(e["value"] for e in info["evidence"] if e["kind"] == "process")
        notes.append(f"在跑的是 {names}，脚本不认识它的配置格式，不能替你判断分流与 DNS")
    return notes


def _process_command_lines() -> list:
    """完整命令行。用来核对「正在跑的那个进程，用的是不是我们读的那份配置」——
    静态读配置最大的疑点就在这儿，能对上才敢据此报绿。"""
    code, out = run(["ps", "-axo", "command="], timeout=15)
    if code != 0:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def running_config_for(backend: str) -> str:
    """从进程命令行里找 -c / --config / -f 指定的配置文件。找不到返回空串。"""
    flags = {
        "singbox": ("-c", "--config", "-D", "--directory"),
        "v2ray": ("-config", "--config", "-c"),
        "mihomo": ("-f", "--config"),
    }.get(backend, ())
    if not flags:
        return ""
    for line in _process_command_lines():
        parts = line.split()
        if not parts:
            continue
        exe = parts[0].rsplit("/", 1)[-1].lower()
        hint = {"singbox": "sing-box", "v2ray": ("xray", "v2ray"), "mihomo": ("mihomo", "clash")}[backend]
        names = (hint,) if isinstance(hint, str) else hint
        if not any(n in exe for n in names):
            continue
        for i, token in enumerate(parts[:-1]):
            if token in flags:
                return parts[i + 1]
        for token in parts[1:]:
            for flag in flags:
                if token.startswith(flag + "="):
                    return token.split("=", 1)[1]
    return ""


def proxy_facts_for(info: dict) -> dict:
    """按后端把配置读成同一套事实。mihomo 走原有的两条独立路径，这里返回空。"""
    backend = info.get("backend")
    cfg_path = (info.get("config") or {}).get("path") or ""
    if backend == "singbox":
        facts = read_singbox_facts(_singbox_config(cfg_path))
    elif backend == "surge":
        facts = read_surge_facts(_read_text_limited(cfg_path) if cfg_path else "")
    elif backend == "v2ray":
        text = _read_text_limited(cfg_path) if cfg_path else ""
        cfg = {}
        if text.strip():
            try:
                loaded = json.loads(text)
                cfg = loaded if isinstance(loaded, dict) else {}
            except json.JSONDecodeError:
                cfg = {}
        facts = read_v2ray_facts(cfg)
    else:
        return {}
    judged = judge_proxy_facts(info, facts)
    declared = running_config_for(backend)
    same = False
    if declared and cfg_path:
        try:
            same = pathlib.Path(declared).resolve() == pathlib.Path(cfg_path).resolve()
        except OSError:
            same = False
    judged["config_is_running"] = same
    judged["declared_config"] = declared
    judged["runtime_verified"] = bool(info.get("controller_ok")) or same
    if not judged["runtime_verified"]:
        judged["verify_hint"] = (
            "正在跑的进程命令行里没写配置文件路径，读到的只是磁盘上这份配置，"
            "不能据此报绿；给它开 clash_api（能读运行时），或让进程用 -c 指定配置路径"
        ) if backend in ("singbox", "v2ray") else "没有运行时证据，不能据此报绿"
    return judged


def system_proxy_enabled() -> list:
    """系统代理是否启用（四个开关）。只报开着的项。"""
    code, out = run(["scutil", "--proxy"], timeout=15)
    if code != 0:
        return []
    enabled = []
    labels = {
        "HTTPEnable": "HTTP", "HTTPSEnable": "HTTPS",
        "SOCKSEnable": "SOCKS", "ProxyAutoConfigEnable": "PAC",
    }
    for line in out.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key in labels and value.strip() == "1":
            enabled.append(labels[key])
    return enabled


def vpn_tunnels() -> list:
    """在用的 VPN 隧道名（scutil --nc list 里状态为 Connected 的）。"""
    code, out = run(["scutil", "--nc", "list"], timeout=15)
    if code != 0:
        return []
    names = []
    for line in out.splitlines():
        if "Connected" not in line:
            continue
        if '"' in line:
            name = line.split('"')[1]
            if name and name not in names:
                names.append(name)
    return names


def _mihomo_tcp_controller(cfg_path) -> dict | None:
    """ClashX 这类走 TCP 的 external-controller。地址与 secret 都是配置里的字段。"""
    text = _read_text_limited(cfg_path) if cfg_path else ""
    host, port, secret = "", 0, ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("external-controller:"):
            value = line.split(":", 1)[1].strip().strip("\"'")
            # 允许 ":9090" 这种只写端口的写法
            if value.startswith(":"):
                host, port = "127.0.0.1", _int_or_zero(value[1:])
            elif ":" in value:
                h, _, ps = value.rpartition(":")
                host, port = (h or "127.0.0.1"), _int_or_zero(ps)
        elif line.startswith("secret:"):
            secret = line.split(":", 1)[1].strip().strip("\"'")
    if not port:
        return None
    return _controller_from_http(host, port, secret, "bearer")


def _int_or_zero(text) -> int:
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return 0


def _singbox_config(cfg_path) -> dict:
    """读 sing-box 的 config.json。读不动就返回空 dict，由调用方报「未检测」。"""
    text = _read_text_limited(cfg_path) if cfg_path else ""
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _singbox_controller(cfg_path) -> dict | None:
    """sing-box 的 clash_api：experimental.clash_api.external_controller。"""
    data = _singbox_config(cfg_path)
    api = ((data.get("experimental") or {}).get("clash_api") or {})
    if not api:
        return None
    addr = str(api.get("external_controller") or "").strip()
    if not addr:
        # 官方文档原话：external_controller 为空时 Clash API 是关闭的。
        # 这里绝不能「默认 9090」——那会去连一个根本没开的端口，再把连不上
        # 说成「服务没在跑」，两种情况完全不是一回事。
        return None
    host, port = "127.0.0.1", 9090
    if addr.startswith(":"):
        port = _int_or_zero(addr[1:]) or 9090
    elif ":" in addr:
        h, _, ps = addr.rpartition(":")
        host, port = (h or "127.0.0.1"), (_int_or_zero(ps) or 9090)
    return _controller_from_http(host, port, str(api.get("secret") or ""), "bearer")


def _surge_profiles() -> list:
    out = []
    for rel in SURGE_PROFILE_DIRS:
        d = _resolve_candidate(rel)
        try:
            if d.is_dir():
                out += sorted(x for x in d.iterdir() if x.suffix == ".conf")
        except OSError:
            continue
    return out


def _surge_active_profile():
    """Surge 当前用的那份 profile。

    优先读 App 自己记的名字（Preferences 里的 plist），读不到就退回最近修改的那份，
    并在证据里写明是「按修改时间推定的」——推定的东西不能当事实说。
    """
    profiles = _surge_profiles()
    if not profiles:
        return None
    try:
        import plistlib
        plist = HOME / "Library/Preferences/com.nssurge.surge-mac.plist"
        if plist.is_file():
            data = plistlib.loads(plist.read_bytes())
            for key in ("currentProfile", "CurrentProfile", "activeProfile"):
                name = str(data.get(key) or "")
                if name:
                    for prof in profiles:
                        if prof.stem == name or prof.name == name:
                            return prof
    except Exception:
        pass
    try:
        return max(profiles, key=lambda x: x.stat().st_mtime)
    except OSError:
        return profiles[0]


def _surge_controller(profile) -> dict | None:
    """Surge 的 HTTP API：配置里有 `http-api = <key>@<host>:<port>` 才开。"""
    text = _read_text_limited(profile) if profile else ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip().lower() != "http-api":
            continue
        value = value.strip().strip("\"'")
        secret, _, addr = value.rpartition("@")
        if not addr:
            secret, addr = "", value
        host, port = "127.0.0.1", 6171
        if addr.startswith(":"):
            port = _int_or_zero(addr[1:]) or 6171
        elif ":" in addr:
            h, _, ps = addr.rpartition(":")
            host, port = (h or "127.0.0.1"), (_int_or_zero(ps) or 6171)
        if host in ("0.0.0.0", "::"):
            host = "127.0.0.1"
        return _controller_from_http(host, port, secret, "x-key")
    return None


# ─────────── 各家的 DNS 与分流：读成同一套事实 ───────────
# 判据不按软件各写一套，先归一成同样的几件事，最后由一个函数统一措辞。
# 归一后要能回答四问：
#   1) 谁在替这台机器解析国外域名？（CN_RESOLVER_MARKERS 认得出国内厂商就算）
#   2) 解析请求本身走哪条路出去？（Clash 是 respect-rules，sing-box 是每个 server 的 detour）
#   3) Claude 那几个域名最后落到哪个出口？那个出口会不会自己换节点？
#   4) 兜底那一条是不是直连？

def _resolver_address(entry) -> str:
    """解析器条目取地址。sing-box 新格式是对象，老格式是字符串。"""
    if isinstance(entry, dict):
        for key in ("server", "address", "addr"):
            if entry.get(key):
                return str(entry[key])
        return ""
    return str(entry or "")


def _resolver_detour(entry) -> str:
    """解析请求自己走哪个出站。空字符串表示没写（＝按规则走，可能是直发）。"""
    if isinstance(entry, dict):
        return str(entry.get("detour") or "")
    return ""


def read_singbox_facts(cfg: dict) -> dict:
    """从 sing-box 配置里读出 DNS 与分流事实。静态读，不代表运行时状态。"""
    facts = {
        "found": bool(cfg), "dns_servers": [], "dns_cn": [], "dns_no_detour": [],
        "dns_rules": [], "final": "", "outbounds": [], "rule_outbounds": {},
        "claude_rules": [], "tun": False, "auto_switch": [], "direct_tags": [],
    }
    if not cfg:
        return facts
    dns = cfg.get("dns") or {}
    for entry in (dns.get("servers") or []):
        addr = _resolver_address(entry)
        if not addr:
            continue
        facts["dns_servers"].append(addr)
        if _resolver_is_cn(addr):
            facts["dns_cn"].append(addr)
            if not _resolver_detour(entry):
                facts["dns_no_detour"].append(addr)
    facts["dns_rules"] = dns.get("rules") or []
    route = cfg.get("route") or {}
    facts["final"] = str(route.get("final") or "")
    for ob in (cfg.get("outbounds") or []):
        if not isinstance(ob, dict):
            continue
        tag = str(ob.get("tag") or "")
        otype = str(ob.get("type") or "")
        members = ob.get("outbounds") or []
        facts["outbounds"].append({"tag": tag, "type": otype, "members": len(members)})
        if otype in ("urltest", "url_test"):
            facts["auto_switch"].append(tag)
        if otype in ("direct", "block"):
            facts["direct_tags"].append(tag)
    for rule in (route.get("rules") or []):
        if not isinstance(rule, dict):
            continue
        out_tag = str(rule.get("outbound") or rule.get("action") or "")
        for field in ("domain_suffix", "domain", "domain_keyword", "domain_regex"):
            for value in (rule.get(field) or []):
                facts["rule_outbounds"].setdefault(str(value).lower(), out_tag)
    for hint in CLAUDE_DOMAIN_HINTS:
        if hint in facts["rule_outbounds"]:
            tag = facts["rule_outbounds"][hint]
            # policy 是各家统一的键名（Surge/v2ray 读取器也用这个）；sing-box 里
            # 对应的是规则的 outbound。两个键都留着，免得下游按名字取错。
            facts["claude_rules"].append({"match": hint, "outbound": tag, "policy": tag})
    for ib in (cfg.get("inbounds") or []):
        if isinstance(ib, dict) and str(ib.get("type")) == "tun":
            facts["tun"] = True
    return facts


def read_surge_facts(text: str) -> dict:
    """从 Surge 的 .conf 里读出 DNS 与分流事实。

    Surge 的配置是分节文本：`[General]` 里 dns-server、`[Proxy Group]` 是策略组、
    `[Rule]` 是按顺序匹配的规则、`FINAL` 是兜底。这里只读，不改。
    """
    facts = {"found": bool(text), "dns_servers": [], "dns_cn": [], "groups": [],
             "claude_rules": [], "final": "", "auto_switch": [], "direct_policies": []}
    if not text:
        return facts
    section = ""
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("//"):
            continue
        if s.startswith("[") and s.endswith("]"):
            section = s.strip("[]").strip().lower()
            continue
        if section.startswith("general"):
            key, _, value = s.partition("=")
            if key.strip().lower() in ("dns-server", "encrypted-dns-server"):
                if key.strip().lower() == "encrypted-dns-server":
                    continue
                for item in value.split(","):
                    addr = item.strip()
                    if addr:
                        facts["dns_servers"].append(addr)
        elif section.startswith("proxy group") or section.startswith("policy group"):
            name, _, rest = s.partition("=")
            parts = [x.strip() for x in rest.split(",") if x.strip()]
            gtype = parts[0].lower() if parts else ""
            facts["groups"].append({"name": name.strip(), "type": gtype, "members": parts[1:]})
            if gtype in AUTO_SWITCH_TYPES:
                facts["auto_switch"].append(name.strip())
        elif section.startswith("rule"):
            parts = [x.strip() for x in s.split(",") if x.strip()]
            if not parts:
                continue
            if parts[0].upper() == "FINAL":
                facts["final"] = parts[1] if len(parts) > 1 else ""
                continue
            tail = [x for x in parts[2:] if x.lower() not in ("no-resolve", "force-remote-dns",
                                                              "extended-matching", "dns-failed")]
            policy = tail[0] if tail else ""
            facts["claude_rules"].append({"type": parts[0], "payload": parts[1] if len(parts) > 1 else "",
                                          "policy": policy})
    facts["dns_cn"] = [x for x in facts["dns_servers"] if _resolver_is_cn(x)]
    for g in facts["groups"]:
        if g["type"] in ("direct", "reject"):
            facts["direct_policies"].append(g["name"])
    return facts


def read_v2ray_facts(cfg: dict) -> dict:
    """从 v2ray / Xray 的 config.json 里读出 DNS 与路由事实。

    没有控制接口时这是唯一能读的东西：读到的是配置，不是运行时。
    路由是顺序匹配、命中即停；一条都没命中时走 outbounds 的第一个。
    """
    facts = {"found": bool(cfg), "dns_servers": [], "dns_cn": [], "rules": [],
             "outbounds": [], "claude_rules": [], "final": "", "auto_switch": [],
             "direct_tags": []}
    if not cfg:
        return facts
    dns = cfg.get("dns") or {}
    for entry in (dns.get("servers") or []):
        addr = _resolver_address(entry)
        if addr:
            facts["dns_servers"].append(addr)
    facts["dns_cn"] = [x for x in facts["dns_servers"] if _resolver_is_cn(x)]
    for ob in (cfg.get("outbounds") or []):
        if not isinstance(ob, dict):
            continue
        tag = str(ob.get("tag") or "")
        proto = str(ob.get("protocol") or "")
        facts["outbounds"].append({"tag": tag, "type": proto, "members": 0})
        if proto.lower() in ("freedom", "blackhole"):
            facts["direct_tags"].append(tag)
    for bal in ((cfg.get("routing") or {}).get("balancers") or []):
        if isinstance(bal, dict) and bal.get("tag"):
            facts["auto_switch"].append(str(bal["tag"]))
    for rule in ((cfg.get("routing") or {}).get("rules") or []):
        if not isinstance(rule, dict):
            continue
        out_tag = str(rule.get("outboundTag") or "")
        for field in ("domain", "ip"):
            for value in (rule.get(field) or []):
                entry = {"type": field, "payload": str(value), "policy": out_tag}
                facts["rules"].append(entry)
                low = str(value).lower().lstrip("full:").lstrip("domain:")
                for hint in CLAUDE_DOMAIN_HINTS:
                    if hint in low:
                        facts["claude_rules"].append({"type": field, "payload": str(value),
                                                      "policy": out_tag})
    if facts["outbounds"]:
        facts["final"] = facts["outbounds"][0]["tag"]
    return facts


def _kind_of(facts: dict, tag: str) -> dict:
    """某个出站/策略是什么性质：直连、会自动换、还是钉死/可选。"""
    if not tag:
        return {"tag": "", "kind": "unknown", "detail": "没有取到出口名"}
    upper = str(tag).upper()
    if upper in ("DIRECT", "REJECT"):
        return {"tag": tag, "kind": "direct", "members": 0}
    for ob in (facts.get("outbounds") or []):
        if ob.get("tag") == tag:
            otype = str(ob.get("type") or "").lower()
            members = int(ob.get("members") or 0)
            if otype in [t.lower() for t in AUTO_SWITCH_TYPES]:
                return {"tag": tag, "kind": "auto", "members": members, "type": otype}
            if otype in [t.lower() for t in DIRECT_TYPES]:
                return {"tag": tag, "kind": "direct", "members": members, "type": otype}
            if otype in ("selector", "select"):
                return {"tag": tag, "kind": "selector", "members": members, "type": otype}
            return {"tag": tag, "kind": "node", "members": members, "type": otype}
    for g in (facts.get("groups") or []):
        if g.get("name") == tag:
            gtype = str(g.get("type") or "").lower()
            members = len(g.get("members") or [])
            if gtype in AUTO_SWITCH_TYPES:
                return {"tag": tag, "kind": "auto", "members": members, "type": gtype}
            if gtype in ("direct", "reject"):
                return {"tag": tag, "kind": "direct", "members": members, "type": gtype}
            if gtype == "select":
                return {"tag": tag, "kind": "selector", "members": members, "type": gtype}
            return {"tag": tag, "kind": "node", "members": members, "type": gtype}
    return {"tag": tag, "kind": "unknown", "members": 0,
            "detail": f"配置里找不到名为 {tag} 的出站或策略组，只能确认名字"}


def judge_proxy_facts(info: dict, facts: dict) -> dict:
    """把某家后端的事实判成「DNS 有没有问题、Claude 会不会直连或自动换」。

    只在机制清楚的地方下结论：
      * 「会自己换节点」看的是组类型（urltest/fallback/load-balance 是自动，select 不是），
        这条对谁家都成立；
      * 「解析请求直发」只有 mihomo 的 respect-rules 与 sing-box 的 detour 有明确语义，
        Surge / v2ray 的解析路径读不到运行时证据，就只报事实、不判泄漏。
    """
    out = {
        "backend": info.get("backend"), "config": (info.get("config") or {}).get("path", ""),
        "dns": {"evaluated": False, "servers": [], "cn": [], "unrouted_cn": [],
                "reasons": [], "limits": [], "fixable": False},
        "routing": {"evaluated": False, "claude_outbound": "", "kind": "", "auto_switch": [],
                    "direct": False, "auto_for_claude": False, "reasons": [], "limits": []},
    }
    if not facts.get("found"):
        out["dns"]["limits"].append("读不到这个后端的配置文件，DNS 与分流都没法判")
        out["routing"]["limits"].append("读不到这个后端的配置文件，分流没法判")
        return out
    out["dns"]["evaluated"] = True
    out["routing"]["evaluated"] = True
    out["dns"]["servers"] = list(facts.get("dns_servers") or [])
    out["dns"]["cn"] = list(facts.get("dns_cn") or [])
    out["dns"]["fixable"] = bool(out["dns"]["cn"])
    backend = info.get("backend")
    if out["dns"]["cn"]:
        if backend == "singbox":
            unrouted = [x for x in (facts.get("dns_no_detour") or [])]
            out["dns"]["unrouted_cn"] = unrouted
            if unrouted:
                out["dns"]["reasons"].append(
                    "国内解析器（" + "、".join(unrouted[:2]) + "）没有配 detour，"
                    "解析请求按规则直发，不经过代理")
            else:
                out["dns"]["reasons"].append(
                    "配置里有国内解析器（" + "、".join(out["dns"]["cn"][:2])
                    + "），但它们都指定了 detour；是否真走代理要看那个出站")
        elif backend in ("surge", "v2ray"):
            out["dns"]["reasons"].append(
                "国外域名会交给国内解析器（" + "、".join(out["dns"]["cn"][:2]) + "）")
            out["dns"]["limits"].append(
                "这个后端的解析请求走哪条线路，脚本读不到运行时证据；"
                "要确认得看 browserleaks.com/dns")
    else:
        out["dns"]["reasons"].append("解析器里没有国内服务器")
    if backend == "mihomo":
        out["dns"]["limits"].append("mihomo 的判据在 DNS 那一行里单独报（respect-rules、dns-hijack）")

    # ── 分流 ──
    eff = ""
    if facts.get("claude_rules"):
        eff = str(facts["claude_rules"][-1].get("policy") or "")
        out["routing"]["claude_outbound"] = eff
        out["routing"]["matched"] = str(facts["claude_rules"][-1].get("payload") or "")
    else:
        eff = str(facts.get("final") or "")
        out["routing"]["claude_outbound"] = eff
        out["routing"]["matched"] = ""
    kind = _kind_of(facts, eff)
    out["routing"]["kind"] = kind.get("kind")
    if kind["kind"] == "direct":
        out["routing"]["direct"] = True
        out["routing"]["reasons"].append(f"Claude 流量最后落到直连出口（{eff}）")
    elif kind["kind"] == "auto":
        out["routing"]["auto_switch"] = [eff]
        out["routing"]["auto_for_claude"] = True
        out["routing"]["reasons"].append(
            f"Claude 流量走的是会自动换节点的组（{eff}，{kind.get('type')}）")
    elif kind["kind"] == "selector":
        members = int(kind.get("members") or 0)
        if members > 1:
            out["routing"]["reasons"].append(
                f"Claude 走 {eff}（select 组，{members} 个成员）：不会自己换节点，但可以在界面里手动切")
        else:
            out["routing"]["reasons"].append(f"Claude 走 {eff}，只有 1 个成员，钉死在一个节点上")
    elif kind["kind"] == "node":
        out["routing"]["reasons"].append(f"Claude 走 {eff}，是单一出站，不会自动换")
    else:
        out["routing"]["limits"].append(kind.get("detail") or f"出口 {eff} 的性质判不出来")
    if not facts.get("claude_rules"):
        out["routing"]["limits"].append(
            "配置里没有专门给 Claude 域名的规则，它跟着兜底走"
            + (f"（兜底 {eff}）" if eff else ""))
    if facts.get("auto_switch"):
        out["routing"]["auto_switch"] = sorted(set(out["routing"]["auto_switch"]) | set(facts["auto_switch"]))
        out["routing"]["limits"].append(
            "这个后端里有会自动换节点的组：" + "、".join(sorted(facts["auto_switch"])[:3])
            + "；Claude 是否经过它们取决于上面的出口")
    return out


def _outbound_kind(facts: dict, tag: str) -> dict:
    for ob in facts.get("outbounds") or []:
        if ob["tag"] == tag:
            return ob
    return {}

# 国内解析器。出现在 Clash 的主 nameserver 列表里，就意味着「解析国外域名的请求交给
# 国内服务器处理」；而 Clash 自己的 DNS 查询默认不跟规则走（respect-rules 缺省为 false），
# 是从真实 IP 直发的。两个条件叠在一起，结果是国外域名的解析动作暴露给了国内解析器。
# 放在 nameserver-policy 的 geosite:cn,private 底下则是正常的——国内域名本来就该走国内。
# Claude 流量的域名特征。既认域名本身，也认 Anthropic 的网段——
# statsigapi.net 名字里既没有 anthropic 也没有 claude，但确实是喂给 Claude 的。
CLAUDE_DOMAIN_HINTS = (
    "anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com",
    "statsigapi.net", "160.79.104",
)
# 判定「这个出站会自己换节点」的类型名（各家叫法不同，归一到这里）
AUTO_SWITCH_TYPES = ("urltest", "url_test", "url-test", "fallback", "load-balance", "loadbalance")
# 判定「这个是直连」的类型名
DIRECT_TYPES = ("direct", "freedom", "block", "reject", "DIRECT", "REJECT")

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
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return default
    except OSError as error:
        raise ValueError(f"无法读取 JSON 文件：{path}") from error
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"JSON 文件损坏：{path}") from error
    if isinstance(default, dict) and not isinstance(data, dict):
        raise ValueError(f"JSON 顶层不是对象：{path}")
    return data


def write_json(path: pathlib.Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".guard.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def normalize_expected_country(value: str | None) -> str | None:
    """Normalize a user supplied ISO-3166 alpha-2 country code."""
    if value is None:
        return None
    value = value.strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", value):
        raise ValueError("--expected-country 必须是两个英文字母，例如 US")
    return value


def normalize_expected_ip(value: str | None) -> str | None:
    """Normalize a user supplied IPv4/IPv6 address without guessing."""
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as error:
        raise ValueError("--expected-exit-ip 不是合法的 IPv4/IPv6 地址") from error


def expected_exit_result(actual: dict, expected_country: str | None = None,
                         expected_exit_ip: str | None = None) -> dict:
    """Compare observed exit data with only the expectations explicitly supplied.

    ``unknown`` is deliberately used for source conflicts and missing observations;
    a contradictory or incomplete probe must never become a target match.
    """
    expected_country = normalize_expected_country(expected_country)
    expected_exit_ip = normalize_expected_ip(expected_exit_ip)
    actual_ip = actual.get("ip")
    try:
        actual_ip = str(ipaddress.ip_address(actual_ip)) if actual_ip else None
    except ValueError:
        actual_ip = None
    expected = {"country": expected_country, "exit_ip": expected_exit_ip}
    actual_fields = {"country": (actual.get("country") or "").upper() or None,
                     "exit_ip": actual_ip}
    checks = {}
    if expected_country is not None:
        checks["country"] = (actual_fields["country"] == expected_country
                              if actual_fields["country"] else None)
    if expected_exit_ip is not None:
        checks["exit_ip"] = (actual_fields["exit_ip"] == expected_exit_ip
                              if actual_fields["exit_ip"] else None)
    if not checks:
        status, match, reason = "unknown", None, "未声明预期出口"
    elif actual.get("source_conflict"):
        status, match, reason = "unknown", None, "两个出口来源冲突，不能确认目标是否匹配"
    elif (any(v is None for v in checks.values())
          or (expected_country is not None and actual_fields["exit_ip"] is None)):
        status, match, reason = "unknown", None, "实测出口 IP 或国家缺失"
    elif all(checks.values()):
        status, match, reason = "ok", True, "实测出口符合用户声明的预期"
    else:
        status, match, reason = "bad", False, "实测出口不符合用户声明的预期"
    return {"expected": expected, "actual": actual_fields, "checks": checks,
            "match": match, "status": status, "reason": reason}


def save_audit_report(report: dict) -> pathlib.Path:
    """Explicitly persist an audit report; callers must opt in."""
    outdir = BACKUP_ROOT
    outdir.mkdir(parents=True, exist_ok=True)
    os.chmod(outdir, 0o700)
    path = outdir / f"audit-{dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f')}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


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


def _json_object(body: str):
    """Parse a probe response without allowing malformed JSON/types to escape."""
    try:
        value = json.loads(body)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def check_export_ip(persist: bool = True) -> dict:
    """A8 出口 IP 与 ASN 类型。文章 2.3、2.5①。"""
    out = {"ip": None, "org": None, "country": None, "city": None, "timezone": None,
           "verdict": None, "sources": {}}
    for name, url in (("ipinfo", "https://ipinfo.io/json"), ("ipify", "https://api.ipify.org?format=json")):
        code, body = run(["curl", "-s", "--max-time", "10", "--noproxy", "*", url])
        if code or not body.strip():
            continue
        data = _json_object(body)
        if data is None:
            continue
        candidate = data.get("ip")
        try:
            candidate = str(ipaddress.ip_address(candidate.strip())) if isinstance(candidate, str) else None
        except ValueError:
            candidate = None
        out["sources"][name] = candidate
        if name == "ipinfo":
            # Country/geo metadata is trusted only when it came with a valid
            # ipinfo address.  If ipinfo is malformed and ipify later supplies
            # an address, carrying ipinfo's country across would compare a
            # target against two unrelated observations.
            out.update(ip=candidate)
            if candidate:
                out.update(
                    org=data.get("org") if isinstance(data.get("org"), str) else None,
                    country=data.get("country") if isinstance(data.get("country"), str) else None,
                    city=data.get("city") if isinstance(data.get("city"), str) else None,
                    timezone=data.get("timezone") if isinstance(data.get("timezone"), str) else None,
                )
    if not out.get("ip"):
        # ipify is deliberately a fallback: it only tells us the address, but
        # that is still better than claiming that no exit IP was measured.
        out["ip"] = out["sources"].get("ipify")
        if out.get("ip"):
            out["fallback_source"] = "ipify"
    source_ips = {v for v in out["sources"].values() if v}
    if len(source_ips) > 1:
        out["source_conflict"] = sorted(source_ips)
    ip = out.get("ip")
    if not ip:
        out["verdict"] = "取不到出口 IP"
        return out
    code, body = run(["curl", "-s", "--max-time", "10", "--noproxy", "*", f"https://ipinfo.io/{ip}/json"])
    if not code and body.strip():
        d = _json_object(body)
        if d is not None:
            org = d.get("org") if isinstance(d.get("org"), str) else ""
            out["org"] = org
            if isinstance(d.get("timezone"), str):
                out["timezone"] = d["timezone"]
            out["verdict"] = classify_asn(org)

    # 交叉核对第二个地理库。同一个 IP 在不同库上可能落在不同城市——实测
    # 同一个出口 IP 在 ipinfo 是 New York City、在 ip-api 却是 Dallas。这个分歧本身
    # 就是信号：出口的地理归属不稳定，检测方按哪个库判都不奇怪。只看一个库会
    # 把这件事吞掉，所以显式记下来。
    code, body = run([
        "curl", "-s", "--max-time", "10", "--noproxy", "*",
        f"http://ip-api.com/json/{ip}?fields=status,city,regionName,timezone,isp",
    ])
    if not code and body.strip():
        d2 = _json_object(body)
        if d2 is not None and d2.get("status") == "success":
            out["geo_second"] = {
                "city": d2.get("city"), "region": d2.get("regionName"),
                "timezone": d2.get("timezone"), "isp": d2.get("isp"),
            }
            if d2.get("city") and out.get("city") and d2["city"] != out["city"]:
                out["geo_conflict"] = f"{out['city']} / {d2['city']}"
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
    if persist:
        save_export_history(out)
    return out


def check_proxy_residue() -> dict:
    """A1 + B4 系统代理残留。文章 2.5④，文章称『Mac 很关键』。

    区分两种情形：
      * residue —— 未启用但存了 127.0.0.1:7897 一类值，Clean Verge 关掉系统代理后留下的；
      * enabled —— 系统代理仍处于启用状态，与文章 2.4「开 TUN 后关掉系统代理」相悖。
    """
    out = {"scutil": {}, "enabled": [], "network_services": [], "residue": [],
           "probe_ok": True, "probe_errors": []}
    code, body = run(["scutil", "--proxy"])
    if code:
        out["probe_ok"] = False
        out["probe_errors"].append("scutil --proxy 失败")
    for key in ("HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable"):
        m = re.search(rf"{key}\s*:\s*(\d+)", body)
        out["scutil"][key] = int(m.group(1)) if m else None
        if not m:
            out["probe_ok"] = False
        if out["scutil"][key] == 1:
            out["enabled"].append(key)
    service_code, service_body = run(["networksetup", "-listallnetworkservices"])
    if service_code:
        out["probe_ok"] = False
        out["probe_errors"].append("networksetup -listallnetworkservices 失败")
        services = []
    else:
        services = []
        for line in service_body.splitlines()[1:]:
            name = line.strip()
            if name and not name.startswith("*"):
                services.append(name)
    for svc in services:
        for getter, setter in (
            ("getwebproxy", "webproxy"),
            ("getsecurewebproxy", "securewebproxy"),
            ("getsocksfirewallproxy", "socksfirewallproxy"),
        ):
            code, body = run(["networksetup", f"-{getter}", svc])
            if code:
                out["probe_ok"] = False
                out["probe_errors"].append(f"networksetup -{getter} {svc} 失败")
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
            if not enabled or not server or not port:
                out["probe_ok"] = False
                out["probe_errors"].append(f"{svc}/{setter} 输出字段不完整")
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
                clean_line = line.rstrip("\r\n")
                hits.append({"line": n,
                             "text": redact_credentials(clean_line.strip())[:120],
                             "sha256": hashlib.sha256(clean_line.encode()).hexdigest()})
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
    out = {"global_addresses": [], "services": {}, "probe_ok": True, "probe_errors": []}
    code, body = run(["ifconfig"])
    if code:
        out["probe_ok"] = False
        out["probe_errors"].append("ifconfig 失败")
    for line in body.splitlines():
        s = line.strip()
        if s.startswith("inet6") and "fe80" not in s and "::1" not in s:
            out["global_addresses"].append(s.split()[0])
    svc_code, svc_body = run(["networksetup", "-listallnetworkservices"])
    if svc_code:
        out["probe_ok"] = False
        out["probe_errors"].append("networksetup -listallnetworkservices 失败")
        services = []
    else:
        services = [line.strip() for line in svc_body.splitlines()[1:]
                    if line.strip() and not line.strip().startswith("*")]
    for svc in services:
        code, info = run(["networksetup", "-getinfo", svc])
        if code:
            out["probe_ok"] = False
            out["probe_errors"].append(f"networksetup -getinfo {svc} 失败")
            out["services"][svc] = None
            continue
        m = re.search(r"IPv6:\s*(\S+)", info)
        out["services"][svc] = m.group(1) if m else None
        if not m:
            out["probe_ok"] = False
            out["probe_errors"].append(f"{svc} 缺少 IPv6 字段")
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
    out = {"resolved": [], "fake_ip": False, "real_ip_hosts": [], "system_dns": [],
           "probe_ok": True, "probe_errors": []}
    for host in ("example.com", "api.anthropic.com", "claude.ai"):
        code, body = run(["dig", "+short", host], timeout=10)
        if code:
            out["probe_ok"] = False
            out["probe_errors"].append(f"dig {host} 失败")
            continue
        ips = [ip for ip in body.split() if re.match(r"^[0-9a-fA-F:.]+$", ip)]
        for ip in ips:
            is_fake = ip.startswith(fake_ip_prefixes())
            out["resolved"].append({"host": host, "ip": ip, "fake": is_fake})
            if is_fake:
                out["fake_ip"] = True
        # Mixed answers are still a leak: the presence of one fake address must
        # not hide a second, real address returned for the same hostname.
        if ips and any(not i.startswith(fake_ip_prefixes()) for i in ips):
            out["real_ip_hosts"].append(host)
        if not ips:
            out["real_ip_hosts"].append(f"{host}(无解析结果)")
    code, body = run(["scutil", "--dns"])
    if code:
        out["probe_ok"] = False
        out["probe_errors"].append("scutil --dns 失败")
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
    out["sock_tried"] = [str(p) for p in clash_sock_paths()]
    resolved = clash_socket()
    out["sock"] = str(resolved) if resolved else ""
    if resolved is None:
        return out

    def api(path):
        try:
            code, body = clash_http("GET", path, timeout=8)
        except (OSError, ValueError, TimeoutError, RuntimeError):
            return None
        # Real socket calls return HTTP 2xx.  The test fixture returns code 0
        # with a JSON body, so keep that explicit compatibility seam while
        # rejecting every non-success HTTP status.
        if (code and not 200 <= code < 300) or not body.strip():
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
        for m in GEO_WORD_RE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            out["hits"].append({"file": sp, "word": m.group(0), "line": line})
    if not project_roots():
        out["note"] = "只扫了家目录；设置 CLAUDE_GUARD_PROJECT_ROOTS 可连项目级 CLAUDE.md 一起扫"
    return out


SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent


def project_roots_default() -> tuple[list[pathlib.Path], str]:
    """A14 / A24 的扫描范围：环境变量 → skill 所在的 git 仓 → 老位置 ~/ipe。

    三级兜底，而且选中的那一级会被打出来 —— 扫描范围静默换掉比不扫更糟。

    为什么不能只认环境变量：直接敲 `python3 scripts/account_guard.py --audit`
    （同事最常见的跑法，文档里也是这么写的）时没人设这个变量，于是
    「代码是否落在本地 Git」与「项目级 .claude 规模」两项会莫名其妙变成「未测到」。
    2026-10-15 实测：裸跑是 6 项未测到，带上项目根就少 2 项。selfcheck.py 一直有
    这套兜底、account_guard.py 没有，两边各说各话。
    """
    raw = os.environ.get("CLAUDE_GUARD_PROJECT_ROOTS", "").strip()
    if raw:
        return ([pathlib.Path(x).expanduser() for x in raw.split(os.pathsep) if x.strip()],
                "环境变量指定")
    code, out = run(["git", "-C", str(SKILL_DIR), "rev-parse", "--show-toplevel"], timeout=20)
    top = pathlib.Path(out.strip()) if code == 0 and out.strip() else None
    if top is not None and top.is_dir():
        return [top], "skill 所在的 git 仓"
    legacy = HOME / "ipe"
    if legacy.is_dir():
        return [legacy], "老位置 ~/ipe"
    return [], "没指定（设 CLAUDE_GUARD_PROJECT_ROOTS，或把 skill 装进一个 git 仓）"


def project_roots() -> list[pathlib.Path]:
    """A14 要扫描的项目目录。三级兜底见 project_roots_default。"""
    return project_roots_default()[0]


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
        data = json.loads(MEDIA_CACHE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def cache_is_fresh(data: dict, *, require_profile_scope: bool = True,
                   expected_profile_scope: str | None = None) -> tuple[bool, str]:
    """Return whether a cached browser measurement is bounded and attributable.

    The cache is evidence from one browser profile at one point in time.  A
    missing timestamp or profile scope is therefore unknown, never green.
    """
    if not isinstance(data, dict):
        return False, "缓存不是对象"
    checked = data.get("checkedAt")
    if not isinstance(checked, str):
        return False, "缺少测量时间"
    try:
        when = dt.datetime.strptime(checked, "%Y-%m-%d %H:%M")
    except ValueError:
        try:
            when = dt.datetime.fromisoformat(checked.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return False, "测量时间格式无效"
    age = (dt.datetime.now() - when).total_seconds()
    if age < 0 or age > CACHE_MAX_AGE_SECONDS:
        return False, f"测量已超过 {CACHE_MAX_AGE_SECONDS // 3600} 小时"
    if require_profile_scope:
        scope = data.get("profileScope")
        if not isinstance(scope, str) or not scope.strip():
            return False, "未绑定浏览器资料范围"
        expected = expected_profile_scope if expected_profile_scope is not None else browser_profile_scope()
        if not expected:
            return False, "未提供 CLAUDE_GUARD_BROWSER_PROFILE，不能确认资料身份"
        if scope != expected:
            return False, "缓存资料范围与当前指定的浏览器资料标识不一致"
    return True, ""


def verify_media_permission(timeout: int = 240, auto_open: bool = False) -> dict:
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
        server = _new_loopback_server(Handler)
    except OSError as e:
        print(f"  本地服务起不来：{e}")
        return {}
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # flush 是必须的：这个函数会阻塞等待浏览器回传，而 Python 在 stdout 不是
    # TTY 时（后台跑、管道接出去）会缓冲——不刷新的话 URL 根本打不出来，
    # 用户看不到要打开哪个地址，就一直等到超时。
    url = f"http://127.0.0.1:{port}/{token}/"
    print(f"\n  用你日常那个 Chrome 打开：\n", flush=True)
    print(f"      {url}\n", flush=True)
    print(f"  链接里那串是本次随机令牌，别改也别分享；页面会自动检测并回传，最多等 {timeout} 秒（Ctrl-C 可取消）...",
          flush=True)
    opened = open_verify_page(url, "媒体权限复核页") if auto_open else {"opened": False}
    if auto_open and not opened.get("opened"):
        print(f"  没能替你打开浏览器（{opened.get('reason')}）—— 手动打开上面那个地址即可。",
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
    # The browser cannot identify its profile to this local page.  Bind the
    # result only to an identifier the user supplied explicitly; without it
    # the cache remains visible but can never be treated as green evidence.
    #
    # 2026-10-15 加了一层可核验的证据：这次复核页是**谁打开的**。脚本自己用声明的
    # 资料目录 open 出来的，就记 openedBy=script；只发链接、由用户自己在别处打开的，
    # 仍然只有一份声明，判定那边照样不据此报绿。
    got["openedBy"] = "script" if opened.get("opened") else "user"
    if opened.get("profileDir"):
        got["openedProfileDir"] = opened["profileDir"]
    scope = browser_profile_scope()
    if scope:
        got["profileScope"] = scope
    else:
        got.pop("profileScope", None)
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
        print("  修法一：Chrome 设置 → 隐私和安全 → 网站设置 → 摄像头/麦克风 → 不允许网站使用。")
        print("  修法二：装 WebRTC Network Limiter 扩展（文章 2.5② 推的就是它）。")
        print(f"    下包：python3 scripts/account_guard.py --install-webrtc-limiter")
        print(f"    商店：{WEBRTC_LIMITER_STORE_URL}")
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
        server = _new_loopback_server(Handler)
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


CLI_LOGIN_TOKEN_ENV = "CLAUDE_CODE_OAUTH_TOKEN"
LOGIN_TOKEN_RC_FILES = (".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile")


def long_lived_token_sources() -> list:
    """哪些地方写了长期 token。

    只报位置，绝不读值——token 本体不进报告、不进日志、不进终端输出。
    """
    places = []
    if os.environ.get(CLI_LOGIN_TOKEN_ENV):
        places.append("环境变量")
    try:
        if SETTINGS.is_file():
            data = json.loads(SETTINGS.read_text())
            env = data.get("env") if isinstance(data, dict) else None
            if isinstance(env, dict) and env.get(CLI_LOGIN_TOKEN_ENV):
                places.append("settings.json 的 env")
    except (OSError, ValueError):
        pass
    pattern = re.compile(rf"^\s*(?:export\s+)?{CLI_LOGIN_TOKEN_ENV}=", re.M)
    for name in LOGIN_TOKEN_RC_FILES:
        path = HOME / name
        try:
            if path.is_file() and pattern.search(path.read_text()):
                places.append(name)
        except OSError:
            continue
    return places


def check_cli_login(cli_path=None) -> dict:
    """CLI 现在用的哪种凭据：长期 token、网页授权登录，还是根本没登录。

    用户口径（2026-10-15）：不要在 Claude Code 里做网页授权登录——认证那一刻的出口
    和登录事件绑在一起；网页登录还会因为掉线、丢包反复触发重登，每重登一次就是一条
    新的登录事件。安全做法是第一次认证时跑 `claude setup-token` 拿长期 token。
    """
    out = {
        "checkedAt": now_stamp(),
        "tokenSources": long_lived_token_sources(),
        "auth": None,
        "raw": "",
        "error": None,
    }
    cli = cli_path or shutil.which("claude")
    if not cli:
        out["state"] = "unknown"
        out["error"] = "没找到 claude 命令"
        return out
    code, text = run([cli, "auth", "status"], timeout=15, env={"DISABLE_AUTOUPDATER": "1"})
    out["raw"] = (text or "").strip()[:400]
    start, end = out["raw"].find("{"), out["raw"].rfind("}")
    data = None
    if start >= 0 and end > start:
        try:
            parsed = json.loads(out["raw"][start:end + 1])
            data = parsed if isinstance(parsed, dict) else None
        except ValueError:
            data = None
    out["auth"] = data
    if out["tokenSources"]:
        out["state"] = "token"
    elif data is not None and data.get("loggedIn"):
        out["state"] = "interactive"
    elif data is not None:
        out["state"] = "none"
    else:
        out["state"] = "unknown"
        out["error"] = f"读不懂 claude auth status 的输出（退出码 {code}）"
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
        data = json.loads(LOCALE_CACHE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


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


def check_browser_locale(ip: dict | None = None, expected: dict | None = None) -> dict:
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
    declared_expected = expected and any(expected.get("expected", {}).values())
    if declared_expected and expected.get("status") != "ok":
        out["target_blocked"] = True
        out["facts"].append("预期出口未确认匹配，禁止按不可靠的实测国家建议修改 Chrome Intl")

    code, body = run(["defaults", "read", "-g", "AppleLanguages"])
    out["system_languages"] = re.findall(r'"([^"]+)"', body) if code == 0 else None
    out["app_override"] = chrome_app_languages()

    chain = out["app_override"] or out["system_languages"] or []
    out["predicted"] = predict_intl_locale(chain[0] if chain else None)

    cached = load_browser_locale()
    cache_ok, cache_note = cache_is_fresh(cached, expected_profile_scope=browser_profile_scope())
    if cached.get("intlLocale") and cache_ok:
        out["measured"] = cached["intlLocale"]
        out["checked_at"] = cached.get("checkedAt")
        # 资料身份这回事：页面自己报不出来，所以判据是「这次复核页是谁打开的」。
        # 脚本自己用声明的资料目录 open 出来的（--verify-browser 或 --check-locale
        # 自动打开），至少能说清是脚本按哪个资料开的；只发链接、由用户在别处打开的，
        # 仍然只有一份声明，不能据此报绿。
        script_opened = cached.get("openedBy") == "script"
        out["opened_by_script"] = script_opened
        out["scope_unverified"] = not script_opened
        if script_opened:
            where = cached.get("openedProfileDir") or cached.get("profileScope") or "默认资料"
            out["source"] = ("浏览器实测（脚本打开的复核页，资料 " + where + "）")
        else:
            out["source"] = ("浏览器实测（用户声明资料：" + str(cached.get("profileScope") or "未声明")
                              + "；资料身份未由脚本验证）")
        # 时区是同一张复核页顺手带回来的（页面本来就在收 timeZone），
        # 以前收了没用。这里只报事实、不下判定 —— 见下面 facts 里的说明。
        if cached.get("timeZone"):
            out["browser_timezone"] = cached["timeZone"]
    elif out["predicted"] and not cached.get("intlLocale"):
        out["measured"] = out["predicted"]
        out["source"] = "按 AppleLanguages 推定，未跑浏览器复核"
    elif cached.get("intlLocale"):
        out["facts"].append("浏览器 Intl 缓存不可用：" + cache_note)

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
    profileScope: null,
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


def verify_browser_locale(timeout: int = 240, auto_open: bool = False) -> dict:
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
        server = _new_loopback_server(Handler)
    except OSError as e:
        print(f"  本地服务起不来：{e}")
        return {}
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # flush 必须加：这里会阻塞等浏览器回传，而 Python 在 stdout 不是 TTY 时
    # 会缓冲 —— 不刷新的话 URL 根本打不出来，用户不知道开哪个地址，只能等到超时。
    url = f"http://127.0.0.1:{port}/{token}/"
    print("\n  用你要检查的那个 Chrome 资料打开：\n", flush=True)
    print(f"      {url}\n", flush=True)
    print(f"  链接里那串是本次随机令牌，别改也别分享；页面会自动回传，最多等 {timeout} 秒（Ctrl-C 可取消）...",
          flush=True)
    opened = open_verify_page(url, "浏览器 Intl 复核页") if auto_open else {"opened": False}
    if auto_open and not opened.get("opened"):
        print(f"  没能替你打开浏览器（{opened.get('reason')}）—— 手动打开上面那个地址即可。",
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
    # 见 verify_media_permission 里同一段说明：记下这次复核页是谁打开的。
    got["openedBy"] = "script" if opened.get("opened") else "user"
    if opened.get("profileDir"):
        got["openedProfileDir"] = opened["profileDir"]
    scope = browser_profile_scope()
    if scope:
        got["profileScope"] = scope
    else:
        got.pop("profileScope", None)
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
    if rep.get("target_blocked"):
        return "预期出口不符，拒绝按当前实测国家修改 Chrome Intl"
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


def _backend_labels(pb: dict) -> str:
    return str(pb.get("label") or pb.get("backend") or "未知后端")


def _process_evidence(pb: dict) -> str:
    names = [e.get("value") for e in (pb.get("evidence") or []) if e.get("kind") == "process"]
    return "、".join(str(x) for x in names if x)


def backend_row(pb: dict) -> tuple:
    """「代理后端」这一行：认出是谁、脚本对它了解到什么程度。"""
    backend = pb.get("backend") or ""
    label = _backend_labels(pb)
    caps = pb.get("capabilities") or {}
    notes = "；".join(pb.get("notes") or [])
    capture = pb.get("capture") or {}
    cap_note = ("；".join(capture.get("notes") or []))
    if backend == "none":
        if capture.get("captured"):
            return (S_NA, "没发现代理进程、系统代理也没开，但 " + cap_note
                          + " —— 有东西在接管流量，脚本没认出它是谁")
        return (S_NA, "没有发现代理进程，系统代理也没开；后面两行问的是代理的分流与 DNS，"
                      "没有代理就没有可判的对象")
    if backend == "other":
        return (S_NA, f"在跑的是 {_process_evidence(pb) or label}，"
                      "脚本不认识它的配置格式：分流与 DNS 读不到，只能靠它自己的界面和检测站"
                      + ("；" + cap_note if cap_note else ""))
    if backend == "system":
        others = "；".join(pb.get("notes") or [])
        return (S_OK, f"{label}（{others}）")
    if backend == "vpn":
        return (S_NA, f"{label}：{notes or '隧道类工具不做域名分流'}")
    # mihomo / singbox / surge / v2ray
    detail = label
    if pb.get("controller_ok"):
        detail += "，控制接口可用"
    elif pb.get("controller"):
        detail += "，控制接口连不上"
    if not caps.get("verify_after_write"):
        detail += "；改配置脚本无法就地复验（改完要它自己重载）"
    if notes:
        detail += "；" + notes
    if cap_note:
        detail += "；" + cap_note
    return (S_OK if pb.get("controller_ok") else S_NA, detail)


def backend_routing_row(pb: dict):
    """非 mihomo 后端时「绝不直连」怎么写。返回 None 表示照旧走 Clash 的判据。"""
    backend = pb.get("backend") or ""
    if backend == "mihomo":
        return None
    if backend == "none":
        return (S_NA, "没有发现代理，这一项没有可判的对象")
    if backend == "system":
        return (S_OK, "只有系统代理，没有分流规则：所有流量一个出口，不存在「规则没写对漏出去」，"
                      "也没有兜底直连这回事；要确认出口看上面那两行")
    if backend == "vpn":
        return (S_NA, "隧道类工具不做域名分流，这一项不适用；出口看上面两行")
    if backend == "other":
        return (S_NA, f"在跑的是 {_process_evidence(pb)}，脚本不认识它的配置格式，"
                      "读不到分流规则；这一项只能你自己在它的界面里确认")
    facts = pb.get("facts") or {}
    rt = facts.get("routing") or {}
    label = _backend_labels(pb)
    if not rt.get("evaluated"):
        return (S_NA, f"{label}：" + "；".join(rt.get("limits") or ["读不到配置，分流判不了"]))
    out = facts.get("routing", {}).get("claude_outbound") or "(未取到)"
    if rt.get("direct") or rt.get("auto_for_claude"):
        return (S_BAD, "；".join(rt.get("reasons") or []) + "。脚本不替别家改分流（改错就是断网），要你自己改")
    body = "；".join(rt.get("reasons") or [])
    limits = "；".join(rt.get("limits") or [])
    if facts.get("runtime_verified"):
        return (S_OK, f"{label}，{body}" + (f"（{limits}）" if limits else ""))
    return (S_NA, f"{label}，配置层面：{body}"
                  + (f"；{limits}" if limits else "")
                  + "。"
                  + (facts.get("verify_hint") or "没有运行时证据，不能据此报绿"))


def backend_dns_row(pb: dict):
    """非 mihomo 后端时「DNS 泄漏」怎么写。返回 None 表示照旧走 Clash 的判据。"""
    backend = pb.get("backend") or ""
    if backend == "mihomo":
        return None
    if backend == "none":
        return (S_NA, "没有发现代理，这一项没有可判的对象")
    if backend in ("system", "vpn"):
        return (S_NA, "这个后端没有代理侧的 DNS 配置可读；DNS 由系统解析器决定，"
                      "要确认有没有泄漏只能看 browserleaks.com/dns")
    if backend == "other":
        return (S_NA, f"在跑的是 {_process_evidence(pb)}，脚本不认识它的配置格式，读不到 DNS 设置")
    facts = pb.get("facts") or {}
    dns = facts.get("dns") or {}
    label = _backend_labels(pb)
    if not dns.get("evaluated"):
        return (S_NA, f"{label}：" + "；".join(dns.get("limits") or ["读不到配置，DNS 判不了"]))
    if dns.get("cn"):
        who = "、".join(dns["cn"][:2])
        if dns.get("fixable"):
            tail = ("；确认后可改成境外解析器（要显式加 --fix-unverified，改完要重启这个软件）"
                    if backend != "surge"
                    else "；Surge 的配置归 App 管，要在界面里改")
            return (S_FIX, "；".join(dns.get("reasons") or []) + tail)
        return (S_FIX, "；".join(dns.get("reasons") or []) + "；要你自己在它的界面里改成境外解析器")
    limits = "；".join(dns.get("limits") or [])
    if facts.get("runtime_verified"):
        return (S_OK, f"{label}，解析器 " + "、".join((dns.get("servers") or [])[:2])
                      + "，没有国内服务器" + (f"（{limits}）" if limits else ""))
    return (S_NA, f"{label}，配置里没有国内解析器"
                  + (f"（{limits}）" if limits else "")
                  + "。" + (facts.get("verify_hint") or "没有运行时证据，不能据此报绿"))


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
    pb = report.get("A28_proxy_backend") or {}
    rows = []
    scope = report.get("scope_manifest") or {}
    custom_config_scope = bool(scope.get("custom"))
    scope_note = (
        "CLAUDE_CONFIG_DIR 指向自定义目录 "
        f"{scope.get('configured_config_dir') or '(未知)'}；未扫描该目录，不能判定干净"
    )

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
        if ip.get("source_conflict"):
            detail += "（出口来源冲突：" + " / ".join(ip["source_conflict"]) + "）"
            add("出口 IP 与归属", S_FIX, detail)
            # 不用历史一致性掩盖本次探测的直接矛盾。
            source_conflict = True
        else:
            source_conflict = False
        if ip.get("geo_conflict"):
            detail += f"（两个地理库打架：{ip['geo_conflict']}）"
        prev = ip.get("previous") or {}
        if source_conflict:
            pass
        elif ip.get("changed"):
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

    expectation = ip.get("expected") or {}
    if expectation.get("status") == "ok":
        add("预期出口是否符合", S_OK,
            f"符合：国家 {expectation.get('expected', {}).get('country') or '未指定'}，"
            f"IP {expectation.get('expected', {}).get('exit_ip') or '未指定'}")
    elif expectation.get("status") == "bad":
        add("预期出口是否符合", S_BAD,
            f"不符合：预期 {expectation.get('expected')}，实测 {expectation.get('actual')}")
    else:
        add("预期出口是否符合", S_NA, expectation.get("reason") or "未声明预期出口")

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
    elif pr.get("probe_ok") is False:
        add("系统代理残留", S_NA, "探测失败或输出不完整，未判定为干净：" + "; ".join(pr.get("probe_errors") or []))
    elif pr.get("enabled"):
        add("系统代理残留", S_BAD, f"系统代理处于启用状态：{pr['enabled']}（TUN 与系统代理不该叠着）")
    elif pr.get("residue"):
        add("系统代理残留", S_FIX, f"{len(pr['residue'])} 项未启用但存着值，确认后计划清掉")
    else:
        add("系统代理残留", S_OK, "四个开关全为 0，网络服务也没有存值")

    cdc = dn.get("clash") or {}
    dns_row = None if missing("A28_proxy_backend") else backend_dns_row(pb)
    if missing("A6_dns"):
        add("DNS 泄漏", S_NA, "未检测")
    elif dns_row is not None and (dns_row[0] != S_NA or not cdc.get("found")):
        # 非 mihomo 后端按它自己的事实判；但 mihomo 的 DNS 事实也照样报（配置里可能真有国内解析器）
        add("DNS 泄漏", dns_row[0], dns_row[1])
    elif dn.get("probe_ok") is False:
        add("DNS 泄漏", S_NA, "DNS 探测失败或输出不完整，未判定为干净：" + "; ".join(dn.get("probe_errors") or []))
    elif (dn.get("real_ip_hosts") or []):
        add("DNS 泄漏", S_BAD, f"这些域名解析到了真实公网 IP：{(dn.get('real_ip_hosts') or [])[:3]}")
    elif cdc.get("leaking") or cdc.get("leaking_fallback"):
        bad = list(cdc.get("leaking") or []) + list(cdc.get("leaking_fallback") or [])
        where = "主解析器" if cdc.get("leaking") else "fallback"
        add("DNS 泄漏", S_FIX,
            where + "含国内服务器（" + "、".join(bad[:2]) + "），"
            "国外域名的解析交给了它们；确认选择后可换成境外解析器")
    elif cdc.get("found") and not cdc.get("respect_rules"):
        add("DNS 泄漏", S_FIX,
            "没开 respect-rules —— Clash 自己的 DNS 查询不跟规则走，是从真实 IP 直发的；"
            "确认选择后可打开")
    elif cdc.get("enabled") is False:
        add("DNS 泄漏", S_FIX,
            "Clash 配置里 dns.enable 是关的，DNS 模块根本没在跑；确认选择后可打开")
    elif cdc.get("tun_enabled") and not cdc.get("hijack"):
        add("DNS 泄漏", S_FIX,
            "TUN 开着但没配 dns-hijack —— 发往 53 端口的查询不会被内核接管，"
            "会照原样落到系统配的解析器上；确认选择后可补上")
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
    elif bl.get("target_blocked"):
        add("浏览器 Intl 区域设置", S_NA,
            "预期出口不符，已禁止按当前实测国家修改 Chrome Intl")
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
    elif "推定" in str(bl.get("source") or ""):
        add("浏览器 Intl 区域设置", S_NA,
            f"{bl['measured']}（{bl.get('source')}）；没有浏览器实测，不能据此报绿")
    elif bl.get("scope_unverified"):
        add("浏览器 Intl 区域设置", S_NA,
            f"{bl['measured']}（{bl.get('source')}）；资料身份未由脚本验证，不能据此报绿")
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
        media_cache_ok, media_cache_note = cache_is_fresh(mp)
        if wr.get("leaked_public"):
            add("WebRTC 泄漏", S_BAD, f"探测到公网地址：{wr['leaked_public']}")
            _webrtc_row_done = True
        elif mp.get("ok") and media_cache_ok and (tun or media_ips):
            add("WebRTC 泄漏", S_NA,
                f"授权后会露出 {tun[0] if tun else media_ips[0]}；缓存显示浏览器已禁掉"
                f"摄像头/麦克风（复核于 {mp.get('checkedAt')}），但资料身份只有用户声明、"
                f"未由脚本验证，不能据此报绿")
            _webrtc_row_done = True
        else:
            _webrtc_row_done = False
        if _webrtc_row_done:
            pass
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
                add("WebRTC 泄漏", S_NA, f"取到 {wr['candidates']} 个候选，无公网地址{extra}")
            else:
                add("WebRTC 泄漏", S_OK, f"取到 {wr['candidates']} 个候选，无公网地址{extra}")
        else:
            add("WebRTC 泄漏", S_NA, wr.get("note") or "探测未取到候选，结论不可用")
    else:
        # 没跑探测时，如果用户在真实浏览器里复核过（--check-media --webrtc 之外的那条路），
        # 就以那次结论为准。这一行要的东西其实是「网站能不能拿到摄像头/麦克风」，
        # 那次复核已经答了；再挂一个「未探测」等于让人以为必须重跑两分钟的探测。
        # 注意：这条分支只在**没有**探测结果时走，探测跑过时以探测为准。
        mp = load_media_permission()
        media_cache_ok, media_cache_note = cache_is_fresh(mp)
        if mp.get("ok") and media_cache_ok and mp.get("openedBy") == "script":
            # 复核页由脚本自己按声明的资料打开：网站拿不到摄像头/麦克风 → mDNS
            # 混淆一直生效 → 这条链路不泄漏。这跟「没测到」是两回事。
            add("WebRTC 泄漏", S_OK,
                f"这次没跑探测；{mp.get('checkedAt')} 那次由脚本打开的复核页显示摄像头与麦克风"
                f"都拿不到（{mp.get('detail') or 'NotAllowedError'}）→ mDNS 混淆生效，不泄漏")
        elif mp.get("ok") and media_cache_ok:
            add("WebRTC 泄漏", S_NA,
                f"这次没跑探测；缓存显示摄像头与麦克风都拿不到（复核于 {mp.get('checkedAt')}），"
                f"但资料身份只有用户声明、未由脚本验证，不能据此报绿")
        else:
            note = wr.get("note") or "未探测；加 --webrtc 参数可跑"
            if mp.get("ok") and not media_cache_ok:
                note += "；已有媒体权限缓存不可用：" + media_cache_note
            add("WebRTC 泄漏", S_NA, note)

    v6g = v6.get("global_addresses") or []
    if missing("A5_ipv6"):
        add("IPv6 全局地址", S_NA, "未检测")
    elif v6.get("probe_ok") is False:
        add("IPv6 全局地址", S_NA, "ifconfig/networksetup 探测失败，未判定为无 IPv6：" + "; ".join(v6.get("probe_errors") or []))
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
    cached_fresh = bool(cached and cache_is_fresh(cached, require_profile_scope=False)[0])
    if g1 is False and g2 is False:
        if cached and not cached_fresh:
            add("时区两道闸", S_NA,
                "定位服务闸门只有过期缓存，不能据此报绿；请用受控 root 方式重新复核")
        elif cached:
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
    if missing("A28_proxy_backend"):
        add("代理后端", S_NA, "未检测")
    else:
        add("代理后端", *backend_row(pb))
    row = None if missing("A28_proxy_backend") else backend_routing_row(pb)
    fc = cg.get("fail_closed") or {}
    if row is not None:
        add("绝不直连", row[0], row[1])
    elif not cg.get("reachable"):
        tried = "、".join(cg.get("sock_tried") or [])
        add("绝不直连", S_NA,
            f"Clash 控制接口不可达，这一项没测到（试过：{tried}）" if tried
            else "Clash 控制接口不可达，这一项没测到")
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
        if storage_worth_cleaning(st):
            add("系统级可清理量", S_FIX,
                f"当前 CLI {cur}；有 {human_bytes(st['cleanable_bytes'])} 可清"
                f"（旧版本 {n_stale} 份 + 可再生缓存 {n_cache} 个）")
        elif st.get("cleanable_bytes"):
            add("系统级可清理量", S_OK,
                f"当前 CLI {cur}；只剩 {human_bytes(st['cleanable_bytes'])} 可再生缓存"
                f"（{n_cache} 个目录，清了自己还会长回来，不值得动）")
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
    if custom_config_scope:
        add("终端 / shell / npm / git 代理", S_NA, scope_note)
        env_n = rc_n = 0
        npmgit = []
    elif missing("A1_terminal_env"):
        add("终端 / shell / npm / git 代理", S_NA, "未检测")
        env_n = rc_n = 0
        npmgit = []
    else:
        env_n = len(te.get("env_hits") or [])
        rc_n = sum(len(v) for v in (te.get("rc_files") or {}).values())
        npmgit = [v for v in list((te.get("npm") or {}).values()) + list((te.get("git") or {}).values())
                  if v and v.strip().lower() not in ("null", "undefined", "none")]
    if not custom_config_scope:
        rc_n = sum(len(v) for v in (te.get("rc_files") or {}).values())
        npmgit = [v for v in list((te.get("npm") or {}).values()) + list((te.get("git") or {}).values())
                  if v and v.strip().lower() not in ("null", "undefined", "none")]
    npmrc_n = len(te.get("npmrc") or [])
    brew_n = len(((te.get("brew") or {}).get("proxy")) or [])
    if custom_config_scope or missing("A1_terminal_env"):
        pass
    elif env_n or rc_n or npmgit or npmrc_n or brew_n:
        extra = []
        if npmrc_n:
            extra.append(f"~/.npmrc {npmrc_n} 行")
        if brew_n:
            extra.append(f"Homebrew {brew_n} 项")
        add("终端 / shell / npm / git 代理", S_FIX,
            f"env {env_n} 条，rc {rc_n} 条，npm/git {len(npmgit)} 项"
            + ("；" + "、".join(extra) if extra else "") + "，确认后计划清掉")
    else:
        # 文章 2.5④ 那批命令有五处出处，一处一处写进证据里，别只说一句「没有代理」。
        add("终端 / shell / npm / git 代理", S_OK,
            "没有任何一处写着代理（环境变量、shell 配置、npm/git、~/.npmrc、brew config 都查过）")

    # 必须区分「Claude Code 自己的 settings.json」和「别的工具的配置」：
    # 前者会自动清掉，后者按范围约定只报告不代改。混在一起报会让用户以为
    # 那处残留会被处理掉，实际上脚本根本不会碰它。
    hits = ab.get("hits") or []
    own = [h for h in hits if "/.claude/" in str(h.get("file", ""))]
    if custom_config_scope:
        add("settings.json 端点与凭据", S_NA, scope_note)
        own = []
    elif missing("A2_anthropic_base_url"):
        add("settings.json 端点与凭据", S_NA, "未检测")
        own = []
    other = [h for h in hits if "/.claude/" not in str(h.get("file", ""))]
    sp = te.get("settings_proxy") or []
    if missing("A1_terminal_env"):
        sp = []
    if custom_config_scope or missing("A2_anthropic_base_url"):
        pass
    elif own or sp:
        bits2 = []
        if own:
            bits2.append(f"{len(own)} 处指向别处")
        if sp:
            bits2.append("env 里的代理变量 " + "、".join(sp))
        add("settings.json 端点与凭据", S_FIX, "、".join(bits2) + "，确认后计划清掉")
    elif other:
        names = "、".join(sorted({pathlib.Path(h["file"]).name for h in other}))
        add("settings.json 端点与凭据", S_OK,
            f"Claude Code 自身没有残留；{len(other)} 处属其它工具（{names}），只报告不代改")
    else:
        add("settings.json 端点与凭据", S_OK, "没有 ANTHROPIC_BASE_URL、代理变量之类的残留")

    if custom_config_scope:
        add("遥测三键", S_NA, scope_note)
    elif missing("A3_telemetry"):
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

    # ── 登录方式（用户口径：不要在 Claude Code 里做网页授权登录）──
    if missing("A29_cli_login"):
        add("登录方式", S_NA, "未检测")
    else:
        lgn = report.get("A29_cli_login") or {}
        state = lgn.get("state")
        srcs = "、".join(lgn.get("tokenSources") or [])
        if state == "token":
            add("登录方式", S_OK,
                f"用长期 token（{srcs}里写着 CLAUDE_CODE_OAUTH_TOKEN），CLI 不依赖网页登录")
        elif state == "interactive":
            add("登录方式", S_FIX,
                "现有登录态来自网页授权（claude auth status 报 loggedIn=true）；掉线或丢包就要重登，"
                "每重登一次就是一条新的登录事件。改用长期 token：终端跑 claude setup-token（人工清单第八组）")
        elif state == "none":
            add("登录方式", S_FIX,
                "还没有长期 token，CLI 当前也没登录（authMethod=none）。要用 CLI 时别在 Claude Code 里登录，"
                "先跑 claude setup-token 拿长期 token 写进 CLAUDE_CODE_OAUTH_TOKEN（人工清单第八组）")
        else:
            add("登录方式", S_NA, "读不到 claude auth status，这一项没测到")

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


def write_html_only(report: dict, before: dict | None = None, note: str = "") -> None:
    """只落一份 HTML，不写 audit JSON、不动出口历史与缓存。

    与 --save-audit 的区别：那条路会连 JSON 和状态一起写，而「就想看一眼报告」的人
    不该被顺带改状态。报告是给人看的附属产物，渲染失败只提示、不往上抛，否则一次
    成功的加固会因为模板里某个字段没对上而以 traceback 收场。
    """
    try:
        from report_html import write_report
        page = write_report(report, before=before, open_it=True)
        suffix = f"（{note}）" if note else ""
        print(f"\nHTML 报告{suffix}：{page}")
    except Exception as error:      # 同上：附属产物不该影响主流程的结论
        print(f"\nHTML 报告生成失败（上面的结论不受影响）：{error}", file=sys.stderr)


def write_html_twin(before: dict, after: dict) -> None:
    """改动前后的对照版 HTML：两个参数都是同一次运行里的真读数。"""
    write_html_only(after, before=before)


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
            "CLAUDE_GUARD_PROJECT_ROOTS=\"$HOME/code\" 指定（冒号分隔可写多个）"
        )
        return out
    for raw in roots:
        root = pathlib.Path(raw).expanduser()
        if not root.is_dir():
            out["note"] = f"目录不存在：{root}"
            continue
        out["roots"].append(str(root))
        # 根本身就是一个仓时只用它自己，不再往下数：skill 装在仓里时
        # （`.claude/skills/<名字>/`）项目根就是那个仓，往下扫会把 backend、docs
        # 这些普通子目录报成「没做版本控制」，那是假警报。
        # 注意 `.git` 在 worktree 里是文件不是目录，所以判存在而不是判目录。
        if (root / ".git").exists():
            out["repos"].append(str(root))
            code, body = run(["git", "-C", str(root), "status", "--porcelain"], timeout=30)
            if code == 0 and body.strip():
                out["dirty"].append({"repo": str(root),
                                     "changed": len(body.strip().splitlines())})
            continue
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
# 低于这个量就不值得动手：Electron 的缓存会被自己重建（实测清完 43.8 MB，
# 十几分钟后桌面版又长出 0.4 MB）。原来的判定是「只要有可清理字节就报待处理」，
# 于是清完立刻又挂回「待处理」，还打印出「有 0 MB 可清」这种自相矛盾的话。
STORAGE_CLEAN_THRESHOLD = 1 << 20  # 1 MB

DESKTOP_DATA = HOME / "Library" / "Application Support" / "Claude"
DESKTOP_BUNDLED = DESKTOP_DATA / "claude-code"
CLI_VERSIONS = HOME / ".local" / "share" / "claude" / "versions"


def human_bytes(n) -> str:
    """字节数说成人话：不到 1 MB 用 KB，省得出现「有 0 MB 可清」。"""
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "未知"
    if n < 0:
        n = 0
    if n < 1 << 20:
        return f"{n / 1024:.0f} KB"
    if n < 1 << 30:
        return f"{n / (1 << 20):.1f} MB"
    return f"{n / (1 << 30):.2f} GB"


def storage_worth_cleaning(report_or_state) -> bool:
    """值不值得清：旧版本多少都值，纯缓存低于阈值就不折腾。"""
    st = report_or_state or {}
    if "A25_claude_storage" in st:
        st = st.get("A25_claude_storage") or {}
    stale = len(st.get("cli", {}).get("stale") or []) + len(st.get("bundled", {}).get("stale") or [])
    if stale:
        return True
    return int(st.get("cleanable_bytes") or 0) >= STORAGE_CLEAN_THRESHOLD


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


def write_cleanup_manifest(reason: str, items: list, extra: dict = None) -> pathlib.Path:
    """把「这次删了什么」写成一份账本，落在备份目录里。

    为什么必须有：这些文件是直接 rmtree/unlink 的，不像改配置文件那样有备份可对照。
    clean_claude_storage 的注释写着「账本由调用方写」，但两条调用路径原先都没写，
    于是删掉几百 MB 之后除了终端输出查无此事（2026-10-13 发现并补上）。
    """
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    path = BACKUP_ROOT / f"cleanup-{stamp}.json"
    body = {
        "createdAt": dt.datetime.now().isoformat(),
        "reason": reason,
        "items": items,
        "totalBytes": sum(int(i.get("bytes") or 0) for i in items if i.get("ok")),
    }
    if extra:
        body.update(extra)
    path.write_text(json.dumps(body, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


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
            # The audit may be stale by the time CONFIRM is reached.  Re-run
            # the narrow dead-rule proof immediately before deleting anything;
            # a rule that became live is left untouched.
            live_dead = {
                permission_rule(e) for e in allow
                if permission_rule(e) and permission_is_dead(permission_rule(e))
            }
            keep = [e for e in allow
                    if permission_rule(e) not in rules or permission_rule(e) not in live_dead]
            removed = len(allow) - len(keep)
            if not removed:
                done.append({"file": rel, "removed": 0,
                             "error": "审计后状态已变化，未删除"})
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


def _dir_size_pair(p: pathlib.Path, sub: pathlib.Path | None = None) -> tuple[int, int]:
    """一次遍历同时给出目录总体积、以及其中某个子目录的体积。

    分开算会把子目录走两遍，而 `worktrees` 占项目级 `.claude` 的 99%：本机实测
    67 个目录 13.4 GB，走两遍要 43 秒，一遍砍掉一半。
    """
    total = 0
    sub_total = 0
    prefix = (str(sub).rstrip("/") + os.sep) if sub is not None else ""
    for dp, _dns, fns in os.walk(p, onerror=lambda e: None):
        for f in fns:
            full = os.path.join(dp, f)
            try:
                size = os.lstat(full).st_size
            except OSError:
                continue
            total += size
            if prefix and full.startswith(prefix):
                sub_total += size
    return total, sub_total


def _dir_size(p: pathlib.Path) -> int:
    """算目录实际占用。遇到读不到的条目跳过，不抛。"""
    return _dir_size_pair(p)[0]


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
                size, wt_size = _dir_size_pair(p, p / "worktrees")
                out["total_bytes"] += size
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

# Do not print a curl recipe containing the Clash bearer token.  The audit
# command is the supported safe reader; it keeps Authorization in Python
# memory while talking to the local Unix socket.
SOCK_HINT = "python3 scripts/account_guard.py --audit --json  # 读取 Clash 状态，secret 不进 argv"

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
         # 这里原来少了一个逗号：("…") 不是元组而是字符串，渲染步骤时按字符迭代，
         # 报告页上就成了竖排一个字一个 <li>。2026-10-15 用户看到并问起才修。
         ("先把本机残留清干净——这台机器上的体检与加固就是干这个的",
          "清干净之后再考虑下一步，不要当天就开新号"),
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
    ("八、登录方式（一次认证，别反复登）", (
        ("不要在 Claude Code 里做网页授权登录，改用 setup-token", "用户口径 2026-10-15",
         ("Claude Code 里不要执行登录、也不要走 claude auth login 的网页授权：认证那一刻的出口和这条登录事件绑在一起",
          "第一次买完（Google Play / App Store / 官网都行）就在一个干净环境里把账号认一次，装官方 App，安卓手机上装也行",
          "在终端跑 claude setup-token，按提示完成这一次认证，拿到长期有效的 token（实测口径是一年）",
          "把 token 放进 CLAUDE_CODE_OAUTH_TOKEN——写进 shell 配置，或写进 ~/.claude/settings.json 的 env",
          "之后 CLI 直接用这份凭据，不再走网页登录；只有掉线、换机、token 到期时才再跑一次 setup-token"),
         "网页端那种认证完还要频繁重登、连丢个包都要重登的方式最危险：每重登一次就是一条新的登录事件，而在 Claude Code 里登录等于把这条事件钉在当前出口上。本 skill 的「登录方式」那一行会读 claude auth status，告诉你这台机器现在用的是哪种"),
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
         ("# 修一：Chrome 设置 → 隐私和安全 → 网站设置 → 摄像头 → 不允许网站使用",
          "#       同一页把「麦克风」也设成不允许",
          "# 修二：装 WebRTC Network Limiter 扩展（文章推的就是它）",
          f"#       {WEBRTC_LIMITER_STORE_URL}",
          "#       本 skill 能把扩展包直接下下来：",
          "#       python3 scripts/account_guard.py --install-webrtc-limiter",
          "# 验：https://browserleaks.com/webrtc，看 Media Devices 里权限显示不是 Prompt"),
         "浏览器里没有开关能「授权之后仍藏住内网 IP」——mDNS 混淆只在页面没有摄像头/"
         "麦克风权限时生效，这是设计如此（P2P 媒体流需要真实局域网地址）。四个 "
         "webRTCIPHandlingPolicy 取值实测都没效果，它们是扩展 API 的参数不是命令行开关。"
         "所以两条路一起走：一是不让网站拿到权限，混淆就一直生效；二是装 "
         "WebRTC Network Limiter（商店里那个 Google 官方扩展），它做的正是往 "
         "webRTCIPHandlingPolicy 写 disable_non_proxied_udp —— 本机 Claude 资料里实测"
         "装的就是它，设置栏就是 disable_non_proxied_udp。装扩展那一下只能你自己点，"
         "Chrome 在 macOS 上不接受脚本代装。"),
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
         "应无输出。原文这条写得太宽：只要当前目录名里带 claude（比如就站在 cc-tackle 目录下），PWD 就会被命中，实测踩过。真要看代理就把它拆成 env | grep -i proxy"),
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
         (SOCK_HINT,),
         "应为 global。规则模式下有 GeoSite,cn,DIRECT 这类分支，不是「绝不直连」的形态"),
        ("GLOBAL 指向哪个组", "本会话补",
         (SOCK_HINT,),
         "应指向 Claude 专用组，且该组只有一个成员。只有 select 类型才不做健康检查切换"),
        ("实际走哪条链", "本会话补",
         (SOCK_HINT,),
         "链里应只有 GLOBAL → Claude → 节点。出现 DIRECT 或 自动切换 就是漏了"),
        ("Claude 规则排在最前", "本会话补",
         (SOCK_HINT,),
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
         "要分开看：svce='Claude Safe Storage' + acct='Claude Key' 是桌面版的加密存储，跟 CLI 的登录凭据不是一回事。CLI 算不算登录看「登录方式」那一行（读 claude auth status）——本机实测这条钥匙串条目和「CLI 有凭据」没有对应关系，别拿它推断"),
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
    print("        查看 JSON 里的 A12_clash_groups；不要把 Authorization 拼进 curl 参数。")
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


def _sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _backup_target(dest: pathlib.Path, path: pathlib.Path) -> pathlib.Path:
    return dest / "files" / str(path).lstrip("/").replace("/", "__")


def _file_state(path: pathlib.Path) -> dict:
    """Capture only states that the restore command can safely prove and restore."""
    if not path.exists() and not path.is_symlink():
        return {"exists": False, "type": "absent", "sha256": None, "mode": None}
    if path.is_symlink():
        raise RuntimeError(f"备份目标是 symlink，拒绝处理：{path}")
    if not path.is_file():
        return {"exists": True, "type": "directory", "sha256": None,
                "mode": path.stat().st_mode & 0o777}
    return {"exists": True, "type": "file", "sha256": _sha256_file(path),
            "mode": path.stat().st_mode & 0o777}


def _unsafe_home_link(path: pathlib.Path) -> bool:
    """Reject a target or lexical HOME parent that is a symlink.

    Checking before ``resolve()`` matters: resolving first would let a link
    inside HOME point outside the home tree while looking harmless.
    """
    path = pathlib.Path(path).expanduser()
    if path.is_symlink():
        return True
    home = pathlib.Path(os.path.abspath(os.path.expanduser(str(HOME))))
    lexical = pathlib.Path(os.path.abspath(os.path.expanduser(str(path))))
    if lexical != home and home not in lexical.parents:
        return False
    cur = lexical.parent
    while cur != home and home in cur.parents:
        if cur.is_symlink():
            return True
        cur = cur.parent
    return False


def _same_file_state(left: dict, right: dict) -> bool:
    return all(left.get(key) == right.get(key)
               for key in ("exists", "type", "sha256", "mode"))


def _write_manifest(path: pathlib.Path, manifest: dict) -> None:
    tmp = path.with_suffix(".json.tmp")
    payload = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    with tmp.open("wb") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    try:
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        # The atomic replace already prevents torn JSON; platforms without a
        # directory fsync leave the journal usable but less durable.
        pass


def _load_v2_manifest(backup: pathlib.Path) -> tuple[pathlib.Path, dict]:
    backup = backup.expanduser().resolve()
    root = BACKUP_ROOT.expanduser().resolve()
    if backup == root or root not in backup.parents:
        raise RuntimeError("备份目录不在 ClaudeGuardBackups 内，拒绝恢复")
    manifest_path = backup / "manifest.json"
    if manifest_path.is_symlink():
        raise RuntimeError("manifest 是 symlink，拒绝恢复")
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeError(f"无法读取备份 manifest：{manifest_path}") from error
    if raw.get("version") != 2 or not isinstance(raw.get("entries"), list):
        raise RuntimeError("只支持新的 v2 备份；旧 v1 清单不能自动恢复")
    for entry in raw["entries"]:
        if not isinstance(entry, dict) or not pathlib.Path(str(entry.get("path", ""))).is_absolute():
            raise RuntimeError("备份清单包含非绝对目标路径，拒绝恢复")
    return backup, raw


def _refresh_backup_manifest(backup: pathlib.Path, step: str) -> None:
    """Journal the state after a completed mutation step.

    Unknown post state intentionally remains unknown after a crash inside a
    mutation.  Restore then refuses to overwrite potentially newer user data.
    """
    if backup is None:
        return                      # 这次没有任何写操作，没有备份可记
    backup, manifest = _load_v2_manifest(backup)
    for entry in manifest["entries"]:
        path = pathlib.Path(entry["path"])
        try:
            state = _file_state(path)
        except (OSError, RuntimeError):
            entry["post"] = {"known": False}
            continue
        entry["post"] = {"known": True, **state}
    manifest.setdefault("steps", []).append({"name": step, "at": dt.datetime.now().isoformat()})
    manifest["pending_step"] = None
    _write_manifest(backup / "manifest.json", manifest)


def _mark_backup_in_progress(backup: pathlib.Path, step: str) -> None:
    """Mark a mutation before its first write; SIGKILL then fails closed."""
    if backup is None:
        return                      # 这次没有任何写操作，没有备份可记（见 main 的 will_write）
    backup, manifest = _load_v2_manifest(backup)
    manifest["pending_step"] = step
    manifest.setdefault("steps", []).append({"name": step + ":in-progress",
                                               "at": dt.datetime.now().isoformat()})
    _write_manifest(backup / "manifest.json", manifest)


def create_backup(paths: list[pathlib.Path], sudo_paths: list[pathlib.Path] | None = None,
                  manual_boundaries: list[str] | None = None) -> pathlib.Path:
    """在任何目标状态变更前，把要动的文件复制到带时间戳的备份目录。

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
    try:
        BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
        os.chmod(BACKUP_ROOT, 0o700)
        os.chmod(dest, 0o700)
        os.chmod(dest / "files", 0o700)
    except OSError as e:
        raise RuntimeError(f"备份目录权限设置失败：{e}") from e
    manifest: dict = {"version": 2, "created": dt.datetime.now().isoformat(),
                      "items": [], "sudo_items": [], "entries": [], "steps": [],
                      "manual_boundaries": list(manual_boundaries or [])}
    seen_paths = set()
    seen_targets = {}
    for p in paths:
        p = pathlib.Path(p).expanduser()
        if str(p) in seen_paths:
            continue
        seen_paths.add(str(p))
        home_lexical = pathlib.Path(os.path.abspath(os.path.expanduser(str(HOME))))
        path_lexical = pathlib.Path(os.path.abspath(os.path.expanduser(str(p))))
        if path_lexical != home_lexical and home_lexical not in path_lexical.parents:
            raise RuntimeError(f"自动备份目标不在 HOME 内，拒绝纳入自动恢复：{p}")
        if _unsafe_home_link(p):
            raise RuntimeError(f"备份目标或父目录是 symlink，拒绝自动改写：{p}")
        target_key = str(_backup_target(dest, p).relative_to(dest))
        previous = seen_targets.get(target_key)
        if previous is not None and previous != str(p):
            raise RuntimeError(f"备份路径编码冲突：{previous} 与 {p}")
        seen_targets[target_key] = str(p)
        state = _file_state(p)
        target = _backup_target(dest, p)
        entry = {"path": str(p), "before": state, "backup": None,
                 "post": {"known": False}}
        if not state["exists"]:
            manifest["entries"].append(entry)
            continue
        if state["type"] == "directory":
            # Directory restoration is intentionally manual.  The manifest still
            # records it, so an automatic restore can fail closed instead of
            # recursively replacing files that may have changed since the run.
            manifest["entries"].append(entry)
            continue
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, target)
        except OSError as e:
            raise RuntimeError(f"备份失败 {p}: {e}") from e
        try:
            if target.is_file():
                os.chmod(target, 0o600)
        except OSError as e:
            raise RuntimeError(f"备份权限设置失败 {target}: {e}") from e
        backup_sha = _sha256_file(target)
        after = _file_state(p)
        if not _same_file_state(state, after) or backup_sha != state.get("sha256"):
            raise RuntimeError(f"备份期间目标内容发生变化，已中止：{p}")
        entry["backup"] = {"relative": str(target.relative_to(dest)),
                            "sha256": backup_sha}
        manifest["entries"].append(entry)
        manifest["items"].append(str(p))
    for p in (sudo_paths or []):
        p = pathlib.Path(p).expanduser()
        # A root owned file may look absent to the unprivileged process.  Let
        # sudo cp prove whether it exists instead of silently treating it as
        # an absent original.
        try:
            accessible = p.exists()
        except OSError:
            accessible = False
        state = _file_state(p) if accessible else {
            "exists": True, "type": "file", "sha256": None, "mode": None}
        target = _backup_target(dest, p)
        target_key = str(target.relative_to(dest))
        previous = seen_targets.get(target_key)
        if previous is not None and previous != str(p):
            raise RuntimeError(f"备份路径编码冲突：{previous} 与 {p}")
        seen_targets[target_key] = str(p)
        entry = {"path": str(p), "before": state, "backup": None,
                 "post": {"known": False}, "sudo": True}
        target.parent.mkdir(parents=True, exist_ok=True)
        code, err = run(["sudo", "-n", "cp", "-p", str(p), str(target)], timeout=60)
        if code or not target.exists() or target.stat().st_size == 0:
            raise RuntimeError(
                f"需要 root 的备份失败：{p}（{err.strip()[:120] or '空文件'}），已中止以免在无备份的情况下改动"
            )
        entry["backup"] = {"relative": str(target.relative_to(dest)),
                            "sha256": _sha256_file(target)}
        manifest["entries"].append(entry)
        manifest["sudo_items"].append(str(p))
    manifest_path = dest / "manifest.json"
    _write_manifest(manifest_path, manifest)
    return dest


def restore_backup(backup: pathlib.Path, *, preview: bool = False,
                   selected: list[str] | None = None) -> int:
    """Restore only files whose current state still matches this run's journal."""
    backup, manifest = _load_v2_manifest(backup)
    if manifest.get("status") == "restored":
        for entry in manifest.get("entries", []):
            if entry.get("restore_status") != "restored":
                continue
            path = pathlib.Path(entry["path"]).expanduser()
            if _unsafe_home_link(path):
                raise RuntimeError(f"{path}：已恢复项目的目标或父目录是 symlink")
            current = _file_state(path)
            expected = entry.get("restore_state") or entry.get("before") or {}
            if not _same_file_state(current, expected):
                raise RuntimeError(f"{path}：已恢复项目随后发生外部改动，拒绝重复恢复")
        print("这份备份已经恢复过，未重复覆盖文件。")
        return 0
    if manifest.get("pending_step"):
        raise RuntimeError(f"备份记录显示步骤 {manifest['pending_step']} 未完成，拒绝自动恢复；请按备份路径人工核对")
    entries = manifest["entries"]
    selected_abs = None
    if selected:
        selected_abs = {str(pathlib.Path(x).expanduser().resolve()) for x in selected}
    targets = [e for e in entries if selected_abs is None or
               str(pathlib.Path(e["path"]).expanduser().resolve()) in selected_abs]
    if selected and len(targets) != len(selected_abs):
        raise RuntimeError("--restore-item 中有路径不在这份备份清单内")
    def changed_in_run(entry: dict) -> bool:
        before, post = entry.get("before") or {}, entry.get("post") or {}
        return any(before.get(key) != post.get(key)
                   for key in ("exists", "type", "sha256", "mode"))
    if selected_abs is None:
        targets = [entry for entry in targets
                   if changed_in_run(entry) and entry.get("restore_status") != "restored"]
    else:
        targets = [entry for entry in targets if entry.get("restore_status") != "restored"]
    home_root = HOME.expanduser().resolve()
    def outside_home(entry: dict) -> bool:
        if entry.get("sudo"):
            return False
        path = pathlib.Path(entry["path"]).expanduser()
        try:
            resolved = path.resolve()
        except OSError:
            return True
        return resolved != home_root and home_root not in resolved.parents

    unsupported = [e for e in targets
                   if (e.get("before") or {}).get("type") == "directory"
                   or (e.get("post") or {}).get("type") == "directory"
                   or e.get("sudo") or outside_home(e)]
    if unsupported and selected:
        raise RuntimeError("目录没有安全的自动恢复实现：" + "、".join(e["path"] for e in unsupported))
    if unsupported:
        print("以下项目不会自动恢复，请按备份目录手工处理：" +
              "、".join(e["path"] for e in unsupported), file=sys.stderr)
        targets = [e for e in targets if e not in unsupported]
    boundaries = manifest.get("manual_boundaries") or []
    if boundaries:
        print("自动恢复范围说明（以下项目不会由文件恢复自动完成）：", file=sys.stderr)
        for boundary in boundaries:
            print(f"  - {boundary}", file=sys.stderr)
    partial_restore = bool(unsupported or selected or boundaries)
    problems = []
    unsafe_link = _unsafe_home_link
    # A prior invocation may have restored one item before a later item
    # failed.  Before skipping that item on a retry, prove the user has not
    # changed it since the recorded restore state.
    for entry in entries:
        if entry.get("restore_status") != "restored":
            continue
        path = pathlib.Path(entry["path"]).expanduser()
        if unsafe_link(path):
            problems.append(f"{path}：已恢复项目的目标或父目录是 symlink")
            continue
        try:
            current = _file_state(path)
        except (OSError, RuntimeError) as error:
            problems.append(f"{path}：无法核对已恢复状态（{error}）")
            continue
        expected_state = entry.get("restore_state") or entry.get("before") or {}
        if not _same_file_state(current, expected_state):
            problems.append(f"{path}：已恢复项目随后发生外部改动，拒绝续跑")
    for entry in targets:
        if entry.get("sudo"):
            problems.append(f"{entry.get('path')}：root 文件只能按备份路径手工恢复")
            continue
        if not (entry.get("post") or {}).get("known"):
            problems.append(f"{entry.get('path')}：写后状态未知（可能在步骤中断）")
            continue
        path = pathlib.Path(entry["path"]).expanduser()
        before = entry.get("before") or {}
        post = entry.get("post") or {}
        if unsafe_link(path):
            problems.append(f"{path}：目标或父目录是 symlink")
            continue
        if before.get("type") == "directory" or post.get("type") == "directory":
            problems.append(f"{path}：目录恢复需人工处理，自动恢复拒绝")
            continue
        try:
            current = _file_state(path)
        except (OSError, RuntimeError) as error:
            problems.append(f"{path}：无法读取当前状态（{error}）")
            continue
        if not _same_file_state(current, post):
            problems.append(f"{path}：当前内容已漂移，拒绝覆盖")
            continue
        backup_info = entry.get("backup")
        if before.get("exists"):
            if not backup_info:
                problems.append(f"{path}：缺少文件备份")
                continue
            source = (backup / backup_info.get("relative", "")).resolve()
            if backup not in source.parents or not source.is_file() or source.is_symlink():
                problems.append(f"{path}：备份路径越界或不是普通文件")
                continue
            if _sha256_file(source) != backup_info.get("sha256"):
                problems.append(f"{path}：备份内容校验失败")
                continue
        # All checks above are read-only.  Parent creation is deliberately
        # deferred until after CONFIRM and the lock-held recheck below.
    if problems:
        raise RuntimeError("恢复拒绝：" + "；".join(problems))
    if preview:
        for entry in targets:
            print(f"可恢复：{entry['path']}")
        return 0
    print("本次将执行的文件恢复：")
    for entry in targets:
        action = "覆盖为备份中的原内容" if (entry.get("before") or {}).get("exists") else "删除本轮新建文件"
        print(f"  - {entry['path']}：{action}")
    if not targets:
        print("  （没有可自动恢复的本轮文件改动）")
        if boundaries or unsupported:
            print("  仅剩人工边界，未声称已完成全量恢复。", file=sys.stderr)
            return 2
        return 0
    if not sys.stdin.isatty():
        raise RuntimeError("恢复需要真实 TTY")
    if input("确认按这份 v2 备份恢复以上文件？输入 CONFIRM：").strip() != "CONFIRM":
        print("已取消，没有恢复任何文件。")
        return 1
    locked, note = acquire_run_lock()
    if not locked:
        raise RuntimeError(note)
    try:
        # The preview/confirmation may have taken time.  Re-read and repeat
        # the drift and backup checks while holding the lock immediately before
        # the first write.
        _, locked_manifest = _load_v2_manifest(backup)
        manifest = locked_manifest
        locked_entries = locked_manifest["entries"]
        locked_by_path = {e.get("path"): e for e in locked_entries}
        locked_targets = []
        for entry in targets:
            if entry.get("sudo"):
                raise RuntimeError(f"{entry['path']} 是 root 文件，只能手工恢复")
            current_entry = locked_by_path.get(entry.get("path"))
            if current_entry is None or not (current_entry.get("post") or {}).get("known"):
                raise RuntimeError(f"{entry['path']} 写后状态未知，拒绝恢复")
            path = pathlib.Path(current_entry["path"]).expanduser()
            if unsafe_link(path):
                raise RuntimeError(f"{path} 目标或父目录是 symlink，拒绝恢复")
            current = _file_state(path)
            post = current_entry["post"]
            if not _same_file_state(current, post):
                raise RuntimeError(f"{path} 当前内容已漂移，拒绝覆盖")
            if (current_entry.get("before") or {}).get("exists"):
                info = current_entry.get("backup") or {}
                source = (backup / info.get("relative", "")).resolve()
                if backup not in source.parents or not source.is_file() or source.is_symlink():
                    raise RuntimeError(f"{path} 备份路径越界或不是普通文件")
                if _sha256_file(source) != info.get("sha256"):
                    raise RuntimeError(f"{path} 备份内容校验失败")
            locked_targets.append(current_entry)
        targets = locked_targets
        for entry in targets:
            path = pathlib.Path(entry["path"]).expanduser()
            before = entry["before"]
            # Repeat the complete target check immediately before the actual
            # mutation.  The earlier locked preflight can still be separated
            # from this item by another item's I/O; in particular, never let a
            # newly inserted parent symlink redirect unlink() outside HOME.
            if _unsafe_home_link(path):
                raise RuntimeError(f"{path} 目标或父目录是 symlink，拒绝恢复")
            current = _file_state(path)
            if not _same_file_state(current, entry.get("post") or {}):
                raise RuntimeError(f"{path} 写入前当前内容已漂移，拒绝覆盖")
            if before.get("exists"):
                path.parent.mkdir(parents=True, exist_ok=True)
                if _unsafe_home_link(path):
                    raise RuntimeError(f"{path} 父目录在写入前变成 symlink，拒绝恢复")
                current = _file_state(path)
                if not _same_file_state(current, entry.get("post") or {}):
                    raise RuntimeError(f"{path} 写入前当前内容已漂移，拒绝覆盖")
            if before.get("exists"):
                source = (backup / entry["backup"]["relative"]).resolve()
                fd, tmp_name = tempfile.mkstemp(prefix=".claude-guard-restore-",
                                                dir=str(path.parent))
                tmp = pathlib.Path(tmp_name)
                try:
                    with os.fdopen(fd, "wb") as out, source.open("rb") as inp:
                        shutil.copyfileobj(inp, out)
                        out.flush()
                        os.fsync(out.fileno())
                    os.chmod(tmp, before.get("mode") or 0o600)
                    if _sha256_file(tmp) != (before.get("sha256") or ""):
                        raise RuntimeError(f"{path} 临时恢复文件校验失败")
                    os.replace(tmp, path)
                except BaseException:
                    try:
                        tmp.unlink()
                    except OSError:
                        pass
                    raise
            elif current.get("exists"):
                path.unlink()
            state = _file_state(path)
            if not _same_file_state(state, before):
                raise RuntimeError(f"{path} 恢复后复验失败")
            # Persist each completed mutation.  If the next item fails, a
            # subsequent explicit restore can skip this item safely instead of
            # treating its restored state as unexplained external drift.
            entry["restore_status"] = "restored"
            entry["restore_state"] = state
            _write_manifest(backup / "manifest.json", manifest)
        manifest["status"] = "partial-restored" if partial_restore else "restored"
        manifest["restoredAt"] = dt.datetime.now().isoformat()
        _write_manifest(backup / "manifest.json", manifest)
        return 0
    finally:
        release_run_lock()


def backup_paths_for_plan(plan: dict, report: dict, selected: dict | None = None) -> tuple[list[pathlib.Path], list[pathlib.Path]]:
    """Build the complete pre-change backup set from the displayed plan."""
    selected = selected or {}
    paths = [SETTINGS, HOME / ".claude.json", HOME / ".npmrc",
             HOME / ".gitconfig", HOME / ".config" / "git" / "config"]
    if selected.get("wrapper", True):
        paths.append(HOME / ".local" / "bin" / "claude-safe")
    if selected.get("browser_locale", True):
        paths.append(LOCALE_ROLLBACK_FILE)
    paths.extend(HOME / name for name in (plan.get("rc_files") or {}))
    if selected.get("dead_permissions", True):
        for d in (report.get("A26_claude_settings") or {}).get("dead") or []:
            paths.append(HOME / d["file"])
    # Deletions are irreversible without a copy.  Include every selected
    # project cleanup path before allowing the first write.
    if not selected.get("project_junk", True):
        return list(dict.fromkeys(paths)), []
    for root in project_roots():
        if not root.is_dir():
            continue
        for dp, dns, fns in os.walk(root, onerror=lambda _e: None):
            p = pathlib.Path(dp)
            if "worktrees" in p.parts or "node_modules" in p.parts:
                dns[:] = []
                continue
            if ".claude" not in p.parts:
                continue
            for name in fns:
                if name == ".DS_Store":
                    paths.append(p / name)
            for name in dns:
                if name == "__pycache__":
                    paths.append(p / name)
    return list(dict.fromkeys(paths)), []


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
    want = dict(env)
    if before == want:
        # 复验要拿「目标状态」比，不能拿「改动前的状态」比。键本来就是 1 时这次写入
        # 不产生任何变化，拿 before 比会把「已经是对的」判成「写入未生效」——
        # 2026-10-15 实测就误报过这一次，而且调用点没兜住异常，流程停在 [3/6]，
        # 后面几步全没跑。这里连文件都不改写，直接返回。
        return "目标键本来就是这些值，无需改动（未改写 settings.json）"
    data["env"] = want
    write_json(SETTINGS, data)
    after = dict(read_json(SETTINGS, {}).get("env", {}) or {})
    if after != want:
        raise RuntimeError(
            f"遥测键写入后复验未生效：期望 {sorted(want)}，实际 {sorted(after)}"
        )
    changed = [k for k in want if before.get(k) != want.get(k)]
    return f"已写入 {', '.join(changed)}"


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
        "# cc-tackle: 文章 2.6 —— 授权链接不交给默认浏览器\n"
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

    第三种情况：报告之后这条已经被别人清干净了（实测定时脚本
    local.proxy-residue-cleanup 会抢在前面）——目标状态本来就达到了，
    跳过并记进 clear_proxy_residue.skipped，不算失败。
    """
    cleared = 0
    skipped = 0
    for item in residue:
        svc, kind = item["service"], item["kind"]
        code, before_body = run(["networksetup", f"-get{kind}", svc])
        before_enabled = re.search(r"Enabled:\s*(\w+)", before_body)
        before_server = re.search(r"Server:\s*(\S*)", before_body)
        before_port = re.search(r"Port:\s*(\S*)", before_body)
        if code or not before_enabled or not before_server or not before_port:
            raise RuntimeError(f"{svc}/{kind} 读不到当前状态，拒绝清理")
        if before_enabled.group(1).lower() != "no":
            # 报告之后被打开了：这条已经不是在用之外的值，碰它可能断网。
            raise RuntimeError(f"{svc}/{kind} 在确认后变成了启用状态，拒绝清理")
        if before_server.group(1) in ("", "0.0.0.0") and before_port.group(1) in ("", "0"):
            # 报告之后已经被别人清掉了（实测：定时脚本 local.proxy-residue-cleanup 会抢在前面），
            # 目标状态本来就达到了，不算失败。
            skipped += 1
            continue
        if (before_server.group(1) != str(item.get("server", ""))
                or before_port.group(1) != str(item.get("port", ""))):
            raise RuntimeError(f"{svc}/{kind} 在确认后换成了别的值，拒绝清理")
        code, body = run(["networksetup", f"-set{kind}", svc, "0.0.0.0", "0"])
        if code:
            raise RuntimeError(f"{svc}/{kind} 清理失败：{body.strip()[:160]}")
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
    clear_proxy_residue.skipped = skipped     # 已经是干净的那些，给调用方措辞用
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
        # Audit-to-confirmation is a TOCTOU window.  Recheck every planned line
        # before deleting it, including its byte fingerprint when available.
        for hit in hits:
            index = int(hit["line"]) - 1
            if index < 0 or index >= len(lines):
                raise RuntimeError(f"{p} 第 {hit['line']} 行已变化，拒绝删除")
            current = lines[index].rstrip("\r\n")
            expected_hash = hit.get("sha256")
            if expected_hash:
                unchanged = hmac.compare_digest(
                    hashlib.sha256(current.encode()).hexdigest(), expected_hash)
            else:
                unchanged = (redact_credentials(current.strip())[:120] == hit.get("text", ""))
            if not unchanged:
                raise RuntimeError(f"{p} 第 {hit['line']} 行已变化，拒绝删除")
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
        code, body = run(["npm", "config", "delete", key])
        if code:
            raise RuntimeError(f"npm:{key} 删除失败：{body.strip()[:160]}")
        code, left = run(["npm", "config", "get", key])
        if code:
            raise RuntimeError(f"npm:{key} 复验失败：{left.strip()[:160]}")
        if left.strip().lower() in ("", "undefined", "null"):
            done.append(f"npm:{key}")
        else:
            raise RuntimeError(f"npm:{key} 删除后仍有值")
    for key in ("http.proxy", "https.proxy"):
        code, body = run(["git", "config", "--global", "--unset", key])
        # git returns 5 when a key is absent; a planned key is expected to
        # exist, so any other error is a real partial failure.
        if code not in (0, 5):
            raise RuntimeError(f"git:{key} 删除失败：{body.strip()[:160]}")
        code, left = run(["git", "config", "--global", "--get", key])
        if code not in (0, 1):
            raise RuntimeError(f"git:{key} 复验失败：{left.strip()[:160]}")
        if not left.strip():
            done.append(f"git:{key}")
        else:
            raise RuntimeError(f"git:{key} 删除后仍有值")
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


def reload_backend(info: dict, config_path) -> str:
    """让改完的配置生效。**只对官方明确支持重载的后端动手。**

      * sing-box：官方唯一的重载手段是 SIGHUP（cmd_run.go 里注册了它），
        收到后会先校验配置再重建实例；校验不过就跳过，不会把服务搞死。
      * v2ray / Xray：**绝不能发 SIGHUP** —— 它们只注册了 SIGINT 与 SIGTERM，
        SIGHUP 会走默认动作直接杀掉进程（main/run.go:105-107）。
      * Surge：走 HTTP API 的 POST /v1/profiles/reload。
      * mihomo：走 PUT /configs，由 clear_clash_dns_leak 负责。

    找不到进程、或进程用的不是我们改的那份配置时，什么都不做并如实说明。
    """
    backend = (info or {}).get("backend")
    path = pathlib.Path(str(config_path)) if config_path else None
    declared = running_config_for(backend) if backend else ""
    if declared and path is not None:
        try:
            if pathlib.Path(declared).resolve() != path.resolve():
                return f"正在跑的进程用的是 {declared}，不是刚改的这份，没有替你重载——请自己重启"
        except OSError:
            pass
    if backend == "singbox":
        code, out = run(["pgrep", "-f", "sing-box"], timeout=10)
        pids = [x.strip() for x in out.split() if x.strip().isdigit()]
        if not pids:
            return "没找到在跑的 sing-box 进程，改完的配置下次启动才生效"
        sent = []
        for pid in pids:
            if run(["kill", "-HUP", pid], timeout=10)[0] == 0:
                sent.append(pid)
        if not sent:
            return "给 sing-box 发 SIGHUP 失败，请自己重启它"
        return (f"已给 sing-box（pid {'、'.join(sent)}）发 SIGHUP 让它重载；"
                "配置校验不过它自己会跳过，重启后请再跑一次体检确认")
    if backend == "surge":
        controller = (info or {}).get("controller")
        if not controller:
            return "Surge 的 HTTP API 没开，改完的配置要在界面里重新载入"
        try:
            code, body = api_call(controller, "POST", "/v1/profiles/reload", body=b"{}")
        except (OSError, ValueError, TimeoutError, RuntimeError) as error:
            return f"调 Surge 重载失败（{error}），请在界面里重新载入"
        return ("已让 Surge 重新载入配置（HTTP %s）" % code) if 200 <= code < 300 \
            else f"Surge 重载返回 {code}，请在界面里确认"
    if backend in ("v2ray",):
        return ("v2ray / Xray 没有重载接口，而且给它们发 SIGHUP 会直接杀掉进程，"
                "所以脚本不碰你的进程——请自己重启它")
    return "这个后端没有脚本认识的重载方式，请自己重启它"


def _write_text_atomic(path: pathlib.Path, text: str) -> None:
    """同目录临时件写好后 rename，保留原权限。中途失败不留半个文件。"""
    path = pathlib.Path(path)
    tmp = path.with_name(path.name + ".guard-tmp")
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        mode = 0o644
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


FOREIGN_DNS_IPS = ("1.1.1.1", "8.8.8.8")


def _foreign_resolver(index: int) -> str:
    return FOREIGN_DNS_IPS[index % len(FOREIGN_DNS_IPS)]


def _looks_like_url(addr: str) -> bool:
    return str(addr).lower().startswith(("http", "tls", "quic", "h3"))


def _unfixed_cn_resolvers(backend: str, path) -> list:
    """按修复时那套跳过规则，看还剩哪些「本该换掉」的国内解析器。

    带 domains / expectIPs 的分流式解析器修复时是故意跳过的（改它们会改变
    分流语义），所以复读核对必须用同一个视角，否则会把它们报成没改干净。
    """
    if backend not in ("singbox", "v2ray"):
        return []
    try:
        cfg = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(cfg, dict):
        return []
    servers = (cfg.get("dns") or {}).get("servers") or []
    out = []
    for entry in servers:
        if isinstance(entry, dict) and (entry.get("domains") or entry.get("expectIPs")):
            continue
        addr = _resolver_address(entry)
        if addr and _resolver_is_cn(addr):
            out.append(addr)
    return out


def clear_other_proxy_dns(info: dict, facts: dict) -> str:
    """把别家后端配置里的国内解析器换成境外解析器。

    这条路只在 ``--fix-unverified`` 下走，原因写在这里免得日后被当成疏漏：
    配置我们能读、能改、能复读核对，但**「正在跑的那个进程有没有重新加载」验不了**——
    sing-box / v2ray 要重启进程，Surge 要在界面里重载 profile，各不相同。所以改完
    必须由用户自己重启那个软件，脚本把这一步说清楚，不假装已经生效。

    只动「解析器地址」这一件事：带 domains/expectIPs 的分流式解析器、以及代理侧
    的分流规则，一律不碰——那些改错就是断网或漏流量。
    """
    backend = (info or {}).get("backend")
    path_text = (facts or {}).get("config") or ((info or {}).get("config") or {}).get("path") or ""
    if not path_text:
        raise RuntimeError("不知道配置文件在哪，拒绝修改")
    path = pathlib.Path(path_text)
    if not path.is_file():
        raise RuntimeError(f"配置文件不存在：{path}")
    ext = path.suffix.lower()
    changed = []

    if backend in ("singbox", "v2ray"):
        try:
            cfg = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise RuntimeError(f"读不出 {path.name}：{error}") from error
        if not isinstance(cfg, dict):
            raise RuntimeError(f"{path.name} 顶层不是对象，拒绝修改")
        dns = cfg.get("dns")
        if not isinstance(dns, dict):
            raise RuntimeError(f"{path.name} 里没有 dns 块，拒绝凭空造一个")
        servers = dns.get("servers")
        if not isinstance(servers, list):
            raise RuntimeError(f"{path.name} 的 dns.servers 不是列表，拒绝修改")
        for i, entry in enumerate(servers):
            if isinstance(entry, dict) and (entry.get("domains") or entry.get("expectIPs")):
                continue  # 分流用的解析器，语义特殊，不碰
            addr = _resolver_address(entry)
            if not addr or not _resolver_is_cn(addr):
                continue
            repl = _foreign_resolver(len(changed))
            if isinstance(entry, dict):
                if "server" in entry:
                    entry["server"] = repl
                elif "address" in entry:
                    entry["address"] = repl
                else:
                    continue
            else:
                servers[i] = ("https://" + repl + "/dns-query") if _looks_like_url(addr) else repl
            changed.append(addr)
        if not changed:
            return "配置里没有国内解析器，无需改动"
        _write_text_atomic(path, json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")

    elif backend == "surge":
        text = path.read_text(encoding="utf-8", errors="replace")
        out_lines = []
        for line in text.splitlines(keepends=True):
            stripped = line.strip()
            if "=" not in stripped or not stripped.lower().startswith("dns-server"):
                out_lines.append(line)
                continue
            key, _, value = stripped.partition("=")
            items = [x.strip() for x in value.split(",")]
            new_items = []
            for item in items:
                if item and _resolver_is_cn(item):
                    new_items.append(_foreign_resolver(len(changed)))
                    changed.append(item)
                else:
                    new_items.append(item)
            indent = line[: len(line) - len(line.lstrip())]
            end = "\n" if line.endswith("\n") else ""
            out_lines.append(f"{indent}{key.strip()} = " + ", ".join(new_items) + end)
        if not changed:
            return "配置里没有国内解析器，无需改动"
        _write_text_atomic(path, "".join(out_lines))
    else:
        raise RuntimeError(f"脚本不认识 {backend} 的配置格式，拒绝修改")

    # 复读核对。注意这里要按「我们会不会动它」的同一套规则去看还剩谁：
    # 带 domains 的分流解析器是被故意跳过的，拿「还有没有国内解析器」去判，
    # 会把它们误报成没改干净（2026-10-15 的用例抓到的就是这个）。
    if backend == "surge":
        left = [x for x in (read_surge_facts(path.read_text(encoding="utf-8", errors="replace"))
                            .get("dns_cn") or []) if x]
    else:
        left = _unfixed_cn_resolvers(backend, path)
    if left:
        raise RuntimeError(f"复读核对没通过，还有该换的国内解析器：{left[:3]}；请从备份恢复")
    names = "、".join(changed[:3])
    reload_note = reload_backend(info, path)
    return (f"已把 {len(changed)} 个国内解析器（{names}）换成 {'、'.join(FOREIGN_DNS_IPS)}；"
            f"改的是 {path.name}。{reload_note}")


def other_proxy_dns_plan(report: dict) -> dict:
    """别家后端的 DNS 修复计划。mihomo 走原有的 clear_clash_dns_leak。"""
    pb = report.get("A28_proxy_backend") or {}
    backend = pb.get("backend") or ""
    facts = pb.get("facts") or {}
    dns = facts.get("dns") or {}
    if backend in ("singbox", "v2ray", "surge") and (dns.get("cn") or []):
        return {"needed": True, "backend": backend, "path": facts.get("config") or "",
                "targets": list(dns.get("cn") or []),
                "verify": "restart", "fix_mode": (pb.get("capabilities") or {}).get("fix_mode", "")}
    return {"needed": False, "backend": backend, "path": "", "targets": [], "verify": "",
            "fix_mode": ""}


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

    try:
        code_s, _ = clash_http(
            "PUT", "/configs",
            json.dumps({"path": str(clash_config()), "force": True}).encode(),
            timeout=10,
        )
    except (OSError, ValueError, TimeoutError, RuntimeError):
        # Tests may replace the command runner while using a missing socket;
        # this fixture carries only method/path and never the authorization.
        if not (clash_socket() or CLASH_SOCK).is_socket():
            fixture_code, fixture_body = run(["__claude_guard_clash_fixture__", "PUT", "/configs"], timeout=10)
            code_s = int((fixture_body or "0").strip()) if fixture_code == 0 and (fixture_body or "").strip().isdigit() else 0
        else:
            code_s = 0
    if code_s not in (200, 204):
        raise RuntimeError(
            "Clash 配置已写入，但内核重载失败（HTTP " + (str(code_s) if code_s else "无响应") + "），"
            "请按备份路径回滚或手动重载"
        )

    after = check_clash_dns()
    # 复验条件直接复用 clash_dns_leaking，不再自己列一遍——两处各写一份迟早会漂移，
    # 补了 dns.enable 与 dns-hijack 之后这边如果不跟着改，就会「检查报待处理、清理报成功」。
    if clash_dns_leaking({"A6_dns": {"clash": after}}):
        raise RuntimeError(
            "改完复验仍不合格：leaking=" + repr(after.get("leaking"))
            + " respect-rules=" + repr(after.get("respect_rules"))
            + " enable=" + repr(after.get("enabled"))
            + " dns-hijack=" + repr(after.get("hijack")))
    tail = "内核已重载"
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
    if "timed" not in key.lower() and "timezone" not in key.lower():
        continue
    # 保留异常条目的形状信号，但不要把原始 plist 值回传到 stdout。
    if not isinstance(val, dict):
        out[key] = None
    else:
        out[key] = {k: v for k, v in val.items() if k != "ClientStorageToken"}
sys.stdout.write(json.dumps(out, default=str))
'''


def location_service_status(*, persist: bool = True) -> dict:
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
    if not persist and os.geteuid() != 0:
        out["note"] = "只读审计不调用 sudo 探针；需要 root 才能复核定位服务状态"
        return out
    # Keep the read path genuinely read-only: pass the tiny plist probe via
    # Python's -c argument instead of creating and deleting a temporary file.
    command = ["python3", "-c", LOCATION_PROBE]
    if os.geteuid() != 0:
        command.insert(0, "-n")
        command.insert(0, "sudo")
    code, body = run(command, timeout=30)
    if code:
        out["note"] = "读不到 /var/db/locationd/clients.plist（需要 root；先 sudo_prime 再执行）"
        return out
    try:
        data = json.loads(body or "{}")
    except json.JSONDecodeError:
        out["note"] = "clients.plist 解析失败，格式与预期不符，已放弃自动处理"
        return out
    if not isinstance(data, dict):
        out["note"] = "clients.plist 解析结果不是对象，已放弃自动处理"
        return out
    out["readable"] = True
    malformed = False
    for key, val in data.items():
        if not isinstance(val, dict):
            # 合法 JSON 也可能有形状异常的条目；不要让它触发
            # AttributeError，更不能让同一份部分读数被当成完整通过证据。
            malformed = True
            out["clients"][key] = {
                "Authorized": None,
                "state": "未知（条目格式异常）",
                "stopped": None,
                "BundlePath": None,
            }
            if "timed" in key.lower():
                out["timed_present"] = True
            continue
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
    if malformed:
        out["readable"] = False
        out["note"] = "clients.plist 含格式异常的客户端条目，已放弃自动处理"
        return out
    if out["clients"] and persist:
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
    fresh, _ = cache_is_fresh(d, require_profile_scope=False)
    if not fresh:
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
    loc = location_service_status(persist=False)
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

def audit(*, persist: bool = False, expected_country: str | None = None,
          expected_exit_ip: str | None = None) -> dict:
    # Normal audits are read-only.  The explicit opt-in is used only when a
    # caller wants export history to be updated for the next comparison.
    expected_country, expected_exit_ip = declared_expected(expected_country, expected_exit_ip)
    if persist:
        # 只有允许写状态的调用才落盘：只读 --audit 一个字节都不写。
        remember_declared_expected(expected_country, expected_exit_ip)
    ip = check_export_ip(persist=persist)  # 出口 IP 只查一次，一致性检查复用同一结果
    scope = claude_config_scope()
    expected = expected_exit_result(ip, expected_country, expected_exit_ip)
    report = {
        "timestamp": dt.datetime.now().isoformat(),
        "scope_manifest": scope,
        "out_of_scope": scope["out_of_scope"],
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
        "A28_proxy_backend": _proxy_backend_report(),
        "A29_cli_login": check_cli_login(),
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
        "A27_browser_locale": check_browser_locale(ip, expected),
        "E1_keychain": check_keychain(),
    }
    report["A1_export_ip"]["expected"] = expected
    return report


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
    expected = ip.get("expected") or {}
    print(f"  预期出口：{expected.get('expected')} → {expected.get('status')}；"
          f"{expected.get('reason') or ''}")
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
                      + " —— 国外域名的解析交给了它们，确认后可按选择替换")
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
    pb = r.get("A28_proxy_backend") or {}
    if pb:
        print(f"  代理后端：{pb.get('label')}")
        for ev in (pb.get("evidence") or []):
            print(f"    · 依据 {ev.get('kind')}：{ev.get('value')}")
        caps = pb.get("capabilities") or {}
        skills = [
            "能读 DNS" if caps.get("read_dns") else "读不到 DNS",
            "能读分流" if caps.get("read_routing") else "读不到分流",
            "能改 DNS" if caps.get("fix_dns") else "不改 DNS",
        ]
        skills.append("改完可复验" if caps.get("verify_after_write") else "改完无法就地复验")
        print("    · 能力：" + "；".join(skills))
        for note in (pb.get("notes") or []):
            print(f"      {note}")
        for note in ((pb.get("facts") or {}).get("dns") or {}).get("limits") or []:
            print(f"      DNS 边界：{note}")
        for note in ((pb.get("facts") or {}).get("routing") or {}).get("limits") or []:
            print(f"      分流边界：{note}")
        for note in ((pb.get("capture") or {}).get("notes") or []):
            print(f"    · 接管：{note}")
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
        tried = "、".join(g.get("sock_tried") or [])
        print("  Clash   ：控制接口不可达，跳过" + (f"（试过：{tried}）" if tried else ""))

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

    这些残留默认按计划清理；Clash/Chrome 和不可原样回滚的清理另行询问：
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
    if st_bytes and storage_worth_cleaning(st):
        n_stale = len(st.get("cli", {}).get("stale") or []) + len(st.get("bundled", {}).get("stale") or [])
        summary.append(
            f"系统级可清理 {human_bytes(st_bytes)}："
            f"被取代的旧版本 {n_stale} 份 + 可再生缓存 {len(st.get('caches') or [])} 个（不可原样回滚，默认不清）"
        )

    cs = report.get("A26_claude_settings") or {}
    if cs.get("dead"):
        summary.append(
            f"项目级 settings 里失效的权限条目 {len(cs['dead'])} 条（已列入备份，默认不清）"
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
            f"（只划掉登记记录，不删任何工作树；元数据变更不可原样回滚，默认不清）"
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
    browser_locale = bool(bl.get("cn") and (bl.get("country") or "") not in ("", "CN")
                          and not bl.get("target_blocked"))
    if browser_locale:
        summary.append(
            f"浏览器 Intl 区域设置是 {bl.get('measured')}（大陆简体），出口却是 "
            f"{bl.get('country')} —— 会把 Chrome 的应用语言设为 {bl.get('target')}"
            f"（只影响 Chrome，系统语言不动；要重启 Chrome 才生效，默认不改）"
        )
    elif bl.get("target_blocked"):
        summary.append("预期出口不符，已跳过按实测国家修改 Chrome Intl")

    other_dns = other_proxy_dns_plan(report)
    if other_dns["needed"]:
        summary.append(
            f"别家代理 DNS：{PROXY_BACKEND_LABELS.get(other_dns['backend'], other_dns['backend'])} "
            f"配置里有国内解析器（{'、'.join(other_dns['targets'][:2])}）——改它要显式加 "
            f"--fix-unverified，且改完要重启那个软件才生效"
        )
    return {
        "other_proxy_dns": other_dns,
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
        "storage_bytes": st_bytes if storage_worth_cleaning(st) else 0,
        "dead_permissions": len(cs.get("dead") or []),
        "project_junk": bool(project_roots()),
        "nonrestorable": bool(st_bytes or stale_repos),
        "summary": summary,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="按四层防线做 Claude 本机体检与加固")
    ap.add_argument("--audit", action="store_true", help="只读体检，不做任何修改")
    ap.add_argument("--fix-unverified", action="store_true",
                    help="允许修改脚本无法就地复验的别家代理配置（sing-box / v2ray / Surge 的 DNS）；"
                         "会先备份，改完要你自己重启那个软件才生效")
    ap.add_argument("--report", action="store_true",
                    help="结束时落一份 HTML 报告（只读模式下也能用，不写 JSON 与状态）")
    ap.add_argument("--save-audit", action="store_true",
                    help="审计完成后显式保存报告与出口历史（默认 --audit 不落盘）")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出体检结果")
    ap.add_argument("--expected-country", type=normalize_expected_country,
                    help="声明预期出口国家（ISO 两字母，例如 US）；"
                         f"也可以用环境变量 {EXPECTED_COUNTRY_ENV}")
    ap.add_argument("--expected-exit-ip", type=normalize_expected_ip,
                    help="声明预期出口 IP；只接受合法 IPv4/IPv6；"
                         f"也可以用环境变量 {EXPECTED_EXIT_IP_ENV}")
    ap.add_argument("--restore", metavar="BACKUP_DIR",
                    help="从 v2 备份显式恢复；需要真实 TTY 和 CONFIRM")
    ap.add_argument("--restore-preview", action="store_true",
                    help="只预览备份恢复计划，不写任何文件")
    ap.add_argument("--restore-item", action="append", default=[], metavar="PATH",
                    help="恢复备份中的指定文件，可重复；默认恢复全部可恢复文件")
    ap.add_argument("--webrtc", action="store_true", help="附加 WebRTC 泄漏探测（直接启动可用 Chromium）")
    ap.add_argument("--check-media", action="store_true",
                    help="起一个本地页面，用你日常浏览器确认摄像头/麦克风权限（WebRTC 那一项靠它转正）")
    ap.add_argument("--check-locale", action="store_true",
                    help="起一个本地页面，用你日常浏览器把 Intl 区域设置回传回来")
    ap.add_argument("--install-webrtc-limiter", action="store_true",
                    help="下载 WebRTC Network Limiter 扩展包并打开商店页"
                         "（安装那一下仍要你自己点，Chrome 不允许脚本代装）")
    ap.add_argument("--verify-browser", action="store_true",
                    help="配合 --audit：体检前脚本自己打开复核页，把 Intl 与媒体权限收回来（会写复核缓存）")
    ap.add_argument("--commands", action="store_true", help="只打印手工核对用的终端命令清单，不体检")
    ap.add_argument("--manual", action="store_true", help="只打印必须人工做的行动清单（带点击路径），不体检")
    args = ap.parse_args(argv)

    if args.verify_browser and not args.audit:
        print("拒绝组合：--verify-browser 只配合 --audit 使用；单独复核用 --check-locale 或 --check-media。",
              file=sys.stderr)
        return 2

    if args.restore_preview and not args.restore:
        print("--restore-preview 必须和 --restore 一起使用。", file=sys.stderr)
        return 2
    if args.restore:
        if any((args.audit, args.json, args.save_audit, args.check_media,
                args.check_locale, args.commands, args.manual)):
            print("拒绝组合：--restore 只能单独运行，不能和审计、JSON、缓存检查或命令清单混用。",
                  file=sys.stderr)
            return 2
        if running_under_claude():
            print("拒绝执行：恢复会改本机状态，请改用普通终端。", file=sys.stderr)
            return 2
        if not args.restore_preview and not sys.stdin.isatty():
            print("拒绝执行：恢复需要真实 TTY 完成知情确认。", file=sys.stderr)
            return 2
        try:
            return restore_backup(pathlib.Path(args.restore), preview=args.restore_preview,
                                  selected=args.restore_item or None)
        except (OSError, ValueError, RuntimeError) as error:
            print(f"恢复停止：{error}", file=sys.stderr)
            return 2

    if args.audit and (args.check_media or args.check_locale):
        print("拒绝组合：--audit 是只读模式，不能同时运行会写浏览器缓存的 --check-media/--check-locale。",
              file=sys.stderr)
        return 2

    if args.check_media:

        verify_media_permission(auto_open=True)

        return 0

    if args.check_locale:

        verify_browser_locale(auto_open=True)

        return 0


    if args.commands:
        print_manual_checks()
        return 0
    if args.manual:
        print_manual_actions()
        return 0

    if args.save_audit and not (args.audit or args.json):
        print(
            "拒绝执行：--save-audit 只适用于 --audit 或 --json 审计；"
            "完整加固请先用 --audit --save-audit 保存报告，再单独运行加固。",
            file=sys.stderr,
        )
        return 2

    if args.install_webrtc_limiter:
        # 只下载一个包 + 打开一个页面，不改本机配置，所以不需要 TTY，也不受
        # 「Claude Code 里只放行只读」那条限制（安装那一下仍旧只能你自己点）。
        return 0 if install_webrtc_limiter()["ok"] else 2

    # --verify-browser 会打开一个浏览器页面并写复核缓存，所以它不算只读模式：
    # 在 Claude Code 里仍旧只放行纯 --audit。
    read_only_run = args.audit and not args.verify_browser
    under_claude = running_under_claude()
    if under_claude and not read_only_run:
        print("拒绝执行：当前脚本由 Claude Code 启动。加固步骤会改本机状态，请改用普通终端；这里只允许 --audit。", file=sys.stderr)
        return 2
    if not args.audit:
        scope = claude_config_scope()
        if scope.get("custom"):
            print(
                "拒绝加固：CLAUDE_CONFIG_DIR 指向自定义目录 "
                f"{scope.get('configured_config_dir')}。本轮未扫描或修改该目录；"
                "请先切回默认目录，或为自定义目录建立明确的受支持范围。",
                file=sys.stderr,
            )
            return 2
    # 加固模式必须在真实 TTY 下运行；放在体检之前，管道里调用就立刻失败，不必先跑完全套只读检查
    if not args.audit and not sys.stdin.isatty():
        print("拒绝执行：需要真实 TTY 完成知情确认。", file=sys.stderr)
        return 2

    if args.verify_browser:
        # 顺序不能反：audit() 读的正是这两份复核缓存，先体检再复核等于白跑一次。
        # --json 模式下 stdout 只能是那一个 JSON 文档（自检脚本靠它解析），
        # 复核过程打的进度行必须让到 stderr，否则整份 JSON 解析不了。
        sink = (contextlib.redirect_stdout(sys.stderr) if args.json
                else contextlib.nullcontext())
        with sink:
            verify_browser_locale(auto_open=True)
            verify_media_permission(auto_open=True)
            print()

    try:
        # Full repair cannot persist audit state before CONFIRM; --save-audit is
        # rejected above for this mode.
        report = audit(persist=args.save_audit and (args.audit or args.json),
                       expected_country=args.expected_country,
                       expected_exit_ip=args.expected_exit_ip)
        if args.webrtc:
            report["A7_webrtc"] = check_webrtc()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        # 只读体检也必须干净报错：早期版本把 audit() 放在 try 之外，
        # 任何一处探测失败都会抛 traceback，用户看到一堆栈帧却不知道发生了什么。
        print(f"体检失败：{error}\n本次没有做任何改动。", file=sys.stderr)
        return 2

    if args.json:
        if args.save_audit:
            print(f"报告已存：{save_audit_report(report)}", file=sys.stderr)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    print("CC tackle —— 四层防线的本机体检")
    print_audit(report)
    if args.audit:
        # 只读模式：体检完直接给总表
        print_summary_table(report)
        print("\n  想自己复核上面每一项：python3 scripts/account_guard.py --commands")
        print("  必须人工做的那些（带点击路径）：python3 scripts/account_guard.py --manual")
        if args.save_audit:
            p = save_audit_report(report)
            print(f"\n报告已存：{p}")
            try:
                from report_html import write_report
                print(f"HTML 版  ：{write_report(report, report_path=str(p))}")
            except Exception as error:
                print(f"HTML 版生成失败（上面的结论不受影响）：{error}", file=sys.stderr)
        elif args.report:
            # 只要一份 HTML，不要 JSON、不要状态：给同事或自己看一眼的那种用法。
            write_html_only(report, note="只有这一次体检，没有改动对照")
        elif getattr(args, "verify_browser", False):
            # 这次的两份浏览器复核缓存是脚本自己开的页面写下的，说「没写缓存」就是谎报。
            print("\n只读审计没写报告与出口历史；浏览器复核结果已存进 "
                  "~/.local/state/claude-guard/ 下的两份缓存。"
                  "需要留档加 --save-audit（含 JSON），只要 HTML 加 --report。")
        else:
            print("\n只读审计未写入报告、出口历史或缓存；"
                  "需要留档加 --save-audit（含 JSON），只要 HTML 加 --report。")
        return 0

    scope = report.get("scope_manifest") or {}
    if scope.get("custom"):
        print(
            "拒绝加固：CLAUDE_CONFIG_DIR 指向自定义目录 "
            f"{scope.get('configured_config_dir')}。本轮未扫描或修改该目录，"
            "因此不能在 CONFIRM、并发锁或备份前继续；请先切回默认目录，"
            "或为自定义目录建立明确的受支持范围。",
            file=sys.stderr,
        )
        return 2

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
        do_clash_dns = bool(plan.get("clash_dns")) and ask_yes(
            "修改 Clash DNS（会写配置并重载内核）？"
        )
        other_dns = plan.get("other_proxy_dns") or {}
        do_other_dns = bool(other_dns.get("needed")) and bool(args.fix_unverified)
        if other_dns.get("needed") and not args.fix_unverified:
            print(f"       别家代理 DNS：{PROXY_BACKEND_LABELS.get(other_dns.get('backend'), '')} "
                  f"配置里有国内解析器（{'、'.join((other_dns.get('targets') or [])[:2])}）；"
                  f"改它要显式加 --fix-unverified，改完还要重启那个软件——"
                  f"这次没动它，命令：python3 scripts/account_guard.py --fix-unverified")
        do_browser_locale = bool(plan.get("browser_locale")) and ask_yes(
            "修改 Chrome Intl 应用语言（会改 Chrome 偏好并需重启）？"
        )
        do_storage = bool(plan.get("storage_bytes")) and ask_yes(
            "清理旧 CLI/桌面副本与缓存（不可原样回滚）？"
        )
        do_dead_permissions = bool(plan.get("dead_permissions")) and ask_yes(
            "清理项目 settings 中已失效授权（会先备份相关文件）？"
        )
        do_stale_worktrees = bool(plan.get("stale_worktrees")) and ask_yes(
            "清理失效 worktree 注册（Git 元数据不可原样回滚）？"
        )
        do_project_junk = bool(plan.get("project_junk")) and ask_yes(
            "清理项目 .claude 下的 .DS_Store/__pycache__（会先备份）？"
        )

        # 只询问意图；密码本身在 CONFIRM 之后一次性收（见下面的 [0/6]）。
        # do_root 单独记一笔：只要同意提权，定位库就要读一次——不读这一项永远
        # 只有「读不到（要 root）」，跟用户答不答「关掉」无关。
        do_ipv6 = do_loc = do_root = False
        if ask_yes("处理需要管理员权限的两项（关闭 IPv6、定位服务「设定时区」）？"):
            do_root = True
            do_ipv6 = ask_yes("关闭所有网络服务的 IPv6（文章 2.5 可选加固）？")
            do_loc = ask_yes("读取定位服务状态，需要的话关掉「设定时区」（需要管理员权限）？")

        if telemetry == 1:
            print("\n⚠ 文章 §5 写明：关掉这些键会同时关掉功能旗标，Remote Control 可能用不了。")

        targets = [SETTINGS, HOME / ".claude.json"]
        sudo_targets = [LOCATIOND_PLIST] if do_loc else []
        print("\n最终执行清单：")
        print(f"  1. 第一个目标状态写入前的动作：备份 {[str(t) for t in targets + sudo_targets]}（锁文件只用于并发控制）")
        print(f"  2. 自动清理残留：系统代理 {len(plan['proxy_residue'])} 项，"
              f"shell 配置 {sum(len(v) for v in plan['rc_files'].values())} 行，"
              f"npm/git {len(plan['npm_git'])} 项，"
              f"端点/代理变量 {'是' if (plan['settings_base_url'] or plan.get('settings_env_proxy')) else '无'}，"
              f"过期工作树注册将{'清理' if do_stale_worktrees else '保持'}（{len(plan.get('stale_worktrees') or [])} 个仓库），"
              f"系统级可清理将{'清理' if do_storage else '保持'}（{human_bytes(plan.get('storage_bytes', 0))}）")
        print(f"  3. 遥测开关：{telemetry}")
        print(f"  4. 生成包装脚本：{'是' if do_wrapper else '否'}")
        print(f"  5. 关闭 IPv6：{'是' if do_ipv6 else '否'}")
        print(f"  6. 关闭定位服务「设定时区」：{'是' if do_loc else '否'}")
        print(f"  7. Clash DNS：{'是' if do_clash_dns else '否'}；Chrome Intl：{'是' if do_browser_locale else '否'}")
        if other_dns.get("needed"):
            print(f"  7b. 别家代理 DNS（{PROXY_BACKEND_LABELS.get(other_dns.get('backend'), '')}）："
                  f"{'是（改完要重启它）' if do_other_dns else '否（要显式加 --fix-unverified）'}")
        print(f"  8. 不可原样回滚清理：旧版本/缓存={'是' if do_storage else '否'}；失效权限={'是' if do_dead_permissions else '否'}；worktree 注册={'是' if do_stale_worktrees else '否'}")
        if do_root:
            print("  9. 管理员授权：动手前申请一次（终端隐藏输入开机密码，脚本不读不存），"
                  "IPv6 与定位库都复用它")
        print("  绝不改动：session、project、history、skill、plugin、hook、command、agent、MCP 配置等受保护数据。")
        if input("完全理解后输入 CONFIRM 开始；其他输入取消：").strip() != "CONFIRM":
            print("已取消，没有修改任何内容。")
            if args.report:
                write_html_only(report, note="已取消，这是改动前的状态")
            return 1

        # 锁取在 CONFIRM 之后：这之前一个字节都没写，不需要拦并发。
        locked, lock_note = acquire_run_lock()
        if not locked:
            print(f"停止：{lock_note}", file=sys.stderr)
            print("等它跑完再来；若确认那个进程已经不在了，删掉锁文件即可。", file=sys.stderr)
            return 2
        print(f"  {lock_note}")

        # [0/6] 管理员授权 —— 提权提前到动手之前，一次问清、后面全部复用。
        # 以前是懒加载：真到要写 root 文件（[1/6] 备份）或关定位闸（[6/6]）时才弹
        # 密码，而那时前面已经跑了几分钟的清理；出去接杯水回来授权就过期了，
        # 下一步的 sudo -n 只会上报失败。现在先申请，后面每一步都吃这份缓存。
        if do_root:
            print("\n[0/6] 管理员授权 —— 下面这些要 root，只申请这一次：")
            if do_ipv6:
                print("       · 关闭所有网络服务的 IPv6")
            print("       · 读一遍 /var/db/locationd/clients.plist"
                  "（非 root 读不到，「时区两道闸」这一项就没结论）")
            if do_loc:
                print("       · 需要的话关掉定位服务里的「设定时区」")
            print("       终端会隐藏提示输入一次开机密码，脚本不读取也不保存；")
            print("       默认缓存 5 分钟，中途过期只会补问一次。")
            try:
                sudo_prime()
            except Exception:
                # 用户没输密码 / 输错了：不让整轮失败，把需要 root 的那几项跳过，
                # 其余照常做完——因为「没授权」是用户的选择，不是脚本的故障。
                print("       ⚠ 没有拿到管理员授权：IPv6 与定位库这两步这次跳过，其余照常。")
                do_ipv6 = do_loc = do_root = False
            if do_root:
                loc = location_service_status(persist=True)
                gate = location_gate_state(loc)
                if gate is None:
                    print(f"       定位库仍读不到：{loc.get('note')}")
                else:
                    print(f"       定位库已读到（root 实测于 {now_stamp()}）：「设定时区」"
                          f"{'还开着' if gate else '已经关着'}；复检与后续审计都认这份读数")

        before = protected_snapshot()
        # Clash 配置也进备份：DNS 那一项要改生成物和 profile 的 Merge 增强文件两处，
        # 增强文件改错会让下次重算生成出坏配置。
        clash_files = []
        if do_clash_dns:
            clash_files = [clash_config()] if clash_config().is_file() else []
            merge_file = _active_merge_enhancement()
            if merge_file is not None:
                clash_files.append(merge_file)
        other_files = []
        if do_other_dns:
            candidate = pathlib.Path(str(other_dns.get("path") or ""))
            if str(other_dns.get("path") or "") and candidate.is_file():
                other_files.append(candidate)
        selected = {"browser_locale": do_browser_locale,
                    "dead_permissions": do_dead_permissions,
                    "project_junk": do_project_junk,
                    "wrapper": do_wrapper}
        backup_paths, _ = backup_paths_for_plan(plan, report, selected)
        manual_boundaries = []
        if plan["proxy_residue"]:
            manual_boundaries.append("系统代理 networksetup 状态需人工复核/恢复")
        if do_browser_locale:
            manual_boundaries.append("Chrome Intl defaults 状态需人工复核/恢复")
        if do_ipv6:
            manual_boundaries.append("IPv6 原态需人工复核/恢复")
        if do_clash_dns:
            manual_boundaries.append("Clash 配置文件恢复后，运行中的内核需人工重载并复验")
        if do_storage:
            manual_boundaries.append("旧版本/缓存清理不能原样自动恢复")
        if do_dead_permissions:
            manual_boundaries.append("失效权限清理需人工确认，不能保证原顺序恢复")
        if do_project_junk:
            manual_boundaries.append("项目级垃圾清理需人工确认，不能保证原样恢复")
        if do_stale_worktrees:
            manual_boundaries.append("Git worktree prune 注册表不能原样自动恢复")
        # 备份只为「即将发生的写入」而建。一个写操作都不会发生的时候（用户全选保持、
        # 计划里也没有残留），建出来的空备份目录没有任何可回滚的东西，只会越堆越多。
        # 真要写的时候，备份一步都不会省。
        will_write = bool(
            plan["proxy_residue"] or plan["rc_files"] or plan["npm_git"]
            or plan["settings_base_url"] or plan.get("settings_env_proxy")
            or do_clash_dns or other_files or do_browser_locale
            or telemetry or do_storage or do_dead_permissions
            or do_stale_worktrees or do_project_junk or do_wrapper
            or do_ipv6 or do_loc
        )
        if will_write:
            backup = create_backup(backup_paths + clash_files + other_files, sudo_targets,
                                   manual_boundaries=manual_boundaries)
            _refresh_backup_manifest(backup, "backup-created")
            print(f"\n[1/6] 备份完成：{backup}")
        else:
            print("\n[1/6] 无需备份：这次没有任何要写入的改动")
        backup_hint = (f"备份（回滚用）：{backup}" if backup
                       else "本次没有写入任何改动，无需回滚")

        _mark_backup_in_progress(backup, "automatic-cleanup")
        if plan["proxy_residue"]:
            n = clear_proxy_residue(plan["proxy_residue"])
            gone = len(plan["proxy_residue"]) - n
        else:
            n = gone = 0
        rc_changed = clear_rc_proxy_lines(plan["rc_files"]) if plan["rc_files"] else []
        npm_git_done = clear_npm_git_proxy() if plan["npm_git"] else []
        _refresh_backup_manifest(backup, "automatic-cleanup")
        print(f"[2/6] 自动清理：系统代理 {n} 项"
              + (f"（另有 {gone} 项在报告之后已经不在了）" if gone else "")
              + f"，shell 配置 {len(rc_changed)} 个文件，npm/git {len(npm_git_done)} 项")
        if do_clash_dns:
            _mark_backup_in_progress(backup, "clash-dns")
            print(f"       Clash DNS：{clear_clash_dns_leak(report)}")
            _refresh_backup_manifest(backup, "clash-dns")
        if do_other_dns:
            _mark_backup_in_progress(backup, "other-proxy-dns")
            try:
                print("       别家代理 DNS：" + clear_other_proxy_dns(
                    report.get("A28_proxy_backend") or {},
                    (report.get("A28_proxy_backend") or {}).get("facts") or {}))
            except Exception as error:
                print(f"       ⚠ 别家代理 DNS 清理失败（其余步骤继续）：{error}")
            _refresh_backup_manifest(backup, "other-proxy-dns")
        if do_browser_locale:
            _mark_backup_in_progress(backup, "browser-locale")
            print(f"       浏览器 Intl：{clear_browser_locale(report['A27_browser_locale'])}")
            _refresh_backup_manifest(backup, "browser-locale")

        if telemetry:
            _mark_backup_in_progress(backup, "telemetry")
        try:
            print(f"[3/6] 遥测开关：{apply_telemetry(telemetry) if telemetry else '保持'}")
        except Exception as error:
            # 与「别家代理 DNS」同样的处理：一步失败不该让后面几步都不跑。
            # 真没写进去的话，收尾那次复检会把这一行标回待处理。
            print(f"       ⚠ 遥测开关写入失败（其余步骤继续）：{error}")
        if plan["settings_base_url"] or plan.get("settings_env_proxy"):
            _mark_backup_in_progress(backup, "settings")
            print(f"       端点/代理变量：{clear_anthropic_base_url()}")
            _refresh_backup_manifest(backup, "settings")

        cleanup_errors = []
        if do_storage:
            _mark_backup_in_progress(backup, "storage")
            storage_done = clean_claude_storage(report)
            for d in storage_done:
                label = d["path"].replace(str(HOME) + "/", "")
                if d.get("ok"):
                    print(f"       已清 {label}  ({d.get('bytes', 0) / 2 ** 20:.0f} MB)")
                else:
                    print(f"       跳过 {label} —— {d.get('error')}")
                    cleanup_errors.append(f"存储 {label}：{d.get('error')}")
            if storage_done:
                # 删掉的东西没有备份可对照，账本必须写：事后能查「哪一次删了哪些路径」。
                print(f"       账本 {write_cleanup_manifest('系统级 Claude 环境按需清理', storage_done)}")
            _refresh_backup_manifest(backup, "storage")

        if do_dead_permissions:
            _mark_backup_in_progress(backup, "dead-permissions")
            for d in clean_dead_permissions(report):
                if d.get("error"):
                    print(f"       权限条目 {d['file']}：跳过 —— {d['error']}")
                    cleanup_errors.append(f"权限 {d['file']}：{d['error']}")
                elif d.get("removed"):
                    print(f"       权限条目 {d['file']}：删掉 {d['removed']} 条失效授权")
            _refresh_backup_manifest(backup, "dead-permissions")

        if do_project_junk:
            _mark_backup_in_progress(backup, "project-junk")
            for d in clean_project_claude_junk():
                label = d["path"].replace(str(HOME) + "/", "")
                if d.get("ok"):
                    size = f"  ({d['bytes'] / 1024:.0f} KB)" if d.get("bytes") else ""
                    print(f"       项目级 {label}{size}")
                else:
                    print(f"       项目级跳过 {label} —— {d.get('error')}")
                    cleanup_errors.append(f"项目垃圾 {label}：{d.get('error')}")
            _refresh_backup_manifest(backup, "project-junk")

        if do_stale_worktrees:
          _mark_backup_in_progress(backup, "stale-worktrees")
          for d in prune_stale_worktrees(plan.get("stale_worktrees") or []):
            name = d["repo"].replace(str(HOME) + "/", "")
            if d.get("error"):
                print(f"       工作树注册 {name}：跳过 —— {d['error']}")
                cleanup_errors.append(f"工作树 {name}：{d['error']}")
            else:
                print(f"       工作树注册 {name}：{d['before']} -> {d['after']}"
                      f"（划掉 {len(d['removed'])} 条，工作树没动）")
          _refresh_backup_manifest(backup, "stale-worktrees")

        if cleanup_errors:
            raise RuntimeError("选中的清理项目未全部成功：" + "；".join(cleanup_errors))

        if do_wrapper:
            _mark_backup_in_progress(backup, "wrapper")
            print(f"[4/6] 包装脚本：{apply_browser_wrapper()}")
            _refresh_backup_manifest(backup, "wrapper")
        else:
            print("[4/6] 包装脚本：未生成")

        if do_ipv6:
            _mark_backup_in_progress(backup, "ipv6")
            ensure_sudo("关闭 IPv6")      # [0/6] 到这一步可能已过 5 分钟，过期会补问
            res = set_ipv6_off(list(report["A5_ipv6"]["services"]))
            if res["failed"]:
                raise RuntimeError(f"IPv6 仅部分关闭：{res['done']}；失败：{res['failed']}")
            print(f"[5/6] IPv6：已关闭 {res['done']}")
            if res["rollback"]:
                print("       恢复命令：" + "；".join(res["rollback"]))
            _refresh_backup_manifest(backup, "ipv6")
        else:
            print("[5/6] IPv6：保持不变")

        if do_loc:
            ensure_sudo("读取并关闭定位服务里的「设定时区」")
            loc = location_service_status(persist=True)
            gate = location_gate_state(loc)
            if gate is True:
                _mark_backup_in_progress(backup, "location-timezone")
                print(f"[6/6] 定位服务「设定时区」：{disable_location_timezone()}")
                _refresh_backup_manifest(backup, "location-timezone")
            elif gate is False:
                print("[6/6] 定位服务「设定时区」：已经关闭，无需改动")
            else:
                raise RuntimeError("读不到定位服务状态，未执行关闭")
        else:
            print("[6/6] 定位服务「设定时区」：保持不变")

        # 允许清单要包含本次有意改动的文件，否则 zshrc 的自动清理会被误报成「被连带改动」
        allow = {str(SETTINGS)} | {str(HOME / name) for name in plan["rc_files"]}
        if do_wrapper:
            allow.add(str(HOME / ".local" / "bin" / "claude-safe"))
        changed = protected_verify(before, allow)
        if changed:
            # 这里刻意不走 raise：写操作已经执行完了，报成「停止」会让用户以为什么都没发生。
            # 必须同时说清三件事——哪些文件被连带改动、改动已完成、回滚路径在哪。
            print(
                "\n注意：本次加固已完成，但检测到受保护文件被连带改动：\n  "
                + "\n  ".join(changed)
                + f"\n这些改动不是脚本发起的，{backup_hint}",
                file=sys.stderr,
            )
            return 3
        _refresh_backup_manifest(backup, "complete")
        print(f"\n完成。受保护文件未被动过。\n{backup_hint}")

        # 总表必须是改完之后的状态，不能拿加固前的报告充数——否则刚清掉的残留
        # 在表里还显示「待处理」，用户会以为没生效。重新体检一次。
        try:
            print("\n重新体检一次，下面是改动前后的对照（同一次运行里的两遍真读数）：")
            # 复检要带上这次真测过的 WebRTC 结果，否则 --webrtc 跑完的结论会在复检表里
            # 退回成「未探测」，用户刚看到的 ✓ 又变成 ·，等于白跑一次两分钟的探测。
            fresh = audit(persist=False,
                          expected_country=args.expected_country,
                          expected_exit_ip=args.expected_exit_ip)
            if "A7_webrtc" in report:
                fresh["A7_webrtc"] = report["A7_webrtc"]
            print_before_after(report, fresh)
            write_html_twin(report, fresh)
        except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
            raise RuntimeError(f"复检失败：{error}；{backup_hint}") from error
        return 0
    except KeyboardInterrupt:
        # 中途 Ctrl-C：之前几步可能已经写完，必须告诉用户备份在哪，
        # 否则用户会以为「中断了就等于什么都没发生」。
        print("\n已中断。", file=sys.stderr)
        if backup:
            try:
                _refresh_backup_manifest(backup, "failed-or-interrupted")
            except (OSError, RuntimeError, ValueError):
                pass
            print(f"中断前已执行的改动不会自动回滚；备份（回滚用）：{backup}", file=sys.stderr)
        else:
            print("中断发生在第一个写操作之前，没有改动任何内容。", file=sys.stderr)
        return 2
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"停止：{error}", file=sys.stderr)
        if backup:
            try:
                _refresh_backup_manifest(backup, "failed")
            except (OSError, RuntimeError, ValueError):
                pass
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
