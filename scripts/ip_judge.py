#!/usr/bin/env python3
"""判定一个出口 IP 是「住宅」还是「机房」。

为什么要多源交叉：单看 ip-api.com 的 hosting 字段会漏判——机房 IP（如 AS979
NetLab）的 hosting 返回 False，和真住宅宽带（Verizon）一样；反过来只看 AS 名字
又会被「名字里带 cloud 的家宽」误伤。所以这里同时查 ip-api、ipinfo、ipwho.is：

  * 任何一源明确 hosting=True            → 机房
  * AS / 组织名命中机房关键词（且没命中家宽关键词）→ 机房
  * AS / 组织名命中家宽运营商关键词        → 住宅
  * 都查到了但没有特征                    → UNKNOWN（不猜）

结果缓存一周（归属很少变），缓存版本变了自动失效。

用法：
  python3 scripts/ip_judge.py <IP>           # 输出 RESIDENTIAL / DATACENTER / UNKNOWN
  python3 scripts/ip_judge.py --json <IP>    # 带判定依据
  python3 scripts/ip_judge.py --batch        # 从 stdin 逐行读 IP
  python3 scripts/ip_judge.py --no-cache <IP>

退出码：0=住宅 1=机房 2=不确定 3=参数错误
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

TIMEOUT = 8
CACHE_DIR = os.path.expanduser("~/.cache/cc-tackle/ip-judge")
CACHE_TTL = 7 * 24 * 3600
CACHE_VERSION = 1

# AS 名称里出现这些词，基本可以确定是机房/云/托管。
# 故意不放 "net" 这种太宽的词——Verizon Business 会被误伤。
DC_WORDS = (
    "dmit", "netlab", "vultr", "digitalocean", "linode", "aws", "amazon",
    "google cloud", "microsoft", "azure", "alibaba", "aliyun", "tencent",
    "oracle", "hetzner", "ovh", "contabo", "racknerd", "bandwagon",
    "cloud", "hosting", "datacenter", "data center", "server", "colocation",
    "choopa", "leaseweb", "psychz", "quadranet", "m247", "cogent",
)

# 公认的家宽 / 移动运营商，命中即强烈指向住宅。
ISP_WORDS = (
    "verizon", "comcast", "at&t", "att ", "spectrum", "charter", "cox ",
    "centurylink", "frontier", "windstream", "mediacom", "optimum",
    "xfinity", "bt ", "virgin media", "sky broadband", "talktalk",
    "deutsche telekom", "vodafone", "orange s.a", "free sas", "sfr",
    "kddi", "ntt", "softbank", "docomo", "hinet", "chunghwa",
    "telecom", "communications", "broadband", "cable", "fiber",
)


def _get(url: str, timeout: int = TIMEOUT) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _ip_api(ip: str) -> dict:
    """ip-api.com —— 有 hosting 标志，但会漏判。"""
    d = _get("http://ip-api.com/json/%s?fields=status,country,isp,org,as,hosting,proxy" % ip)
    if d.get("status") != "success":
        raise ValueError("ip-api: %s" % d.get("message", "fail"))
    return {
        "src": "ip-api",
        "as": (d.get("as") or "").strip(),
        "org": (d.get("org") or d.get("isp") or "").strip(),
        "hosting": d.get("hosting"),
        "country": d.get("country") or "",
    }


def _ipinfo(ip: str) -> dict:
    """ipinfo.io —— 免费额度给 org 字段，形如 'AS701 Verizon Business'。"""
    d = _get("https://ipinfo.io/%s/json" % ip)
    if d.get("bogon"):
        raise ValueError("ipinfo: bogon")
    return {
        "src": "ipinfo",
        "as": (d.get("org") or "").strip(),
        "org": (d.get("org") or "").strip(),
        "hosting": None,
        "country": d.get("country") or "",
    }


def _ipwhois(ip: str) -> dict:
    """ipwho.is —— connection.isp / connection.org，作为第三票。"""
    d = _get("https://ipwho.is/%s" % ip)
    if not d.get("success", True):
        raise ValueError("ipwho: %s" % d.get("message", "fail"))
    conn = d.get("connection") or {}
    return {
        "src": "ipwho.is",
        "as": "",
        "org": (conn.get("isp") or "") + " / " + (conn.get("org") or ""),
        "hosting": None,
        "country": d.get("country") or "",
    }


SOURCES = (_ip_api, _ipinfo, _ipwhois)


def judge(ip: str, fetchers=None, pause: float = 0.35) -> tuple[str, dict]:
    """返回 (RESIDENTIAL|DATACENTER|UNKNOWN, 明细)。fetchers 可注入，便于测试。"""
    fns = fetchers or SOURCES
    details, errors = [], []
    for fn in fns:
        try:
            details.append(fn(ip))
        except (urllib.error.URLError, ValueError, OSError, json.JSONDecodeError) as exc:
            name = getattr(fn, "__name__", "source").strip("_")
            errors.append("%s: %s" % (name, str(exc)[:60]))
        if pause:
            time.sleep(pause)

    if not details:
        return "UNKNOWN", {"details": [], "errors": errors, "reason": "所有数据源都不可用"}

    for d in details:
        if d.get("hosting") is True:
            return "DATACENTER", {
                "details": details, "errors": errors,
                "reason": "%s 报告 hosting=True" % d["src"],
                "as": d.get("as"), "org": d.get("org"),
            }

    blob = " ".join((d.get("as") or "") + " " + (d.get("org") or "") for d in details).lower()
    has_isp = any(w in blob for w in ISP_WORDS)
    if not has_isp:
        for w in DC_WORDS:
            if w in blob:
                return "DATACENTER", {
                    "details": details, "errors": errors,
                    "reason": "AS/组织名命中机房关键词「%s」" % w,
                    "as": details[0].get("as"), "org": details[0].get("org"),
                }

    for w in ISP_WORDS:
        if w in blob:
            return "RESIDENTIAL", {
                "details": details, "errors": errors,
                "reason": "AS/组织名命中家宽运营商「%s」" % w.strip(),
                "as": details[0].get("as"), "org": details[0].get("org"),
            }

    return "UNKNOWN", {
        "details": details, "errors": errors,
        "reason": "各源一致但未命中任何已知家宽/机房特征，需人工确认",
        "as": details[0].get("as"), "org": details[0].get("org"),
    }


def _cache_path(ip: str) -> str:
    return os.path.join(CACHE_DIR, "ip-%s.json" % ip.replace(":", "_"))


def cache_get(ip: str):
    try:
        with open(_cache_path(ip)) as f:
            d = json.load(f)
        if d.get("v") != CACHE_VERSION:
            return None
        if time.time() - d.get("t", 0) > CACHE_TTL:
            return None
        return d.get("r")
    except (OSError, ValueError):
        return None


def cache_put(ip: str, result: dict) -> None:
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(_cache_path(ip), "w") as f:
            json.dump({"v": CACHE_VERSION, "t": time.time(), "r": result}, f)
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if args and args[0] == "--batch":
        for line in sys.stdin:
            ip = line.strip()
            if ip:
                result, _ = judge(ip)
                print("%s\t%s" % (ip, result))
                sys.stdout.flush()
        return 0

    as_json = "--json" in args
    no_cache = "--no-cache" in args
    args = [a for a in args if a not in ("--json", "--no-cache")]
    if len(args) != 1:
        sys.stderr.write("用法: ip_judge.py [--json] [--no-cache] <IP> | --batch\n")
        return 3

    ip = args[0]
    cached = None if no_cache else cache_get(ip)
    if cached:
        result, info = cached["result"], cached["info"]
        info["cached"] = True
    else:
        result, info = judge(ip)
        cache_put(ip, {"result": result, "info": info})

    if as_json:
        info = dict(info, result=result)
        print(json.dumps(info, ensure_ascii=False, indent=2))
    else:
        print(result)
    return {"RESIDENTIAL": 0, "DATACENTER": 1, "UNKNOWN": 2}.get(result, 2)


if __name__ == "__main__":
    raise SystemExit(main())
