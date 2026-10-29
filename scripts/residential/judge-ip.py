#!/usr/bin/env python3
# 判定一个出口 IP 是「住宅」还是「机房」。
#
# 为什么要多源交叉：
#   实测过某个机房 IP（AS979 NetLab Global），
#   ip-api.com 的 hosting 字段返回 False —— 单源会把它判成住宅。
#   而真住宅宽带（如 AS701 Verizon）同为 False。
#   所以「hosting=False」本身不构成住宅证据，必须几个源一起看：
#   只要有任何一个源明确指向机房，或 AS 名称命中机房关键词，就判机房。
#
# 用法：
#   judge-ip.py <IP>              # 输出 RESULT
#   judge-ip.py --json <IP>       # 输出完整判定依据
#   judge-ip.py --batch           # 从 stdin 读 IP，逐行输出 "IP<TAB>RESULT"
#
# 退出码：0=住宅 1=机房 2=不确定 3=参数错误
#
# RESULT 取值：
#   RESIDENTIAL  多个源一致认为是住宅
#   DATACENTER   至少一个源认为是机房，或 AS 名称命中机房关键词
#   UNKNOWN      查不到（网络不通 / IP 无效）

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

TIMEOUT = 8
CACHE_DIR = os.path.expanduser("~/Library/Caches/claude-residential")
CACHE_TTL = 7 * 24 * 3600          # 归属很少变，缓存一周
CACHE_VERSION = 2                   # 判定逻辑改了要让旧缓存失效

# AS 名称里出现这些词，基本可以确定是机房/云/托管。
# 注意不要放 "net" / "cloud" 这种太宽的词——Verizon Business 也会被误伤。
DC_WORDS = (
    "dmit", "netlab", "vultr", "digitalocean", "linode", "aws", "amazon",
    "google cloud", "microsoft", "azure", "alibaba", "aliyun", "tencent",
    "oracle", "hetzner", "ovh", "contabo", "racknerd", "bandwagon",
    "cloud", "hosting", "datacenter", "data center", "server", "colocation",
    "choopa", "leaseweb", "psychz", "quadranet", "m247", "cogent",
)

# 这些都是公认的家宽/移动运营商，命中即强烈指向住宅。
ISP_WORDS = (
    "verizon", "comcast", "at&t", "att ", "spectrum", "charter", "cox ",
    "centurylink", "frontier", "windstream", "mediacom", "optimum",
    "xfinity", "bt ", "virgin media", "sky broadband", "talktalk",
    "deutsche telekom", "vodafone", "orange s.a", "free sas", "sfr",
    "kddi", "ntt", "softbank", "docomo", "hinet", "chunghwa",
    "telecom", "communications", "broadband", "cable", "fiber",
)


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _cache_path(ip):
    return os.path.join(CACHE_DIR, "ip-%s.json" % ip.replace(":", "_"))


def _cache_get(ip):
    try:
        with open(_cache_path(ip)) as f:
            d = json.load(f)
        if d.get("v") != CACHE_VERSION:
            return None
        if time.time() - d.get("t", 0) > CACHE_TTL:
            return None
        return d.get("r")
    except Exception:
        return None


def _cache_put(ip, result):
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(_cache_path(ip), "w") as f:
            json.dump({"v": CACHE_VERSION, "t": time.time(), "r": result}, f)
    except Exception:
        pass


def _ip_api(ip):
    """ip-api.com —— 有 hosting 标志，但会漏判（NetLab 那次）。"""
    d = _get("http://ip-api.com/json/%s?fields=status,country,isp,org,as,hosting,proxy"
             % ip)
    if d.get("status") != "success":
        raise ValueError("ip-api: %s" % d.get("message", "fail"))
    return {
        "src": "ip-api",
        "as": (d.get("as") or "").strip(),
        "org": (d.get("org") or d.get("isp") or "").strip(),
        "hosting": d.get("hosting"),
        "country": d.get("country") or "",
    }


def _ipinfo(ip):
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


def _ipwhois(ip):
    """ipwho.is —— connection.isp / connection.org，作为第三票。"""
    d = _get("https://ipwho.is/%s" % ip)
    if not d.get("success", True):
        raise ValueError("ipwho: %s" % d.get("message", "fail"))
    c = d.get("connection") or {}
    return {
        "src": "ipwho.is",
        "as": "",
        "org": (c.get("isp") or "") + " / " + (c.get("org") or ""),
        "hosting": None,
        "country": d.get("country") or "",
    }


SOURCES = (_ip_api, _ipinfo, _ipwhois)


def judge(ip):
    """返回 (RESIDENTIAL|DATACENTER|UNKNOWN, 明细 dict)。"""
    details = []
    errors = []

    for fn in SOURCES:
        try:
            details.append(fn(ip))
        except (urllib.error.URLError, ValueError, OSError, json.JSONDecodeError) as e:
            errors.append("%s: %s" % (fn.__name__.strip("_"), str(e)[:60]))
        # 免费 API 有速率限制，串行且留点间隔
        time.sleep(0.35)

    if not details:
        return "UNKNOWN", {"details": [], "errors": errors}

    # ── 判据一：任何源明确说 hosting=True → 机房 ──────────
    for d in details:
        if d.get("hosting") is True:
            return "DATACENTER", {
                "details": details, "errors": errors,
                "reason": "%s 报告 hosting=True" % d["src"],
                "as": d.get("as"), "org": d.get("org"),
            }

    # ── 判据二：AS / org 名称命中机房关键词 → 机房 ────────
    # 这一步是补上 hosting 漏判的。NetLab / DMIT 都靠这个抓出来。
    blob = " ".join(
        (d.get("as") or "") + " " + (d.get("org") or "") for d in details
    ).lower()
    for w in DC_WORDS:
        if w in blob:
            # 但要排除「名字里带 cloud 的家宽」这种误伤：
            # 只有同时没命中家宽关键词时才算机房。
            if any(i in blob for i in ISP_WORDS):
                continue
            return "DATACENTER", {
                "details": details, "errors": errors,
                "reason": "AS/组织名命中机房关键词「%s」" % w,
                "as": details[0].get("as"), "org": details[0].get("org"),
            }

    # ── 判据三：命中家宽运营商名字 → 住宅 ────────────────
    for i in ISP_WORDS:
        if i in blob:
            return "RESIDENTIAL", {
                "details": details, "errors": errors,
                "reason": "AS/组织名命中家宽运营商「%s」" % i.strip(),
                "as": details[0].get("as"), "org": details[0].get("org"),
            }

    # ── 都查到了，但谁也没认出它 ──────────────────────────
    # 这种情况不猜。住宅是要用来兜 Claude 全流量的，
    # 判不准就得人来定，不能默认放行。
    return "UNKNOWN", {
        "details": details, "errors": errors,
        "reason": "各源一致但未命中任何已知家宽/机房特征，需人工确认",
        "as": details[0].get("as"), "org": details[0].get("org"),
    }


def main():
    args = sys.argv[1:]

    if args and args[0] == "--batch":
        for line in sys.stdin:
            ip = line.strip()
            if not ip:
                continue
            r, _ = judge(ip)
            print("%s\t%s" % (ip, r))
            sys.stdout.flush()
        return 0

    as_json = bool(args and args[0] == "--json")
    if as_json:
        args = args[1:]

    if len(args) != 1:
        sys.stderr.write("用法: judge-ip.py [--json] <IP> | --batch\n")
        return 3

    ip = args[0]
    cached = _cache_get(ip)
    if cached:
        result, info = cached["result"], cached["info"]
        info["cached"] = True
    else:
        result, info = judge(ip)
        _cache_put(ip, {"result": result, "info": info})

    if as_json:
        info["result"] = result
        print(json.dumps(info, ensure_ascii=False, indent=2))
    else:
        print(result)

    return {"RESIDENTIAL": 0, "DATACENTER": 1, "UNKNOWN": 2}.get(result, 2)


if __name__ == "__main__":
    sys.exit(main())
