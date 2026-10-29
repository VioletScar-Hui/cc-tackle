#!/usr/bin/env python3
"""把体检结果渲染成一份自包含的 HTML 报告。

为什么要 HTML：终端里的表格靠空格对齐，项目名一长就歪，而且没法一眼看出
「整体怎么样」。报告页要回答的是三个问题——总分多少、哪几项没过、每一项的依据是什么。

两条硬约束：

1. **整页不引用任何外部资源**（没有 CDN、没有 web font、没有分析脚本）。这个工具本身就是
   查网络痕迹的，报告再往外发请求就自相矛盾了。所有样式和脚本都内联在这一个文件里。
2. **页面上的每个数字都来自报告本身**，没有写死的结论。判定逻辑一律复用
   `account_guard.build_summary()`，不在这里重写一遍——两处各写一份迟早会漂移，
   到时候页面说通过、终端说不通过，没人知道该信哪个。

单独跑：
    python3 scripts/report_html.py                    # 用最新那份 audit-*.json
    python3 scripts/report_html.py <report.json>      # 指定报告
    python3 scripts/report_html.py --out ~/Desktop    # 指定输出目录
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

BACKUP_DIR = pathlib.Path.home() / "ClaudeGuardBackups"

# 主题分组：把体检的每一行按「你在排查什么」归类，页面上按组给一个通过率。
# 这里必须是全部行——漏掉的行在按项列表里还在，但不会进任何一组的通过率，
# 页面就会显得比实际干净。有一条用例按 build_summary 的行名逐个核对。
GROUPS = (
    ("出口与线路", ("出口 IP 与归属", "预期出口是否符合", "出口 ASN 类型", "系统代理残留",
                    "代理后端", "绝不直连", "IPv6 全局地址")),
    ("DNS 与泄漏", ("DNS 泄漏", "WebRTC 泄漏")),
    ("时区与作息", ("时区是否锁在台北", "时区两道闸", "作息与出口时区")),
    ("浏览器与身份", ("浏览器 Intl 区域设置", "浏览器资料是否隔离", "多账号痕迹",
                     "钥匙串条目", "时区／出口／语言一致性", "登录方式")),
    ("Claude 本机数据", ("项目级 .claude 规模", "系统级可清理量", "settings 失效权限",
                        "settings.json 端点与凭据", "遥测三键", "CLI 完整性",
                        "第三方客户端", "CLAUDE.md 地理位置词")),
    ("终端与凭据", ("终端 / shell / npm / git 代理",)),
    ("代码与仓库", ("代码是否落在本地 Git",)),
)

# 页面末尾给的自查入口。这些是给用户自己点开核对的第三方检测站：脚本不代跑，
# 也不抓它们的任何资源——页面上只有链接，没有外链图片或脚本，离线打开也不会去连它们。
DETECTION_SITES = (
    ("出口与归属", (
        ("https://ipinfo.io/", "IP 归属、ASN 与运营商；看「是机房还是住宅」用的就是它"),
        ("https://ping0.cc/", "IP 类型与风控值：原生还是广播、多少人共用这个出口"),
        ("https://cleanip.io/", "聚合 20+ 数据源的纯净度评分与欺诈分"),
        ("https://ippure.com/", "IP 纯净度与风险系数，附带浏览器指纹总览"),
    )),
    ("针对 Claude 的区域指纹与线路", (
        ("https://ippure.com/claude.html", "六项区域指纹加权：时区、语言、中文字体、Intl 区域设置、时区偏移、Emoji"),
        ("https://ip.net.coffee/claude/", "Claude 相关域名实际的出口与纯净度"),
    )),
    ("分流有没有生效", (
        ("https://ip.net.coffee/", "国内外 35+ 站点各自的出口 IP，用来核对规则有没有按预期分流"),
    )),
    ("泄漏面", (
        ("https://browserleaks.com/webrtc", "WebRTC 候选里有没有真实 IP 或 TUN 地址"),
        ("https://browserleaks.com/dns", "到底是谁在替你解析域名，有没有国内解析器"),
    )),
    ("顺手装一个扩展", (
        ("https://chromewebstore.google.com/detail/npeicpdbkakmehahjeeohfdhnlpdklia",
         "WebRTC Network Limiter：Google 官方扩展，把 WebRTC 的 UDP 限制成只走代理"),
    )),
)


def _detection_sites_html() -> str:
    blocks = []
    for group, sites in DETECTION_SITES:
        items = "".join(
            f"<li><a href='{_esc(url)}' target='_blank' rel='noopener noreferrer'>{_esc(url)}</a>"
            f"<span class='tiny'>{_esc(note)}</span></li>"
            for url, note in sites
        )
        blocks.append(f"<div class='card'><h3>{_esc(group)}</h3><ul class='sites'>{items}</ul></div>")
    return "<div class='grid g2'>" + "".join(blocks) + "</div>"


# 每一行的依据来自报告里的哪个字段。「看依据」按钮把这几个字段摊开，数值不动，
# 只摘掉出处标注；页面上的说法和原始读数仍然对得上。
ROW_SOURCE = {
    "出口 IP 与归属": ("A1_export_ip",),
    "出口 ASN 类型": ("A1_export_ip",),
    "系统代理残留": ("A1_proxy_residue",),
    "DNS 泄漏": ("A6_dns",),
    "WebRTC 泄漏": ("A7_webrtc",),
    "IPv6 全局地址": ("A5_ipv6",),
    "时区是否锁在台北": ("A21_timezone_layers",),
    "时区两道闸": ("A21_timezone_layers",),
    "绝不直连": ("A12_clash_groups",),
    "代理后端": ("A28_proxy_backend",),
    "登录方式": ("A29_cli_login",),
    "代码是否落在本地 Git": ("A14_local_git",),
    "作息与出口时区": ("A22_schedule",),
    "浏览器资料是否隔离": ("A23_browser_profiles",),
    "项目级 .claude 规模": ("A24_project_claude",),
    "系统级可清理量": ("A25_claude_storage",),
    "settings 失效权限": ("A26_claude_settings",),
    "终端 / shell / npm / git 代理": ("A1_terminal_env",),
    "settings.json 端点与凭据": ("A2_anthropic_base_url",),
    "遥测三键": ("A3_telemetry",),
    "CLAUDE.md 地理位置词": ("A9_geo_words",),
    "第三方客户端": ("A10_third_party",),
    "CLI 完整性": ("A11_client_integrity",),
    "钥匙串条目": ("E1_keychain",),
    "多账号痕迹": ("A13_multi_account",),
    "时区／出口／语言一致性": ("A15_consistency",),
    "浏览器 Intl 区域设置": ("A27_browser_locale",),
}

EVIDENCE_CAP = 1600  # 每个字段摊开时的字符上限，A6_dns 这种能到几千字符

CSS = """
:root{
  --bg:#f4f5f2; --card:#ffffff; --ink:#14141f; --muted:#6b7280; --line:#e3e5e0;
  --ok:#35a952; --ok-bg:#eaf6ee; --warn:#f59e0b; --warn-bg:#fdf3e3;
  --bad:#ef4444; --bad-bg:#fdeceb; --na:#94a3b8; --na-bg:#eef1f4;
  --dark:#14141f; --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC","Helvetica Neue",Segoe UI,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:28px 20px 64px}
a{color:inherit}
code,pre,.mono{font-family:var(--mono)}

/* ── 顶部总分 ── */
.hero{background:var(--dark);color:#fff;border-radius:18px;padding:26px 26px 22px;margin-bottom:18px}
.hero h1{margin:0 0 2px;font-size:19px;letter-spacing:.2px}
.hero .sub{color:#9aa3b2;font-size:13px;margin-bottom:20px}
.hero-grid{display:flex;gap:26px;align-items:center;flex-wrap:wrap}
.ring{--p:0;width:132px;height:132px;border-radius:50%;flex:0 0 auto;
  background:conic-gradient(var(--ring) calc(var(--p)*1%), #262a35 0);
  display:grid;place-items:center}
.ring-in{width:104px;height:104px;border-radius:50%;background:var(--dark);
  display:grid;place-items:center;line-height:1}
.ring-in b{font-size:34px;font-weight:700}
.ring-in small{color:#9aa3b2;font-size:12px}
.grade{font-size:30px;font-weight:700;margin-right:2px}
.grade small{font-size:12px;color:#9aa3b2;font-weight:400;display:block;margin-top:2px}
.hero-note{color:#c7ccd6;font-size:13px}
.cmp{display:flex;align-items:center;gap:10px;padding:7px 2px;border-bottom:1px dashed var(--line);font-size:13.5px}
.cmp:last-child{border-bottom:0}
.cmp-name{flex:1;min-width:0;color:var(--ink)}
.cmp-mark{flex:0 0 32px;text-align:center;border-radius:8px;font-weight:600;padding:1px 0;font-size:13px}
.cmp-mark.ok{color:var(--ok);background:var(--ok-bg)}
.cmp-mark.warn{color:#a35c00;background:var(--warn-bg)}
.cmp-mark.bad{color:var(--bad);background:var(--bad-bg)}
.cmp-mark.na{color:var(--na);background:var(--na-bg)}
.cmp-arrow{flex:0 0 14px;text-align:center;color:var(--na)}
.delta{margin-top:8px;font-size:13px;color:#c7ccd6}
.delta b{color:#fff}
.delta .up{color:#7ee2a8}.delta .down{color:#ffb4ae}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}
.chip{border-radius:999px;padding:5px 12px;font-size:13px;border:1px solid #2e3340;color:#dfe3ea}
.chip b{font-size:15px}
.chip.ok b{color:#7ee2a8}.chip.warn b{color:#ffd08a}.chip.bad b{color:#ffb4ae}.chip.na b{color:#b9c0cc}

/* ── 关键实测 ── */
.sites{list-style:none;margin:8px 0 0;padding:0}
.sites li{padding:6px 0;border-bottom:1px dashed var(--line)}
.sites li:last-child{border-bottom:0}
.sites a{color:#0f233d;text-decoration:none;border-bottom:1px solid #cfd8e3;word-break:break-all}
.sites a:hover{border-bottom-color:#0f233d}
.sites .tiny{display:block;color:var(--muted);margin-top:2px;word-break:normal}
.facts{display:grid;grid-template-columns:repeat(auto-fill,minmax(228px,1fr));gap:10px;margin:18px 0 6px}
.fact{background:#1b1f2a;border-radius:12px;padding:11px 13px}
.fact .k{color:#9aa3b2;font-size:12px;margin-bottom:4px}
.fact .v{font-size:14px;word-break:break-all}

/* ── 通用区块 ── */
section{margin-top:22px}
h2{font-size:16px;margin:0 0 12px;display:flex;align-items:center;gap:8px}
h2 .hint{font-size:12px;color:var(--muted);font-weight:400}
.grid{display:grid;gap:12px}
.grid.g3{grid-template-columns:repeat(auto-fill,minmax(300px,1fr))}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px}
.card h3{margin:0 0 8px;font-size:14px;display:flex;justify-content:space-between;align-items:baseline;gap:8px}
.card h3 em{font-style:normal;color:var(--muted);font-size:12px}

.bar{height:7px;border-radius:99px;background:#e9ebe7;overflow:hidden;margin:8px 0 6px}
.bar i{display:block;height:100%;background:var(--ok)}
.bar i.warn{background:var(--warn)}
.bar i.bad{background:var(--bad)}
.bar i.na{background:var(--na)}
.tiny{font-size:12px;color:var(--muted)}

/* ── 逐项卡 ── */
.item{display:flex;gap:11px;padding:12px 14px;border:1px solid var(--line);border-radius:13px;
  background:var(--card);margin-bottom:9px;border-left:3px solid var(--na)}
.item.ok{border-left-color:var(--ok)}
.item.warn{border-left-color:var(--warn)}
.item.bad{border-left-color:var(--bad)}
.dot{width:21px;height:21px;border-radius:50%;flex:0 0 auto;display:grid;place-items:center;
  font-size:12px;font-weight:700;margin-top:1px}
.ok .dot{background:var(--ok-bg);color:var(--ok)}
.warn .dot{background:var(--warn-bg);color:#b45309}
.bad .dot{background:var(--bad-bg);color:var(--bad)}
.na .dot{background:var(--na-bg);color:#64748b}
.item .name{font-weight:600;font-size:14px}
.item .detail{color:#3f4652;font-size:13px;margin-top:2px}
    .item .protects-box{margin-top:9px;background:#f6f7f4;border:1px solid var(--line);
      border-radius:10px;padding:9px 13px}
    .item .protects-title{font-size:13px;font-weight:700;color:var(--ink);margin-bottom:5px}
    .item .protects{margin:0 0 0 1.15em;padding:0;line-height:1.7;font-size:14px;color:#2b3038}
    .item .protects li{margin:2px 0}
details{margin-top:7px}
summary{cursor:pointer;font-size:12px;color:var(--muted);outline:none}
summary:hover{color:var(--ink)}
pre{margin:7px 0 0;background:#f7f8f6;border:1px solid var(--line);border-radius:10px;
  padding:10px 12px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}

/* ── 人工清单 ── */
details.manual{border:1px solid var(--line);border-radius:13px;background:var(--card);margin-bottom:9px}
details.manual>summary{padding:12px 15px;font-size:14px;font-weight:600;color:var(--ink)}
details.manual>summary em{font-style:normal;color:var(--muted);font-weight:400;font-size:12px;margin-left:6px}
.ma{padding:0 15px 12px 15px;border-top:1px solid var(--line);margin-top:0}
.ma h4{margin:12px 0 5px;font-size:13.5px}
.ma h4 span{color:var(--muted);font-weight:400;font-size:12px;margin-left:6px}
.ma ol{margin:4px 0 0 18px;padding:0}
.ma li{margin:3px 0;font-size:13px}
.ma .why{color:var(--muted);font-size:12px;margin-top:5px}

/* ── 页脚 ── */
footer{margin-top:26px;padding-top:14px;border-top:1px solid var(--line);
  color:var(--muted);font-size:12px;line-height:1.9}
.pill{display:inline-block;border:1px solid var(--line);border-radius:99px;padding:2px 9px;margin-right:6px}

/* ── 修复按钮（只在服务模式出现）── */
.name-row{display:flex;align-items:center;justify-content:space-between;gap:10px}
button.fix{font:inherit;font-size:12.5px;padding:5px 13px;border-radius:9px;cursor:pointer;
  border:1px solid var(--ok);background:var(--ok);color:#fff;white-space:nowrap}
button.fix:hover{filter:brightness(1.08)}
button.fix[disabled]{opacity:.5;cursor:default}
button.fix.ghost{background:#fff;color:var(--ink);border-color:var(--line)}
button.fix.ghost:hover{border-color:#c9cdc6}
.acts{display:flex;gap:9px;flex-wrap:wrap;margin-top:16px}
#flash{position:sticky;top:0;z-index:9;margin-bottom:14px}
.msg{border-radius:12px;padding:11px 14px;margin-bottom:8px;font-size:13.5px;
  border:1px solid var(--line);background:#fff}
.msg.ok{border-left:4px solid var(--ok)}
.msg.bad{border-left:4px solid var(--bad)}
.msg ul{margin:6px 0 0 18px;padding:0}
.msg li{margin:2px 0}
@media print{.hero{background:#fff;color:#000}.acts,#flash{display:none}}
@media (max-width:640px){.hero-grid{gap:16px}.ring{width:112px;height:112px}.ring-in{width:88px;height:88px}}
"""


JS = """
(function () {
  var BASE = "__BASE__";
  var TOKEN = BASE.split("/").filter(Boolean).pop();
  var FLASH = "guardFlash";

  function post(path, body) {
    return fetch(BASE + "/" + path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Guard-Token": TOKEN },
      body: JSON.stringify(body || {})
    }).then(function (r) { return r.json(); });
  }

  function wait(btn, on) {
    if (!btn) return;
    btn.disabled = on;
    if (on) { btn.dataset.text = btn.textContent; btn.textContent = "处理中…"; }
    else if (btn.dataset.text) { btn.textContent = btn.dataset.text; }
  }

  function run(btn, path, body, confirmText) {
    if (confirmText && !window.confirm(confirmText)) return;
    wait(btn, true);
    post(path, body).then(function (res) {
      sessionStorage.setItem(FLASH, JSON.stringify({
        msgs: res.messages || [], failed: res.failed || [], error: res.error || ""
      }));
      location.reload();
    }).catch(function (e) {
      sessionStorage.setItem(FLASH, JSON.stringify({ msgs: [], failed: [String(e)], error: "" }));
      location.reload();
    });
  }

  document.addEventListener("click", function (ev) {
    var b = ev.target.closest("button.fix");
    if (!b) return;
    if (b.dataset.all) {
      run(b, "fix", { all: true }, "把这一页里所有能自动修的项都跑一遍？每项都会先做备份。");
    } else if (b.dataset.rescan) {
      run(b, "rescan", {}, null);
    } else if (b.dataset.stop) {
      run(b, "stop", {}, "结束本地服务？页面会留在浏览器里，只是按钮不再生效。");
    } else if (b.dataset.rows) {
      run(b, "fix", { rows: [b.dataset.rows] }, null);
    }
  });

  var raw = sessionStorage.getItem(FLASH);
  if (raw) {
    sessionStorage.removeItem(FLASH);
    var d = JSON.parse(raw), box = document.getElementById("flash"), html = "";
    if (d.msgs && d.msgs.length) {
      html += "<div class='msg ok'><b>已完成</b><ul>" +
        d.msgs.map(function (m) { return "<li>" + m + "</li>"; }).join("") + "</ul></div>";
    }
    if (d.error) html += "<div class='msg bad'>" + d.error + "</div>";
    if (d.failed && d.failed.length) {
      html += "<div class='msg bad'><b>这几项没成</b><ul>" +
        d.failed.map(function (m) { return "<li>" + m + "</li>"; }).join("") + "</ul></div>";
    }
    if (box) box.innerHTML = html;
  }
})();
"""


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""), quote=True)


def _age_text(seconds: float) -> str:
    """把秒数说成「12 秒 / 3 分 / 2 小时 / 5 天」。"""
    seconds = int(seconds or 0)
    if seconds < 60:
        return f"{seconds} 秒"
    if seconds < 3600:
        return f"{seconds // 60} 分"
    if seconds < 86400:
        return f"{seconds // 3600} 小时"
    return f"{seconds // 86400} 天"


def _kind(status: str) -> str:
    """把 build_summary 的状态记号翻成 CSS 类名。"""
    return {"✓": "ok", "!": "warn", "✗": "bad"}.get((status or "").strip(), "na")


# 计分口径：27 个基础项合计 100 分，每个 100/27 分；加分项通过再往上加。
BASE_ITEMS = 27
BASE_MAX = 100
BONUS_ROW = "登录方式"
BONUS_POINTS = 5
MAX_SCORE = BASE_MAX + BONUS_POINTS


def _score(rows) -> dict:
    """加分制：27 个基础项合计 100 分，加分项（登录方式）另外加。

    基础分：每项满分 100/27。通过拿满、待处理拿一半、未通过 0 分；
    **「这次没测到」同样是 0 分**——分母固定 27，测不到就不拿分，既不折算成
    剩下那几项的比例，也不会因为「测到的都过了」而显示接近满分。要么测到并
    通过，要么这一项就不给分。

    加分项：登录方式通过时额外加 BONUS_POINTS 分，不计入那 27 项，总分最高 105。
    """
    w = {"ok": 1.0, "warn": 0.5, "bad": 0.0, "na": 0.0}
    counts = {"ok": 0, "warn": 0, "bad": 0, "na": 0}
    for r in rows:
        counts[_kind(r[1])] += 1
    bonus = 0
    earned = 0.0
    seen = set()
    for r in rows:
        if r[0] == BONUS_ROW:
            if _kind(r[1]) == "ok":
                bonus = BONUS_POINTS
            continue
        if r[0] in seen:
            # 同一项出现两次只算一次：否则多出来的一条「通过」会把另一条失败抵消掉。
            continue
        seen.add(r[0])
        earned += w[_kind(r[1])]
    # 分母固定为 27：以后真加了检查项而没有同步 BASE_ITEMS，宁可分数封顶，
    # 也不能让它靠多出来的行把总分撑过 100。
    score = min(BASE_MAX, round(BASE_MAX * earned / BASE_ITEMS))
    total = score + bonus
    if total >= 100:
        grade, ring = "A+", "#35a952"
    elif total >= 90:
        grade, ring = "A", "#35a952"
    elif total >= 80:
        grade, ring = "B", "#7bc043"
    elif total >= 70:
        grade, ring = "C", "#f59e0b"
    elif total >= 50:
        grade, ring = "D", "#f97316"
    else:
        grade, ring = "F", "#ef4444"
    return {"score": score, "total": total, "bonus": bonus, "per_item": BASE_MAX / BASE_ITEMS,
            "grade": grade, "counts": counts, "ring": ring}


def _facts(rep: dict) -> list:
    """页面上那一排关键读数。没有的字段直接不显示，不留空壳。"""
    ip = rep.get("A1_export_ip") or {}
    dn = (rep.get("A6_dns") or {}).get("clash") or {}
    cg = rep.get("A12_clash_groups") or {}
    tz = rep.get("A21_timezone_layers") or {}
    cli = rep.get("A11_client_integrity") or {}
    st = rep.get("A26_claude_settings") or {}
    loc = rep.get("A27_browser_locale") or {}
    inst = cli.get("install")
    # install 是 dict（method/layout_ok/probes/evidence），dead 与 risky 是列表。
    # 直接把 dict 塞进 f-string 会把整坨探测细节打到页面上——2026-10-13 第一版就是这么错的。
    method = (inst or {}).get("method") if isinstance(inst, dict) else inst
    dead_n = len(st["dead"]) if isinstance(st.get("dead"), (list, tuple)) else st.get("dead")
    risky_n = len(st["risky"]) if isinstance(st.get("risky"), (list, tuple)) else st.get("risky")
    tun = cg.get("tun") or {}
    grp = cg.get("claude_group") or {}
    fb = cg.get("fallback") or {}
    layers = tz.get("layers") or {}
    pb = rep.get("A28_proxy_backend") or {}
    caps = pb.get("capabilities") or {}
    cap_bits = [
        "能读 DNS" if caps.get("read_dns") else None,
        "能读分流" if caps.get("read_routing") else None,
        "能改 DNS" if caps.get("fix_dns") else None,
        "改完可复验" if caps.get("verify_after_write") else "改完不能就地复验",
    ]
    out = [
        ("代理后端", pb.get("short") or pb.get("label")),
        ("代理能力", "、".join([x for x in cap_bits if x]) or None),
        ("出口 IP", ip.get("ip")),
        ("归属", " / ".join([x for x in (ip.get("city"), ip.get("country")) if x])),
        ("运营商与 ASN", ip.get("org")),
        ("出口时区", ip.get("timezone")),
        ("Clash 模式", f"{cg.get('mode')}　TUN {'开' if tun.get('enable') else '关'}　严格路由 {'开' if tun.get('strict-route') else '关'}" if cg.get("mode") else None),
        ("Claude 专用组", f"{grp.get('now')}（{len(grp.get('members') or [])} 个成员）" if grp.get("now") else None),
        ("规则兜底", fb.get("proxy")),
        ("DNS 主解析器", "、".join(dn.get("nameserver") or []) or None),
        ("DNS 劫持", "、".join(dn.get("hijack") or []) or None),
        ("系统时区", layers.get("new_process") or layers.get("localtime")),
        ("浏览器 Intl", loc.get("measured")),
        ("CLI 版本", f"{cli.get('cli_version')}（{method or '安装方式未知'}）" if cli.get("cli_version") else None),
        ("settings 授权", f"{st.get('total')} 条（清掉失效 {dead_n or 0}，偏危险 {risky_n or 0} 只报告）"
         if st.get("total") else None),
    ]
    return [(k, v) for k, v in out if v not in (None, "", [])]


def _fix_bar(name: str, live, actions) -> str:
    """某一行的修复按钮。live 为空（静态文件）时不出按钮，只出说明。"""
    specs = ((actions or {}).get(name) or []) if live else []
    if not specs:
        return ""
    hints = []
    for a in specs:
        if a.get("hint") and a["hint"] not in hints:
            hints.append(a["hint"])
    label = specs[0].get("label") or "修复"
    if len(specs) > 1:
        label += "全部"
    return (f"<button class='fix' data-rows='{_esc(name)}' title='{_esc('；'.join(hints))}'>"
            f"{_esc(label)}</button>")


def _evidence(rep: dict, name: str) -> str:
    """一行结论的原始依据：把来源字段贴出来，数值与结构不改。

    唯一的加工是把「文章 §2.2」这类出处标注摘掉（strip_article_refs）——页面是给人看的
    结论页，不带出处；落盘的报告 JSON 里出处完好，要看原始措辞去
    ~/ClaudeGuardBackups/audit-*.json。
    """
    keys = ROW_SOURCE.get(name) or ()
    blocks = []
    for k in keys:
        if k not in rep:
            continue
        body = strip_article_refs(json.dumps(rep[k], ensure_ascii=False, indent=2))
        if len(body) > EVIDENCE_CAP:
            body = body[:EVIDENCE_CAP] + "\n… （已截断，完整内容见报告 JSON）"
        blocks.append(f"<pre>{_esc(body)}</pre>")
    if not blocks:
        return "<div class='tiny'>这一项由多个字段共同决定，明细见报告 JSON 与终端输出。</div>"
    return "".join(blocks)


_ARTICLE_QUOTE = re.compile(r"文章原话[：:]?「[^」]*」")
_PAREN = re.compile(r"（[^）]*）")
_HAS_WORD = re.compile(r"[0-9A-Za-z\u4e00-\u9fff]")


def strip_article_refs(text: str) -> str:
    """把「文章 2.2」「文章原话：「…」」这类出处从页面文字里摘掉。

    页面是结论页：读的人要的是做什么，不是这句话出自哪里。逐条出处留在
    references/article-mapping.md 里备查，页面不带。规则分四步：

    1. 整段引文（文章原话「…」）连引号一起删掉；
    2. 括号内按逗号拆，含「文章」的那一截删掉；括号里全被删光就整对括号删掉；
    3. 括号外按句号、分号拆，含「文章」的整句删掉；整句只剩标点就丢；
       一句话里只有前半截带出处时，再按逗号拆一次，保留没出处的后半截；
    4. 收尾扫掉多余标点、空括号和残留的破折号。
    """
    if not text or "文章" not in text:
        return text

    t = _ARTICLE_QUOTE.sub("", text)

    def _paren(match):
        inner = match.group(0)[1:-1]
        kept = [part for part in inner.split("，") if "文章" not in part]
        return f"（{'，'.join(kept)}）" if kept else ""

    t = _PAREN.sub(_paren, t)

    kept = []
    for sentence in re.split(r"(?<=[。；])", t):
        if "文章" not in sentence:
            kept.append(sentence)
            continue
        rest = "".join(part for part in re.split(r"(?<=[，])", sentence) if "文章" not in part)
        if _HAS_WORD.search(rest):
            kept.append(rest)
    t = "".join(kept)

    t = re.sub(r"[，、；]{2,}", "，", t)
    t = re.sub(r"^[，。、；：—－\s]+", "", t)
    t = re.sub(r"[，、；：\s]+$", "", t)
    t = re.sub(r"[—－]{2,}$", "", t.strip())
    t = t.replace("（）", "")
    # 引文夹在句子中间时（「文章原话：「老 Gmail 更稳」的说法…」），删掉引文会剩下一个
    # 悬空的「的」，补一个「这」把它接回去
    if t.startswith("的"):
        t = "这种" + t[1:]
    return t.strip()


def _manual_html(manual) -> str:
    out = []
    for grp in manual:
        title, items = grp[0], grp[1]
        body = []
        for it in items:
            name, _src, steps, note = (list(it) + [None] * 4)[:4]
            lis = "".join(f"<li>{_esc(s)}</li>" for s in (steps or ()))
            # 出处标签（文章 2.2 这种）不进页面；说明里带出处的部分也一并摘掉
            name = strip_article_refs(name)
            note = strip_article_refs(note) if note else ""
            body.append(
                f"<h4>{_esc(name)}</h4>"
                f"<ol>{lis}</ol>"
                + (f"<div class='why'>{_esc(note)}</div>" if note else "")
            )
        out.append(
            f"<details class='manual'><summary>{_esc(strip_article_refs(title))}<em>{len(items)} 条</em></summary>"
            f"<div class='ma'>{''.join(body)}</div></details>"
        )
    return "".join(out)


def render(report: dict, before: dict = None, report_path=None,
           live=None, actions=None, note: str = "") -> str:
    """渲染整页。report 是体检报告字典，before 是同一轮里动手前那份（可选）。

    note 会原样印在页面顶部：用来标注「这一轮没有改动」「已取消」这类上下文——
    以前只在终端打印，页面单独发出去就看不出它是哪一种了。
    """
    import account_guard as g  # 延迟导入：单独跑本模块时也要能用，且避免循环导入

    rows = g.build_summary(report)
    before_rows = g.build_summary(before) if before else None
    sc = _score(rows)
    before_sc = _score(before_rows) if before_rows else None

    # ── 顶部 ──
    counts = sc["counts"]
    chips = "".join(
        f"<span class='chip {k}'><b>{counts[k]}</b> {t}</span>"
        for k, t in (("ok", "已解决"), ("warn", "待处理"), ("bad", "未解决"), ("na", "没测到"))
        if counts[k] or k != "na"
    )
    delta = ""
    if before_sc and before_sc["total"] is not None and sc["total"] is not None:
        d = sc["total"] - before_sc["total"]
        arrow = "↑" if d > 0 else ("↓" if d < 0 else "＝")
        cls = "up" if d > 0 else ("down" if d < 0 else "")
        delta = (f"<div class='delta'>修复前 <b>{before_sc['total']}</b> → 修复后 "
                 f"<b>{sc['total']}</b> <span class='{cls}'>{arrow} {abs(d)}</span></div>")
    if sc["bonus"]:
        delta += (f"<div class='delta'><span class='up'>加分项「{_esc(BONUS_ROW)}」已通过"
                  f" +{sc['bonus']}</span></div>")
    facts = "".join(f"<div class='fact'><div class='k'>{_esc(k)}</div>"
                    f"<div class='v'>{_esc(v)}</div></div>" for k, v in _facts(report))

    # ── 分组通过率 ──
    by_name = {r[0]: r for r in rows}
    group_cards = []
    for gname, names in GROUPS:
        items = [by_name[n] for n in names if n in by_name]
        if not items:
            continue
        kinds = [_kind(r[1]) for r in items]
        ok_n = sum(1 for k in kinds if k == "ok")
        na_n = sum(1 for k in kinds if k == "na")
        # 分母用这一组的全部检查项：「没测到」按 0 分，分组通过率也就不会被
        # 那几项悄悄抬高——和总分是同一口径。
        pct = round(100 * ok_n / len(items))
        cls = "ok" if pct == 100 else ("warn" if pct >= 60 else "bad")
        bad = [r[0] for r in items if _kind(r[1]) in ("bad", "warn")]
        notes = []
        if bad:
            notes.append("待处理：" + "、".join(bad))
        if na_n:
            notes.append(f"未测到 {na_n} 项")
        group_cards.append(
            f"<div class='card'><h3>{_esc(gname)}<em>{ok_n}/{len(items)}</em></h3>"
            f"<div class='bar'><i class='{cls}' style='width:{pct}%'></i></div>"
            f"<div class='tiny'>{_esc('；'.join(notes) or '全部通过')}</div></div>"
        )

    # ── 常驻程序（只列本 skill 自己的，按功能分组；不计分）──
    resident = report.get("A30_resident") or {}
    resident_html = ""
    if resident.get("items"):
        by_label = {item["label"]: item for item in resident.get("items") or []}
        groups = resident.get("groups") or [
            {"name": "常驻程序", "labels": list(by_label)}]
        cards = []
        for group in groups:
            members = [by_label[label] for label in (group.get("labels") or [])
                       if label in by_label]
            if not members:
                continue
            entries = []          # 别叫 rows：外面那个 rows 是整张表的 28 行
            for item in members:
                if item.get("running"):
                    kind, mark = "ok", "●"
                elif item.get("loaded"):
                    kind, mark = "warn", "!"
                else:
                    kind, mark = "bad", "✗"
                program = (item.get("program") or "").strip()
                if len(program) > 96:
                    program = "…" + program[-95:]
                state_txt = item.get("state") or ""
                if item.get("elapsed"):
                    state_txt += f"，已跑 {item['elapsed']}"
                detail = f"{state_txt} · {item.get('autostart') or ''}"
                if item.get("scan_age_seconds") is not None:
                    detail += f" · 最近扫描 {_age_text(item['scan_age_seconds'])}前"
                if program:
                    detail += f" · {program}"
                protects = item.get("protects") or []
                if isinstance(protects, str):        # 兼容旧报告 JSON
                    protects = [protects] if protects else []
                protect_line = ""
                if protects:
                    points = "".join(f"<li>{_esc(p)}</li>" for p in protects)
                    protect_line = (f"<div class='protects-box'>"
                                    f"<div class='protects-title'>这个进程保护什么</div>"
                                    f"<ul class='protects'>{points}</ul></div>")
                entries.append(
                    f"<div class='item {kind}'><div class='dot'>{mark}</div>"
                    f"<div style='flex:1'><div class='name-row'>"
                    f"<div class='name'>{_esc(item.get('label') or '')}</div></div>"
                    f"<div class='detail'>{_esc(detail)}</div>{protect_line}</div></div>"
                )
            cards.append(
                f"<div class='card'><h3>{_esc(group.get('name') or '')}"
                f"<em>{len(members)} 个</em></h3>{''.join(entries)}</div>")
        hint = (f"{resident.get('total', len(by_label))} 个，"
                f"{resident.get('autostart', 0)} 个设了开机自启")
        if resident.get("disabled"):
            hint += f"，{resident['disabled']} 个被禁用"
        if resident.get("not_loaded"):
            hint += f"，{resident['not_loaded']} 个未加载"
        resident_html = (
            f"<section><h2>本 skill 的常驻程序 <span class='hint'>{_esc(hint)}</span></h2>"
            f"<div class='grid g2'>{''.join(cards)}</div></section>"
        )
    elif "A30_resident" in report and resident.get("note"):
        resident_html = (
            "<section><h2>本 skill 的常驻程序</h2>"
            f"<div class='card'>{_esc(resident['note'])}</div></section>"
        )

    # ── 逐项 ──
    item_cards = []
    for name, status, detail in rows:
        k = _kind(status)
        mark = {"ok": "✓", "warn": "!", "bad": "✗", "na": "·"}[k]
        item_cards.append(
            f"<div class='item {k}'><div class='dot'>{mark}</div><div style='flex:1'>"
            f"<div class='name-row'><div class='name'>{_esc(name)}</div>"
            f"{_fix_bar(name, live, actions)}</div>"
            f"<div class='detail'>{_esc(strip_article_refs(detail)) or '（没有说明）'}</div>"
            f"<details><summary>看依据</summary>{_evidence(report, name)}</details>"
            f"</div></div>"
        )

    # ── 需要你处理的 ──
    todo = [r for r in rows if _kind(r[1]) in ("bad", "warn")]
    na_n = sum(1 for r in rows if _kind(r[1]) == "na")
    if todo:
        todo_html = "".join(
            f"<div class='item {_kind(r[1])}'><div class='dot'>{'!' if _kind(r[1])=='warn' else '✗'}</div>"
            f"<div style='flex:1'><div class='name-row'><div class='name'>{_esc(r[0])}</div>"
            f"{_fix_bar(r[0], live, actions)}</div>"
            f"<div class='detail'>{_esc(strip_article_refs(r[2]))}</div></div></div>"
            for r in todo
        )
    elif na_n:
        # 「没测到」按 0 分计，就不能再说「全部通过」——0 分和全部通过同时出现，
        # 等于把没测到的项偷偷当成了通过。
        todo_html = (f"<div class='card'>{len(rows) - na_n} 项已经判定，另有 {na_n} 项"
                     f"这次没测到、按 0 分计，不能算通过；要下结论先把这几项测到。</div>")
    else:
        todo_html = f"<div class='card'>{len(rows)} 项全部通过，不需要你做任何事。</div>"

    changed = ""
    if before_rows:
        # 逐项把「动手前」与「动手后」两个记号并排摆出来。只列改好的那几项不够用：
        # 这份页面本身就是前后对照，没变的项也要能看到它当时是什么。
        rank = {"bad": 0, "warn": 1, "ok": 2}
        bmap = {r[0]: r[1] for r in before_rows}
        lines, fixed, worse, incomparable = [], 0, [], 0
        for r in rows:
            was, now = bmap.get(r[0], "·"), r[1]
            a, b = rank.get(_kind(was)), rank.get(_kind(now))
            # 「这次没测到」不参与比较：从 · 变成 ✓ 是这次量到了，不是被改好的，
            # 反过来把 没测到 当成比 已解决 还高，就会把一整片正常的项报成「变差了」。
            if a is None or b is None:
                incomparable += 1
            elif b > a:
                fixed += 1
            elif b < a:
                worse.append(r[0])
            lines.append(
                "<div class='cmp'>"
                f"<div class='cmp-name'>{_esc(r[0])}</div>"
                f"<div class='cmp-mark {_kind(was)}'>{_esc((was or '·').strip())}</div>"
                "<div class='cmp-arrow'>→</div>"
                f"<div class='cmp-mark {_kind(now)}'>{_esc((now or '·').strip())}</div>"
                "</div>")
        note = f"同一轮运行里的两次真读数：这一轮改好 {fixed} 项"
        if worse:
            note += f"，另有 {len(worse)} 项比动手前差（" + "、".join(worse) + "）"
        if incomparable:
            note += f"；{incomparable} 项有一边是「没测到」，不计入对比"
        changed = (f"<section><h2>修复前 → 修复后 <span class='hint'>{_esc(note)}</span></h2>"
                   f"<div class='card'>{''.join(lines)}</div></section>")

    stamp = report.get("timestamp") or dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    meta = [f"<span class='pill'>报告 JSON：{_esc(report_path or '（未保存）')}</span>",
            f"<span class='pill'>生成于 {_esc(stamp)}</span>",
            "<span class='pill'>本页不加载任何外部资源</span>"]
    score_txt = "—" if sc["total"] is None else sc["total"]
    ring_pct = 0 if sc["total"] is None else min(100, sc["total"])
    note_html = (f"<div class='hero-note' style='color:#e8c07d;margin-top:6px'>"
                 f"{_esc(note)}</div>") if note else ""

    # 修复按钮只在本地服务模式下出现（静态文件执行不了命令，出了按钮只会骗人）。
    if live:
        n_fixable = len([r for r in rows if (actions or {}).get(r[0])])
        acts = ("<div class='acts'>"
                f"<button class='fix' data-all='1'>修复全部可自动修的项（{n_fixable} 项）</button>"
                "<button class='fix ghost' data-rescan='1'>重新体检</button></div>")
        foot_acts = "<br><button class='fix ghost' data-stop='1'>结束本地服务</button>"
        script = "<script>" + JS.replace("__BASE__", live) + "</script>"
    else:
        acts = foot_acts = script = ""

    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Claude 环境体检报告 · {_esc(score_txt)} 分</title>
<style>{CSS}</style></head>
<body><div class="wrap">

<div id="flash"></div>

<div class="hero">
  <h1>Claude 环境体检报告</h1>
  <div class="sub">CC tackle · {len(rows)} 项检查（{BASE_ITEMS} 项计分，{_esc(BONUS_ROW)}为加分项）· 未测到的项按 0 分计</div>
  <div class="hero-grid">
    <div class="ring" style="--p:{ring_pct};--ring:{sc['ring']}">
      <div class="ring-in"><div style="text-align:center"><b>{score_txt}</b><br><small>/ {MAX_SCORE}</small></div></div>
    </div>
    <div class="grade">{sc['grade']}<small>综合评分</small></div>
    <div>
      <div class="hero-note">{BASE_ITEMS} 项基础分合计 {BASE_MAX} 分：通过拿满、待处理拿一半、未通过 0 分；「没测到」也按 0 分计，分母固定 {BASE_ITEMS} 项，不折算成剩下几项的比例。{_esc(BONUS_ROW)}是加分项，通过再加 {BONUS_POINTS} 分，满分 {MAX_SCORE}。</div>
      {note_html}
      {delta}
    </div>
  </div>
  <div class="chips">{chips}</div>
  {acts}
  <div class="facts">{facts}</div>
</div>

{resident_html}

<section><h2>分组通过率 <span class="hint">按你在排查什么归类</span></h2>
  <div class="grid g3">{''.join(group_cards)}</div></section>

<section><h2>需要你处理的 <span class="hint">能自动修的已经在运行里处理掉</span></h2>
  {todo_html}</section>

{changed}

<section><h2>逐项结果 <span class="hint">点「看依据」展开这一项的原始读数</span></h2>
  {''.join(item_cards)}</section>

<section><h2>必须人工做的 <span class="hint">{sum(len(x[1]) for x in g.MANUAL_ACTIONS)} 条，脚本碰不到</span></h2>
  {_manual_html(g.MANUAL_ACTIONS)}</section>

<section><h2>自己再核一遍 <span class="hint">这些站脚本不代跑，点开自己看。最后一条是 Chrome 扩展，本 skill 用 <code>--install-webrtc-limiter</code> 把包装下到本机</span></h2>
  {_detection_sites_html()}</section>

<footer>
  {''.join(meta)}<br>
  判定逻辑与终端输出同源（都走 build_summary），页面上的数字没有一处是写死的。<br>
  一键自检：<code>python3 scripts/selfcheck.py</code>　完整加固：<code>python3 scripts/account_guard.py</code>
  {foot_acts}
</footer>
</div>{script}</body></html>
"""


def write_report(report: dict, before: dict = None, out_dir=None,
                 open_it: bool = False, report_path=None, note: str = "") -> pathlib.Path:
    """落盘一份 HTML 报告，返回路径。open_it 为真时在 macOS 上用默认浏览器打开。

    note 原样印在页面顶部（「这一轮没有改动」「已取消」这类上下文）。
    """
    out_dir = pathlib.Path(out_dir) if out_dir else BACKUP_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = out_dir / f"report-{stamp}.html"
    path.write_text(render(report, before=before, report_path=report_path, note=note),
                    encoding="utf-8")
    if open_it and sys.platform == "darwin" and not os.environ.get("CLAUDE_GUARD_NO_OPEN"):
        # 打不开要说出来：Claude Code 的沙箱、SSH、没有 GUI 会话时 `open` 会失败，
        # 以前 check=False + 吞异常，用户只看到一个路径，以为页面没生成。
        try:
            proc = subprocess.run(["open", str(path)], check=False, timeout=15,
                                  capture_output=True, text=True)
            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout or "").strip()
                print(f"没能自动打开报告（open 返回 {proc.returncode}"
                      + (f"：{detail[:120]}" if detail else "") + f"）；路径：{path}",
                      file=sys.stderr)
        except (OSError, subprocess.SubprocessError) as error:
            print(f"没能自动打开报告（{type(error).__name__}: {error}）；路径：{path}",
                  file=sys.stderr)
    return path


def _latest_report() -> pathlib.Path:
    files = sorted(BACKUP_DIR.glob("audit-*.json"))
    if not files:
        sys.exit("找不到 audit-*.json；先跑一次 python3 scripts/account_guard.py --audit")
    return files[-1]


def main() -> int:
    ap = argparse.ArgumentParser(description="把体检报告渲染成自包含的 HTML")
    ap.add_argument("report", nargs="?", help="audit-*.json 路径，默认取最新那份")
    ap.add_argument("--out", help="输出目录，默认 ~/ClaudeGuardBackups")
    ap.add_argument("--open", action="store_true", help="生成后用默认浏览器打开")
    a = ap.parse_args()

    src = pathlib.Path(a.report) if a.report else _latest_report()
    report = json.loads(src.read_text(encoding="utf-8"))
    path = write_report(report, out_dir=a.out, open_it=a.open, report_path=str(src))
    print(f"  报告：{path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
