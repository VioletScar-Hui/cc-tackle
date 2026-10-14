#!/usr/bin/env python3
"""把报告页变成可点的：起一个只绑回环的小服务，页面上的「修复」按钮打到它，
它调用 account_guard 里已有的清理函数，然后把页面刷成新状态。

为什么必须是服务：`file://` 页面执行不了本机命令。要让「点一下就修」成立，浏览器得有
个东西可打——就是这里。

安全边界写死三条，不是可选项：
  1. 只绑 127.0.0.1，端口随机；
  2. 路径前缀是 48 位十六进制随机令牌，用 hmac.compare_digest 比，不带令牌一律 404；
  3. POST 还要再带一个自定义头（跨站表单发不出自定义头，所以别的网页撞不上它），
     并且只认白名单里的动作 —— 这个进程能跑清理函数，不能变成通用执行器。

用法：
    python3 scripts/report_serve.py                # 体检 → 起服务 → 打开浏览器
    python3 scripts/report_serve.py --no-open      # 只打印地址
    python3 scripts/report_serve.py --timeout 600  # 10 分钟没人点就自己退出

页面上的每个按钮都对应一个动作，动作只做这个 skill 本来就敢自己做的事（幂等、可逆、
有备份）：残留清理、DNS、Intl、失效权限、可清理的系统级占用。要你拿主意的（遥测开关、
IPv6、定位服务）和必须人工的（手机时区、支付、浏览器隔离）不出按钮。
"""
from __future__ import annotations

import argparse
import datetime as dt
import hmac
import json
import os
import pathlib
import secrets
import socket
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import account_guard as g  # noqa: E402
import report_html  # noqa: E402

TOKEN_BYTES = 24
MAX_BODY = 65536


# ── 动作表 ────────────────────────────────────────────────────────────────
# 每个动作四件事：按钮上写什么、对应报告里哪几行、动手前备份哪些文件、动完重查哪几项。
# 重查只跑受影响的那几个检查，不重跑整份体检——整份要几十秒，点一下等那么久没人受得了。
def _paths_rc(rep, plan, after=None):
    return [g.HOME / name for name in (plan.get("rc_files") or {})]


def _paths_settings(rep, plan, after=None):
    return [g.SETTINGS]


def _paths_clash(rep, plan, after=None):
    out = [g.clash_config()]
    merge = g._active_merge_enhancement()
    if merge is not None:
        out.append(merge)
    return out


def _paths_dead_perms(rep, plan, after=None):
    # 报告里的 file 是相对家目录的（check_claude_settings 里是 str(f).replace(HOME + "/", "")），
    # 直接当路径用 is_file() 为假，于是这一笔会在没有备份的情况下改文件。
    # HOME / f 对绝对路径返回 f 本身，两种形态都对。
    files = {d["file"] for d in (rep.get("A26_claude_settings") or {}).get("dead") or []}
    return [g.HOME / pathlib.Path(f) for f in files]


def _apply_proxy_residue(rep, plan):
    items = plan.get("proxy_residue") or []
    if not items:
        return "系统代理没有残留，无需改动"
    cleared = g.clear_proxy_residue(items)
    gone = len(items) - cleared
    if not cleared:
        return f"系统代理残留已经不在了（{gone} 项，多半被定时脚本清掉了），无需改动"
    if gone:
        return f"清掉系统代理残留 {cleared} 项，另有 {gone} 项已经不在了"
    return f"清掉系统代理残留 {cleared} 项"


def _apply_rc_proxy(rep, plan):
    files = {k: v for k, v in (plan.get("rc_files") or {}).items() if v}
    if not files:
        return "shell 配置里没有代理行，无需改动"
    return "删掉 shell 配置里的代理行：" + "、".join(g.clear_rc_proxy_lines(files))


def _apply_npm_git(rep, plan):
    if not plan.get("npm_git"):
        return "npm / git 没有设代理，无需改动"
    return "清掉 npm / git 全局代理：" + "、".join(g.clear_npm_git_proxy())


def _apply_settings_endpoint(rep, plan):
    if not (plan.get("settings_base_url") or plan.get("settings_env_proxy")):
        return "settings.json 里没有端点或代理变量，无需改动"
    return g.clear_anthropic_base_url()


def _apply_clash_dns(rep, plan):
    if not plan.get("clash_dns"):
        return "Clash 的 DNS 不含国内解析器，无需改动"
    return g.clear_clash_dns_leak(rep)


def _apply_browser_locale(rep, plan):
    if not plan.get("browser_locale"):
        return "浏览器 Intl 不是大陆简体，无需改动"
    return g.clear_browser_locale(rep.get("A27_browser_locale") or {})


def _apply_storage(rep, plan):
    details = g.clean_claude_storage(rep)
    if not details:
        return "没有可清理的系统级占用"
    freed = sum(d.get("bytes", 0) for d in details if d.get("ok"))
    skipped = [d for d in details if not d.get("ok")]
    # 删掉的东西没有备份可对照，账本必须写：事后能查「哪一次点击删了哪些路径」。
    ledger = g.write_cleanup_manifest("报告页点「清理」触发的系统级清理", details,
                                      extra={"source": "report_serve"})
    msg = f"清掉 {len([d for d in details if d.get('ok')])} 项，释放 {freed / 2 ** 20:.0f} MB"
    if skipped:
        msg += f"；{len(skipped)} 项跳过（{skipped[0].get('error')}）"
    return msg + f"，账本 {ledger}"


def _apply_dead_perms(rep, plan):
    details = g.clean_dead_permissions(rep)
    removed = sum(d.get("removed", 0) for d in details)
    if not removed:
        return "没有失效的权限条目，无需改动"
    return f"删掉 {removed} 条失效授权（涉及 {len([d for d in details if d.get('removed')])} 个文件）"


def _apply_project_claude(rep, plan):
    msgs = []
    junk = [d for d in g.clean_project_claude_junk() if d.get("ok")]
    if junk:
        msgs.append(f"清掉项目级 .claude 里的垃圾 {len(junk)} 项")
    stale = g.prune_stale_worktrees(plan.get("stale_worktrees") or [])
    pruned = sum(len(d.get("removed") or []) for d in stale)
    if pruned:
        msgs.append(f"划掉 {pruned} 条失效的工作树注册（工作树本身没动）")
    return "；".join(msgs) or "没有可自动清理的项目级内容"


ACTIONS = {
    "proxy_residue": {
        "label": "修复",
        "rows": ("系统代理残留",),
        "hint": "清掉系统代理里「已关闭但存了值」的残留，正在使用的代理不动",
        "apply": _apply_proxy_residue,
        "paths": lambda rep, plan, after=None: [],
        "recheck": lambda rep: {"A1_proxy_residue": g.check_proxy_residue()},
    },
    "rc_proxy": {
        "label": "修复",
        "rows": ("终端 / shell / npm / git 代理",),
        "hint": "删掉 shell 配置里的代理行，注释和其它行原样保留",
        "apply": _apply_rc_proxy,
        "paths": _paths_rc,
        "recheck": lambda rep: {"A1_terminal_env": g.check_terminal_env()},
    },
    "npm_git": {
        "label": "修复",
        "rows": ("终端 / shell / npm / git 代理",),
        "hint": "清掉 npm 与 git 的全局代理设置",
        "apply": _apply_npm_git,
        "paths": lambda rep, plan, after=None: [g.HOME / ".npmrc", g.HOME / ".gitconfig"],
        "recheck": lambda rep: {"A1_terminal_env": g.check_terminal_env()},
    },
    "settings_endpoint": {
        "label": "修复",
        "rows": ("settings.json 端点与凭据",),
        "hint": "从 settings.json 的 env 里移除端点、凭据与代理变量，其余键保留",
        "apply": _apply_settings_endpoint,
        "paths": _paths_settings,
        "recheck": lambda rep: {
            "A2_anthropic_base_url": g.check_anthropic_base_url(),
            "A1_terminal_env": g.check_terminal_env(),
        },
    },
    "clash_dns": {
        "label": "修复",
        "rows": ("DNS 泄漏",),
        "hint": "把 Clash 的主解析器换成境外的并打开 respect-rules，然后重载内核",
        "apply": _apply_clash_dns,
        "paths": _paths_clash,
        "recheck": lambda rep: {"A6_dns": {**g.check_dns(), "clash": g.check_clash_dns()}},
    },
    "browser_locale": {
        "label": "修复",
        "rows": ("浏览器 Intl 区域设置",),
        "hint": "把 Chrome 的界面语言设成出口国语言（要重开 Chrome 才生效）",
        "apply": _apply_browser_locale,
        "paths": lambda rep, plan, after=None: [],
        "recheck": lambda rep: {
            "A27_browser_locale": g.check_browser_locale(rep.get("A1_export_ip") or {})},
    },
    "claude_storage": {
        "label": "清理",
        "rows": ("系统级可清理量",),
        "hint": "删掉被取代的旧版本与可再生缓存，当前版本与账号数据不动",
        "apply": _apply_storage,
        "paths": lambda rep, plan, after=None: [],
        "recheck": lambda rep: {"A25_claude_storage": g.check_claude_storage()},
    },
    "dead_permissions": {
        "label": "清理",
        "rows": ("settings 失效权限",),
        "hint": "删掉指向别的机器、已消失路径和一次性 PID 的授权条目",
        "apply": _apply_dead_perms,
        "paths": _paths_dead_perms,
        "recheck": lambda rep: {"A26_claude_settings": g.check_claude_settings()},
    },
    "project_claude": {
        "label": "清理",
        "rows": ("项目级 .claude 规模",),
        "hint": "清掉项目级 .claude 里的垃圾文件，并划掉指向已消失路径的工作树注册",
        "apply": _apply_project_claude,
        "paths": lambda rep, plan, after=None: [],
        "recheck": lambda rep: {"A24_project_claude": g.check_project_claude()},
    },
}

# 反过来查：报告里的某一行，点了会跑哪几个动作
ROW_ACTIONS: dict = {}
for _aid, _spec in ACTIONS.items():
    for _row in _spec["rows"]:
        ROW_ACTIONS.setdefault(_row, []).append(_aid)


def ui_actions(report: dict | None = None) -> dict:
    """给渲染器用的表：行名 → [{id,label,hint}]。

    report_html 不能 import 本模块（本模块已经 import 了它），所以按钮上要显示的文字
    由这里带过去，渲染器只负责摆位置。

    给了 report 就只留有「待处理」行的动作：否则一行已经报绿，上面照样挂着「清理」
    按钮，页头的「可自动修的项」还会把它算进去（2026-10-14 清完缓存后就是这样：
    那 0.4 MB 会自己长回来，行报绿了，按钮却还在）。
    """
    pending = None
    if report is not None:
        pending = {name for name, status, _detail in g.build_summary(report) if status == g.S_FIX}
    out: dict = {}
    for aid, spec in ACTIONS.items():
        for row in spec["rows"]:
            if pending is not None and row not in pending:
                continue
            out.setdefault(row, []).append(
                {"id": aid, "label": spec.get("label", "修复"), "hint": spec.get("hint", "")})
    return out


class State:
    """服务期间的唯一可变状态：一份报告、一把锁、上次有人操作的时间。"""

    def __init__(self, report: dict, roots: str = ""):
        self.report = report
        self.roots = roots
        self.lock = threading.Lock()
        self.touched = time.time()
        # 「结束服务」按钮要把等待循环也叫醒：只调 httpd.shutdown() 的话
        # serve_forever 会返回，但主循环还在 sleep 里打转，进程不退（实测踩到）。
        self.stopping = threading.Event()
        self.log: list = []

    def rows(self):
        return g.build_summary(self.report)

    def fix(self, action_id: str) -> str:
        """跑一个动作：先算计划 → 备份 → 执行 → 重查受影响的那几项。

        顺序不能反。2026-10-14 实测抓到过反的那版：先 apply 再 create_backup，
        于是备份里存的是**已经改过**的文件——点坏了照着它回滚，等于把改完的状态再写一遍。
        现在的规矩和终端流程一致：备份先拍，备份失败就把异常抛出去，那个字一个都不动。
        """
        spec = ACTIONS[action_id]
        plan = g.auto_clean_plan(self.report)
        paths = [p for p in (spec["paths"](self.report, plan) or []) if p and p.is_file()]
        backup_note = ""
        if paths:
            backup_note = f"；备份 {g.create_backup(paths)}"
        message = spec["apply"](self.report, plan)
        self.report.update(spec["recheck"](self.report))
        self.report["timestamp"] = dt.datetime.now().isoformat()
        return message + backup_note


class Handler(BaseHTTPRequestHandler):
    server_version = "claude-account-guard-report"
    state: State = None          # 由 serve() 挂上
    token: str = ""

    # ── 工具 ──
    def _ok_route(self) -> bool:
        """路径必须以 /<token> 开头；不带或不对一律当没有这个路由。"""
        path = self.path.split("?", 1)[0]
        parts = path.split("/")
        if len(parts) < 3 or not hmac.compare_digest(parts[1], self.token):
            return False
        return True

    def _sub(self) -> str:
        parts = self.path.split("?", 1)[0].split("/")
        return parts[2] if len(parts) > 2 else ""

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _origin_ok(self) -> bool:
        """带 Origin 的请求必须来自本服务自己；不带 Origin 的（curl 等）放行。"""
        origin = self.headers.get("Origin")
        if not origin:
            return True
        host = self.headers.get("Host", "")
        return origin == f"http://{host}"

    def log_message(self, fmt, *args):    # 别往 stderr 刷访问日志
        pass

    # ── 路由 ──
    def do_GET(self):
        if not self._ok_route():
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        sub = self._sub()
        st = self.server.state
        if sub in ("", "index.html"):
            html = report_html.render(st.report, live=f"http://{self.headers.get('Host')}/{self.token}",
                                      report_path="（本页由本地服务实时渲染）",
                                      actions=ui_actions(st.report))
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        elif sub == "state":
            self._json(200, {"rows": st.rows(), "timestamp": st.report.get("timestamp")})
        else:
            self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self):
        if not self._ok_route():
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        if not self._origin_ok():
            self._json(403, {"ok": False, "error": "来源不对"})
            return
        # 自定义头：跨站表单发不出它，所以这一条挡住的是「别的网页替我点修复」
        if not hmac.compare_digest(self.headers.get("X-Guard-Token", ""), self.token):
            self._json(403, {"ok": False, "error": "缺少令牌"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            self._json(413, {"ok": False, "error": "请求体过大"})
            return
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw or b"{}")
        except ValueError:
            self._json(400, {"ok": False, "error": "请求体不是 JSON"})
            return

        sub = self._sub()
        st = self.server.state
        if sub == "stop":
            self._json(200, {"ok": True, "messages": ["服务正在退出"]})
            st.stopping.set()
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        if sub == "rescan":
            with st.lock:
                st.report = g.audit()
            self._json(200, {"ok": True, "messages": ["重新体检完成"]})
            return
        if sub != "fix":
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return

        rows = payload.get("rows") if isinstance(payload, dict) else None
        if payload.get("all"):
            wanted = list(ROW_ACTIONS)
        elif isinstance(rows, list):
            wanted = [r for r in rows if r in ROW_ACTIONS]
        else:
            wanted = []
        if not wanted:
            self._json(400, {"ok": False, "error": "没有可执行的行"})
            return

        messages, failed = [], []
        with st.lock:
            st.touched = time.time()
            for row in wanted:
                for action_id in ROW_ACTIONS[row]:
                    try:
                        messages.append(f"{row}：{st.fix(action_id)}")
                    except Exception as error:       # 单个动作失败不影响其余
                        failed.append(f"{row}：{error}")
        self._json(200, {
            "ok": not failed,
            "messages": messages,
            "failed": failed,
            "rows": st.rows(),
        })


def serve(report: dict = None, open_it: bool = True, timeout: int = 1800,
          roots: str = "") -> None:
    if report is None:
        print("  正在体检（约 30 秒）…", flush=True)
        report = g.audit()
    state = State(report, roots=roots)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.state = state
    token = secrets.token_hex(TOKEN_BYTES)
    httpd.token = token
    Handler.token = token
    Handler.state = state
    port = httpd.server_address[1]
    url = f"http://127.0.0.1:{port}/{token}/"

    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"\n  报告页（可点修复）：{url}")
    print(f"  只监听回环，地址里带一次性令牌；{timeout // 60} 分钟没人操作就自己退出。")
    print("  停掉服务：页面上的「结束」按钮，或 Ctrl-C。\n", flush=True)

    if open_it and not os.environ.get("CLAUDE_GUARD_NO_OPEN"):
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        while not state.stopping.wait(5):
            if time.time() - state.touched > timeout:
                print("  长时间没有操作，服务退出。")
                break
    except KeyboardInterrupt:
        print("\n  已停止。")
    finally:
        httpd.shutdown()


def project_roots_default() -> str:
    """和 selfcheck 一个口径：环境变量 → skill 所在的 git 仓 → ~/ipe。"""
    if os.environ.get("CLAUDE_GUARD_PROJECT_ROOTS"):
        return os.environ["CLAUDE_GUARD_PROJECT_ROOTS"]
    skill_dir = HERE.parent
    try:
        code, out = g.run(["git", "-C", str(skill_dir), "rev-parse", "--show-toplevel"], timeout=10)
        if not code and out.strip():
            return out.strip()
    except Exception:
        pass
    fallback = pathlib.Path.home() / "ipe"
    return str(fallback) if fallback.is_dir() else ""


def main() -> int:
    ap = argparse.ArgumentParser(description="带修复按钮的报告页（本地服务）")
    ap.add_argument("--no-open", action="store_true", help="不自动打开浏览器")
    ap.add_argument("--timeout", type=int, default=1800, help="空闲多少秒后退出，默认 1800")
    ap.add_argument("--roots", default=None, help="项目根，默认按环境变量/git 仓/~ipe 推断")
    a = ap.parse_args()
    roots = a.roots if a.roots is not None else project_roots_default()
    if roots:
        os.environ["CLAUDE_GUARD_PROJECT_ROOTS"] = roots
    serve(open_it=not a.no_open, timeout=a.timeout, roots=roots)
    return 0


if __name__ == "__main__":
    sys.exit(main())
