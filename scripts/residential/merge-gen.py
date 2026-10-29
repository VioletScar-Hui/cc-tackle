#!/usr/bin/env python3
# 从参数文件生成 Verge 的 Merge.yaml 增强规则。
#
# 为什么需要它：
#   expand.py 只"读" Merge.yaml，不会生成。团队里每个人的 Verge 是各自装的，
#   同事机器上没有这份 Merge.yaml 时 prepend-rules 为空 —— 9 条 Claude 规则
#   和 11 条 UDP REJECT 一条都不会进内核，整套方案静默失效。
#   guard.sh 以前遇到这种情况只能说"无备份可用，需重新写入"，把活留给人。
#
# 规则构成（数量由参数决定，不写死）：
#   UDP REJECT     = 域名 + CDN + ANTHROPIC_V4 + STUN端口  （不含 v6）
#   Claude 指向住宅 = 域名 + CDN + ANTHROPIC_V4 + ANTHROPIC_V6
# 这两个公式与 guard.sh 的 EXPECT_UDP / EXPECT_CLAUDE 完全一致，改一处必须改两处。
#
# 用法：
#   merge-gen.py                写入 <VERGE_DIR>/profiles/Merge.yaml（已有则拒绝）
#   merge-gen.py --force        覆盖（原文件先备份）
#   merge-gen.py --dry-run      只校验并报告，不落盘
#   merge-gen.py --stdout       打印全文
#   merge-gen.py --with-dns     额外生成 dns 段（redir-host / 1053）
#
# 退出码：0 成功 / 1 参数缺失 / 2 目标已存在且未加 --force

import os
import sys

ENV_FILE = os.environ.get("CLAUDE_RESIDENTIAL_ENV") or \
    os.path.expanduser("~/Library/Scripts/claude-residential.env")
LEGACY = os.path.expanduser("~/Library/Scripts/claude-profile.env")
STUN_DEFAULT = "3478 5349 19302-19309"


def load_env():
    # 显式指定 CLAUDE_RESIDENTIAL_ENV 时必须认它：不存在就报错，
    # 不能悄悄回退到别的文件——否则"换了路径测试"会实际作用到真配置上。
    explicit = os.environ.get("CLAUDE_RESIDENTIAL_ENV")
    if explicit:
        if not os.path.exists(explicit):
            sys.stderr.write("指定的参数文件不存在：%s\n" % explicit)
            return None
        path = explicit
    elif os.path.exists(ENV_FILE):
        path = ENV_FILE
    elif os.path.exists(LEGACY):
        path = LEGACY          # 旧名兼容，仅在未显式指定时生效
    else:
        sys.stderr.write("找不到参数文件：%s\n" % ENV_FILE)
        return None

    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            if k.startswith("export "):
                k = k[7:].strip()
            v = v.strip().strip('"').strip("'")
            v = os.path.expandvars(v)
            env[k] = v

    # 旧名兼容
    if "RESIDENT_NODE" not in env and "NODE_NAME" in env:
        env["RESIDENT_NODE"] = env["NODE_NAME"]
    return env


def build(env, with_dns=False):
    """按参数拼出 Merge.yaml 内容。返回 (文本, 统计)。"""
    node = env.get("RESIDENT_NODE", "")
    domains = (env.get("CLAUDE_DOMAINS") or "").split()
    cdns = [c.split("/")[0] for c in (env.get("CDN_IPS") or "").split()]
    v4 = (env.get("ANTHROPIC_V4") or "").split()
    v6 = (env.get("ANTHROPIC_V6") or "").split()
    stun = (env.get("STUN_PORTS") or STUN_DEFAULT).split()

    if not node or not domains:
        return None, {}

    udp, claude = [], []

    # ── UDP 全封 ──────────────────────────────────────────
    # 家宽链路只承载 TCP。UDP 在 VPS 侧本地 NAT 出去，出口是 VPS 入口 IP
    # 而非住宅出口 —— 这一层修不了，只能断掉。宁可 UDP 不通，也不降级。
    # 按端口封是必须的：浏览器/Electron 会向任意公共 STUN 服务器发探测，
    # 只封 Anthropic 域名拦不住 WebRTC。
    for d in domains:
        udp.append("AND,((NETWORK,UDP),(DOMAIN-SUFFIX,%s)),REJECT" % d)
    for c in cdns:
        udp.append("AND,((NETWORK,UDP),(IP-CIDR,%s/32)),REJECT" % c)
    for n in v4:
        udp.append("AND,((NETWORK,UDP),(IP-CIDR,%s)),REJECT" % n)
    for p in stun:
        udp.append("AND,((NETWORK,UDP),(DST-PORT,%s)),REJECT" % p)

    # ── Claude 流量指向住宅节点 ────────────────────────────
    # 直指节点名，不进任何 Selector/URLTest 组：组是可切换的，节点名不是。
    # 这才是"不 fallback"能成立的原因，换成组名就等于留了后门。
    for d in domains:
        claude.append("DOMAIN-SUFFIX,%s,%s" % (d, node))
    for c in cdns:
        claude.append("IP-CIDR,%s/32,%s,no-resolve" % (c, node))
    for n in v4:
        claude.append("IP-CIDR,%s,%s,no-resolve" % (n, node))
    for n in v6:
        # IPv6 必须用 IP-CIDR6，写成 IP-CIDR 内核不认
        claude.append("IP-CIDR6,%s,%s,no-resolve" % (n, node))

    L = []
    L.append("# Claude 住宅链路增强规则")
    L.append("#")
    L.append("# 由 merge-gen.py 按 claude-residential.env 生成，不要手改。")
    L.append("# 改了参数文件就重跑 merge-gen.py。")
    L.append("#")
    L.append("# 这些规则必须放在 prepend-rules 里，不能追加到 rules 末尾：")
    L.append("# 订阅自带的 MATCH 会兜走一切，排在它后面等于没写。")
    L.append("")
    L.append("profile:")
    L.append("  store-selected: true")
    L.append("")
    L.append("prepend-rules:")
    L.append("")
    L.append("  # ── UDP 封堵 ──────────────────────────────────────")
    L.append("  # 家宽链路只承载 TCP，UDP 走 VPS 侧 NAT，出口是 VPS 入口 IP。")
    L.append("  # 修不了，只能断掉——宁可 UDP 不通，也不泄漏非住宅 IP。")
    L.append("  # 逻辑规则 AND+NETWORK,UDP 在 mihomo v1.19.32 上实测可命中。")
    for r in udp:
        L.append("  - %s" % r)
    L.append("")
    L.append("  # ── WebRTC / STUN / TURN 端口 ─────────────────────")
    L.append("  # 见上：探测不限于 Claude 域名，浏览器会打任意公共 STUN 服务器，")
    L.append("  # 所以按端口封，不能只按域名封。")
    L.append("")
    L.append("  # ── Claude 流量直指住宅节点 ────────────────────────")
    L.append("  # 直指节点名而非组名：组能切，节点名不能。")
    for r in claude:
        L.append("  - %s" % r)
    L.append("")

    if with_dns:
        # 可选段。redir-host 让客户端拿到真实 IP，内核重启后浏览器缓存的
        # 域名不会指错；fake-ip 在重启后容易拿到陈旧映射。
        L.append("dns:")
        L.append("  enable: true")
        L.append("  listen: 0.0.0.0:1053")
        L.append("  ipv6: false")
        L.append("  enhanced-mode: redir-host")
        L.append("  fake-ip-range: 198.18.0.1/16")
        L.append("")

    stats = {
        "udp": len(udp),
        "claude": len(claude),
        "domains": len(domains),
        "cdns": len(cdns),
        "v4": len(v4),
        "v6": len(v6),
        "stun": len(stun),
    }
    return "\n".join(L) + "\n", stats


def main():
    args = sys.argv[1:]
    dry = "--dry-run" in args
    to_stdout = "--stdout" in args
    force = "--force" in args
    with_dns = "--with-dns" in args

    env = load_env()
    if env is None:
        return 1

    text, st = build(env, with_dns=with_dns)
    if text is None:
        sys.stderr.write("参数不全：RESIDENT_NODE 与 CLAUDE_DOMAINS 必须有值。\n")
        return 1

    # 与 guard.sh 的期望值对齐，避免生成出 guard 会判"偏离"的配置
    want_udp = st["domains"] + st["cdns"] + st["v4"] + st["stun"]
    want_claude = st["domains"] + st["cdns"] + st["v4"] + st["v6"]
    if st["udp"] != want_udp or st["claude"] != want_claude:
        sys.stderr.write("内部计数不一致，拒绝写入（udp %d/%d claude %d/%d）\n"
                         % (st["udp"], want_udp, st["claude"], want_claude))
        return 1

    summary = ("  UDP REJECT      %d 条（域名 %d + CDN %d + v4 %d + 端口 %d）\n"
               "  Claude 指住宅    %d 条（域名 %d + CDN %d + v4 %d + v6 %d）\n"
               % (st["udp"], st["domains"], st["cdns"], st["v4"], st["stun"],
                  st["claude"], st["domains"], st["cdns"], st["v4"], st["v6"]))

    if to_stdout or dry:
        if to_stdout:
            sys.stdout.write(text)
        if dry:
            sys.stderr.write("[dry-run] 规则数校验通过\n" + summary)
        return 0

    verge = os.environ.get("VERGE_DIR") or env.get("VERGE_DIR") or \
        os.path.expanduser(
            "~/Library/Application Support/"
            "io.github.clash-verge-rev.clash-verge-rev")
    target = os.path.join(verge, "profiles", "Merge.yaml")

    if os.path.exists(target) and not force:
        sys.stderr.write(
            "已存在：%s\n不加 --force 不会动它。\n" % target)
        return 2

    os.makedirs(os.path.dirname(target), exist_ok=True)

    if os.path.exists(target):
        import time
        bak = "%s.bak-%s" % (target, time.strftime("%Y%m%d-%H%M%S"))
        os.rename(target, bak)
        sys.stderr.write("已备份：%s\n" % bak)

    with open(target, "w") as f:
        f.write(text)

    sys.stderr.write("已写入 %s\n%s" % (target, summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
