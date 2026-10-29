#!/usr/bin/env python3
"""Claude DNS 守卫：代理不健康时对 Claude 域名返回 NXDOMAIN。

代理不健康（无响应 / 状态过期 / 出口在中国大陆）时，Claude 域名返回 NXDOMAIN，
让任何应用连解析都做不到。其余域名原样转发上游。

Claude 域名单独走 CLAUDE_UPSTREAM（本机 mihomo DNS），查询经隧道以 DoH 出网，
不会以明文送给国内公共 DNS。非 Claude 域名仍走上游列表。

由 harden-root.sh 安装到 /usr/local/libexec/，由 LaunchDaemon 以 root 拉起。
配置从 /usr/local/etc/claude-residential/ 读，不写死在代码里。
"""
import json
import os
import socket
import sys
import time

ETC = "/usr/local/etc/claude-residential"
STATE_FILE = "/var/tmp/claude-residential-state.json"
DOMAINS_FILE = os.path.join(ETC, "domains.txt")
UPSTREAMS_FILE = os.path.join(ETC, "upstreams.txt")
CONFIG_ENV = os.path.join(ETC, "config.env")
LOG = "/var/log/claude-residential-dns.log"

STATE_MAX_AGE = 900


def log(msg):
    try:
        with open(LOG, "a") as f:
            f.write("%s %s\n" % (time.strftime("%F %T"), msg))
    except OSError:
        pass


def read_env(path):
    """读 key=value 形式的配置文件，忽略注释。"""
    out = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def load_lines(path):
    try:
        with open(path) as f:
            return [l.split("#")[0].strip() for l in f if l.split("#")[0].strip()]
    except OSError:
        return []


def load_domains():
    ds = [l.lower().lstrip(".") for l in load_lines(DOMAINS_FILE)]
    # 兜底：配置文件缺失时至少守住主域名
    return ds or ["claude.ai", "claude.com", "anthropic.com",
                  "claudeusercontent.com"]


def load_upstreams():
    ups = [(l, 53) for l in load_lines(UPSTREAMS_FILE)]
    return ups or [("223.5.5.5", 53), ("119.29.29.29", 53)]


cfg = read_env(CONFIG_ENV)
LISTEN = (cfg.get("DNS_GUARD_LISTEN", "127.0.0.1"), int(cfg.get("DNS_GUARD_PORT", "53")))
CLAUDE_UPSTREAM = (cfg.get("MIHOMO_DNS", "127.0.0.1"),
                   int(cfg.get("MIHOMO_DNS_PORT", "1053")))

DOMAINS = load_domains()
UPSTREAMS = load_upstreams()


def proxy_healthy():
    try:
        with open(STATE_FILE) as f:
            st = json.load(f)
        if time.time() - float(st.get("ts", 0)) > STATE_MAX_AGE:
            return False
        return bool(st.get("healthy")) and st.get("country") != "CN"
    except Exception:
        return False


def parse_qname(pkt):
    i = 12
    labels = []
    while i < len(pkt):
        n = pkt[i]
        if n == 0:
            return ".".join(labels).lower(), i + 5
        if n & 0xC0 or i + 1 + n > len(pkt):
            return None, None
        labels.append(pkt[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return None, None


def is_blocked(name):
    return any(name == d or name.endswith("." + d) for d in DOMAINS)


def nxdomain(pkt, qend):
    return pkt[:2] + b"\x81\x83" + pkt[4:6] + b"\x00\x00\x00\x00\x00\x00" + pkt[12:qend]


def servfail(pkt, qend):
    return pkt[:2] + b"\x81\x82" + pkt[4:6] + b"\x00\x00\x00\x00\x00\x00" + pkt[12:qend]


def forward(pkt, upstreams):
    for up in upstreams:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(4)
            s.sendto(pkt, up)
            data, _ = s.recvfrom(65535)
            s.close()
            return data
        except OSError:
            continue
    return None


def main():
    global DOMAINS, UPSTREAMS
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        srv.bind(LISTEN)
    except OSError as e:
        sys.stderr.write("bind %s:%d 失败: %s\n" % (LISTEN[0], LISTEN[1], e))
        sys.stderr.write("（端口 53 需要 root；或该端口已被其它 DNS 占用）\n")
        return 1
    log("dns-guard started, domains=%d claude_up=%s:%d upstreams=%s"
        % (len(DOMAINS), CLAUDE_UPSTREAM[0], CLAUDE_UPSTREAM[1],
           ",".join(u[0] for u in UPSTREAMS)))
    last_reload = time.time()
    while True:
        pkt, addr = srv.recvfrom(65535)
        if len(pkt) < 13:
            continue
        if time.time() - last_reload > 3600:
            DOMAINS = load_domains()
            UPSTREAMS = load_upstreams()
            last_reload = time.time()
        name, qend = parse_qname(pkt)
        if name is None:
            continue
        claude = is_blocked(name)
        if claude and not proxy_healthy():
            srv.sendto(nxdomain(pkt, qend), addr)
            log("NXDOMAIN %s (proxy unhealthy)" % name)
            continue
        if claude:
            resp = forward(pkt, [CLAUDE_UPSTREAM])
            if resp is None:
                resp = forward(pkt, UPSTREAMS)
        else:
            resp = forward(pkt, UPSTREAMS)
        srv.sendto(resp if resp is not None else servfail(pkt, qend), addr)


if __name__ == "__main__":
    sys.exit(main() or 0)
