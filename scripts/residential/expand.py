#!/usr/bin/env python3
"""把 Verge 的 GUI 配置展开成完整 mihomo 配置，输出成可直接 PUT 的 payload。

为什么需要它：
    Verge 的 clash-verge.yaml 里有 prepend-rules / prepend-proxy-groups 这类
    Verge 专有字段，mihomo 内核不认。规则能否生效，取决于 Verge 生成时有没有
    展开进 rules。核实不了它每次都展开，就自己展开 —— 展开结果通过
    /configs 热载，不碰 root 属主的 runtime 目录。

校验原则：
    规则里引用的目标必须真实存在（节点或组），否则 mihomo 会拒绝整份配置。
    宁可拒绝写入并报清楚哪条规则非法，也不要灌一份内核不接受的配置进去。

环境变量（由 lib-common.sh 或调用方提供）：
    RESIDENT_NODE   住宅节点名，必须存在于订阅
    VERGE_DIR       Verge 配置目录
    不提供时回退读 claude-residential.env

用法：
    python3 expand.py [-o 输出文件]
    python3 expand.py --check        # 只校验，不写文件
"""
import argparse
import json
import os
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "缺 pyyaml。装一下：\n"
        "  /usr/bin/python3 -m pip install --user pyyaml\n"
    )
    sys.exit(1)


def load_env(path=None):
    """读参数文件，补齐环境变量里没有的项。

    兼容旧格式：早先这套东西用 claude-profile.env，变量名是 NODE_NAME /
    CDN_IPS / PHYS_IFACES，这里一并映射到新名字。
    """
    explicit = os.environ.get("CLAUDE_RESIDENTIAL_ENV")
    path = path or explicit or \
        os.path.expanduser("~/Library/Scripts/claude-residential.env")

    if not os.path.exists(path):
        # 旧名回退只在没有显式指定时生效
        legacy = os.path.expanduser("~/Library/Scripts/claude-profile.env")
        if not explicit and os.path.exists(legacy):
            path = legacy
        else:
            return {}

    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            v = os.path.expandvars(v)
            env[k] = v

    # 旧名 → 新名
    if "RESIDENT_NODE" not in env and "NODE_NAME" in env:
        env["RESIDENT_NODE"] = env["NODE_NAME"]
    return env


def split_rule(rule):
    """按括号深度切分规则。

    逻辑规则(AND/OR/NOT)的 payload 里含逗号，不能直接 str.split：
        AND,((NETWORK,UDP),(IP-CIDR,160.79.104.0/21)),REJECT
          -> ['AND', '((NETWORK,UDP),(IP-CIDR,160.79.104.0/21))', 'REJECT']
    普通规则：
        IP-CIDR,1.2.3.4/32,DIRECT,no-resolve
          -> ['IP-CIDR', '1.2.3.4/32', 'DIRECT', 'no-resolve']
    """
    parts, buf, depth = [], [], 0
    for ch in rule:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return parts


def rule_target(parts):
    """取规则目标（节点 / 组 / DIRECT / REJECT）。

    普通规则目标在 [2]；MATCH 在 [1]；
    逻辑规则在最后一个非 no-resolve 元素。
    """
    if not parts:
        return None
    kind = parts[0].upper()
    if kind == "MATCH":
        return parts[1] if len(parts) > 1 else None
    if kind in ("AND", "OR", "NOT"):
        for p in reversed(parts[1:]):
            if p.lower() not in ("no-resolve", ""):
                return p
        return None
    if len(parts) > 2:
        return parts[2]
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", default=None, help="payload 输出路径")
    ap.add_argument("--check", action="store_true", help="只校验不写文件")
    args = ap.parse_args()

    env = load_env()
    verge = os.environ.get("VERGE_DIR") or env.get("VERGE_DIR") or \
        os.path.expanduser("~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev")
    resident = os.environ.get("RESIDENT_NODE") or env.get("RESIDENT_NODE") or ""

    base_p = os.path.join(verge, "clash-verge.yaml")
    merge_p = os.path.join(verge, "profiles", "Merge.yaml")
    out_p = args.out or os.environ.get("PAYLOAD") or "/tmp/claude-residential-payload.json"

    if not resident:
        sys.stderr.write("RESIDENT_NODE 未设置，拒绝展开（不知道要把规则指向谁）\n")
        return 1
    if not os.path.exists(base_p):
        sys.stderr.write("找不到 %s\n" % base_p)
        return 1

    with open(base_p) as f:
        cfg = yaml.safe_load(f) or {}

    # Merge.yaml 是 Verge GUI 里"当前启用"的那套增强，优先用它的
    merge = {}
    if os.path.exists(merge_p):
        with open(merge_p) as f:
            merge = yaml.safe_load(f) or {}

    pre_rules = merge.get("prepend-rules") or cfg.pop("prepend-rules", []) or []
    pre_groups = merge.get("prepend-proxy-groups") or cfg.pop("prepend-proxy-groups", []) or []
    cfg.pop("prepend-rules", None)
    cfg.pop("prepend-proxy-groups", None)

    rules = cfg.get("rules") or []
    cfg["rules"] = [r for r in pre_rules if r not in rules] + rules

    groups = cfg.get("proxy-groups") or []
    existing = {g.get("name") for g in groups}
    cfg["proxy-groups"] = [g for g in pre_groups if g.get("name") not in existing] + groups

    # 目标校验：引用了不存在的节点/组会让内核拒绝整份配置
    node_names = {x.get("name") for x in cfg.get("proxies") or []}
    group_names = {g.get("name") for g in cfg["proxy-groups"]}
    valid = node_names | group_names | {
        "DIRECT", "REJECT", "PASS", "REJECT-DROP", "COMPATIBLE"}

    bad = []
    for rule in cfg["rules"]:
        if not isinstance(rule, str):
            bad.append(str(rule))
            continue
        parts = split_rule(rule)
        if len(parts) < 2:
            bad.append(rule)
            continue
        target = rule_target(parts)
        if target and target not in valid:
            bad.append(rule)
    if bad:
        sys.stderr.write("规则目标非法，拒绝写入：\n  " + "\n  ".join(bad) + "\n")
        return 1

    # 住宅节点必须在订阅里，否则整套策略没有落点
    if resident not in node_names:
        sys.stderr.write(
            "住宅节点 \"%s\" 不在订阅里，拒绝写入。\n"
            "检查参数文件里的 RESIDENT_NODE 是否和订阅里的名字完全一致"
            "（空格/括号/中文都要一致）。\n" % resident)
        return 1

    n_claude = sum(1 for r in cfg["rules"]
                   if isinstance(r, str) and resident in r)
    if args.check:
        print("ok: %d rules (%d 指向住宅), %d groups, 住宅节点在订阅里"
              % (len(cfg["rules"]), n_claude, len(cfg["proxy-groups"])))
        return 0

    body = json.dumps(
        {"payload": yaml.safe_dump(cfg, allow_unicode=True,
                                   sort_keys=False, width=100000),
         "force": True},
        ensure_ascii=False)
    with open(out_p, "w") as f:
        f.write(body)
    print("payload ok: %d bytes, %d rules, %d groups"
          % (len(body), len(cfg["rules"]), len(cfg["proxy-groups"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
