#!/usr/bin/env python3
"""把「Claude 域名 → 固定住宅出口」翻译成各家客户端能吃的配置片段。

为什么单独一个模块：规则写法各家不一样（mihomo 是 YAML、sing-box 是 JSON、
Surge / Shadowrocket 是 ini 风格的 [Rule]），而这条规则最容易犯的错不是写错语法，
是**组里只放了一个节点**——节点一挂，Claude 就整体打不开，其它网站却一切正常
（2026-10-30 实测踩过）。

所以每个片段都同时给出「组 + 规则」两部分，并且组里默认列出多条入口线路；
只有一条线路时，脚本会显式提醒。

用法（CLI 见 scripts/proxy_guard.py --emit <client>）：
    from client_adapters import emit
    print(emit("mihomo", policy="Claude"))
"""

from __future__ import annotations

import json

# 这些域名必须走同一个固定出口。少一个都会漏：claude.ai 与 claude.com 会互相跳转，
# anthropic.com 是 API/控制台，claudeusercontent.com 是附件预览。
CLAUDE_DOMAINS = (
    "claude.ai",
    "claude.com",
    "anthropic.com",
    "claudeusercontent.com",
)

# 四个「入口线路」占位名。真实名字因订阅而异，CLI 会用 --nodes 覆盖。
DEFAULT_NODES = (
    "住宅线路1",
    "住宅线路2",
    "住宅线路3",
    "住宅线路4",
)


def mihomo_yaml(policy: str = "Claude", nodes: tuple[str, ...] = DEFAULT_NODES) -> str:
    """mihomo 内核（Clash Verge Rev / FlClash / Mihomo Party / ClashX）用的 YAML。"""
    items = "\n".join(f"      - {n}" for n in nodes)
    rules = "\n".join(f"  - DOMAIN-SUFFIX,{d},{policy}" for d in CLAUDE_DOMAINS)
    return (
        "proxy-groups:\n"
        f"  - name: {policy}\n"
        "    type: select        # 想自动切就改 fallback；select 不换节点、只按你选的走\n"
        "    proxies:\n"
        f"{items}\n"
        "\n"
        "rules:\n"
        f"{rules}\n"
        f"  - MATCH,DIRECT\n"
    )


def sing_box_json(policy: str = "claude-residential",
                  nodes: tuple[str, ...] = DEFAULT_NODES) -> str:
    """sing-box 用的 JSON：一个 selector outbound + 域名路由。"""
    outbounds = [{
        "type": "selector",
        "tag": policy,
        "outbounds": list(nodes),
        "default": nodes[0],
    }, {
        "type": "direct",
        "tag": "direct",
    }]
    payload = {
        "outbounds": outbounds,
        "route": {
            "rules": [{
                "domain_suffix": list(CLAUDE_DOMAINS),
                "outbound": policy,
            }],
            "final": "direct",
        },
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def surge_conf(policy: str = "Claude",
               nodes: tuple[str, ...] = DEFAULT_NODES) -> str:
    """Surge 用的 [Proxy Group] + [Rule] 片段。"""
    lines = ["[Proxy Group]",
             f'{policy} = select, {", ".join(nodes)}', "",
             "[Rule]"]
    lines += [f"DOMAIN-SUFFIX,{d},{policy}" for d in CLAUDE_DOMAINS]
    lines.append("FINAL,DIRECT")
    return "\n".join(lines) + "\n"


def shadowrocket_conf(policy: str = "Claude",
                      nodes: tuple[str, ...] = DEFAULT_NODES) -> str:
    """Shadowrocket 用的配置片段（它认 Surge 风格的 [Rule]，组在 App 里建）。"""
    _ = nodes  # 组名由 App 里的策略组提供，这里只用规则
    lines = ["[Rule]"]
    lines += [f"DOMAIN-SUFFIX,{d},{policy}" for d in CLAUDE_DOMAINS]
    lines.append("FINAL,DIRECT")
    return "\n".join(lines) + "\n"


ADAPTERS = {
    "mihomo": mihomo_yaml,
    "clash-verge": mihomo_yaml,
    "flclash": mihomo_yaml,
    "mihomo-party": mihomo_yaml,
    "sing-box": sing_box_json,
    "surge": surge_conf,
    "shadowrocket": shadowrocket_conf,
}


def emit(client: str, policy: str = "Claude",
         nodes: tuple[str, ...] = DEFAULT_NODES) -> str:
    """返回某个客户端的配置片段；未知客户端抛 KeyError。"""
    fn = ADAPTERS[client.strip().lower()]
    return fn(policy=policy, nodes=nodes)


def notes(client: str) -> str:
    """每个客户端「片段贴哪儿」的一句话说明。"""
    key = client.strip().lower()
    table = {
        "mihomo": "贴进 mihomo 的 config.yaml（proxy-groups 与 rules 同级追加）。",
        "clash-verge": "Clash Verge Rev：写进「订阅 → 编辑 → 全局扩展/Merge」，别直接改 clash-verge.yaml"
                       "（订阅一更新就被覆盖）。",
        "flclash": "FlClash：在「配置 → 编辑」里给 profile 加，或做成 Override 配置。",
        "mihomo-party": "Mihomo Party：用「覆写」功能加 group 与 rules，不要只改运行时配置。",
        "sing-box": "sing-box：合并进 config.json 的 outbounds 与 route.rules（节点 outbound 先存在）。",
        "surge": "Surge：Proxy Group 和 Rule 都在策略文件里；Mac 上可直接编辑。",
        "shadowrocket": "Shadowrocket 在 iOS 上，Mac 侧探测不到；在 App 的「配置」里加 [Rule]，"
                        "策略组名要和 App 里建的一致。",
    }
    return table.get(key, "")


if __name__ == "__main__":
    import sys

    client = sys.argv[1] if len(sys.argv) > 1 else "mihomo"
    print(emit(client))
