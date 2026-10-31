# Claude 固定出口：各家客户端适配

把 `claude.ai / claude.com / anthropic.com / claudeusercontent.com` 钉在一个住宅出口上，
规则本身很简单，容易错的是**组里只放一条线路**：那条线路一挂，Claude 全家打不开，
而其它网站全部正常——因为它走的是别的组。

## 通用原则

1. **组里至少两条入口线路**。同一个住宅出口的多条入口线路，随便挂一条都不至于全断。
2. 想自动切就用 `fallback` / `url-test`；想钉死就 `select`，但要把所有入口都列进去。
3. 规则只写四个域名，别写 `MATCH`——兜底留给正常分流。
4. 订阅换节点名之后，组里的旧名字会失效，记得跑一次 `scripts/proxy_guard.py --check`。

## mihomo 内核（Clash Verge Rev / FlClash / Mihomo Party / ClashX）

```yaml
proxy-groups:
  - name: Claude
    type: select        # 想自动切就改 fallback；select 不换节点、只按你选的走
    proxies:
      - 住宅线路1
      - 住宅线路2
      - 住宅线路3
      - 住宅线路4

rules:
  - DOMAIN-SUFFIX,claude.ai,Claude
  - DOMAIN-SUFFIX,claude.com,Claude
  - DOMAIN-SUFFIX,anthropic.com,Claude
  - DOMAIN-SUFFIX,claudeusercontent.com,Claude
  - MATCH,DIRECT
```

贴哪里：

- Clash Verge Rev：订阅 → 编辑 → **全局扩展 / Merge**（写进 `clash-verge.yaml` 会被订阅更新覆盖）
- FlClash：配置 → 编辑 → Override/覆写
- Mihomo Party：用「覆写」功能
- ClashX：直接改 profile

## sing-box

```json
{
  "outbounds": [
    {
      "type": "selector",
      "tag": "Claude",
      "outbounds": [
        "住宅线路1",
        "住宅线路2",
        "住宅线路3",
        "住宅线路4"
      ],
      "default": "住宅线路1"
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": [
      {
        "domain_suffix": [
          "claude.ai",
          "claude.com",
          "anthropic.com",
          "claudeusercontent.com"
        ],
        "outbound": "Claude"
      }
    ],
    "final": "direct"
  }
}```

合并进 `config.json`：`outbounds` 里补上你的节点，`route.rules` 追加这一段；`route.final` 保持原来的兜底。

## Surge

```ini
[Proxy Group]
Claude = select, 住宅线路1, 住宅线路2, 住宅线路3, 住宅线路4

[Rule]
DOMAIN-SUFFIX,claude.ai,Claude
DOMAIN-SUFFIX,claude.com,Claude
DOMAIN-SUFFIX,anthropic.com,Claude
DOMAIN-SUFFIX,claudeusercontent.com,Claude
FINAL,DIRECT
```

`[Proxy Group]` 里的线路名换成你自己的；规则放 `[Rule]`。Surge 没有可查询的本地 API，
脚本只负责生成片段，不探测。

## Shadowrocket

```ini
[Rule]
DOMAIN-SUFFIX,claude.ai,Claude
DOMAIN-SUFFIX,claude.com,Claude
DOMAIN-SUFFIX,anthropic.com,Claude
DOMAIN-SUFFIX,claudeusercontent.com,Claude
FINAL,DIRECT
```

Shadowrocket 在 iOS 上，Mac 侧探测不到。在 App 里先建一个策略组（选住宅节点），
再把上面几条 `DOMAIN-SUFFIX` 加进「配置 → 规则」。

## 探测能力对照

| 客户端 | 能自动体检 | 说明 |
| --- | --- | --- |
| Clash Verge Rev / FlClash / Mihomo Party / mihomo | ✅ | 通过 mihomo 控制 socket 读 `/proxies` 和 `/rules` |
| Surge | ❌ | 只能给配置片段 |
| Shadowrocket | ❌ | iOS，Mac 上探测不到 |
| sing-box | ❌ | 只能给配置片段 |

## 2026-10-30 的事故

- **症状**：claude.ai 握手到一半断开，claude.com 也打不开；GitHub、Google 全部正常。
- **原因**：Claude 组只有一个成员「连接线路1」，这条线路当天挂了；`select` 组不自动切换，
  于是 Claude 流量全部失败。其它网站走 `IpEqual` 组，所以看起来「网络没问题」。
- **修复**：把 4 条入口线路都加进 Claude 组，切到线路4；出口 IP 没变（同一个住宅 IP）。
- **教训**：单点组是隐性单点故障，报告里要能一眼看出来——这就是 `proxy_guard.py` 存在的理由。
