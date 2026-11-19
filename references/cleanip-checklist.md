# CleanIP 的 Claude 检查维度怎么落地

来源：<https://cleanip.io/claude>（本页 2026-11-19 读取；站点自述 2026-05-23 上线）。
它的官方依据是 Anthropic 的 Supported Regions Policy
（<https://www.anthropic.com/legal/supported-regions>，2026-11-12 生效版本）。

这一页给的是「Claude 会怎么看你这次访问」的检查维度：出口地区是否受支持、出口像不像
代理/VPN/机房、Claude 各域名是不是同一个出口、WebRTC 与 DNS 有没有泄漏真实 IP、浏览器
环境像不像中国大陆用户。cc-tackle 原本的 28 行已经覆盖了泄漏、时区、浏览器 Intl 等部分；
2026-11-19 把剩下能在这台机器上复现的四项并进总表，共 32 行。

## 它检查什么，我们落成哪一行

| CleanIP 的维度 | cc-tackle 的行 | 数据来源（本机实测） | 没照搬的部分 |
| --- | --- | --- | --- |
| 支持地区（硬门槛，185 国白名单） | Claude 支持地区 | 三个 Claude 域名的 Cloudflare `trace` 里的 `loc`，再与地理库 `country` 交叉 | 不复制它的私有地区库 |
| 出口网络画像（Tor / 代理 / 住宅代理 / VPN / WARP） | 出口 IP 纯净度 | `ip-api` 的 `proxy`/`hosting`/`mobile`、`proxycheck.io` 的 `proxy`/`type`、org/ASN 名里的已知 VPN 厂商 | 它的 `api.proxypurity.com` 私有信誉库 |
| 滥用与黑名单 | 出口 IP 纯净度（同上） | `dnsbl.sorbs.net`、`bl.spamcop.net`、`psbl.surriel.com`、`dnsbl.zapbl.net` 的 DoH 查询 | 它的 abuse 分值 |
| 各域名是否同一出口、IPv4 / IPv6 是否跨国家 | Claude 域名出口一致性 | `claude.ai` / `api.anthropic.com` / `platform.claude.com` 的 `/cdn-cgi/trace`（ip / loc / colo）；有全局 IPv6 时再查一次 v6 trace | 它按 /24、ASN 做的细节聚合 |
| WebRTC 真实 IP 暴露 | WebRTC 泄漏（原有） | 本地复核页 + 强制授权的 ICE 探测 | — |
| DNS 泄漏 | DNS 泄漏（原有） | 解析器配置 + fake-ip 结果 + Tailscale 接管检查 | 它另发探针域名的做法 |
| 浏览器侧大陆特征 7 项 | 大陆环境特征（估算） | 本轮浏览器复核页回传：时区、浏览器语言、Intl 区域、非系统预装中文字体、国产厂商字体、国产浏览器 UA、国产设备；`webdriver` / cookie 作自动化痕迹 | 它的 0–100 总分与加权门控 |
| 账号层面的手机号 / 付款卡 / 股权归属 | 无（明确不做） | 站外检测不到，写进边界说明 | 它的账号建议 |

## 判据细节

- **支持地区**：`SUPPORTED_REGIONS` 是 185 个 ISO 3166-1 二位码，来自官方政策页；
  白名单之外一律不支持（港澳不在名单内，台湾在）。Cloudflare 说支持、地理库说不支持时
  报「分歧」，不替用户合并成一个「不支持」；两边都在名单内但国家不同，报「归属不稳」。
- **出口 IP 纯净度**：普通机房 / IDC 标签**不单独扣分**（CleanIP 与官方 FAQ 都是这个口径）；
  真正算信号的是代理 / VPN / Tor / 住宅代理 / 黑名单这些。拿不到的数据源写成「未确认」，
  不写成「干净」。
- **大陆环境特征**：7 项权重取自该页客户端配置里同一组值
  （时区 30 / 语言 22 / 字体 14 / 国产字体 12 / 国产浏览器 10 / 国产设备 6 / Intl 6），
  分档 0–30 低、31–60 中、61+ 高。**这是估算**：7 项里只有「系统时区」对应社区披露的
  机制（FuckClaude 对中转端点的逆向分析），其余是相关特征，不是 Anthropic 的官方判定。

## 故意不照搬的部分

- 不调用 `cleanip.io` 或 `api.proxypurity.com`：行里只依赖公开、可复现的数据源；它的
  私有信誉库站外复现不了，也不适合让体检依赖第三方服务端。
- 不复刻它的 0–100 总分、`blocked` / `watch` 分档：把第三方评分当成官方判定，会让
  报告比证据本身更权威。
- 不读它的历史记录、不提交本机环境：7 项环境特征在我们的复核页里本地计算，
  和其他复核结果一样只回传本机脚本。

## 已知边界

- Cloudflare `trace` 只代表 Cloudflare 这一跳的观测；企业代理、CDN 回源、ESNI 场景
  可能有出入。
- `ip-api` / `proxycheck.io` 有免费额度与速率限制，DNSBL 可能拒绝公共解析器
  （返回 `127.255.255.x` 是「拒查」不是「命中」）；这些都按「未确认」处理。
- 地理库之间可能判出不同国家；报告分开列，不隐藏分歧。
- 官方支持地区名单会调整；页内代码更新后要同步 `SUPPORTED_REGIONS`，单测钉住 185
  这个数字和几个代表国家，改了就必须一起改。

## 怎么更新

- 官方名单变了：从政策页抄国家清单 → 改 `SUPPORTED_REGIONS` 与单测期望值。
- 想调大陆特征权重：改 `CN_ENV_WEIGHTS`，并同步 SKILL / README 里的说明。
- CleanIP 加了新维度：先确认有没有公开、可复现的数据源；没有就只在人工核对入口里
  加链接，不硬造一行「已确认」。
