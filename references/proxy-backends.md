# 代理后端：不只是 Clash

体检里真正依赖代理软件的只有两行：「绝不直连」与「DNS 泄漏」。其余各项（出口 IP 与
ASN 类型、系统代理残留、终端与 shell 残留、时区、CLI 完整性、浏览器两项）与代理软件
无关，用哪一家都照跑。这一节说的是那两行怎么按后端分派。

脚本会先认出这台机器上是哪一家（报告里的 `A28_proxy_backend`），再说清对它了解到什么
程度：能力矩阵写在 `_capabilities()` 里，判定写在 `backend_row()` /
`backend_routing_row()` / `backend_dns_row()` 三个函数里。

## 认哪些、怎么认

| 后端 | 怎么认出来 | 读 DNS | 读分流 | 能改 DNS | 改完能就地复验 |
| --- | --- | --- | --- | --- | --- |
| mihomo 内核 | unix socket 探活，或进程名 | 配置文件 | 控制接口 `/configs`、`/proxies`、`/rules` | 能 | 能（写配置 + `PUT /configs` + 复读） |
| sing-box | 进程名或配置文件 | `dns.servers` | `clash_api`（要开才有） | 能 | 不能，靠 SIGHUP 重载 |
| Surge | 进程名或 profile 文件 | `dns-server` | HTTP API（要配 `http-api`） | 不改文件，指到界面 | — |
| v2ray / Xray | 进程名或 `config.json` | `dns.servers` | `routing.rules`（静态） | 能 | 不能，且**绝不发 SIGHUP** |
| 只有系统代理 | `scutil --proxy` | — | 没有分流概念 | — | — |
| VPN 隧道 | `scutil --nc list` | — | 没有域名分流 | — | — |
| 认得出进程但格式不认识 | 进程名 | — | — | — | — |

mihomo 一家的控制接口位置就不统一，代码里都列了：Clash Verge 的 unix socket（服务模式下
在 `/var/run/clash-verge-service/users/<uid>/verge-mihomo.sock`）、ClashX 的
`127.0.0.1:8080`（TCP，不是 socket）、Mihomo Party 的 `/tmp/mihomo-party-<uid>-<pid>.sock`。
FlClash 的内核也是 mihomo，但它用自家的 JSON-RPC socket，不认 Clash API——脚本认得出
进程、拿不到控制接口，这正是事实，照实说。

## 四条硬规矩

**静态读配置不等于运行时。** sing-box 与 v2ray 的配置读起来是一回事，正在跑的进程用的
可能是另一份。所以要拿 `ps` 里的命令行核对：进程写的是 `-c <路径>` 且与读到的配置是同一
个文件时，才允许据此报绿；对不上就只报事实，并说明「正在跑的进程命令行里没写配置文件
路径，不能据此报绿」。mihomo 与 Surge 靠控制接口拿运行时状态，不受这条限制。

**只有「改完能复验」的才自动改。** mihomo 走原来的路（写生成物与 Merge 增强文件 +
`PUT /configs` + 复读核对）。sing-box / v2ray / Surge 的配置改动要显式加
`--fix-unverified`：改完能不能生效取决于那个软件自己重启，脚本验不了，所以默认只报告，
把命令和后果写清楚，由用户决定。

**绝不替别家改分流规则。** 换解析器地址是一件事，改完能复读核对；分流规则写错就是断网
或漏流量，所以只报告。带 `domains` / `expectIPs` 的分流式解析器也不动——那是刻意的分流
语义。复读核对用的是同一套跳过规则，否则会把这些故意留着的解析器误报成没改干净
（2026-10-15 的用例抓到的就是这个）。

**认不出来就说认不出来。** 进程认得出、配置格式不认识时，那一行写「脚本不认识它的配置
格式」，并给人工核对命令；不留白，也不假装通过。

## 重载：各家官方支持的方式不一样

| 后端 | 重载方式 | 依据 |
| --- | --- | --- |
| mihomo | `PUT /configs` 指向新配置，`force: true` | 实测返回 204 并生效 |
| sing-box | **SIGHUP** | 官方 `cmd/sing-box/cmd_run.go` 注册了 `syscall.SIGHUP`，收到后先校验配置再重建实例；校验不过就跳过，不会把服务搞死 |
| Surge | `POST /v1/profiles/reload` | 官方 HTTP API 手册 |
| v2ray / Xray | **没有重载接口** | 它们的 `main/run.go` 只注册了 `SIGINT` 与 `SIGTERM`；**收到 SIGHUP 会走默认动作直接杀掉进程**，脚本里绝不能写 |

sing-box 的 `PUT /configs` 是注册了但什么都不做的空实现（实测：发
`{"mode":"global"}` 返回 204，再读 `/configs` 里 mode 仍是 `Rule`），所以不要用它重载。
sing-box 的 `clash_api.external_controller` 为空时 API 是**关闭**的，不是默认 9090——
把「没开」说成「连不上」是两回事。

## 对任何后端都成立的一条：流量有没有真的被接管

`scutil --proxy` 四个开关全 0，流量照样可能已经被 TUN 接管。本机实测：四个开关全 0，而
`route -n get 1.1.1.1` 返回 `interface: utun1024`。所以判据是三条：

1. 去一个公网地址走哪个网卡（`route -n get 1.1.1.1` 的 `interface:`），以及路由表里
   指向该 utun 的那些具体路由（`netstat -rn -f inet`；代理插的是一串覆盖全网的具体路由，
   不是改 default）；
2. 那个 utun **有没有 IPv4 地址**——系统自带的 utun 只有链路本地 v6，代理的才有 v4。
   这是区分两者唯一可靠的办法，`flags` 和 `status:` 都判不出来；
3. 本机有没有**真能完成 SOCKS5 握手**的端口。端口开着不等于它是代理：本机实测过一个
   LISTEN 着的端口，收到 SOCKS 握手回的是 `HTTP/1.1 400 Bad Request`。

认不出后端时，这一条是唯一还能说的实话：配置读不到，但「流量确实进了隧道 utun1024
（198.18.0.1）」这种话是站得住的。

## 真机验证到什么程度（2026-10-15）

本机只有 Clash Verge（mihomo）与**下载到 /tmp 的 sing-box 1.14.3**，所以：

- **mihomo 全链路**：本机常态运行，识别、判读、修复都跑过。
- **sing-box 全链路（真跑，未改系统）**：在 `/tmp` 起真 sing-box（`clash_api` 监听
  19090，配置里放一个国内解析器 `223.5.5.5` 与一个带 `detour` 的境外解析器）。验证了：
  读取器认得出三种解析器形态与 `domain_suffix` 规则；判读报出「国内解析器没配 detour」；
  修复把 `223.5.5.5` 换成 `1.1.1.1` 且 `tag`、`detour`、`inbounds`、`experimental` 等键
  一个没动；复读核对通过；`running_config_for()` 从进程命令行认出了正在用的那份配置；
  发 SIGHUP 后进程存活、API 仍在监听（重载成功）；`PUT /configs` 确认是 no-op；
  `PUT /proxies/<selector>` 成功返回 204、给不存在的成员返回 400。
- **Surge / v2ray / Xray 只有夹具单测**：本机没装这三家，端点与键名依据官方文档与源码，
  **没有真机验证过**。第一次真机跑之前，把它们当「照文档写的」看待。
- **一条边界**：sing-box 的 Apple 客户端（SFM）以 Network Extension 运行，`clash_api`
  监听在扩展进程里，外部是否可达没有实测过——脚本会去连，连不上就如实报「连不上」。

## 参考来源

- sing-box：<https://sing-box.sagernet.org/configuration/experimental/clash-api/>、
  <https://sing-box.sagernet.org/configuration/dns/>、仓库 `SagerNet/sing-box`
  （`experimental/clashapi/`、`cmd/sing-box/cmd_run.go`）
- Surge：<https://manual.nssurge.com/tools/http-api.html>、
  <https://manual.nssurge.com/dns/dns-server.html>
- v2ray / Xray：<https://xtls.github.io/en/config/dns.html>、
  <https://xtls.github.io/en/config/routing.html>、仓库 `XTLS/Xray-core` `main/run.go`
- mihomo：<https://github.com/MetaCubeX/mihomo>（`hub/route/`）
- Clash Verge Rev：<https://github.com/clash-verge-rev/clash-verge-rev>
