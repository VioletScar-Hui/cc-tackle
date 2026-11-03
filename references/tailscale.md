# 本机接 Tailscale 时，DNS 和 Clash 怎么共存

Tailscale 默认会**接管系统 DNS**（MagicDNS，解析器 `100.100.100.100`）。这跟 mihomo 的
`fake-ip` + `dns-hijack` 直接冲突：查询不再进入 Clash，Claude 域名被解析成真实公网 IP，
体检里「DNS 泄漏」变红。2026-11-03 在本机真机踩过，这一页是当时的排查与两种解法。

## 先确认是不是这个问题

```bash
# 第一个解析器是不是 Tailscale 的？（是 100.100.100.100 / fd7a:115c:a1e0::53 就对上了）
scutil --dns | grep 'nameserver\[0\]' | head -3

# 公共域名解析出来是真实 IP 而不是 198.18.x，说明劫持失效
dig example.com +short

# Tailscale 自己的开关：CorpDNS 为 true 就是在接管
/Applications/Tailscale.app/Contents/MacOS/Tailscale debug prefs | grep CorpDNS
```

`python3 scripts/account_guard.py --audit` 的「DNS 泄漏」那一行出现 Tailscale 提示时，
就是这份文档。

## 第一步：把系统 DNS 还给 mihomo（必做）

```bash
/Applications/Tailscale.app/Contents/MacOS/Tailscale set --accept-dns=false
```

设备之间照样互联，只是 `xxx.tailNNNN.ts.net` 这类 MagicDNS 名字不再由系统 DNS 解析。
**副作用**就是下面要补的：Rex、`tailscale ssh` 之类按名字连的工具会拿到 Clash 的
fake-ip（`198.18.x`），连过去 EOF / 超时。

## 第二步：让 Clash 在本地回答 `*.ts.net`（推荐，不用管理员密码）

`scripts/tailscale_hosts.py` 读 `tailscale status --json` 的对端 IPv4，写进**当前订阅
profile 的 merge 文件**的 `hosts:` 块，再热载一次。公共 DNS 一个字节不查，系统级 DNS
设置一点不动。

```bash
python3 scripts/tailscale_hosts.py --status            # Tailscale、解析器、已有 hosts、dig 结果
python3 scripts/tailscale_hosts.py --sync --dry-run     # 看会新增/更新哪几条
python3 scripts/tailscale_hosts.py --sync               # 写 merge（先备份）+ 热载 + 复验
```

- 只写**对端**，不写本机自己的名字（`--include-self` 可改）；`--names a,b` 只同步指定名字。
- 写之前备份成 `*.bak-ts-hosts-<时间戳>`；写之后 `dig <名字>` 应是 `100.x`，
  `dig example.com` 应还是 `198.18.x`，两条都过才算成功。
- 热载只影响当前内核；merge 文件保证下次 Verge 重新生成配置时还在。
- **限制**：依赖 Clash Verge 在运行；换订阅/切 profile 之后要重跑一次 `--sync`
  （新 profile 的 merge 是另一份文件）；只映射 IPv4 对端。

merge 文件长这样（`hosts:` 与 `dns:` 同级）：

```yaml
hosts:
  node-a.tail-example.ts.net: 100.64.0.11
  node-b.tail-example.ts.net: 100.64.0.12
```

## 另一条路：`/etc/resolver/ts.net`（要管理员密码，一劳永逸）

让 `*.ts.net` 单独走 MagicDNS，跟 Clash 是否在运行无关，也不影响其它 DNS 和审计：

```bash
sudo mkdir -p /etc/resolver
printf 'nameserver 100.100.100.100\n' | sudo tee /etc/resolver/ts.net
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```

装了这个就不需要 hosts 映射；两条都留着也不冲突（hosts 会先命中）。代价是要 root，
而且这是系统级改动，卸载时删掉 `/etc/resolver/ts.net` 即可。

## 和体检的关系

- 「DNS 泄漏」：Tailscale 接管时会红，并直接在那一行给出 `--accept-dns=false` 和
  `tailscale_hosts.py --sync` 的提示。
- 「IPv6 全局地址」：Tailscale 给设备的 `fd7a:…` 是 ULA（`fc00::/7`），**不是公网 IPv6**，
  1.2.1 起不再计入（见 `CHANGELOG.md`）。
- 常驻进程一节只列和保护 Claude 环境相关的后台项，Tailscale 自身不列。

## 常见误判

| 看到的 | 别当成 | 实际是 |
| --- | --- | --- |
| `100.100.100.100` 是解析器 | 公共 DNS / 泄漏到运营商 | Tailscale 自带的 MagicDNS 入口 |
| `fd7a:115c:a1e0::…` | 公网 IPv6 泄漏 | Tailscale 的 ULA 内网地址 |
| `dig xxx.ts.net` 得到 `198.18.x` | 域名被墙 / 解析坏了 | Clash 的 fake-ip：需要上面的 hosts 映射 |
| Clash 一停 `*.ts.net` 就连不上 | Tailscale 又坏了 | hosts 方案依赖 Clash；或改用 `/etc/resolver` 方案 |

## 2026-11-03 的真机记录

- 关掉 `accept-dns=false` 之后，Rex 把 `node-a.tail-example.ts.net` 解析到 `198.18.x`，
  连接 EOF；客户端日志里一排 `no SNI ServerName`（App 记录被写成了不带 scheme 的裸主机名）。
- 修法：在当前订阅的 merge 里加两条 `hosts`（就是 `--sync` 写的那种），重启 Clash Verge；
  App 里的 locator 恢复成 `https://node-a.tail-example.ts.net`。
- 结果：`dig` 内网名字回 `100.x`、公共域名回 `198.18.x`、`scutil --dns` 首个解析器仍是
  `114.114.114.114`、体检 IPv6 与 DNS 两行都 ✓。
