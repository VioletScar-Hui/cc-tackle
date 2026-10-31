# 手工核对清单与检测网站

> 这是 `SKILL.md` 的可选补充，不改变任何判据。脚本能判的项不必手工再做；只有脚本判不了、或用户想自己复核时才读这一页。
>
> 规则只有一条：**在新开的终端里跑**，老窗口可能还带着启动时的旧代理变量。Clash API 不要手工拼 `Authorization` 头，也不要让 `CLASH_SECRET` 进命令行参数——用脚本内建的只读审计入口。

## 什么时候用这一页

- 脚本报「未测到」，用户想自己确认（浏览器权限、系统面板、外部检测站）。
- 用户想看每条原始命令长什么样，或想自己重跑一遍。
- 排查脚本覆盖不到的情况：别的代理软件、别的浏览器、系统级设置。

全文按五组组织：出口与泄漏面、系统与终端残留、Clash 线路与绝不直连、时区与定位、客户端与账号；最后附文章给的检测网站和三条快速命令。
想查看脚本能判断的状态，直接运行只读审计：

```bash
python3 scripts/account_guard.py --audit
```

如果需要外部网站和人工路径，才运行 `python3 scripts/account_guard.py --commands`；其中 Clash API 检查不要手工拼接 Authorization 请求头或调用 curl，始终使用上面的脚本内建安全入口。规则是：**在新开的终端里跑**，老窗口可能还带着启动时的旧代理变量。

## 一、出口与泄漏面

**出口 IP 与归属**（文章 2.5①）

```bash
curl -s --noproxy '*' https://api.ipify.org
curl -s ipinfo.io
```

期望国家固定、城市别每次变、org 不是一眼能认出是机房的名字。加 `--noproxy` 是为了走 TUN 而不是 7897 那个混合端口，两条路的结论可能不同。

这一项还会和上一次比。每次体检把出口记进 `~/.local/state/claude-guard/export-ip.json`，下次读出来对比，变了就把两次数值都列出来——变了不等于错（换订阅、服务商换 IP 都会变），所以报待处理而不是 ✗；取不到出口时不覆盖旧记录。文章 §2.5① 的「城市别每次变」与 §9 的「出口国家和上次一致」都只能靠这一步才看得见，单看一次永远是「现在是谁」。

**出口 ASN 类型**（文章 2.3）

```bash
curl -s "https://ipinfo.io/$(curl -s --noproxy '*' https://api.ipify.org)/org"
```

住宅 ISP 与机房 IP 的区别就在这一栏。

**WebRTC 泄漏**（文章 2.5②）：浏览器打开 `https://browserleaks.com/webrtc`。不能出现真实公网 IP；只有一条 mDNS 混淆的 `.local` 主机名属正常。

**DNS 泄漏**（文章 2.5③）——要看两件事，不是一件

```bash
dig example.com +short
```

第一件是解析结果落在 `198.18.0.0/16`（本机实测 fake-ip-range 是 `198.18.0.1/16`），这证明 TUN 劫持生效。

第二件是**谁在解析**，`check_clash_dns()` 查的就是它。只看第一件会漏：2026-10-09 换成住宅代理订阅后，profile 自带的主解析器是阿里 `223.5.5.5` 且 `respect-rules` 整个丢了，`dig` 依然返回 fake-IP（劫持是好的），但国外域名的解析请求全交给了国内解析器，而且因为缺 `respect-rules`，Clash 自己的 DNS 查询还是从真实 IP 直发的。三个站点实测都看到了中国解析器。

- 五条判据：`leaking`、`leaking_fallback`、`respect_rules`、`enabled`、`hijack`。后两条读的是 `dns.enable` 与 `tun.dns-hijack`（后者在 `tun` 底下、不在 `dns` 块里），只在 TUN 开着时才要求；任一成立即待处理，逐条解释见 `references/article-mapping.md`。

注意 `nameserver-policy` 里把 `geosite:cn,private` 指向国内 DNS 是**对的**，国内域名本来就该走国内解析，别把它算成泄漏。

用浏览器复核时记住：`browserleaks.com/dns` 与 `dnsleaktest.com` 会直接列出解析器归属；**`ipleak.net` 的读数要等它跑完**——它最多跑 300 轮，每轮解析一个 `{session}-{n}.ipleak.net`，服务端日志还有滞后，前几十轮显示的就是「0 servers detected」，那是没跑完，不是没检测到。

**IPv6 直连漏出**（文章 2.5 可选加固）

```bash
ifconfig | grep inet6 | grep -vE 'fe80|::1'
networksetup -getinfo Wi-Fi | grep -i ipv6
```

期望无输出。**必须排掉 `::1`**，否则 loopback 会被误报成全局地址，这一点实测踩过。

## 二、系统与终端残留

**系统代理开关**（文章 2.5④）

```bash
scutil --proxy | grep -E "HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable"
```

四个值都应是 0。

**网络服务里的残留值**

```bash
networksetup -listallnetworkservices
networksetup -getwebproxy Wi-Fi; networksetup -getsecurewebproxy Wi-Fi; networksetup -getsocksfirewallproxy Wi-Fi
```

`Enabled` 应为 No，`Server` 应为 `0.0.0.0`、`Port` 为 0。列表第一行是说明文字、被禁用的服务名字前面带星号，按名字操作时要去掉。

**终端环境变量**（文章 2.5⑤）

```bash
env | grep -iE "proxy|anthropic|claude"
```

期望无输出。**原文这条写得太宽**：只要当前目录名里带 claude（比如就站在 `cc-tackle` 目录下），`PWD` 就会被命中，实测踩过。真要查代理就拆成 `env | grep -i proxy`。

**shell 配置里的代理行**（文章 2.5⑤）

```bash
grep -inE "proxy|ANTHROPIC" ~/.zshrc ~/.bashrc ~/.profile ~/.zshenv ~/.zprofile 2>/dev/null
```

**npm / git 的全局代理**（文章 2.5⑤）

```bash
npm config get proxy; npm config get https-proxy
git config --global --get http.proxy; git config --global --get https.proxy
cat ~/.npmrc
```

npm 两项应输出 `null`，git 两条应无输出。`~/.npmrc` 要直接看文件：`npm config get` 读的是生效值，带作用域的写法它反映不出来，脚本两种都查。顺带看一眼那里有没有明文 token——那是另一回事，脚本不碰。

**Homebrew 的代理**（文章里没有，是清单补的）

```bash
brew config | grep -i proxy
```

应无输出。实测 Homebrew 7 只把（小写的）`http_proxy` / `https_proxy` / `all_proxy` 打进 `config` —— 把大小写六个都设上再跑一次 diff，多出来的只有小写那三行，大写那三个它一个字都不提。所以这条能测出来的是 `env | grep -i proxy` 的子集。

**settings.json 内容**（文章 2.5⑤）

```bash
cat ~/.claude/settings.json 2>/dev/null
```

重点看 `env` 里有没有 `ANTHROPIC_BASE_URL`。用过镜像站或各种中转的这里常有残留，服务端一看请求就知道没走官方。清单里那条写得更细，是 `grep -iE "proxy|base_url|anthropic_"` 三段——**proxy 那一段同样要查**：在 `env` 里放一个 `HTTPS_PROXY`，请求就绕到那个代理上去了，而早先的实现只认端点与凭据键，既不报也不清；2026-10-10 补上，现在三类一起报、一起清。

## 三、Clash 线路与绝不直连

不要手工拼 Authorization 头，也不要把 `CLASH_SECRET` 交给外部命令参数：这样 secret 会进入进程参数。使用脚本内建的只读审计入口；它通过 Python 内存中的 Unix socket 请求头读取 Clash 状态，secret 不进入 argv：

先通过已有安全机制预先注入 `CLASH_SECRET` 环境变量（不要在命令行或 shell 历史中写明文，也不要写入脚本或仓库），再运行：

```bash
python3 scripts/account_guard.py --audit
```

审计输出会报告当前模式、GLOBAL/Claude 组、实时连接链、Claude 规则和 DNS 判据；需要机器可读结果时使用 `python3 scripts/account_guard.py --audit --json`。如果 socket 或 secret 不可用，按“未测到/待处理”报告，不要退回 curl 手工请求。

**订阅会不会把规则改回去**（这台机器上最容易忽略的一条）

```bash
grep -nE '^mode:' ~/Library/Application\ Support/io.github.clash-verge-rev.clash-verge-rev/profiles/*.yaml
tail -5 ~/Library/Logs/clash-mode-guard.log
```

这个值不在任何落盘文件里（`verge.yaml` 没有 mode 键、`profiles.yaml` 只有组选择、`cache.db` 是空的），Clash Verge 会按内存里的值把它推回去，所以只能靠守护脚本每 30 秒盯一次，日志里能看到 `mode was 'x' -> restored to rule`。

守护脚本的判据改过一次。旧版只在 `clash-verge.yaml` 被改写时才动手，把「文件没变」等同于「你自己在界面上切的」。但 Verge 完全可以在不碰文件的情况下改运行时 mode——2026-10-09 实测发生过，mode 被推回 global 而文件一直写着 rule，守护脚本放过了它，分流就此停摆。现在改成「只要运行时不是目标值就拉回来」，想让手动切换生效就 `touch ~/.local/state/clash-mode-guard.hold`。

## 四、时区与定位

**系统时区**（文章 2.2）

```bash
readlink /etc/localtime
node -e "console.log(Intl.DateTimeFormat().resolvedOptions().timeZone)"
```

两条都应指向 `Asia/Taipei`。第二条才是应用和浏览器实际读到的值。

**定位驱动时区有没有关**（文章 2.2）

```bash
defaults read /Library/Preferences/com.apple.timezone.auto.plist Active
log show --last 2h --style compact --predicate 'process == "timed" AND eventMessage CONTAINS "TZ,computed"' | tail -3
```

第一条是「按位置自动设定时区」，应为 0。第二条看 `timed` 最近算出过什么时区——它只是历史，判断当前状态要看上面那两个活读数。

第二道闸在「定位服务 → 系统服务 → 设定时区」，读它要 root，看 timed 日志里有没有 `setSourceUnavailable`。

## 五、客户端与账号

**Claude Code 版本与占用**（文章 §5）

```bash
which claude; DISABLE_AUTOUPDATER=1 claude --version
ls -la ~/.local/share/claude/versions/
du -sh ~/.local/share/claude/versions/
```

`versions` 目录每份 200 MB 上下，安装器会自行清理旧版本。加 `DISABLE_AUTOUPDATER=1` 是因为不加的话，这次查看会顺手把 CLI 升到最新，而同一个动作后面正要数 `versions` 里留了几份 —— 等于一边量一边把被测对象改了。

脚本在这上面查四件事，缺一件都不报绿：怎么装上去的（native / Homebrew / npm / bun 四条通道各自验特征，一条都对不上就写「安装方式未知」，不猜）、链接形状对不对（官方安装是 `versions/<版本>` 真文件 + `bin/claude` 软链；软链指到 versions 外面、或 versions 目录本身是软链，都算形状不对）、实跑 `--version` 报出来的版本号正不正常、软链指向的那个版本在不在 `versions` 目录里。签名有效只证明「这是官方发的那份」，不等于「它就是现在该在用的那份」。

**钥匙串条目**（文章 2.6）

```bash
security dump-keychain 2>/dev/null | grep -E '"(svce|acct)"' | sort -u
```

要分开看：`svce='Claude Safe Storage'` 配 `acct='Claude Key'` 是桌面版的加密存储，跟 CLI 的登录凭据不是一回事——CLI 登没登录别从这里推断，看下面那条。
**登录方式**（用户口径 2026-10-15）

```bash
claude auth status        # 只读，返回 loggedIn / authMethod / apiProvider
```

读两处：`claude auth status` 报的登录态，以及 `CLAUDE_CODE_OAUTH_TOKEN` 有没有被写在环境变量、`~/.claude/settings.json` 的 `env` 或 shell 配置里（**只记位置，绝不读值**）。四态：有长期 token 报绿；是网页授权登录、或压根没登录，都报待处理并指向 `claude setup-token`；`claude auth status` 读不出来报「没测到」，不猜。

为什么单列一项：在 Claude Code 里做网页授权登录，等于把这条登录事件钉在当前出口上；而网页登录还会随掉线、丢包反复要求重登，每重登一次就是一条新的登录记录。只认证一次的办法见人工清单第八组。

**遥测三键**（文章 §5）

```bash
python3 -c "import json;print(json.load(open('$HOME/.claude/settings.json')).get('env',{}))"
```

想关就在这里加 `DISABLE_TELEMETRY` 与 `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` 为 `1`。有副作用，Remote Control 可能失效。

## 文章里给的检测网站

| 用途 | 网站 | 说明 |
| :--- | :--- | :--- |
| 出口 IP | ipinfo.io、ping0.cc、whoer.net | 看 country / city / org，国家要固定、城市别每次变 |
| IP 纯净度 | ippure.com | 文章 2.3 附的来源，看是不是住宅段 |
| 社区检测页 | ip.net.coffee/claude | 文章原话「只作参考」，不当作判据 |
| WebRTC | browserleaks.com/webrtc | 不能出现真实公网 IP |
| DNS | browserleaks.com/dns | 不应出现中国的 DNS 服务器 |
| Claude 服务状态 | status.anthropic.com | 怀疑是服务端问题时先看这里 |

## 只想快速看一眼（三条就够）

```bash
scutil --proxy | grep -E "HTTPEnable|HTTPSEnable|SOCKSEnable"
curl -s --noproxy '*' https://api.ipify.org
python3 scripts/account_guard.py --audit
```

前两条分别用于查看系统代理开关和实测出口；第三条由脚本安全读取 Clash 状态并报告模式、线路和 DNS。目标国家/IP 只有在命令显式提供 `--expected-country`、`--expected-exit-ip` 时才参与匹配。
