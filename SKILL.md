---
name: claude-account-guard
description: 检测并自动清理 Claude Code 的本机环境（macOS）。一条命令跑完 25 项：出口 IP 与 ASN 类型是不是住宅、出口是否和上次一致、系统代理残留、DNS 与 WebRTC 有没有泄漏真实 IP、IPv6 有没有绕过隧道、时区分层与两道闸、浏览器 Intl 区域设置、settings.json 里的中转端点与凭据、遥测三键、第三方客户端痕迹、CLI 签名完整性、多账号痕迹、失效权限条目、过期工作树注册；检测完可自动清掉安全可逆的残留，改前先备份。Use when the user asks to check, audit, clean or harden a Claude Code / Claude environment on macOS：环境体检、登录前自检、被封后换环境前的排查、代理残留、DNS 泄漏、WebRTC 泄漏、出口 IP 与节点检查、时区不一致、账号风控排查。Claude Code environment audit, proxy / DNS / WebRTC leak check, exit IP and ASN, macOS only；不涉及账号申诉、付款或网页端设置。
---

# Claude Code 环境检测与自动清理

一个脚本做两件事：**检测环境**，然后**自动清理环境里可安全清理的残留**。

安全约定沿用 `claude-cleanup`：只读审计永远安全；写操作需要真实 TTY 和一次最终确认；备份是第一个写操作，失败即停；需要 root 时只在终端原生 sudo 隐藏提示里输密码，脚本从不读取或保存密码。

## 自动清理什么

下面四类都幂等、可逆、有备份，所以**不再逐项询问**，跑一次直接清完：

- 未启用但存了值的系统代理残留（`127.0.0.1:7897` 这类，只在 `Enabled: No` 时才动）；
- shell 配置（`.zshrc` / `.zprofile` / `.profile` 等）里的代理行；
- npm 与 git 的全局代理配置；
- Claude Code `settings.json` 的 `env` 里指向别处的端点、凭据与代理变量（`ANTHROPIC_BASE_URL`、`HTTPS_PROXY` 等）。

清 shell 配置时只删命中那几行，注释、`EDITOR`、`alias` 之类全部原样保留；清 `settings.json` 时只动 `env` 里属于端点、凭据、代理的键，其余键以及非 `env` 键全部保留。每一项清完都复验。

当前 shell 进程里的代理或端点变量只报告不代改——脚本改不了已经启动的进程环境，需要用户在新终端里确认。

## 什么仍然由你决定

因为**有副作用**，这三类保留询问，默认都选否：

- 遥测开关（`DISABLE_TELEMETRY` 等）——文章 §5 写明会连带关掉功能旗标，Remote Control 可能失效；
- 关闭网络服务的 IPv6——需要管理员密码；
- 关闭定位服务里的「设定时区」——改动系统隐私库，风险最高。

## 运行顺序

想一次看全貌，先跑这一条（只读，约 1.5 分钟）：

```bash
python3 scripts/selfcheck.py
```

它把「技能文件齐全（含 SKILL.md 的 `name` 与目录名是否逐字符相等）→ 语法编译 → 全部单元测试 → 三个守护脚本 → Clash 内核状态 → 系统代理四开关 → 完整体检」串成七项，跑完出两张表：先一张七项结论表，再把「完整环境体检」那 25 项逐条展开，末尾给退出码（`0` 全过、`1` 有失败）。`--fast` 跳过单元测试，`--no-audit` 跳过体检。

1. 如果当前执行者就是 Claude Code，只跑只读审计，并提醒用户换普通终端再执行加固（加固会改本机状态，不适合由正在使用它的进程发起）。

   ```bash
   python3 scripts/account_guard.py --audit
   ```

2. 由普通终端执行时，先跑审计并向用户说明：备份是第一个写操作；残留类会自动清、配置类会逐项问；密码只走 sudo 原生提示；每项改动后立即复验。

3. 用户明确要求继续后：

   ```bash
   python3 scripts/account_guard.py
   ```

退出码：`0` 正常完成；`1` 用户在 CONFIRM 处取消；`2` 拒绝执行或中途停止；`3` 加固已完成但检测到受保护文件被本脚本之外的进程改动（stderr 会给出文件和备份路径）。

体检还会报出 CLI 的 `versions` 目录留存了几份、占多少空间（每份 200 MB 上下，非当前版本可手动删），并对当前在跑的那份二进制**验签**：官方 CLI 带 Anthropic 的 Developer ID 签名，`codesign --verify --strict` 通过即等于「没被替换过」；没签名报待处理，验签失败报 ✗。

## 跑完看什么：结果总表

不管是 `--audit` 还是完整执行，最后都会打印一张 25 行的方框表格，一栏是检查项、一栏是状态、一栏是实测结果。四种状态：

| 状态 | 含义 |
| :--- | :--- |
| ✓ | 已经没问题 |
| ! | 能自动处理的，或者需要你点一下 |
| ✗ | 有问题 |
| · | 这次没测到 |

表尾给出计数汇总。完整执行时这张表是**改动之后重新体检一次**得到的，不是拿加固前的报告充数——否则刚清掉的残留还会显示「待处理」，用户会以为没生效。

完整执行的收尾还多打一张**只有记号的对账表**，两栏分别是「修复前」和「修复后」。这两栏不是回忆出来的：前一份是同一次运行里动手之前的体检，后一份是动手之后的复检，两遍都是真读数。只有真从「没通过」变成「通过」的项才连带打印改动明细，一项都没变时不会多出那一段；`·`（这次没测到）不计进「没通过」。要看每一项现在的实测值，单独跑一次 `--audit`。

表格按**显示宽度**对齐，不是按字符数：中文一个字占两格、ASCII 占一格，用 `len()` 算会让每一行都歪。结果列超出 58 格会按显示宽度截断并补省略号。

有两条口径是这个表刻意守住的：

**缺字段一律当「未测到」，不默认成「干净」。** 某一项因为报错没跑出来时，它必须显示 `·`，绝不能因为字段缺失就显示 ✓。这条有测试守着（空报告应当 25 项全部未测到、0 项已解决）。

**别把别的工具的残留说成会被清理。** 扫描会连带命中 `~/.dsh/settings.yaml` 这类别的工具的配置，按范围约定脚本不碰它们，所以表里要写「只报告不代改」，不能写「自动清理会清掉」。

## 「绝不直连」怎么判

这一项不靠人眼看，脚本会给出明确结论（A12）。判据落在**代理组**上，不落在规则上：

- 模式要么是 `global`、要么是 `rule`，两种都算成立，但**成立的理由不一样**，判据必须跟着模式走：
  - `global` 模式下 mihomo 一条分流规则都不执行，全部流量交给 GLOBAL 选择器。这时看的是 GLOBAL 有没有指向 Claude 专用组。
  - `rule` 模式下规则照常执行（国内直连、其余走代理）。这时 GLOBAL 指向谁跟 Claude 无关，该看的是 Claude 那几个域名有没有指向专用组的规则，以及兜底那一条会不会落到 `DIRECT`。

  两种模式的共同要求：Claude 组必须是 `select`、只有一个成员、没有可切换的对象。

  这里我犯过一次错：第一版写死「必须 global」，于是把 `mode=rule` 本身判成故障。而 rule 恰恰是「国内直连、国外走代理」所必需的模式——把用户的选择当成故障，跟早前把「台北时区 + 美国出口」判成矛盾是同一个毛病。文章 2.4 那句「用 Claude 期间不建议用规则模式」有它的道理（分流规则写错就会漏），但只要 Claude 域名被显式规则钉进专用组、兜底又不是 DIRECT，规则模式同样能保证不漏，而且国内站点不用绕出去。
- `GLOBAL` 必须指向 Claude 专用组，不能指向 `Proxy`、`自动切换` 或 `DIRECT`。
- 那个组必须是 `select` 类型、且**只有一个成员**。只有 select 才不做健康检查切换；fallback 即使只剩一个成员也存在切走的可能。

三条都成立时报告打 `✓ 绝不直连成立`，任一条不成立就把具体原因列出来。

真机实测过节点死掉的行为：把专用组指向一个不可达地址后，`api.anthropic.com`、`claude.ai`、`www.baidu.com` 全部连接失败（curl 退出码 35），出口 IP 取不到，没有任何降级到备用节点或直连的路径。

**这条覆盖不到的情况要说清**：内核（`verge-mihomo`）本身退出或 TUN 接口消失时，接管流量的那几条路由会随之消失，default 路由回到物理网卡，那一刻是全量直出。规则层和组配置都管不到这件事。缓解在于内核挂在 root 特权助手 `clash-verge-service` 底下，崩溃后会秒级重启。

## 时区这一项只检测，不改写

`check_timezone_layers` 报三件事：两个活读数（`/etc/localtime` 指向、新起进程实际拿到的时区）、`timed` 最近一次算出的时区及时间、控制时区的两道闸各自的状态。判定「现在是不是台北」只用两个活读数，`timed` 的日志是历史，单独列出来带时间戳，不参与判定。

这一点踩过坑：6 小时窗口里可能同时躺着几小时前的一次 `Asia/Shanghai` 和之后的一次 `setSourceUnavailable`，把历史当现状会天天误报。所以日志是按时间戳逐条解析后取最后一条事件。

脚本不自动改写定位服务的配置。读 `/var/db/locationd/clients.plist` 需要 root，非 root 时如实报「读不到」并给出 UI 路径，绝不把读不到当成「已关」。

## 项目目录要显式指定

A9（扫项目级 `CLAUDE.md` 里的地理位置词）需要知道你的项目在哪。skill 不猜目录结构，用环境变量指定，冒号分隔：

```bash
CLAUDE_GUARD_PROJECT_ROOTS="$HOME/CC_Project" python3 scripts/account_guard.py --audit
```

不设这个变量时这一项会跳过并说明怎么开。

## 必须向用户讲清的五件事

**一、`networksetup -set{kind}` 会把代理顺带置为启用。** 实测确认的陷阱：写入服务器值这个动作本身会打开代理。清残留之后必须再执行一次 `set{kind}state off` 并复验 `Enabled: No`，否则会把「未启用的残留」变成「已启用的代理」，正好造成文章最担心的后果。脚本已内置，手工排查时不要漏。**只处理 `Enabled: No` 的残留，正在启用的代理一律不碰。**

**二、关闭时区自动设定有「两道闸」。** 文章 2.2 说「很多人漏这一步」指的是定位服务里的那一项。本机实测证实过：只把 `com.apple.timezone.auto.plist` 置 0 之后，时区仍被 `locationd` 覆盖过一次。两道都要关。

**三、遥测开关有副作用。** 见上，脚本不主动改，只在用户选择后才写。

**四、「设定时区」不是官方支持的改动路径。** 脚本会先读出 `/var/db/locationd/clients.plist` 里的候选条目，逐个尝试后**重新读取整份 plist** 复验 `Authorized` 是否真的翻成 False，验不到就判定未生效并让用户走 UI。不会做「写不进去却报成功」这种事。

**五、查钥匙串要看清 `svce` 与 `acct`，它们不是一回事。** `svce="Claude Safe Storage"` / `acct="Claude Key"` 是 Claude **Desktop** 的加密存储；Claude **Code CLI** 的登录凭据是 `svce="Claude Code-credentials"`。早期把两者混为一谈，看到 Safe Storage 就以为 CLI 有凭据，结论是错的。另外 `security dump-keychain` 会把每个条目列两遍（一遍十六进制属性号、一遍具名属性），只认 `"svce"` 会漏掉一半条目——实测 `Claude Safe Storage` 正好只出现在十六进制那遍里。解析必须两种写法都吃，并且 `svce` 与 `acct` 只能在同一条目块内配对，不能全局抓。

## 范围

只针对 Claude Code。以下明确不在范围内：账号申诉、付款与退款、claude.ai 网页端设置、Active sessions、订阅节奏与路线选择这类行为决策，以及 `~/.codex`、`~/.dsh` 等其它工具的配置——那些只报告，不代改。

本 skill 也不用于规避封禁、支付检查或任何平台风控。清残留是为了在支持地区正常使用官方客户端时少被误伤，不是给开新号铺路。

## 回滚

所有写操作前都会在 `~/ClaudeGuardBackups/guard-<时间戳>/` 留下带 `manifest.json` 的备份：

```bash
ls ~/ClaudeGuardBackups
cp ~/ClaudeGuardBackups/guard-<时间戳>/files/Users__*__settings.json ~/.claude/settings.json
cp ~/ClaudeGuardBackups/guard-<时间戳>/files/Users__*__.zshrc ~/.zshrc
```

需要 root 的文件（`/var/db/locationd/clients.plist`）用 `sudo cp` 从同一目录还原。生成的 `~/.local/bin/claude-safe` 直接删除即可。只读审计的报告存在 `~/ClaudeGuardBackups/audit-<时间戳>.json`。

IPv6 是唯一不走文件备份的改动，它在系统网络配置里，恢复要显式执行；脚本在关闭成功后会把这组命令直接打印出来，照抄即可。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

覆盖 ASN 归类（含 `AT&T` 这类需要归一化才能命中的真实坑）、自动清理只删该删的行、遥测三键策略、备份优先于写入、清理后不得变成启用、非 TTY 拒绝、失败时报告备份路径、以及有意清理的 shell 配置不被误报。

结果总表也有专门的一组测试：每行的显示宽度必须一致（守住 CJK 对齐）、截断按显示宽度算、缺字段不得默认成「干净」、读不到的闸门必须标成待处理而不是已关、别的工具的残留不得说成会被清理、WebRTC 的 0 候选必须标成结论不可用。

时区与钥匙串这两项另有针对性回归：历史时区事件不得翻转当前判定、同一窗口内多个定位源事件要取时间上最后那条、`dump-keychain` 的十六进制写法必须能解析、`svce` 与 `acct` 不得跨条目块拼接。「绝不直连」判据按模式分别测：全局模式下 GLOBAL 指错要判不成立；规则模式下 Claude 域名没规则、规则指向别处、兜底是 DIRECT，三种都要判不成立；两种模式下组类型是 fallback、成员不止一个，都要判不成立。另有一条专门盯着「不得把 mode=rule 本身当成故障」——那是修过的 bug，容易被改回去。

## WebRTC：只有「授权之后」才漏，而且它绕过 TUN

先纠正一个常见误读：检测站报「WebRTC 有泄漏风险」多半是通用警告，它们压根没测。真正测的那个（browserleaks.com/webrtc）在未授权时给的是 `No Leak`，Local IP 和 Public IP 都是空的。

但确实有一条真实路径。Chrome 的 mDNS 混淆（`enable-webrtc-hide-local-ips-with-mdns`，原文「Conceal local IP addresses with mDNS hostnames」）**只在页面没有摄像头/麦克风权限时生效**——设计如此，P2P 媒体流需要真实局域网地址。实测同一台机器：

    未授权    1 个候选，mDNS 的 .local，看不到任何地址
    已授权    5 个候选，其中一条是 typ srflx，带真实公网 IP + 内网 + TUN 地址

已授权那次拿到的原始候选是这样：

    candidate:2415635606 1 udp 1686052607 203.0.113.9 54364 typ srflx raddr 192.168.1.5 rport 54364 network-id 1

`203.0.113.9` 是真实公网出口（示例值），`raddr 192.168.1.5` 是 en0 的内网地址，`network-id 1` 指向 Wi-Fi。也就是说 **STUN 是绑在物理网卡上直发出去的，根本没进 TUN**，Clash 那几条拦 UDP 的规则看不到它——Python 侧直测 19302/3478 等端口全部超时（那些走了 TUN），浏览器这条路径照样通。判断有没有绕过，看 `raddr` 是不是内网地址比数候选个数可靠。另外 `198.18.0.0/15` 属 RFC 2544 保留段，出现它等于自报在用 Clash 类代理。

**有效开关有，但只在资料里，不在命令行。** 三样东西容易混成一件：

| 设置方式 | 实测结果 |
| :--- | :--- |
| `webrtc.ip_handling_policy`（Chrome 资料的 pref，WebRTC Network Limiter 扩展就是设它） | 有效。`disable_non_proxied_udp` 与 `default_public_interface_only` 都让候选数归 0；`default_public_and_private_interfaces` 只剩 TUN 地址 |
| `--force-webrtc-ip-handling-policy`（命令行开关） | 无效，写与不写候选数和地址一模一样 |
| `defaults write com.google.Chrome WebRtcIPHandling`（用户级企业策略） | 无效，同样毫无变化。机器级 `/Library/Managed Preferences/` 需要管理员权限，未验证 |

验证有效性的唯一办法是拿一个临时资料写进 pref，再跑一次真实 ICE 收集做对照——光看文档会把这三者的效果当成一回事，这一条我错过一次。

所以修法有几条，按优先级排：

1. **别让网站拿到权限**（Chrome 设置 → 隐私和安全 → 网站设置 → 摄像头/麦克风 → 不允许）。最彻底：授权那条路径不可达，泄漏就无从发生。
2. **在资料里设 `webrtc.ip_handling_policy`**。文章 2.5② 推荐的 Chrome 官方扩展 WebRTC Network Limiter，选「Use my proxy server (if present)」，装的其实就是这个 pref——实测本机那个资料里 `webrtc.ip_handling_policy = disable_non_proxied_udp` 正是它写进去的（扩展来自 Chrome 应用店、`disable_reasons` 为空）。所以装扩展和手工设 pref 是一回事，扩展的好处只是不用手工改文件。
3. **Firefox**：文章给的办法是在 `about:config` 里把 `media.peerconnection.enabled` 改成 `false`。这条没有在本机实测过（本机用 Chrome），照文章记下来；原理是把整个 WebRTC 关掉，代价同样是网页视频通话用不了。

代价要说清楚：任何有效设置都会让网页视频通话建不起来（候选数为 0，P2P 建立不了），**可用性和不泄漏在这个网络结构下不可兼得**，所以要按资料分别决定，别一刀切。

复核这一项要用户配合：脚本读不了 Chrome 的资料文件（TCC 挡着 `open()`），所以 `--check-media` 起一个本地页面，让用户在他真实的浏览器里打开，页面把权限状态 POST 回来并缓存到 `~/.local/state/claude-guard/media-permission.json`。**必须用那个资料打开**，用别的资料读到的是别的资料的权限。顺带一个已经踩过的坑：用 sudo 跑过之后这个状态目录可能是 root 的，写入会静默失败（`except OSError: pass` 吞掉），所以 `hand_back_ownership()` 会在 sudo 之下把属主交还给 `SUDO_UID`。


这里面有个坑值得记下来：**探测用哪个浏览器会决定结论真假**。同样给了媒体权限，headless shell 只给 1 个候选、看不到任何 IP，完整 Chromium 给 4 个、露出真实地址。也就是说用 headless shell 测，「授权后会不会露」这个问题永远答「不会」——一个看起来干净的假阴性。所以 `find_chromium()` 现在把完整版排在前面，结果里也会标明用的是哪个。

（曾试过把 TUN 地址从 `198.18.0.1` 换成普通的 `172.19.0.1`，让泄漏出来的地址不那么显眼。写了 `tun.inet4-address` 但 mihomo 在配置重载时不重建 TUN 接口，要生效得重启内核；而重启后接口地址与 fake-IP 段不在同一网段，可能影响 fake-IP 路由。这个改动只在「已经授权、真实内网 IP 也一起漏」的场景下才有意义，收益不值这个险，已回滚。）

## 浏览器 Intl 区域设置：ippure 权重 10 的那一项

量的是 `Intl.DateTimeFormat().resolvedOptions().locale`。ippure.com/claude.html 只给大陆简体计分，`en-US` 是 0 分。

控制它的不是 Chrome 设置也不是命令行：`--lang=en-US` 实测无效，资料里的 `intl.accept_languages` 只改 `navigator.language`。真开关是 **macOS 应用域的 AppleLanguages**：`defaults write com.google.Chrome AppleLanguages -array en-US` 一改，`Intl` 的几个 API 和 `navigator.language` 全跟着变。只影响 Chrome，`defaults delete` 一条还原；代价是界面语言也变英文，且**要完全退出再打开才生效**。

判定只认大陆简体，`zh-TW` / `zh-HK` 不算——判成命中等于拿正确设置报错。实测值跑 `--check-locale`。

## 项目级 settings：清「你给 Claude 的授权」

前面几项清的是 Claude 留下的东西，这一项反过来——Claude Code 每同意一次「总是允许」就往 `permissions.allow` 里加一条，攒下来是本机 25 个文件 1127 条，其中 140 条证明不可能再命中：`Bash(kill 2220)` 这种一次性 PID、`/Users/别人/...` 这种别的机器的路径、还有指向已删目录的绝对路径。

失效的自动清，偏危险的（`Read(**/.ssh/**)`、`Bash(pkill ...)`、`Bash(curl:*)`）只报告不代删——那会让 Claude 多弹确认，是取舍不是清理。

两个地方容易判错：`Bash(pnpm --filter @acme/schema build)` 里的 `/schema` 是包名不是路径，判死就把在用权限删了，所以只认 `/Users`、`/home` 这类真文件系统根；`pkill` 里也含 `kill`，但它是按模式杀，不是一次性 PID。

还有一个格式上的坑，代价最大：权限条目有纯字符串和 `["规则", null]` 两种形态。第一版清理把保留项写成元组，序列化成 JSON 就变成了数组——241 条字符串被改写成 209 条 `["...", null]`，JSON 能解析、肉眼也像对的，但格式已经变了。发现后从备份回滚重做，并钉了回归用例。**写回用户文件时，原对象要原样放回，不重建、不归一化。**

## 系统级占用：按类别清，不按大小清

`A25_claude_storage` 把「能清的」和「不能清的」分开列。能清的是两类：被取代的旧版本（CLI 攒下的历史版本、桌面版内置的旧副本），和会自己重建的缓存（Electron 的 `Code Cache`、`Cache`、`GPUCache`、`Dawn*`）。不能清的是 `Local Storage`、`IndexedDB`、`Cookies`、`Preferences`、配置、会话、用量历史——那些可能是账号状态的一部分。

判「哪份是旧的」看的是 `command -v claude` 的软链接指向，不是版本号比大小：`2.1.99` 和 `2.1.100` 按字符串比就会判反。

这一轮实测清掉约 990 MB：CLI 历史版本 637 MB、桌面版内置旧副本 219 MB、Electron 缓存 133 MB。

## 项目级 `.claude` 按需要清，不按体积清

文章只讲了家目录那三处残留，但实测本机真正占地方的是项目里的 `.claude/worktrees`：55 个目录 8.5 GB，**99% 是工作树**——那是 Claude Code 的 git 工作树，里面是真实代码，还有 `backend/.env` 这类文件。

所以脚本对项目级只做两件事，都指向「失效」而不是「占地方」：

一是**报事实**。`A24_project_claude` 给出一共有几个目录、多大、worktrees 占多少、活工作树几个、失效注册几条。看到「8.5 GB」不要顺手去删，那 8.5 GB 里 8.46 GB 是你在跑的代码。

二是**清失效注册**。`prune_stale_worktrees` 跑 `git worktree prune`，只处理「路径已经不存在」的条目——工作树目录早没了，剩的只是 `.git/worktrees/<name>` 里一条登记。活的工作树 `prune` 不会碰，脚本也不会碰。

项目级对应的是 `clean_project_claude_junk`：清 `.DS_Store` 和 `__pycache__`，不碰 `skills/`、`settings*.json`、`agents/`、`hooks/`、`commands/`，也不进 `worktrees/`。实测这部分只有 5 个小东西（约 96 KB），真正的大头在系统级。

一个必须按精确文件名清的坑：skill 目录下的 `*.log` 看着像日志，实际是 eval 的测试夹具（本机 294 个），按后缀扫会把 skill 自己的测试弄坏。

还有两个实现上的坑，也是实测撞出来的：工作树里的 `.git` 是个**文件**（内容写着 `gitdir: ...`），用 `.exists()` 判断会把每个工作树当成一个仓库、把父仓库的整份列表重复数一遍，我第一次就报出了「活工作树 1464 个」；`.claude/worktrees/.DS_Store` 这类孤立文件按目录深度扫会当成工作树目录，要单独认。

## 必须人工做的事（`--manual`）

文章里有二十三项本机没有接口、脚本替不了，集中成一份人工行动清单（七组）：

```bash
python3 scripts/account_guard.py --manual
```

分七组：手机与其它设备、浏览器与设备隔离、网页端设置、账号与支付节奏、使用行为、被封之后、出口这个节点本身。每项都带 `〔文章 §X〕` 出处、能直接照抄的点击路径，和一句「为什么」。它是只读的，不体检、不改任何东西。

三条最容易漏的：

**iPhone 的两道开关都要关。** 只关「自动设置」不够，还要进 设置 → 隐私与安全性 → 定位服务 → 系统服务 里关掉「设定时区」。文章原话是「两端要对齐，电脑说自己在台北，手机说自己在上海，这本身就是一对矛盾信号」。

**验证邮件只在专用浏览器里点开。** 文章原话：「环境配得再干净，在日常浏览器里点一下 Claude 的登录链接，真实 IP 就交出去了」，并说注册阶段翻车最多的就是这一步。

**额度见黄就停。** 文章原话「限额不等于封号，换号绕过限制才像滥用」。这条零成本，来自被封过多个号的人。

另外两项在总表里能直接看到，不用去人工清单找：**浏览器资料是否隔离**（A23，只报数量）、**作息与出口时区**（A22，出口当地是不是深夜）。

## 手工核对清单与检测网站

想自己复核一遍而不跑脚本，用这条命令把清单打出来：

```bash
python3 scripts/account_guard.py --commands
```

下面就是它的内容。规则是：**在新开的终端里跑**，老窗口可能还带着启动时的旧代理变量。

### 一、出口与泄漏面

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

### 二、系统与终端残留

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

期望无输出。**原文这条写得太宽**：只要当前目录名里带 claude（比如就站在 `claude-account-guard` 目录下），`PWD` 就会被命中，实测踩过。真要查代理就拆成 `env | grep -i proxy`。

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

应无输出。实测 Homebrew 7 只把（小写的）`http_proxy` / `https_proxy` / `all_proxy` 打进 `config` —— 把大小写六个都设上再跑一次 diff，多出来的只有小写那三行，大写那三个它一个字都不提。所以这条能测出来的是 `env | grep -i proxy` 的子集，不是独立的一层。

**settings.json 内容**（文章 2.5⑤）

```bash
cat ~/.claude/settings.json 2>/dev/null
```

重点看 `env` 里有没有 `ANTHROPIC_BASE_URL`。用过镜像站或各种中转的这里常有残留，服务端一看请求就知道没走官方。清单里那条写得更细，是 `grep -iE "proxy|base_url|anthropic_"` 三段——**proxy 那一段同样要查**：在 `env` 里放一个 `HTTPS_PROXY`，请求就绕到那个代理上去了，而早先的实现只认端点与凭据键，既不报也不清；2026-10-10 补上，现在三类一起报、一起清。

### 三、Clash 线路与绝不直连

三条命令共用一个前缀：

```bash
SOCK=/tmp/verge/verge-mihomo.sock; AUTH="Authorization: Bearer ${CLASH_SECRET:-<你的 secret>}"
```

**当前模式**

```bash
curl -s --unix-socket $SOCK -H "$AUTH" http://localhost/configs   | python3 -c "import json,sys;print(json.load(sys.stdin)['mode'])"
```

应为 `rule`（或 `global`，见上文「代理与线路」那节的判据）。

**GLOBAL 指向哪个组**

```bash
curl -s --unix-socket $SOCK -H "$AUTH" http://localhost/proxies   | python3 -c "import json,sys;p=json.load(sys.stdin)['proxies'];print(p['GLOBAL']['now'], '|', p['Claude']['all'])"
```

应指向 Claude 专用组，且该组只有一个成员。

**实际走哪条链**

```bash
curl -s --unix-socket $SOCK -H "$AUTH" http://localhost/connections   | python3 -c "import json,sys;from collections import Counter;print(Counter(' -> '.join(reversed(c['chains'])) for c in json.load(sys.stdin)['connections']))"
```

链里应只有 `GLOBAL -> Claude -> 节点`。**切模式之后老连接的链是旧的**，先清一下再看：把上面的 URL 换成 `-X DELETE`。

**Claude 规则排在最前**

```bash
curl -s --unix-socket $SOCK -H "$AUTH" http://localhost/rules   | python3 -c "import json,sys;[print(r['payload'],'->',r['proxy']) for r in json.load(sys.stdin)['rules'][:7]]"
```

前 7 条应是 `anthropic.com` / `claude.ai` / `claude.com` / `claudeusercontent.com` / `statsigapi.net` 与 `160.79.104.0/21`，全部指向 `Claude` 组。

**订阅会不会把规则改回去**（这台机器上最容易忽略的一条）

```bash
grep -nE '^mode:' ~/Library/Application\ Support/io.github.clash-verge-rev.clash-verge-rev/profiles/*.yaml
tail -5 ~/Library/Logs/clash-mode-guard.log
```

这个值不在任何落盘文件里（`verge.yaml` 没有 mode 键、`profiles.yaml` 只有组选择、`cache.db` 是空的），Clash Verge 会按内存里的值把它推回去，所以只能靠守护脚本每 30 秒盯一次，日志里能看到 `mode was 'x' -> restored to rule`。

守护脚本的判据改过一次。旧版只在 `clash-verge.yaml` 被改写时才动手，把「文件没变」等同于「你自己在界面上切的」。但 Verge 完全可以在不碰文件的情况下改运行时 mode——2026-10-09 实测发生过，mode 被推回 global 而文件一直写着 rule，守护脚本放过了它，分流就此停摆。现在改成「只要运行时不是目标值就拉回来」，想让手动切换生效就 `touch ~/.local/state/clash-mode-guard.hold`。

### 四、时区与定位

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

### 五、客户端与账号

**Claude Code 版本与占用**（文章 §5）

```bash
which claude; claude --version
ls -la ~/.local/share/claude/versions/
du -sh ~/.local/share/claude/versions/
```

`versions` 目录每份 200 MB 上下，安装器会自行清理旧版本。

**钥匙串条目**（文章 2.6）

```bash
security dump-keychain 2>/dev/null | grep -E '"(svce|acct)"' | sort -u
```

要分开看：`svce='Claude Safe Storage'` 配 `acct='Claude Key'` 是桌面版的加密存储；CLI 的凭据是 `svce='Claude Code-credentials'`。两者不是一回事。

**遥测三键**（文章 §5）

```bash
python3 -c "import json;print(json.load(open('$HOME/.claude/settings.json')).get('env',{}))"
```

想关就在这里加 `DISABLE_TELEMETRY` 与 `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` 为 `1`。有副作用，Remote Control 可能失效。

### 文章里给的检测网站

| 用途 | 网站 | 说明 |
| :--- | :--- | :--- |
| 出口 IP | ipinfo.io、ping0.cc、whoer.net | 看 country / city / org，国家要固定、城市别每次变 |
| IP 纯净度 | ippure.com | 文章 2.3 附的来源，看是不是住宅段 |
| 社区检测页 | ip.net.coffee/claude | 文章原话「只作参考」，不当作判据 |
| WebRTC | browserleaks.com/webrtc | 不能出现真实公网 IP |
| DNS | browserleaks.com/dns | 不应出现中国的 DNS 服务器 |
| Claude 服务状态 | status.anthropic.com | 怀疑是服务端问题时先看这里 |

### 只想快速看一眼

三条就够：

```bash
scutil --proxy | grep -E "HTTPEnable|HTTPSEnable|SOCKSEnable"
curl -s --noproxy '*' https://api.ipify.org
SOCK=/tmp/verge/verge-mihomo.sock; AUTH="Authorization: Bearer ${CLASH_SECRET:-<你的 secret>}"
curl -s --unix-socket $SOCK -H "$AUTH" http://localhost/configs \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['mode'])"
```

第一条全 0、第二条是预期出口、第三条是 `rule`（或 `global`），就没大问题。

## 参考来源

检查项的取材与逐条对照见 `references/article-mapping.md`。来源是一篇公开长文，以及它自己引用的三篇材料：

- 《你的 Claude 账号是怎么被封的》 https://x.com/AYi_AInotes/status/2106639522586829094
- 陈大黄复盘贴 https://x.com/realchendahuang/status/2104455272614035947
- 实践哥复盘贴 https://x.com/MinLiBuilds/status/2105890192108536029
- wangray《半年稳定的配置》 https://x.com/wangray/status/2105658146685608265

原文文末自带的两条推广（住宅代理服务商、新加坡卡）没有收进来，也没有作为任何检查项的依据。
