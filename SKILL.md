---
name: cc-tackle
metadata:
  version: "1.0.4"
description: >-
  检测并按用户选择修复 Claude Code 的本机环境——出口 IP 与 ASN 归属、用户指定的预期国家/IP、系统代理与 shell/npm/git 残留、Clash 的 DNS 解析器与 WebRTC 泄漏、IPv6、时区分层与两道闸、`settings.json` 里的中转端点、钥匙串条目、第三方客户端痕迹、CLI 完整性、多账号痕迹与 CLI 登录凭据（长期 token 还是网页授权登录）。默认审计只读且不落盘；加固先展示完整计划，确认后备份优先、失败即停、每项写入后复验；恢复必须使用显式备份目录并逐项验证。
  Use when 用户说「Claude 环境自检 / 保号体检 / 登录 Claude 前先检查环境 / 系统代理残留又出现了 / DNS 泄漏 / WebRTC 泄漏 / 出口 IP 是机房还是住宅 / 时区对不对 / settings.json 有没有中转残留 / 换订阅后 Claude 线路还通不通 / 换机器后 Claude Code 又要求重新登录」，或换环境、换代理订阅、被封后重开之前要做环境排查时。
  不用于：账号申诉、付款退款与 claude.ai 网页端设置（人工流程，本 skill 不涉及）；业务仓代码修复；本机网络链路或内核故障排查。
---

# CC tackle —— Claude Code 环境检测与自动清理

本 skill 的产出是「一张环境体检总表 + 用户明确选择后的改动记录」。它不改业务仓代码、不做账号申诉、不碰付款，也不处理其它工具（`~/.codex`、`~/.dsh`）自己的配置——那些只报告不代改。

一个脚本做两件事：**检测环境**，然后在用户确认后清理可安全清理的残留。

安全约定沿用 `claude-cleanup`：只读审计永远安全且默认不落盘（注意它仍会调用 `claude` / `npm` 读状态，这两个 CLI 自己可能写迁移或日志，`--fix-auto` 的备份是动手前那一刻的状态）；写操作需要真实 TTY 和一次最终确认，确认前不请求 sudo、不建备份、不改状态；确认后先完成备份再改目标状态（并发锁只是控制元数据），备份失败即停；需要 root 时只在终端原生 sudo 隐藏提示里输密码，脚本从不读取或保存密码。

## 确认后可清理什么

以下残留会在最终确认后按计划清理；Clash DNS、Chrome Intl 和不可原样回滚的清理动作会另行询问：

- 未启用但存了值的系统代理残留（`127.0.0.1:7897` 这类，只在 `Enabled: No` 时才动）；
- shell 配置（`.zshrc` / `.zprofile` / `.profile` 等）里的代理行；
- npm 与 git 的全局代理配置；
- Claude Code `settings.json` 的 `env` 里指向别处的端点、凭据与代理变量（`ANTHROPIC_BASE_URL`、`HTTPS_PROXY` 等）。

这些目标和项目级 settings、npm/git 配置、浏览器回滚凭据都会纳入确认前展示的备份清单。系统级旧版本/缓存、失效 permissions、`.DS_Store`/`__pycache__` 和失效 worktree 注册不再默认清理：前两类不可原样回滚，worktree 是 Git 元数据变更；会单独列出并默认选否。

清 shell 配置时只删命中那几行，注释、`EDITOR`、`alias` 之类全部原样保留；清 `settings.json` 时只动 `env` 里属于端点、凭据、代理的键，其余键以及非 `env` 键全部保留。每一项清完都复验。

当前 shell 进程里的代理或端点变量只报告不代改——脚本改不了已经启动的进程环境，需要用户在新终端里确认。

## 什么仍然由你决定

因为**有副作用**，以下操作逐项询问，默认都选否：

- 遥测开关（`DISABLE_TELEMETRY` 等）——文章 §5 写明会连带关掉功能旗标，Remote Control 可能失效；
- 关闭网络服务的 IPv6——需要管理员密码；
- 关闭定位服务里的「设定时区」——改动系统隐私库，风险最高。
- 修改 Clash DNS——写配置并请求内核重载。
- 修改 Chrome Intl 应用语言——写 Chrome 偏好并需要重启。
- 清理系统级旧版本/缓存、项目失效权限和 Git worktree 注册——分别按不可原样回滚或需备份的范围确认。

## 标准调用流程：前测 → 修 → 后测 → 一份 HTML

### 一次跑完：先问一屏，再体检、修、复检、出 HTML

不想来回三轮就这一条：

```bash
python3 scripts/account_guard.py --preflight --fix-auto
```

它按顺序做四件事；开头问一屏，动手前再确认一次：

1. **问一屏**（`--preflight`）：要不要现在开浏览器复核页，把 Intl 与媒体权限测回来；要不要顺带跑一次 WebRTC 探测；复核页开在哪个 Chrome 资料（留空=默认资料）；有没有固定出口国家 / IP 要声明。这四件不先定下来，对应的三项就只会是 `·`（也可以直接用参数表达），所以问在体检之前，而不是等表打完了再补问。资料名问到手后会写进环境变量，复核缓存与后续判定用的是同一份声明。
2. **体检**：只读那一整套，28 项。
3. **当场修**（`--fix-auto`）：把有备份、改完能就地复验的四类残留列出来，确认一次后先备份再改——系统代理残留、shell 代理行、npm / git 全局代理、`settings.json` 里的端点与代理变量。不申请 root、不删不可原样回滚的东西、不问遥测与 IPv6。
4. **复检 + 出 HTML**：改动之后重新体检，打印「修复前 → 修复后」，直接落一份前后对照的 HTML 并打开。

`--fix-auto` 没有可修项时也出页面（注明只有体检结果）；在确认处取消同样出页面（注明这是改动前的状态）。

agent 没有 TTY，用参数表达同一组授权，一个回合跑完：

```bash
python3 scripts/account_guard.py --audit --verify-browser --webrtc --fix-auto --yes
```

`--yes` 只对 `--fix-auto` 有效，作用是跳过动手前那次确认。它等价于「用户已经在对话里同意这张清单」，所以必须先问、拿到明确同意再带上它，不许替用户默认同意。

### 想分两步看的时候

最常见的用法就这四步，一条命令走完前三步：

```bash
# 前测（只读，不改任何状态；加 --report 顺手留下一份 HTML）
python3 scripts/account_guard.py --audit

# 修 + 后测 + 出报告（需要普通终端：会先列改动清单，敲一次 CONFIRM 才开始）
python3 scripts/account_guard.py
```

- 第 2 条命令自己就是完整流水线：**动手前体检一次 → 备份 → 执行改动 → 改动之后重新体检一次 → 打印前后对照表 → 落一份带前后对照的 HTML 并打开**。不需要另外跑一遍后测，也不要拿加固前那份报告充当结果。
- 整轮**只在最后出那一份**（第 2 条命令结尾自动出，并打开）。只想单独要一份快照、不要前后对照时加 `--report`：`--audit --report` 给「只有这一次体检」的页面，也不顺带写 JSON 与出口历史。
- 需要管理员权限的两步（关闭 IPv6、定位服务「设定时区」）在动手前**一次性申请授权**：敲完 CONFIRM 就先走 `[0/6] 管理员授权`，终端隐藏输入一次开机密码，后面所有 root 步骤都复用这份缓存（过期只补问一次）。同一次授权里会把 `/var/db/locationd/clients.plist` 读一遍并落进 24 小时缓存——不读的话「时区两道闸」那一项永远只有「读不到（要 root）」，跟用户答不答「关掉」无关。没有拿到授权不会让整轮失败，只会跳过这两步、其余照常做完。
- 在 CONFIRM 处取消时，加过 `--report` 的同样会给一份 HTML，并注明「已取消，这是改动前的状态」——取消不等于什么都不给。
- 浏览器 Intl 与 WebRTC 那两项默认要有人开一次本地复核页，不加 `--verify-browser` 就只会显示 `·`（没测到），不会假装通过。加了之后脚本自己把两个复核页在你指定的资料里打开并等回传，一次跑完就能出结论，所以它现在是标准流程的第一步而不是可选项。判据是**谁打开的**：脚本自己开的页面算证据，手工开的只当参考——脚本能证明的是「我让哪个资料打开了这个页面」，不是「这个资料就是你的日常账号」。在 Claude Code 里这条也放行（只开本机复核页、写自己的复核缓存，不动 Claude 的状态）；被拦住的只剩完整加固。

## 运行顺序

想先看全貌（只读，约 1.5 分钟），在本 skill 目录下跑 `python3 scripts/selfcheck.py`。它把「技能文件齐全（含 SKILL.md 的 `name` 与目录名是否逐字符相等）→ 语法编译 → 全部单元测试 → 三个守护脚本 → Clash 内核状态 → 系统代理四开关 → 完整体检」串成七项，跑完出两张表，并把体检那 28 项逐条展开；脚本按自己的位置定位，从任何工作目录调用都行，项目根没在 `CLAUDE_GUARD_PROJECT_ROOTS` 里指定时会自动用本 skill 所在的 git 仓并在末尾打出选中的是哪个。它跑体检时会带上 `--verify-browser` 与 `--webrtc`：前者把浏览器 Intl 与媒体权限两个复核页弹出来并等回传，后者临时起一个浏览器资料做真实的 ICE 探测，所以一次就能把这 28 项全部测到、不留「未测到」。`--fast` 跳过单元测试，`--no-audit` 跳过体检，`--no-browser` 不弹复核页（那两项会退回「未测到」）。它**不生成 HTML 报告**：报告是加固收尾那一份带前后对照的（想要只读快照用 `account_guard.py --audit --report`）。在 Claude Code 里跑 selfcheck 时脚本会自动降级成纯只读审计并在末尾说明。

1. **先问，再跑，一轮结束。** 开工前用一条消息把三件事一次问完，不要边跑边补问：
   - 现在能不能开浏览器复核页（不然「浏览器 Intl」「WebRTC」两项只能报未测到）；
   - 有没有固定的出口国家 / IP 要声明（不声明，「预期出口是否符合」只能报未声明）；
   - 体检发现的残留要不要当场修掉。

   拿到回答后用一条命令跑完：

   ```bash
   python3 scripts/account_guard.py --preflight --fix-auto
   ```

   agent 没有 TTY，用参数把同样的授权带进去，同样一轮跑完：

   ```bash
   python3 scripts/account_guard.py --audit --verify-browser \
     --expected-country US --expected-exit-ip 203.0.113.10 --fix-auto --yes
   ```

   跑完的形状是一条链：体检 → 当场修可自动修的 → 复检 → HTML。收尾把 HTML 路径给用户，别让报告只停在终端里。

   在 Claude Code 里：`--audit`、`--verify-browser`、`--fix-auto` 都能跑，但 `--fix-auto` 会跳过 Claude Code 正在用的 `~/.claude/settings.json`，那部分留给用户换普通终端再清；完整加固（不带参数那条）仍然只能在普通终端跑。

2. 由普通终端执行时，先跑审计并向用户说明：确认前不写任何状态；确认后先备份再改目标状态；代理、shell、npm/git 和 Claude settings 会按计划处理，Clash DNS 与 Chrome Intl 分开询问且默认否；密码只走 sudo 原生提示；每项改动后立即复验。`--save-audit` 只与 `--audit` 或 `--json` 一起使用，完整加固模式会拒绝该组合。

3. 用户明确要求继续后：

   ```bash
   python3 scripts/account_guard.py
   ```

   要连别家代理（sing-box / v2ray / Surge）的 DNS 配置一起改，加 `--fix-unverified`：改完能不能生效取决于那个软件自己重启，脚本验不了，所以默认不动，改之前照样先备份。

   ```bash
   python3 scripts/account_guard.py --fix-unverified
   ```

### 出口目标要由用户明确指定

如果你有固定的线路目标，可以把目标国家和出口 IP 直接交给审计：

```bash
python3 scripts/account_guard.py --audit \
  --expected-country US \
  --expected-exit-ip 203.0.113.10
```

`--expected-country` 只接受 ISO 3166-1 两字母代码，`--expected-exit-ip` 接受合法的 IPv4 或 IPv6。这两个值也可以放进 `CLAUDE_GUARD_EXPECTED_COUNTRY` 与 `CLAUDE_GUARD_EXPECTED_EXIT_IP` 环境变量（命令行优先），这样 `selfcheck.py`、报告服务这些拿不到命令行的入口认的是同一份声明；两处都没给才算没声明。带持久化的那几种运行方式（`--save-audit`）会把你给的声明记进 `~/.local/state/claude-guard/expected-exit.json`，第三次运行的入口（比如自检脚本、报告服务）就认这份记录，不会因为换个入口就退回「未声明」；只读 `--audit` 一个字节都不写。声明必须由你显式给出，脚本不会从当前实测结果自动填入。没有指定目标时，报告只能说「未声明目标」，不能说目标匹配；实测出口和目标不一致时先检查线路，脚本不会根据错误的国家自动改 Chrome 的语言或区域。

退出码：`0` 正常完成；`1` 用户在 CONFIRM 处取消；`2` 拒绝执行或中途停止（`--fix-auto` 里改动做完但收尾 HTML 没写成也算 2，因为那条流程把页面当交付的一部分）；`3` 加固已完成但检测到受保护文件被本脚本之外的进程改动（stderr 会给出文件和备份路径）。

体检还会报出 CLI 的 `versions` 目录留存了几份、占多少空间（每份 200 MB 上下，非当前版本可手动删），并对当前在跑的那份二进制**验签**：官方 CLI 带 Anthropic 的 Developer ID 签名，`codesign --verify --strict` 通过即等于「没被替换过」；没签名报待处理，验签失败报 ✗。

## 跑完看什么：结果总表

不管是 `--audit` 还是完整执行，最后都会打印一张 28 行的方框表格，一栏是检查项、一栏是状态、一栏是实测结果。四种状态：

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

**缺字段一律当「未测到」，不默认成「干净」。** 某一项因为报错没跑出来时，它必须显示 `·`，绝不能因为字段缺失就显示 ✓。这条有测试守着（空报告应当 28 项全部未测到、0 项已解决）。

**别把别的工具的残留说成会被清理。** 扫描会连带命中 `~/.dsh/settings.yaml` 这类别的工具的配置，按范围约定脚本不碰它们，所以表里要写「只报告不代改」，不能写「自动清理会清掉」。

## 结果页：HTML 报告

默认**只在完整加固的最后落一份**（`~/ClaudeGuardBackups/report-<时间戳>.html`）：零外部资源、无 JS。这一页天生是前后对照——顶上「修复前 X → 修复后 Y」的分数，下面逐项把动手前与动手后的记号并排列出来，因为那一轮里真的测过两次。分数用**加分制**：27 个基础项合计 100 分，每项 100/27 分，通过拿满、待处理拿一半、未通过 0 分，「没测到」也按 0 分计，分母固定 27 项，不折算；「登录方式」是第 28 行但不计基础分，属于额外加分项，通过再加 5 分，满分 105。只读自检 `selfcheck.py` 不出页面：一次流程只留最后那一份，免得最终报告被稀释成随手可得的快照。只读运行想要一份快照就显式加 `--report`（页面会注明「只有这一次体检，没有改动对照」），`--audit --save-audit` 落盘并打印路径。想在上面**点着修**就跑 `python3 scripts/report_serve.py` —— 本地回环服务加一次性令牌，只给「本来就敢自动做」的项出按钮。详见 `references/report-page.md`。

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

## 不只认 Clash

上面那套判据是 mihomo 的。真正依赖代理软件的只有两行——「绝不直连」与「DNS 泄漏」，其余各项（出口 IP 与 ASN、系统代理残留、终端与 shell 残留、时区、CLI 完整性、浏览器两项）用哪一家都照跑。

脚本会先认出这台机器上是哪一家（报告里的 `A28_proxy_backend`），再按它自己的能力去判：mihomo 内核读控制接口，sing-box 读 `clash_api` 或配置文件，Surge 读 profile 或 HTTP API，v2ray / Xray 读 `config.json`，只有系统代理与 VPN 就直说「没有分流概念」。认得出进程但配置格式不认识时，那一行写「脚本不认识它的配置格式」并给人工核对命令，不留白也不假装通过。

四条硬规矩：**静态读配置不等于运行时**（要让 `ps` 里的 `-c` 路径与读到的配置对得上才据此报绿）；**只有改完能复验的才自动改**（mihomo 走原路；sing-box / v2ray / Surge 的配置改动要显式加 `--fix-unverified`，因为生效与否取决于那个软件自己重启）；**绝不替别家改分流规则**（只换解析器地址，改完复读核对）；**重载按各家官方支持的方式做**——sing-box 是 SIGHUP，Surge 是 `POST /v1/profiles/reload`，而 v2ray / Xray 收到 SIGHUP 会被直接杀掉，所以脚本只提示你自己重启。

还有一条对任何后端都成立的判定：**流量到底有没有被接管**。`scutil --proxy` 四个开关全 0 也可能已经被 TUN 接管（本机实测：开关全 0，去 1.1.1.1 却走 utun1024）。判据是路由、那个 utun 有没有 IPv4 地址（系统自带的 utun 只有链路本地 v6）、以及本机有没有真能完成 SOCKS5 握手的端口（端口开着不等于它是代理）。认不出后端时，这一条是唯一还能说的实话。

各家的端点、键名、重载方式，以及真机验证到什么程度，见 `references/proxy-backends.md`。其中 mihomo 是本机常态运行验证的，sing-box 是在 `/tmp` 起真实例验证的（含 SIGHUP 重载与 `PUT /configs` 是 no-op 这两条），Surge / v2ray / Xray 只有按官方文档写的夹具单测。

## 时区这一项只检测，不改写

`check_timezone_layers` 报三件事：两个活读数（`/etc/localtime` 指向、新起进程实际拿到的时区）、`timed` 最近一次算出的时区及时间、控制时区的两道闸各自的状态。判定「现在是不是台北」只用两个活读数，`timed` 的日志是历史，单独列出来带时间戳，不参与判定。

这一点踩过坑：6 小时窗口里可能同时躺着几小时前的一次 `Asia/Shanghai` 和之后的一次 `setSourceUnavailable`，把历史当现状会天天误报。所以日志是按时间戳逐条解析后取最后一条事件。

脚本不自动改写定位服务的配置。读 `/var/db/locationd/clients.plist` 需要 root，非 root 时如实报「读不到」并给出 UI 路径，绝不把读不到当成「已关」。

## 项目目录要显式指定

A9（扫项目级 `CLAUDE.md` 里的地理位置词）需要知道你的项目在哪。skill 不猜目录结构，用环境变量指定，冒号分隔：

```bash
CLAUDE_GUARD_PROJECT_ROOTS="$HOME/code" python3 scripts/account_guard.py --audit
```

不设这个变量时这一项会跳过并说明怎么开。

## 必须向用户讲清的五件事

**一、`networksetup -set{kind}` 会把代理顺带置为启用。** 实测确认的陷阱：写入服务器值这个动作本身会打开代理。清残留之后必须再执行一次 `set{kind}state off` 并复验 `Enabled: No`，否则会把「未启用的残留」变成「已启用的代理」，正好造成文章最担心的后果。脚本已内置，手工排查时不要漏。**只处理 `Enabled: No` 的残留，正在启用的代理一律不碰。** 反过来，如果报告生成之后这条已经被清掉了（`local.proxy-residue-cleanup` 每 5 分钟跑一次，实测会抢在前面），脚本按「无需改动」处理而不是报失败——目标状态本来就已经达到；只有「被改成启用」或「换成别的值」才拒绝执行并写明原因。

**二、关闭时区自动设定有「两道闸」。** 文章 2.2 说「很多人漏这一步」指的是定位服务里的那一项。本机实测证实过：只把 `com.apple.timezone.auto.plist` 置 0 之后，时区仍被 `locationd` 覆盖过一次。两道都要关。

**三、遥测开关有副作用。** 见上，脚本不主动改，只在用户选择后才写。

**四、「设定时区」不是官方支持的改动路径。** 脚本会先读出 `/var/db/locationd/clients.plist` 里的候选条目，逐个尝试后**重新读取整份 plist** 复验 `Authorized` 是否真的翻成 False，验不到就判定未生效并让用户走 UI。不会做「写不进去却报成功」这种事。

**五、查钥匙串要看清 `svce` 与 `acct`，它们不是一回事。** `svce="Claude Safe Storage"` / `acct="Claude Key"` 是 Claude **Desktop** 的加密存储；CLI 的登录凭据另存（macOS 上走钥匙串），跟这条不是一回事——**别拿钥匙串条目推断 CLI 登没登录**，那件事看下面的「登录方式」（直接读 `claude auth status`）。另外 `security dump-keychain` 会把每个条目列两遍（一遍十六进制属性号、一遍具名属性），只认 `"svce"` 会漏掉一半条目——实测 `Claude Safe Storage` 正好只出现在十六进制那遍里。解析必须两种写法都吃，并且 `svce` 与 `acct` 只能在同一条目块内配对，不能全局抓。

## 范围

只针对 Claude Code。默认覆盖 `~/.claude`；如果设置了 `CLAUDE_CONFIG_DIR` 指向其它目录，审计会在 `scope_manifest.out_of_scope` 明确列出未覆盖的全局 settings，并把相关行标为未测；完整加固会在确认、并发锁和备份前直接拒绝，不扫描或修改该自定义目录。以下明确不在范围内：账号申诉、付款与退款、claude.ai 网页端设置、Active sessions、订阅节奏与路线选择这类行为决策，以及 `~/.codex`、`~/.dsh` 等其它工具的配置——那些只报告，不代改。

本 skill 也不用于规避封禁、支付检查或任何平台风控。清残留是为了在支持地区正常使用官方客户端时少被误伤，不是给开新号铺路。

## 回滚

确认后、任何改动前，脚本会先为受支持的文件目标建立带 `manifest.json` 的备份；系统设置和不可逆清理另列人工边界（并发锁只用于控制运行）：

```bash
ls ~/ClaudeGuardBackups
cp ~/ClaudeGuardBackups/guard-<时间戳>/files/Users__*__settings.json ~/.claude/settings.json
cp ~/ClaudeGuardBackups/guard-<时间戳>/files/Users__*__.zshrc ~/.zshrc
```

需要 root 的文件（`/var/db/locationd/clients.plist`）用 `sudo cp` 从同一目录还原。本次新建的 `~/.local/bin/claude-safe` 可直接删除；原本已存在的 wrapper 按 `manifest.json` 从备份恢复。只有显式 `--save-audit` 时才会把报告写到 `~/ClaudeGuardBackups/audit-<时间戳>.json`；普通 `--audit` 不写报告、出口历史或浏览器缓存。

系统代理、Chrome Intl 和 IPv6 的原态不在文件恢复快照里，恢复时必须按输出人工复核；系统级缓存、旧版本和 Git worktree 注册也没有完整的自动恢复范围。Clash 配置文件如果被恢复，运行中的内核不会由 `--restore` 自动重载，需在 Clash Verge 中重载或重启后再跑一次审计确认实时状态。

### 显式恢复

需要恢复时必须在普通真实终端里明确指定备份目录：

```bash
# 先只看这份备份能恢复什么
python3 scripts/account_guard.py --restore "$HOME/ClaudeGuardBackups/guard-<时间戳>" --restore-preview

# 确认后恢复全部可验证文件
python3 scripts/account_guard.py --restore "$HOME/ClaudeGuardBackups/guard-<时间戳>"

# 只恢复清单中的某个文件
python3 scripts/account_guard.py --restore "$HOME/ClaudeGuardBackups/guard-<时间戳>" \
  --restore-item "$HOME/.claude/settings.json"
```

恢复同样需要一次确认。脚本会检查备份清单、文件内容和当前文件是否仍是本轮改动后的版本，只恢复能确认由这次运行改动、且之后没有被其他人修改的项目。旧版 v1 备份、清单损坏、文件发生漂移或无法证明归属时会拒绝恢复，避免把新改动覆盖掉。IPv6、系统代理、Chrome Intl、系统级缓存、旧版本和 Git worktree 注册没有完整文件快照，仍需按输出的人工步骤处理；如果恢复了 Clash 配置文件，还要在 Clash Verge 中手动重载或重启内核并重新审计。不能把 `--restore` 当成所有系统状态的一键还原。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

覆盖 ASN 归类（含 `AT&T` 这类需要归一化才能命中的真实坑）、自动清理只删该删的行、遥测三键策略、备份优先于写入、清理后不得变成启用、非 TTY 拒绝、失败时报告备份路径、以及有意清理的 shell 配置不被误报。

结果总表也有专门的一组测试：每行的显示宽度必须一致（守住 CJK 对齐）、截断按显示宽度算、缺字段不得默认成「干净」、读不到的闸门必须标成待处理而不是已关、别的工具的残留不得说成会被清理、WebRTC 的 0 候选必须标成结论不可用。

时区与钥匙串这两项另有针对性回归：历史时区事件不得翻转当前判定、同一窗口内多个定位源事件要取时间上最后那条、`dump-keychain` 的十六进制写法必须能解析、`svce` 与 `acct` 不得跨条目块拼接。「绝不直连」判据按模式分别测：全局模式下 GLOBAL 指错要判不成立；规则模式下 Claude 域名没规则、规则指向别处、兜底是 DIRECT，三种都要判不成立；两种模式下组类型是 fallback、成员不止一个，都要判不成立。另有一条专门盯着「不得把 mode=rule 本身当成故障」——那是修过的 bug，容易被改回去。

安装方式与本地服务另有覆盖：四条安装通道各自的命中条件、探测读不出来不得混成「没装」、老报告里没有 `install` 键时不得凭空指控「安装方式未知」、三个复核服务的令牌路由（不知道令牌取页面与投结果都必须是 404，这条是起真服务端到端跑的）、并发锁（第二个进程被拒、死进程留下的遗留锁能接管、放锁不删别人的锁）、带凭据的代理 URL 进报告前必须脱敏。Chrome「要不要重启」那一项也修掉一个假阳性：原来拿偏好 plist 的 mtime 当「语言刚被改过」的凭据，而 Chrome 运行时会重写它自己那份 plist —— 实测 10-09 22:25 启动的 Chrome，plist 在 10-10 13:24 被 Chrome 自己写了一次，判定就说要重启，而那份值早就生效了。现在只有「我们亲手改过」（读回滚凭据里记的时刻）才算依据，判断不了就返回 `None` 并指向 `--check-locale`。

## 借来的做法（来源：liseami/CCBaga）

有几条做法是照这个项目改过来的，都落在脚本内部，表里那 28 行不变。

**两个横切规则。** 第一，不可验证的东西不参与通过判定：探测本身读取失败（`brew list` 跑不起来、node 全局根读不出来）和「确实没装」必须分开报，读不到就说读不到。第二，改完必须回读断言：清完代理残留要再读一次 `Enabled`，改完 Clash DNS 要重跑一次判定。

**三个具体做法。** 三个本地复核服务（媒体权限、WebRTC、Intl）各起一个 127.0.0.1 的 HTTP 服务，端口随机，但端口随机不等于有鉴权 —— 本机任何进程都能扫到端口往上投一份「摄像头已拒绝」，把没测过的项报成已通过；现在每次生成 24 字节随机令牌当 URL 路径前缀，不知道令牌取页面和投结果都是一律 404。加固流程加了并发锁：备份、删除、改配置交错会让回滚凭据和实际状态对不上，所以用 `O_CREAT|O_EXCL` 原子建锁文件，锁里记 pid，持有进程已消失的遗留锁自动接管。调 CLI 一律带 `DISABLE_AUTOUPDATER=1`。Clash API 的 secret 由 Python 在内存中组装请求头，不再放进 curl 的进程参数；仍需通过本机环境变量传入，并避免把环境变量复制到日志、脚本或仓库。

**代理凭据不进报告。** `proxy=http://user:pass@host:port` 很常见，这些字符串会同时进终端输出和 audit JSON。进报告前统一过一遍 `redact_credentials`：URL 里的用户名密码抹成 `***`，没有 `scheme://` 的 `@` 不碰（免得把邮箱也毁掉），先抹再截断。

## WebRTC：只有「授权之后」才漏，而且它绕过 TUN

未授权时 mDNS 混淆生效、不泄漏；**拿到摄像头/麦克风权限后，候选里会出现真实公网 IP 和内网地址，而且它绕过 TUN**。判据、实测数据与两条走不通的路见 `references/webrtc.md`。
## 浏览器 Intl 区域设置

`Intl.DateTimeFormat().resolvedOptions().locale`，ippure 权重 10，只认大陆简体。见 mapping A27。
浏览器媒体权限与 Intl 缓存必须同时满足 24 小时 freshness 和资料范围匹配：缓存里的 `profileScope` 要和这次复核页实际打开的资料一致。范围默认取 `CLAUDE_GUARD_BROWSER_PROFILE`，没设就取 `CLAUDE_GUARD_BROWSER_PROFILE_DIR`，两者都没有就记 `default`（Chrome 默认资料）——这样全新用户照文档跑一轮也能拿到结论。多资料或切换资料后，显式设一个名字把它钉住；对不上就按未测处理。脚本无法从本地复核页自行识别 Chrome 资料路径，只会记下自己实际用的那个目录，不会伪造资料标签。
决定这两项能不能算证据的是缓存里的 `openedBy`：`--verify-browser`（以及 `--check-media` / `--check-locale`）由脚本自己拉起 `CLAUDE_GUARD_BROWSER_PROFILE_DIR` 指定的 Chrome 资料去开复核页，回传记 `openedBy=script`，这两项才出结论；页面是别人手工打开、脚本只等回传时记 `openedBy=user`，即使 `profileScope` 对上、时效也在，仍按未确证处理。脚本能证明的是「哪个资料打开了这个页面」，不是「这个资料就是你的日常账号」，所以页面上写的是「浏览器实测（脚本打开的复核页，资料 Profile 1）」，把依据一并摊开。
`--audit` 不能和 `--check-media`、`--check-locale` 同时使用（那两项会写缓存、要和体检分开跑）；要用一次跑完就走 `--audit --verify-browser`。

WebRTC 那两项的修法里有一条是装扩展：文章 2.5② 推的 Google 官方扩展 **WebRTC Network Limiter**，`python3 scripts/account_guard.py --install-webrtc-limiter` 会把扩展包从商店的官方分发接口下到 `~/.local/state/claude-guard/extensions/`，报出本机每个 Chrome 资料里装没装、设置对不对，再把商店页在你声明的资料里打开。**装的那一下只能你自己点**——Chrome 在 macOS 上不接受脚本代装扩展；唯一无人值守的路子是机器级策略 `ExtensionInstallForcelist`，代价是浏览器显示「由组织管理」且扩展卸不掉，那条命令写在 `references/webrtc.md` 里，吃不吃这个代价由你决定。下到的包要过三道核，最后一道是拿签名块里的公钥算出扩展 ID 与申请时那个比对——名字能改，ID 由公钥定。

定位服务的 root 实测缓存只在 24 小时内有效，缺少时间戳或过期都按未测处理。只读审计不会创建临时探针文件；非 root 时不调用 sudo 探针，定位服务状态会如实显示为待复核。

## 扩展维护说明

项目授权、缓存与工作树边界、人工清单和历史判断背景见 [`references/maintenance-notes.md`](references/maintenance-notes.md)。这些内容用于深入复查，不改变默认只读、用户确认和显式恢复规则。

## 手工核对清单与检测网站

想查看脚本能判断的状态，直接运行只读审计：

```bash
python3 scripts/account_guard.py --audit
```

如果需要外部网站和人工路径，才运行 `python3 scripts/account_guard.py --commands`；其中 Clash API 检查不要手工拼接 Authorization 请求头或调用 curl，始终使用上面的脚本内建安全入口。规则是：**在新开的终端里跑**，老窗口可能还带着启动时的旧代理变量。

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

### 三、Clash 线路与绝不直连

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

### 文章里给的检测网站

| 用途 | 网站 | 说明 |
| :--- | :--- | :--- |
| 出口 IP | ipinfo.io、ping0.cc、whoer.net | 看 country / city / org，国家要固定、城市别每次变 |
| IP 纯净度 | ippure.com | 文章 2.3 附的来源，看是不是住宅段 |
| 社区检测页 | ip.net.coffee/claude | 文章原话「只作参考」，不当作判据 |
| WebRTC | browserleaks.com/webrtc | 不能出现真实公网 IP |
| DNS | browserleaks.com/dns | 不应出现中国的 DNS 服务器 |
| Claude 服务状态 | status.anthropic.com | 怀疑是服务端问题时先看这里 |
### 只想快速看一眼（三条就够）

```bash
scutil --proxy | grep -E "HTTPEnable|HTTPSEnable|SOCKSEnable"
curl -s --noproxy '*' https://api.ipify.org
python3 scripts/account_guard.py --audit
```

前两条分别用于查看系统代理开关和实测出口；第三条由脚本安全读取 Clash 状态并报告模式、线路和 DNS。目标国家/IP 只有在命令显式提供 `--expected-country`、`--expected-exit-ip` 时才参与匹配。
