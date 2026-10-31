<div align="center">
  <h1>CC tackle</h1>
  <p><strong>Claude Code 本机环境体检与可控清理</strong></p>
  <p>macOS · Python 标准库 · 证据优先 · 改动可复核 · 一条命令</p>
  <p>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-e8a181?style=flat-square" alt="MIT license" /></a>
    <img src="https://img.shields.io/badge/platform-macOS-111827?style=flat-square&amp;logo=apple&amp;logoColor=white" alt="macOS" />
    <img src="https://img.shields.io/badge/runtime-Python%203-111827?style=flat-square&amp;logo=python&amp;logoColor=white" alt="Python 3" />
    <img src="https://img.shields.io/badge/core-Python%20stdlib-111827?style=flat-square" alt="Core uses Python standard library" />
    <a href="https://github.com/VioletScar-Hui/cc-tackle/actions/workflows/tests.yml"><img src="https://github.com/VioletScar-Hui/cc-tackle/actions/workflows/tests.yml/badge.svg" alt="Tests" /></a>
    <img src="https://img.shields.io/badge/version-1.1.0-111827?style=flat-square" alt="version 1.1.0" />
  </p>
  <p>
    <a href="#what-it-does">它能做什么</a> ·
    <a href="#bottom-lines">几条底线</a> ·
    <a href="#how-it-works">怎么工作</a> ·
    <a href="#authorization">分级授权</a> ·
    <a href="#quick-start">快速开始</a> ·
    <a href="#detection-scope">检测范围</a> ·
    <a href="#data-boundaries">数据边界</a> ·
    <a href="#docs">文档导航</a>
  </p>
  <p>
    中文 · <a href="README.en.md">English</a> ·
    <a href="CHANGELOG.md">更新记录</a> ·
    <a href="docs/decisions.md">决策记录</a> ·
    <a href="#verified">验证到什么程度</a>
  </p>
</div>

![Claude Account Guard: a warm pixel-art scene for inspecting and verifying a local Claude Code environment](docs/readme-hero.png)

> **用途边界**：这是一个面向 macOS 本机的环境检查与维护工具。它帮助你发现网络出口、代理残留、时区、浏览器测量和 Claude Code 本地配置中的可见问题；它不能解释服务端风控原因，也不能保证账号可用或通过任何服务的审核。

CC tackle 把检测、证据、备份和复验放在同一条命令链里。默认先看清楚环境，再决定是否处理。普通 `--audit` **默认落一份 HTML 页面并打开**（终端那张表新人看不出下一步），但它仍然不写审计 JSON、出口历史或缓存；脚本化场景设 `CLAUDE_GUARD_NO_REPORT=1` 关掉页面，要留 JSON 再用 `--audit --save-audit`。完整加固会先展示执行清单，只有确认后才锁定目标、备份和修改。

它是一组脚本，也是一个给 agent 用的 skill：`SKILL.md` 写明判据和执行边界，agent 照着跑；人也可以只在终端里敲一条命令。

<a id="what-it-does"></a>

## 它能做什么

| 能力 | 具体做什么 |
| --- | --- |
| **网络身份** | 检查出口 IP 与 ASN 类型、出口变化、DNS 泄漏、WebRTC、IPv6 和 Claude 域名的路由结果，并把“未测到”和“异常”分开。 |
| **代理链路** | 查看系统代理、shell、npm、git 与代理软件配置中的残留或不一致项，保留原始证据供复核；识别 mihomo / sing-box / Surge / v2ray 等后端。 |
| **Claude 配置** | 检查 `settings.json` 的端点、凭据和代理变量，以及遥测开关、CLI 签名和第三方客户端痕迹。 |
| **账号环境** | 核对时区层级、浏览器 Intl 区域、浏览器资料复用、多账号痕迹和钥匙串条目。 |
| **环境卫生** | 定位项目级 `.claude` 噪声、失效权限条目、过期工作树登记和可回收的系统体积。 |
| **常驻保护** | 可选装直连看门狗（绕隧道就杀）、出口 IP 漂移告警、住宅链路锁定（pf + DNS 守卫）。 |
| **人工清单** | 对脚本无法代替的浏览器权限、系统设置和外部检测，给出带来源的人工核对路径。 |

<a id="bottom-lines"></a>

## 几条底线（先看这几条）

- **钱和账号你来。** 付款、登录、KYC、OAuth 都由你本人完成。脚本不登录、不支付、不做申诉。
- **不读凭据值。** 长期 token 只记“它写在哪个文件/哪个变量里”，绝不读值、不出现在报告里。
- **改前先备份，改后必复验。** 确认前不建备份、不改状态；备份失败即停；每项改动后回读断言；不可原样回滚的动作单列、默认否。
- **别人的工具只报告不代改。** `~/.codex`、`~/.dsh` 和其它软件的配置会被扫到，但只写“不代改”。
- **不替平台下结论。** 不承诺免封，不解释服务端风控，不把“网络通”当成“账号可用”；它只报告这台机器当次测到的证据。

<a id="how-it-works"></a>

## 怎么工作

```mermaid
flowchart LR
    U["你：一条命令"] --> P["前测<br/>只读体检 · 问一屏"]
    P --> C["分类<br/>能自动修 / 要你定 / 只能人工"]
    C --> A["确认<br/>CONFIRM 或 --yes"]
    A --> B["备份<br/>manifest + 文件快照"]
    B --> F["改动<br/>逐项执行 · 失败即停"]
    F --> R["复验<br/>重新体检 · 前后对照"]
    R --> H["报告<br/>HTML + 下一步命令"]
```

- **先看再动。** 只读审计不写本工具的配置与状态；确实要改，先给你一张清单，你点头才动手。
- **一遍一趟。** 完整流程一次跑完：体检 → 当场修可自动修的 → 复检 → 一份 HTML；不需要另跑一遍后测。
- **报告是证据，不是说明书。** 页面列出两次真读数，收尾时 agent 还会在回复里直说下一步命令。
- **agent 与人的入口相同。** 没有 TTY 时用参数表达同一组授权（如 `--yes`），脚本不会因为调用方是 agent 就放宽。

<a id="authorization"></a>

## 分级授权：哪些要你点头

| 档位 | 你要做什么 | 本 skill 里对应什么 |
| --- | --- | --- |
| 🟢 **A · 只读，直接跑** | 说一声就行 | `--audit`、`--json`、`selfcheck --fast`、`proxy_guard.py --check`、`net_guard.py --once --dry-run`、`residential_lock.py --status/--check/--discover`、打开报告页 |
| 🟡 **B · 批一次计划** | 批准整张清单，之后连续执行、失败即停 | `--fix-auto --yes`（四类残留）、完整加固敲一次 `CONFIRM`（逐项默认否、每步复验）、`net_guard.py --install --yes`、`residential_lock.py --init/--install`、`--install-webrtc-limiter` |
| 🔴 **C · 做到那步再说** | 当场确认，不预先批准 | `sudo` 两步（关 IPv6、关定位「设定时区」）、`residential_lock.py --root-install`（改 `/etc/pf.conf` + 装 LaunchDaemon）、`--fix-unverified`（改别家代理 DNS）、`--restore`（覆盖当前状态）、不可原样回滚的清理（系统缓存、旧版本） |

批准以你在对话里的明确回复为准；换了目标或路线要重新确认。`--yes` 只替代 `--fix-auto` 动手前那一次确认，不替代 C 档里的任何一步。

<a id="quick-start"></a>

## 快速开始

### 1. 一条命令跑完（推荐）

先问一屏 → 体检 → 修 → 复检 → 一份 HTML：

```bash
python3 scripts/account_guard.py --preflight --fix-auto
```

- `--preflight` 把四件事问在体检之前：要不要现在开浏览器复核页（Intl 与媒体权限就靠它转正）、要不要顺带跑一次 WebRTC 探测、复核页开在哪个 Chrome 资料（留空就是默认资料）、有没有固定出口国家与 IP 要声明。答「要」的项这一轮就会测到；答「不」的项如实留 `·`，不假装通过。
- `--fix-auto` 把能自动修的残留当场列出来——系统代理残留、shell 代理行、npm / git 全局代理、`settings.json` 里的端点与代理变量——确认一次后先备份再改，不申请 root、不删不可原样回滚的东西。
- 修完自动复检，落一份前后对照的 HTML 并打开。没有可修项、或者在确认处取消，同样给页面。

agent 没有真实终端时，用参数带上同一组授权，一个回合跑完：

```bash
python3 scripts/account_guard.py --audit --verify-browser --webrtc --fix-auto --yes
```

`--yes` 只对 `--fix-auto` 有效，等价于用户已在对话里同意那张清单，必须先问再带。

### 2. 想先只读看一眼

```bash
python3 scripts/account_guard.py --audit            # 只读体检，默认顺手给一份 HTML
python3 scripts/account_guard.py --audit --save-audit   # 另外留一份 JSON
python3 scripts/account_guard.py --audit --json         # 只要机器可读结果
```

只读审计仍然会调用 `claude` 与 `npm` 读状态，这两个 CLI 自己会写东西；它不写审计 JSON、出口历史或缓存，除非你显式加 `--save-audit`。要关掉自动打开的报告页：`CLAUDE_GUARD_NO_REPORT=1`。

如果你有明确的线路目标，把目标国家和出口 IP 一起写进审计：

```bash
python3 scripts/account_guard.py --audit \
  --expected-country US \
  --expected-exit-ip 203.0.113.10
```

这两个值必须由你自己指定；脚本不会从历史记录或当前实测结果自动猜目标。没有指定目标时，只能报告“未声明目标”。

也可以分两步：先 `--audit --preflight` 只读体检，再跑不带参数的那条做完整流水线（列清单 → CONFIRM → 备份 → 改 → 复检 → HTML）。这条路径要跑两次，因为第一步是纯只读的。

### 3. 报告页：静态 HTML 与可点修复

完整加固与 `--fix-auto` 都在收尾**生成一份**自包含的 HTML 报告，落在 `~/ClaudeGuardBackups/report-<时间戳>.html`——那一页就是前后对照：顶上是「修复前 → 修复后」的分数，下面逐项列出两次真读数。分数是**加分制**：27 个基础项合计 100 分（每项 100/27，通过拿满、待处理拿一半、未通过 0 分），「没测到」也按 0 分计，分母固定 27 项；「登录方式」是第 28 行但不在 27 项里，通过再加 5 分，所以页面满分 105。

页面里另有一节「本 skill 的常驻程序」：只列这个 skill 自己装出来的后台任务，按功能分组（网络防护 / 报告服务 / 体检与清理），标出在不在跑、有没有设开机自启、有没有被禁用。别的软件和系统的 agent 不往里塞。它只是清单，不计分，也不改任何 plist。整页不引用任何外部资源（没有 CDN、没有 web font、没有 JS），页面上的数字全部来自报告本身——判定与终端输出同源，都是 `build_summary`。

```bash
python3 scripts/report_html.py --open              # 用最新那份报告重渲染
python3 scripts/report_html.py <报告.json> --out ~/Desktop
```

想让它**点着修**，用本地服务模式：

```bash
python3 scripts/report_serve.py
```

体检完起一个只绑 `127.0.0.1` 的服务并打开页面。能自动修的项右边多一个按钮，点一下执行、页面刷新、顶部写明这次做了什么；顶部另有「修复全部可自动修的项」和「重新体检」，页脚「结束本地服务」，空闲 30 分钟自动退出。安全边界：端口随机、URL 带一次性令牌、POST 需自定义头、动作白名单，不带令牌一律 404。

按钮只出现在本来就敢自动做的项上：系统代理残留、shell/npm/git 代理、settings.json 端点与凭据、Clash DNS、浏览器 Intl、系统级可清理量、settings 失效权限、项目级垃圾与失效工作树注册。需要人拿主意的（遥测开关、IPv6、定位服务）和必须人工的（手机时区、支付、浏览器隔离）不出按钮。

别家代理（sing-box / v2ray / Surge）的 DNS 配置改动不在按钮里，也不默认执行：改完能不能生效取决于那个软件自己重启，脚本验不了，要用 `--fix-unverified` 显式开启，且会先备份。

### 4. 常驻保护（可选，默认不装）

体检只是在「看」，这几层负责「拦」和「盯」。它们都默认不装，要显式开。

**直连看门狗**：每 5 秒看一遍 Claude 相关进程的对外 TCP 连接，发现它绕过了隧道（路由落在 `en0` 这类物理接口，而不是 `utun`）就 SIGKILL 那个进程，并把 pid、进程路径、目标地址、出口接口写进日志。

```bash
python3 scripts/net_guard.py --once --dry-run   # 先看一眼判据，只看不杀
python3 scripts/net_guard.py                    # 前台跑，每 5 秒一次，发现直连就杀
python3 scripts/net_guard.py --install --yes    # 装成 LaunchAgent 常驻（每 5 秒）
python3 scripts/net_guard.py --status           # 在不在跑
python3 scripts/net_guard.py --uninstall        # 卸载
```

它**不会**把「Clash 规则选了 DIRECT」当成直连——那种流量仍然走 TUN。它抓的是「绕过了隧道」。判据、误杀边界与已知盲区见 [`references/net-guard.md`](references/net-guard.md)。

看门狗还带一个可选的出口锁定：`--init-lock --expected-ip <住宅出口IP>` 之后，每 30 秒顺带查一次真实出口 IP，变了或判成机房就写日志 + 发系统通知。判定用 [`scripts/ip_judge.py`](scripts/ip_judge.py) 多源交叉（ip-api / ipinfo / ipwho.is），判不准返回 `UNKNOWN` 而不是猜，结果缓存一周。它只告警不改配置。

**Claude 出口体检**：2026-10-30 实测踩过——Claude 组里只放了一条线路，那条挂掉后 claude.ai 与 claude.com 全断，而别的站点照常，因为它们走的是别的组。

```bash
python3 scripts/proxy_guard.py --check        # 规则指向哪个组、几条线路、选中的节点是否活着
python3 scripts/proxy_guard.py --fix          # 组内有活节点时，就地切过去
python3 scripts/proxy_guard.py --fix-members --nodes "线路1,线路2,线路3,线路4"
python3 scripts/proxy_guard.py --emit sing-box   # 给 mihomo / sing-box / Surge / Shadowrocket 生成片段
```

单点组、死节点、规则缺失三种情况分别给结论；能探测的只有本机的 mihomo 系（Clash Verge Rev / FlClash / Mihomo Party / ClashX），其余只出片段。事故复盘与各客户端贴法见 [`references/client-adapters.md`](references/client-adapters.md)。

**住宅链路锁定**：比看门狗更重的一层——Clash 规则自愈、pf 防火墙挡住物理网卡直连、代理不健康时 Claude 域名直接 NXDOMAIN。整套脚本收在 [`scripts/residential/`](scripts/residential/)，统一入口是 `scripts/residential_lock.py`：

```bash
python3 scripts/residential_lock.py --status     # 先看现状
python3 scripts/residential_lock.py --init       # 生成参数文件
python3 scripts/residential_lock.py --install    # 装用户级自愈（免 sudo）
python3 scripts/residential_lock.py --discover   # 逐个节点测真实出口，找出住宅节点
sudo python3 scripts/residential_lock.py --root-install   # pf + DNS 守卫（要 sudo）
```

用户级部分免 sudo；root 部分会改 `/etc/pf.conf`（先备份）并装两个 LaunchDaemon，卸载用 `--root-uninstall`。依赖 Clash Verge（service 模式）和 pyyaml（`expand.py` 要用）。细节与踩坑见 [`references/residential-lock.md`](references/residential-lock.md)、[`references/residential-pitfalls.md`](references/residential-pitfalls.md)。

### 5. 一键自检与专项检查

```bash
python3 scripts/selfcheck.py           # 技能文件 → 编译 → 单测 → 守护脚本 → Clash → 系统代理 → 完整体检
python3 scripts/selfcheck.py --fast    # 跳过单测
```

```bash
python3 scripts/account_guard.py --manual       # 打印人工核对清单
python3 scripts/account_guard.py --commands     # 打印检测网站与命令
python3 scripts/account_guard.py --audit --webrtc        # 审计里附加 WebRTC 探测
python3 scripts/account_guard.py --audit --verify-browser # 脚本自己开复核页，一次跑完不留未测到
python3 scripts/account_guard.py --install-webrtc-limiter # 下载 WebRTC Network Limiter 扩展包并打开商店页
python3 scripts/account_guard.py --check-media            # 单独跑：开复核页并等回传媒体权限
python3 scripts/account_guard.py --check-locale           # 单独跑：开复核页并等回传 Intl 区域
```

`--install-webrtc-limiter` 只下载与报告，不改本机配置，所以不需要 TTY：它把扩展包从商店的官方分发接口下到 `~/.local/state/claude-guard/extensions/`，核对签名公钥算出来的扩展 ID，并报出每个 Chrome 资料里装没装。**安装那一下仍然只能你自己点**：Chrome 在 macOS 上不接受脚本代装扩展。

`--audit --webrtc` 会启动临时浏览器资料进行探测，并在结束后清理；它不会修改日常浏览器资料。`--check-media` 和 `--check-locale` 会在本机保存回传缓存，并且会自己把复核页打开——想指定开在哪个 Chrome 资料（就是你日常用 Claude 的那个）就设 `CLAUDE_GUARD_BROWSER_PROFILE_DIR`，例如 `Profile 1`。脚本自己打开的复核页写进缓存的 `openedBy` 是 `script`，这两项才判结论；别人手工打开的记 `user`，只当参考、不作通过证据。

### 6. 需要修改本机状态时

```bash
python3 scripts/account_guard.py
```

完整加固需要真实终端。脚本会先展示最终执行清单，只有在你明确输入 `CONFIRM` 后才锁定目标、创建备份和修改状态。Clash DNS、Chrome Intl、旧版本与缓存、失效权限、过期 worktree 和项目垃圾等项目会逐项询问，默认选择否。需要管理员权限的两步（关闭 IPv6、定位服务「设定时区」）在敲完 CONFIRM 之后先走一步 `[0/6] 管理员授权`：终端隐藏输入一次开机密码，这一次覆盖后面所有 root 步骤，中途过期只补问一次；同一次授权里还会把定位库读一遍并落 24 小时缓存，让「时区两道闸」这一项有结论。没拿到授权不会让整轮失败，只跳过那两步。不要在正在使用 Claude Code 的进程里发起会修改本机状态的操作。

如果中途需要恢复，使用明确的备份目录：

```bash
# 先预览这份备份能恢复什么
python3 scripts/account_guard.py --restore "$HOME/ClaudeGuardBackups/guard-<时间戳>" --restore-preview

# 确认后恢复全部可验证文件
python3 scripts/account_guard.py --restore "$HOME/ClaudeGuardBackups/guard-<时间戳>"

# 也可以只恢复备份清单里的某个文件
python3 scripts/account_guard.py --restore "$HOME/ClaudeGuardBackups/guard-<时间戳>" \
  --restore-item "$HOME/.claude/settings.json"
```

恢复需要真实终端和再次确认。脚本只恢复能确认属于本轮改动、且之后没有被其他修改的文件；旧版 v1 备份、清单损坏或当前文件已漂移时会拒绝恢复。系统代理、Chrome Intl、IPv6、系统缓存、旧版本和 Git worktree 登记没有完整快照，仍要按输出的人工步骤处理。如果恢复了 Clash 配置文件，`--restore` 不会自动重载运行中的内核，请在 Clash Verge 中手动重载或重启后再跑一次 `--audit`。不能把恢复命令当成所有设置的一键还原。

<a id="signals"></a>

## 记号与判据

| 状态 | 含义 |
| --- | --- |
| ✓ | 已满足当前判据 |
| ! | 需要处理或人工复核 |
| ✗ | 检测到异常 |
| · | 当前条件下没有测到 |

**“未测到”不等于通过，也不等于失败**：它表示没有足够证据完成该项检查。缺字段一律当「未测到」，不默认成「干净」。表里出现 `·` 最多的情况是浏览器两项——没开复核页就没有浏览器回传。

<a id="detection-scope"></a>

## 检测范围

检查项按五组组织，具体数量和可用性随平台权限、浏览器回传和本机软件状态变化：

| 组别 | 典型检查 |
| --- | --- |
| 网络身份 | 出口 IP 与归属、ASN 类型、出口一致性、DNS、WebRTC、IPv6、Claude 域名路由 |
| 代理链路 | 系统代理、shell 配置、npm/git 全局代理、代理后端的模式与 DNS |
| 账号环境 | 时区层级、浏览器 Intl、浏览器资料复用、多账号痕迹、钥匙串条目 |
| Claude Code | `settings.json` 端点与凭据、遥测开关、第三方客户端、CLI 签名完整性、CLI 登录凭据 |
| 环境卫生 | 项目级 `.claude`、失效权限、过期工作树登记、可回收系统体积 |

浏览器缓存型结果要同时满足三件事才出结论：不超过 24 小时、`profileScope` 与这次复核页实际打开的资料一致、以及缓存里的 `openedBy` 是 `script`（复核页由脚本自己拉起，而不是别人手工打开）。资料范围默认按实际打开的那个资料记（没声明就是 Chrome 默认资料），所以你照文档跑一轮就能拿到结论；多资料时再用 `CLAUDE_GUARD_BROWSER_PROFILE` 把它钉到某个名字上。脚本能证明的是「哪个资料打开了这个页面」，不能独立证明它就是你的日常账号，所以页面上会把依据写成「浏览器实测（脚本打开的复核页，资料 Profile 1）」而不是一句「通过」。

### 登录方式：不要在 Claude Code 里登录

报告里「登录方式」那一行读的是 `claude auth status`，告诉你这台机器现在用的是哪种凭据：长期 token、网页授权登录，还是根本没登录。

为什么值得单列一项：在 Claude Code 里做网页授权登录，等于把这条登录事件钉在当前出口上；而网页登录还会随掉线、丢包反复要求重登，每重登一次就是一条新的登录记录。更稳的做法是只认证一次：

```bash
claude setup-token        # 按提示完成这一次认证，拿到长期有效的 token
```

把拿到的 token 放进 `CLAUDE_CODE_OAUTH_TOKEN`（写进 shell 配置，或写进 `~/.claude/settings.json` 的 `env`），之后 CLI 直接用这份凭据，不再走网页登录。第一次认证最好在一个干净环境里做（官方 App 也一样），之后只有掉线、换机、token 到期时才再跑一次。

这一项只读状态：脚本不读 token 的值，报告里只出现「它写在哪个文件/哪个变量里」。

## 清理与副作用

安全边界按动作拆分：

- 对系统代理残留、shell 代理行、npm/git 全局代理和 `settings.json` 中明确命中的端点/凭据/代理变量，脚本只改命中的键或行，并在修改后复验。长期 token（`CLAUDE_CODE_OAUTH_TOKEN`）是官方凭据、不是残留，任何一条清理路径都不会删它。进程环境里的代理变量按「只报告」处理：只要 shell 配置、npm/git、`~/.npmrc` 里没有，这一项就算干净。
- 主模式在 `CONFIRM` 前不创建运行锁、备份或修改目标；确认后先创建运行锁，并在任何改动前为受支持的文件目标完成备份；系统设置和不可逆清理另列人工边界。
- Clash DNS、Chrome Intl、旧版本与缓存、失效权限、过期 worktree 和项目垃圾等改动会逐项列出并默认选择否，可能影响后续网络、浏览器或本机空间。
- 遥测开关、IPv6、定位服务时区等操作可能带来功能或系统权限影响，需要单独决定。
- 只有确认并开始加固后，备份目录才会保存本次执行可恢复的输入与变更信息；恢复能力取决于具体项目、文件权限和外部系统状态，不能把它理解成所有系统状态的自动回滚。

脚本不会替你删除 session、project、history、skill、plugin、hook、command、agent 或 MCP 配置，也不会处理账号申诉、付款和网页端设置。

![Illustration for the Claude Account Guard verification workflow](docs/verification-workflow.png)

这张图是说明性插画，不是精确的执行时序图。实际顺序是：**审计 → 分类 → 确认 → 备份 → 处理 → 复验**。

<a id="data-boundaries"></a>

## 数据边界

- 「只读」指的是不写本工具的配置与状态，不等于机器上什么都没发生：审计会调用 `claude` 与 `npm` 读状态，这两个 CLI 自己会写东西——实测 Claude CLI 会把 `settings.json` 里的 `model` 别名迁移一次，npm 会在 `~/.npm/_logs` 留日志。因此 `--fix-auto` 的备份是「动手前那一刻」的状态，还原不了 CLI 自己做的迁移；要彻底干净的只读，得把 CLI 也放进隔离的 HOME 里跑，那会让登录态探测失去意义，所以这里选择如实说明而不是假装没有。
- 出口检查需要访问外部 IP/归属服务；这些服务只能看到本机发出的查询，不会收到项目文件。
- WebRTC 和 Intl 检查通过本机回环页面等待浏览器回传；不会把完整审计报告上传到远端。
- 代理后端会自动识别：mihomo 内核（Clash Verge / ClashX / Mihomo Party / FlClash）、sing-box、Surge、v2ray / Xray、只有系统代理、VPN 隧道。依赖代理的只有「绝不直连」与「DNS 泄漏」两行，其余各项与代理软件无关。自定义 secret 通过 `CLASH_SECRET` 传入，不要把它写进仓库。
- 脚本不会读取或保存 sudo 密码。Clash secret 从 `CLASH_SECRET` 读取；脚本调用本机 Clash API 时，会在 Python 内存中组装请求头，不把 secret 交给外部命令参数。仍请保护该环境变量，不要把它写入日志、脚本或仓库。
- 默认项目范围可以通过 `CLAUDE_GUARD_PROJECT_ROOTS` 指定；自定义 `CLAUDE_CONFIG_DIR` 只会报告，不纳入加固范围。
- 「系统级可清理量」少于 1 MB 不算待处理：Electron 的可再生缓存会被应用自己重建（实测清掉 43.8 MB，十几分钟后桌面版又长回 0.4 MB），为这点量常挂一个待处理没有意义。低于这个量时该行报通过，并写明还剩多少、为什么不动。

### 环境变量

```bash
export CLAUDE_GUARD_PROJECT_ROOTS="$HOME/code:$HOME/work"
export CLAUDE_GUARD_BROWSER_PROFILE="my-claude-profile"      # 可选：多资料时给「日常用 Claude 的那个」起个名字
export CLAUDE_GUARD_BROWSER_PROFILE_DIR="Profile 1"          # 可选：复核页开在哪个 Chrome 目录；不设就是默认资料
export CLAUDE_GUARD_EXPECTED_COUNTRY="US"           # 你声明这条线路应该落在哪一国
export CLAUDE_GUARD_EXPECTED_EXIT_IP="203.0.113.10" # 可选：把出口 IP 也一起钉死
```

`CLAUDE_GUARD_EXPECTED_COUNTRY` / `CLAUDE_GUARD_EXPECTED_EXIT_IP` 和对应的两个命令行参数是同一件事：声明你预期的出口。命令行优先，其次环境变量，最后是设过 `--save-audit` 之后记在 `~/.local/state/claude-guard/expected-exit.json` 里的那份；三处都没有，「预期出口是否符合」那一项就如实报「未测到」，脚本不会替你猜一个。只读审计不写这份记录。

如果本机 secret 不是默认值，请通过已有安全机制预先注入 `CLASH_SECRET` 环境变量；不要在命令行、shell 历史、脚本或仓库中写明文 secret。

<a id="verified"></a>

## 验证到什么程度

- **单测**：`python3 -m unittest discover -s tests` 目前 800+ 个用例（以 `Ran N tests` 那行为准），覆盖判据、结果表对齐、备份优先于写入、非 TTY 拒绝、结果表缺字段不得默认成干净、bash 3.2 的多字节变量回归、各客户端片段格式等。全部跑在合成夹具上，不碰真实配置、真实代理或真实浏览器权限。
- **CI**：macOS + Python 3.11/3.13，跑编译检查、全量单测、命令帮助、可复现打包（同一个 zip 两次构建必须字节一致）。
- **真机实测过**：本机 macOS 27.0 上验证过 mihomo / Clash Verge Rev 的规则与组判据、TUN 接管与 fake-ip、sing-box 真实例重载、浏览器复核页回传、2026-10-30 的单点组事故与修复、出口切换后的复验。
- **没有验证、也不打算假装验证的**：Windows 与 Linux、Chromium 之外的浏览器、用户手工装的每一条代理客户端版本、服务端风控的因果关系。
- 逐项证据等级和最后真机日期见 [`references/verification-status.md`](references/verification-status.md)；测试覆盖与不覆盖见 [`tests/README.md`](tests/README.md)。

<a id="install"></a>

## 安装到 Claude Code

把仓库放入本机的 skills 目录，并保持目录名与 `SKILL.md` frontmatter 的 `name` 完全一致：

```bash
git clone https://github.com/VioletScar-Hui/cc-tackle.git \
  ~/.claude/skills/cc-tackle
```

也可以只取运行时文件：`python3 tools/package_skill.py` 会打一个可复现的 zip（只含 `SKILL.md`、`scripts/`、`references/`）。安装后仍建议从普通终端先运行 `--audit`，再根据实际报告决定是否继续加固。

<a id="repository-map"></a>

## 目录结构

<details>
<summary><strong>展开仓库地图</strong></summary>

```text
.
├── SKILL.md                      # 判据、执行边界、agent 怎么调用（权威）
├── scripts/
│   ├── account_guard.py          # 主体：体检、加固、恢复、报告
│   ├── selfcheck.py              # 一键自检（七项串联）
│   ├── report_html.py            # 把结果渲染成自包含 HTML
│   ├── report_serve.py           # 带修复按钮的本地服务版
│   ├── net_guard.py              # 直连看门狗 + 出口锁定
│   ├── ip_judge.py               # 住宅 / 机房多源判定
│   ├── proxy_guard.py            # Claude 出口体检与单点组修复
│   ├── client_adapters.py        # 六种客户端片段生成
│   ├── residential_lock.py       # 住宅链路锁定的统一入口
│   └── residential/              # 吸收自 claude-residential-lock 的脚本
├── references/                   # 按主题拆开的判据与排错（见「文档导航」）
├── tests/                        # 合成夹具单测（见 tests/README.md）
├── tools/
│   └── package_skill.py          # 可复现打包
├── docs/
│   ├── decisions.md              # 决策记录（ADR）
│   ├── readme-hero.png
│   └── verification-workflow.png
├── CHANGELOG.md                  # 版本变化、已知限制与回滚
└── AGENTS.md                     # 维护约定（给 agent 和人工维护者）
```

</details>

## 本地测试与 CI

```bash
python3 -m unittest discover -s tests -v
python3 scripts/selfcheck.py --fast
python3 tools/package_skill.py --check
```

测试应在隔离夹具中运行；真实设备、真实代理、真实浏览器权限和管理员设置不属于单元测试的覆盖范围。每次推送到 `main`、提交 Pull Request 或手动运行时，GitHub Actions 会在 macOS 上用 Python 3.11 和 3.13 执行编译检查、单元测试、命令帮助检查和可复现打包。CI 只运行隔离的只读检查，不会执行真实的审计、加固、恢复或自检操作：[`查看 CI 工作流`](https://github.com/VioletScar-Hui/cc-tackle/actions/workflows/tests.yml)。

<a id="docs"></a>

## 文档导航

| 想知道 | 看 |
| --- | --- |
| agent 怎么调用、每项判据与执行边界 | [`SKILL.md`](SKILL.md) |
| 每项检查的证据等级与最后真机日期 | [`references/verification-status.md`](references/verification-status.md) |
| 检查项与原始文章/检测站的逐条对照 | [`references/article-mapping.md`](references/article-mapping.md) |
| 手工核对清单：curl、检测网站、系统面板 | [`references/manual-checklist.md`](references/manual-checklist.md) |
| 直连看门狗的判据、误杀边界与盲区 | [`references/net-guard.md`](references/net-guard.md) |
| 住宅链路锁定的安装与排错 | [`references/residential-lock.md`](references/residential-lock.md)、[`references/residential-pitfalls.md`](references/residential-pitfalls.md) |
| 六种客户端的组与规则片段、10-30 事故复盘 | [`references/client-adapters.md`](references/client-adapters.md)、[`references/proxy-guard.md`](references/proxy-guard.md) |
| 别家代理读什么、怎么重载 | [`references/proxy-backends.md`](references/proxy-backends.md) |
| WebRTC 判据与实测 | [`references/webrtc.md`](references/webrtc.md) |
| 报告页与可点修复的安全边界 | [`references/report-page.md`](references/report-page.md) |
| 历史判断背景、缓存与工作树边界 | [`references/maintenance-notes.md`](references/maintenance-notes.md) |
| 脚本清单与「什么时候用哪条」 | [`references/scripts-index.md`](references/scripts-index.md) |
| 为什么这么设计（决策记录） | [`docs/decisions.md`](docs/decisions.md) |
| 版本变化、已知限制与回滚 | [`CHANGELOG.md`](CHANGELOG.md) |
| 维护约定（给 agent 和人工维护者） | [`AGENTS.md`](AGENTS.md) |
| 测试覆盖与不覆盖 | [`tests/README.md`](tests/README.md) |
| 打一个可复现的 skill 包 | [`tools/package_skill.py`](tools/package_skill.py) |

<a id="references"></a>

## 参考来源

检查项的来源和逐条对照见 [`references/article-mapping.md`](references/article-mapping.md)。仓库保留引用材料，方便检查项变化时重新复核依据。

工具不会因为某一篇文章、某个检测站或某个 IP 归属服务而获得服务端结论；它只报告本机在当次运行中测到的证据。

<a id="license"></a>

## License

MIT © VioletScar-Hui
