<div align="center">
  <h1>CC tackle</h1>
  <p><strong>Claude Code 本机环境体检与可控清理</strong></p>
  <p>macOS · 核心检测使用 Python 标准库 · 证据优先 · 改动可复核</p>
  <p>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-e8a181?style=flat-square" alt="MIT license" /></a>
    <img src="https://img.shields.io/badge/platform-macOS-111827?style=flat-square&amp;logo=apple&amp;logoColor=white" alt="macOS" />
    <img src="https://img.shields.io/badge/runtime-Python%203-111827?style=flat-square&amp;logo=python&amp;logoColor=white" alt="Python 3" />
    <img src="https://img.shields.io/badge/core-Python%20stdlib-111827?style=flat-square" alt="Core uses Python standard library" />
  </p>
  <p>
    <a href="#quick-start">快速开始</a> ·
    <a href="#features">功能概览</a> ·
    <a href="#side-effects">清理与副作用</a> ·
    <a href="#data-boundaries">数据边界</a> ·
    <a href="#install">安装</a>
  </p>
</div>

![Claude Account Guard: a warm pixel-art scene for inspecting and verifying a local Claude Code environment](docs/readme-hero.png)

> **用途边界**：这是一个面向 macOS 本机的环境检查与维护工具。它帮助你发现网络出口、代理残留、时区、浏览器测量和 Claude Code 本地配置中的可见问题；它不能解释服务端风控原因，也不能保证账号可用或通过任何服务的审核。

CC tackle 把检测、证据、备份和复验放在同一条命令链里。默认先看清楚环境，再决定是否处理。普通 `--audit` 默认不写审计报告、出口历史或缓存；需要保存时显式使用 `--audit --save-audit`。完整加固会先展示执行清单，只有确认后才锁定目标、备份和修改。

<a id="features"></a>

## 功能概览

<table>
  <tr>
    <td width="33%"><strong>网络身份</strong><br /><br />检查出口 IP 与 ASN 类型、出口变化、DNS、WebRTC、IPv6 和 Claude 域名的路由结果，并把“未测到”和“异常”分开。</td>
    <td width="33%"><strong>代理链路</strong><br /><br />查看系统代理、shell、npm、git 与代理软件配置中的残留或不一致项，保留原始证据供复核。</td>
    <td width="33%"><strong>Claude 配置</strong><br /><br />检查 <code>settings.json</code> 的端点、凭据和代理变量，以及遥测开关、CLI 签名和第三方客户端痕迹。</td>
  </tr>
  <tr>
    <td><strong>账号环境</strong><br /><br />核对时区层级、浏览器 Intl 区域、浏览器资料复用、多账号痕迹和钥匙串条目。</td>
    <td><strong>环境卫生</strong><br /><br />定位项目级 <code>.claude</code> 噪声、失效权限条目、过期工作树登记和可回收的系统体积。</td>
    <td><strong>人工清单</strong><br /><br />对脚本无法代替的浏览器权限、系统设置和外部检测，给出带来源的人工核对路径。</td>
  </tr>
</table>

<a id="quick-start"></a>

## 快速开始

### 一次跑完：先问一屏 → 体检 → 修 → 复检 → 一份 HTML

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

### 想分两步看的时候（可选）

一次跑完是上面那条命令。如果更习惯先只读看一眼、再决定动不动手：

```bash
python3 scripts/account_guard.py --audit --preflight  # 前测：只读，体检前先问那三件事
python3 scripts/account_guard.py                      # 修：列清单 → CONFIRM → 备份 → 改 → 复检 → HTML
```

这条路径要跑两次，因为第一步是纯只读的；`--preflight` 只是让第一遍也把那三项测到，不至于体检完还是 `·`。第二条命令本身是完整流水线：动手前体检、备份、改动、复检、前后对照，最后落一份 HTML 并打开。只想单独留一份快照（没有前后对照）时用 `--report`，它也不顺带写 JSON 与出口历史；在 CONFIRM 处取消时，加过 `--report` 才会给出「改动前」那一份。

### Claude 直连看门狗（可选，默认不装）

体检只是在「看」，这个脚本负责「拦」：每 5 秒看一遍 Claude 相关进程的对外 TCP 连接，
发现它绕过了隧道（路由落在 `en0` 这类物理接口，而不是 `utun`）就 SIGKILL 那个进程，
并把 pid、进程路径、目标地址、出口接口写进日志。

```bash
python3 scripts/net_guard.py --once --dry-run   # 先看一眼判据，只看不杀
python3 scripts/net_guard.py                    # 前台跑，每 5 秒一次，发现直连就杀
python3 scripts/net_guard.py --install --yes    # 装成 LaunchAgent 常驻（每 5 秒）
python3 scripts/net_guard.py --status           # 在不在跑
python3 scripts/net_guard.py --uninstall        # 卸载
```

它**不会**把「Clash 规则选了 DIRECT」当成直连——那种流量仍然走 TUN。它抓的是「绕过了隧道」。
判据、误杀边界与已知盲区见 [references/net-guard.md](references/net-guard.md)。

### 只读审计入口

```bash
git clone https://github.com/VioletScar-Hui/cc-tackle.git
cd cc-tackle
python3 scripts/account_guard.py --audit
```

普通审计只在终端输出状态表，不自动保存报告、出口历史或缓存。需要保存审计结果时显式加上 `--save-audit`；如果你只想看机器可读结果，可以使用：

```bash
python3 scripts/account_guard.py --audit --json
```

保存审计结果：

```bash
python3 scripts/account_guard.py --audit --save-audit
```

如果你有明确的线路目标，可以把目标国家和出口 IP 一起写进审计：

```bash
python3 scripts/account_guard.py --audit \
  --expected-country US \
  --expected-exit-ip 203.0.113.10
```

这两个值必须由你自己指定；脚本不会从历史记录或当前实测结果自动猜目标。没有指定目标时，只能报告“未声明目标”；如果实测出口不符，先处理线路，脚本不会自动修改 Chrome 语言。

### 一键自检

```bash
python3 scripts/selfcheck.py
python3 scripts/selfcheck.py --fast
```

自检会串联技能文件、Python 编译、单元测试、守护脚本、Clash 状态、系统代理和完整环境审计。`--fast` 用于跳过耗时较长的单元测试。

### 报告页：静态 HTML 与可点修复

完整加固与 `--fix-auto` 都在收尾**生成一份**自包含的 HTML 报告，落在 `~/ClaudeGuardBackups/report-<时间戳>.html`——那一页就是前后对照：顶上是「修复前 → 修复后」的分数，下面逐项列出两次真读数；`--fix-auto` 没有可修项或中途取消时同样给页面，只是注明「这一轮没有改动」或「已取消」；完整加固取消时只有加过 `--report` 才出页面。只读自检不出页面（一次流程只留最后那一份），只读运行想要快照就显式加 `--report`。分数是**加分制**：27 个基础项合计 100 分（每项 100/27，通过拿满、待处理拿一半、未通过 0 分），「没测到」也按 0 分计，分母固定 27 项，不折算成剩下几项的比例；「登录方式」不在这 27 项里，是额外加分项，通过再加 5 分，所以页面满分 105。页面里另有一节「常驻任务」：用户域 LaunchAgent 的清单——哪些在跑、哪些设了开机自启、哪些被禁用或上次退码非 0。它只是清单，不计分，也不改任何 plist。整页不引用任何外部资源（没有 CDN、没有 web font、没有 JS），页面上的数字全部来自报告本身——判定与终端输出同源，都是 `build_summary`。

```bash
python3 scripts/report_html.py --open              # 用最新那份报告重渲染
python3 scripts/report_html.py <报告.json> --out ~/Desktop
```

想让它**点着修**，用本地服务模式：

```bash
python3 scripts/report_serve.py
```

体检完起一个只绑 `127.0.0.1` 的服务并打开页面。能自动修的项右边多一个按钮，点一下执行、页面刷新、顶部写明这次做了什么；顶部另有「修复全部可自动修的项」和「重新体检」，页脚「结束本地服务」，空闲 30 分钟自动退出。安全边界：端口随机、URL 带一次性令牌、POST 需自定义头、动作白名单，不带令牌一律 404。

别家代理（sing-box / v2ray / Surge）的 DNS 配置改动不在按钮里，也不默认执行：改完能不能生效取决于那个软件自己重启，脚本验不了，要用 `--fix-unverified` 显式开启，且会先备份。

按钮只出现在本来就敢自动做的项上：系统代理残留、shell/npm/git 代理、settings.json 端点与凭据、Clash DNS、浏览器 Intl、系统级可清理量、settings 失效权限、项目级垃圾与失效工作树注册。需要人拿主意的（遥测开关、IPv6、定位服务）和必须人工的（手机时区、支付、浏览器隔离）不出按钮。

删掉的旧版本与缓存没法像配置文件那样回滚，所以每次清理都会在 `~/ClaudeGuardBackups/cleanup-<时间戳>.json` 留一份账本，写明删了哪些路径、各多大。

### 专项检查与清单

```bash
python3 scripts/account_guard.py --manual       # 打印人工核对清单
python3 scripts/account_guard.py --commands     # 打印检测网站与命令
python3 scripts/account_guard.py --audit --webrtc       # 在审计中附加 WebRTC 探测
python3 scripts/account_guard.py --audit --verify-browser # 脚本自己开复核页，一次跑完不留未测到
python3 scripts/account_guard.py --install-webrtc-limiter # 下载 WebRTC Network Limiter 扩展包并打开商店页
python3 scripts/account_guard.py --check-media           # 单独跑：开复核页并等回传媒体权限
python3 scripts/account_guard.py --check-locale          # 单独跑：开复核页并等回传 Intl 区域
```

`--install-webrtc-limiter` 只下载与报告，不改本机配置，所以不需要 TTY：它把扩展包从商店的官方分发接口下到 `~/.local/state/claude-guard/extensions/`，核对签名公钥算出来的扩展 ID，并报出每个 Chrome 资料里装没装。**安装那一下仍然只能你自己点**：Chrome 在 macOS 上不接受脚本代装扩展。

`--audit --webrtc` 会启动临时浏览器资料进行探测，并在结束后清理；它不会修改日常浏览器资料。`--check-media` 和 `--check-locale` 会在本机保存回传缓存，并且会自己把复核页打开——想指定开在哪个 Chrome 资料（就是你日常用 Claude 的那个）就设 `CLAUDE_GUARD_BROWSER_PROFILE_DIR`，例如 `Profile 1`。脚本自己打开的复核页写进缓存的 `openedBy` 是 `script`，这两项才判结论；别人手工打开的记 `user`，只当参考、不作通过证据。
WebRTC 专项探测会直接启动本机可用的 Chromium；其余核心检测使用 Python 标准库。

### 需要修改本机状态时

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

状态表会区分：

- `✓` 已满足当前判据
- `!` 需要处理或人工复核
- `✗` 检测到异常
- `·` 当前条件下没有测到

“未测到”表示没有足够证据完成该项检查，不等于通过，也不等于失败。

<a id="side-effects"></a>

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

- 对系统代理残留、shell 代理行、npm/git 全局代理和 `settings.json` 中明确命中的端点/凭据/代理变量，脚本只改命中的键或行，并在修改后复验。长期 token（`CLAUDE_CODE_OAUTH_TOKEN`）是官方凭据、不是残留，任何一条清理路径都不会删它。进程环境里的代理变量（例如 Claude 从带代理的终端启动时继承的那几条）按「只报告」处理：只要 shell 配置、npm/git、`~/.npmrc` 里没有，这一项就算干净。
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

<a id="install"></a>

## 安装到 Claude Code

把仓库放入本机的 skills 目录，并保持目录名与 `SKILL.md` frontmatter 的 `name` 完全一致：

```bash
git clone https://github.com/VioletScar-Hui/cc-tackle.git \
  ~/.claude/skills/cc-tackle
```

安装后仍建议从普通终端先运行 `--audit`，再根据实际报告决定是否继续加固。

<a id="repository-map"></a>

## 目录结构

<details>
<summary><strong>展开仓库地图</strong></summary>

```text
.
├── SKILL.md                    # 检查项、判据和执行边界
├── scripts/
│   ├── account_guard.py        # 主体脚本
│   ├── selfcheck.py            # 一键自检
│   ├── report_html.py          # 把结果渲染成自包含的 HTML 报告
│   └── report_serve.py         # 带修复按钮的本地服务版
├── tests/
│   └── test_account_guard.py   # 单元测试与隔离夹具
├── references/
│   ├── article-mapping.md      # 检查项与参考来源的映射
│   ├── report-page.md          # 报告页与可点修复的边界说明
│   └── webrtc.md               # WebRTC 判据与实测说明
└── docs/
    ├── readme-hero.png         # README 顶部插图
    └── verification-workflow.png # 工作流说明插画
```

</details>

### 本地测试

```bash
python3 tests/test_account_guard.py
```

测试应在隔离夹具中运行；真实设备、真实代理、真实浏览器权限和管理员设置不属于单元测试的覆盖范围。

每次推送到 `main`、提交 Pull Request 或手动运行时，GitHub Actions 会在 macOS 上用 Python 3.11 和 3.13 执行编译检查、单元测试和命令帮助检查。CI 只运行隔离的只读检查，不会执行真实的审计、加固、恢复或自检操作：[`查看 CI 工作流`](https://github.com/VioletScar-Hui/cc-tackle/actions/workflows/tests.yml)。

<a id="references"></a>

## 参考来源

检查项的来源和逐条对照见 [`references/article-mapping.md`](references/article-mapping.md)。仓库保留引用材料，方便检查项变化时重新复核依据。

工具不会因为某一篇文章、某个检测站或某个 IP 归属服务而获得服务端结论；它只报告本机在当次运行中测到的证据。

<a id="license"></a>

## License

MIT © VioletScar-Hui
