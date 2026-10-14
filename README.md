<div align="center">
  <h1>claude-account-guard</h1>
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

`claude-account-guard` 把检测、证据、备份和复验放在同一条命令链里。默认先看清楚环境，再决定是否处理。普通 `--audit` 默认不写审计报告、出口历史或缓存；需要保存时显式使用 `--audit --save-audit`。完整加固会先展示执行清单，只有确认后才锁定目标、备份和修改。

<a id="features"></a>

## 功能概览

<table>
  <tr>
    <td width="33%"><strong>网络身份</strong><br /><br />检查出口 IP 与 ASN 类型、出口变化、DNS、WebRTC、IPv6 和 Claude 域名的路由结果，并把“未测到”和“异常”分开。</td>
    <td width="33%"><strong>代理链路</strong><br /><br />查看系统代理、shell、npm、git 与 Clash 配置中的残留或不一致项，保留原始证据供复核。</td>
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

### 只读审计入口

```bash
git clone https://github.com/VioletScar-Hui/claude-account-guard.git
cd claude-account-guard
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

每跑完一次都会生成一份自包含的 HTML 报告，落在 `~/ClaudeGuardBackups/report-<时间戳>.html`。整页不引用任何外部资源（没有 CDN、没有 web font、没有 JS），页面上的数字全部来自报告本身——判定与终端输出同源，都是 `build_summary`。

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

删掉的旧版本与缓存没法像配置文件那样回滚，所以每次清理都会在 `~/ClaudeGuardBackups/cleanup-<时间戳>.json` 留一份账本，写明删了哪些路径、各多大。

### 专项检查与清单

```bash
python3 scripts/account_guard.py --manual       # 打印人工核对清单
python3 scripts/account_guard.py --commands     # 打印检测网站与命令
python3 scripts/account_guard.py --audit --webrtc # 在审计中附加 WebRTC 探测
python3 scripts/account_guard.py --check-media  # 等待浏览器回传媒体权限
python3 scripts/account_guard.py --check-locale # 等待浏览器回传 Intl 区域
```

`--audit --webrtc` 会启动临时浏览器资料进行探测，并在结束后清理；它不会修改日常浏览器资料。`--check-media` 和 `--check-locale` 会在本机保存回传缓存。
WebRTC 专项探测会直接启动本机可用的 Chromium；其余核心检测使用 Python 标准库。

### 需要修改本机状态时

```bash
python3 scripts/account_guard.py
```

完整加固需要真实终端。脚本会先展示最终执行清单，只有在你明确输入 `CONFIRM` 后才锁定目标、创建备份和修改状态。Clash DNS、Chrome Intl、旧版本与缓存、失效权限、过期 worktree 和项目垃圾等项目会逐项询问，默认选择否；涉及管理员权限的操作仍会单独询问。不要在正在使用 Claude Code 的进程里发起会修改本机状态的操作。

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
| 代理链路 | 系统代理、shell 配置、npm/git 全局代理、Clash 模式和 DNS |
| 账号环境 | 时区层级、浏览器 Intl、浏览器资料复用、多账号痕迹、钥匙串条目 |
| Claude Code | `settings.json` 端点与凭据、遥测开关、第三方客户端、CLI 签名完整性 |
| 环境卫生 | 项目级 `.claude`、失效权限、过期工作树登记、可回收系统体积 |

浏览器缓存型结果只在缓存不超过 24 小时、且与显式设置的 `CLAUDE_GUARD_BROWSER_PROFILE` 匹配时作为参考；否则标记为未测到或要求重新测量。这个资料名由用户声明，脚本无法独立证明打开复核页面的浏览器资料身份，所以仅凭匹配缓存也不会标记为通过。

状态表会区分：

- `✓` 已满足当前判据
- `!` 需要处理或人工复核
- `✗` 检测到异常
- `·` 当前条件下没有测到

“未测到”表示没有足够证据完成该项检查，不等于通过，也不等于失败。

<a id="side-effects"></a>

## 清理与副作用

安全边界按动作拆分：

- 对系统代理残留、shell 代理行、npm/git 全局代理和 `settings.json` 中明确命中的端点/凭据/代理变量，脚本只改命中的键或行，并在修改后复验。
- 主模式在 `CONFIRM` 前不创建运行锁、备份或修改目标；确认后先创建运行锁，并在任何改动前为受支持的文件目标完成备份；系统设置和不可逆清理另列人工边界。
- Clash DNS、Chrome Intl、旧版本与缓存、失效权限、过期 worktree 和项目垃圾等改动会逐项列出并默认选择否，可能影响后续网络、浏览器或本机空间。
- 遥测开关、IPv6、定位服务时区等操作可能带来功能或系统权限影响，需要单独决定。
- 只有确认并开始加固后，备份目录才会保存本次执行可恢复的输入与变更信息；恢复能力取决于具体项目、文件权限和外部系统状态，不能把它理解成所有系统状态的自动回滚。

脚本不会替你删除 session、project、history、skill、plugin、hook、command、agent 或 MCP 配置，也不会处理账号申诉、付款和网页端设置。

![Illustration for the Claude Account Guard verification workflow](docs/verification-workflow.png)

这张图是说明性插画，不是精确的执行时序图。实际顺序是：**审计 → 分类 → 确认 → 备份 → 处理 → 复验**。

<a id="data-boundaries"></a>

## 数据边界

- 出口检查需要访问外部 IP/归属服务；这些服务只能看到本机发出的查询，不会收到项目文件。
- WebRTC 和 Intl 检查通过本机回环页面等待浏览器回传；不会把完整审计报告上传到远端。
- Clash 读取本机配置或 socket；自定义 secret 通过 `CLASH_SECRET` 传入，不要把它写进仓库。
- 脚本不会读取或保存 sudo 密码。Clash secret 从 `CLASH_SECRET` 读取；脚本调用本机 Clash API 时，会在 Python 内存中组装请求头，不把 secret 交给外部命令参数。仍请保护该环境变量，不要把它写入日志、脚本或仓库。
- 默认项目范围可以通过 `CLAUDE_GUARD_PROJECT_ROOTS` 指定；自定义 `CLAUDE_CONFIG_DIR` 只会报告，不纳入加固范围。
- 「系统级可清理量」少于 1 MB 不算待处理：Electron 的可再生缓存会被应用自己重建（实测清掉 43.8 MB，十几分钟后桌面版又长回 0.4 MB），为这点量常挂一个待处理没有意义。低于这个量时该行报通过，并写明还剩多少、为什么不动。

### 环境变量

```bash
export CLAUDE_GUARD_PROJECT_ROOTS="$HOME/code:$HOME/work"
export CLAUDE_GUARD_BROWSER_PROFILE="my-claude-profile"
export CLAUDE_GUARD_EXPECTED_COUNTRY="US"           # 你声明这条线路应该落在哪一国
export CLAUDE_GUARD_EXPECTED_EXIT_IP="203.0.113.10" # 可选：把出口 IP 也一起钉死
```

`CLAUDE_GUARD_EXPECTED_COUNTRY` / `CLAUDE_GUARD_EXPECTED_EXIT_IP` 和对应的两个命令行参数是同一件事：声明你预期的出口。命令行优先，其次环境变量；两处都没给，「预期出口是否符合」那一项就如实报「未测到」，脚本不会替你猜一个。

如果本机 secret 不是默认值，请通过已有安全机制预先注入 `CLASH_SECRET` 环境变量；不要在命令行、shell 历史、脚本或仓库中写明文 secret。

<a id="install"></a>

## 安装到 Claude Code

把仓库放入本机的 skills 目录，并保持目录名与 `SKILL.md` frontmatter 的 `name` 完全一致：

```bash
git clone https://github.com/VioletScar-Hui/claude-account-guard.git \
  ~/.claude/skills/claude-account-guard
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

每次推送到 `main`、提交 Pull Request 或手动运行时，GitHub Actions 会在 macOS 上用 Python 3.11 和 3.13 执行编译检查、单元测试和命令帮助检查。CI 只运行隔离的只读检查，不会执行真实的审计、加固、恢复或自检操作：[`查看 CI 工作流`](https://github.com/VioletScar-Hui/claude-account-guard/actions/workflows/tests.yml)。

<a id="references"></a>

## 参考来源

检查项的来源和逐条对照见 [`references/article-mapping.md`](references/article-mapping.md)。仓库保留引用材料，方便检查项变化时重新复核依据。

工具不会因为某一篇文章、某个检测站或某个 IP 归属服务而获得服务端结论；它只报告本机在当次运行中测到的证据。

<a id="license"></a>

## License

MIT © VioletScar-Hui
