# 决策记录

这里记录已采纳的设计决定：为什么这样做、放弃了什么、代价是什么。判据与操作步骤的权威在 [`SKILL.md`](../SKILL.md)，实现细节在各 [`references/`](../references/) 专题里；本文件不复述操作步骤，只回答「为什么这样定」。

格式：`## ADR-编号 · 标题`，正文依次是状态、背景、决定、后果，末尾列出证据出处。

## ADR-001 · 默认只读审计，HTML 报告是默认交付

**状态**：已采纳（2026-10）
**背景**：终端里的状态表新人看不出下一步；早期只有 `--save-audit` / `--report` 这类显式参数才出页面，跑完 `--audit` 的人停在表前就没有下文。
**决定**：`--audit` 也落一份自包含 HTML 并打开，但不同时写审计 JSON、出口历史或缓存（要 JSON 显式加 `--save-audit`）；脚本化场景用 `CLAUDE_GUARD_NO_REPORT=1` 关掉页面；`--fix-auto` 无论修了、没得修还是在确认处取消，都交一份页面。
**后果**：「只读」的措辞要精确到「不写本工具的状态，但仍会调 `claude` / `npm` 读状态」；报告是证据不是说明书，下一步命令仍由 agent 在回复里直接说。

证据：[`SKILL.md`](../SKILL.md)「安全约定」「结果页：HTML 报告」、[`references/report-page.md`](../references/report-page.md)。

## ADR-002 · 写操作：确认 → 锁 → 备份 → 改 → 复验

**状态**：已采纳（2026-10）
**背景**：报告页上的修复按钮被实测出「先改后备份」；两次运行交错会让回滚凭据和实际状态对不上。
**决定**：`CONFIRM` 之前不建运行锁、不建备份、不改任何状态；确认后原子建锁（`O_CREAT|O_EXCL`，锁里记 pid，持有进程已消失的遗留锁可接管），先完成备份再改，备份失败即停；每项改完回读断言；恢复必须显式指定备份目录并逐项验证归属。
**后果**：备份是「动手前那一刻」的状态，CLI 自己写下的迁移或日志还原不了；系统代理、Chrome Intl、IPv6、系统缓存这类没有完整文件快照的动作另列人工边界。

证据：[`SKILL.md`](../SKILL.md)「回滚」「显式恢复」、[`references/report-page.md`](../references/report-page.md)、[`tests/README.md`](../tests/README.md)。

## ADR-003 · 「绝不直连」判据按代理模式分派，组必须是 select

**状态**：已采纳（2026-10）
**背景**：第一版把「必须 global」写死，于是把 `mode=rule` 本身判成故障——而 rule 恰恰是国内直连、国外走代理所必需的模式；这条 bug 后来专门加了回归用例。
**决定**：`global` 模式看 GLOBAL 是否指向 Claude 专用组；`rule` 模式看 Claude 域名的显式规则与兜底会不会落到 `DIRECT`；两种模式都要求组是 `select`，`fallback` 即使只剩一个成员也不等效（它仍可能切走）。成员这一侧只查「不能混进 `DIRECT` / `REJECT`」——多入口的 select 组不会自己切走，入口数不影响「绝不直连」。
**后果**：判据按模式分别解释，报告要列出具体不成立的原因；「会不会漏」与「扛不扛得住单点」是两个问题，后者由 `scripts/proxy_guard.py` 单独判。2026-10-30 的单点组事故一度把这条判据推成「必须只有一个成员」，结果修好事故后的 4 入口配置反而被判 ✗——成员数因此被明确移出这一项。

证据：[`SKILL.md`](../SKILL.md)「『绝不直连』怎么判」、[`tests/test_account_guard.py`](../tests/test_account_guard.py) 中 `TestFailClosedIsModeAware`。

## ADR-004 · 出口锁定只告警，不改用户订阅

**状态**：已采纳（2026-10）
**背景**：自动改 Clash 配置或切节点，很容易把用户的订阅规则和分流搞乱；改配置应该由人决定。
**决定**：`scripts/net_guard.py --init-lock --expected-ip` 只记录期望出口与查询代理；常驻后每 30 秒查一次真实出口，IP 变了、判成机房、或判不准（`UNKNOWN`）时写日志并发系统通知。判定用多源交叉（ip-api / ipinfo / ipwho.is），判不准不猜，结果缓存一周。
**后果**：想「自愈」只能用住宅链路锁定那一套（用户级 `guard.sh` 加 root 层 pf / DNS 守卫），且必须由用户显式安装；看门狗永远不替用户改订阅。

证据：[`references/net-guard.md`](../references/net-guard.md)「出口锁定」、[`references/residential-lock.md`](../references/residential-lock.md)。

## ADR-005 · 默认不申请 sudo，root 操作一次性授权或拆成独立入口

**状态**：已采纳（2026-10）
**背景**：agent 与 CI 没有真实 TTY，逐项 sudo 必然卡住；普通加固里真正需要 root 的只有 IPv6 与定位「设定时区」两步。
**决定**：敲完 `CONFIRM` 先走 `[0/6]` 管理员授权，一次密码覆盖本轮所有 root 步骤，过期只补问一次；拿不到授权就跳过那两步、其余照做，不因授权失败让整轮失败。更重的 root 层（pf 防火墙 + DNS 守卫）拆成 `scripts/residential_lock.py --root-install`，默认不装。
**后果**：没有 TTY 的环境里，root 步骤作为唯一的手工步骤交给用户；测试与 CI 永远不安装 root 层，也不执行 pf / LaunchDaemon 操作。

证据：[`SKILL.md`](../SKILL.md)「想分两步看的时候」与管理员授权段落、[`references/residential-lock.md`](../references/residential-lock.md)、[`tests/test_residential_lock.py`](../tests/test_residential_lock.py)。

## ADR-006 · 核心只用 Python 标准库，浏览器能力按实探测

**状态**：已采纳（2026-10）
**背景**：本机 `/usr/bin/python3` 是 3.9.6，用户不该为一次体检安装一堆第三方包；浏览器侧能做什么取决于本机 Chrome，不能假设。
**决定**：核心检测与报告只用标准库；WebRTC 探测才启动本机 Chromium，命令行 `--dump-dom` 这条路实测不可靠，0 个候选只能报「结论不可用」而不是「没有泄漏」；`pyyaml` 只有住宅锁定的 `expand.py` 需要，缺了明确报缺。
**后果**：3.9 兼容是硬约束，不写 3.10+ 才有的语法；CI 跑 3.11 / 3.13，本机还要用 `/usr/bin/python3` 跑一遍兜底。

证据：[`README.md`](../README.md)「验证到什么程度」、[`references/webrtc.md`](../references/webrtc.md)、[`references/residential-lock.md`](../references/residential-lock.md)「前置条件」。

## ADR-007 · 凭据不进 argv、不进报告

**状态**：已采纳（2026-10）
**背景**：拼 `Authorization` 请求头交给外部命令、或把 secret 放进命令参数，secret 会出现在进程参数里；`proxy=http://user:pass@host:port` 这种代理 URL 也很常见。
**决定**：Clash secret 从 `CLASH_SECRET` 环境变量读，请求头在 Python 内存里组装，不交给 curl；进报告前统一过 `redact_credentials`（先抹再截断）；OAuth token 只记「写在哪个文件 / 哪个变量」，绝不读值。
**后果**：环境变量本身仍要用户自己保护，不能写进仓库、日志或脚本；报告与终端输出里只出现键名和位置。

证据：[`SKILL.md`](../SKILL.md)「手工核对清单与检测网站」的 Clash 入口段、[`tests/test_account_guard.py`](../tests/test_account_guard.py) 中 `TestRedactCredentials`。

## ADR-008 · 常驻程序只列清单，不计分

**状态**：已采纳（2026-10）
**背景**：把整机 LaunchAgent 都倒到报告里，会让人以为这个 skill 在管别的软件；把常驻状态算进分数，也会让「体检」和「装没装保护」两件事混在一起。
**决定**：只列本 skill 自己装出来的后台任务，按功能分组（网络防护 / 报告服务 / 体检与清理），显示在不在跑、有没有设开机自启、有没有被禁用；不进 28 行、不计分、不写 plist、不启动任何东西。
**后果**：看门狗与住宅锁定是可选运行时保护，不是体检结论；「在跑」只证明 launchd 认为它活着，所以页面还显示 uptime 与最后一次扫描时间。

证据：[`references/report-page.md`](../references/report-page.md)、[`SKILL.md`](../SKILL.md)「直连看门狗」、[`tests/test_resident.py`](../tests/test_resident.py)。

## ADR-009 · 浏览器证据只认脚本打开的复核页

**状态**：已采纳（2026-10）
**背景**：回环服务端口随机不等于有鉴权——本机任何进程都能往随机端口投一份「摄像头已拒绝」，把没测过的项报成通过；反过来，别人手工打开的页面也不能证明是你要测的那个浏览器资料。
**决定**：复核页 URL 带 24 字节随机令牌，不知道令牌取页面与投结果一律 404；结果要同时满足 24 小时 freshness、`profileScope` 与这次实际打开的资料一致、且缓存里的 `openedBy=script`，才出结论；手工打开的记 `user`，只当参考。
**后果**：全新用户不声明资料也能拿到结论（默认资料），但脚本只能证明「哪个资料打开了这个页面」，不能证明「这个资料就是你的日常账号」，所以页面上要把依据摊开写。

证据：[`SKILL.md`](../SKILL.md)「浏览器 Intl 区域设置」、[`references/webrtc.md`](../references/webrtc.md)、[`references/report-page.md`](../references/report-page.md)。

## ADR-010 · 缺字段一律「未测到」，读不到不等于「已关」

**状态**：已采纳（2026-10）
**背景**：`build_summary` 曾经用 `report.get(k) or {}` 取值，某项没跑出来时字段缺失会被判成干净；非 root 读不到定位库时，也曾把「读不到」当成「已关」。
**决定**：加 `missing()` 守卫，缺字段显示 `·`；读不到的闸门标待处理并给 UI 路径；空报告的正确结果是全部未测到、0 项已解决，并有用例钉住。
**后果**：「未测到」既不算通过也不算失败，报告分数会因此下降，这是刻意的；写文档时不能把「脚本没测到」说成「环境是干净的」。

证据：[`SKILL.md`](../SKILL.md)「跑完看什么：结果总表」两条口径、[`references/verification-status.md`](../references/verification-status.md)、[`references/report-page.md`](../references/report-page.md)。

## ADR-011 · 只声明 macOS，不宣称 Windows / Linux

**状态**：已采纳（2026-10）
**背景**：检测项依赖 macOS 独有命令（`networksetup`、`scutil`、`launchctl`、`log show`、`security`、`codesign` 等），别的平台没有等价实现。
**决定**：README、SKILL.md 与 CI 都只写 macOS；真机验证只在本机做；不写「支持 Windows / Linux」，也不写「理论可行但没做」这类模糊话。
**后果**：其它平台用户不能按文档运行；CI 在 macOS runner 上跑的也是合成夹具，绿了不等于这台机器真机通过，验收仍以 `--audit` 的实测输出和人工复核为准。

证据：[`README.md`](../README.md)「用途边界」、[`references/verification-status.md`](../references/verification-status.md)、[`.github/workflows/tests.yml`](../.github/workflows/tests.yml)。

## ADR-012 · 住宅链路锁定整包吸收，root 层单独入口

**状态**：已采纳（2026-10）
**背景**：claude-residential-lock 原本是一套独立脚本，拷贝时容易只搬包装壳、丢脚本；它的 root 部分会改 `/etc/pf.conf` 并装两个 LaunchDaemon，风险与用户级自愈不是一回事。
**决定**：脚本原样放在 `scripts/residential/`，`scripts/residential_lock.py` 只做统一入口（动作到命令的映射、状态汇总）；用户级自愈免 sudo；root 层单独 `--root-install`，改 pf 前先备份，卸载有 `--root-uninstall`；测试与 CI 不装任何一层。
**后果**：root 层必须由用户显式确认；非 Verge 环境（裸 mihomo、非 Verge 配置目录）要按 [`references/residential-pitfalls.md`](../references/residential-pitfalls.md) 调整，不能照搬默认路径。

证据：[`SKILL.md`](../SKILL.md)「住宅链路锁定」、[`references/residential-lock.md`](../references/residential-lock.md)、[`tests/test_residential_lock.py`](../tests/test_residential_lock.py)。
