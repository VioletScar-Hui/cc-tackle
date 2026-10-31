# 更新记录

本文件按交付批次记录变化，格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。版本号与 `SKILL.md` frontmatter 里的 `metadata.version` 保持一致；`1.0.4` 及更早的版本号是事后回填的，依据见文末「版本号说明」。

## [1.1.0] - 2026-10-31

本批次。代码部分见提交 `e20141b` 与本批次的 A12 判据修正（见 Fixed），文档部分随本批次一起整理（README、SKILL.md、本文件与维护文档）。

### Added

- **Claude 出口体检**：新增 `scripts/proxy_guard.py`。`--check` 读 mihomo 控制接口，报出 Claude 规则指向哪个组、组里有几个成员、选中的节点是否可用；只有一个成员的 `select` 组直接报「单点组」。`--fix` 在组内切到可用成员（不改配置），`--fix-members --nodes` 给 Clash Verge Rev 的组文件补入口线路并热载（原文件备份成 `.bak-<日期>`），`--emit <client>` 生成 mihomo / sing-box / Surge / Shadowrocket 片段。
- **客户端适配模板**：新增 `scripts/client_adapters.py`，六种客户端的「组 + 规则」模板默认列出多条入口线路；配套文档 `references/client-adapters.md`（每种片段贴在哪、探测能力对照、2026-10-30 单点组事故复盘）与 `references/proxy-guard.md`（判定规则、`--fix-members` 改了什么）。
- **可复现打包**：新增 `tools/package_skill.py`，只打运行时文件（`SKILL.md`、`scripts/`、`references/`），`--check` 连建两遍比对 sha256；CI 增加打包校验步骤。
- **维护文档**：新增 `AGENTS.md`、`CHANGELOG.md`、`docs/decisions.md`、`tests/README.md`、`references/scripts-index.md`，README 与 SKILL.md 相应增加导航。
- **文档完整性用例**：新增 `tests/test_docs.py`，守仓库地图、相对链接、README 锚点、`SKILL.md` 行数上限与版本号三处一致。

### Changed

- `scripts/net_guard.py --status` 增加 Claude 出口体检的入口提示。
- `SKILL.md` 增加「按需加载」「脚本索引」「授权档位」「汇报格式」四节；手工核对清单移到 `references/manual-checklist.md`，逐项证据等级移到 `references/verification-status.md`。
- README 重排为「它能做什么 / 几条底线 / 怎么工作 / 分级授权 / 快速开始 / 检测范围 / 文档导航」，补版本徽章与 CI 徽章。

### Fixed

- 「绝不直连」（A12）不再要求 Claude 组只有一个成员。原来的判据和 10-30 单点组修复自相矛盾：补到 4 条入口线路后，这一行反而报 ✗，等于让 agent 把刚修好的配置再改回单点。现在只查三项：组类型是 `select`、成员不少于一个、成员里没有 `DIRECT` / `REJECT`；单入口作为提示写进报告，抗单点由 `proxy_guard.py --check` 判。回归用例：多成员 select 通过、成员含 `DIRECT` 判 ✗、空组判 ✗。

## [1.0.4] - 2026-10-29

### Added

- 吸收 claude-residential-lock 整套脚本到 `scripts/residential/`（Clash 规则自愈、root pf 防火墙、代理不健康时 Claude 域名 NXDOMAIN 的 DNS 守卫），新增统一入口 `scripts/residential_lock.py`，动作映射为 `--status`、`--init`、`--install`、`--uninstall`、`--check`、`--discover`、`--selfcheck`、`--root-install`、`--root-uninstall`。
- 补两份专题文档 `references/residential-lock.md`、`references/residential-pitfalls.md`，以及入口回归用例 `tests/test_residential_lock.py`（脚本还在不在、`--root-*` 是否带 sudo、`--dry-run` 是否透传）。
- 报告页「本 skill 的常驻程序」卡片补上每组的职责清单（网络防护 / 报告服务 / 体检与清理），用短句列出，替代原来只写 pid 与日志年龄的做法。

### Changed

- 报告页的常驻保护范围区块改成带标题框、浅色背景、五条短句和两列卡片，长段灰色文字不再挤在三列网格里。

### Fixed

- bash 3.2 下 `$VAR` 紧跟全角括号会被当成变量名的一部分，`set -u` 直接报 unbound variable：吸收时统一改成 `${VAR}`，并加回归用例。
- `launchctl` 偶发输出非 UTF-8 字节时 `text=True` 解码失败：子进程输出改用 `errors="replace"`。

## [1.0.3] - 2026-10-28

### Added

- 出口锁定：新增 `scripts/ip_judge.py` 做住宅 / 机房多源判定（ip-api、ipinfo、ipwho.is 交叉，AS / 组织名关键词兜底，判不准返回 `UNKNOWN`，结果缓存一周）；`scripts/net_guard.py` 增加 `--init-lock --expected-ip` 与 `--check-ip`，常驻后每 30 秒查一次真实出口，漂移、判成机房或判不准就写日志、发通知。它只告警，不改 Clash 配置。
- 报告页的常驻程序卡片显示看门狗进程运行时长与最后一次扫描时间，卡死的循环不再和正常进程长得一样。

### Changed

- `--audit` 现在每次运行都落一份 HTML 报告并打开；脚本与 CI 用 `CLAUDE_GUARD_NO_REPORT=1` 关掉，`--report` 降为兼容写法。
- 报告页去掉「下一步」区块，改为要求 agent 在回复里说下一步；`SKILL.md` 补「用户只发一条『修到 100 分并常驻』」时的一次性执行链，并写明不要为装看门狗再问一轮。

### Fixed

- `--audit --save-audit` 写了页面却不打开、`open` 失败被静默吞掉、非交互 `--fix-auto` 缺 `--yes` 时既不修也不出页面：三处都改成给出页面并说明原因。

## [1.0.2] - 2026-10-20

### Added

- 一次性运行：`--preflight` 在体检前问清浏览器复核、WebRTC 探测与预期出口；`--fix-auto` 当场修四类有备份、改完能复验的残留；`--yes` 只配合 `--fix-auto`，给没有 TTY 的 agent 用。
- 直连看门狗 `scripts/net_guard.py`：每 5 秒扫 Claude 相关进程的对外 TCP 连接，路由落在物理网卡而不是 `utun` / `tun` 就 SIGKILL；判据、误杀边界与已知盲区写在 `references/net-guard.md`。
- 报告页新增「本 skill 的常驻程序」只读清单：在跑没在跑、最后退出码、是否 `RunAtLoad` / `StartInterval` / 被禁用；只列清单，不进 28 行、不评分、不写 plist。

### Changed

- 浏览器资料范围改为从复核页实际打开的资料推导（显式名字 → 资料目录 → `default`）；项目本地 Git 检查改用同一套三级兜底；扫完没发现的项报通过而不是「未知」。
- 进程环境里继承来的代理变量按「环境」只报告，不再因为它把终端残留那一行判成待处理。

### Fixed

- 自动清理误删 `CLAUDE_CODE_OAUTH_TOKEN`：键名匹配用了 `re.search("auth_token")`，会把 `oauth_token` 一起命中；改成按完整键名匹配，并从 shell 匹配器里去掉。
- 报告页只列本 skill 自己装的 LaunchAgent，不再把整机 agent 倒出来；`log show` 超时问题有缓存就跳过。
- 修同一轮暴露的文档与行为不一致：检查项计数 25/26 改成 28、`selfcheck` 补传 `--webrtc`、README 对取消后是否出页面的说法、`~/.npmrc` 被 `npm config delete` 重写这件事写清楚。

## [1.0.1] - 2026-10-16

### Added

- 登录凭据检查（A29）：读 `claude auth status`，并在环境变量、`settings.json` 的 `env`、shell 配置里找 `CLAUDE_CODE_OAUTH_TOKEN` 的**位置**（只记位置，不读值）；长期 token 报绿，网页授权登录或未登录报待处理并指向 `claude setup-token`。人工清单补第八组，合计 24 项 8 组。
- 代理后端分派（A28）：认出 mihomo、sing-box、Surge、v2ray / Xray、只有系统代理、VPN 隧道与「认得出进程但格式不认识」；新增后端能力矩阵与三行判定，别家代理的 DNS 修复放到 `--fix-unverified` 之后；重载按各家官方方式做（sing-box SIGHUP、Surge `POST /v1/profiles/reload`、v2ray / Xray 绝不发 SIGHUP）。
- `--report` 只落 HTML 页面；在 `CONFIRM` 处取消时也交一份，注明是改动前状态。
- 浏览器自动复核 `--verify-browser`，以及 WebRTC Network Limiter 扩展包下载 `--install-webrtc-limiter`（下载、核对签名公钥算出的扩展 ID、报每个 Chrome 资料装没装；安装那一下仍要用户自己点）。

### Changed

- 项目改名 CC tackle（目录名与 `SKILL.md` 的 `name` 保持一致）。
- 报告分改成加分制：27 个基础项合计 100 分（每项 100/27），「登录方式」是额外加分项，通过再加 5 分，页面满分 105。
- `selfcheck` 不再出报告页；加固收尾只留一份前后对照的报告。加固确认后先走 `[0/6]` 管理员授权，一次密码覆盖所有 root 步骤，并顺带把定位库读进 24 小时缓存。

### Fixed

- `SKILL.md` 两处检查项计数 27 改成 28。
- 测试把 36 KB 的夹具报告写进真实备份目录、用真实出口 IP 做夹具：改用临时目录与文档保留地址。

## [1.0.0] - 2026-10-14

### Added

- HTML 报告页 `scripts/report_html.py`：自包含、零外部资源、零 JS，页面数字全部来自 `build_summary`；本地可点修复服务 `scripts/report_serve.py`：只绑回环、URL 一次性令牌、POST 自定义头、动作白名单；删除操作留账本 `cleanup-<时间戳>.json`。
- macOS CI：在 `macos-latest` 上用 Python 3.11 / 3.13 跑编译检查、单元测试与命令帮助检查。
- 预期出口检查与可验证的显式恢复；Clash 控制端点自动发现（Clash Verge 2.5 把 socket 移进特权服务运行目录）。

### Changed

- 备份先于改动：报告页上的修复按钮原本先改后备份、相对路径的失效权限条目备份落空、目标已被别人清掉时被误报为失败；三处都改成「先解析路径 → 备份 → 改动 → 复验」，目标已达标按「无需改动」报。
- loopback 服务启动不做反向 DNS，测试等本地服务就绪再请求。

### Fixed

- WebRTC 探测的要求修正（0 候选只能报「结论不可用」，不能报「没有泄漏」）。
- `selfcheck` 汇总行的技能文件计数修正。
- Claude Guard 的安全边界与 README 配图修正。

## 初始版本（2026-10-10～10-12）

### Added

- 初始提交：Claude Code 环境检测与自动清理——只读审计、确认后清理系统代理残留 / shell 代理行 / npm 与 git 全局代理 / `settings.json` 里的端点与凭据变量，写操作备份优先、逐项复验。
- 一键自检 `scripts/selfcheck.py`：脚本按自身位置定位，项目根三级兜底；修 A9 时区标识符误判与 A14 仓根漏判。
- 吸收 CCBaga 的四处做法：三个本地复核服务加一次性令牌（端口随机不等于有鉴权）、加固流程加 `O_CREAT|O_EXCL` 并发锁、CLI 完整性增强（安装方式 / 链接形状 / `--version` / 版本目录断言，调 CLI 一律带 `DISABLE_AUTOUPDATER=1`）、代理 URL 进报告前脱敏。另修掉 Chrome 重启判定的假阳性。

### Changed

- README 与 SKILL.md 面向技能目录和生成式检索优化可发现性；补全四篇原始材料链接，并注明未收录的两条推广。

## 已知限制

- 只支持 macOS。检测依赖 `networksetup`、`scutil`、`launchctl`、`log show`、`security` 等系统命令，Windows / Linux 没有对应实现，文档也不宣称支持。
- 真机验证只到本机能做的范围：mihomo 本机常态验证，sing-box 在 `/tmp` 起真实例验证，Surge / v2ray / Xray 只有按官方文档写的夹具；逐项证据等级与最后真机日期见 [`references/verification-status.md`](references/verification-status.md)。
- 浏览器 Intl 与媒体权限依赖本机回环复核页回传，要同时满足 24 小时 freshness、`profileScope` 匹配与 `openedBy=script`；没开复核页就是「未测到」（`·`），不当作通过。
- 「只读」指不写本工具的配置与状态，但审计仍会调用 `claude` 与 `npm` 读状态，这两个 CLI 自己可能写迁移或日志；`--fix-auto` 的备份是动手前那一刻的状态。
- 系统代理、Chrome Intl、IPv6、系统级缓存、旧版本与 Git worktree 注册没有完整文件快照，`--restore` 不能当成这些系统状态的一键还原。
- `--fix-auto` 只覆盖四类残留；其余待处理项要么要 root，要么要用户决定，要么只能人工。

## 回滚

- 改动前会为受支持的文件目标建立带 `manifest.json` 的备份，落在 `~/ClaudeGuardBackups/guard-<时间戳>/`。
- 先预览再恢复：`python3 scripts/account_guard.py --restore "$HOME/ClaudeGuardBackups/guard-<时间戳>" --restore-preview`；确认后去掉 `--restore-preview`；只恢复单个文件用 `--restore-item`。
- 恢复只处理能证明属于本轮改动、且之后没有被其它进程改过的文件；旧版 v1 备份、清单损坏、文件漂移时拒绝恢复。
- 删掉的旧版本与缓存不可逆，只能对照 `cleanup-<时间戳>.json` 账本；系统代理、Chrome Intl、IPv6 没有文件快照，要按输出人工复核；恢复了 Clash 配置不会自动重载内核，需在 Clash Verge 里手动重载后再审计一次。

## 版本号说明

- 当前发布版本以 `SKILL.md` 的 `metadata.version`、README 徽章与本文件三处为准，发布前保持一致。
- `1.0.4` 及更早的版本号是事后按提交日期回填的，仓库此前没有 tag。它们表示那几天合并进来的一组提交，不是当时发布过的包；逐条原始记录以 `git log --date=short --pretty='%h %ad %s'` 为准。
