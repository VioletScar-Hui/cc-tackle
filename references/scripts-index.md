# 脚本索引：哪个入口、扫什么、主要参数

本文件只是索引，不是规范。每个脚本的行为、判据、确认门和执行边界以 [`SKILL.md`](../SKILL.md) 对应章节为准；判据细节、真机验证范围与踩坑见同目录的专题文档。这里只回答「要跑哪条命令、它大致做什么」。

## 入口脚本（`scripts/`）

| 脚本 | 一行说明 | 主要参数 |
| --- | --- | --- |
| [`account_guard.py`](../scripts/account_guard.py) | 主体：28 项只读体检、确认后加固、显式恢复、HTML 报告 | `--audit`、`--audit --json`、`--audit --save-audit`、`--preflight`、`--fix-auto`、`--yes`（只配 `--fix-auto`）、`--verify-browser`、`--webrtc`、`--check-media`、`--check-locale`、`--install-webrtc-limiter`、`--expected-country`、`--expected-exit-ip`、`--fix-unverified`、`--manual`、`--commands`、`--report`（兼容写法）、`--restore`、`--restore-preview`、`--restore-item` |
| [`selfcheck.py`](../scripts/selfcheck.py) | 七项串联自检：技能文件 → 编译 → 单测 → 守护脚本 → Clash → 系统代理 → 完整体检；只读，不出 HTML | `--fast`（跳过单测）、`--no-audit`（跳过体检）、`--no-browser`（不弹复核页，浏览器两项改为未测到） |
| [`report_html.py`](../scripts/report_html.py) | 把审计 JSON 重渲染成自包含 HTML；页面数字来自 `build_summary`，不在这里另写判定 | `[报告.json]`（默认取最新）、`--out`、`--open` |
| [`report_serve.py`](../scripts/report_serve.py) | 回环服务 + 页面上的修复按钮；URL 带令牌、POST 需自定义头、动作白名单；空闲自动退出 | `--no-open`、`--timeout`（默认 1800 秒）、`--roots` |
| [`net_guard.py`](../scripts/net_guard.py) | 直连看门狗：每 5 秒扫 Claude 进程的 TCP 连接，路由落物理网卡就 SIGKILL；附带出口锁定告警 | `--once`、`--dry-run`、`--interval`（默认 5）、`--install --yes`、`--uninstall`、`--status`、`--init-lock --expected-ip`、`--check-ip`、`--no-residential`、`--proxy`、`--lock-interval`（默认 30） |
| [`ip_judge.py`](../scripts/ip_judge.py) | 单个出口 IP 的住宅 / 机房判定：多源交叉、关键词兜底、判不准 `UNKNOWN`、缓存一周 | `<IP>`、`--json`、`--batch`（stdin 逐行）、`--no-cache` |
| [`proxy_guard.py`](../scripts/proxy_guard.py) | Claude 出口体检：规则目标组、成员数、选中节点是否可用；单点组告警；组内切换 / 补成员 / 生成片段 | `--check`（默认）、`--json`、`--fix`、`--fix-members`、`--nodes`、`--emit <client>`、`--clients`、`--policy`（默认组名 `Claude`）、`--no-reload` |
| [`client_adapters.py`](../scripts/client_adapters.py) | 六种客户端的「组 + 规则」模板（库模块，没有独立 CLI，由 `proxy_guard.py --emit` 调用） | 无 |
| [`residential_lock.py`](../scripts/residential_lock.py) | 住宅链路锁定的统一入口，把 `scripts/residential/` 下散落的脚本映射成动作 | `--status`、`--init`、`--install`、`--uninstall`、`--check`、`--discover`、`--selfcheck`、`--root-install`、`--root-uninstall`、`--dry-run` |

## 住宅链路锁定（`scripts/residential/`）

由 [`references/residential-lock.md`](residential-lock.md) 整包吸收而来；入口是上面的 `residential_lock.py`，一般不用手工敲这些文件名。

| 文件 | 一行说明 |
| --- | --- |
| [`guard.sh`](../scripts/residential/guard.sh) | 用户级自愈核心：校验内核里有没有 Claude 规则与 UDP 封堵，偏离就通过 `PUT /configs` 热载修复 |
| [`guard-install.sh`](../scripts/residential/guard-install.sh) | 安装 / 卸载用户级 LaunchAgent（`WatchPaths` + 30 秒轮询） |
| [`expand.py`](../scripts/residential/expand.py) | 把 Verge 的 GUI 配置展开成可热载的 mihomo payload，并校验规则引用的目标真实存在 |
| [`merge-gen.py`](../scripts/residential/merge-gen.py) | 从参数文件生成 Verge 的 `Merge.yaml` 增强规则 |
| [`discover.sh`](../scripts/residential/discover.sh) | 逐个节点切上去测真实出口，多源判定哪个是住宅节点；探测期间临时停用户级 guard |
| [`judge-ip.py`](../scripts/residential/judge-ip.py) | `discover.sh` 用的单 IP 判定（与 `scripts/ip_judge.py` 同源逻辑） |
| [`install.sh`](../scripts/residential/install.sh) | 交互生成参数文件 `~/Library/Scripts/claude-residential.env`，已有配置先备份 |
| [`selfcheck.sh`](../scripts/residential/selfcheck.sh) | 真发流量验结果：出口 IP、UDP / STUN 泄漏、绑物理网卡直连是否被挡；`--no-asn` 可跳过归属查询 |
| [`verify.sh`](../scripts/residential/verify.sh) | 部署后的全量验收（整套防线在不在）；`--quick` 跳过逐域名追踪 |
| [`harden-root.sh`](../scripts/residential/harden-root.sh) | root 层：pf 锚点规则 + DNS 守卫 + 看门狗，装 LaunchDaemon，需 sudo，幂等 |
| [`dns-guard.py`](../scripts/residential/dns-guard.py) | 代理不健康时对 Claude 域名返回 NXDOMAIN；由 LaunchDaemon 以 root 拉起 |
| [`pf-update.sh`](../scripts/residential/pf-update.sh) | 只替换 `claude-residential` 这一段 pf anchor，避免整表重载刷掉别家动态规则 |
| [`lib-common.sh`](../scripts/residential/lib-common.sh) | 公共库（读参数文件、封装 mihomo API、`cr_judge_ip`），被其它脚本 source，不单独执行 |
| [`claude-residential.env.example`](../scripts/residential/claude-residential.env.example) | 参数模板，每一项都写了查法 |

## 什么时候用哪条

- 先看整体环境、不做任何改动：`python3 scripts/account_guard.py --audit`（判定口径见 `SKILL.md`「跑完看什么：结果总表」）。
- 一条命令体检 + 修四类残留 + 复检 + 一份 HTML：`--preflight --fix-auto`；agent 没有 TTY 时用 `--audit --verify-browser --webrtc --fix-auto --yes`，但 `--yes` 必须先拿到用户明确同意。
- 只要机器可读结果：`--audit --json`；要多留一份审计 JSON：`--audit --save-audit`。
- 想在页面上点着修：`python3 scripts/report_serve.py`（边界见 [`references/report-page.md`](report-page.md)）。
- 要恢复某次改动：先 `--restore <备份目录> --restore-preview` 看能恢复什么，确认后再 `--restore`。
- 换订阅 / 换线路后先查 Claude 组有没有单点、目标组对不对：`python3 scripts/proxy_guard.py --check`。
- 想拦住绕过隧道的直连：先 `net_guard.py --once --dry-run` 看判据，再 `--install --yes` 常驻（判据见 [`references/net-guard.md`](net-guard.md)）。
- 想盯住出口 IP 漂移：`net_guard.py --init-lock --expected-ip <住宅出口IP>`，它只告警不改配置。
- 要规则自愈 / pf / DNS 层：从 `residential_lock.py --status` 起手，只有 `--root-*` 需要 sudo（见 [`references/residential-lock.md`](residential-lock.md)）。
- 怀疑某个节点不是住宅：`residential_lock.py --discover`，或直接 `ip_judge.py <IP>`。
- 提交前自查：`python3 scripts/selfcheck.py --fast`；发布前打包校验：`python3 tools/package_skill.py --check`（参数见 [`AGENTS.md`](../AGENTS.md)「常用命令」）。

## 共用环境变量

| 变量 | 作用 |
| --- | --- |
| `CLAUDE_GUARD_PROJECT_ROOTS` | 项目根列表（冒号分隔），决定 A9 / A14 / A24 扫哪些目录；不设时按 git 仓 / 家目录候选推断 |
| `CLAUDE_GUARD_BROWSER_PROFILE` / `CLAUDE_GUARD_BROWSER_PROFILE_DIR` | 复核页开在哪个 Chrome 资料，以及缓存 `profileScope` 的匹配依据 |
| `CLAUDE_GUARD_EXPECTED_COUNTRY` / `CLAUDE_GUARD_EXPECTED_EXIT_IP` | 预期出口声明；命令行优先，其次是环境变量，最后是 `--save-audit` 记下的那份 |
| `CLAUDE_GUARD_NO_REPORT` / `CLAUDE_GUARD_NO_OPEN` | 不落 / 不打开 HTML 报告，脚本化与 CI 用 |
| `CLASH_SECRET` | Clash 控制接口的 secret；只在内存里组装请求头，不交给外部命令参数 |
| `CLAUDE_CONFIG_DIR` | 自定义 Claude 配置目录；审计只报告、完整加固拒绝纳入范围 |
| `CLAUDE_RESIDENTIAL_ENV` | 住宅链路锁定参数文件的替代路径（默认 `~/Library/Scripts/claude-residential.env`） |

环境变量的完整语义、优先级与不设时的行为，以 [`SKILL.md`](../SKILL.md) 对应章节和 [`README.md`](../README.md)「环境变量」为准。
