# AGENTS.md —— 维护约定

给在本仓库里改代码或改文档的 agent 和人工维护者。它只说「怎么改这个仓库」；每项检查的判据、确认门与执行边界以 [`SKILL.md`](SKILL.md) 为准，这里不重复。

## 目标与依据

- 仓库交付一个 macOS 上的 Claude Code 环境体检 skill：默认只读体检，用户确认后备份、修改、复验，最后交一份 HTML 报告。
- 事实来源按这个顺序看：
  1. [`SKILL.md`](SKILL.md)：行为、判据与授权档位的唯一权威，且有用例守着行数上限；
  2. [`references/`](references/) 里的专题：判据细节、真机验证范围、踩坑记录；
  3. [`CHANGELOG.md`](CHANGELOG.md)：每个交付批次改了什么；
  4. [`docs/decisions.md`](docs/decisions.md)：为什么这样定、放弃了什么；
  5. [`references/verification-status.md`](references/verification-status.md)：每一项的证据等级与最后真机日期。
- 文档与代码矛盾时，先确认实际行为（读代码，或在本机跑一次只读审计），再决定改哪边；不要两边各改一半，也不要为了让文字自洽去改判据。
- 文档口吻是「实测到哪一步、哪一步没测」；不写「保证」「彻底」「最」这类营销词，不承诺免封，也不解释服务端风控。
- 新增或移动维护文档时，要一起更新 README「文档导航」表与 [`tests/test_docs.py`](tests/test_docs.py) 的 `REQUIRED_DOCS`，否则用例会红。

## Git 与交付

- 普通提交，不用 `--force`，不改写已推送的历史；一个提交只做一件事，不把无关改动混在一起。
- 提交信息写清「为什么」，不写 emoji；改判据的提交要把依据写进正文。
- 提交前跑全量单测（见「常用命令」）；改到 shell 脚本时再跑 `bash -n scripts/residential/*.sh`；改到文档时跑 `python3 -m unittest tests.test_docs -v` 自查链接、锚点与版本号。
- 推送后去 GitHub Actions 看 `Python 3.11` / `Python 3.13` 两个 job（都在 macOS runner 上）。CI 绿了才算交付；本地单测通过不等于 CI 通过。
- 不删测试、不放宽断言、不加 `skip` 来换绿。修 bug 的提交要带一条会先红的回归用例。
- 不提交打包产物：`dist/` 与 `*.zip` 已在 `.gitignore` 里。

## 实现与验证

证据分六档，从低到高；**低档不能替高档**。文档里写「验证过」必须能说清是哪一档、哪一天：

1. **文档已写**：`SKILL.md` / `references/` 里写了，只说明设计意图，不说明代码做了。
2. **代码已实现**：能看到函数与分支，不等于这条路径被走到过。
3. **单测或合成夹具**：默认证据；只证明判据逻辑与安全边界，不证明真实环境。
4. **CI 原生**：macOS runner 上 3.11 / 3.13 的编译、单测、打包校验与命令帮助检查；只证明隔离环境下可重复。
5. **用户真机实测**：只能由维护者在本机 macOS 上做，记录日期、命令与结果。范例见 [`references/proxy-backends.md`](references/proxy-backends.md)：mihomo 本机常态验证、sing-box 在 `/tmp` 起真实例、Surge / v2ray / Xray 只有夹具。
6. **实际操作授权**：`sudo` 两步、`--root-install`、`--fix-unverified`、`--restore` 与不可回滚清理必须每次向用户确认；代码里有 `--yes` 不等于本次已授权。

逐项证据等级与「明确不算证据的东西」见 [`references/verification-status.md`](references/verification-status.md)；新增或修改检查项时同步更新那张表。

## 平台约束

- **只在 macOS 上做真机验证**，文档与 CI 都不宣称 Windows / Linux。检测依赖 `networksetup`、`scutil`、`launchctl`、`log show`、`security`、`codesign`，别的平台没有等价实现。
- **Python**：本机 `/usr/bin/python3` 是 3.9.6。核心脚本只用标准库；不写 3.10+ 才有的语法（`match`、`zip(strict=)`、运行期的 `X | Y` 类型）。新文件沿用 `from __future__ import annotations`。CI 只跑 3.11 / 3.13，3.9 兼容靠这条约束加本机跑一遍兜底。
- **bash**：本机 `/bin/bash` 是 3.2.57。shell 脚本用 `set -u`；`$VAR` 后面紧跟全角字符必须写 `${VAR}`（吸收住宅锁定时踩过，`tests/test_residential_lock.py` 有回归）；不要引入 bash 4 的关联数组、`mapfile`。
- **测试不碰真实环境**：`tests/` 只用临时目录、假命令输出、假 fetcher；不读真实配置、不联网、不申请 sudo、不开浏览器。`CLAUDE_GUARD_*` 由 `setUpModule()` 摘除再放回。
- **测试数量不是证据**：几百个用例证明逻辑被守住，不证明这台机器真实环境如何，别拿用例数当能力覆盖。

## 权限与数据

- 仓库、日志、测试夹具里不允许出现：Clash secret、OAuth token、代理 URL 里的用户名密码、sudo 密码。secret 只从 `CLASH_SECRET` 环境变量进内存，不交给外部命令参数。
- 报告与终端输出里，凭据只记位置不读值；代理 URL 进报告前必须过 `redact_credentials`（先抹再截断）。
- 写「只读」时要说清它仍会调用 `claude` / `npm` 读状态，这两个 CLI 自己可能写迁移或日志；`--fix-auto` 的备份是动手前那一刻，不是安装时。
- 测试与脚本都不许动用户真实的 `~/.claude`、`~/Library`、LaunchAgents、Clash 配置或运行中的代理内核；需要真机验证的写进 `references/` 并标明日期。
- 本机 3080 的 DSH 宿主另有保护规则：不 kill、不重启、不用 `lsof` 找端口后杀进程。

## 常用命令

```bash
# 全量单测（提交前必跑）
python3 -m unittest discover -s tests -v

# 单个文件 / 单个类
python3 -m unittest tests.test_net_guard -v
python3 -m unittest tests.test_account_guard.TestFailClosedIsModeAware -v

# 一键自检（只读；--fast 跳过单测）
python3 scripts/selfcheck.py --fast

# 可复现打包校验（CI 同款；输出默认 dist/，已被 .gitignore 忽略）
python3 tools/package_skill.py --check

# 只读体检（会调 claude / npm 读状态，默认落一份 HTML 并打开）
python3 scripts/account_guard.py --audit

# 语法与帮助
python3 -m compileall -q scripts
python3 scripts/account_guard.py --help
```

文档类改动提交前额外跑一次 `python3 -m unittest tests.test_docs -v`：它检查必需文档、相对链接、README 锚点、`SKILL.md` 行数上限与版本号三处一致。
