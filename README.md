# claude-account-guard

> Claude Code 本机环境体检与自动清理 · macOS · Python 标准库 · 零依赖

一条命令把本机跟 Claude Code 有关的环境查一遍（25 项），再把其中可以安全清理的残留清掉（十类，幂等、可逆、改前先备份）。

**English** — claude-account-guard is a macOS command-line tool that audits and cleans the local environment around Claude Code: exit IP and ASN type, proxy residue, DNS and WebRTC leaks, IPv6 leaks, timezone layers, third-party endpoint leftovers in `settings.json`, telemetry switches, CLI signature integrity, stale permission entries and project-level junk. The audit is read-only; cleaning is idempotent, reversible, and always preceded by a backup.

```bash
git clone https://github.com/VioletScar-Hui/claude-account-guard.git
cd claude-account-guard && python3 scripts/account_guard.py --audit
```

## 什么时候用它

- 登录 Claude 之前，想确认本机环境是干净的
- 换了代理或节点之后，确认出口 IP、DNS、WebRTC 都没有泄漏
- 排查过 DNS 泄漏、WebRTC 泄漏，或者发现系统代理被反复回填
- 账号被风控或封禁之后，换环境之前做一次排查
- 日常巡检：时区、遥测开关、权限条目、可回收的缓存

它想回答的是这类问题：我的 Claude Code 环境干净吗？我的真实 IP 会不会泄漏给网站？我的出口是住宅还是机房？系统代理有没有残留？DNS 有没有被交给国内解析器？时区对不对？`settings.json` 里有没有指向第三方中转的端点？

## 它查哪 25 项

网络身份：出口 IP 与归属、出口的 ASN 类型（住宅还是机房）、出口是否和上一次一致、DNS 有没有落到国内解析器、WebRTC 在拿到摄像头权限后会不会露出真实 IP、IPv6 有没有绕过隧道、Claude 域名会不会走到直连。

代理链路：系统代理里有没有未启用却存着值的残留、终端与 shell 配置里的代理、npm 与 git 的全局代理、Clash 的规则模式与 DNS 配置。

账号环境：时区分层与那两道闸、浏览器 Intl 区域设置、浏览器资料有没有和日常混用、本机有没有多账号痕迹、钥匙串里的凭据条目、时区与出口与语言是否自相矛盾。

Claude Code 自身：`settings.json` 里有没有指向第三方中转的端点与凭据、遥测三键、有没有装第三方客户端、CLI 二进制有没有被改过（走官方签名验签，不是比版本号）。

环境卫生：项目级 `.claude` 的规模、过期的工作树注册、系统级可回收的体积、项目级 `settings.json` 里已经失效的权限条目、代码有没有落在本地 Git。

## 快速开始：只读体检

```bash
python3 scripts/account_guard.py --audit
```

只读，不改任何文件。出一张 25 项的表，末尾给出完整 JSON 报告的路径。第一次用建议就停在这一步。

一键自检：

```bash
python3 scripts/selfcheck.py
```

把语法编译、单元测试、LaunchAgent、Clash 内核状态、系统代理四开关、完整环境体检串成七项，跑完出两张表。加 `--fast` 跳过单测（约 20 秒）。

## 完整加固（会改状态）

```bash
python3 scripts/account_guard.py
```

需要真实终端，先列出「最终执行清单」，输入 `CONFIRM` 才开始，整个过程只输一次 sudo 密码。

自动清的十类，不再逐项问：

1. 系统代理残留——只清 `Enabled: No` 却存着值的那些，正在启用的整条跳过
2. shell 配置（`.zshrc` / `.zprofile` / `.profile`）里的代理行，只删命中那几行
3. npm 与 git 的全局代理
4. Claude Code `settings.json` 的 `env` 里指向别处的端点、凭据、代理变量
5. Clash 的 DNS 里出现国内解析器、或没开 `respect-rules` 时改回来并重载内核
6. 浏览器 Intl 区域设置（默认语言不是大陆简体时直接判「无需改动」，不写）
7. 系统级可再生体积：CLI 被取代的旧版本、桌面版内置旧副本、Electron 缓存
8. 项目级 `settings.json` 里已证明失效的权限条目（一次性 PID、别的机器路径、已消失路径）
9. 项目级 `.claude` 里的 `.DS_Store` 与 `__pycache__`
10. 过期的工作树注册——只划掉 `.git/worktrees` 里的登记记录，一个工作树都不删

仍会问你的三件，因为它们有副作用：遥测三键、`claude-safe` 包装脚本、两项要 root 的（关 IPv6、关定位服务里的「设定时区」）。

只报告不代改：`~/.npmrc` 里的代理、`brew config` 报出的代理、当前进程环境里的代理与端点变量、偏危险的长期授权、属于其它工具的端点（`~/.dsh`、`~/.codex`）。

绝不动：session、project、history、skill、plugin、hook、command、agent、MCP 配置等受保护数据。钥匙串只读列条目，不做任何删除。

## 人工清单

```bash
python3 scripts/account_guard.py --manual
```

23 条本机没有接口、脚本替不了的行动项，分七组，每条带出处和能直接照抄的点击路径。只打印，不写任何东西。

## 其它参数

```bash
python3 scripts/account_guard.py --json          # 只读体检的 JSON
python3 scripts/account_guard.py --commands      # 手工核对命令清单
python3 scripts/account_guard.py --webrtc        # 单独跑 WebRTC 探测
python3 scripts/account_guard.py --check-media   # 起本地页面，等浏览器回传摄像头/麦克风权限结论
python3 scripts/account_guard.py --check-locale  # 同上，复核浏览器 Intl 区域设置
```

## 两个环境变量

- `CLAUDE_GUARD_PROJECT_ROOTS` —— 项目根目录，冒号分隔，例如 `$HOME/code`。不给会跳过「项目级 .claude 规模」与「过期工作树注册」两项。
- `CLASH_SECRET` —— Clash 的 external-controller secret，默认 `set-your-secret`（Clash Verge 的默认占位值）。改过 secret 就设这个变量，否则 Clash 相关的几项读不到。

## 退出码

- `0` 正常结束
- `1` 在 `CONFIRM` 那一步取消，或脚本自身报错
- `2` 拒绝执行（非真实 TTY，或在 Claude Code 里跑）或中途停止
- `3` 加固完成，但受保护文件被外部改动过

## 备份与回滚

第一个写操作就是备份，落在 `~/ClaudeGuardBackups/guard-<时间戳>/`。任何一项备份失败都直接中止，不会在没有备份的情况下继续改——对 root 文件尤其重要，因为不可读路径的 `exists()` 返回 `False`，会把「备份不了」静默变成「不用备份」。

清完会复验；另有受保护文件比对，发现被连带改动会返回退出码 3 并说明改了哪些、备份在哪。浏览器区域设置那项的回滚是一条 `defaults delete com.google.Chrome AppleLanguages`。

## 常见问题

**它会删我的会话、项目文件或聊天记录吗？**
不会。它没有任何一处删除 session、project、history、skill、plugin、hook、command、agent 或 MCP 配置的代码。项目级 `.claude` 里实测 99% 的体积是 git 工作树，属真实代码，脚本只划掉指向已消失路径的登记记录，一个工作树都不删。

**它需要 root 吗？**
只有两件可选的事需要：关 IPv6、关定位服务里的「设定时区」。不做这两件，其余全部功能不需要提权。要提权时会走终端原生的 sudo 提示，脚本不读取也不保存密码，整个流程只问一次。

**没装 Clash，或者用的是别的代理，能用吗？**
能。「绝不直连」「DNS 泄漏」「系统代理残留」这几项会报未检测到，这不是失败，其余检查照常。检测出口 IP 与 ASN 类型不依赖任何特定代理软件。

**支持 Windows 或 Linux 吗？**
目前只做 macOS。用到的 `networksetup`、`scutil`、`security`、`plutil`、`defaults`、`codesign` 都是 macOS 专有命令。

**它和 claude-cleanup 有什么区别？**
`claude-cleanup` 管的是删缓存、日志、会话记录那类体积清理。这个管的是环境：网络出口、代理残留、泄漏面、时区、端点配置、权限条目。两者不重叠，可以一起用。它也沿用了 `claude-cleanup` 的安全约定：只读审计永远安全，写操作要真实 TTY 加一次最终确认，备份是第一个写操作，失败即停。

**跑完显示「未检测到」是失败吗？**
不是。没装 Clash、没给终端完全磁盘访问权限、或者当前模型通道拿不到浏览器内部状态时，对应几项会如实报「未检测到」，脚本不会把它当成通过。

**它会往外发我的数据吗？**
脚本只会向 `api.ipify.org`、`ip-api.com`、`ipinfo.io` 各查一次本机出口 IP 与归属（这是「你的出口是谁」唯一能问出来的办法），向本地 Clash 的 unix socket 读配置，以及在你跑 `--check-media` / `--check-locale` 时起一个本机回环端口等你用浏览器打开。除此之外不上传任何文件，不回传任何检查结果。文档里提到的 browserleaks、ping0、ippure、ipleak 那些检测站，都要你自己在浏览器里打开，脚本不代你访问。

**账号被封能靠这个防住吗？**
不能保证。封禁判定在服务端，本地看不到原因。这个工具能做的是把环境侧可控的变量收敛到一致、干净、不泄漏，并且把该人工做的事列清楚。检查项的取材见下方「参考来源」。

## 装进 Claude Code

把这个仓库整个放到 `~/.claude/skills/` 下面即可，`SKILL.md` 的 frontmatter 里 `name` 必须和目录名逐字符相等。

```bash
git clone https://github.com/VioletScar-Hui/claude-account-guard.git ~/.claude/skills/claude-account-guard
```

## 目录结构

```
.
├── SKILL.md                    # 每一项查什么、判据是什么、为什么这么判
├── scripts/
│   ├── account_guard.py        # 主体
│   └── selfcheck.py            # 七项自检
├── tests/
│   └── test_account_guard.py   # 413 个用例
└── references/
    └── article-mapping.md      # 每一项对应到参考文章哪一节
```

单测：

```bash
python3 tests/test_account_guard.py
```

## 参考来源

检查项的取材与逐条对照见 `references/article-mapping.md`。主要来源是一篇公开长文：

**《你的 Claude 账号是怎么被封的》**
https://x.com/AYi_AInotes/status/2106639522586829094

原文自己引用的三篇材料也一并留着，免得日后只剩结论、丢了出处：

- 陈大黄复盘贴 https://x.com/realchendahuang/status/2104455272614035947
- 实践哥复盘贴 https://x.com/MinLiBuilds/status/2105890192108536029 —— 「内容也别碰红线」那一条的出处（§4）
- wangray《半年稳定的配置》 https://x.com/wangray/status/2105658146685608265

原文文末自带两条推广（住宅代理服务商 `equaldcdn.com/?ref=…`、新加坡卡 `sg.starryblu.com/x/…`），原文自己标了广告，没有收进来，也没有作为任何检查项的依据。

检查项里用到的检测网站，逐条标了对应的文章小节，见 `SKILL.md` 的「手工核对清单与检测网站」一节；`python3 scripts/account_guard.py --commands` 会把同一份清单打出来。

## License

MIT
