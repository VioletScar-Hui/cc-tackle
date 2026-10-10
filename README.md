# claude-account-guard

给 Claude Code 做本机环境体检，再把其中可以安全清理的残留清掉。

macOS + Python 3.9 以上，纯标准库，没有第三方依赖。清理动作幂等、可逆、动手前先备份。

```bash
git clone https://github.com/VioletScar-Hui/claude-account-guard.git
cd claude-account-guard && python3 scripts/account_guard.py --audit
```

## 它查什么

25 项，分五类。

网络身份：出口 IP 与归属、出口的 ASN 类型（住宅还是机房）、出口是否和上一次一致、DNS 有没有交给国内解析器、WebRTC 授权后会不会露出真实 IP、IPv6 有没有绕过隧道。

代理链路：系统代理里有没有未启用却存着值的残留、终端与 shell 配置和 npm / git 里的代理、Clash 的规则模式与 DNS 解析器、Claude 域名有没有落到直连。

账号环境：时区分层与那两道闸、浏览器 Intl 区域设置、浏览器资料有没有和日常混用、本机有没有多账号痕迹、钥匙串里的凭据条目。

Claude Code 自身：`settings.json` 里有没有指向第三方中转的端点与凭据、遥测三键、有没有装第三方客户端、CLI 二进制有没有被改过（走官方签名验签，不是比版本号）。

环境卫生：项目级 `.claude` 的规模、过期的工作树注册、系统级可回收的体积、项目级 `settings.json` 里已经失效的权限条目。

## 先跑只读体检

```bash
python3 scripts/account_guard.py --audit
```

只读，不改任何文件。会出一张 25 项的表，末尾给出完整 JSON 报告的路径。第一次用建议就停在这一步。

一键自检：

```bash
python3 scripts/selfcheck.py
```

它把语法编译、单元测试、LaunchAgent、Clash 内核状态、系统代理四开关、完整环境体检串成七项，跑完出两张表。加 `--fast` 跳过单测（约 20 秒）。

## 完整加固（会改状态）

```bash
python3 scripts/account_guard.py
```

需要真实终端，会先列出「最终执行清单」，输入 `CONFIRM` 才开始，整个过程只输一次 sudo 密码。

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

## 外部条件

Clash Verge Rev 开着 TUN 模式时，「绝不直连」「DNS 泄漏」「系统代理残留」这几项才有内容可查；没有 Clash 的机器会报未检测到，不是失败。

读 Chrome 的资料文件需要给终端「完全磁盘访问」权限，不给也能跑，只是浏览器资料那两项读不到。

WebRTC 与浏览器区域设置这两项的浏览器侧复核要你自己打开它打印的本地地址，脚本拿不到浏览器内部状态。

## 退出码

- `0` 正常结束
- `1` 在 `CONFIRM` 那一步取消，或脚本自身报错
- `2` 拒绝执行（非真实 TTY，或在 Claude Code 里跑）或中途停止
- `3` 加固完成，但受保护文件被外部改动过

## 备份与回滚

第一个写操作就是备份，落在 `~/ClaudeGuardBackups/guard-<时间戳>/`。任何一项备份失败都直接中止，不会在没有备份的情况下继续改——对 root 文件尤其重要，因为不可读路径的 `exists()` 返回 `False`，会把「备份不了」静默变成「不用备份」。

清完会复验；另有受保护文件比对，发现被连带改动会返回退出码 3 并说明改了哪些、备份在哪。浏览器区域设置那项的回滚是一条 `defaults delete com.google.Chrome AppleLanguages`。

## 装进 Claude Code

把仓库目录整个放到 `~/.claude/skills/` 下面即可，`SKILL.md` 的 frontmatter 里 `name` 必须和目录名逐字符相等。

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
│   └── test_account_guard.py   # 348 个用例
└── references/
    └── article-mapping.md      # 每一项对应到参考文章哪一节
```

单测：

```bash
python3 tests/test_account_guard.py
```

## 参考来源

检查项的取材与逐条对照见 `references/article-mapping.md`，主要来源是这篇公开长文：

《你的 Claude 账号是怎么被封的》 https://x.com/AYi_AInotes/status/2106639522586829094

文中引用的三篇复盘贴也一并记在映射文件里。原文自带的两个推广链接（住宅代理服务商、新加坡卡）没有收录。

## License

MIT
