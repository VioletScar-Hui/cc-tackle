# 子目标对照表 —— 只覆盖 Claude Code 的环境检测与环境清理

来源：《你的 Claude 账号是怎么被封的》
https://x.com/AYi_AInotes/status/2106639522586829094

原文自己引用的材料也一并留着，免得日后只剩结论、丢了出处：

- 陈大黄复盘贴 https://x.com/realchendahuang/status/2104455272614035947
- 实践哥复盘贴 https://x.com/MinLiBuilds/status/2105890192108536029
- wangray 半年稳定的配置 https://x.com/wangray/status/2105658146685608265

另外两条是推广，原文自己在文末标了广告，没有收进来：住宅代理服务商 `equaldcdn.com/?ref=…`，以及新加坡卡的 `sg.starryblu.com/x/…`。

范围：**检测 Claude Code 的本机环境** + **自动清理环境里可安全清理的残留**。共 33 项（检测与自动清理 A1-A21 共 20 项，提权 B1/B2/B3/B5 四项，待决策 D2/D3/D4 三项，claude-cleanup 覆盖 E1-E5 五项，基线 F1 一项）。

## 检测项（只读）

| 编号 | 子目标 | 文章出处 | 脚本里的位置 |
| :--- | :--- | :--- | :--- |
| A1 | 出口 IP、**出口与上次是否一致**、系统代理、终端/rc/npm/git、`~/.npmrc` 与 `brew config` 的代理 | 2.5 ①④⑤、§9 第 2 条（brew 那一条文章里没有，属清单补充） | `check_export_ip` `load_export_history` `check_proxy_residue` `check_terminal_env` |
| A2 | `settings.json` 里指向别处的端点、凭据与代理变量 | 2.5 ⑤ | `check_anthropic_base_url` `clear_anthropic_base_url` |
| A3 | 遥测三键的当前状态 | §5 | `apply_telemetry`（读）+ `check` 部分 |
| A4 | `BROWSER=false` 包装脚本是否已建 | 2.6 | `apply_browser_wrapper` |
| A5 | IPv6 是否有全局地址 | 2.5 可选加固 | `check_ipv6` |
| A6 | DNS 是否落进 fake-ip 段 | 2.5 ③ | `check_dns` |
| A6 | DNS 交给了谁解析（主解析器/fallback 有无国内解析器、respect-rules 是否开启） | 2.5 ③ | `check_dns` + `check_clash_dns` / `clash_dns_leaking` / `clear_clash_dns_leak` |
| A7 | WebRTC 是否漏公网地址 | 2.5 ② | `check_webrtc`（`--webrtc`） |
| A8 | 出口 IP 的 ASN 类型是 ISP 还是机房 | 2.3、2.5 ① | `check_export_ip` `classify_asn` |
| A9 | `CLAUDE.md` 与 settings 里的地理位置词 | §4 | `check_geo_words` |
| A10 | 是否接了第三方客户端 | §1 | `check_third_party` |
| A11 | Claude Code CLI 完整性与版本占用；**这份二进制有没有被改过** | §5 | `check_client_integrity` `check_cli_signature` |
| A12 | 还有哪些代理组在做自动切换；「绝不直连」判据 | 2.3、2.4 | `check_clash_groups` |
| A13 | 本机账号痕迹 | §1、2.6 | `check_multi_account` |
| A14 | 代码有没有落在本地 Git | §6 第 11 步、§9 末条 | `check_local_git` |
| A15 | 时区／出口国／语言／AppleLocale 一致性 | 2.2、3.3 | `check_consistency` |
| A17 | `versions` 目录留存了几份、非当前版本占多少 | §5 | `check_client_integrity` |
| A21 | 时区三层读数，以及控制时区的两道闸 | 2.2 | `check_timezone_layers` |
| A22 | 作息与出口时区对不对得上 | 2.3 末尾 | `check_schedule_consistency` |
| A23 | 浏览器有没有给 Claude 单独建资料 | 2.6 | `check_browser_profiles` |
| A24 | 项目级 `.claude` 的规模与失效注册 | 2.6（延伸） | `check_project_claude` |
| A25 | 系统级占用里能清的部分（旧版本 + 可再生缓存） | 2.6、§5 | `check_claude_storage` |
| A26 | 项目级 settings 里的失效权限与危险授权 | §5 | `check_claude_settings` |
| A27 | 浏览器 Intl 区域设置 | 不在文章里，来自 ippure.com/claude.html 的检测项（权重 10） | `check_browser_locale` / `clear_browser_locale` / `is_cn_locale` |

出口固定性（2026-10-10 补）。文章 §2.5① 的原话是「国家固定，城市别每次变」，§9 清单第 2 条是「出口国家、城市和上次一致」——这两句都只能靠**和上一次比**才看得出来，而脚本原来每次只报「现在是谁」，等于把文章排在最前面的那条信号漏掉了。补法是每次体检把出口记进 `~/.local/state/claude-guard/export-ip.json`，下次读出来比：

- 变了报待处理，并把两次数值都写出来（上次是哪个 IP、哪个城市、什么时候记的）。**变了不等于错**——换订阅、服务商换 IP 都会变——所以是「待你确认」而不是「✗」。
- 取不到出口时**不覆盖**旧记录，否则一次网络抖动就把参照物弄丢了。
- 记录文件坏了、内容是别的 JSON 类型，一律当成「没有历史」，下次重新记，不报错。
- 路径写成 `export_state_path()` 函数而不是模块级常量：常量在 import 那一刻就把 `HOME` 定死了，测试把 `HOME` 指到沙箱也带不走它，会写到真实家目录去。
- 老报告里没有 `previous` / `changed` 两个键时，这一行照样渲染、不崩不变色。

A11 原先只管「装了没、装了几份、占多少地方」，而它的文档字符串却写着覆盖文章 §5 的「不要改客户端二进制」——**说到了、没做到**。2026-10-10 补上 `check_cli_signature`：

- 官方 CLI 是带签名的 Mach-O（实测 `Authority=Developer ID Application: Anthropic PBC (Q6L2SF6YDW)`），签名里存着整个二进制每一页的哈希，改一个字节签名就废。所以 `codesign --verify --strict` 通过 ≈ 「这份还是官方发出来的那份」。
- 三种结果分开报：验签通过是 ✓；**没签名**是待处理（可能是自己编译的、也可能是安装流程之外的二进制）；**验签失败**才是 ✗。顺序不能反——没签名时 `--verify` 必然也失败，先判失败会把「非官方安装」误报成「被人改过」。
- 还有一层：`codesign` 本身跑不了时（不是 Mach-O、机器上没有这个命令），`signed` 会是默认的 `False`，不看 `checked` 就会把「没测到」报成「没签名」。这一条一并在用例里钉住了。

拿到签名只是多一个判据，不等于能查出一切：签名只覆盖那个可执行文件，不覆盖它加载的 JS 资源；真正想彻底确认来源，还是得走官方安装脚本重装一遍。

A14 一度被当成「不属于环境检测」删掉。文章 §6 的第 11 步和 §9 清单的最后一条都是「代码放本地 Git，别让项目只存在 Claude 里」，它既是保号习惯也是出事时的退路，所以恢复。判据放得很松：只要扫到的目录里存在 git 仓库就算过，一个都没有才报待处理——项目根底下本来就可能有 `skills/` 这类不需要版本控制的目录，按目录数报警会天天误报。

A6 的两条补充判据（2026-10-10）。文章 2.5③ 给 DNS 排查的入口原话是「仍然看到国内 DNS，就检查 Clash 配置里 DNS 是否开启、`dns-hijack` 是否生效」，而原来的 `check_clash_dns()` 只看了 nameserver、fallback、respect-rules 三个键，恰好把这两个入口漏了——排查手册里让人查的东西自己没查。补法：

- `enabled` 只在 `dns.enable` 被**显式**写成 `false` 时报，键不存在属于用内核默认，不算故障（否则会把一堆正常配置误报）。
- `hijack` 读的是 `tun.dns-hijack`，**不在 `dns` 块里**。找错地方会永远报「没配」。而且只在 TUN 开着时才要求这一条——纯系统代理的部署没有那张虚拟网卡，缺它是正常的。

`clear_clash_dns_leak` 的复验条件改成直接复用 `clash_dns_leaking()`，不再自己列一遍。原来两处各写一份判断，补了这两条判据之后如果只改一处，就会出现「体检查出待处理、清理却报成功」这种自相矛盾的状态。

写这一段的原因之一是该写：为了把上面四条判据塞进 SKILL.md，tpp 那份的 SKILL.md 曾冲到 503 行，被 `scripts/check-project-skills.mjs`（`MAX_SKILL_LINES = 500`，按 `raw.split(/\r?\n/).length` 算）拦下。结论是 SKILL.md 只留判据本身，理由与坑放这里。

§2.1 那一节的标题是「动手前，先搞懂 5 个词」，正文先打比方讲了机房 IP 和住宅 IP，接着是一张五行的表——**出口 IP、ASN 类型、TUN 模式、系统代理、WebRTC / DNS 泄漏**。这五个词在 skill 里都已各有归处，不需要新增检查项：出口 IP 与系统代理归 A1，ASN 类型归 A8，TUN 归 A12，WebRTC 归 A7，DNS 归 A6。

这里有一个坑值得写下来：光看标题和开头那段比方，很容易以为「5 个词」指的是机房 IP / 住宅 IP / 原生 IP / 广播 IP / 双 ISP。那是社区里另一套常见分类，**原文从头到尾没有出现过「原生」「广播」「双 ISP」这三个词**——搜全文与原始推文的 243 个文本块均为 0 命中。所以不要照那套去给 `classify_asn` 加判据，那会变成往对照表里塞一个没有出处的子目标。真正对应文章的是：「机房 / 住宅」这一层由 `classify_asn` 覆盖，「纯净度」那一层文章交给 `ippure.com` 人工看，脚本不代判。

A22 只报事实不下判定。文章原话是「你在国内白天高强度写代码，换到美西就是凌晨三四点……不过这条只影响画像，优先级排在固定出口后面」。所以脚本报出本地时间、出口当地时间、时差，只在出口当地处于 0–6 点时才多一句提示。

A23 的实现有个坑：Chrome 的 `Local State` 被 macOS 的 TCC 挡住，`open()` 直接 `PermissionError: Operation not permitted`，连 `iterdir()` 也一样。但对**已知路径**的 `is_dir()` 是放行的，所以改成按浏览器固定的资料命名去探（`Default`、`Profile 1`……）。代价是拿不到资料的自定义名字——本来也判断不了哪个是给 Claude 用的，所以这条只报数量加建议。

A24 是文章里没有、实测补上的。文章 §2.6 只提家目录那三处残留（`~/.claude`、钥匙串、应用支持目录），但真正占地方的是**项目里的** `.claude/worktrees`：本机 55 个项目级 `.claude` 合计 8.5 GB，其中 99% 是工作树，也就是 Claude Code 的 git 工作树，装着真实代码和 `backend/.env` 这类文件。

所以这一项的口径是**按需要清，不按体积清**：

- 自动清理只做一件事——`git worktree prune`，把指向已消失路径的**注册记录**划掉。那种条目的工作树目录早就不在了，剩的只是 `.git/worktrees/<name>` 里一条登记，划掉不丢任何数据。
- 活的工作树一个都不碰，`prune` 也不会碰（它只处理路径已不存在的）。
- `.claude/worktrees/.DS_Store` 这类孤立文件顺手删掉。

A25 的口径是「按类别清」，不是「按大小清」：

- **清**被取代的旧版本。CLI 自己留的历史版本（实测攒了 4 份 862 MB），还有桌面版内置的那份副本（2.1.288 旧、2.1.293 新）。
- **清**会自己重建的缓存。Electron 的 `Code Cache`、`Cache`、`GPUCache`、`Dawn*`。
- **不清**用户数据。`Local Storage`、`IndexedDB`、`Cookies`、`Preferences`、配置、会话、用量历史——这些可能是账号状态的一部分，不是缓存。实测这部分的判据是：目录名在 `DESKTOP_CACHE_DIRS` 白名单里才清，不在的一律不动。

「哪份是旧的」用的是**当前在跑的那份**（`command -v claude` 的软链接指向），不是版本号比大小。版本号比大小在 `2.1.99` 和 `2.1.100` 之间就会判错。

项目级那边对应的是 `clean_project_claude_junk`：清 `.DS_Store` 和 `__pycache__`，**不碰** `skills/`、`settings*.json`、`agents/`、`hooks/`、`commands/`（对应系统级的 PROTECTED 名单），也不进 `worktrees/`。

有一个坑必须按精确文件名清、不能按后缀扫：skill 目录下的 `*.log` 看着像日志，实际是 eval 的测试夹具（本机 294 个，全在 `skills/*/evals/fixtures/` 下），按后缀删会把 skill 自己的测试弄坏。

A27 不在文章里，是用户拿 ippure.com/claude.html 的检测结果来问才加的。那页六项指纹里「Intl 区域设置」权重 10，量的是浏览器做日期 / 数字格式化用的 locale，只给大陆简体计分——`en-US` 拿 0，`zh-CN` 计满。

查这一项时先纠正了一个想当然：Chrome 的 `--lang=en-US` 启动参数完全无效（临时资料起真 Chrome、连 CDP 读值实测），资料里的 `intl.accept_languages` 也只改 `navigator.language`。真正驱动 ICU 默认 locale 的是 **macOS 应用域的 AppleLanguages** —— `-AppleLanguages "(en-US)"` 一给，`Intl.DateTimeFormat` / `NumberFormat` / `Collator` / `navigator.language` 全部变成 en-US，日期样例从 `2026/10/9` 变成 `10/9/2026`。所以持久化的修法是 `defaults write com.google.Chrome AppleLanguages -array en-US`：只作用在 Chrome 上，不动系统语言，一条 `defaults delete` 就能还原。

两个边界写死在代码里，别改回去：① 判定只认大陆简体，`zh-TW` / `zh-HK` 也讲中文，但那不等于「中国用户」，判成命中等于拿一个正确的设置去报错；② 值改对了但 Chrome 还是改之前启动的那个进程时，浏览器报出来的仍是旧值，这种情况必须留成待处理，报绿等于替浏览器撒谎 —— `chrome_needs_restart()` 用进程启动时间和偏好文件 mtime 比，判断不了就返回 None，绝不猜。

A26 是问题的另一面：前面几项都在清「Claude 留下的东西」，这一项清的是「你给 Claude 的东西」。Claude Code 每同意一次「总是允许」就往 `permissions.allow` 里加一条，日积月累会攒下大量一次性授权——实测本机 25 个文件 1127 条，其中 140 条可以证明不可能再命中。

分两半处理，因为性质不同：

- `dead`（证明失效）自动清。判据收得很紧，只认三种能证明的：一次性的 PID（`Bash(kill 2220)`，那进程早没了）、别的机器家目录下的路径、绝对路径连同父目录都已消失。带通配的一律当活着。
- `risky`（还活着但偏危险）**只报告不代删**。比如 `Read(**/.ssh/**)`、`Bash(pkill ...)`、`Bash(curl:*)`。删掉会让 Claude 多弹确认，那是用户的取舍，不是脚本该替他做的决定。

两个判据上的坑，都是用例抓出来的。一是 `Bash(pnpm --filter @acme/schema build)` 里的 `/schema` 会被朴素正则当成路径，把这条**在用**的权限判死——所以只认 `/Users`、`/home`、`/opt` 这类真正的文件系统根开头；`./list-devices.sh` 同理。二是 `pkill` 里也含 `kill`，但它按模式杀、不是一次性 PID，不能混为一谈。

还有一个**写回格式**的坑，代价最大：权限条目有两种形态，纯字符串 `"Bash(git add *)"` 和两元数组 `["Bash(git add *)", null]`。第一版清理代码写成 `keep.append((str(x), r))`，元组序列化成 JSON 就是数组，于是 241 条纯字符串被改写成 209 条 `["Bash(...)", null]`。JSON 照样能解析、肉眼也像对的，但已经不是用户的格式了。发现后从备份整体回滚重做，并把「字符串条目必须还是字符串、数组条目必须还是数组」钉成回归用例。

## 自动清理项（不逐项询问）

| 编号 | 子目标 | 文章出处 | 脚本里的位置 |
| :--- | :--- | :--- | :--- |
| A16 | 清未启用但存了值的系统代理 | 2.5 ④ | `clear_proxy_residue` |
| A24 | 划掉项目级失效的工作树注册 | 2.6（延伸） | `prune_stale_worktrees` |
| A25 | 清被取代的旧版本与会自己重建的缓存 | 2.6、§5 | `clean_claude_storage` |
| A26 | 清掉证明失效的权限条目 | §5 | `clean_dead_permissions` |
| A27 | 把 Chrome 的应用语言对到出口国家 | ippure 检测页 | `clear_browser_locale` |
| A24 | 清项目级 `.claude` 里的 `.DS_Store` 与 `__pycache__` | 2.6（延伸） | `clean_project_claude_junk` |
| A18 | 清 shell 配置里的代理行 | 2.5 ⑤ | `clear_rc_proxy_lines` |
| A19 | 清 npm / git 的全局代理 | 2.5 ⑤ | `clear_npm_git_proxy` |
| A20 | 清 `settings.json` 里的端点与凭据变量 | 2.5 ⑤ | `clear_anthropic_base_url` |

## 需要提权的项（仍逐项询问）

| 编号 | 子目标 | 文章出处 | 脚本里的位置 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| B1 | 关「按位置自动设定时区」 | 2.2 | `check_timezone_layers` 复查 | 已完成，实测 Active=0 |
| B2 | 时区设 Asia/Taipei | 2.2 | 已完成 | 已完成 |
| B3 | 关闭网络服务的 IPv6 | 2.5 可选加固 | `set_ipv6_off` | 待做 |
| B5 | 关「定位服务 → 系统服务 → 设定时区」 | 2.2 | `location_service_status` `disable_location_timezone` | 读 clients.plist 要 root，非 root 时报读不到并给 UI 路径 |

## 有副作用、仍由用户决定的项

A3（遥测开关写入）已在上面列出，它同时属于这一类：会连带关掉功能旗标，Remote Control 可能失效，所以只检测不主动写。

| 编号 | 子目标 | 说明 |
| :--- | :--- | :--- |
| D2 | 全局模式还是规则模式 | **已定：规则（rule）**。文章 2.4 原话是「代理页切到全局……用 Claude 期间不建议用规则模式，分流规则写错就会漏」，全局模式的理由是怕分流规则写错导致漏。但 2026-10-09 换成住宅代理订阅后用户明确要「国内网站用规则、国外走代理」，而 Claude 域名已被 6 条显式规则钉进专用组、兜底是 `MATCH,住宅代理组` 不是 DIRECT，漏的风险由那条专用线路兜住了。所以选 rule。 |
| D3 | `Claude` 组是否加入「备用」节点 | **已定：不加**。两节点出口 IP 相同，加了只牺牲确定性 |
| D4 | iPhone / Windows 端时区对齐 | 文章原话「电脑说在台北，手机说在上海，本身就是一对矛盾信号」 |

## 交给 claude-cleanup 的项

| 编号 | 子目标 | 文章出处 | 脚本里的位置 |
| :--- | :--- | :--- | :--- |
| E1 | 钥匙串 `Claude Code-credentials` | 2.6 | `check_keychain`（svce 与 acct 分开报） |
| E2 | 应用支持目录历史会话 | 2.6 |
| E3 | 备份 `~/.claude` | 2.6 |
| E4 | `~/.claude` 可再生部分清理 | 2.6 |
| E5 | 不在 Claude Code 下清理自己 | 2.6 |

## 已完成基线

| 编号 | 子目标 | 状态 |
| :--- | :--- | :--- |
| F1 | 代理客户端配置：订阅、服务模式、开 TUN、关系统代理 | 已就绪 |

## 明确移出范围

按「只做 Claude Code 的环境检测与清理」这条口径，以下原先列过的项全部移出：

- 付款与退款（原 C3、H7）
- claude.ai 网页端设置与 Active sessions（原 C1、C2、H6）
- 账号申诉与数据导出（原 C4、C6、H8）
- 路线选择、邮箱手机号、订阅节奏、支付渠道、不共享不借号、行为像人、手机端少用（原 D1、D5–D10）
- DSH 自身的工具链问题：持久记忆写入失败、trcost 拦截、macOS 无 `timeout`、废纸篓 TCC、osascript 权限（原 P2、P5、P6、P7、P8）
- skill 摆放位置问题（原 P17）
- 文章带联盟链接（原 P10，与本 skill 无关）

「移出」的口径是**不写成脚本自动化的子目标**，不等于假装文章没说过。上面第一到第四组后来都进了人工行动清单（`--manual`），一条一条给出点击路径和出处。

本地 Git（原 A14）是唯一被恢复成自动检查的：它属于本机环境，只是判据要放松，一个仓库都没有才算待处理。

## 人工行动清单（`--manual`）

文章里有二十三项本机没有接口、脚本替不了，只能人去做。它们不进自动流程，但也不该在交付里消失，所以集中成 `MANUAL_ACTIONS`，用 `python3 scripts/account_guard.py --manual` 打印。分六组：

| 组 | 内容 | 为什么脚本做不了 |
| :--- | :--- | :--- |
| 一、手机与其它设备 | iPhone、Windows 端的两道时区开关 | 不在本机 |
| 二、浏览器与设备隔离 | 单独建资料专登 Claude、授权链接走哪打开、一台设备一个号 | 浏览器资料的状态读不到（TCC），「哪个资料是给 Claude 用的」也判断不了 |
| 三、网页端设置 | Active sessions 踢陌生设备、`data-privacy-controls` 关改进计划 | 只能进网页点 |
| 四、账号与支付节奏 | 邮箱手机号、验证邮件在哪点开、新号 1–3 天／4–7 天／2–3 周节奏、额度见黄就停、走 App Store 内购 | 全是人的决定，本机没有对应状态 |
| 五、使用行为 | 别把地理位置写进提示、别像脚本、只用官方客户端 | 前两条看的是你写进 prompt 的内容；第三条 A10 能查本机，人工清单负责讲清为什么 |
| 六、被封之后 | 先分辨是限额还是封号、申诉只写事实、退款与取消续费、别在同一台没清理过的电脑上秒开新号 | 都发生在网页端和账号侧 |
| 七、出口这个节点本身 | 买完节点自己验类型与独享、自建 VPS 避开国内大厂海外区 | 纯净度和共享人数只有检测站能给，ASN 类型脚本能报、这两项报不了 |

每项都带 `〔文章 §X〕` 出处、可照做的点击路径，以及一句「为什么」，验收标准是每一步都能直接照着走，不出现「适当配置一下」这类空话。

## 第二遍逐行对账补的五处（2026-10-10）

第一遍是按小节对账，第二遍改成**逐行抽祈使句和表项**，又找出五处文章写了、skill 里没有的：

| 文章位置 | 原来是 | 现在 |
| :--- | :--- | :--- |
| §2.5① + §9 第 2 条「城市别每次变 / 和上次一致」 | 只报当前出口，从不与上次比 | A1 增出口固定性比对，变了报待处理并列出两次数值 |
| §2.3 第 4 步 + §6 第 2 步「ping0.cc、ippure.com 查共享人数」 | 人工清单里 `ping0` / `ippure` / `独享` / `纯净` 零命中 | `--manual` 新增第七组「出口这个节点本身」，两条 |
| 附 5「内容别碰红线」+ §4 实践哥复盘 | 人工清单没收 | 「使用行为」组补一条（网络安全护栏 / Cyber Verification Program） |
| §1 九月新变化「被要求身份验证只能用本人证件」 | 人工清单里 `证件` / `身份验证` 零命中 | 「被封之后」组补一条 |
| §2.5② 的 Firefox 修法 `media.peerconnection.enabled` | 文档里没有 | WebRTC 那一节补上，并标明未在本机实测 |

顺带补的一条：§1 条款「不能把登录信息、API Key、凭据分享给任何人」原来只在「不借号」那条里隐含，现在写成明文步骤。「买完验节点」与「避开国内大厂海外区」两条是附 12 那张方案表的注脚，一并收进第七组。

## 文章里没有变成检查项的部分

逐节对完账，文章一共有三处没有对应的检查项，都是**性质决定的**，不是漏掉：

| 文章位置 | 内容 | 为什么不是检查项 |
| :--- | :--- | :--- |
| §0 + 附 8 | 路线对照表：按你的情况选 A/B/C/D，默认走 B | 这是「投入多少」的选择题，不是本机的某个状态，没有可读的字段。本 skill 服务的正是 B 路线里「环境」那一层 |
| §8 + 附 9 | 「这些说法可以少信」：时区与中文输入法别神化、充得多不一定容易封、研究员号未验证、代过验证是欺诈、拼车成品号是幻觉 | 全是判断与传闻的分辨，没有本机状态可测。其中「时区别神化」一条已经体现在 A15 的口径里——那一项只报事实、不下判定 |
| §10 | 新加坡卡的整节广告 | 与 skill 无关，前面已记为推广 |

换句话讲：**凡是文章里能用本机状态判断的，都已经有了落地；剩下的三类分别是路线选择、传闻分辨和广告。**

## 检查中改正的问题

第一遍（逐节对账）发现两处遗漏：§6 第 11 步的「代码放本地 Git」补为 A14（后来恢复成 `check_local_git`）；§2.2 的「两端要对齐」加 §3.3 的「同国」要求构成一致性检查，补为 A15。

第二遍（核对本机现状）发现两处实错：早期记录说 `~/.codex/config.toml` 仍指向自建中转端点并含明文 token，实测已无；早期记录说钥匙串 `Claude Code-credentials` 存在，实测不存在，钥匙串里唯一相关项是 Claude Desktop 的 `Claude Safe Storage`，此前把两者混淆了。

第三遍（可行性核对）发现两处分类错：清系统代理残留不需要提权（实测退出码 0），移入自动清理类；A7 的浏览器运行时其实存在，是查错了目录。

第四遍（写脚本后的静态审查）改掉：`clear_proxy_residue` 里 `server` 赋值后未使用；`check_local_git` 最早把目录写死在代码里，现在改成读 `CLAUDE_GUARD_PROJECT_ROOTS`，不设就跳过并说明怎么开；`check_geo_words` 只扫家目录；`apply_browser_wrapper` 不检查 PATH 与 `claude` 是否存在；`set_ipv6_off` 无 root 时静默跳过并打印「已关闭 []」，且没有回滚说明；`check_consistency` 把文章自己推荐的配置判成矛盾；`check_dns` 用一个词掩盖真正的泄漏信号；`disable_location_timezone` 的复验写成 `"false" not in body`，而整份 plist 必然含 "false"，等于没验证；`protected_verify` 在写完之后才抛错；`check_terminal_env` 沿用文章的 grep 会把正常变量算成残留；`audit()` 写在 `try` 之外会抛 traceback。

第五遍（异常路径与并发）改掉：未捕获 `KeyboardInterrupt`；备份时间戳只到秒会互相覆盖（实测 8 线程 8 目录）；`check_webrtc` 用固定临时路径且把 node 堆栈原样吐出；网络服务列表在未 strip 的行上判断星号。

第六遍（测试可靠性）改掉：失败路径测试是假通过（遥测选 0 时 `apply_telemetry` 根本不会被调用）；测试没 patch `HOME` 读到了真实数据。

第七遍（收窄范围后）改掉：`check_client_integrity` 按 `is_dir()` 过滤 `versions` 目录，而官方安装放的是可执行文件，导致把 4 个版本报成 0 份；`protected_verify` 的允许清单漏了有意清理的 shell 配置文件，把正常清理误报成「受保护文件被改动」并返回退出码 3。

第八遍（T8-T12 真机实测）改掉两处「把历史当现状」的判定错误，都在 `check_timezone_layers` 里：

- 6 小时窗口里同时躺着 17:51 的 `TZ,computed,result,Asia/Shanghai` 和 20:55 的 `TZ,setSourceUnavailable`，原先「窗口里出现过 Shanghai 就算没锁住」把稳定的台北判成失败，会天天误报。改成只按时间戳排序取最后一条，判定则只看两个活读数（`/etc/localtime` 与新进程实际拿到的时区）。
- 同一个窗口里 `Available` 与 `Unavailable` 都有时，「先匹配到 Available 就算 True」会把最新的 `Unavailable` 盖掉，结论正好相反。同样改成取时间上最后一条事件。

`check_keychain` 也修正一处解析错误：`security dump-keychain` 会把每个条目列两遍，一遍用十六进制属性号、一遍用具名属性。genp 的服务名在十六进制那遍写作 `0x00000007`，只认 `"svce"` 会漏掉前一半条目——实测 Claude Safe Storage 正好只出现在十六进制那遍，拼出来的结果是 `('', 'Claude Key')`。

真机实测结论：节点置死时 `api.anthropic.com`、`claude.ai`、`www.baidu.com` 全部连接失败（curl 退出码 35），出口 IP 取不到，没有任何降级到备用节点或直连的路径，fail-closed 成立。

第九遍（做最终总表时）改掉一处会误导人的报法：`check_anthropic_base_url` 会连带扫到别的工具的配置，原先表里只要有命中就写「自动清理会清掉」，实测命中的那唯一一处恰恰是 `~/.dsh/settings.yaml:10`——按范围约定脚本根本不碰它。改成区分「Claude Code 自己的 `settings.json`」与「其它工具」，后者只报告不代改。

同一轮还发现缺字段会被默认成「干净」：`build_summary` 里多处用 `report.get(k) or {}` 取值，某一项没跑出来时字段缺失，判定会走到 `else` 分支报 ✓。加了 `missing()` 守卫，缺字段一律显示「未测到」。空报告现在的正确结果是 18 项全部未测到、0 项已解决。

`check_webrtc` 也重写了一次。旧实现依赖 node 侧 playwright 模块，这台机器上模块不存在，所以这一项永远测不出结果。新实现把浏览器当命令行工具用（`--dump-dom`），并实测了三种组合：完整版 Chrome 新旧 headless 都会挂死不返回；headless shell 配 `--virtual-time-budget` 能返回但虚拟时钟把等待提前触发、ICE 来不及跑完，稳定给出 0 个候选；配 `--timeout` 则在 load 时就 dump，异步结果写不进 DOM。结论是命令行这条路不可靠，于是把口径定成「能测就报，测不到就明说」，并把 0 候选明确标成结论不可用而不是没有泄漏。

操作教训：改代码不要用 `sed`（曾把 f-string 改出 `SyntaxError` 并弄坏整个文件）；macOS 没有 `timeout` 命令。
