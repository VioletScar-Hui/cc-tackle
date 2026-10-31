# 测试说明

单元测试全部跑在合成夹具上：不碰真实设备、真实代理、真实浏览器权限，也不申请管理员权限。它证明的是判据逻辑与安全边界被守住，不是这台机器的真实环境如何。

## 怎么跑

在仓库根目录：

```bash
# 全量（提交前跑这条）
python3 -m unittest discover -s tests -v

# 单个文件 / 单个类
python3 -m unittest tests.test_net_guard -v
python3 -m unittest tests.test_account_guard.TestFailClosedIsModeAware -v
```

CI 在 `macos-latest` 上用 Python 3.11 与 3.13 各跑一遍（配置见 [`.github/workflows/tests.yml`](../.github/workflows/tests.yml)），步骤是编译检查、全量单测、打包校验、命令帮助检查。本机 `/usr/bin/python3` 是 3.9.6，核心脚本的最低版本就是 3.9，所以本机也应当能跑全量。

用例数量会随增删变化，不写死在本文件里——以 `Ran N tests` 结尾那行为准。

## 隔离约定

- 一切资源都用临时对象现造：`tempfile.TemporaryDirectory()`、假的命令输出、假的 plist、假的 HTTP 服务、注入的假 fetcher。**不访问网络、不启动代理内核、不开浏览器、不读真实钥匙串、不执行 sudo。**
- `tests/test_account_guard.py` 的 `setUpModule()` 会摘掉所有 `CLAUDE_GUARD_*` 环境变量，`tearDownModule()` 再放回；需要某个变量才能测的用例自己用 `mock.patch.dict` 设。这样开发机 `export` 了什么都不会影响用例结果（2026-10-14 出过一次「环境串味」，见 [`references/maintenance-notes.md`](../references/maintenance-notes.md)「测试的环境隔离」）。
- 交互流程按**提示语**作答（`prompt_answering()`），不按顺序。改 `main()` 的问句顺序不会炸出看不懂的 `StopIteration`；认不出的提示语会直接失败并带上原文。
- 页面类用例用 `CLAUDE_GUARD_NO_REPORT=1` 关掉自动报告，并有用例专门断言整套测试不会往真实 `~/ClaudeGuardBackups` 写文件。写路径的用例一律把输出指到临时目录。
- 夹具里的 IP、凭据一律用文档保留地址或假值（例如 `203.0.113.10`），不写真实出口 IP、不写真实 token。

## 覆盖什么

| 文件 | 覆盖 |
| --- | --- |
| [`test_account_guard.py`](../tests/test_account_guard.py) | 主体脚本：28 项判据与结果表对齐（显示宽度、截断、缺字段一律「未测到」）、ASN 归类、写操作安全边界（非 TTY 拒绝、备份先于写入、清理后不得变成启用、受保护文件、并发锁、备份恢复）、时区与钥匙串解析、「绝不直连」按模式分判、CLI 安装方式与签名、登录方式 A29、代理后端分派、浏览器缓存的 24 小时 / `profileScope` / `openedBy` 三项条件、报告页与本地服务（零外部资源、静态页无 JS 无按钮、修复按钮先备份、令牌路由）、`--fix-auto` 与 `selfcheck` 的收尾行为。 |
| [`test_net_guard.py`](../tests/test_net_guard.py) | 看门狗：Claude 进程识别（排除 `cc-tackle`、DSH 与参数里带 `claude.ai` 的 curl）、`lsof` 两种地址格式解析、直连 / 隧道 / 本机判定表、误杀保护（不杀自己、父进程链、pid 1，每分钟击杀上限）、LaunchAgent plist 形状、出口锁定状态。 |
| [`test_proxy_guard.py`](../tests/test_proxy_guard.py) | Claude 出口体检：六种客户端片段格式、单点组 / 死节点 / 规则缺失三种诊断、组内切换与补成员、CLI 动作映射；2026-10-30 单点组事故的症状固化成用例。 |
| [`test_resident.py`](../tests/test_resident.py) | 常驻任务清单：`launchctl` 的在跑 / 被禁用 / 未加载三种状态要分清；报告页常驻区块按 `<li>` 渲染短句，且只列本 skill 自己的任务。 |
| [`test_residential_lock.py`](../tests/test_residential_lock.py) | 住宅链路锁定：吸收进来的脚本还在且可执行、动作到命令的映射（`--root-*` 必须带 sudo、`--dry-run` 要透传）、参数文件允许用环境变量覆盖、`--status` 输出；另有 bash 3.2 多字节变量回归。 |
| [`test_ip_judge.py`](../tests/test_ip_judge.py) | 住宅 / 机房判定：任一源 `hosting=True` 即判机房、家宽关键词兜底、都认不出返回 `UNKNOWN`；缓存读写与版本失效。数据源全部注入假 fetcher，不联网。 |
| [`test_package_skill.py`](../tests/test_package_skill.py) | 可复现打包：只含运行时文件、排除项不误入、两遍构建字节一致、清单 sha256 与 zip 一致、输出落进包内或软链外指要被拒绝。 |
| [`test_docs.py`](../tests/test_docs.py) | 仓库地图与文档导航：必需文档存在、README 提到每份 reference 与顶层脚本、相对链接与锚点可解析、`SKILL.md` 行数上限、版本号在 `SKILL.md` / README / CHANGELOG 三处一致。 |

## 明确不覆盖什么

- **真实 macOS 行为**：`networksetup`、`scutil`、`launchctl`、`log show`、`codesign`、TCC 的真实回执都没有跑。单测只验证脚本对这些输出的解析与判定，不验证系统真的会这样回。
- **真实网络**：出口 IP、ASN 归属、DNS 解析、WebRTC ICE / STUN 一律不测。`ip_judge` 的每个数据源都是注入的假 fetcher。
- **真实 Clash / 浏览器**：不启动代理内核、不读真实 Clash 配置、不打开真实 Chrome 资料、不装扩展、不碰钥匙串。
- **Windows / Linux**：不支持，也没有用例；检测依赖的 macOS 命令在别的平台不存在。
- **sudo 与 root 层**：不执行 pf、不装 LaunchDaemon、不申请管理员权限；root 层只测命令映射与参数透传。
- **CI 绿不等于真机通过**：CI 在 macOS runner 上跑的也是合成夹具，验证代码，不验证你的系统设置。真机项（TUN 路由、单点组事故复现、sudo 两步、pf 规则、浏览器复核回传）只能由人在本机验证，逐项证据等级见 [`references/verification-status.md`](../references/verification-status.md)。

## 加用例的约定

- 修 bug 先写一条会红的回归用例，再改代码。仓库里 Chrome 重启误判、bash 3.2 多字节变量、`--fix-auto` 误删 OAuth token、缺字段默认成「干净」都留有专门用例。
- 涉及写路径的用例必须把输出指到临时目录，并断言真实目录没有新增文件。
- 不删用例、不放宽断言来换绿。要改一条断言，先写清它原来守的是什么问题。
- 需要 root、联网或真实浏览器权限的验证写进 `references/` 的真机验证小节，不进 `tests/`。
