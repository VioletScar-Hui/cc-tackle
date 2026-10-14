# Claude Guard 维护说明

这些背景和人工清单用于需要深入核对时的复查，不改变 Skill 的默认入口、确认门或恢复边界。

## 项目级 settings

`permissions.allow` 是用户给 Claude Code 的授权记录。失效授权（一次性 PID、其他机器的绝对路径、已删除目录）可以在用户确认后处理；涉及 `Read(**/.ssh/**)`、`Bash(pkill ...)`、`Bash(curl:*)` 等高风险条目先报告，默认不代删。

判断包名和路径时，只把 `/Users`、`/home` 等文件系统根当作路径；`pnpm --filter @task-pilot/schema build` 中的 `/schema` 是包名。`pkill` 按模式杀进程，不等于一次性 PID。

权限条目可能是纯字符串，也可能是 `["规则", null]`。写回时保留原对象和形状，不重建或归一化；发现格式漂移应从备份回滚并重做。

## 系统与项目级占用

系统级清理按类别判断：可处理的是已被当前版本取代的旧版本和可重建缓存（`Code Cache`、`Cache`、`GPUCache`、`Dawn*`）；`Local Storage`、`IndexedDB`、`Cookies`、`Preferences`、配置、会话和用量历史可能包含账号状态，不能按体积删除。

旧版本以 `command -v claude` 的软链接指向判断，不能按版本字符串排序。项目 `.claude/worktrees` 里是真实代码和环境文件，不能因体积大而删除；只可清理已经不存在的工作树登记。项目级杂项仅处理 `.DS_Store`、`__pycache__`，保留 `skills/`、`settings*.json`、`agents/`、`hooks/`、`commands/`，不进入 `worktrees/`。skill 目录内的 `*.log` 可能是 eval 测试夹具，不能按后缀批量扫。

工作树的 `.git` 是文件（内容指向真实 gitdir），不能用目录存在性当作仓库判断；`.claude/worktrees/.DS_Store` 这类孤立文件也不应计为工作树。

## 测试的环境隔离

这套用例的结果不能取决于开发机 exports 了什么。`main()` 是**按体检结果问不定数量的问题**的，可清理项多一项就多一问；而 `auto_clean_plan` 里有一项是现场读环境的：`"project_junk": bool(project_roots())`（只看有没有配项目根，不看真有没有垃圾）。2026-10-14 因此出过一次「环境串味」：开发机 `export CLAUDE_GUARD_PROJECT_ROOTS=...`，交互多出「清理项目级 .claude 垃圾」一问，用例里写死的四段答案错位，5 个用例报 `StopIteration`（完全看不出是哪个问题对不上），自检跟着变红；同一份代码在不带变量的终端里跑就是全绿。

两处防线：

- `tests/test_account_guard.py` 的 `setUpModule()` 在整套用例开始前摘掉所有 `CLAUDE_GUARD_*`，`tearDownModule()` 结束再放回。需要某个变量才能测的用例自己用 `mock.patch.dict` 设。
- `prompt_answering()` 按**提示语**作答而不是按顺序：CONFIRM 那一问回 `CONFIRM`，含「遥测开关」的回合选项号，带 `[y/N]` 的（`ask_yes` 自己补的标记）回 `y`/`n`；认不出来的提示语直接 `AssertionError` 并带上原文。改 `main()` 的问句顺序不会再让用例炸成看不懂的报错。

改完必须**两种环境各跑一遍**（带 `CLAUDE_GUARD_PROJECT_ROOTS` 和不带），两边都全过才算修好。跑自检时若单测红，`selfcheck.py` 会把整套输出落到 `~/ClaudeGuardBackups/tests-failure-<时间戳>.log` 并在说明里给出路径——只留摘要不留现场，问题就不可复现。

## 必须人工处理的事项

```bash
python3 scripts/account_guard.py --manual
```

`--manual` 只打印行动清单，不体检、不修改。清单覆盖手机和其他设备、浏览器资料隔离、网页设置、账号与支付节奏、使用行为、被封后处理。重点包括：同时关闭 iPhone 的自动设置和系统服务中的设定时区；验证邮件只在专用浏览器资料中打开；看到额度预警就停用，不用换号绕过；浏览器资料隔离和出口当地时间仍需人工确认。

## 历史判断背景

`mode=rule` 本身不表示故障；系统代理、TUN、内核网络扩展和订阅生成配置的限制需要结合实测证据判断。DNS、WebRTC、浏览器 Intl、媒体权限和定位服务各自有 freshness 与资料范围要求，过期或范围不符只能算未测。订阅配置可能覆盖手工改动，修复顺序应先确认真实出口和路由，再处理浏览器区域设置。
