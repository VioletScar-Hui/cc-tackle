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

## 必须人工处理的事项

```bash
python3 scripts/account_guard.py --manual
```

`--manual` 只打印行动清单，不体检、不修改。清单覆盖手机和其他设备、浏览器资料隔离、网页设置、账号与支付节奏、使用行为、被封后处理。重点包括：同时关闭 iPhone 的自动设置和系统服务中的设定时区；验证邮件只在专用浏览器资料中打开；看到额度预警就停用，不用换号绕过；浏览器资料隔离和出口当地时间仍需人工确认。

## 历史判断背景

`mode=rule` 本身不表示故障；系统代理、TUN、内核网络扩展和订阅生成配置的限制需要结合实测证据判断。DNS、WebRTC、浏览器 Intl、媒体权限和定位服务各自有 freshness 与资料范围要求，过期或范围不符只能算未测。订阅配置可能覆盖手工改动，修复顺序应先确认真实出口和路由，再处理浏览器区域设置。
