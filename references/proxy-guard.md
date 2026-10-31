# 出口体检：Claude 规则指向谁，那个组还活着吗

`scripts/proxy_guard.py` 回答三个问题：

1. Claude 规则的目标组是什么？
2. 组里有几个成员？选中的那个还活着吗？
3. 如果选中的挂了、但组里还有活的，能不能就地切过去？

## 用法

```bash
python3 scripts/proxy_guard.py --check          # 只体检，退出码 1 表示有问题
python3 scripts/proxy_guard.py --json           # 机器可读
python3 scripts/proxy_guard.py --fix            # 在组内切到可用成员（不改配置）
python3 scripts/proxy_guard.py --fix-members --nodes "线路1,线路2,线路3,线路4"
python3 scripts/proxy_guard.py --emit sing-box  # 生成某家客户端的片段
python3 scripts/proxy_guard.py --clients        # 这台机器上检测到哪些客户端
```

## 判定规则

- 第一条覆盖 Claude 域名的规则决定目标组；找不到 → 报「会走 MATCH 兜底」。
- 组里成员 ≤ 1 → 报「单点组」：这条线路挂了 Claude 就整体不可用。
- 选中节点 `alive=false` 或延迟为 0，但组里还有健康成员 → 标记「可切换修复」。
- 组里一个健康成员都没有 → 让你先查订阅/住宅线路本身。

## --fix-members 改了什么

只支持 Clash Verge Rev：

- 往 `clash-verge.yaml` 和 `profiles/*.yaml` 里含有该组的文件补节点（原文件备份成 `.bak-20261031`）
- 用 `PUT /configs` 把改后的配置热载进内核
- 提醒你去「订阅 → 编辑 → 全局扩展」确认，否则订阅更新会覆盖

其它客户端（Sing-box / Surge / Shadowrocket）不写文件，只用 `--emit` 生成片段。
