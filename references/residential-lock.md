> 本文件是吸收进来的原始说明；脚本在 `scripts/residential/`，统一入口 `scripts/residential_lock.py`（本文里的 `bash scripts/xxx.sh` 对应 `scripts/residential/xxx.sh`）。

---
name: claude-residential-lock
description: 让 macOS 上 Claude 的全部流量（含 UDP/WebRTC）强制走指定住宅家宽节点，禁止直连、禁止 fallback，并在订阅更新或重启后自动修复。当用户要求"Claude 走家宽/固定出口 IP/防泄漏/出口隔离"，或需要排查已部署的此类链路是否健康时使用。
---

# Claude 住宅链路锁定

把 Claude 桌面版与 CLI 的全部流量钉死在一个住宅出口 IP 上，并保证：

- 任何形式的直连都不成立，包括安装包下载与自动更新
- 不 fallback、不自动切换，节点断了就断，不走别的路
- UDP / WebRTC 不会绕过代理泄漏真实或 VPS 出口
- 订阅更新、Verge 重启、系统重启之后自动恢复到正确状态

## 先理解它防的是什么

这不是"配个代理规则"那么简单。整套东西存在的唯一理由是三个互相独立的事实：

**一、`prepend-rules` 是 Clash Verge 的专有字段，mihomo 内核不认它。**

内核只读 `rules` 数组。你在 Verge 的 Merge 增强里写的规则，能不能进内核，取决于 Verge 生成配置时有没有展开它。所以"我配好了"和"内核真的在用"是两件事，必须分开验证。

**二、内核读的不是 `clash-verge.yaml`。**

启动参数是 `-f .../runtime/config.yaml`，那个文件 root 属主、用户读不了。`clash-verge.yaml` 只是 Verge 的中间产物。所以改文件不等于改内核，必须走 `PUT /configs` 热载；反过来只热载也不够，因为下次 Verge 重启会从文件重新生成。

**三、订阅兜底是 `MATCH,<某个可切换组>`，而那个组通常有十几个成员。**

规则一旦丢失，TCP 可能还碰巧走在正确节点上（因为组当前选中它），但任何人手动切一下、或内核重启后选择漂移，就立刻离开住宅链路。UDP 更糟——它常常根本不走代理，直接以 VPS 入口 IP 出网。

**这三条是整个方案的根因，所有脚本都围绕它们设计。** 详细推导和踩过的坑见 `references/pitfalls.md`，动手前建议先读一遍，能省掉几个小时的试错。

## 先找出住宅节点（不要靠名字猜）

**这是最容易搞错、而且错得最隐蔽的一步。**

订阅里的节点名字是服务商随便起的，`(赠送)美国CN2专线娱乐节点` 可能连的是机房，
而 `高仿住宅IP` 也可能是个机房。更麻烦的是：即使你选错了节点，
`selfcheck.sh` 只要发现「出口 IP 等于你填的 EXIT_IP」，就会全绿通过 ——
因为它验证的是*一致性*，不是*是不是住宅*。

所以先跑这个：

```bash
bash scripts/discover.sh
```

它会逐个把节点切上去、测真实出口 IP、多源交叉判定归属，出一张表：

```
      节点名                      出口 IP        判定
  ----------------------------------------------------------
  ❌  (赠送)美国CN2-2专线娱乐节点 203.0.113.21   AS/组织名命中机房关键词「netlab」
  ❌  (赠送)美国CN2专线娱乐节点   203.0.113.22   AS/组织名命中机房关键词「netlab」
  ✅  住宅节点A                  203.0.113.77   AS/组织名命中家宽运营商「verizon」
```

（上面是示意。真实节点名和 IP 每人不同，跑你自己的 `discover.sh` 看。）

判定原理（`judge-ip.py`）：

- **多源交叉**。单看 `ip-api.com` 的 `hosting` 字段会漏判——实测 NetLab（AS979，机房）
  的 `hosting` 返回 `False`，跟 Verizon 真住宅一样。所以同时查 ip-api、ipinfo、ipwho.is，
  任何一源明确说机房、或 AS/组织名命中机房关键词（dmit/netlab/cloud/hosting…）就判机房。
- **AS 名称兜底**。命中家宽运营商名（verizon/comcast/telecom/broadband…）判住宅。
- **判不准就报 UNKNOWN**，不猜。住宅是要兜 Claude 全流量的，猜错等于没防。

探测的安全性：

- Claude 规则直指节点名、完全绕过 `IPEqual` 组，所以切换 `IPEqual` **不影响 Claude 链路**
- 探测全程走 `mixed-port`，不产生任何直连
- 探测期间会临时 `bootout` 用户级 guard（否则它每 30 秒会把节点改回去，导致所有节点
  都报同一个住宅 IP —— 这个坑实测踩过），结束（含 Ctrl-C）自动恢复并切回原节点
- 多个节点报出同一个 IP 时会自动重测，排除串扰

## 前置条件

- macOS 13 或更高（用到 `sfltool`、launchd `WatchPaths`）
- Clash Verge（rev）已安装并运行，且**内核走的是 Verge 的 service 模式**（`mixed-port` 有值、`/var/run/clash-verge-service/users/<UID>/verge-mihomo.sock` 存在）
- 订阅里有一个住宅节点。**名字可以不预先知道，用 `discover.sh` 探测出来**；
  如果手工填，名字必须精确到空格、括号、中文
- 能访问 `ip-api.com` / `ipinfo.io` / `ipwho.is` 做归属判定（判定结果缓存一周，
  之后离线也能用）
- 系统 Python 3（`/usr/bin/python3`）与 `pyyaml`。没有 pyyaml 就先装：
  `/usr/bin/python3 -m pip install --user pyyaml`

不需要 sudo 就能完成全部用户级部署。只有 pf 防火墙那一层需要 root。

## 部署：四步

### 第一步，找出住宅节点并生成参数文件

```bash
bash scripts/discover.sh    # 先探测，看到底哪个节点是住宅
bash scripts/install.sh     # 再生成参数文件（会引用探测结论）
```

`install.sh` 交互式问你几个问题（住宅节点名、住宅出口 IP、VPS 入口 IP、网卡名等），
把答案写进 `~/Library/Scripts/claude-residential.env`，然后自动推导出其余参数。
第一项会问你要不要现场探测；选 Y 就调用 `discover.sh` 并采用它的结论。
**每一项都注释了查法**，不确定的项它会现场探测。

填完出口 IP 时它会立刻查一次归属：如果判定是机房，当场告警，
不会让你装完才发现走的是机房 IP。

已有的旧配置不会被覆盖，会先备份成 `.bak-<时间戳>`。
`discover.sh` 写回配置时也会先备份。

### 第二步，验证参数对不对

```bash
bash scripts/selfcheck.sh
```

它检查的是**结果**不是**配置**：真的把流量打到 `claude.ai/cdn-cgi/trace` 看出口 IP、
真的发 STUN 包看 UDP 有没有漏、真的绑物理网卡试直连能不能通。

第 2 项除了比对「出口等于你填的 EXIT_IP」，还会**查这个 IP 本身是不是住宅**。
这一项堵的是最隐蔽的失败模式：`EXIT_IP` 填成机房 IP 时，只比对一致性会全绿，
但 Claude 全程走机房。现在会直接判失败并提示你跑 `discover.sh`。

配置写对了但没生效，它一样会报错。这也是它和普通"检查配置文件"脚本的区别。

### 第三步，装自动修复

```bash
bash scripts/guard-install.sh
```

装两个东西：一个用户级 LaunchAgent（秒级响应配置变化 + 30 秒轮询兜底），
以及配套的修复脚本。不需要 sudo、不需要密码。

### 第四步，加固防火墙（需要 root，可选但强烈建议）

```bash
sudo bash scripts/harden-root.sh
```

装 pf 规则：物理网卡上禁止直连 Anthropic 网段与已知 CDN IP、禁止非白名单 DNS 出网。
**这一层是 fail-closed 的**——Verge 没运行时 Claude 是"断"而不是"漏"。

装完重启一次，再跑：

```bash
bash scripts/verify.sh
```

全绿才算真的达标。

## 排查：按症状找

| 症状 | 先查什么 |
|---|---|
| 不知道哪个节点是住宅 | `discover.sh --list`，看表里的 ✅ |
| 全绿但 Claude 明显走机房 | 跑 `selfcheck.sh`，第 2 项的归属校验会抓出来 |
| 所有节点报同一个出口 IP | guard 在探测中途把节点改回去了；`discover.sh` 已自动暂停它 |
| TCP 出口不是住宅 IP | `verify.sh` 第 1 项；再看内核规则里 Claude 规则指向谁 |
| STUN 拿到了 IP | UDP 泄漏。查 11 条 UDP REJECT 规则在不在内核里 |
| 规则数不对 | `prepend-rules` 被丢了。跑 `guard.sh` 手动触发一次 |
| 订阅更新后失效 | 看 `~/Library/Logs/claude-residential-guard.log` 有没有触发记录 |
| 重启后 Claude 连不上 | 正常——pf 在拦。等 Verge 起来后跑一次 `guard.sh` |
| 装了却完全没反应 | `launchctl print gui/$(id -u)/local.claude-residential-guard` |

每一条的具体判断命令在 `references/pitfalls.md` 的"排障"一节。

## 怎么知道它是真的在工作

不要相信"配置写好了"。只信这三个可观测结果：

```bash
# 1. 出口 IP 真的对
curl -s https://claude.ai/cdn-cgi/trace | grep '^ip='

# 2. 内核里真有那些规则（不是文件里有）
curl -s --unix-socket <SOCK> http://localhost/rules | python3 -m json.tool | grep -c REJECT

# 3. 物理网卡直连真的被拦（exit=7）
curl -s --interface en0 https://160.79.104.10/ -o /dev/null -w '%{exitcode}\n'
```

三项同时成立，才算这套东西在起作用。任何一项不成立，前面所有配置都等于没配。

## 文件说明

```
scripts/
  discover.sh         探测各节点真实出口 IP，判定哪个是住宅（先跑这个）
  judge-ip.py         单 IP 归属判定：住宅/机房，多源交叉 + 缓存
  merge-gen.py        生成 Verge 的 Merge.yaml 增强规则（同事机器上通常没有）
  install.sh          生成参数文件（交互式，带推导）
  selfcheck.sh        验证参数与结果是否吻合（含出口归属校验）
  guard.sh            核心自愈：校验内核规则，偏离就修复（内存态+文件态）
  guard-install.sh    安装/卸载 LaunchAgent
  harden-root.sh      root 加固：pf 规则 + DNS 守卫 + 看门狗
  verify.sh           全量验收（部署完成后跑）
  expand.py           把 Verge 配置展开成可热载的 mihomo payload
  lib-common.sh       公共函数（读配置、API 封装、cr_judge_ip）
  claude-residential.env.example   参数模板，每项都写了查法
references/
  pitfalls.md         踩坑记录与原理推导（重要）
```

## 把这份东西交给同事

这套东西**不是拷过去就能跑**，每人机器上有两件事必须各自做：

1. **住宅节点名和出口 IP 不同**。别抄别人的 `.env`，跑 `discover.sh` 自己测出来。
   同一个订阅在不同人手上，住宅节点大概率是同一个，但出口 IP、VPS 入口 IP
   一定要自己确认。
2. **Verge 的 `Merge.yaml` 是各机器独立的**。没这份文件，
   `prepend-rules` 就是空的 —— 9 条 Claude 规则和 11 条 UDP 封堵
   一条都进不了内核，而 `selfcheck.sh` 还会全绿。`install.sh` 现在会自动生成，
   但生成完必须去 Verge GUI 里让 `Merge` 生效（设置 → 配置 → Merge）。

给他们这三步就够：

```
bash scripts/discover.sh        # 1. 测出哪个节点是住宅
bash scripts/install.sh         # 2. 生成参数 + Merge.yaml
bash scripts/selfcheck.sh       # 3. 14 项应全过
```

然后 `guard-install.sh` 装自愈，`sudo bash harden-root.sh` 加固。四步走完。

**`selfcheck.sh` 全绿不等于走的是住宅** —— 它只是校验"实际出口 == 参数里的 IP"。
所以第 2 项会额外查一次 IP 归属，机房 IP 直接判失败。真正确认要看
`curl -x socks5h://127.0.0.1:7897 https://claude.ai/cdn-cgi/trace` 出来的 `ip=`
是不是那个住宅 IP。

**别把带个人业务规则的 `Merge.yaml` 一起发出去**。`merge-gen.py` 只生成
Claude 相关的 20 条，不生成任何 `DIRECT` 白名单 —— 那是各人自己的东西。

## 换一台机器、换一个订阅时

**换了订阅，节点名和住宅 IP 一定不同**，先跑 `discover.sh` 重新探测，
不要照抄别人的 `.env`。`install.sh` 的探测分支就是为这个场景准备的。

只有 `claude-residential.env` 需要改，所有脚本都读它。改完跑 `selfcheck.sh`，
它会逐项告诉你哪一项不对、错在哪。

如果目标机器没有 Verge 而是裸 mihomo，`guard.sh` 里的 `PUT /configs` 路径仍然适用，
但 `expand.py` 的输入不再是 Verge 的配置目录——这种情况需要按 `references/pitfalls.md`
的"非 Verge 环境"一节调整。
