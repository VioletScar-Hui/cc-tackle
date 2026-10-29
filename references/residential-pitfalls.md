# 踩坑记录与原理推导

这份文档是整个方案里最值钱的部分。脚本谁都能照着写，但这些坑每一条都是花了几个小时才弄明白的。
按"你会遇到它的顺序"排列。

---

## 一、四个必须分开理解的层次

很多人第一次搭这个东西会以为"配个规则就行"。实际上有四层，任何一层没对上，链路就是漏的。

### 第 1 层：Verge 的 GUI 配置（你编辑的）

`~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/profiles/Merge.yaml`

这是 Clash Verge 的"增强配置"，里面可以写 `prepend-rules`、`prepend-proxy-groups`、`append-rules` 等
Verge 专有字段。**mihomo 内核不认这些字段。**

### 第 2 层：中间产物（Verge 生成的）

同目录下的 `clash-verge.yaml`。Verge 把订阅 + 增强配置合并后写在这里。

**关键：内核不读这个文件。** 但 Verge 重启时会从这里重新生成运行时配置，所以它必须是对的。

### 第 3 层：内核真正读的配置（root 属主）

```
/var/run/clash-verge-service/users/<UID>/runtime/config.yaml
```

root 属主，普通用户读不了。要看实际生效的规则，不要读文件，走 API：

```bash
curl -s --unix-socket /var/run/clash-verge-service/users/$(id -u)/verge-mihomo.sock \
  http://localhost/rules | python3 -m json.tool
```

### 第 4 层：实际网络行为

规则对了不等于流量真的走了。必须实测出口 IP、实测 UDP 是否漏。

**这四层的对应关系是整件事的核心难点：**

| 你改的 | 影响第 2 层 | 影响第 3 层 | 需要什么操作 |
|---|---|---|---|
| Merge.yaml | 是（下次生成时） | 否 | 让 Verge 重新生成 + 重启内核 |
| clash-verge.yaml | — | 否 | 让 Verge 重启内核 |
| `PUT /configs` | 否 | **是**（立即） | 无，即时生效 |
| 订阅更新 | 覆盖 | 覆盖 | 无，但会把你改的冲掉 |

**所以修复必须同时做两件事：`PUT /configs` 修内存态，重写 `clash-verge.yaml` 修文件态。**
只做前者，下次 Verge 重启从文件重新生成，规则又没了。
只做后者，当前这一刻内核还在跑旧配置，泄漏继续。

这是 `guard.sh` 里为什么那段代码看起来重复的原因。

---

## 二、`prepend-rules` 到底会不会被展开

**结论：会，但不是每次都可靠，所以不要依赖它。**

实测证据（Verge 2.5.8）：

- `profiles/sZph4wf4tvkG.js` 里只有一个 `function main(config){return config}`，什么都不做
- `profiles/rrfgseK3Gfn7.yaml` 的 `prepend`/`append`/`delete` 全为空
- 但 Merge.yaml 里写的 4 条 `DIRECT` 规则，确实出现在了 `clash-verge.yaml` 的 `rules` 里
  （订阅 25 条 → `clash-verge` 44 条）

说明 Verge 生成配置时会展开 `prepend-rules`。但**"会展开"不等于"永远展开"**——
订阅更新、版本升级、配置重新加载都可能走不同的代码路径。

所以脚本的立场是：**不赌它展开。自己展开，然后校验内核里到底有没有。**

`expand.py` 做的就是这件事：读 Merge.yaml 的 `prepend-rules`，手工合并进 `rules`，
再通过 `PUT /configs` 热载。

### 规则目标的陷阱

`expand.py` 里有一个容易被忽略的校验：**规则引用的目标必须真实存在**。

历史事故：Merge 里写了 `DOMAIN-SUFFIX,claude.ai,Claude`，指向一个叫 `Claude` 的组。
但订阅里没有这个组（或者组被删了）。mihomo 遇到不存在的目标会**整份配置拒绝加载**，
而不是跳过那一条。结果就是"看起来配了，实际一条都没生效"。

现在 `expand.py` 会在写入前检查每条规则的目标，不合法就报错并拒绝写入，
把问题暴露在部署阶段而不是运行时。

---

## 三、UDP 泄漏：为什么"修"不了，只能封

这是整个方案里最反直觉的一点。

### 现象

即使 TCP 全部走住宅节点、出口 IP 完全正确，WebRTC 的 STUN 探测仍然能拿到一个 IP。
而且那个 IP **不是住宅出口 IP，是 VPS 入口 IP**。

### 原因

mihomo 的 TUN 接管的是 TCP 和部分 UDP，但 WebRTC 走的 UDP 在多数配置下会绕过代理规则，
直接以本机网络出口出去——而本机在 VPS 的 NAT 后面，所以外部看到的就是 VPS 入口 IP。

这不是"配置错了"，这是**这条链路的固有拓扑限制**：住宅节点的 UDP 落地在 VPS 上，
进不了住宅线路。

### 所以怎么办

**封掉，而不是"修好"。** 因为客户端侧无法让 UDP 走住宅线路。

规则是 11 条（数量随参数变化）：

```
4 条  域名 UDP REJECT      claude.ai / claude.com / anthropic.com / claudeusercontent.com
3 条  CDN IP UDP REJECT    这些 IP 在 Anthropic 网段外，域名规则拦不住裸 IP 访问
1 条  v4 网段 UDP REJECT   160.79.104.0/21
3 条  STUN 端口 UDP REJECT 3478 / 5349 / 19302-19309
```

**为什么必须按端口封 STUN：**
只封 Claude 域名是不够的。WebRTC 不需要访问 Claude 就能探测你的出口——
它会去找 `stun.l.google.com`。只封域名的话，STUN 照样能问出 VPS IP。

这一条如果漏了，前面所有工作都白做。`selfcheck.sh` 的第 3 项就是专门测这个。

### 验证方法

```bash
# 正确结果：无输出（UDP 被封死，STUN 拿不到回包）
python3 -c "
import socket, struct, os
pkt = struct.pack('!HHI', 1, 0, 0x2112A442) + os.urandom(12)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(4)
u.sendto(pkt, (socket.gethostbyname('stun.l.google.com'), 19302))
print(u.recvfrom(2048))
" 2>&1

# 如果拿到了 IP，就是漏了。看那个 IP 是 VPS 入口还是真实 IP，都要处理。
```

---

## 四、重启恢复：分三层，结论不同

很多人会问"重启后还要重新弄吗"。答案分三层：

### pf 层：全自动

系统自带 `/System/Library/LaunchDaemons/com.apple.pfctl.plist`，`RunAtLoad=true`，
开机执行 `pfctl -f /etc/pf.conf`。只要 `/etc/pf.conf` 里有：

```
anchor "claude-residential"
load anchor "claude-residential" from "/etc/pf.anchors/claude-residential"
```

重启后防火墙立即生效。**这一层是 fail-closed 的**——
Verge 还没起来时，Claude 是"断"而不是"漏"。这是设计上的正确行为，不是故障。

### 内核规则层：依赖 Verge 启动

规则在 mihomo 内核里，内核没跑就没有规则。所以这部分依赖 Verge 开机自启。

两个设置都要检查：

```bash
# Verge 配置文件（enable_auto_launch 必须是 true）
grep -E 'enable_auto_launch|enable_silent_start' \
  "$HOME/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/verge.yaml"
```

`enable_silent_start: false` 意味着开机会弹窗，需要人点。建议改成 `true`。

### 自愈层：登录后自动

LaunchAgent 的 `RunAtLoad` + `WatchPaths` + `StartInterval 30` 组合，
登录后自动跑，并且持续盯着。

### 完整重启时间线

```
开机
 → pf 生效（Claude 全断，这是对的）
 → 登录
 → Verge 自启，拉内核
 → guard 等内核（最多 90 秒）
 → 内核就绪后 1 秒内补齐规则
 → 链路恢复
```

**注意 guard 里那个"等 90 秒"的逻辑**：launchd 的 `RunAtLoad` 可能比内核先起。
如果 socket 不存在就直接退出，这次检查就白跑了，得等下一个 `StartInterval`（30 秒）。
所以它选择等——内核一起来就继续，比干等下一轮快得多。

---

## 五、不要碰的东西

### 不要改 Claude.app 的包

改包会破坏 Developer ID 签名（`Developer ID Application: Anthropic PBC (Q6L2SF6YDW)`），
而且每次自动更新都会还原。全部问题都该在网络层和内核层解决。

### 不要做 wrapper

同理。任何"启动前先检查/切换"的包装脚本都会带来新的失效点，
而且会被应用更新绕过。

### 不要用 `pfctl -f /etc/pf.conf` 做自愈

整表重载会刷掉 Surge、Proxyman 这类软件运行时动态插入的 anchor 规则。
正确做法是只替换自己那一段：

```bash
pfctl -a claude-residential -f /etc/pf.anchors/claude-residential
```

---

## 六、CDN IP 的判断标准

Claude 的部分资产不在 Anthropic 自有网段（`160.79.104.0/21`）里，
而是托管在 Google Cloud 的 LB 上。这些要靠单独列表拦住。

**关键：只收 Anthropic 专用的，共享前端不要收。**

```bash
# 查法：看这些域名解析到哪
dig +short a-cdn.anthropic.com assets.claude.ai downloads.claude.ai
```

如果某个 IP 同时托管着其它站点，加进去会误伤那些站点的正常访问。
判断方法：

```bash
# 看证书里有几个域名
echo | openssl s_client -connect 34.54.194.141:443 -servername s-cdn.anthropic.com 2>/dev/null \
  | openssl x509 -noout -text | grep DNS:
```

实测 `s-cdn.anthropic.com` → `34.54.194.141`，同 IP 还有 `gr4vy`、`hexagon-cdn`。
**这种就不该加。** 加进去会把无关流量也拦掉。

---

## 七、排障：按症状找

### TCP 出口不是住宅 IP

```bash
# 1. 现在实际走的是哪个节点
curl -s --unix-socket <SOCK> http://localhost/connections \
  | python3 -c "import sys,json;[print(c['chains']) for c in json.load(sys.stdin)['connections'][:5]]"

# 2. 内核里 Claude 规则指向谁
curl -s --unix-socket <SOCK> http://localhost/rules \
  | python3 -c "
import sys,json
for r in json.load(sys.stdin)['rules']:
    p=(r.get('payload') or '').lower()
    if 'claude' in p or 'anthropic' in p: print(r['type'], r['payload'], '->', r['proxy'])
"
```

如果规则指向一个组而不是节点名，说明规则没展开成功。

### 规则数量不对

跑 `bash guard.sh --verbose`，看它报的期望值和实际值差多少。

差值是 4 的倍数 → 域名规则全丢了
差值等于 CDN IP 数量 → CDN 规则丢了
差值等于 STUN 端口数量 → 端口规则丢了

### 订阅更新后失效

```bash
tail -50 ~/Library/Logs/claude-residential-guard.log
```

正常应该看到 `!! 偏离` 之后跟着 `修复成功`。如果完全没有触发记录，
检查 `WatchPaths` 里的路径对不对。

### 重启后 Claude 连不上

这是**正常的**。pf 在拦。等 Verge 起来后：

```bash
bash ~/Library/Scripts/claude-residential-guard.sh --verbose
```

如果一直不恢复，看 Verge 有没有真的起来：

```bash
pgrep -fl verge-mihomo
ls -la /var/run/clash-verge-service/users/$(id -u)/
```

### LaunchAgent 装了但没反应

```bash
launchctl print gui/$(id -u)/local.claude-residential-guard
```

看 `state` 和 `last exit code`。`last exit code` 非 0 就去看日志。

**一个容易踩的坑：** `sfltool dumpbtm` 显示 `[disabled, allowed, not notified]`，
但这不代表真的被禁用。`launchctl print-disabled gui/$(id -u)` 才是权威。
实测这两个可能不一致，以后者为准。

### DNS 守卫起不来

端口 53 可能被别的 DNS 占用：

```bash
sudo lsof -nP -iUDP:53
```

占用者是 `mDNSResponder` 是正常的（它只在特定地址上监听）。
如果是别的程序，要么停掉它，要么把守卫换到别的端口并改系统 DNS 指向。

---

## 八、非 Verge 环境

这套脚本默认用 Clash Verge 的配置布局。如果目标机器是裸 mihomo：

- `expand.py` 的输入不再是 Verge 目录，需要改成读你的 mihomo 配置文件
- `guard.sh` 的 `PUT /configs` 依然适用（mihomo 的 RESTful API 是一样的）
- `WatchPaths` 要改成监听你自己的配置文件路径
- `MERGE` 变量的语义要换（没有 Merge.yaml 这层了）

其余部分（pf 加固、DNS 守卫、UDP 封堵思路）完全通用。

---

## 九、怎么确定哪个节点才是住宅（最隐蔽的一个坑）

### 现象

选错节点，整套方案**全绿通过**，但 Claude 全程走机房 IP。

原因是 `selfcheck.sh` 原先只验证「出口 IP == 你填的 EXIT_IP」。
这是*一致性*校验，不是*性质*校验。填一个机房 IP 进去，两项自然吻合，
13 项全过，什么都不会报。

### 为什么不能靠节点名判断

节点名是订阅服务商起的，没有任何约束：

- 真住宅可能叫 `(赠送)美国CN2专线娱乐节点`（名字里一个"住宅"字都没有）
- 机房也可能叫 `高仿住宅IP`
- 同一份订阅里，同类节点命名风格还可能不一致

实测某订阅 13 个节点，只有 1 个名字带"住宅"，其余全叫 `(赠送)XX专线娱乐节点`。

### 为什么单源查 IP 归属也会错

实测三个 IP 的判定，`ip-api.com` 的 `hosting` 字段：

| IP | AS | `hosting` | 真实性质 |
|---|---|---|---|
| 美国住宅样本 | AS701 Verizon Business | `false` | 住宅 ✅ |
| 某中转机房 | AS979 NetLab Global | **`false`** | 机房 ❌ |
| 某 VPS 入口 | AS906 DMIT Cloud | `true` | 机房 ❌ |

**第二行是关键：NetLab 那个被漏判了。** 单靠 `hosting` 会把机房当住宅放过去。

### 解法：多源交叉，宁可否决

`judge-ip.py` 同时查 ip-api / ipinfo / ipwho.is，按这个顺序判：

1. 任何一源明确 `hosting=True` → 机房
2. AS / 组织名命中机房关键词（dmit/netlab/cloud/hosting/datacenter…）→ 机房
3. 命中家宽运营商名（verizon/comcast/telecom/broadband/cable/fiber…）→ 住宅
4. 都没命中 → `UNKNOWN`，**不猜**

关键词表要注意别放 `net`、`cloud` 这种太宽的词 —— Verizon Business 会被误伤。
命中机房关键词时还额外检查有没有同时命中家宽关键词，有的话不下机房结论。

第 4 条是关键：住宅要用来兜 Claude 全流量，判不准就得人来定，
不能让脚本默认放行。

### 探测时的两个实现陷阱

**陷阱一：不能用 `claude.ai` 当探测点。**

Claude 规则直指节点名、完全绕过 `IPEqual` 组。所以切换 `IPEqual` 之后去测
`claude.ai/cdn-cgi/trace`，拿到的永远是住宅节点的 IP —— 不管实际切到了哪个节点。
实测第一版 `discover.sh` 因此让 11 个节点全部返回同一个住宅 IP。

探测点必须用**走 `MATCH -> IPEqual` 的中立域名**：`api.ipify.org` / `icanhazip.com` /
`ifconfig.me/ip`。

**陷阱二：guard 会在探测中途把节点改回去。**

`local.claude-guard-user` 每 30 秒把 `IPEqual` 改回钉住的住宅节点 —— 这是它该做的事。
但探测要连续切好几个节点，一旦 guard 插进来，切上去的节点 10 秒内就被改回，
后续探测拿到的全是住宅 IP。

实测现象：某节点第一次返回机房真 IP，后两次都变回住宅 IP。

所以 `discover.sh` 探测前 `launchctl bootout` 用户级 guard，用 `trap` 保证
（含 Ctrl-C / Ctrl-Z 中断）退出时 `bootstrap` 回来并切回原节点。
只动用户级 guard，不碰 root 侧的 pf / DNS 守卫 —— 那两层不参与探测。

**陷阱三：部分订阅节点会 SSL 握手失败。**

`curl` 返回 `EXIT 35`，换探测域名也没用，是节点自身的问题。
这种情况记为「不通」，不要当成「住宅」也不要当成「机房」——
它只是没法判定。`discover.sh` 会自动重试两轮再下结论。

**陷阱四：多个节点偶尔报出同一个 IP。**

赠送节点抽风时会连到主节点上，导致它和住宅节点报同一个出口。
这种不能直接当成"又一个住宅节点"。`discover.sh` 对重复 IP 的节点自动重测一次，
仍取不到就标为不通。

### 怎么复核

```bash
# 单个 IP 的判定依据（不只看结论，看它凭什么这么判）
python3 scripts/judge-ip.py --json 203.0.113.22

# 全节点探测，不写配置
bash scripts/discover.sh --list
```

判定结果缓存在 `~/Library/Caches/claude-residential/`，一周有效，
所以同一台机器上重复跑不会反复请求免费 API。

---

## 十、`Merge.yaml` 不在，整套方案静默失效

这是发给同事时最容易翻车的一点，比节点选错更隐蔽。

**现象**：`selfcheck.sh` 14 项全过，`guard.sh --check` 也报"正常"，
但 Claude 实际走的不是住宅 IP —— 或者更常见的是，规则压根没进内核。

**为什么**：`clash-verge.yaml` 里那个 `prepend-rules` 字段是 Verge 的产物，
来源是 `profiles/Merge.yaml`。这份文件属于**每台机器各自**的 Verge 配置，
跟着订阅走、不跟着脚本走。新人装好 Verge、导入订阅，`Merge.yaml` 是不存在的。

`expand.py` 只**读**它，不会**写**它：

```python
merge = {}
if os.path.exists(merge_p):          # 不存在就留空
    merge = yaml.safe_load(f) or {}
pre_rules = merge.get("prepend-rules") or cfg.pop("prepend-rules", []) or []
```

`prepend-rules` 为空 → 展开出来的 payload 里没有那 20 条 → 内核只加载订阅自带的
`MATCH,IPEqual`。而 `IPEqual` 是个 12 成员的可切换组，正好是这套方案要防的东西。

`guard.sh` 原来遇到这种情况只能说"无备份可用，需重新写入"然后 `exit 1` ——
把活留给一个不知道该怎么办的人。

**现在**：`merge-gen.py` 按参数文件生成。`install.sh` 检测到没有就自动写，
`guard.sh` 无备份时也调它重建。生成的数量由参数推导，和 `guard.sh` 的
`EXPECT_UDP` / `EXPECT_CLAUDE` 用同一套公式：

```
UDP REJECT      = 域名 + CDN + ANTHROPIC_V4 + STUN端口   （不含 v6）
Claude 指向住宅  = 域名 + CDN + ANTHROPIC_V4 + ANTHROPIC_V6
```

两个坑记在这里：

- **IPv6 必须写 `IP-CIDR6`**，写成 `IP-CIDR,2607:6bc0::/32` 内核不认，那条规则等于没写。
- **UDP 段不含 v6**。现有 11 条是 4 域名 + 3 CDN + 1 个 v4 网段 + 3 个端口段。
  多算一条就会被 `guard.sh` 判成"偏离"，然后它每次运行都试图"修复"，陷入循环。

**生成完还有一步不能省**：去 Verge GUI 里让这份 Merge 生效
（设置 → 配置 → Merge → 选中）。文件写在那儿不等于 Verge 会用它。

**别把带个人业务规则的 Merge.yaml 发出去**。本机这份除了 20 条 Claude 规则，
还有四条 `DIRECT` 白名单（业务域名）。那些是个人配置，不属于这套方案。
`merge-gen.py` 只生成 Claude 相关的部分，这也是它比"拷文件"更该用的原因。

---

## 十一、这套方案不解决的问题

诚实地列出来，避免给人错误预期：

- **节点本身的安全性**：住宅 IP 是好，但出口在别人机器上。流量对节点所有者是可见的（除非端到端加密）。
- **VPS 入口暴露**：TCP 握手的目标 IP 是 VPS。这不影响 Claude 看到的来源，但对路径上的观察者可见。
- **应用层反检测**：这套东西只管网络路径。Claude 服务端如果从行为特征判断，这套方案管不了。
- **多用户共享同一出口**：如果团队都用同一个住宅节点，在服务端看来是同一个 IP。这会带来别的问题。
