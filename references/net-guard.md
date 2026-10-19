# 直连看门狗：判据、边界与误杀

`scripts/net_guard.py` 每 5 秒看一遍 Claude 相关进程的对外 TCP 连接，发现「绕过隧道」的连接就
SIGKILL 那个进程。这份文档说明它凭什么判、什么时候不会触发、以及哪些情况它会漏。

## 为什么杀进程而不是「关线程」

macOS 没有「只终止某个线程」的用户态接口（`pthread_cancel` 在内核里本来就不是强制终止）。
一个 Claude 进程的直连可能来自任意线程，能做的只有两种：杀整个进程，或者不管。
所以这里杀进程，并在日志里留下 pid、进程路径、目标地址、出口接口，事后能查。

## 判据

对每个 Claude 进程的每条已建立 / 正在发起的 TCP 连接，看**对端地址**和**到它的路由**：

| 对端 | 判定 | 动作 |
| --- | --- | --- |
| 回环、私网、链路本地、CGNAT（100.64/10） | `local` | 放行（本机代理、局域网代理都在这） |
| `198.18.0.0/15`（Clash 的 fake-ip 段） | `tunnel` | 放行 |
| 路由接口是 `utun*` / `tun*` / `ppp*` / `ipsec*` | `tunnel` | 放行 |
| 路由接口是 `en*` / `bridge*` / `awdl*` | `direct` | **SIGKILL** |
| 路由读不到 | `unknown` | 只记日志，不动手 |

`route -n get <ip>` 是本机唯一能回答「这条连接走哪个接口」的普通用户接口。
本机实测：`1.1.1.1` 走 `utun1024`（Clash TUN），所以正常流量不会被误判。

## 为什么在开了 TUN 的机器上它很少开枪

Clash TUN + `strict-route` 下，所有公网流量在 IP 层就被接管，套接字看到的路由也是 `utun`。
这时**没有**「直连」可言——看门狗不会触发，这是正常的。它真正会开枪的场景是：

- TUN 被关掉 / `strict-route` 没开，而 Claude 进程自己连公网；
- 某个进程绑定了物理网卡（`bind` 到 `en0`）或用了 `IP_BOUND_IF`；
- IPv6 有全局地址而 TUN 没接管 v6；
- 别的代理软件把 Claude 域名判成 DIRECT 且绕开了隧道（例如只配了系统代理、TUN 关着）。

注意：Clash 规则里的 `DIRECT` 出站**仍然**经过 TUN，套接字路由还是 `utun`，所以看门狗判不出来。
它回答的是「有没有绕过隧道」，不是「Clash 选了哪条规则」——后者要去看 Clash 的分流日志。

## 不误杀的几条约定

1. **不杀自己、父进程链、pid 1**；启动时把它们算进保护集合。
2. **路由读不到就不杀**（`unknown`）：宁可漏一次，不可误杀一次。
3. **每分钟最多 12 次击杀**：防止某个守护进程把 Claude 拉起来又被杀、形成循环。
4. **只认可执行路径**：`comm` 是 `claude`、`Claude Helper ...`、`~/.local/share/claude/versions/*`、
   或 node 版的 `claude-code/cli.js`。`cc-tackle`、`claude-guard`、DSH 这些名字里带 claude 的
   都被显式排除；参数里出现 `claude.ai` 的 curl 不会被误认。
5. **默认不常驻**：脚本要显式 `--install` 才装 LaunchAgent，卸载用 `--uninstall`。

## 用法

```bash
python3 scripts/net_guard.py --once --dry-run     # 只扫一次、只看不杀，先确认判据
python3 scripts/net_guard.py --dry-run            # 前台跑，每 5 秒一次，只记日志
python3 scripts/net_guard.py                      # 前台跑，发现直连就杀
python3 scripts/net_guard.py --install --yes      # 装成 LaunchAgent，常驻每 5 秒
python3 scripts/net_guard.py --status             # 看有没有在跑、日志多大
python3 scripts/net_guard.py --uninstall          # 卸载
```

日志在 `~/.local/state/claude-guard/net-guard.log`，一行一次判定：

```
2026-10-19T22:42:29+08:00 pid=25124 comm=/…/Python remote=1.1.1.1:443 iface=en0 \
  state=ESTABLISHED verdict=direct action=kill note=已终止
```

干净的一轮写 `scan clean`。`--dry-run` 把 `action` 记成 `dry-run`，不会执行 kill。

## 已知盲区

- **UDP / DNS**：只看 TCP。Claude 进程如果直接用 UDP 发 DNS，这一版看不到。
- **别的用户的进程**：普通用户看不到 root 进程的连接，需要 sudo 才能覆盖。
- **SIP 保护的进程**：SIGKILL 会被系统拒绝，日志里记为 `kill-failed`。
- **杀完就完了**：脚本不阻止重启，也不做持久化封禁；要彻底断，还是得在 Clash 侧把 Claude
  域名钉到固定出口组（这也是 `--audit` 里「绝不直连」那一项在查的东西）。
