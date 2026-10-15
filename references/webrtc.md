# WebRTC 泄漏：判据、实测与两条走不通的路

本文件由 SKILL.md 外移而来（2026-10-10）。SKILL.md 正文有字符上限，
这一节是正文里最大的一块，移出来给它腾地方；公开版对示例地址补充了脱敏说明。

先纠正一个常见误读：检测站报「WebRTC 有泄漏风险」多半是通用警告，它们压根没测。真正测的那个（browserleaks.com/webrtc）在未授权时给的是 `No Leak`，Local IP 和 Public IP 都是空的。

但确实有一条真实路径。Chrome 的 mDNS 混淆（`enable-webrtc-hide-local-ips-with-mdns`，原文「Conceal local IP addresses with mDNS hostnames」）**只在页面没有摄像头/麦克风权限时生效**——设计如此，P2P 媒体流需要真实局域网地址。实测同一台机器：

    未授权    1 个候选，mDNS 的 .local，看不到任何地址
    已授权    5 个候选，其中一条是 typ srflx，带真实公网 IP + 内网 + TUN 地址

已授权那次拿到的候选结构如下；公网地址已替换成文档保留的脱敏示例：

    candidate:2415635606 1 udp 1686052607 203.0.113.9 54364 typ srflx raddr 192.168.1.5 rport 54364 network-id 1

`203.0.113.9` 是 TEST-NET-3 保留段中的脱敏示例地址，不是实测公网出口；`raddr 192.168.1.5` 是 en0 的内网地址，`network-id 1` 指向 Wi-Fi。也就是说 **STUN 是绑在物理网卡上直发出去的，根本没进 TUN**，Clash 那几条拦 UDP 的规则看不到它——Python 侧直测 19302/3478 等端口全部超时（那些走了 TUN），浏览器这条路径照样通。判断有没有绕过，看 `raddr` 是不是内网地址比数候选个数可靠。另外 `198.18.0.0/15` 属 RFC 2544 保留段，出现它等于自报在用 Clash 类代理。

**有效开关有，但只在资料里，不在命令行。** 三样东西容易混成一件：

| 设置方式 | 实测结果 |
| :--- | :--- |
| `webrtc.ip_handling_policy`（Chrome 资料的 pref，WebRTC Network Limiter 扩展就是设它） | 有效。`disable_non_proxied_udp` 与 `default_public_interface_only` 都让候选数归 0；`default_public_and_private_interfaces` 只剩 TUN 地址 |
| `--force-webrtc-ip-handling-policy`（命令行开关） | 无效，写与不写候选数和地址一模一样 |
| `defaults write com.google.Chrome WebRtcIPHandling`（用户级企业策略） | 无效，同样毫无变化。机器级 `/Library/Managed Preferences/` 需要管理员权限，未验证 |

验证有效性的唯一办法是拿一个临时资料写进 pref，再跑一次真实 ICE 收集做对照——光看文档会把这三者的效果当成一回事，这一条我错过一次。

所以修法有几条，按优先级排：

1. **别让网站拿到权限**（Chrome 设置 → 隐私和安全 → 网站设置 → 摄像头/麦克风 → 不允许）。最彻底：授权那条路径不可达，泄漏就无从发生。
2. **在资料里设 `webrtc.ip_handling_policy`**。文章 2.5② 推荐的 Chrome 官方扩展 WebRTC Network Limiter，选「Use my proxy server (if present)」，装的其实就是这个 pref——实测本机那个资料里 `webrtc.ip_handling_policy = disable_non_proxied_udp` 正是它写进去的（扩展来自 Chrome 应用店、`disable_reasons` 为空）。所以装扩展和手工设 pref 是一回事，扩展的好处只是不用手工改文件。
3. **Firefox**：文章给的办法是在 `about:config` 里把 `media.peerconnection.enabled` 改成 `false`。这条没有在本机实测过（本机用 Chrome），照文章记下来；原理是把整个 WebRTC 关掉，代价同样是网页视频通话用不了。

代价要说清楚：任何有效设置都会让网页视频通话建不起来（候选数为 0，P2P 建立不了），**可用性和不泄漏在这个网络结构下不可兼得**，所以要按资料分别决定，别一刀切。

复核这一项要用户配合：脚本读不了 Chrome 的资料文件（TCC 挡着 `open()`），所以 `--check-media` 起一个本地页面，让用户在他真实的浏览器里打开，页面把权限状态 POST 回来并缓存到 `~/.local/state/claude-guard/media-permission.json`。**必须用那个资料打开**，用别的资料读到的是别的资料的权限。顺带一个已经踩过的坑：用 sudo 跑过之后这个状态目录可能是 root 的，写入会静默失败（`except OSError: pass` 吞掉），所以 `hand_back_ownership()` 会在 sudo 之下把属主交还给 `SUDO_UID`。

这里面有个坑值得记下来：**探测用哪个浏览器会决定结论真假**。同样给了媒体权限，headless shell 只给 1 个候选、看不到任何 IP，完整 Chromium 给 4 个、露出真实地址。也就是说用 headless shell 测，「授权后会不会露」这个问题永远答「不会」——一个看起来干净的假阴性。所以 `find_chromium()` 现在把完整版排在前面，结果里也会标明用的是哪个。

（曾试过把 TUN 地址从 `198.18.0.1` 换成普通的 `172.19.0.1`，让泄漏出来的地址不那么显眼。写了 `tun.inet4-address` 但 mihomo 在配置重载时不重建 TUN 接口，要生效得重启内核；而重启后接口地址与 fake-IP 段不在同一网段，可能影响 fake-IP 路由。这个改动只在「已经授权、真实内网 IP 也一起漏」的场景下才有意义，收益不值这个险，已回滚。）

## 把 WebRTC Network Limiter 装上

文章 2.5② 推的那个扩展就是 Google 官方的 **WebRTC Network Limiter**，商店里查得到的 ID 是 `npeicpdbkakmehahjeeohfdhnlpdklia`，主页：

```
https://chromewebstore.google.com/detail/npeicpdbkakmehahjeeohfdhnlpdklia
```

本 skill 能把扩展包直接下到本机：

```
python3 scripts/account_guard.py --install-webrtc-limiter
```

这条命令做三件事：先报本机每个 Chrome 资料里装没装、设置对不对；再把扩展包下到 `~/.local/state/claude-guard/extensions/`；最后在声明的资料里把商店页打开。装的那一下仍然要你点——**Chrome 在 macOS 上不接受脚本代装扩展**，这一条不是没做，是做不到。

### 下下来的包怎么确信是它

包走的是商店自己的分发接口，不是第三方镜像：

```
https://clients2.google.com/service/update2/crx?response=redirect
  &prod=chromiumcrx&prodversion=<本机 Chrome 版本>&acceptformat=crx2,crx3
  &x=id%3D<扩展 ID>%26installsource%3Dondemand%26uc
```

`prod=chromiumcrx`、`x=` 里那串 id 与 installsource 一个都不能少，少一个服务端回的是商店页面而不是包（实测：返回 302 加一段 HTML）。

下到之后按三道核：`Cr24` 魔数加版本头 → 包里 zip 的 `manifest.json` 能读出来且 `update_url` 指向商店 → **签名块里的公钥算出来的扩展 ID 与申请时那个一致**。第三道是最硬的：扩展 ID 本来就是发布者公钥的 SHA-256 前 16 字节按 `a`–`p` 映射出来的，名字能在 manifest 里随便改，ID 改不了。商店下发的包里有两块签名（Google 的商店密钥和发布者密钥），只有发布者那块对得上，所以两块都算、命中一块即认。

2026-10-15 实机下到的：`0.2.1.4`（manifest v3），11439 字节，sha256 `3a4205af59c2df0d…`。

### 怎么知道已经装上了

读每个资料的 `Secure Preferences`（不是 `Preferences`——实测同一个资料的 `Preferences` 里 `extensions.settings` 是空的，带 MAC 保护的扩展设置在这个文件里），看 `extensions.settings.<ID>` 在不在、`preferences` 里的 `webrtc.ip_handling_policy` 是不是 `disable_non_proxied_udp`。

macOS 的 TCC 可能不让脚本读另一个 App 的资料目录（本机从 DSH 里跑就是 `Operation not permitted`，双击终端跑则通常可以）。**读不到时报「读不到」，不报「没装」**——这两件事不一样。

### 想彻底免手工

唯一能无人值守装上的路子是机器级策略，代价是浏览器从此显示「由组织管理」、这个扩展你自己也卸不掉：

```
sudo defaults write "/Library/Managed Preferences/com.google.Chrome" \
    ExtensionInstallForcelist -array "npeicpdbkakmehahjeeohfdhnlpdklia;https://clients2.google.com/service/update2/crx"
```

要不要吃这个代价由你决定，体检脚本不替你决定。没网或下不动时的后备：把下下来的 `.crx` 拖进 `chrome://extensions/`（先打开右上角的开发者模式）。

装完记得：它只是把 `webRTCIPHandlingPolicy` 设成 `disable_non_proxied_udp`，**网页视频通话从此建不起来**，而且这个设置是按资料生效的，别的资料要单独装。要按需决定，别一刀切。
