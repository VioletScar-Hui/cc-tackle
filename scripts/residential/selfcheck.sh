#!/bin/bash
# Claude 住宅链路 —— 参数与结果自查
#
# 检查的是"结果对不对"，不是"配置写没写"。
# 每一项都实测：出口 IP 真的打过去看、UDP 真的发 STUN 看回包、
# 直连真的绑物理网卡试。所以它不会因为配置写对而误报通过。
#
# 特别注意第 2 项：不只比对"出口 IP 是不是等于你填的 EXIT_IP"，
# 还要查这个 IP 本身是不是住宅。因为 EXIT_IP 是你自己填的，
# 填一个机房 IP 进去，只比对一致性会全绿但 Claude 全程走机房。
#
# 用法：bash selfcheck.sh [--no-asn]
#   --no-asn  跳过 IP 归属查询（离线/被限速时用，该项会记为跳过）

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib-common.sh
. "$SCRIPT_DIR/lib-common.sh"

SKIP_ASN=0
[ "${1:-}" = "--no-asn" ] && SKIP_ASN=1

cr_load_env

echo "参数文件：$ENV_FILE"

cr_head "0. 参数自洽"
[ "$EXIT_IP" != "$VPS_IP" ] \
  && cr_ok "出口 IP 与 VPS IP 不同（正常拓扑）" \
  || cr_bad "EXIT_IP 等于 VPS_IP —— 你以为的住宅出口其实是 VPS"
cr_sock_ready && cr_ok "mihomo socket 存在" \
  || cr_bad "socket 不在：${SOCK}（mihomo 没跑？）"
[ -d "$VERGE_DIR" ] && cr_ok "Verge 配置目录存在" \
  || cr_bad "Verge 配置目录不在：$VERGE_DIR"
if [ ${#CR_IFACES[@]} -gt 0 ] && /sbin/ifconfig "${CR_IFACES[0]}" >/dev/null 2>&1; then
  cr_ok "首个物理网卡 ${CR_IFACES[0]} 存在"
else
  cr_bad "物理网卡 ${CR_IFACES[0]:-（空）} 不存在 —— 检查 PHYS_IFACES"
fi

if ! cr_sock_ready; then
  echo
  echo "════════ 结果：$CR_PASS 通过 / $CR_FAIL 失败 ════════"
  echo "内核没跑，后续项无法检测。先启动 Clash Verge。"
  exit 1
fi

cr_head "1. 住宅节点存在"
if cr_api /proxies | CR_NODE="$RESIDENT_NODE" /usr/bin/python3 -c '
import os, sys, json
d = json.load(sys.stdin).get("proxies") or {}
sys.exit(0 if os.environ["CR_NODE"] in d else 1)
' 2>/dev/null; then
  cr_ok "节点「${RESIDENT_NODE}」在订阅里"
else
  cr_bad "节点「${RESIDENT_NODE}」不在订阅里 —— 检查名字是否完全一致（含空格/括号/中文）"
fi

cr_head "2. TCP 出口 = 住宅 IP"
TRACE=$(/usr/bin/curl -s --max-time 15 https://claude.ai/cdn-cgi/trace 2>/dev/null)
TCP_IP=$(printf '%s' "$TRACE" | /usr/bin/awk -F= '/^ip=/{print $2}')
LOC=$(printf '%s' "$TRACE" | /usr/bin/awk -F= '/^loc=/{print $2}')
[ "$TCP_IP" = "$EXIT_IP" ] && cr_ok "TCP 出口 = $EXIT_IP" \
  || cr_bad "TCP 出口 = ${TCP_IP:-取不到}，期望 $EXIT_IP"
[ "$TCP_IP" = "$VPS_IP" ] && cr_bad "TCP 出口是 VPS IP —— 链路没走到住宅"

# 关键一项：实际出口是不是住宅。
# 上面那条只验证"出口等于你填的值"，如果你填的是机房 IP，
# 它照样通过。这一项不看参数，只看实际落地的归属。
if [ "$SKIP_ASN" -eq 1 ]; then
  cr_warn "跳过 IP 归属校验（--no-asn）—— 无法确认这个出口是不是住宅"
elif [ -n "${TCP_IP:-}" ]; then
  VERDICT=$(cr_judge_ip "$TCP_IP")
  case "$VERDICT" in
    RESIDENTIAL)
      cr_ok "出口 $TCP_IP 判定为住宅（$(cr_judge_reason "$TCP_IP")）" ;;
    DATACENTER)
      cr_bad "出口 $TCP_IP 是机房 IP，不是住宅！$(cr_judge_reason "$TCP_IP")"
      cr_bad "　→ 这个 EXIT_IP 填错了。跑 discover.sh 重新探测真正的住宅节点" ;;
    *)
      cr_warn "出口 $TCP_IP 归属判不准 —— $(cr_judge_reason "$TCP_IP")"
      cr_warn "　→ 人工确认后再用；判不准就不要当住宅用" ;;
  esac
else
  cr_warn "取不到出口 IP，无法校验归属"
fi

# 住宅 IP 的 Cloudflare loc 应为 US。非 US 通常说明落在了别的地区，属于提示级。
[ -n "$LOC" ] && { [ "$LOC" = "US" ] || cr_warn "出口地区 = ${LOC}（住宅 IP 通常应显示 US）"; }

cr_head "3. UDP 不得泄漏"
# 关键：本机 UDP 若走 VPS NAT，出口就是 VPS_IP，必须封死而不是"修好"。
STUN=$(/usr/bin/python3 - <<'PY' 2>/dev/null
import socket, struct, os
def stun(host, port=19302, t=4):
    pkt = struct.pack('!HHI', 1, 0, 0x2112A442) + os.urandom(12)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(t)
    u.sendto(pkt, (socket.gethostbyname(host), port))
    r, _ = u.recvfrom(2048); i = 20
    while i + 4 <= len(r):
        ty, l = struct.unpack('!HH', r[i:i+4]); v = r[i+4:i+4+l]
        if ty in (0x20, 1) and v[1] == 1:
            raw = v[4:8]
            if ty == 0x20:
                raw = bytes(a ^ b for a, b in zip(raw, struct.pack('!I', 0x2112A442)[:4]))
            return socket.inet_ntoa(raw)
        i += 4 + l + ((4 - l % 4) % 4 if l % 4 else 0)
    return None
for h in ('stun.l.google.com', 'stun.cloudflare.com'):
    try:
        ip = stun(h)
        if ip:
            print(ip); break
    except Exception:
        pass
PY
)
if [ -z "$STUN" ]; then
  cr_ok "STUN 无回包，UDP 已封（WebRTC 不会漏）"
elif [ "$STUN" = "$EXIT_IP" ]; then
  cr_warn "STUN 拿到 $STUN = 住宅出口，UDP 也走在住宅上（理想状态）"
else
  cr_bad "STUN 拿到 $STUN —— UDP 在漏，WebRTC 会暴露这个 IP"
fi

cr_head "4. Claude 规则直指住宅节点"
read -r HST UD CL FI <<<"$(cr_rule_health)"
EXPECT_UDP=$(( ${#CR_DOMAINS[@]} + ${#CR_CDNS[@]} + 4 ))
EXPECT_CLAUDE=$(( ${#CR_DOMAINS[@]} + ${#CR_CDNS[@]} + 2 ))
[ "${HST:-ERR}" = "ERR" ] && cr_bad "读不到内核规则" || {
  [ "$UD" -ge "$EXPECT_UDP" ] && cr_ok "$UD 条 UDP REJECT 规则（需 ${EXPECT_UDP}）" \
    || cr_bad "只有 $UD 条 UDP REJECT（需 ${EXPECT_UDP}）—— UDP 会漏"
  [ "$CL" -ge "$EXPECT_CLAUDE" ] && cr_ok "$CL 条 Claude 规则直指住宅（需 ${EXPECT_CLAUDE}）" \
    || cr_bad "只有 $CL 条 Claude 规则指向住宅（需 ${EXPECT_CLAUDE}）—— 检查 Merge 是否被展开"
  [ "$FI" -eq 1 ] && cr_ok "首条 Claude 规则指向住宅（未被订阅规则抢占）" \
    || cr_bad "首条 Claude 规则被别的规则抢占了 —— 顺序错了"
}

cr_head "5. 无 fallback / 自动切换"
FB=$(cr_api /proxies | CR_NODE="$RESIDENT_NODE" /usr/bin/python3 -c '
import os, sys, json
node = os.environ["CR_NODE"]
ps = (json.load(sys.stdin).get("proxies") or {})
bad = []
for name, v in ps.items():
    if v.get("type") not in ("Fallback", "URLTest", "LoadBalance"):
        continue
    if node in (v.get("all") or []):
        bad.append(name)
print(",".join(bad))
' 2>/dev/null)
[ -z "$FB" ] && cr_ok "无 fallback/url-test/load-balance 组引用住宅节点" \
  || cr_bad "这些组引用住宅节点且会自动切换：$FB"

cr_head "6. 自动更新已关"
[ "$(/usr/bin/defaults read com.anthropic.claudefordesktop SUAutomaticallyUpdate 2>/dev/null)" = "0" ] \
  && cr_ok "桌面版自动更新 = off" \
  || cr_warn "桌面版自动更新未关（会从网络拉安装包，属于直连）"
CLI_UPDATE=$(/usr/bin/python3 -c "
import json, os
p = os.path.expanduser('~/.claude/settings.json')
try:
    print((json.load(open(p)).get('env') or {}).get('DISABLE_AUTOUPDATER', ''))
except Exception:
    print('')
" 2>/dev/null)
[ "$CLI_UPDATE" = "1" ] && cr_ok "CLI DISABLE_AUTOUPDATER = 1" \
  || cr_warn "CLI 自动更新未关（在 ~/.claude/settings.json 的 env 里设 DISABLE_AUTOUPDATER=1）"

echo
echo "════════ 结果：$CR_PASS 通过 / $CR_FAIL 失败 / $CR_WARN 警告 ════════"
if [ "$CR_FAIL" -eq 0 ]; then
  echo "参数与结果吻合 ✅"
  [ "$CR_WARN" -gt 0 ] && echo "有 $CR_WARN 项警告，不致命但建议处理。"
  exit 0
fi
echo "有 $CR_FAIL 项会导致 Claude 流量不走住宅，需修。"
exit 1
