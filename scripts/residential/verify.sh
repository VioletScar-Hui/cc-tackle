#!/bin/bash
# Claude 住宅链路 —— 全量验收
#
# selfcheck.sh 验的是"参数与结果吻合"，verify.sh 验的是"整套防线都在"。
# 部署完成后跑这个：全绿才算真的达标。
#
# 用法：bash verify.sh [--quick]
#   --quick  跳过耗时的多域名逐个追踪（第 4 节）

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib-common.sh
. "$SCRIPT_DIR/lib-common.sh"
cr_load_env

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

# 本机 mixed-port 从内核配置读，不写死
MIXED=$(cr_api /configs | /usr/bin/python3 -c \
  'import sys,json;print(json.load(sys.stdin).get("mixed-port") or 7897)' 2>/dev/null)
: "${MIXED:=7897}"

if ! cr_sock_ready; then
  echo "内核没跑（${SOCK}），先启动 Clash Verge。"
  exit 1
fi

cr_head "1. 出口 IP"
TRACE=$(/usr/bin/curl -s -x "socks5h://127.0.0.1:$MIXED" --max-time 20 \
  'https://claude.ai/cdn-cgi/trace' 2>/dev/null)
IP=$(printf '%s' "$TRACE" | /usr/bin/awk -F= '/^ip=/{print $2}')
LOC=$(printf '%s' "$TRACE" | /usr/bin/awk -F= '/^loc=/{print $2}')
[ "$IP" = "$EXIT_IP" ] && cr_ok "Claude 出口 = $IP" \
  || cr_bad "Claude 出口 = ${IP:-无响应}（期望 ${EXIT_IP}）"
[ -n "$LOC" ] && { [ "$LOC" = "US" ] && cr_ok "地区 = US" || cr_warn "地区 = $LOC"; }

cr_head "2. 规则全部直指住宅（无中间组）"
read -r HST UD CL FI <<<"$(cr_rule_health)"
EXPECT_UDP=$(( ${#CR_DOMAINS[@]} + ${#CR_CDNS[@]} + 4 ))
EXPECT_CLAUDE=$(( ${#CR_DOMAINS[@]} + ${#CR_CDNS[@]} + 2 ))
if [ "${HST:-ERR}" = "ERR" ]; then
  cr_bad "读不到规则"
else
  [ "$CL" -eq "$EXPECT_CLAUDE" ] && cr_ok "$CL 条 Claude 规则直指住宅节点" \
    || cr_bad "Claude 规则数 = ${CL}（期望 ${EXPECT_CLAUDE}）"
  [ "$UD" -eq "$EXPECT_UDP" ] && cr_ok "$UD 条 UDP REJECT 规则" \
    || cr_bad "UDP REJECT 规则数 = ${UD}（期望 ${EXPECT_UDP}）"
  [ "$FI" -eq 1 ] && cr_ok "首条 Claude 规则指向住宅" \
    || cr_bad "首条 Claude 规则被抢占"
fi

cr_head "3. 无 fallback / 无自动切换"
AUTO=$(cr_api /proxies | CR_NODE="$RESIDENT_NODE" /usr/bin/python3 -c '
import os, sys, json
node = os.environ["CR_NODE"]
ps = (json.load(sys.stdin).get("proxies") or {})
print(",".join(k for k, v in ps.items()
               if v.get("type") in ("Fallback", "URLTest", "LoadBalance")
               and node in (v.get("all") or [])))
' 2>/dev/null)
[ -z "$AUTO" ] && cr_ok "无 fallback/url-test 组引用住宅节点" \
  || cr_bad "自动切换组引用住宅：$AUTO"

cr_head "4. Claude 域名逐个追踪"
if [ "$QUICK" -eq 1 ]; then
  echo "  （--quick，跳过）"
else
  TRACK_DOMAINS="api.anthropic.com assets.claude.ai downloads.claude.ai a-cdn.anthropic.com"
  for d in $TRACK_DOMAINS; do
    /usr/bin/curl -s -x "socks5h://127.0.0.1:$MIXED" --max-time 20 -o /dev/null \
      "https://$d/" 2>/dev/null &
    CP=$!
    sleep 1.2
    CH=$(cr_api /connections | D="$d" /usr/bin/python3 -c '
import os, sys, json
d = os.environ["D"]
try:
    for c in json.load(sys.stdin).get("connections") or []:
        if d in (c["metadata"].get("host") or ""):
            print(",".join(c.get("chains") or [])); break
except Exception:
    pass
' 2>/dev/null)
    wait $CP 2>/dev/null
    [ "$CH" = "$RESIDENT_NODE" ] && cr_ok "$d → 住宅" \
      || cr_bad "$d → ${CH:-未捕获}"
  done
fi

cr_head "5. 裸 IP 兜底"
BARE=$(echo "$ANTHROPIC_V4" | /usr/bin/awk -F/ '{print $1}' | /usr/bin/sed 's/\.0$/.10/')
BARE_LIST="$BARE"
for ip in $CDN_IPS; do BARE_LIST="$BARE_LIST $ip"; done
for ip in $BARE_LIST; do
  /usr/bin/curl -s -x "socks5h://127.0.0.1:$MIXED" --max-time 15 -k -o /dev/null \
    "https://$ip/" 2>/dev/null &
  CP=$!
  CH=""
  for _ in 1 2 3 4 5 6; do
    sleep 0.6
    CH=$(cr_api /connections | IP="$ip" /usr/bin/python3 -c '
import os, sys, json
ip = os.environ["IP"]
try:
    for c in json.load(sys.stdin).get("connections") or []:
        if c["metadata"].get("destinationIP") == ip:
            print(",".join(c.get("chains") or [])); break
except Exception:
    pass
' 2>/dev/null)
    [ -n "$CH" ] && break
  done
  wait $CP 2>/dev/null
  [ "$CH" = "$RESIDENT_NODE" ] && cr_ok "裸 $ip → 住宅" \
    || cr_bad "裸 $ip → ${CH:-未捕获}"
done

cr_head "6. TUN 全量接管"
BADR=""
for ip in "$BARE" 8.8.8.8 1.2.3.4 203.0.113.5; do
  IFC=$(/sbin/route -n get "$ip" 2>/dev/null | /usr/bin/awk '/interface:/{print $2}')
  case "$IFC" in utun*) ;; *) BADR="$BADR $ip->${IFC:-无路由}" ;; esac
done
[ -z "$BADR" ] && cr_ok "外部 IP 全部走 TUN" || cr_bad "未走 TUN：$BADR"

cr_head "7. 无全局 IPv6"
V6=$(/sbin/ifconfig 2>/dev/null | /usr/bin/grep 'inet6 [23]' | /usr/bin/grep -v fe80 | /usr/bin/head -1)
[ -z "$V6" ] && cr_ok "无全局 IPv6（v6 直连不可能）" || cr_bad "存在全局 v6：$V6"

cr_head "8. 自动更新已关"
[ "$(/usr/bin/defaults read com.anthropic.claudefordesktop SUAutomaticallyUpdate 2>/dev/null)" = "0" ] \
  && cr_ok "桌面版自动更新 = off" || cr_bad "桌面版自动更新未关"
CLI_UPDATE=$(/usr/bin/python3 -c "
import json, os
try:
    print((json.load(open(os.path.expanduser('~/.claude/settings.json'))).get('env') or {}).get('DISABLE_AUTOUPDATER', ''))
except Exception:
    print('')
" 2>/dev/null)
[ "$CLI_UPDATE" = "1" ] && cr_ok "CLI DISABLE_AUTOUPDATER = 1" || cr_bad "CLI 自动更新未关"

cr_head "9. pf 直连拦截（需 root 加固后生效）"
PF_N=0; PF_OK=0
for ip in $BARE_LIST; do
  PF_N=$((PF_N+1))
  R=$(/usr/bin/curl -s --interface "${CR_IFACES[0]}" --max-time 8 -o /dev/null \
    -w '%{exitcode}' "https://$ip/" 2>&1)
  if [ "$R" = "7" ]; then
    PF_OK=$((PF_OK+1))
  else
    cr_bad "${CR_IFACES[0]} 直连 $ip 可连通（exit=${R}）—— 需跑 sudo bash harden-root.sh"
  fi
done
[ "$PF_OK" -eq "$PF_N" ] && cr_ok "$PF_N 个目标在 ${CR_IFACES[0]} 上全部被拦（exit=7）"

cr_head "10. UDP / WebRTC 封堵"
STUN_OUT=$(/usr/bin/python3 - <<'PY' 2>/dev/null
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
if [ -z "$STUN_OUT" ]; then
  cr_ok "STUN 探测无回包（UDP 已封，不会漏）"
elif [ "$STUN_OUT" = "$EXIT_IP" ]; then
  cr_warn "STUN 拿到 $STUN_OUT = 住宅出口（理想：UDP 也走住宅）"
else
  cr_bad "STUN 拿到 $STUN_OUT —— UDP 未封，WebRTC 会暴露这个 IP"
fi

echo
echo "════════ 结果：$CR_PASS 通过 / $CR_FAIL 失败 / $CR_WARN 警告 ════════"
[ "$CR_FAIL" -eq 0 ] && echo "全部通过 ✅" || echo "有 $CR_FAIL 项需处理"
exit 0
