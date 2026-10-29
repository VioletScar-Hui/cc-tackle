#!/bin/bash
# Claude 住宅链路 —— 参数生成
#
# 能自动探测的都自动探，只有真正需要人判断的才问（用哪个节点、出口 IP 是多少）。
# 已有配置会先备份，不会静默覆盖。
#
# 用法：
#   bash install.sh              交互式生成
#   bash install.sh --from-env   不交互，直接用现有参数文件（迁移场景）

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENVF="$HOME/Library/Scripts/claude-residential.env"
LEGACY="$HOME/Library/Scripts/claude-profile.env"
STAMP=$(date +%Y%m%d-%H%M%S)

say()  { printf '%s\n' "$*"; }
head2() { printf '\n──── %s ────\n' "$1"; }

need() {  # need <提示> <默认值> ; 结果存 REPLY
  local prompt="$1" def="${2:-}" ans
  if [ -n "$def" ]; then
    printf '%s [%s]: ' "$prompt" "$def"
  else
    printf '%s: ' "$prompt"
  fi
  read -r ans </dev/tty
  [ -z "$ans" ] && ans="$def"
  REPLY="$ans"
}

say "Claude 住宅链路 —— 参数生成"
say "参数文件：$ENVF"

# ── 自动探测 ──────────────────────────────────────────────
head2 "自动探测"

UID_NOW=$(id -u)
SOCK_GUESS="/var/run/clash-verge-service/users/$UID_NOW/verge-mihomo.sock"
if [ -S "$SOCK_GUESS" ]; then
  say "  ✅ mihomo socket: $SOCK_GUESS"
  DEF_SOCK="$SOCK_GUESS"
else
  say "  ⚠️  $SOCK_GUESS 不存在（Clash Verge 没在跑？）"
  ALT=$(/bin/ls -d /var/run/clash-verge-service/users/*/ 2>/dev/null | head -1)
  DEF_SOCK="${ALT%/}/verge-mihomo.sock"
  [ -d "${ALT:-}" ] && say "      探测到另一个: $DEF_SOCK" || DEF_SOCK="$SOCK_GUESS"
fi

IFACES_AUTO=$(/sbin/ifconfig -l | tr ' ' '\n' | grep -E '^(en|ppp|ipsec)[0-9]+$' | tr '\n' ' ' | sed 's/ $//')
say "  ✅ 物理网卡: $IFACES_AUTO"

VERGE_GUESS="$HOME/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev"
[ -d "$VERGE_GUESS" ] && say "  ✅ Verge 目录: $VERGE_GUESS" \
  || say "  ⚠️  Verge 目录不在默认位置: $VERGE_GUESS"

# 从内核读当前节点列表，帮用户挑
DEF_NODE=""
node_list=""
if [ -S "$DEF_SOCK" ]; then
  node_list=$(/usr/bin/curl -s --unix-socket "$DEF_SOCK" --max-time 8 \
    http://localhost/proxies 2>/dev/null | /usr/bin/python3 -c '
import sys, json
try:
    ps = json.load(sys.stdin).get("proxies") or {}
except Exception:
    sys.exit(0)
skip = {"DIRECT", "REJECT", "PASS", "GLOBAL", "COMPATIBLE"}
out = [k for k, v in ps.items()
       if k not in skip and v.get("type") in
       ("Shadowsocks", "Vmess", "Trojan", "Vless", "Hysteria", "Hysteria2",
        "Tuic", "WireGuard", "Snell", "Socks5", "Http")]
print("\n".join(out))
' 2>/dev/null)
fi

# ── 交互 ──────────────────────────────────────────────────
if [ "${1:-}" = "--from-env" ]; then
  if [ -f "$ENVF" ]; then
    say "从现有参数文件读取，不交互。"
  elif [ -f "$LEGACY" ]; then
    say "从旧参数文件读取：$LEGACY"
    ENVF_TO_COPY="$LEGACY"
  else
    say "没有现成参数文件，无法 --from-env。去掉该参数走交互模式。"
    exit 1
  fi
fi

if [ "${1:-}" != "--from-env" ]; then
  head2 "第 1 步：找出住宅节点"

  say "节点名字是订阅方随便起的，「住宅」两个字可能有也可能没有。"
  say "所以不靠名字猜，直接测每个节点的实际出口 IP，看归属。"
  say ""
  say "这个步骤会："
  say "  · 逐个把节点切上去测出口（走代理端口，不产生直连）"
  say "  · 多源交叉判定住宅/机房"
  say "  · 期间临时暂停 guard，测完自动恢复并切回原节点"
  say ""
  printf '现在探测吗？[Y/n] '
  read -r do_probe
  case "${do_probe:-Y}" in
    [Yy]*)
      echo
      # discover.sh 探测完会写回参数文件（如果已有）。
      # 安装阶段通常还没有，所以这里只拿它的结论。
      PROBE_OUT=$(bash "$SCRIPT_DIR/discover.sh" --list 2>&1)
      printf '%s\n' "$PROBE_OUT"

      # 从结论段落里抽第一个住宅节点
      DETECTED=$(printf '%s\n' "$PROBE_OUT" \
        | /usr/bin/awk '/^找到 .* 个判定为住宅的节点：/{f=1;next} f&&/^    /{sub(/^    /,"");print;exit}')

      echo
      if [ -n "$DETECTED" ]; then
        say "探测结论：住宅节点是「${DETECTED}」"
        need "住宅节点名" "$DETECTED"
        NODE="$REPLY"
      else
        say "没探测到住宅节点。"
        say "如果确认订阅里有住宅线路，跳过探测手工填（填错整套方案会全绿但没用）。"
        need "住宅节点名" ""
        NODE="$REPLY"
      fi
      ;;
    *)
      if [ -n "$node_list" ]; then
        say ""
        say "订阅里的节点（挑出那个住宅节点，名字要一字不差）："
        printf '%s\n' "$node_list" | /usr/bin/head -40 | /usr/bin/sed 's/^/    /'
        echo
      fi
      need "住宅节点名" ""
      NODE="$REPLY"
      ;;
  esac
  [ -z "$NODE" ] && { say "节点名不能为空。"; exit 1; }

  # 出口 IP：直接测"走这个节点时"的真实出口，不靠用户回忆。
  # 做法是让用户先把 IPEqual 切到该节点，或者由 discover 已经测过。
  say ""
  say "现在测这个节点的出口 IP（会临时走一次代理）……"
  MIXED=$(/usr/bin/curl -s --unix-socket "$DEF_SOCK" --max-time 6 http://localhost/configs 2>/dev/null \
    | /usr/bin/python3 -c 'import sys,json;print(json.load(sys.stdin).get("mixed-port") or 7897)' 2>/dev/null)
  : "${MIXED:=7897}"

  # 直接从 discover 的结论里拿这个节点的出口，拿不到再现场测
  # 用 index() 做字面匹配，节点名常含括号（如「(赠送)…」），
  # 当正则用会失配或误匹配。
  DETECTED_IP=$(printf '%s\n' "${PROBE_OUT:-}" | /usr/bin/awk -v n="$NODE" '
    index($0, n) && index($0, "✅") {
      for (i = 1; i <= NF; i++)
        if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) { print $i; exit }
    }')

  if [ -n "$DETECTED_IP" ]; then
    EXIT_PROBE="$DETECTED_IP"
    say "  探测得到出口：$EXIT_PROBE"
  else
    EXIT_PROBE=$(/usr/bin/curl -s -x "socks5h://127.0.0.1:$MIXED" --max-time 20 \
      https://claude.ai/cdn-cgi/trace 2>/dev/null | /usr/bin/awk -F= '/^ip=/{print $2}')
    [ -n "$EXIT_PROBE" ] && say "  当前 Claude 出口：$EXIT_PROBE"
  fi

  if [ -n "$EXIT_PROBE" ]; then
    need "住宅出口 IP" "$EXIT_PROBE"
  else
    need "住宅出口 IP" ""
  fi
  EXITIP="$REPLY"

  # 现场告警：填进来的出口如果不是住宅，立刻说清楚，
  # 别让人装完以为万事大吉。
  if [ -n "$EXITIP" ]; then
    VERDICT=$(/usr/bin/python3 "$SCRIPT_DIR/judge-ip.py" "$EXITIP" 2>/dev/null)
    case "$VERDICT" in
      DATACENTER)
        say ""
        say "  ⚠️  这个 IP 判定为机房，不是住宅。"
        say "     装着也能跑，但 Claude 走的是机房 IP，这套方案的意义就没了。"
        say "     建议先跑 discover.sh 找真正的住宅节点。" ;;
      UNKNOWN)
        say ""
        say "  ⚠️  这个 IP 的归属判不准，建议人工确认后再继续。" ;;
    esac
  fi

  need "VPS 入口 IP（节点配置里的 server，不该出现在出口里）" ""
  VPSIP="$REPLY"

  CDN_DEF=$(for d in a-cdn.anthropic.com assets.claude.ai downloads.claude.ai; do
    /usr/bin/dig +short "$d" 2>/dev/null | grep -E '^[0-9]+\.' | head -1
  done | tr '\n' ' ' | sed 's/ $//')
  need "Claude 第三方 CDN IP（空格分隔，可留空）" "$CDN_DEF"
  CDN="$REPLY"

  need "物理网卡" "$IFACES_AUTO"
  IFACES="$REPLY"

  need "mihomo socket" "$DEF_SOCK"
  SOCKV="$REPLY"

  need "Verge 配置目录" "$VERGE_GUESS"
  VERGED="$REPLY"

  need "明文 DNS 白名单（空格分隔）" "223.5.5.5 119.29.29.29"
  DNSV="$REPLY"
fi

# ── 写文件 ────────────────────────────────────────────────
head2 "写入"
/bin/mkdir -p "$HOME/Library/Scripts" "$HOME/Library/Logs"

if [ -n "${ENVF_TO_COPY:-}" ]; then
  # 旧格式迁移：把旧变量名映射过来
  # shellcheck disable=SC1090
  . "$ENVF_TO_COPY"
  NODE="${NODE_NAME:-}"
  EXITIP="${EXIT_IP:-}"
  VPSIP="${VPS_IP:-}"
  CDN="${CDN_IPS:-}"
  IFACES="${PHYS_IFACES:-}"
  SOCKV="${MIHOMO_SOCK:-}"
  VERGED="${VERGE_DIR:-}"
  DNSV="${DNS_UPSTREAMS:-}"
  say "  旧参数已映射到新格式"
fi

if [ -f "$ENVF" ]; then
  /bin/cp "$ENVF" "$ENVF.bak-$STAMP"
  say "  已有配置备份为 $(basename "$ENVF").bak-$STAMP"
fi

cat > "$ENVF" <<EOF
# Claude 住宅链路 —— 环境参数
# 生成于 $(date '+%Y-%m-%d %H:%M:%S')，由 install.sh 写入
# 这是整套东西里唯一需要按机器修改的文件。

RESIDENT_NODE="$NODE"
EXIT_IP="$EXITIP"
VPS_IP="$VPSIP"
PHYS_IFACES="$IFACES"
MIHOMO_SOCK="$SOCKV"
VERGE_DIR="$VERGED"
DNS_UPSTREAMS="$DNSV"
CDN_IPS="$CDN"
ANTHROPIC_V4="160.79.104.0/21"
ANTHROPIC_V6="2607:6bc0::/32"
CLAUDE_DOMAINS="claude.ai claude.com anthropic.com claudeusercontent.com"
STUN_PORTS="3478 5349 19302-19309"
SCRIPTS_DIR="\$HOME/Library/Scripts"
LOG_DIR="\$HOME/Library/Logs"
GUARD_LABEL="local.claude-residential-guard"
EOF
/bin/chmod 600 "$ENVF"
say "  ✅ $ENVF"

# 同步一份到脚本目录，便于 guard 找到同版本的 expand.py
/bin/cp "$ENVF" "$SCRIPT_DIR/claude-residential.env" 2>/dev/null
/bin/chmod 600 "$SCRIPT_DIR/claude-residential.env" 2>/dev/null

# ── Merge.yaml 增强规则 ───────────────────────────────────
# 没有这份文件，prepend-rules 就是空的：9 条 Claude 规则和 11 条 UDP REJECT
# 一条都进不了内核，selfcheck 还会全绿 —— 装完等于没装。
# 所以这里必须主动生成，而不是假设它已经存在。
head2 "Merge.yaml 增强规则"

# 兜底：极端情况下 VERGED 可能为空，用默认路径
: "${VERGED:=$HOME/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev}"
MERGE_P="$VERGED/profiles/Merge.yaml"
if [ -f "$MERGE_P" ]; then
  say "  ✅ 已存在，不覆盖：$MERGE_P"
  say "     （要按新参数重建：python3 $SCRIPT_DIR/merge-gen.py --force）"
else
  say "  没找到 Merge.yaml —— 同事机器上通常都没有，现在生成一份"
  # 管道会吞掉退出码，先存输出再判断
  MERGE_LOG=$(/usr/bin/python3 "$SCRIPT_DIR/merge-gen.py" 2>&1)
  MERGE_RC=$?
  printf '%s\n' "$MERGE_LOG" | /usr/bin/sed 's/^/  /'
  if [ "$MERGE_RC" -eq 0 ]; then
    MERGE_OK=1
  else
    MERGE_OK=0
  fi
  if [ "${MERGE_OK:-0}" -eq 1 ]; then
    say "  ⚠️  还需在 Verge GUI 里让它生效："
    say "     设置 → 配置 → Merge → 选中刚生成的这份"
    say "     否则 Verge 生成 clash-verge.yaml 时不会带上这些规则"
  else
    say "  ❌ 生成失败，请先修上面的报错再继续"
  fi
fi

# ── 立刻验一次 ────────────────────────────────────────────
head2 "验证"
say "跑一次自查，确认参数和实际结果吻合："
say ""
/bin/bash "$SCRIPT_DIR/selfcheck.sh"
RC=$?

echo
if [ "$RC" -eq 0 ]; then
  say "参数没问题。下一步："
  say "  bash $SCRIPT_DIR/guard-install.sh      # 装自动修复"
  say "  sudo bash $SCRIPT_DIR/harden-root.sh   # 加固防火墙（需 root）"
else
  say "有项目不通过，按上面的提示改 ${ENVF}，改完重跑 selfcheck.sh。"
fi
exit "$RC"
