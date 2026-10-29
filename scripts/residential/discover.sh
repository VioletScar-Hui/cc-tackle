#!/bin/bash
# 探测订阅里每个节点的实际出口 IP，判定哪个才是住宅。
#
# 解决的问题：节点名字是订阅方随便起的，「住宅」两个字既可能有也可能没有。
# 靠名字猜会选错，而选错的后果是整套方案全绿但 Claude 全程走机房。
# 所以这里不看名字，只看实际落地：
#
#   逐个把节点切上去 → 测出口 IP → 多个数据源交叉判定住宅/机房 → 出表给人挑
#
# 安全性：
#   · Claude 规则直指节点名，不经过 IPEqual 组，所以切换 IPEqual 不影响 Claude
#   · 探测全程走 mixed-port，不产生任何直连
#   · 结束（含被打断）一律切回原节点，用 trap 保证
#
# 用法：
#   bash discover.sh                # 探测全部节点，交互选定
#   bash discover.sh --quick        # 只测名字像住宅的，快
#   bash discover.sh --list         # 只出表，不写配置
#   bash discover.sh --node "名字"   # 只测指定节点
#   bash discover.sh --timeout 8    # 每节点等待秒数（默认 10）

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JUDGE="$SCRIPT_DIR/judge-ip.py"

# 这里不 source lib-common.sh：探测要在装好之前就能跑，
# 那时可能还没有参数文件。所以自己解析 socket 与端口。
DEF_UID="$(id -u)"
DEF_SOCK="/var/run/clash-verge-service/users/$DEF_UID/verge-mihomo.sock"
if [ ! -S "$DEF_SOCK" ]; then
  # 兜底：有些部署 socket 在别的路径，翻一下
  for s in /var/run/clash-verge-service/users/*/verge-mihomo.sock; do
    [ -S "$s" ] && { DEF_SOCK="$s"; break; }
  done
fi

ENVF="${CLAUDE_RESIDENTIAL_ENV:-$HOME/Library/Scripts/claude-residential.env}"
[ ! -f "$ENVF" ] && [ -f "$HOME/Library/Scripts/claude-profile.env" ] \
  && ENVF="$HOME/Library/Scripts/claude-profile.env"

SOCK="$DEF_SOCK"
QUICK=0
LIST_ONLY=0
ONLY_NODE=""
WAIT=10
# 看起来像住宅的名字关键词。只用于 --quick 预筛，不做最终判据。
CAND_RE="${CANDIDATE_PATTERN:-住宅|家宽|宽带|静态|residential|home}"

# ── 输出 ──────────────────────────────────────────────────
say()  { printf '%s\n' "$*"; }
head2() { printf '\n════════ %s ════════\n' "$1"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --quick)   QUICK=1; shift ;;
    --list)    LIST_ONLY=1; shift ;;
    --node)    ONLY_NODE="${2:-}"; shift 2 ;;
    --timeout) WAIT="${2:-10}"; shift 2 ;;
    --sock)    SOCK="${2:-}"; shift 2 ;;
    -h|--help)
      /usr/bin/sed -n '2,26p' "$0" | /usr/bin/sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) say "未知参数：$1（-h 看用法）"; exit 2 ;;
  esac
done

[ -S "$SOCK" ] || { say "mihomo socket 不在：$SOCK"; say "先把 Clash Verge 启动起来。"; exit 1; }

api() { /usr/bin/curl -s --unix-socket "$SOCK" --max-time 8 "http://localhost$1" 2>/dev/null; }

MIXED=$(api /configs | /usr/bin/python3 -c \
  'import sys,json;print(json.load(sys.stdin).get("mixed-port") or 7897)' 2>/dev/null)
: "${MIXED:=7897}"

# ── 记住原状态，退出时无条件恢复 ──────────────────────────
ORIG_SEL=$(api /proxies/IPEqual | /usr/bin/python3 -c \
  'import sys,json;print(json.load(sys.stdin).get("now") or "")' 2>/dev/null)
SEL_GROUP="IPEqual"
if [ -z "$ORIG_SEL" ]; then
  # 没有 IPEqual 组就退回到任意一个含住宅节点的 Selector
  SEL_GROUP=$(api /proxies | /usr/bin/python3 -c '
import sys, json
ps = (json.load(sys.stdin).get("proxies") or {})
for n, v in ps.items():
    if v.get("type") == "Selector" and len(v.get("all") or []) > 1:
        print(n); break
' 2>/dev/null)
  [ -n "$SEL_GROUP" ] && ORIG_SEL=$(api "/proxies/$SEL_GROUP" | /usr/bin/python3 -c \
    'import sys,json;print(json.load(sys.stdin).get("now") or "")' 2>/dev/null)
fi

# ── 探测期间暂停 guard ────────────────────────────────────
# guard 每 30 秒把 IPEqual 改回钉住的住宅节点。不暂停的话，
# 探测切上去的节点会在 10 秒内被改回来 —— 实测第一轮探测
# 11 个节点全报同一个住宅 IP，就是这个原因。
# 只 bootout 用户级 guard，不碰 root 侧的 pf/DNS。
GUARD_LABEL="${GUARD_LABEL:-local.claude-guard-user}"
GUARD_PAUSED=0
RESTORED=0

restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  # 先切回原节点
  if [ -n "$ORIG_SEL" ]; then
    local body
    body=$(/usr/bin/python3 -c \
      'import json,sys;print(json.dumps({"name":sys.argv[1]},ensure_ascii=False))' "$ORIG_SEL")
    /usr/bin/curl -s --unix-socket "$SOCK" --max-time 8 -X PUT \
      -H 'Content-Type: application/json' --data-binary "$body" -o /dev/null \
      "http://localhost/proxies/$SEL_GROUP" 2>/dev/null
  fi
  # 再恢复 guard：它会重新把节点钉住
  if [ "$GUARD_PAUSED" -eq 1 ]; then
    local plist="$HOME/Library/LaunchAgents/$GUARD_LABEL.plist"
    if [ -f "$plist" ]; then
      launchctl bootstrap "gui/$(id -u)" "$plist" >/dev/null 2>&1
    else
      launchctl kickstart "gui/$(id -u)/$GUARD_LABEL" >/dev/null 2>&1
    fi
    GUARD_PAUSED=0
  fi
}

pause_guard() {
  if launchctl print "gui/$(id -u)/$GUARD_LABEL" >/dev/null 2>&1; then
    if launchctl bootout "gui/$(id -u)/$GUARD_LABEL" >/dev/null 2>&1; then
      GUARD_PAUSED=1
      say "已暂停 ${GUARD_LABEL}（探测期间不会把节点改回去，结束后自动恢复）"
    fi
  fi
}

trap 'restore; exit 130' INT TERM
trap restore EXIT
pause_guard

# ── 取节点列表（只取真实节点，不含组和内置项）──────────────
NODES=$(api /proxies | /usr/bin/python3 -c '
import sys, json
ps = (json.load(sys.stdin).get("proxies") or {})
skip = {"DIRECT", "REJECT", "PASS", "GLOBAL", "COMPATIBLE"}
proxy_types = ("Shadowsocks", "Vmess", "Trojan", "Vless", "Hysteria",
               "Hysteria2", "Tuic", "WireGuard", "Snell", "Socks5", "Http", "Ssh")
for k, v in ps.items():
    if k in skip:
        continue
    if v.get("type") in proxy_types:
        print(k)
' 2>/dev/null)

[ -z "$NODES" ] && { say "订阅里没读到任何节点。"; exit 1; }

if [ -n "$ONLY_NODE" ]; then
  if printf '%s\n' "$NODES" | grep -qxF "$ONLY_NODE"; then
    NODES="$ONLY_NODE"
  else
    say "订阅里没有这个节点：$ONLY_NODE"
    exit 1
  fi
elif [ "$QUICK" -eq 1 ]; then
  FILTERED=$(printf '%s\n' "$NODES" | grep -E "$CAND_RE" 2>/dev/null)
  if [ -n "$FILTERED" ]; then
    NODES="$FILTERED"
    say "按名字预筛到 $(printf '%s\n' "$NODES" | wc -l | tr -d ' ') 个候选"
    say "（名字只是预筛，最终以出口 IP 判定为准）"
  else
    say "名字里没有住宅特征，改为全部探测。"
  fi
fi

TOTAL=$(printf '%s\n' "$NODES" | wc -l | tr -d ' ')

head2 "探测 $TOTAL 个节点的实际出口"
say "切换组：$SEL_GROUP    当前选中：${ORIG_SEL:-（空）}"
say "探测走 mixed-port ${MIXED}，不产生直连；结束后自动切回。"
[ "$TOTAL" -gt 8 ] && say "节点较多，每个约 $((WAIT + 4)) 秒，总共约 $(( TOTAL * (WAIT + 4) )) 秒。"

probe_one() {
  local node="$1" body ip
  body=$(/usr/bin/python3 -c \
    'import json,sys;print(json.dumps({"name":sys.argv[1]},ensure_ascii=False))' "$node")
  /usr/bin/curl -s --unix-socket "$SOCK" --max-time 8 -X PUT \
    -H 'Content-Type: application/json' --data-binary "$body" -o /dev/null \
    "http://localhost/proxies/$SEL_GROUP" 2>/dev/null
  /bin/sleep 1

  # 探测点必须走 IPEqual，不能用 claude.ai。
  # 原因：Claude 规则直指节点名、完全绕过 IPEqual，所以测 claude.ai 时
  # 不管 IPEqual 切到哪个节点，拿到的永远是住宅 IP —— 实测 11 个节点
  # 全返回同一个 IP 就是这么来的。中立域名才会跟随 IPEqual 的选中项。
  #
  # 换三个探测点是因为有些订阅节点会 SSL 握手失败（EXIT 35），
  # 换域名没用，所以失败就重试同一个域名，两次都不通才判"不通"。
  ip=""
  local attempt u raw
  for attempt in 1 2; do
    for u in https://api.ipify.org https://icanhazip.com https://ifconfig.me/ip; do
      raw=$(/usr/bin/curl -s -x "socks5h://127.0.0.1:$MIXED" --max-time "$WAIT" \
            "$u" 2>/dev/null | /usr/bin/tr -d ' \r\n')
      # 只接受纯 IP，别把错误页当成 IP
      if printf '%s' "$raw" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$|:'; then
        ip="$raw"; break 2
      fi
    done
    [ "$attempt" -eq 1 ] && /bin/sleep 2
  done
  printf '%s\t%s\n' "$node" "$ip"
}

RESULTS=""
i=0
while IFS= read -r n; do
  [ -z "$n" ] && continue
  i=$((i + 1))
  printf '  [%d/%d] %s … ' "$i" "$TOTAL" "$n"
  line=$(probe_one "$n")
  ip="${line#*$'\t'}"
  if [ -z "$ip" ]; then
    printf '取不到出口\n'
  else
    printf '%s\n' "$ip"
  fi
  RESULTS="$RESULTS$line"$'\n'
done <<<"$NODES"

# ── 判定 ──────────────────────────────────────────────────
head2 "判定（多源交叉）"

TABLE_FILE="${TMPDIR:-/tmp}/claude-discover.txt"
: >"$TABLE_FILE"

while IFS=$'\t' read -r n ip; do
  [ -z "$n" ] && continue
  if [ -z "$ip" ]; then
    verdict="UNKNOWN"; mark="❓"; why="节点不通，没取到出口"
  else
    verdict=$(/usr/bin/python3 "$JUDGE" "$ip" 2>/dev/null)
    why=$(/usr/bin/python3 "$JUDGE" --json "$ip" 2>/dev/null \
      | /usr/bin/python3 -c 'import sys,json;print(json.load(sys.stdin).get("reason") or "")' 2>/dev/null)
    case "$verdict" in
      RESIDENTIAL) mark="✅" ;;
      DATACENTER)  mark="❌" ;;
      *)           mark="❓" ;;
    esac
  fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$mark" "$n" "${ip:-—}" "$verdict" "$why" >>"$TABLE_FILE"
done <<<"$RESULTS"

# 打印表格：中文按两格宽对齐
/usr/bin/python3 - "$TABLE_FILE" <<'PY'
import sys, unicodedata

def w(s):
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)

def pad(s, n):
    return s + " " * max(0, n - w(s))

rows = []
with open(sys.argv[1]) as f:
    for line in f:
        p = line.rstrip("\n").split("\t")
        if len(p) == 5:
            rows.append(p)

hdr = ("", "节点名", "出口 IP", "判定")
widths = [3, 4, 8, 4]
for r in rows:
    for i in (1, 2, 3):
        widths[i] = max(widths[i], w(r[i]))

print("  %s %s %s %s" % (
    pad(hdr[0], widths[0]), pad(hdr[1], widths[1]),
    pad(hdr[2], widths[2]), hdr[3]))
print("  " + "-" * (sum(widths) + 3))
for r in rows:
    print("  %s %s %s %s" % (
        pad(r[0], widths[0]), pad(r[1], widths[1]),
        pad(r[2], widths[2]), r[4] or r[3]))
PY

# ── 交叉校验：多个节点返回同一个 IP 时重测 ────────────────
# 订阅里的赠送节点偶尔会抽风连到主节点上，导致它报出和住宅节点
# 相同的出口。这种情况不能直接当成"又一个住宅节点"，否则用户可能
# 选中一个其实不稳定的节点。对重复 IP 的节点重测一次，仍重复就标注。
head2 "交叉校验"
DUP_IPS=$(/usr/bin/awk -F'\t' '$3!="—"{c[$3]++} END{for(i in c) if(c[i]>1) print i}' "$TABLE_FILE")

if [ -n "$DUP_IPS" ]; then
  say "这些 IP 被多个节点共用，重测一次以排除串扰："
  printf '%s\n' "$DUP_IPS" | /usr/bin/sed 's/^/    /'
  echo
  TMP2="${TMPDIR:-/tmp}/claude-discover-recheck.txt"
  : >"$TMP2"
  while IFS= read -r dup; do
    [ -z "$dup" ] && continue
    /usr/bin/awk -F'\t' -v ip="$dup" '$3==ip{print $2}' "$TABLE_FILE" \
      | while IFS= read -r n2; do
          [ -z "$n2" ] && continue
          printf '  重测 %s … ' "$n2"
          l2=$(probe_one "$n2")
          ip2="${l2#*$'\t'}"
          printf '%s\n' "${ip2:-取不到}"
          printf '%s\t%s\n' "$n2" "$ip2" >>"$TMP2"
        done
  done <<<"$DUP_IPS"

  # 用重测结果覆盖
  while IFS=$'\t' read -r n3 ip3; do
    [ -z "$n3" ] && continue
    /usr/bin/python3 - "$TABLE_FILE" "$n3" "$ip3" <<'PY'
import sys
path, node, ip = sys.argv[1], sys.argv[2], sys.argv[3]
rows = []
for line in open(path):
    p = line.rstrip("\n").split("\t")
    if len(p) == 5 and p[1] == node:
        if not ip:
            p = ["❓", node, "—", "UNKNOWN", "重测仍取不到出口"]
        else:
            p[2] = ip
        line = "\t".join(p) + "\n"
    rows.append(line)
open(path, "w").writelines(rows)
PY
  done <"$TMP2"

  # 重测后重新判定归属
  while IFS=$'\t' read -r mark n4 ip4 rest; do
    [ -z "$n4" ] && continue
    [ "$ip4" = "—" ] && continue
    v4=$(/usr/bin/python3 "$JUDGE" "$ip4" 2>/dev/null)
    w4=$(/usr/bin/python3 "$JUDGE" --json "$ip4" 2>/dev/null \
      | /usr/bin/python3 -c 'import sys,json;print(json.load(sys.stdin).get("reason") or "")' 2>/dev/null)
    case "$v4" in
      RESIDENTIAL) m4="✅" ;;
      DATACENTER)  m4="❌" ;;
      *)           m4="❓" ;;
    esac
    /usr/bin/python3 - "$TABLE_FILE" "$n4" "$m4" "$v4" "$w4" <<'PY'
import sys
path, node, mark, verdict, why = sys.argv[1:6]
rows = []
for line in open(path):
    p = line.rstrip("\n").split("\t")
    if len(p) == 5 and p[1] == node:
        p = [mark, node, p[2], verdict, why]
        line = "\t".join(p) + "\n"
    rows.append(line)
open(path, "w").writelines(rows)
PY
  done <"$TABLE_FILE"

  rm -f "$TMP2"
  say ""
  say "重测后的结果："
  /usr/bin/python3 - "$TABLE_FILE" <<'PY'
import sys, unicodedata
def w(s): return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)
def pad(s, n): return s + " " * max(0, n - w(s))
rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1])]
rows = [r for r in rows if len(r) == 5]
wds = [3, 4, 8]
for r in rows:
    for i in (1, 2): wds[i] = max(wds[i], w(r[i]))
for r in rows:
    print("  %s %s %s %s" % (pad(r[0], wds[0]), pad(r[1], wds[1]),
                             pad(r[2], wds[2]), r[4] or r[3]))
PY
else
  say "各节点出口互不相同，无串扰。"
fi

RESIDENT=$(/usr/bin/awk -F'\t' '$1=="✅"{print $2}' "$TABLE_FILE")
R_COUNT=$(printf '%s\n' "$RESIDENT" | grep -c . 2>/dev/null || echo 0)

head2 "结论"
if [ "$R_COUNT" -eq 0 ]; then
  say "没有探测到住宅节点。"
  say ""
  say "可能原因："
  say "  · 订阅里确实没有住宅线路（这是机房订阅）"
  say "  · 住宅节点需要单独购买/未在订阅里"
  say "  · 出口 IP 查询被限速（等一分钟重跑）"
  say ""
  say "没有住宅节点就不要装这套方案 —— 装了也不会让 Claude 走住宅。"
  exit 1
fi

say "找到 $R_COUNT 个判定为住宅的节点："
printf '%s\n' "$RESIDENT" | /usr/bin/sed 's/^/    /'

if [ "$LIST_ONLY" -eq 1 ]; then
  say ""
  say "（--list 模式，不写配置）"
  exit 0
fi

# 选哪个
CHOSEN=""
if [ "$R_COUNT" -eq 1 ]; then
  CHOSEN="$(printf '%s\n' "$RESIDENT" | /usr/bin/head -1)"
  say ""
  say "只有一个，自动选定：$CHOSEN"
else
  say ""
  say "多个住宅节点，需要你指定一个（名字要一字不差）："
  printf '%s\n' "$RESIDENT" | /usr/bin/nl -w4 -s'. ' | /usr/bin/sed 's/^/    /'
  printf '  选第几个（回车默认 1）：'
  read -r pick
  : "${pick:=1}"
  CHOSEN="$(printf '%s\n' "$RESIDENT" | /usr/bin/sed -n "${pick}p")"
  [ -z "$CHOSEN" ] && { say "序号无效。"; exit 1; }
fi

CHOSEN_IP=$(/usr/bin/awk -F'\t' -v n="$CHOSEN" '$2==n{print $3}' "$TABLE_FILE")
CHOSEN_WHY=$(/usr/bin/awk -F'\t' -v n="$CHOSEN" '$2==n{print $5}' "$TABLE_FILE")

head2 "选定"
say "  节点：$CHOSEN"
say "  出口：$CHOSEN_IP"
say "  依据：$CHOSEN_WHY"

# ── 写入参数文件 ──────────────────────────────────────────
if [ -f "$ENVF" ]; then
  head2 "更新参数文件"
  /bin/cp "$ENVF" "$ENVF.bak.$(date +%Y%m%d-%H%M%S)"
  /usr/bin/python3 - "$ENVF" "$CHOSEN" "$CHOSEN_IP" <<'PY'
import re, sys
path, node, ip = sys.argv[1], sys.argv[2], sys.argv[3]

def esc(v):
    # 节点名常含括号/空格，统一加引号
    return '"%s"' % v.replace('"', '\\"')

lines = open(path).read().splitlines()
out, seen_node, seen_ip = [], False, False
for ln in lines:
    if re.match(r'^\s*(RESIDENT_NODE|NODE_NAME)\s*=', ln):
        out.append("RESIDENT_NODE=%s" % esc(node)); seen_node = True
    elif re.match(r'^\s*EXIT_IP\s*=', ln):
        out.append("EXIT_IP=%s" % esc(ip)); seen_ip = True
    else:
        out.append(ln)
if not seen_node:
    out.append("RESIDENT_NODE=%s" % esc(node))
if not seen_ip:
    out.append("EXIT_IP=%s" % esc(ip))

open(path, "w").write("\n".join(out) + "\n")
print("  已写入 %s" % path)
PY
  say "  已备份原文件为 $ENVF.bak.*"
  say ""
  say "下一步："
  say "  bash $SCRIPT_DIR/selfcheck.sh     # 应全绿"
else
  say ""
  say "还没有参数文件 $ENVF"
  say "把这两行填进参数文件（或跑 install.sh 让它带你走一遍）："
  say "  RESIDENT_NODE=\"$CHOSEN\""
  say "  EXIT_IP=\"$CHOSEN_IP\""
fi
