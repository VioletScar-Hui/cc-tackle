#!/bin/bash
# 公共库：被其它脚本 source，不单独执行。
#
# 职责：
#   1. 定位并加载参数文件，缺项时明确报错而不是带着空值继续跑
#   2. 封装 mihomo API 调用（用户可能不是第二个参数里的 UID）
#   3. 提供统一的输出格式与计数

# shellcheck shell=bash

ENV_FILE="${CLAUDE_RESIDENTIAL_ENV:-$HOME/Library/Scripts/claude-residential.env}"

# 旧名字的兼容：早先版本叫 claude-profile.env
# 只在"没有显式指定"时才回退——显式指定了却悄悄用另一个文件，
# 会让测试实际作用到真配置上。
if [ -z "${CLAUDE_RESIDENTIAL_ENV:-}" ] \
   && [ ! -f "$ENV_FILE" ] \
   && [ -f "$HOME/Library/Scripts/claude-profile.env" ]; then
  ENV_FILE="$HOME/Library/Scripts/claude-profile.env"
fi

cr_die() { printf '  ❌ %s\n' "$1" >&2; exit 1; }

cr_load_env() {
  if [ ! -f "$ENV_FILE" ]; then
    cat >&2 <<EOF
缺参数文件：$ENV_FILE

生成方式：
  bash $(dirname "${BASH_SOURCE[0]}")/install.sh

或者手工：
  cp claude-residential.env.example $ENV_FILE
  然后按注释填好每一项
EOF
    exit 1
  fi
  # shellcheck disable=SC1090
  . "$ENV_FILE"

  # 旧版参数文件的变量名兼容：早先这套东西叫 claude-profile.env，
  # 用的是 NODE_NAME/EXIT_IP/VPS_IP/CDN_IPS/PHYS_IFACES 等名字。
  # 映射到新名字，让老部署不改文件也能跑。
  : "${RESIDENT_NODE:=${NODE_NAME:-}}"
  : "${CDN_IPS:=${CDN_IPS:-}}"

  # 必填项为空时直接停，避免带着空值跑出误导性的结果。
  # 注意：CDN_IPS 允许为空（有些环境确实没有额外 CDN IP）。
  local miss="" v val
  for v in RESIDENT_NODE EXIT_IP VPS_IP PHYS_IFACES MIHOMO_SOCK VERGE_DIR \
           ANTHROPIC_V4 ANTHROPIC_V6 CLAUDE_DOMAINS; do
    eval "val=\${$v:-}"
    [ -z "$val" ] && miss="$miss $v"
  done
  if [ -n "$miss" ]; then
    printf '  ❌ 参数文件里这些项为空：%s\n' "$miss" >&2
    printf '     文件：%s\n' "$ENV_FILE" >&2
    printf '     若用的是旧格式文件，RESIDENT_NODE 对应旧名 NODE_NAME。\n' >&2
    exit 1
  fi

  # 派生量：脚本内部统一用这些名字
  SOCK="$MIHOMO_SOCK"
  : "${STUN_PORTS:=3478 5349 19302-19309}"
  : "${SCRIPTS_DIR:=$HOME/Library/Scripts}"
  : "${LOG_DIR:=$HOME/Library/Logs}"
  : "${GUARD_LABEL:=local.claude-residential-guard}"
  GUARD_LOG="$LOG_DIR/claude-residential-guard.log"
  MERGE="$VERGE_DIR/profiles/Merge.yaml"
  CV="$VERGE_DIR/clash-verge.yaml"
  PAYLOAD="${TMPDIR:-/tmp}/claude-residential-payload.json"
  PIN_FILE="$SCRIPTS_DIR/claude-pinned-node.txt"

  # CLAUDE_DOMAINS 是空格分隔，转成数组供循环
  # shellcheck disable=SC2206
  CR_DOMAINS=($CLAUDE_DOMAINS)
  # shellcheck disable=SC2206
  CR_CDNS=($CDN_IPS)
  # shellcheck disable=SC2206
  CR_IFACES=($PHYS_IFACES)
}

# ── mihomo API ────────────────────────────────────────────
cr_api() {
  /usr/bin/curl -s --unix-socket "$SOCK" --max-time "${2:-8}" \
    "http://localhost$1" 2>/dev/null
}

cr_api_put() {
  /usr/bin/curl -s --unix-socket "$SOCK" --max-time "${3:-10}" \
    -X PUT -H 'Content-Type: application/json' \
    --data-binary "$1" -o /dev/null -w '%{http_code}' \
    "http://localhost$2" 2>/dev/null
}

cr_sock_ready() { [ -S "$SOCK" ]; }

# 开机场景下 LaunchAgent 可能比内核先起。等一会儿，别白跑。
cr_wait_sock() {
  local limit="${1:-90}" i
  cr_sock_ready && return 0
  for ((i = 0; i < limit; i++)); do
    /bin/sleep 1
    cr_sock_ready && return 0
  done
  return 1
}

# ── IP 归属判定 ───────────────────────────────────────────
# 查一个 IP 是住宅还是机房。多源交叉，结果缓存一周。
# 参数：IP。输出：RESIDENTIAL / DATACENTER / UNKNOWN
# 注意 judge-ip.py 用退出码表达结果（0 住宅 / 1 机房 / 2 未知），
# 所以这里不能用 `|| echo UNKNOWN` —— 机房会返回 1 而污染输出。
cr_judge_ip() {
  local out
  out=$(/usr/bin/python3 "$(cr_script_dir)/judge-ip.py" "$1" 2>/dev/null)
  case "$out" in
    RESIDENTIAL|DATACENTER|UNKNOWN) printf '%s' "$out" ;;
    *) printf 'UNKNOWN' ;;
  esac
}

# 判定依据（给人看的一句话）。取缓存，不重复发请求。
cr_judge_reason() {
  /usr/bin/python3 "$(cr_script_dir)/judge-ip.py" --json "$1" 2>/dev/null \
    | /usr/bin/python3 -c \
      'import sys,json
try:
    d = json.load(sys.stdin)
    print(d.get("reason") or d.get("as") or d.get("org") or "无依据")
except Exception:
    print("查询失败")'
}

# 脚本所在目录。lib-common.sh 被 source 时 BASH_SOURCE 指向它自己。
cr_script_dir() {
  local src="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
  /usr/bin/dirname "$(/usr/bin/readlink -f "$src" 2>/dev/null || echo "$src")"
}

# ── 规则计数 ──────────────────────────────────────────────
# 输出三个数：UDP REJECT 条数、指向住宅节点的 Claude 规则条数、
# 首条非 REJECT 的 Claude 规则是否指向住宅节点（1/0）。
# 前两个是"量"，第三个是"序" —— 光有量不够，被订阅规则抢在前面一样失效。
cr_rule_health() {
  cr_api /rules | CR_NODE="$RESIDENT_NODE" CR_DOMAINS="$CLAUDE_DOMAINS" \
    CR_CDNS="$CDN_IPS" \
    /usr/bin/python3 -c '
import os, sys, json
try:
    rs = json.load(sys.stdin).get("rules") or []
except Exception:
    print("ERR 0 0 0"); sys.exit(0)

node = os.environ["CR_NODE"]
doms = [d for d in os.environ["CR_DOMAINS"].split() if d]
cdns = [c for c in os.environ["CR_CDNS"].split() if c]
# 域名 + 网段 + CDN IP 都算 Claude 相关目标。
# CDN IP 那段不能省：它们在 Anthropic 网段外，只靠 claude/anthropic 关键词匹配不到。
kw = ["claude", "anthropic", "160.79.104", "2607:6bc0"] + doms + cdns

udp = sum(1 for r in rs
          if r.get("type") == "AND"
          and "udp" in (r.get("payload") or "").lower()
          and r.get("proxy") == "REJECT")

claude = sum(1 for r in rs
             if r.get("proxy") == node
             and any(k in (r.get("payload") or "").lower() for k in kw))

first_ok = 1
for r in rs:
    p = (r.get("payload") or "").lower()
    if not any(k in p for k in kw):
        continue
    if r.get("proxy") == "REJECT":
        continue
    first_ok = 1 if r.get("proxy") == node else 0
    break

print("OK %d %d %d" % (udp, claude, first_ok))
' 2>/dev/null
}

# ── 输出 ──────────────────────────────────────────────────
CR_PASS=0; CR_FAIL=0; CR_WARN=0
cr_ok()   { printf '  ✅ %s\n' "$1"; CR_PASS=$((CR_PASS+1)); }
cr_bad()  { printf '  ❌ %s\n' "$1"; CR_FAIL=$((CR_FAIL+1)); }
cr_warn() { printf '  ⚠️  %s\n' "$1"; CR_WARN=$((CR_WARN+1)); }
cr_head() { printf '\n════════ %s ════════\n' "$1"; }
