#!/bin/bash
# Claude 住宅链路自愈 —— 核心脚本（用户级，免 sudo）
#
# 为什么不需要 root：
#   mihomo 控制 socket 的属主就是登录用户，普通用户即可 PUT /configs 热载。
#   Verge 的订阅更新与配置重生成都不涉及系统目录，所以整条自愈链可以在
#   用户态闭环 —— 不需要 LaunchDaemon，不需要密码。
#
# 它防的是什么：
#   订阅更新会让 Verge 重新生成 clash-verge.yaml，然后重启内核。
#   而 mihomo 不认 prepend-rules 这个 Verge 专有字段，增强规则能否生效全看
#   Verge 生成时有没有展开进 rules。没展开时：
#     - UDP 立刻泄漏，出口变成 VPS 入口 IP
#     - TCP 靠订阅兜底 MATCH,<可切换组> 侥幸走对，但那个组一旦被切走就离开住宅
#
# 健康标准（全部满足才算健康）：
#   A. 11 条 UDP REJECT 规则（4 域名 + 4 CDN IP + 3 STUN 端口）
#   B. 9 条 Claude 规则直指住宅节点（4 域名 + 3 CDN IP + 2 网段）
#   C. 非 REJECT 的首条 Claude 规则指向住宅（不被订阅规则抢占）
#
# 修复时内存态和文件态必须一起修：
#   只热载内存 → 下次 Verge 重启从文件重新生成，规则又丢
#   只改文件   → 内核当前还在跑旧配置，泄漏继续
#
# 用法：
#   bash guard.sh              正常自愈（LaunchAgent 调用这个）
#   bash guard.sh --check      只检查不修复，用退出码报告
#   bash guard.sh --verbose    同时输出到终端

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib-common.sh
. "$SCRIPT_DIR/lib-common.sh"
cr_load_env

# expand.py 可能和本脚本同目录（技能目录里），也可能已复制到 ~/Library/Scripts。
# 两处都找，优先用脚本自己目录里的那份（保证版本一致）。
EXPAND="$SCRIPT_DIR/expand.py"
[ -f "$EXPAND" ] || EXPAND="$SCRIPTS_DIR/expand.py"
if [ ! -f "$EXPAND" ]; then
  echo "找不到 expand.py（找过 $SCRIPT_DIR 和 ${SCRIPTS_DIR}）" >&2
  exit 1
fi

CHECK_ONLY=0
VERBOSE=0
for a in "$@"; do
  case "$a" in
    --check)   CHECK_ONLY=1 ;;
    --verbose) VERBOSE=1 ;;
  esac
done

mkdir -p "$LOG_DIR"

# 用户级日志自己控制体积：launchd 不管，newsyslog 只管 /var/log。
if [ -f "$GUARD_LOG" ] && [ "$(/usr/bin/stat -f%z "$GUARD_LOG" 2>/dev/null || echo 0)" -gt 1048576 ]; then
  /usr/bin/tail -2000 "$GUARD_LOG" > "$GUARD_LOG.tmp" 2>/dev/null && /bin/mv "$GUARD_LOG.tmp" "$GUARD_LOG"
fi

# 终端里手动跑时同时输出到屏幕和日志；launchd 调用时（无 tty）只写日志。
# --check 是给调用方判读的，必须保留终端输出，不能只进日志。
if [ -t 1 ] || [ "$CHECK_ONLY" -eq 1 ]; then
  exec > >(/usr/bin/tee -a "$GUARD_LOG") 2>&1
else
  exec >>"$GUARD_LOG" 2>&1
fi
# WatchPaths 会在写入时连续触发多次（Verge 一次生成可能写好几个文件），
# 用锁避免自己打自己。拿不到锁就退出，让先拿到的那次干完。
LOCK="${TMPDIR:-/tmp}/claude-residential-guard.lock"
if ! /usr/bin/shlock -p $$ -f "$LOCK" 2>/dev/null; then
  echo "== $(date '+%H:%M:%S') 已有实例在跑，跳过"
  exit 0
fi
trap '/bin/rm -f "$LOCK"' EXIT

echo "== $(date '+%Y-%m-%d %H:%M:%S') guard check =="

if ! cr_wait_sock 90; then
  echo "  socket 未就绪（${SOCK}），内核没起来，放弃本次"
  [ "$CHECK_ONLY" -eq 1 ] && exit 3
  exit 0
fi

# ── 判断当前是否健康 ──────────────────────────────────────
read -r ST UD CL FI <<<"$(cr_rule_health)"
if [ "${ST:-ERR}" = "ERR" ]; then
  echo "  读不到规则（内核可能在重载），放弃本次"
  [ "$CHECK_ONLY" -eq 1 ] && exit 3
  exit 0
fi

# 期望条数由参数推导，不写死：
#   UDP  = 4 域名 + N 个 CDN IP + 1 个 v4 网段 + 3 个 STUN 端口段
#   Claude = 4 域名 + N 个 CDN IP + 2 个网段（v4 + v6）
EXPECT_UDP=$(( ${#CR_DOMAINS[@]} + ${#CR_CDNS[@]} + 4 ))
EXPECT_CLAUDE=$(( ${#CR_DOMAINS[@]} + ${#CR_CDNS[@]} + 2 ))

echo "  UDP规则=$UD (需$EXPECT_UDP)  Claude规则=$CL (需$EXPECT_CLAUDE)  首条正确=$FI"

# ── 钉住可切换组的选中项（可选）───────────────────────────
# Claude 规则直指节点名，不经过任何组，所以组的选择不影响 Claude 链路。
# 但若团队要求"选中项不许漂移"，把节点名写进 pin 文件即可，这里负责改回。
if [ -f "$PIN_FILE" ]; then
  WANT=$(/usr/bin/head -1 "$PIN_FILE" 2>/dev/null | /usr/bin/tr -d '\r\n')
  if [ -n "$WANT" ]; then
    # 找哪个组当前选中了别的东西 —— 只处理明确指向住宅节点的组，避免乱动
    DRIFT=$(cr_api /proxies | WANT="$WANT" /usr/bin/python3 -c '
import os, sys, json
want = os.environ["WANT"]
try:
    ps = json.load(sys.stdin).get("proxies") or {}
except Exception:
    sys.exit(0)
for name, v in ps.items():
    if v.get("type") != "Selector":
        continue
    allm = v.get("all") or []
    if want not in allm:
        continue
    if v.get("now") != want:
        print("%s\t%s" % (name, v.get("now", "")))
' 2>/dev/null)

    if [ -n "$DRIFT" ]; then
      while IFS=$'\t' read -r GNAME GNOW; do
        [ -z "$GNAME" ] && continue
        echo "  组 \"$GNAME\" 漂移: \"$GNOW\" != \"$WANT\"，改回"
        BODY=$(/usr/bin/python3 -c \
          'import json,sys;print(json.dumps({"name":sys.argv[1]},ensure_ascii=False))' "$WANT")
        PC=$(cr_api_put "$BODY" "/proxies/$GNAME" 8)
        echo "  钉住 HTTP $PC"
      done <<< "$DRIFT"
    fi
  fi
fi

if [ "$UD" -eq "$EXPECT_UDP" ] && [ "$CL" -eq "$EXPECT_CLAUDE" ] && [ "$FI" -eq 1 ]; then
  echo "  正常"
  exit 0
fi

echo "  !! 偏离（期望 UDP=$EXPECT_UDP Claude=${EXPECT_CLAUDE}），开始修复"

if [ "$CHECK_ONLY" -eq 1 ]; then
  exit 1
fi

# ── 前置：Merge.yaml 必须有规则，否则展开出来还是错的 ──────
if ! /usr/bin/grep -q 'NETWORK,UDP' "$MERGE" 2>/dev/null; then
  echo "  !! Merge.yaml 缺 UDP 规则（可能被订阅覆盖），尝试从备份恢复"
  LATEST=$(/bin/ls -t "$VERGE_DIR/profiles/"Merge.yaml.bak-* 2>/dev/null | /usr/bin/head -1)
  if [ -n "$LATEST" ]; then
    /bin/cp "$LATEST" "$MERGE" && echo "  已从 $(basename "$LATEST") 恢复"
  else
    # 没有备份不是"无法修复"，是"还没生成过"——按参数文件重建一份。
    # 这是同事第一次装、或从未备份过时的正常路径，不该直接退出。
    GEN="$(dirname "${BASH_SOURCE[0]}")/merge-gen.py"
    if [ -f "$GEN" ]; then
      echo "  无备份可用，按参数文件重建 Merge.yaml"
      if /usr/bin/python3 "$GEN" --force 2>&1 | /usr/bin/sed 's/^/    /'; then
        echo "  已重建"
      else
        echo "  !! 重建失败，见 references/pitfalls.md"; exit 1
      fi
    else
      echo "  !! 无备份、也没有 merge-gen.py，需手工写入 Merge 增强规则"
      echo "     见 references/pitfalls.md"; exit 1
    fi
  fi
  # 重建后复核一次，别带着空规则往下走
  if ! /usr/bin/grep -q 'NETWORK,UDP' "$MERGE" 2>/dev/null; then
    echo "  !! 恢复后仍缺 UDP 规则，放弃本次修复"; exit 1
  fi
fi

# ── 展开成可热载的 payload ────────────────────────────────
if /usr/bin/python3 "$EXPAND" 2>&1 | /usr/bin/sed 's/^/  /'; then
  :
else
  echo "  !! 展开失败"; exit 1
fi

# ── 文件态：改 clash-verge.yaml 的 prepend-rules ──────────
# 内核此刻读的是 runtime/config.yaml，但 Verge 重启时会从 clash-verge.yaml
# 重新生成。文件里若也丢了，重启后再犯一次。所以两个状态都要修。
if [ -f "$CV" ]; then
  REPAIRED=$(/usr/bin/python3 - "$CV" "$MERGE" <<'PY' 2>&1
import sys, yaml
cvp, mgp = sys.argv[1], sys.argv[2]
cv = yaml.safe_load(open(cvp)) or {}
mg = yaml.safe_load(open(mgp)) or {}
cur = cv.get('prepend-rules') or []
want = mg.get('prepend-rules') or []
if cur == want:
    print('unchanged'); sys.exit(0)
cv['prepend-rules'] = want
pg = mg.get('prepend-proxy-groups') or []
names = {g.get('name') for g in (cv.get('proxy-groups') or [])}
cv['prepend-proxy-groups'] = [g for g in pg if g.get('name') not in names]
yaml.safe_dump(cv, open(cvp, 'w'), allow_unicode=True, sort_keys=False, width=100000)
print('rewritten')
PY
)
  echo "  clash-verge.yaml: $REPAIRED"
fi

# ── 内存态：热载 ──────────────────────────────────────────
CODE=$(/usr/bin/curl -s --unix-socket "$SOCK" --max-time 10 \
  -X PUT -H 'Content-Type: application/json' \
  --data-binary @"$PAYLOAD" -o /dev/null -w '%{http_code}' \
  http://localhost/configs 2>/dev/null)
echo "  热载 HTTP $CODE"

sleep 2
read -r ST2 UD2 CL2 FI2 <<<"$(cr_rule_health)"
echo "  修复后: UDP规则=$UD2 Claude规则=$CL2 首条正确=$FI2"
if [ "$UD2" -eq "$EXPECT_UDP" ] && [ "$CL2" -eq "$EXPECT_CLAUDE" ] && [ "$FI2" -eq 1 ]; then
  echo "  修复成功"
  exit 0
fi
echo "  !! 修复后仍不正常，需人工介入（见 references/pitfalls.md 排障一节）"
exit 1
