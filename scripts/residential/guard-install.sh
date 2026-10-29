#!/bin/bash
# 安装 / 卸载用户级自愈守护（免 sudo）
#
# 装的是一个 LaunchAgent，两条互补的触发方式：
#   1. WatchPaths 监听 Verge 的配置目录 —— 订阅更新一写入就触发，把窗口压到秒级。
#      这是主力。
#   2. StartInterval 30 秒轮询 —— 防止 WatchPaths 漏事件（比如文件没变但内核被重启）。
#
# 为什么用用户级而不是 LaunchDaemon：
#   mihomo 控制 socket 的属主就是登录用户，PUT /configs 不需要 root。
#   整条自愈链可以在用户态闭环，不需要密码，也不需要提权。
#
# 用法：
#   bash guard-install.sh             安装/更新
#   bash guard-install.sh --uninstall 卸载
#   bash guard-install.sh --status    查看状态

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib-common.sh
. "$SCRIPT_DIR/lib-common.sh"

case "${1:-}" in
  --uninstall)
    LABEL="local.claude-residential-guard"
    # 先读 label，读不到就用默认
    if [ -f "$HOME/Library/Scripts/claude-residential.env" ]; then
      # shellcheck disable=SC1091
      . "$HOME/Library/Scripts/claude-residential.env" 2>/dev/null
      LABEL="${GUARD_LABEL:-$LABEL}"
    fi
    /bin/launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null
    /bin/rm -f "$HOME/Library/LaunchAgents/$LABEL.plist"
    echo "已卸载 $LABEL"
    exit 0
    ;;
  --status)
    LABEL="local.claude-residential-guard"
    if [ -f "$HOME/Library/Scripts/claude-residential.env" ]; then
      # shellcheck disable=SC1091
      . "$HOME/Library/Scripts/claude-residential.env" 2>/dev/null
      LABEL="${GUARD_LABEL:-$LABEL}"
    fi
    /bin/launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null \
      | grep -E 'state|last exit|program|run interval' \
      || echo "未安装（${LABEL}）"
    exit 0
    ;;
esac

cr_load_env

PLIST="$HOME/Library/LaunchAgents/$GUARD_LABEL.plist"
GUARD="$SCRIPT_DIR/guard.sh"
UID_NOW=$(id -u)

[ -x "$GUARD" ] || /bin/chmod 755 "$GUARD" 2>/dev/null
[ -f "$GUARD" ] || { echo "找不到 $GUARD"; exit 1; }

# 先确认参数和目标能对上，免得装上一个每次都失败的守护
echo "验证参数……"
if ! /bin/bash "$GUARD" --check >/dev/null 2>&1; then
  echo "  ⚠️  当前链路不健康（可能还没切到住宅节点）。"
  echo "     守护装上后会自己修，但建议先跑 selfcheck.sh 看清原因。"
fi

/bin/mkdir -p "$HOME/Library/LaunchAgents" "$(dirname "$GUARD_LOG")"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$GUARD_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$GUARD</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>30</integer>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>WatchPaths</key>
  <array>
    <string>$CV</string>
    <string>$MERGE</string>
    <string>$VERGE_DIR/profiles</string>
  </array>
  <key>StandardErrorPath</key><string>$GUARD_LOG</string>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
</dict>
</plist>
EOF

/bin/chmod 644 "$PLIST"

echo "已写 $PLIST"

# 重载：先 bootout 再 bootstrap，避免旧定义残留
/bin/launchctl bootout "gui/$UID_NOW/$GUARD_LABEL" 2>/dev/null
if /bin/launchctl bootstrap "gui/$UID_NOW" "$PLIST" 2>&1; then
  echo "  ✅ 已加载 $GUARD_LABEL"
else
  echo "  ❌ 加载失败。试着手工："
  echo "     launchctl bootstrap gui/$UID_NOW \"$PLIST\""
  exit 1
fi

# 立刻跑一次，把日志写出来方便确认
/bin/sleep 1
/bin/launchctl kickstart -k "gui/$UID_NOW/$GUARD_LABEL" 2>/dev/null
/bin/sleep 2

echo
echo "状态："
/bin/launchctl print "gui/$UID_NOW/$GUARD_LABEL" 2>/dev/null \
  | grep -E '^\s*(state|program|last exit)' | sed 's/^/  /'

echo
echo "最近的日志（${GUARD_LOG}）："
/usr/bin/tail -8 "$GUARD_LOG" 2>/dev/null | sed 's/^/  /'

echo
echo "常用操作："
echo "  bash $SCRIPT_DIR/guard-install.sh --status     查看状态"
echo "  bash $SCRIPT_DIR/guard.sh --verbose            手动触发一次并看输出"
echo "  bash $SCRIPT_DIR/guard-install.sh --uninstall  卸载"
