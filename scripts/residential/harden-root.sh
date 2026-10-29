#!/bin/bash
# Claude 住宅链路 —— root 加固（防火墙 + DNS 守卫）
#
# 这一层解决两件事：
#   1. 物理网卡上禁止直连 Anthropic 与已知 CDN 地址 —— 即使代理没跑、规则丢了、
#      有人手动绕过 TUN，也连不出去。这是 fail-closed：宁可断，不可漏。
#   2. 代理不健康时 Claude 域名直接 NXDOMAIN —— 让"连解析都做不到"。
#
# 全部操作幂等，可反复运行。装的东西：
#   /etc/pf.anchors/claude-residential         pf 规则（由 pf-update.sh 生成）
#   /etc/pf.conf                               追加 anchor 点（先备份）
#   /usr/local/libexec/claude-residential-pf.sh     pf 重建脚本（开机+每小时）
#   /usr/local/libexec/claude-residential-dns.py    DNS 守卫
#   /usr/local/etc/claude-residential/         配置（从用户参数文件导出）
#   /Library/LaunchDaemons/local.claude-residential-{pf,dns}.plist
#
# 用法：
#   sudo bash harden-root.sh              安装/更新
#   sudo bash harden-root.sh --uninstall  卸载
#   sudo bash harden-root.sh --dry-run    只打印将要做的事

set -uo pipefail

[ "$(id -u)" -eq 0 ] || { echo "需要 root：sudo bash $0"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# root 下 HOME 是 /var/root，参数文件在目标用户家里
TARGET_USER="${SUDO_USER:-$(/usr/bin/stat -f%Su /dev/console 2>/dev/null)}"
TARGET_HOME=$(/usr/bin/dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null \
  | /usr/bin/awk '{print $2}')
[ -d "${TARGET_HOME:-}" ] || { echo "定位不到用户 $TARGET_USER 的家目录"; exit 1; }
export CLAUDE_RESIDENTIAL_ENV="$TARGET_HOME/Library/Scripts/claude-residential.env"
[ -f "$CLAUDE_RESIDENTIAL_ENV" ] || \
  CLAUDE_RESIDENTIAL_ENV="$TARGET_HOME/Library/Scripts/claude-profile.env"

# shellcheck source=lib-common.sh
. "$SCRIPT_DIR/lib-common.sh"
cr_load_env

ETC=/usr/local/etc/claude-residential
LIB=/usr/local/libexec
ANCHOR=claude-residential
PF_DAEMON=local.claude-residential-pf
DNS_DAEMON=local.claude-residential-dns
STAMP=$(date +%Y%m%d-%H%M%S)

MODE=install
for a in "$@"; do
  case "$a" in
    --uninstall) MODE=uninstall ;;
    --dry-run)   MODE=dryrun ;;
  esac
done

echo "用户          : $TARGET_USER"
echo "参数文件      : $CLAUDE_RESIDENTIAL_ENV"
echo "住宅节点      : $RESIDENT_NODE"
echo "住宅出口      : $EXIT_IP"
echo "Anthropic v4  : $ANTHROPIC_V4"
echo "网卡          : $PHYS_IFACES"
echo "模式          : $MODE"
echo

# ── 卸载 ──────────────────────────────────────────────────
if [ "$MODE" = "uninstall" ]; then
  echo "== 卸载 =="
  for d in "$PF_DAEMON" "$DNS_DAEMON"; do
    /bin/launchctl bootout "system/$d" 2>/dev/null \
      || /bin/launchctl unload "/Library/LaunchDaemons/$d.plist" 2>/dev/null
    /bin/rm -f "/Library/LaunchDaemons/$d.plist"
    echo "  已移除 $d"
  done
  /sbin/pfctl -a "$ANCHOR" -F rules 2>/dev/null && echo "  已清空 pf anchor"
  /bin/rm -f "/etc/pf.anchors/$ANCHOR" "$LIB/claude-residential-pf.sh" \
            "$LIB/claude-residential-dns.py"
  # pf.conf 里的 anchor 点保留无害（文件不在时 pfctl 会跳过），
  # 但为了让卸载干净，还是删掉自己加的那三行
  if [ -f /etc/pf.conf.bak-claude-residential ]; then
    /bin/cp /etc/pf.conf.bak-claude-residential /etc/pf.conf
    echo "  已从备份还原 /etc/pf.conf"
  fi
  echo "卸载完成。DNS 与 pf 规则已移除，Claude 直连不再被拦。"
  exit 0
fi

if [ "$MODE" = "dryrun" ]; then
  echo "== dry-run：以下文件将被写入 =="
  echo "  $ETC/{config.env,domains.txt,upstreams.txt,cdn_ips.txt,expected_ip.txt}"
  echo "  $LIB/claude-residential-pf.sh"
  echo "  $LIB/claude-residential-dns.py"
  echo "  /etc/pf.anchors/$ANCHOR"
  echo "  /Library/LaunchDaemons/$PF_DAEMON.plist"
  echo "  /Library/LaunchDaemons/$DNS_DAEMON.plist"
  echo "  /etc/pf.conf （追加 anchor 点，先备份）"
  exit 0
fi

# ── 备份 ──────────────────────────────────────────────────
echo "== 备份 =="
/bin/mkdir -p "$ETC/backup-$STAMP"
for f in "$ETC/config.env" "$ETC/domains.txt" "$ETC/upstreams.txt" \
         "$ETC/cdn_ips.txt" "$ETC/expected_ip.txt" \
         "$LIB/claude-residential-pf.sh" "$LIB/claude-residential-dns.py" \
         "/etc/pf.anchors/$ANCHOR" /etc/pf.conf; do
  [ -f "$f" ] && /bin/cp "$f" "$ETC/backup-$STAMP/" 2>/dev/null
done
echo "  → $ETC/backup-$STAMP"

# ── 配置 ──────────────────────────────────────────────────
echo "== 写配置 =="
/bin/mkdir -p "$ETC"

cat > "$ETC/config.env" <<EOF
# 由 harden-root.sh 从用户参数文件导出，勿手工改（下次运行会覆盖）
ANTHROPIC_V4="$ANTHROPIC_V4"
ANTHROPIC_V6="$ANTHROPIC_V6"
PHYS_IFACES="$PHYS_IFACES"
DNS_UPSTREAMS="$DNS_UPSTREAMS"
EXPECTED_IP="$EXIT_IP"
VPS_IP="$VPS_IP"
MIHOMO_DNS="127.0.0.1"
MIHOMO_DNS_PORT="1053"
DNS_GUARD_LISTEN="127.0.0.1"
DNS_GUARD_PORT="53"
EOF

printf '%s\n' "$CLAUDE_DOMAINS" | tr ' ' '\n' | grep -v '^$' > "$ETC/domains.txt"
printf '%s\n' "$DNS_UPSTREAMS" | tr ' ' '\n' | grep -v '^$' > "$ETC/upstreams.txt"
printf '%s\n' "$CDN_IPS" | tr ' ' '\n' | grep -v '^$' > "$ETC/cdn_ips.txt"
echo "$EXIT_IP" > "$ETC/expected_ip.txt"

/bin/chmod 644 "$ETC"/*.txt "$ETC/config.env"
echo "  config.env / domains.txt / upstreams.txt / cdn_ips.txt / expected_ip.txt"

# ── 脚本 ──────────────────────────────────────────────────
echo "== 安装脚本 =="
/bin/mkdir -p "$LIB"
/bin/cp "$SCRIPT_DIR/pf-update.sh" "$LIB/claude-residential-pf.sh"
/bin/chmod 755 "$LIB/claude-residential-pf.sh"
/bin/cp "$SCRIPT_DIR/dns-guard.py" "$LIB/claude-residential-dns.py"
/bin/chmod 755 "$LIB/claude-residential-dns.py"
echo "  $LIB/claude-residential-pf.sh"
echo "  $LIB/claude-residential-dns.py"

# ── LaunchDaemons ─────────────────────────────────────────
echo "== 安装守护 =="

cat > "/Library/LaunchDaemons/$PF_DAEMON.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$PF_DAEMON</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$LIB/claude-residential-pf.sh</string></array>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>3600</integer>
  <key>StandardErrorPath</key><string>/var/log/claude-residential-pf.log</string>
</dict>
</plist>
EOF

cat > "/Library/LaunchDaemons/$DNS_DAEMON.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$DNS_DAEMON</string>
  <key>ProgramArguments</key>
  <array><string>/usr/bin/python3</string><string>$LIB/claude-residential-dns.py</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/var/log/claude-residential-dns.log</string>
</dict>
</plist>
EOF

/bin/chmod 644 "/Library/LaunchDaemons/$PF_DAEMON.plist" \
                "/Library/LaunchDaemons/$DNS_DAEMON.plist"
/bin/chown root:wheel "/Library/LaunchDaemons/$PF_DAEMON.plist" \
                      "/Library/LaunchDaemons/$DNS_DAEMON.plist"

# ── 生效 ──────────────────────────────────────────────────
echo "== 生效 =="
# 关键顺序：pf 规则文件是 pf-update.sh 的产物，必须先运行它重建，
# 再让 pf 加载。加固脚本自己写规则、自己加载但漏了这步，
# 会导致加载的还是上一次生成的旧规则。
"$LIB/claude-residential-pf.sh" || echo "  !! pf 规则重建有问题，见 /var/log/claude-residential-pf.log"

for d in "$PF_DAEMON" "$DNS_DAEMON"; do
  /bin/launchctl bootout "system/$d" 2>/dev/null
  /bin/launchctl bootstrap system "/Library/LaunchDaemons/$d.plist" 2>&1 \
    && echo "  已加载 $d" \
    || echo "  !! $d 加载失败"
done

echo
echo "== 自检 =="
echo -n "  pf 规则条数: "
/sbin/pfctl -a "$ANCHOR" -s rules 2>/dev/null | wc -l | tr -d ' '
echo -n "  pf 表 claude_block: "
/sbin/pfctl -a "$ANCHOR" -t claude_block -T show 2>/dev/null | tr '\n' ' '
echo
echo -n "  DNS 守卫: "
/bin/launchctl print "system/$DNS_DAEMON" 2>/dev/null | grep -q 'state = running' \
  && echo "运行中" || echo "未运行（看 /var/log/claude-residential-dns.log）"
echo
echo "加固完成。现在跑一次验收："
echo "  bash $SCRIPT_DIR/verify.sh"
echo
echo "卸载（如需）："
echo "  sudo bash $SCRIPT_DIR/harden-root.sh --uninstall"
