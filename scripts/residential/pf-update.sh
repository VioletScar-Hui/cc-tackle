#!/bin/bash
# pf 规则重建（root，由 LaunchDaemon 开机运行 + 每小时刷新）
#
# 为什么不用 pfctl -f /etc/pf.conf：
#   整表重载会刷掉 Surge / Proxyman 这类软件运行时动态插入的 anchor 规则。
#   这里只替换自己那一段（-a claude-residential -f），别人不受影响。
#
# 为什么 anchor 用独立名字：
#   与系统 anchor（com.apple/*）和其它代理软件的 anchor 互不干扰。
#
# 由 harden-root.sh 安装到 /usr/local/libexec/claude-residential-pf.sh

ETC=/usr/local/etc/claude-residential
ANCHOR=claude-residential
LOG=/var/log/claude-residential-pf.log

exec >>"$LOG" 2>&1
echo "== $(date) reload =="

# 从配置读参数，不写死
read_cfg() {
  [ -f "$ETC/config.env" ] || return 0
  # shellcheck disable=SC1090
  . "$ETC/config.env"
}

ANTHROPIC_V4=""
ANTHROPIC_V6=""
PHYS_IFACES=""
DNS_UPSTREAMS=""
read_cfg

[ -z "$ANTHROPIC_V4" ] && { echo "!! 缺 ANTHROPIC_V4，放弃"; exit 1; }

# 网卡：用配置里列的，并过滤掉实际不存在的（pf 对不存在的网卡会报错）
IFACES=""
for i in $PHYS_IFACES; do
  /sbin/ifconfig "$i" >/dev/null 2>&1 && IFACES="$IFACES $i"
done
[ -z "$IFACES" ] && IFACES=$(/sbin/ifconfig -l | tr ' ' '\n' \
  | grep -E '^(en|ppp|ipsec)[0-9]+$' | tr '\n' ' ')
[ -z "$IFACES" ] && { echo "!! 找不到任何物理网卡，放弃"; exit 1; }

[ -z "$DNS_UPSTREAMS" ] && DNS_UPSTREAMS="223.5.5.5 119.29.29.29"

CDN_LIST=$(grep -vE '^\s*(#|$)' "$ETC/cdn_ips.txt" 2>/dev/null | awk '{print $1}' | tr '\n' ' ')

{
  echo "# Claude 住宅链路 kill-switch"
  echo "# 作用：物理网卡上禁止直连 Anthropic 与已知 CDN 地址，禁止非白名单 DNS 出网"
  echo "# 这是 fail-closed 设计：代理没跑时 Claude 是「断」而不是「漏」"
  echo ""
  echo "# Anthropic 自有网段（ARIN NET-160-79-104-0-1 / NET6-2607-6BC0-1）"
  echo "table <claude_block> persist { $ANTHROPIC_V4 $ANTHROPIC_V6 }"
  if [ -n "$CDN_LIST" ]; then
    echo ""
    echo "# Claude 资产落在第三方 CDN 上的地址（不在 Anthropic 网段内）"
    echo "table <claude_cdn> persist { $CDN_LIST }"
  fi
  echo ""
  echo "# DNS：只放行白名单上游的 53，其余 53 一律拦（防 DNS 泄漏）"
  echo "dns_servers = \"{ $DNS_UPSTREAMS }\""
  echo "pass out quick on {$IFACES} proto { tcp udp } from any to \$dns_servers port 53"
  echo "block return out quick on {$IFACES} proto { tcp udp } from any to any port 53"
  echo ""
  echo "# 禁止物理网卡直连 Claude 地址（return 而不是 drop：快速失败，便于发现）"
  echo "block return out quick on {$IFACES} proto tcp from any to <claude_block>"
  echo "block return out quick on {$IFACES} proto udp from any to <claude_block>"
  if [ -n "$CDN_LIST" ]; then
    echo "block return out quick on {$IFACES} proto tcp from any to <claude_cdn>"
    echo "block return out quick on {$IFACES} proto udp from any to <claude_cdn>"
  fi
} > "/etc/pf.anchors/$ANCHOR"

# pf.conf 里挂上 anchor 点（幂等）
if ! grep -q "anchor \"$ANCHOR\"" /etc/pf.conf; then
  [ -f /etc/pf.conf.bak-claude-residential ] || \
    cp /etc/pf.conf /etc/pf.conf.bak-claude-residential
  {
    echo ''
    echo "# $ANCHOR anchor point"
    echo "anchor \"$ANCHOR\""
    echo "load anchor \"$ANCHOR\" from \"/etc/pf.anchors/$ANCHOR\""
  } >> /etc/pf.conf
  echo "pf.conf updated"
fi

/sbin/pfctl -E 2>&1 | head -2
/sbin/pfctl -a "$ANCHOR" -f "/etc/pf.anchors/$ANCHOR" 2>&1
/sbin/pfctl -a "$ANCHOR" -s rules 2>&1 | head -20
