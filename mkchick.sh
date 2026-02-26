#!/usr/bin/env bash
set -euo pipefail

NAME="${1:-}"
[[ -n "$NAME" ]] || { echo "Usage: mkchick <name>"; exit 1; }

UPLINK="eth1"
LAN_NET="lan0"
PUB_PREFIX=""

STATE_DIR="/var/lib/mkchick"
mkdir -p "$STATE_DIR"
NEXT_FILE="$STATE_DIR/next_hex"

# routed IPv6 必需
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
sysctl -w net.ipv6.conf.all.proxy_ndp=1 >/dev/null

hex="$(cat "$NEXT_FILE" 2>/dev/null || echo 100)"
while true; do
  IPV6="${PUB_PREFIX}::${hex}"
  if ip -6 route | grep -q -F "${IPV6}/128"; then
    hex=$(printf "%x" $((0x$hex + 1)))
  else
    break
  fi
done
echo "$(printf "%x" $((0x$hex + 1)))" >"$NEXT_FILE"

incus init images:alpine/3.21 "$NAME" >/dev/null

# 清理可能继承的设备，避免冲突
incus config device remove "$NAME" eth0 >/dev/null 2>&1 || true
incus config device remove "$NAME" lan1 >/dev/null 2>&1 || true

# 公网 IPv6 /128
incus config device add "$NAME" eth0 nic nictype=routed parent="$UPLINK" ipv6.address="$IPV6" >/dev/null
# 内网 IPv4 DHCP
incus config device add "$NAME" lan1 nic network="$LAN_NET" name=lan1 >/dev/null

incus start "$NAME" >/dev/null

PASS="$(openssl rand -base64 10)"
SSH_OK="NO"

if incus exec "$NAME" -- sh -lc "
set -e

# 1) 确保开机自动 DHCP（根治重启掉网）
apk add --no-cache openrc >/dev/null 2>&1 || true
cat >/etc/network/interfaces <<'IFACE'
auto lo
iface lo inet loopback

auto lan1
iface lan1 inet dhcp
IFACE
rc-update add networking >/dev/null 2>&1 || true
rc-service networking restart >/dev/null 2>&1 || true

# 2) 先立刻拿一次 DHCP，保证本次也有网
udhcpc -i lan1 -n -q >/dev/null 2>&1 || true

# 3) 装 SSH（重试）
ok=0
for i in 1 2 3 4 5 6 7 8; do
  apk update >/dev/null 2>&1 && apk add --no-cache openssh-server >/dev/null 2>&1 && ok=1 && break
  sleep 2
done
[ \"\$ok\" -eq 1 ] || exit 20

echo root:$PASS | chpasswd
ssh-keygen -A >/dev/null 2>&1 || true

# 允许 root+密码
if [ -f /etc/ssh/sshd_config ]; then
  sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config || true
  sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
fi

rc-update add sshd >/dev/null 2>&1 || true
rc-service sshd restart >/dev/null 2>&1 || rc-service sshd start >/dev/null 2>&1 || true

# 确认 22 监听
ss -lnt 2>/dev/null | grep -q ':22' || netstat -lnt 2>/dev/null | grep -q ':22'
" >/dev/null 2>&1; then
  SSH_OK="YES"
fi

LAN_IP="$(incus exec "$NAME" -- sh -lc "ip -4 addr show dev lan1 | awk '/inet /{print \$2}' | head -n1" 2>/dev/null || true)"

echo "======================================"
echo "Container: $NAME"
echo "Public IPv6: $IPV6"
echo "LAN IPv4: ${LAN_IP:-pending}"
echo "SSH ready: $SSH_OK"
echo "SSH: ssh root@[$IPV6]"
echo "Password: $PASS"
if [[ \"$SSH_OK\" != \"YES\" ]]; then
  echo \"NOTE: SSH not ready; run:\"
  echo \"incus exec $NAME -- sh -lc 'udhcpc -i lan1 -n -q; apk update; apk add --no-cache openssh-server; ssh-keygen -A; rc-service sshd start'\"
fi
echo "======================================"