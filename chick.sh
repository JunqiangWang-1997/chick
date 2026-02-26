#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="/etc/chick.conf"
STATE_DIR="/var/lib/mkchick"
NEXT_FILE="$STATE_DIR/next_hex"

UPLINK="eth1"
LAN_NET="lan0"
PUB_PREFIX=""

load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/etc/chick.conf
    source "$CONFIG_FILE"
  fi
}

save_config() {
  mkdir -p "$(dirname "$CONFIG_FILE")"
  cat >"$CONFIG_FILE" <<EOF
UPLINK="${UPLINK}"
LAN_NET="${LAN_NET}"
PUB_PREFIX="${PUB_PREFIX}"
EOF
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run as root"
    exit 1
  fi
}

ensure_incus_ready() {
  if ! command -v incus >/dev/null 2>&1; then
    echo "incus not found. Run option 1 first."
    exit 1
  fi

  if ! incus info >/dev/null 2>&1; then
    echo "Initializing incus with --auto ..."
    incus admin init --auto
  fi
}

install_incus_and_deps() {
  require_root

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y incus incus-client openssl iproute2 curl ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y incus openssl iproute curl ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y incus openssl iproute curl ca-certificates
  elif command -v apk >/dev/null 2>&1; then
    apk update
    apk add incus incus-client openssl iproute2 curl ca-certificates
  else
    echo "Unsupported package manager. Please install incus manually."
    exit 1
  fi

  systemctl enable --now incus >/dev/null 2>&1 || true
  systemctl enable --now incus.socket >/dev/null 2>&1 || true

  ensure_incus_ready
  echo "Install done."
}

tune_host_network() {
  require_root
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
  sysctl -w net.ipv6.conf.all.proxy_ndp=1 >/dev/null

  cat >/etc/sysctl.d/99-chick.conf <<'EOF'
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.all.proxy_ndp=1
EOF
  sysctl --system >/dev/null 2>&1 || true
}

ensure_lan_network() {
  ensure_incus_ready
  if ! incus network show "$LAN_NET" >/dev/null 2>&1; then
    incus network create "$LAN_NET" ipv4.address=10.55.0.1/24 ipv4.nat=true ipv6.address=none
  fi
}

configure_network() {
  require_root
  load_config

  local input
  echo "Current UPLINK   : $UPLINK"
  read -r -p "UPLINK interface [${UPLINK}]: " input
  if [[ -n "$input" ]]; then
    UPLINK="$input"
  fi

  echo "Current LAN_NET  : $LAN_NET"
  read -r -p "Incus LAN network name [${LAN_NET}]: " input
  if [[ -n "$input" ]]; then
    LAN_NET="$input"
  fi

  echo "Current PUB_PREFIX: ${PUB_PREFIX:-<empty>}"
  read -r -p "Public IPv6 prefix (example: 2001:db8:1234:5678) [${PUB_PREFIX}]: " input
  if [[ -n "$input" ]]; then
    PUB_PREFIX="$input"
  fi

  save_config
  tune_host_network
  ensure_lan_network

  echo "Network config saved: $CONFIG_FILE"
}

allocate_ipv6() {
  mkdir -p "$STATE_DIR"

  if [[ -z "$PUB_PREFIX" ]]; then
    echo "PUB_PREFIX is empty. Run option 2 first."
    exit 1
  fi

  local hex ipv6
  hex="$(cat "$NEXT_FILE" 2>/dev/null || echo 100)"
  while true; do
    ipv6="${PUB_PREFIX}::${hex}"
    if ip -6 route | grep -q -F "${ipv6}/128"; then
      hex="$(printf "%x" $((0x$hex + 1)))"
    else
      break
    fi
  done

  echo "$(printf "%x" $((0x$hex + 1)))" >"$NEXT_FILE"
  echo "$ipv6"
}

create_chick() {
  require_root
  load_config
  ensure_incus_ready
  tune_host_network
  ensure_lan_network

  local name="${1:-}"
  if [[ -z "$name" ]]; then
    read -r -p "Container name: " name
  fi
  [[ -n "$name" ]] || { echo "Name required"; exit 1; }

  local ipv6
  ipv6="$(allocate_ipv6)"

  incus init images:alpine/3.21 "$name" >/dev/null

  incus config device remove "$name" eth0 >/dev/null 2>&1 || true
  incus config device remove "$name" lan1 >/dev/null 2>&1 || true

  incus config device add "$name" eth0 nic nictype=routed parent="$UPLINK" ipv6.address="$ipv6" >/dev/null
  incus config device add "$name" lan1 nic network="$LAN_NET" name=lan1 >/dev/null

  incus start "$name" >/dev/null

  local pass ssh_ok lan_ip
  pass="$(openssl rand -base64 10)"
  ssh_ok="NO"

  if incus exec "$name" -- sh -lc "
set -e

apk add --no-cache openrc >/dev/null 2>&1 || true
cat >/etc/network/interfaces <<'IFACE'
auto lo
iface lo inet loopback

auto lan1
iface lan1 inet dhcp
IFACE
rc-update add networking >/dev/null 2>&1 || true
rc-service networking restart >/dev/null 2>&1 || true

udhcpc -i lan1 -n -q >/dev/null 2>&1 || true

ok=0
for i in 1 2 3 4 5 6 7 8; do
  apk update >/dev/null 2>&1 && apk add --no-cache openssh-server >/dev/null 2>&1 && ok=1 && break
  sleep 2
done
[ \"\$ok\" -eq 1 ] || exit 20

echo root:$pass | chpasswd
ssh-keygen -A >/dev/null 2>&1 || true

if [ -f /etc/ssh/sshd_config ]; then
  sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config || true
  sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
fi

rc-update add sshd >/dev/null 2>&1 || true
rc-service sshd restart >/dev/null 2>&1 || rc-service sshd start >/dev/null 2>&1 || true

ss -lnt 2>/dev/null | grep -q ':22' || netstat -lnt 2>/dev/null | grep -q ':22'
" >/dev/null 2>&1; then
    ssh_ok="YES"
  fi

  lan_ip="$(incus exec "$name" -- sh -lc "ip -4 addr show dev lan1 | awk '/inet /{print \$2}' | head -n1" 2>/dev/null || true)"

  echo "======================================"
  echo "Container: $name"
  echo "Public IPv6: $ipv6"
  echo "LAN IPv4: ${lan_ip:-pending}"
  echo "SSH ready: $ssh_ok"
  echo "SSH: ssh root@[$ipv6]"
  echo "Password: $pass"
  if [[ "$ssh_ok" != "YES" ]]; then
    echo "NOTE: SSH not ready; run:"
    echo "incus exec $name -- sh -lc 'udhcpc -i lan1 -n -q; apk update; apk add --no-cache openssh-server; ssh-keygen -A; rc-service sshd start'"
  fi
  echo "======================================"
}

delete_chick() {
  require_root
  local name="${1:-}"
  if [[ -z "$name" ]]; then
    read -r -p "Container name to delete: " name
  fi
  [[ -n "$name" ]] || { echo "Name required"; exit 1; }
  incus delete -f "$name"
  echo "Deleted: $name"
}

show_menu() {
  while true; do
    echo
    echo "========== Chick Menu =========="
    echo "1) Install Incus and deps"
    echo "2) Configure network (UPLINK/LAN/PUB_PREFIX)"
    echo "3) Create chick"
    echo "4) Delete chick"
    echo "0) Exit"
    read -r -p "Choose: " choice

    case "$choice" in
    1) install_incus_and_deps ;;
    2) configure_network ;;
    3) create_chick ;;
    4) delete_chick ;;
    0) exit 0 ;;
    *) echo "Invalid option" ;;
    esac
  done
}

main() {
  local action="${1:-menu}"
  case "$action" in
  install)
    install_incus_and_deps
    ;;
  network)
    configure_network
    ;;
  create)
    create_chick "${2:-}"
    ;;
  delete)
    delete_chick "${2:-}"
    ;;
  menu)
    show_menu
    ;;
  *)
    echo "Usage: $0 [install|network|create <name>|delete <name>|menu]"
    exit 1
    ;;
  esac
}

main "$@"