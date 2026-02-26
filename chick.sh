#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="/etc/chick.conf"
STATE_DIR="/var/lib/mkchick"
NEXT_FILE="$STATE_DIR/next_hex"
CHICKS_FILE="$STATE_DIR/chicks.tsv"
DEFAULT_IMAGE="images:alpine/3.21"

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

init_chicks_file() {
  mkdir -p "$STATE_DIR"
  if [[ ! -f "$CHICKS_FILE" ]]; then
    printf 'name\tipv6\tlan_ipv4\tpassword\tssh_ready\tuplink\tlan_net\tcreated_at\timage\n' >"$CHICKS_FILE"
  fi
}

upsert_chick_record() {
  local name="$1"
  local ipv6="$2"
  local lan_ipv4="$3"
  local password="$4"
  local ssh_ready="$5"
  local uplink="$6"
  local lan_net="$7"
  local created_at="$8"
  local image="$9"

  init_chicks_file

  local tmp_file
  tmp_file="$(mktemp "$STATE_DIR/chicks.XXXXXX")"
  awk -F'\t' -v OFS='\t' -v target="$name" 'NR == 1 || $1 != target { print }' "$CHICKS_FILE" >"$tmp_file"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$name" "$ipv6" "$lan_ipv4" "$password" "$ssh_ready" "$uplink" "$lan_net" "$created_at" "$image" >>"$tmp_file"
  mv "$tmp_file" "$CHICKS_FILE"
}

remove_chick_record() {
  local name="$1"
  [[ -f "$CHICKS_FILE" ]] || return 0

  local tmp_file
  tmp_file="$(mktemp "$STATE_DIR/chicks.XXXXXX")"
  awk -F'\t' -v OFS='\t' -v target="$name" 'NR == 1 || $1 != target { print }' "$CHICKS_FILE" >"$tmp_file"
  mv "$tmp_file" "$CHICKS_FILE"
}

detect_default_uplink() {
  ip route 2>/dev/null | awk '
    $1 == "default" {
      for (i = 1; i <= NF; i++) {
        if ($i == "dev" && (i + 1) <= NF) {
          print $(i + 1)
          exit
        }
      }
    }
  '
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

  incus init "$DEFAULT_IMAGE" "$name" >/dev/null

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
  lan_ip="${lan_ip//$'\n'/}"

  upsert_chick_record \
    "$name" \
    "$ipv6" \
    "${lan_ip:-pending}" \
    "$pass" \
    "$ssh_ok" \
    "$UPLINK" \
    "$LAN_NET" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$DEFAULT_IMAGE"

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
  remove_chick_record "$name"
  echo "Deleted: $name"
}

list_chicks() {
  if [[ ! -f "$CHICKS_FILE" ]]; then
    echo "No chick records yet. Expected file: $CHICKS_FILE"
    return 0
  fi

  local rows
  rows="$(awk 'END { print NR }' "$CHICKS_FILE")"
  if [[ "$rows" -le 1 ]]; then
    echo "No chick records yet. Expected file: $CHICKS_FILE"
    return 0
  fi

  if command -v column >/dev/null 2>&1; then
    column -t -s $'\t' "$CHICKS_FILE"
  else
    cat "$CHICKS_FILE"
  fi
}

show_chick_info() {
  local name="${1:-}"
  if [[ -z "$name" ]]; then
    read -r -p "Container name: " name
  fi
  [[ -n "$name" ]] || { echo "Name required"; exit 1; }

  if [[ ! -f "$CHICKS_FILE" ]]; then
    echo "No records file found: $CHICKS_FILE"
    exit 1
  fi

  local record
  record="$(awk -F'\t' -v target="$name" 'NR > 1 && $1 == target { print; exit }' "$CHICKS_FILE")"
  if [[ -z "$record" ]]; then
    echo "No record for container: $name"
    exit 1
  fi

  local rec_name rec_ipv6 rec_lan_ipv4 rec_password rec_ssh_ready rec_uplink rec_lan_net rec_created_at rec_image
  IFS=$'\t' read -r rec_name rec_ipv6 rec_lan_ipv4 rec_password rec_ssh_ready rec_uplink rec_lan_net rec_created_at rec_image <<<"$record"

  echo "name: $rec_name"
  echo "ipv6: $rec_ipv6"
  echo "lan_ipv4: $rec_lan_ipv4"
  echo "password: $rec_password"
  echo "ssh_ready: $rec_ssh_ready"
  echo "uplink: $rec_uplink"
  echo "lan_net: $rec_lan_net"
  echo "created_at: $rec_created_at"
  echo "image: $rec_image"
}

oneshot_chick() {
  require_root

  local config_exists=0
  if [[ -f "$CONFIG_FILE" ]]; then
    config_exists=1
  fi
  load_config

  local name=""
  local uplink_arg=""
  local lan_net_arg=""
  local pub_prefix_arg=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
    --uplink)
      [[ $# -ge 2 ]] || { echo "Missing value for --uplink"; exit 1; }
      uplink_arg="$2"
      shift 2
      ;;
    --lan-net)
      [[ $# -ge 2 ]] || { echo "Missing value for --lan-net"; exit 1; }
      lan_net_arg="$2"
      shift 2
      ;;
    --pub-prefix)
      [[ $# -ge 2 ]] || { echo "Missing value for --pub-prefix"; exit 1; }
      pub_prefix_arg="$2"
      shift 2
      ;;
    -h | --help)
      echo "Usage: $0 oneshot <name> [--uplink IFACE] [--lan-net NAME] [--pub-prefix PREFIX]"
      return 0
      ;;
    *)
      if [[ -z "$name" ]]; then
        name="$1"
        shift
      else
        echo "Unknown argument: $1"
        exit 1
      fi
      ;;
    esac
  done

  [[ -n "$name" ]] || read -r -p "Container name: " name
  [[ -n "$name" ]] || { echo "Name required"; exit 1; }

  if [[ -n "$uplink_arg" ]]; then
    UPLINK="$uplink_arg"
  elif [[ "$config_exists" -eq 0 ]]; then
    UPLINK="$(detect_default_uplink || true)"
  fi

  if [[ -n "$lan_net_arg" ]]; then
    LAN_NET="$lan_net_arg"
  fi

  if [[ -n "$pub_prefix_arg" ]]; then
    PUB_PREFIX="$pub_prefix_arg"
  fi

  if [[ -z "$PUB_PREFIX" ]]; then
    read -r -p "Public IPv6 prefix (example: 2001:db8:1234:5678): " PUB_PREFIX
  fi

  [[ -n "$UPLINK" ]] || { echo "UPLINK is empty. Use --uplink IFACE."; exit 1; }
  [[ -n "$LAN_NET" ]] || { echo "LAN_NET is empty. Use --lan-net NAME."; exit 1; }
  [[ -n "$PUB_PREFIX" ]] || { echo "PUB_PREFIX is required."; exit 1; }

  install_incus_and_deps
  save_config
  create_chick "$name"
}

show_menu() {
  while true; do
    echo
    echo "========== Chick Menu =========="
    echo "1) Install Incus and deps"
    echo "2) Configure network (UPLINK/LAN/PUB_PREFIX)"
    echo "3) Create chick"
    echo "4) Delete chick"
    echo "5) List chick records"
    echo "6) Show chick record"
    echo "7) Oneshot (install + create)"
    echo "0) Exit"
    read -r -p "Choose: " choice

    case "$choice" in
    1) install_incus_and_deps ;;
    2) configure_network ;;
    3) create_chick ;;
    4) delete_chick ;;
    5) list_chicks ;;
    6) show_chick_info ;;
    7) oneshot_chick ;;
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
  list)
    list_chicks
    ;;
  info)
    show_chick_info "${2:-}"
    ;;
  oneshot)
    shift
    oneshot_chick "$@"
    ;;
  menu)
    show_menu
    ;;
  *)
    echo "Usage: $0 [install|network|create <name>|delete <name>|list|info <name>|oneshot <name> [--uplink IFACE] [--lan-net NAME] [--pub-prefix PREFIX]|menu]"
    exit 1
    ;;
  esac
}

main "$@"
