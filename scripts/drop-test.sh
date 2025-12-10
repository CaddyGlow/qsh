#!/usr/bin/env bash
set -euo pipefail

# Packet drop simulation using tc with BPF filters
# Requires root privileges
#
# Supports precise BPF-based filtering for:
# - IP address (source/dest)
# - Port (source/dest)
# - Protocol (udp/tcp/icmp)
# - Custom BPF expressions

TARGET_IP="${TARGET_IP:-}"
TARGET_PORT="${TARGET_PORT:-}"
PROTOCOL="${PROTOCOL:-udp}"
INTERFACE="${INTERFACE:-}"
DURATION="${DURATION:-60}"
DIRECTION="${DIRECTION:-both}"  # ingress, egress, both
BPF_FILTER="${BPF_FILTER:-}"    # Custom tcpdump-style BPF filter
DROP_PERCENT="${DROP_PERCENT:-100}"  # Percentage of packets to drop (1-100)

QDISC_HANDLE="1:"
INGRESS_HANDLE="ffff:"

usage() {
  cat <<EOF
Usage: $0 [start|stop|status]

Simulate packet loss using tc with BPF filters for precise targeting.

Commands:
    start   - Start dropping packets
    stop    - Stop dropping packets
    status  - Show current tc rules

Environment variables:
    TARGET_IP    - Target IP address
    TARGET_PORT  - Target port number
    PROTOCOL     - Protocol: udp, tcp, icmp (default: udp)
    INTERFACE    - Network interface (auto-detected if not set)
    DIRECTION    - ingress, egress, or both (default: both)
    DURATION     - Duration in seconds, 0 for indefinite (default: 60)
    DROP_PERCENT - Percentage of matching packets to drop (default: 100)
    BPF_FILTER   - Custom tcpdump-style BPF filter (overrides other filters)

Examples:
    # Drop all UDP packets to IP on port 4433
    sudo TARGET_IP=192.168.100.3 TARGET_PORT=4433 ./drop-test.sh start

    # Drop 50% of packets (simulate lossy network)
    sudo TARGET_IP=192.168.100.3 DROP_PERCENT=50 ./drop-test.sh start

    # Drop only egress (outbound) packets
    sudo TARGET_IP=192.168.100.3 DIRECTION=egress ./drop-test.sh start

    # Use custom BPF filter (tcpdump syntax)
    sudo BPF_FILTER="udp port 4433 and host 192.168.100.3" ./drop-test.sh start

    # Drop QUIC packets (UDP port 443)
    sudo TARGET_IP=192.168.100.3 TARGET_PORT=443 PROTOCOL=udp ./drop-test.sh start

    # Stop dropping packets
    sudo ./drop-test.sh stop
EOF
  exit 1
}

check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root" >&2
    exit 1
  fi
}

check_deps() {
  local missing=()
  command -v tc >/dev/null 2>&1 || missing+=("tc (iproute2)")
  command -v tcpdump >/dev/null 2>&1 || missing+=("tcpdump")

  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Error: Missing required tools: ${missing[*]}" >&2
    exit 1
  fi
}

detect_interface() {
  if [[ -n "$INTERFACE" ]]; then
    return
  fi

  if [[ -n "$TARGET_IP" ]]; then
    # Find interface for route to target
    INTERFACE=$(ip route get "$TARGET_IP" 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
  fi

  if [[ -z "$INTERFACE" ]]; then
    # Fall back to default interface
    INTERFACE=$(ip route show default | grep -oP 'dev \K\S+' | head -1)
  fi

  if [[ -z "$INTERFACE" ]]; then
    echo "Error: Could not detect network interface. Set INTERFACE manually." >&2
    exit 1
  fi
}

build_bpf_filter() {
  if [[ -n "$BPF_FILTER" ]]; then
    echo "$BPF_FILTER"
    return
  fi

  local parts=()

  # Protocol
  if [[ -n "$PROTOCOL" ]]; then
    parts+=("$PROTOCOL")
  fi

  # Port filter
  if [[ -n "$TARGET_PORT" ]]; then
    parts+=("port $TARGET_PORT")
  fi

  # IP filter
  if [[ -n "$TARGET_IP" ]]; then
    parts+=("host $TARGET_IP")
  fi

  if [[ ${#parts[@]} -eq 0 ]]; then
    echo "Error: Must specify TARGET_IP, TARGET_PORT, or BPF_FILTER" >&2
    exit 1
  fi

  # Join with "and"
  local IFS=" and "
  echo "${parts[*]}"
}

# Convert tcpdump filter to tc BPF bytecode
get_bpf_bytecode() {
  local filter="$1"
  local direction="$2"  # in or out

  # tcpdump -ddd outputs BPF bytecode in tc-compatible format
  # Use -s 65535 to ensure we can match on full packet
  local bytecode
  if [[ "$direction" == "in" ]]; then
    bytecode=$(tcpdump -i "$INTERFACE" -ddd "$filter" 2>/dev/null)
  else
    bytecode=$(tcpdump -i "$INTERFACE" -ddd "$filter" 2>/dev/null)
  fi

  if [[ -z "$bytecode" ]]; then
    echo "Error: Invalid BPF filter: $filter" >&2
    exit 1
  fi

  # Format for tc: first line is count, rest are comma-separated instructions
  echo "$bytecode" | {
    read -r count
    local instructions=()
    while read -r a b c d; do
      instructions+=("$a $b $c $d")
    done
    echo "$count,$(IFS=','; echo "${instructions[*]}")"
  }
}

setup_egress_qdisc() {
  # Remove existing qdisc if present
  tc qdisc del dev "$INTERFACE" root 2>/dev/null || true

  # Add prio qdisc for classification
  tc qdisc add dev "$INTERFACE" root handle "$QDISC_HANDLE" prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
}

setup_ingress_qdisc() {
  # Remove existing ingress qdisc if present
  tc qdisc del dev "$INTERFACE" ingress 2>/dev/null || true

  # Add ingress qdisc
  tc qdisc add dev "$INTERFACE" ingress
}

add_drop_filter() {
  local direction="$1"
  local bpf_filter="$2"

  local bytecode
  bytecode=$(get_bpf_bytecode "$bpf_filter" "$direction")

  if [[ "$DROP_PERCENT" -lt 100 ]]; then
    # Use probabilistic dropping with u32 hash
    # This is a simplification - for true random we'd need a more complex setup
    echo "  Warning: Probabilistic dropping uses hash-based selection, not true random" >&2
  fi

  if [[ "$direction" == "out" ]]; then
    # Egress filter
    if [[ "$DROP_PERCENT" -ge 100 ]]; then
      tc filter add dev "$INTERFACE" parent "$QDISC_HANDLE" protocol ip prio 1 \
        bpf bytecode "$bytecode" \
        action drop
    else
      # Use probability-based action
      tc filter add dev "$INTERFACE" parent "$QDISC_HANDLE" protocol ip prio 1 \
        bpf bytecode "$bytecode" \
        action gact drop random determ pass "$DROP_PERCENT"
    fi
  else
    # Ingress filter
    if [[ "$DROP_PERCENT" -ge 100 ]]; then
      tc filter add dev "$INTERFACE" parent "$INGRESS_HANDLE" protocol ip prio 1 \
        bpf bytecode "$bytecode" \
        action drop
    else
      tc filter add dev "$INTERFACE" parent "$INGRESS_HANDLE" protocol ip prio 1 \
        bpf bytecode "$bytecode" \
        action gact drop random determ pass "$DROP_PERCENT"
    fi
  fi
}

start_drop() {
  check_root
  check_deps
  detect_interface

  local bpf_filter
  bpf_filter=$(build_bpf_filter)

  # Clean up first
  stop_drop_quiet

  echo "Dropping packets on interface $INTERFACE"
  echo "  Filter: $bpf_filter"
  echo "  Direction: $DIRECTION"
  echo "  Drop rate: ${DROP_PERCENT}%"

  if [[ "$DIRECTION" == "egress" || "$DIRECTION" == "both" ]]; then
    setup_egress_qdisc
    add_drop_filter "out" "$bpf_filter"
    echo "  Egress filter: active"
  fi

  if [[ "$DIRECTION" == "ingress" || "$DIRECTION" == "both" ]]; then
    setup_ingress_qdisc
    add_drop_filter "in" "$bpf_filter"
    echo "  Ingress filter: active"
  fi

  if [[ "$DURATION" -gt 0 ]]; then
    echo "  Duration: ${DURATION}s"
    echo ""
    echo "Press Ctrl+C to stop early..."

    trap 'stop_drop; exit 0' INT TERM
    sleep "$DURATION"
    stop_drop
  else
    echo "  Duration: indefinite (run '$0 stop' to remove)"
  fi
}

stop_drop_quiet() {
  detect_interface 2>/dev/null || true
  if [[ -n "$INTERFACE" ]]; then
    tc qdisc del dev "$INTERFACE" root 2>/dev/null || true
    tc qdisc del dev "$INTERFACE" ingress 2>/dev/null || true
  fi

  # Also try common interfaces
  for iface in eth0 ens3 ens4 enp0s3 wlan0; do
    tc qdisc del dev "$iface" root 2>/dev/null || true
    tc qdisc del dev "$iface" ingress 2>/dev/null || true
  done
}

stop_drop() {
  check_root

  echo "Restoring connectivity..."
  stop_drop_quiet
  echo "Done."
}

show_status() {
  detect_interface 2>/dev/null || INTERFACE="eth0"

  echo "=== tc qdisc ($INTERFACE) ==="
  tc qdisc show dev "$INTERFACE" 2>/dev/null || echo "  (no qdisc)"
  echo ""
  echo "=== tc filters ($INTERFACE) ==="
  tc filter show dev "$INTERFACE" 2>/dev/null || echo "  (no egress filters)"
  echo ""
  tc filter show dev "$INTERFACE" ingress 2>/dev/null || echo "  (no ingress filters)"
}

case "${1:-}" in
start)
  start_drop
  ;;
stop)
  stop_drop
  ;;
status)
  show_status
  ;;
*)
  usage
  ;;
esac
