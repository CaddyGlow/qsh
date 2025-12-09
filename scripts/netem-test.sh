#!/usr/bin/env bash
set -euo pipefail

# Network impairment simulation using tc netem
# Requires root privileges

IFACE="${IFACE:-eth0}"
TARGET_IP="${TARGET_IP:-}"
TARGET_PORT="${TARGET_PORT:-}"
TARGET_PROTO="${TARGET_PROTO:-}"
INGRESS_FILTER="${INGRESS_FILTER:-}"
EGRESS_FILTER="${EGRESS_FILTER:-}"
LATENCY_MS="${LATENCY_MS:-100}"
JITTER_MS="${JITTER_MS:-20}"
LOSS_PERCENT="${LOSS_PERCENT:-5}"
DURATION="${DURATION:-30}"
RATE_KBIT="${RATE_KBIT:-}"
IFB_DEV="ifb0"

usage() {
  cat <<EOF
Usage: $0 [start|stop|status]

Simulate bad network conditions using tc netem.
Applies to both egress and ingress for accurate RTT simulation.

Commands:
    start   - Apply network impairments
    stop    - Remove network impairments
    status  - Show current qdisc settings

Environment variables:
    IFACE        - Network interface (default: eth0)
    TARGET_IP    - Target IP address (optional)
    TARGET_PORT  - Target TCP/UDP port (optional)
    TARGET_PROTO - L4 protocol: tcp, udp, icmp or numeric (optional)
    INGRESS_FILTER - Custom tc filter body for ingress (optional, overrides TARGET_*)
    EGRESS_FILTER  - Custom tc filter body for egress  (optional, overrides TARGET_*)
    LATENCY_MS   - Base latency in ms (default: 100)
    JITTER_MS    - Latency jitter in ms (default: 20)
    LOSS_PERCENT - Packet loss percentage (default: 5)
    DURATION     - Duration in seconds, 0 for indefinite (default: 30)
    RATE_KBIT    - Bandwidth limit in kbit/s (optional, unlimited if unset)

Examples:
    # Add impairments to specific IP
    sudo TARGET_IP=104.238.191.37 ./netem-test.sh start

    # Add 200ms latency with 10% loss to specific IP
    sudo TARGET_IP=1.2.3.4 LATENCY_MS=200 LOSS_PERCENT=10 ./netem-test.sh start

    # Limit to TCP 443 to a specific IP
    sudo TARGET_IP=1.2.3.4 TARGET_PORT=443 TARGET_PROTO=tcp ./netem-test.sh start

    # Limit to all TCP 443 traffic, any IP
    sudo TARGET_PORT=443 TARGET_PROTO=tcp ./netem-test.sh start

    # Simulate terrible mobile network to all traffic
    sudo LATENCY_MS=300 JITTER_MS=100 LOSS_PERCENT=15 ./netem-test.sh start

    # Remove impairments
    sudo ./netem-test.sh stop
EOF
  exit 1
}

check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root" >&2
    exit 1
  fi
}

setup_ifb() {
  # Load ifb module and bring up ifb0
  modprobe ifb numifbs=1 2>/dev/null || true
  ip link set dev "$IFB_DEV" up 2>/dev/null || true
}

start_impairment() {
  check_root

  # Clean up first
  stop_impairment_quiet

  setup_ifb

  local proto_num=""
  if [[ -n "$TARGET_PROTO" ]]; then
    case "$TARGET_PROTO" in
    tcp | TCP) proto_num=6 ;;
    udp | UDP) proto_num=17 ;;
    icmp | ICMP) proto_num=1 ;;
    [0-9]*) proto_num="$TARGET_PROTO" ;;
    *)
      echo "Error: unsupported TARGET_PROTO '$TARGET_PROTO' (use tcp, udp, icmp, or numeric protocol number)" >&2
      exit 1
      ;;
    esac
  fi

  echo "Applying network impairments to $IFACE (egress + ingress):"
  if [[ -n "$INGRESS_FILTER" || -n "$EGRESS_FILTER" ]]; then
    echo "  Custom filters enabled (TARGET_* ignored):"
    if [[ -n "$EGRESS_FILTER" ]]; then
      echo "    EGRESS_FILTER: $EGRESS_FILTER"
    fi
    if [[ -n "$INGRESS_FILTER" ]]; then
      echo "    INGRESS_FILTER: $INGRESS_FILTER"
    fi
  elif [[ -n "$TARGET_IP" || -n "$TARGET_PORT" || -n "$TARGET_PROTO" ]]; then
    echo "  Target filters (built from TARGET_*):"
    echo "    IP: ${TARGET_IP:-any}"
    echo "    Port: ${TARGET_PORT:-any}"
    echo "    Proto: ${TARGET_PROTO:-any}"
  else
    echo "  Target: all traffic"
  fi
  echo "  Latency: ${LATENCY_MS}ms (+/- ${JITTER_MS}ms jitter) each direction"
  echo "  Loss: ${LOSS_PERCENT}% each direction"
  if [[ -n "$RATE_KBIT" ]]; then
    echo "  Rate limit: ${RATE_KBIT} kbit/s each direction"
  else
    echo "  Rate limit: unlimited"
  fi

  local netem_rate_args=()
  if [[ -n "$RATE_KBIT" ]]; then
    netem_rate_args=(rate "${RATE_KBIT}kbit")
  fi

  if [[ -n "$INGRESS_FILTER" || -n "$EGRESS_FILTER" || -n "$TARGET_IP" || -n "$TARGET_PORT" || -n "$TARGET_PROTO" ]]; then
    # EGRESS: Use prio qdisc with filter to target specific traffic
    tc qdisc add dev "$IFACE" root handle 1: prio bands 3 priomap 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2
    tc qdisc add dev "$IFACE" parent 1:1 handle 10: netem \
      delay "${LATENCY_MS}ms" "${JITTER_MS}ms" distribution normal \
      loss "${LOSS_PERCENT}%" \
      "${netem_rate_args[@]}"

    if [[ -n "$EGRESS_FILTER" ]]; then
      # Full filter body is provided by user, e.g.:
      #   "protocol ip prio 1 u32 match ip dst 1.2.3.4/32 flowid 1:1"
      tc filter add dev "$IFACE" parent 1:0 $EGRESS_FILTER
    else
      local egress_filter=(tc filter add dev "$IFACE" parent 1:0 protocol ip prio 1 u32)
      if [[ -n "$proto_num" ]]; then
        egress_filter+=(match ip protocol "$proto_num" 0xff)
      fi
      if [[ -n "$TARGET_IP" ]]; then
        egress_filter+=(match ip dst "$TARGET_IP"/32)
      fi
      if [[ -n "$TARGET_PORT" ]]; then
        egress_filter+=(match ip dport "$TARGET_PORT" 0xffff)
      fi
      egress_filter+=(flowid 1:1)
      "${egress_filter[@]}"
    fi

    # INGRESS: Redirect to IFB, then apply netem there
    tc qdisc add dev "$IFACE" handle ffff: ingress
    if [[ -n "$INGRESS_FILTER" ]]; then
      # Full filter body is provided by user, e.g.:
      #   "protocol ip u32 match ip src 1.2.3.4/32 action mirred egress redirect dev ifb0"
      tc filter add dev "$IFACE" parent ffff: $INGRESS_FILTER
    else
      local ingress_filter=(tc filter add dev "$IFACE" parent ffff: protocol ip u32)
      if [[ -n "$proto_num" ]]; then
        ingress_filter+=(match ip protocol "$proto_num" 0xff)
      fi
      if [[ -n "$TARGET_IP" ]]; then
        ingress_filter+=(match ip src "$TARGET_IP"/32)
      fi
      if [[ -n "$TARGET_PORT" ]]; then
        ingress_filter+=(match ip sport "$TARGET_PORT" 0xffff)
      fi
      ingress_filter+=(action mirred egress redirect dev "$IFB_DEV")
      "${ingress_filter[@]}"
    fi

    tc qdisc add dev "$IFB_DEV" root handle 1: netem \
      delay "${LATENCY_MS}ms" "${JITTER_MS}ms" distribution normal \
      loss "${LOSS_PERCENT}%" \
      "${netem_rate_args[@]}"
  else
    # EGRESS: Apply to all traffic
    tc qdisc add dev "$IFACE" root netem \
      delay "${LATENCY_MS}ms" "${JITTER_MS}ms" distribution normal \
      loss "${LOSS_PERCENT}%" \
      "${netem_rate_args[@]}"

    # INGRESS: Redirect all to IFB
    tc qdisc add dev "$IFACE" handle ffff: ingress
    tc filter add dev "$IFACE" parent ffff: protocol ip u32 \
      match u32 0 0 \
      action mirred egress redirect dev "$IFB_DEV"

    tc qdisc add dev "$IFB_DEV" root handle 1: netem \
      delay "${LATENCY_MS}ms" "${JITTER_MS}ms" distribution normal \
      loss "${LOSS_PERCENT}%" \
      "${netem_rate_args[@]}"
  fi

  if [[ "$DURATION" -gt 0 ]]; then
    echo "  Duration: ${DURATION}s"
    echo ""
    echo "Press Ctrl+C to stop early..."

    trap 'stop_impairment; exit 0' INT TERM
    sleep "$DURATION"
    stop_impairment
  else
    echo "  Duration: indefinite (run '$0 stop' to remove)"
  fi
}

stop_impairment_quiet() {
  tc qdisc del dev "$IFACE" root 2>/dev/null || true
  tc qdisc del dev "$IFACE" ingress 2>/dev/null || true
  tc qdisc del dev "$IFB_DEV" root 2>/dev/null || true
}

stop_impairment() {
  check_root

  echo "Removing network impairments from $IFACE..."
  stop_impairment_quiet
  echo "Done."
}

show_status() {
  echo "=== $IFACE qdisc ==="
  tc qdisc show dev "$IFACE" 2>/dev/null || echo "  (none)"
  echo ""
  echo "=== $IFACE filters ==="
  tc filter show dev "$IFACE" 2>/dev/null || echo "  (none)"
  echo ""
  echo "=== $IFACE ingress ==="
  tc filter show dev "$IFACE" ingress 2>/dev/null || echo "  (none)"
  echo ""
  echo "=== $IFB_DEV qdisc ==="
  tc qdisc show dev "$IFB_DEV" 2>/dev/null || echo "  (none)"
}

case "${1:-}" in
start)
  start_impairment
  ;;
stop)
  stop_impairment
  ;;
status)
  show_status
  ;;
*)
  usage
  ;;
esac
