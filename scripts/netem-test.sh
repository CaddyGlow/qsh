#!/bin/bash
set -euo pipefail

# Network impairment simulation using tc netem
# Requires root privileges

IFACE="${IFACE:-eth0}"
TARGET_IP="${TARGET_IP:-}"
LATENCY_MS="${LATENCY_MS:-100}"
JITTER_MS="${JITTER_MS:-20}"
LOSS_PERCENT="${LOSS_PERCENT:-5}"
DURATION="${DURATION:-30}"
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
    TARGET_IP    - Target IP address (optional, applies to all traffic if not set)
    LATENCY_MS   - Base latency in ms (default: 100)
    JITTER_MS    - Latency jitter in ms (default: 20)
    LOSS_PERCENT - Packet loss percentage (default: 5)
    DURATION     - Duration in seconds, 0 for indefinite (default: 30)

Examples:
    # Add impairments to specific IP
    sudo TARGET_IP=104.238.191.37 ./netem-test.sh start

    # Add 200ms latency with 10% loss to specific IP
    sudo TARGET_IP=1.2.3.4 LATENCY_MS=200 LOSS_PERCENT=10 ./netem-test.sh start

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

    echo "Applying network impairments to $IFACE (egress + ingress):"
    if [[ -n "$TARGET_IP" ]]; then
        echo "  Target: $TARGET_IP"
    else
        echo "  Target: all traffic"
    fi
    echo "  Latency: ${LATENCY_MS}ms (+/- ${JITTER_MS}ms jitter) each direction"
    echo "  Loss: ${LOSS_PERCENT}% each direction"

    if [[ -n "$TARGET_IP" ]]; then
        # EGRESS: Use prio qdisc with filter to target specific IP
        tc qdisc add dev "$IFACE" root handle 1: prio bands 3 priomap 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2
        tc qdisc add dev "$IFACE" parent 1:1 handle 10: netem \
            delay "${LATENCY_MS}ms" "${JITTER_MS}ms" distribution normal \
            loss "${LOSS_PERCENT}%"
        tc filter add dev "$IFACE" parent 1:0 protocol ip prio 1 u32 \
            match ip dst "$TARGET_IP"/32 flowid 1:1

        # INGRESS: Redirect to IFB, then apply netem there
        tc qdisc add dev "$IFACE" handle ffff: ingress
        tc filter add dev "$IFACE" parent ffff: protocol ip u32 \
            match ip src "$TARGET_IP"/32 \
            action mirred egress redirect dev "$IFB_DEV"

        tc qdisc add dev "$IFB_DEV" root handle 1: netem \
            delay "${LATENCY_MS}ms" "${JITTER_MS}ms" distribution normal \
            loss "${LOSS_PERCENT}%"
    else
        # EGRESS: Apply to all traffic
        tc qdisc add dev "$IFACE" root netem \
            delay "${LATENCY_MS}ms" "${JITTER_MS}ms" distribution normal \
            loss "${LOSS_PERCENT}%"

        # INGRESS: Redirect all to IFB
        tc qdisc add dev "$IFACE" handle ffff: ingress
        tc filter add dev "$IFACE" parent ffff: protocol ip u32 \
            match u32 0 0 \
            action mirred egress redirect dev "$IFB_DEV"

        tc qdisc add dev "$IFB_DEV" root handle 1: netem \
            delay "${LATENCY_MS}ms" "${JITTER_MS}ms" distribution normal \
            loss "${LOSS_PERCENT}%"
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
