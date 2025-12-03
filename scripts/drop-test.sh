#!/usr/bin/env bash
set -euo pipefail

# Packet drop simulation using nftables
# Requires root privileges

TARGET_IP="${TARGET_IP:-}"
DURATION="${DURATION:-60}"
TABLE_NAME="qsh_test"

usage() {
  cat <<EOF
Usage: $0 [start|stop|status]

Simulate complete packet loss using nftables.

Commands:
    start   - Start dropping packets
    stop    - Stop dropping packets
    status  - Show current nft rules

Environment variables:
    TARGET_IP - Target IP address (required for start)
    DURATION  - Duration in seconds, 0 for indefinite (default: 60)

Examples:
    # Drop packets to specific IP for 60 seconds
    sudo TARGET_IP=192.168.100.3./drop-test.sh start

    # Drop packets indefinitely
    sudo TARGET_IP=192.168.100.3 DURATION=0 ./drop-test.sh start

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

ensure_table() {
  nft add table inet "$TABLE_NAME" 2>/dev/null || true
  nft add chain inet "$TABLE_NAME" output { type filter hook output priority 0 \; } 2>/dev/null || true
  nft add chain inet "$TABLE_NAME" input { type filter hook input priority 0 \; } 2>/dev/null || true
}

start_drop() {
  check_root

  if [[ -z "$TARGET_IP" ]]; then
    echo "Error: TARGET_IP is required" >&2
    usage
  fi

  # Clean up first
  stop_drop_quiet

  ensure_table

  echo "Dropping packets to/from $TARGET_IP:"

  nft add rule inet "$TABLE_NAME" output ip daddr "$TARGET_IP" drop
  nft add rule inet "$TABLE_NAME" input ip saddr "$TARGET_IP" drop

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
  nft flush chain inet "$TABLE_NAME" output 2>/dev/null || true
  nft flush chain inet "$TABLE_NAME" input 2>/dev/null || true
}

stop_drop() {
  check_root

  echo "Restoring connectivity..."
  stop_drop_quiet
  echo "Done."
}

show_status() {
  echo "=== nft $TABLE_NAME rules ==="
  nft list table inet "$TABLE_NAME" 2>/dev/null || echo "  (table not found)"
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
