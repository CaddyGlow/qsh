#!/usr/bin/env bash
set -euo pipefail

# Profile-based network impairment wrapper around netem-test.sh
# Requires root privileges (same as netem-test.sh).
#
# Usage:
#   netem-profile.sh <profile> [start|stop|status]
#   netem-profile.sh list
#
# Examples:
#   sudo ./scripts/netem-profile.sh 3g start
#   sudo ./scripts/netem-profile.sh wifi_shitty start
#   sudo ./scripts/netem-profile.sh sat start
#   sudo ./scripts/netem-profile.sh 3g stop
#   ./scripts/netem-profile.sh list
#
# Profiles are defined as functions in scripts/netem-profiles.conf:
#   profile_<name>() { LATENCY_MS=...; JITTER_MS=...; LOSS_PERCENT=...; RATE_KBIT=...; }
# You can override or add your own profiles by editing that file or
# pointing NETEM_PROFILE_CONFIG to an alternate config path.
#
# You can further restrict which traffic is affected by setting either:
#   TARGET_IP / TARGET_PORT / TARGET_PROTO
# or advanced tc fragments:
#   EGRESS_FILTER / INGRESS_FILTER
# (when INGRESS_FILTER/EGRESS_FILTER are set, TARGET_* are ignored and
#  the filter body is passed directly to `tc filter add`.)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETEM_SCRIPT="${SCRIPT_DIR}/netem-test.sh"
PROFILE_CONFIG="${NETEM_PROFILE_CONFIG:-${SCRIPT_DIR}/netem-profiles.conf}"

usage() {
  cat <<EOF
Usage:
  $0 <profile> [start|stop|status]
  $0 list

Profiles are mapped to tc netem settings (latency, jitter, loss, rate).

Examples:
  sudo $0 3g start
  sudo $0 3g_shitty start
  sudo $0 4g start
  sudo $0 wifi_shitty start
  sudo $0 sat start
  sudo $0 adsl start
  sudo $0 56k start
  sudo $0 3g stop
  $0 list

To narrow which traffic is shaped, combine with environment variables:
  # Only HTTPS to a specific IP:
  sudo TARGET_IP=1.2.3.4 TARGET_PORT=443 TARGET_PROTO=tcp $0 3g start

  # Custom tc filters (advanced):
  sudo EGRESS_FILTER='protocol ip prio 1 u32 match ip dst 1.2.3.4/32 flowid 1:1' \\
       INGRESS_FILTER='protocol ip u32 match ip src 1.2.3.4/32 action mirred egress redirect dev ifb0' \\
       $0 3g start
EOF
  exit 1
}

load_profiles() {
  if [[ -f "$PROFILE_CONFIG" ]]; then
    # shellcheck source=/dev/null
    . "$PROFILE_CONFIG"
  fi
}

list_profiles() {
  load_profiles
  echo "Available profiles:"
  compgen -A function | sed -n 's/^profile_//p' | sort
}

apply_profile() {
  local profile="$1"
  local func="profile_${profile}"

  load_profiles

  if ! declare -F "$func" >/dev/null 2>&1; then
    echo "Error: unknown profile '${profile}'" >&2
    echo "" >&2
    list_profiles >&2
    exit 1
  fi

  # Call the profile function in this shell to set LATENCY_MS, JITTER_MS, etc.
  "$func"

  : "${LATENCY_MS:?profile did not set LATENCY_MS}"
  : "${JITTER_MS:?profile did not set JITTER_MS}"
  : "${LOSS_PERCENT:?profile did not set LOSS_PERCENT}"
  : "${RATE_KBIT:=}"

  echo "Using profile '${profile}':"
  echo "  Latency: ${LATENCY_MS}ms (+/- ${JITTER_MS}ms jitter)"
  echo "  Loss: ${LOSS_PERCENT}%"
  if [[ -n "${RATE_KBIT}" ]]; then
    echo "  Rate: ${RATE_KBIT} kbit/s"
  else
    echo "  Rate: unlimited"
  fi
}

main() {
  if [[ $# -eq 0 ]]; then
    usage
  fi

  local profile action

  case "$1" in
    list)
      list_profiles
      exit 0
      ;;
  esac

  profile="$1"
  action="${2:-start}"

  case "$action" in
    start|stop|status)
      ;;
    *)
      usage
      ;;
  esac

  if [[ ! -x "$NETEM_SCRIPT" ]]; then
    echo "Error: netem-test.sh not found or not executable at: $NETEM_SCRIPT" >&2
    exit 1
  fi

  if [[ "$action" == "start" ]]; then
    apply_profile "$profile"
  fi

  # Delegate to netem-test.sh with whatever env vars are now set.
  exec "$NETEM_SCRIPT" "$action"
}

main "$@"
