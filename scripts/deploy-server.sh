#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# -------------------------------------------------------------------
# Config (override via env or flags)
# -------------------------------------------------------------------
HOST="${HOST:-rl.mazenet.org}"
SSH_USER="${SSH_USER:-deploy}"
TARGET="${TARGET:-x86_64-unknown-linux-musl}"
PROFILE="${PROFILE:-release}"   # release|debug
SKIP_CLIENT="${SKIP_CLIENT:-0}" # 1 to skip qsh client upload
SKIP_SERVER="${SKIP_SERVER:-0}" # 1 to skip qsh-server upload

usage() {
  cat <<'EOF'
Usage: ./deploy-server.sh [--release] [--skip-client] [--skip-server] [--host HOST] [--user USER]
Env overrides: HOST, SSH_USER, TARGET, PROFILE, SKIP_CLIENT, SKIP_SERVER
EOF
}

# Parse a few lightweight flags (keep simple)
while [[ $# -gt 0 ]]; do
  case "$1" in
  --debug) PROFILE="debug" ;;
  --skip-client) SKIP_CLIENT=1 ;;
  --skip-server) SKIP_SERVER=1 ;;
  --host)
    HOST="$2"
    shift
    ;;
  --user)
    SSH_USER="$2"
    shift
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "Unknown arg: $1" >&2
    usage
    exit 1
    ;;
  esac
  shift
done

# Use nix develop if not already inside
if [[ -n "${IN_NIX_SHELL:-}" ]]; then
  NIX_PREFIX=()
else
  NIX_PREFIX=(nix develop --command)
fi

profile_flag=(--release)
profile_dir="release"
if [[ "$PROFILE" == "debug" ]]; then
  profile_flag=()
  profile_dir="debug"
fi

build() {
  "${NIX_PREFIX[@]}" cargo build -p qsh-server -p qsh-client --bin qsh --bin qsh-server --target "$TARGET" "${profile_flag[@]}"
}

copy_bin() {
  local src="$1" dst="$2"
  pv "$src" | ssh -C "$SSH_USER@$HOST" "sudo tee $dst >/dev/null && sudo chmod +x $dst"
}

# Graceful stop: SIGTERM with timeout, then SIGKILL
graceful_stop() {
  local proc="$1" timeout="${2:-10}"
  ssh "$SSH_USER@$HOST" "
    if pgrep -x '$proc' >/dev/null 2>&1; then
      echo 'Stopping $proc (SIGTERM)...'
      sudo pkill -TERM -x '$proc' || true
      for i in \$(seq 1 $timeout); do
        pgrep -x '$proc' >/dev/null 2>&1 || { echo '$proc stopped'; exit 0; }
        sleep 1
      done
      echo '$proc did not stop, sending SIGKILL...'
      sudo pkill -KILL -x '$proc' || true
    fi
  "
}

server_path="target/$TARGET/$profile_dir/qsh-server"
client_path="target/$TARGET/$profile_dir/qsh"

echo "Target: $TARGET | Profile: $PROFILE | Host: $SSH_USER@$HOST"

echo "Building binaries..."
build

echo "Stopping old binaries on $HOST..."
graceful_stop qsh-server 10
graceful_stop qsh 10
ssh "$SSH_USER@$HOST" "sudo rm -f /tmp/qsh-server.log /usr/local/bin/qsh-server /usr/local/bin/qsh"

if [[ "$SKIP_SERVER" != "1" ]]; then
  echo "Deploying qsh-server..."
  copy_bin "$server_path" "/usr/local/bin/qsh-server"
fi

if [[ "$SKIP_CLIENT" != "1" ]]; then
  echo "Deploying qsh client..."
  copy_bin "$client_path" "/usr/local/bin/qsh"
fi

echo "Deployment complete."
