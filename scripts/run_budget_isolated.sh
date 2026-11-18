#!/usr/bin/env bash
# B's campaign, confined to a disposable user/network/mount namespace.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export P20_PYTHON="${P20_PYTHON:-$PWD/.venv/bin/python}"
export NO_PROXY="127.0.0.1,localhost,10.20.0.1"
unshare --user --map-root-user --net --mount --propagation private bash -euc '
  mount -t tmpfs -o size=1m tmpfs /run/netns
  ip link set lo up
  lab=$(mktemp -d)
  redis_pid=""
  cleanup() {
    if [ -n "$redis_pid" ]; then
      kill "$redis_pid" 2>/dev/null || true
      wait "$redis_pid" 2>/dev/null || true
    fi
    rm -f "$lab/redis.log" "$lab/netns.log"
    rmdir "$lab"
  }
  trap cleanup EXIT
  if ! bash scripts/make_netns.sh > "$lab/netns.log" 2>&1; then
    cat "$lab/netns.log" >&2
    exit 1
  fi
  redis-server --bind 127.0.0.1 --port 16379 --save "" --appendonly no --dir "$lab" > "$lab/redis.log" 2>&1 &
  redis_pid=$!
  for _ in {1..40}; do
    redis-cli -p 16379 ping 2>/dev/null | grep -qx PONG && break
    kill -0 "$redis_pid"
    sleep .1
  done
  export REDIS_URL=redis://127.0.0.1:16379/0
  bash scripts/reset_state.sh --redis-url "$REDIS_URL"
  "$P20_PYTHON" "${P20_CAMPAIGN_SCRIPT:-scripts/run_budget_campaign.py}" --redis-url "$REDIS_URL" "$@"
' bash "$@"
