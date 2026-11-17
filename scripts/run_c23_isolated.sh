#!/usr/bin/env bash
# Start the C2/C3 comparison on a private Linux bridge with disposable Redis.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export P20_PYTHON="${P20_PYTHON:-$PWD/.venv/bin/python}"
export NO_PROXY="127.0.0.1,localhost,10.20.0.1"
export WAF_MODEL_PATH="${WAF_MODEL_PATH:-$PWD/ml/model_base.joblib}"
export P20_MODEL_SHA256="${P20_MODEL_SHA256:-$(sha256sum "$WAF_MODEL_PATH" | cut -d' ' -f1)}"
out="${1:?usage: run_c23_isolated.sh OUTPUT_DIR [--smoke] [--workload NAME]}"
shift

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
  redis-cli -p 16379 ping | grep -qx PONG
  out=$1
  shift
  "$P20_PYTHON" scripts/run_c23_benchmark.py --out "$out" --redis-url redis://127.0.0.1:16379/0 \
    --model "$WAF_MODEL_PATH" \
    --model-sha256 "$P20_MODEL_SHA256" "$@"
' bash "$out" "$@"
