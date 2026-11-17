#!/usr/bin/env bash
# Repetition grid for MASTER_PLAN 7.2.6: three repetitions per (config, workload), with
# the execution order rotated between repetitions so a slow first run does not always
# land on the same workload. Per-run rows stay in eval/results.csv; the median/range
# summary is produced afterwards by compute_metrics.py --summary-out.
#
#   sudo ./eval/run_grid.sh C0
#   sudo ./eval/run_grid.sh C2 2            # repetition 2 only
#   sudo ./eval/run_grid.sh C0 -- --dry-run # print commands, change nothing
#
# A failed or invalid run is reported and the grid continues; the exit status is the
# number of failed runs (0 = all runs returned success).
set -uo pipefail

CONFIG="${1:?usage: run_grid.sh C0|C2 [repetition] [-- extra harness args]}"
shift
ONLY_REP=""
if [[ $# -gt 0 && "$1" != --* ]]; then
  ONLY_REP="$1"
  shift
fi
if [[ $# -gt 0 && "$1" == "--" ]]; then
  shift
fi
EXTRA=("$@")

if [[ ! -f eval/harness.py ]]; then
  echo "run this from the repository root (eval/harness.py not found)" >&2
  exit 64
fi

PY=".venv/bin/python"
WORKLOADS=(stuffing scraping dow-undercap dow-overcap honeypot churn benign combined mixed)
FAILURES=0

run_one() {
  local name="$1" rep="$2"
  local args=()
  case "$name" in
    stuffing)     args=(--workload credential_stuffing --duration 45s) ;;
    scraping)     args=(--workload scraping            --duration 45s) ;;
    dow-undercap) args=(--workload dow --profile undercap --duration 45s) ;;
    dow-overcap)  args=(--workload dow --profile overcap  --duration 45s) ;;
    honeypot)     args=(--workload honeypot            --duration 20s) ;;
    churn)        args=(--workload churn               --duration 20s) ;;
    benign)       args=(--workload benign --duration 90s --users 10) ;;
    combined)     args=(--workload combined            --duration 45s) ;;
    mixed)        args=(--workload mixed               --duration 90s) ;;
    *)            echo "unknown workload name $name" >&2; return 1 ;;
  esac
  local run_id
  run_id="$(echo "$CONFIG" | tr '[:upper:]' '[:lower:]')-${name}-r${rep}"
  echo "=== $run_id ==="
  "$PY" eval/harness.py run --config "$CONFIG" "${args[@]}" \
      --repetition "$rep" --run-id "$run_id" "${EXTRA[@]}"
}

for rep in 1 2 3; do
  if [[ -n "$ONLY_REP" && "$rep" != "$ONLY_REP" ]]; then
    continue
  fi
  offset=$(( rep - 1 ))
  for i in "${!WORKLOADS[@]}"; do
    name="${WORKLOADS[$(( (i + offset) % ${#WORKLOADS[@]} ))]}"
    if ! run_one "$name" "$rep"; then
      echo "FAILED or invalid: $CONFIG/$name r$rep" >&2
      FAILURES=$(( FAILURES + 1 ))
    fi
  done
done

echo "grid finished: $FAILURES failed run(s)"
exit "$FAILURES"
