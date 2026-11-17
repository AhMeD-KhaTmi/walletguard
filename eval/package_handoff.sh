#!/usr/bin/env bash
# Package the traffic/data handoff Member B consumes.
#
# B needs the feature rows, the run manifests, the raw client/decision records, the
# label file and the split proposal. All of that lives under eval/runs/, which is
# gitignored, so this builds a checksummed tarball instead of committing runtime
# evidence.
#
#   bash eval/package_handoff.sh [runs_dir] [out_dir]
#
# Exit status is non-zero when no run carries an archived feature export: an archive
# without features cannot start C3, and saying so is better than shipping an empty one.

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runs=${1:-"$root/eval/runs"}
out_dir=${2:-"$root/eval/handoff"}
commit=$(git -C "$root" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

if [ ! -d "$runs" ]; then
  echo "no run directory at $runs" >&2
  exit 2
fi

mkdir -p "$stage/features" "$stage/manifests" "$stage/raw"
run_count=0
feature_count=0

for run in "$runs"/*/; do
  [ -f "$run/manifest.json" ] || continue
  id=$(basename "$run")
  run_count=$((run_count + 1))
  cp "$run/manifest.json" "$stage/manifests/$id.json"
  if [ -s "$run/features.jsonl" ]; then
    cp "$run/features.jsonl" "$stage/features/$id.jsonl"
    feature_count=$((feature_count + 1))
  fi
  mkdir -p "$stage/raw/$id"
  shopt -s nullglob
  files=("$run"attempts-*.jsonl "$run"decisions.jsonl "$run"bans.json \
         "$run"usage.json "$run"worker-*.json "$run"api.log "$run"mock.log \
         "$run"locust-*.log)
  shopt -u nullglob
  if [ ${#files[@]} -gt 0 ]; then
    cp "${files[@]}" "$stage/raw/$id/"
  fi
done

for shared in labels.json splits.json results.csv summary.csv; do
  if [ -f "$root/eval/$shared" ]; then
    cp "$root/eval/$shared" "$stage/$shared"
  fi
done

# B's ml/train.py reads CSV, so render the same archived rows with the label joined.
if [ "$feature_count" -gt 0 ]; then
  py=${PYTHON:-"$root/.venv/bin/python"}
  [ -x "$py" ] || py=python3
  "$py" "$root/eval/export_features.py" --runs "$runs" \
    --labels "$root/eval/labels.json" --out-dir "$stage/features-csv" > "$stage/csv.log" \
    || { cat "$stage/csv.log" >&2; echo "ERROR: labelled CSV rendering failed" >&2; exit 1; }
fi

{
  echo "# WalletGuard traffic / C1 handoff"
  echo
  echo "- built: $stamp"
  echo "- code revision: $commit"
  echo "- runs included: $run_count"
  echo "- runs with an archived feature export: $feature_count"
  echo
  echo "## Layout"
  echo
  echo '```'
  echo "features/<run_id>.jsonl   # p20:stream:waf_features, one JSON object per line"
  echo "features-csv/<run_id>.csv # same rows + label joined from labels.json (for ml/train.py)"
  echo "manifests/<run_id>.json   # config, flags, seed(s), identities, hashes, features count"
  echo "raw/<run_id>/             # attempts, decisions, bans, usage, worker seeds, logs"
  echo "labels.json               # run_id -> source IP -> benign/attack/probe"
  echo "splits.json               # fit/calibration/test run IDs (only feature-carrying runs)"
  echo "results.csv, summary.csv  # the measured rows and the per-group medians"
  echo '```'
  echo
  echo "Feature rows already carry the WAF's own \`run_id\` and \`ip\`, so they join to"
  echo "\`labels.json\` without re-deriving identities. \`manifest.features\` records the"
  echo "row count and SHA-256 that this archive was built from. The CSV rendering is the"
  echo "same rows, so a run appears in both or in neither."
  echo
  echo "## Feature exports"
  echo
  echo "| run_id | rows | sha256 |"
  echo "|---|---|---|"
  for file in "$stage"/features/*.jsonl; do
    [ -e "$file" ] || continue
    printf '| %s | %s | %s |\n' \
      "$(basename "$file" .jsonl)" \
      "$(wc -l < "$file")" \
      "$(sha256sum "$file" | cut -d' ' -f1)"
  done
} > "$stage/HANDOFF.md"

mkdir -p "$out_dir"
archive="$out_dir/p20-handoff-$commit-$stamp.tar.gz"
tar -czf "$archive" -C "$stage" .

echo "archive: $archive"
echo "size: $(stat -c%s "$archive") bytes"
echo "sha256: $(sha256sum "$archive" | cut -d' ' -f1)"
echo "runs: $run_count, with features: $feature_count"

if [ "$feature_count" -eq 0 ]; then
  echo "ERROR: no run has a features.jsonl export; C3 cannot start from this archive" >&2
  exit 1
fi
