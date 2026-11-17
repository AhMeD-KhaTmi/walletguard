# PR #1 — Member A traffic/data handoff

Branch: `member-a/traffic-handoff`. No merge to `main`.

## Delivery

- Release: https://github.com/AhMeD-KhaTmi/walletguard/releases/tag/traffic-handoff-20261117
- Asset: `p20-handoff-4764f4be4548-20261117T152204Z.tar.gz`
- Size: 141,492,605 bytes.
- SHA-256: `84d0ab8c5b6f176ecab76fbcd9e422feeeca78d0ee0183a353c90f16d35cd55f`
- Archive contains 118 manifests, six feature JSONL exports, six labeled CSVs,
  labels/splits, results/summary and available raw per-run evidence.
- Measurement revision for the corrected benchmark: `4764f4b`. The delivery
  commit comes later; the archive preserves original measurement revisions.

## Response to B's three requests

1. **C1 data collected and packaged.** Independent benign runs:
   `c1-benign-f1` (364 rows), `c1-benign-f2` (401), `c1-benign-f3` (387).
   Attack runs: credential stuffing (4171), scraping (7000), under-cap DoW (3290).
   Labels join by run ID and source IP. No unknown labels or empty CSV fields
   were found in these six exported files during artifact review.
   `splits.json` proposes f1 for fit, f2 for calibration and f3 plus all three
   attacks for held-out testing. Old featureless C1 runs are excluded.
2. **Harness corrections implemented.** Failed/overrunning workers and late
   traffic invalidate runs; actual configured and per-process derived seeds are
   recorded. HTTP timeouts and uncertain generation outcomes remain explicit.
   Setup and measured traffic are separate; benign metrics exclude attack traffic.
   Future standalone DoW manifests record pacing. Summary groups separate code
   revision and DoW pacing; missing historical pace is unavailable, not zero.
   User verified 106 eval tests passing on the Linux VM.
3. **Corrected C0/C2 benchmark rerun.** 54 new `corrected-*` runs at clean
   `4764f4b`: nine workload/profile shapes, two configs, three repetitions,
   distinct source IPs, seed 42 and varied execution order. All 54 verified
   valid; all 118 historical/new result rows are currently valid under aggregation.
   Use the `4764f4b` summary groups for the corrected benchmark, not older revisions.
   Attempts, usage and bans are archived; C1/C2 decisions are archived. C0 has
   no decision stream because the WAF is off, not because zero detections were
   measured. Older runs lack per-worker seed files; they were not reconstructed.

## Token-budget evidence

`c2-dow-undercap-paced-r1` is a separate 150-second probe at `0eecf88`:
29 successful measured attempts, 37 blocked, no unknown outcomes. Decisions:
12 `throttle/llm_tok`, three `ban/budget`, 22 `block/banned`, 29 allow.
First token throttle was 56,537 ms after the first measured request; the
server-side first Redis ban metric was 91,642 ms. These are different endpoints,
not interchangeable defense-processing latencies. Client `time_to_ban_ms` is
unavailable for this DoW row. Its old manifest does not record pacing; no
retroactive value was inserted. It is not pooled with the corrected burst runs.

## What B does next

- Verify the asset SHA-256 and feature hashes against the per-run manifests.
- Review the CSVs, labels and proposed splits. Current `ml/train.py` requires at
  least two benign run groups and performs its own grouped fit/calibration split:
  supply f1+f2 together, retain their run IDs, inspect the resulting model manifest,
  and keep f3 plus all attack runs out of training. Passing f1 alone will fail.
  Enforcing the exact proposed fit/calibration assignment is B's tooling decision.
- Train/calibrate/evaluate C3 and report held-out detector precision/recall/FPR.
  No production model, C3 result or C4/kernel integration is claimed here.

The archive is a Release attachment, not a Git blob. Shared documents and eval
artifacts are in the branch; B-owned application/WAF/ML code was not changed.
