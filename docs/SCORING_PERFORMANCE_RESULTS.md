# Original-model scoring performance

Twelve valid C3 runs form six matched direct/batched pairs, three repetitions
per workload with seeds 601–603. Both variants use the original frozen forest,
40,000-token capacity / 2,400-token/s policy and identical agent/mock runtime.
Benign windows last 45 seconds (10 users); mixed windows last 90 seconds
(14 users). Batch size is 32, collection delay 2ms, bounded queue 256; size 1
selects the original per-request off-thread execution. No model weights or
anomaly threshold changed.

## Results

Values below are medians of the three per-run measurements. Client p95 is for
successful labeled benign traffic. WAF and scoring p95 use their own finalized
server timing samples. CPU is mean API-process utilization in percent of one
core; workload throughput can change when latency changes.

| Workload / execution | Benign client p95 ms | Scoring p95 ms | WAF p95 ms | API CPU % | Benign denials / attempts | Benign unknowns | Benign bans |
|---|---:|---:|---:|---:|---:|---:|---:|
| benign / direct | 128.56 | 39.51 | 56.19 | 10.74 | 0 / 554 | 1 | 0 |
| benign / batch | 120.18 | 26.15 | 37.84 | 8.26 | 0 / 558 | 0 | 0 |
| mixed / direct | 712.05 | 165.39 | 258.47 | 91.12 | 0 / 490 | 0 | 0 |
| mixed / batch | 291.50 | 52.99 | 96.47 | 96.75 | 0 / 530 | 0 | 0 |

One direct benign request ended with `GreenletExit` at shutdown (0.858ms)
and remains unknown; the five-second stop timeout did not eliminate every
shutdown interruption. All batched benign outcomes are complete.

Retain bounded batching as the default based on these matched latency results.
Mixed-load CPU remains high: batching permits more work during the same window,
so these data do not establish lower CPU cost per request. Direct execution is
available with `WAF_SCORE_BATCH_SIZE=1` for comparison and troubleshooting.
All safety denominators and metric ranges remain in [the JSON](evidence/model_calibration/performance.json)
and [per-run CSV](evidence/model_calibration/performance.csv).

## Evidence and limitations

The validator checks all twelve distinct runs, clean source, matching per-pair
seeds/identity/policy/workload/mock/model, full source coverage, timing evidence,
and exact independent API/mock token/step/cost totals. Raw captures are local at
`eval/runs/model-performance-v1/`; measured source is `c220319`. Runtime hashes
are in [the publication manifest](evidence/model_calibration/runtime_source.json).

An environment restart interrupted the campaign after seven intact captures.
Mixed direct repetition 2 had empty JSON snapshots and was excluded and rerun;
its seed/settings remain fixed. The original batch-then-direct order for this
pair is retained across the restart. Repetition 3 follows the restart. Preserve
this timing/environment limitation and the rejected capture rather than claiming
an uninterrupted campaign. [Recovery record](evidence/model_calibration/performance_restart.json).

These are C3 execution variants, with no matched C0 in this performance-only
campaign. Do not present their difference as a C0 overhead measurement. Earlier
C0/C2/C3 budget and professor campaigns remain immutable. Detector quality is
unchanged: [new candidate acceptance failed](MODEL_CALIBRATION_REVISIONS.md).
Real sensor/XDP/C4 and joint IT-1–IT-6 remain pending.
