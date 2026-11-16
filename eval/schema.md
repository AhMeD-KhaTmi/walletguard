# Evaluation result schema — Member A (traffic and client-side truth)

Version 1 · 2026-11-16 · supersedes the earlier starter column set.
Governed by `docs/MASTER_PLAN.md` section 7. Join key is **`(run_id, config, workload,
repetition)`**; never join on `config` alone.

## 1. What this file defines

`eval/results.csv` is produced by `eval/compute_metrics.py` from raw per-attempt records.
Each row is one measured run of one workload in one configuration. Raw evidence stays in
`eval/runs/<run_id>/` and is never rewritten by aggregation.

Rules that every column obeys:

1. The **client** is the denominator. Requests are counted because a workload decided to
   send them, including those dropped later by XDP or answered with a timeout.
2. Success is the **attack objective**, not Locust's status flag: a valid login token, the
   requested product data, or accounted generation (`HTTP 200` and `X-Tokens-Out > 0`).
3. `would_*` decisions are hypothetical observations, never denials.
4. A metric with no evidence is an **empty cell**, and its name is listed in
   `unavailable_fields`. Zero is only written when zero was measured.
5. Setup logins (`phase="setup"`) are excluded from malicious denominators and reported
   separately by the raw records.

## 2. Columns

| Column | Unit | Source | Definition |
|---|---|---|---|
| `run_id` | string | manifest | Unique run identifier; also the directory name under `eval/runs/` |
| `config` | C0–C4 | manifest | Requested configuration, confirmed through `/health` before traffic |
| `workload` | enum | manifest | `benign`, `credential_stuffing`, `scraping`, `dow`, `honeypot`, `churn` |
| `attack` | enum/empty | manifest | `credential_stuffing`, `scraping`, `dow`, `honeypot`, `churn`; empty for benign |
| `repetition` | integer | manifest | Repetition index for the same (config, workload) pair |
| `seed` | integer | manifest | `P20_SEED` used by the workload and dataset |
| `duration_s` | seconds | manifest | Wall-clock duration of the measured phase |
| `measured_attempts` | count | attempts | **All** attempts the client actually sent (`phase="measured"`), any outcome and any workload. Zero means the run is invalid |
| `malicious_attempts` | count | attempts | Measured attempts with `objective=true` |
| `attack_success` | count | attempts | Attempts whose objective was met |
| `unknown_outcomes` | count | attempts | `timeout`/`unknown`; may have succeeded server-side |
| `asr` | ratio | derived | `attack_success / malicious_attempts` |
| `unique_objectives` | count | attempts | Stuffing: distinct accounts compromised. Scraping: distinct products harvested. DoW: distinct accounts that generated usage |
| `tokens_in` | tokens | attempts | Sum of `X-Tokens-In` over measured malicious chat attempts |
| `tokens_out` | tokens | attempts | Sum of `X-Tokens-Out` (accounted generation) |
| `simulated_cost_usd` | USD | attempts | Sum of `X-Cost-USD`; synthetic pricing, not real spend |
| `detected_malicious_requests` | count | decisions stream | Malicious attempts whose `request_id` carries `throttle`/`block`/`ban`/`would_*` |
| `detection_rate` | ratio | derived | `detected_malicious_requests / malicious_attempts` |
| `observation_coverage` | ratio | decisions stream | Malicious attempts whose `request_id` appears in the stream at all; report it next to detection rate |
| `benign_attempts` | count | attempts | Measured non-objective attempts from labeled benign addresses |
| `benign_policy_denials` | count | attempts | Benign attempts answered 403/429 (a real denial, not a shadow verdict) |
| `false_positive_rate` | ratio | derived | `benign_policy_denials / benign_attempts` |
| `benign_errors`/`benign_timeouts` | count | attempts | Kept separate from policy denials |
| `latency_p50_ms`,`p95`,`p99` | ms | attempts | **Client** end-to-end latency of successful measured responses only |
| `time_to_ban_ms` | ms | attempts | Honeypot workload: first decoy hit → first follow-up answered 403 |
| `run_valid` | bool | manifest | `true` only when readiness passed and evidence exists |
| `evidence_path` | path | — | Run directory holding attempts, manifest, logs and decisions |
| `unavailable_fields` | csv | — | Names of columns with no evidence for this run |

## 3. Deliberately not in this file

Owned by Member B and merged later from `eval/results_b.csv`: request latency
percentiles measured inside the app, WAF `latency_ms` overhead, IsolationForest scoring
time and detector precision/recall/FPR, dashboard/user-facing behavior.

Also absent by design until the kernel layer exists: `time_to_redis_ban_ms`,
`time_to_map_insert_ms`, `time_to_first_xdp_drop_ms`, `agent_cpu_pct`,
`agent_rss_mb`, `xdp_dropped_packets`. Writing them now would be fabrication.

## 4. Raw run directory

```
eval/runs/<run_id>/
  manifest.json             # config, flags, seeds, identities, hashes, versions, revision
  attempts-<workload>-<ip>-<pid>.jsonl   # one line per attempt, one file per process
  decisions.jsonl           # p20:stream:waf_decisions captured during the run (C1/C2+)
  health.json               # effective mode/controls confirmed before traffic
  usage.json                # app usage counters before/after traffic
  api.log, mock.log         # process output
  locust-<ns>-<ip>.log      # per-identity workload output
```

Attempt record fields: `run_id, workload, attack, phase, objective, ip, pid, route,
method, intent, attempt_id, started_ms, ended_ms, latency_ms, status, outcome, reason,
unresolved` plus workload-specific fields (`client_id`, `credential_kind`, `page`,
`per_page`, `product_ids`, `tokens_in`, `tokens_out`, `cost_usd`, `usage_store`,
`request_id`, `response_bytes`).

`outcome` is one of `success`, `fail`, `blocked`, `timeout`, `error`, `unknown`.
No bearer token, password or prompt text is written.

## 5. Labels for ML training

`eval/labels.py` writes `run_id -> source IP -> benign|attack` from the workload each run
actually executed and the addresses observed in its own records. It refuses to label a run
that emitted traffic from an undeclared address.

`--splits-out` additionally suggests disjoint `benign_fit`, `benign_calibration` and
`test` run groups (attacks are test-only). B's `ml/train.py` still requires at least two
independent benign run groups and rejects overlapping test/training run IDs; the split
file is a proposal, not a policy override.
