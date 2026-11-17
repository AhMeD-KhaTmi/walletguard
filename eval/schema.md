# Evaluation result schema — Member A (traffic and client-side truth)

Version 2 · 2026-11-17 · supersedes the earlier starter column set.
Governed by `docs/MASTER_PLAN.md` section 7. Join key is **`(run_id, config, workload,
profile, repetition)`**; never join on `config` alone. `profile` is empty for every
workload except `dow`, which is run under `undercap` and `overcap`.

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
| `workload` | enum | manifest | `benign`, `credential_stuffing`, `scraping`, `dow`, `honeypot`, `churn`, `mixed`, `combined` |
| `profile` | enum/empty | manifest | Sub-profile of a workload that changes traffic shape: `undercap`/`overcap` for `dow`, empty otherwise. Part of the summary grouping key, so the two DoW profiles are never averaged into one median. The harness's `--profile` default is **not** reported for other workloads, even though pre-2026-11-17 manifests carry it. |
| `attack` | enum/empty | manifest | `credential_stuffing`, `scraping`, `dow`, `honeypot`, `churn`, `combined`, `mixed`; empty for benign |
| `repetition` | integer | manifest | Repetition index for the same (config, workload) pair |
| `seed` | integer | manifest | `P20_SEED` used by the workload and dataset |
| `duration_s` | seconds | manifest | Wall-clock duration of the measured phase (the setup/gated phase is excluded; total run time is `wall_duration_s` in the manifest) |
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
| `waf_overhead_ms_mean` | ms | decisions stream | Mean `latency_ms` of WAF decisions. That field excludes downstream app/mock time, so it is WAF overhead, not client latency |
| `scoring_p50_ms`,`p95` | ms | — | IsolationForest scoring duration per request. Unavailable until a model runs (C3+) and the decision record carries a scoring duration |
| `time_to_ban_ms` | ms | attempts | Honeypot workload, **client-observed**: first decoy hit → first follow-up answered 403 |
| `time_to_redis_ban_ms` | ms | bans + attempts | Server-side: first measured malicious request from the banned IP → Redis `p20:ban:<ip>.ts_ms` |
| `time_to_map_insert_ms` | ms | — | Kernel layer only; empty with a status until the agent runs |
| `time_to_first_xdp_drop_ms` | ms | — | Kernel layer only; empty with a status until XDP is attached |
| `app_cpu_pct` | % of one core | `/proc` sample | Mean CPU of the API process over the measured phase (top convention). Interval and core count are in `manifest.resources` |
| `app_rss_mb` | MiB | `/proc` sample | Peak RSS of the API process during the measured phase |
| `agent_cpu_pct`,`agent_rss_mb` | — | manifest | Empty with `not_used_in_this_run` until the kernel agent exists |
| `xdp_dropped_packets` | packets | manifest | Empty with a status until XDP is attached. Packet counts are not request counts |
| `code_revision` | sha | manifest | Git commit that produced the evidence; a dirty tree is recorded as such |
| `policy_hash` | sha256 | manifest | Hash of `waf/config.py`, so bucket/ban policy cannot drift silently between runs |
| `model_hash` | sha256/empty | manifest | Hash of the model file; empty when no model ran (C0–C2) |
| `manifest_path` | path | — | `eval/runs/<run_id>/manifest.json` |
| `run_valid` | bool | manifest | `true` only when readiness passed and evidence exists |
| `evidence_path` | path | — | Run directory holding attempts, manifest, logs, decisions and bans |
| `unavailable_fields` | csv | — | Names of columns with no evidence for this run |

## 2a. Staged and multi-objective runs

- **`dow`**: each attacker logs in during a `phase="setup"` step; the harness then clears
  buckets, bans, strikes and streams while keeping `p20:app:session:*`, and only then opens
  the measured phase. Setup logins therefore never enter `malicious_attempts`, and the
  measured window starts with documented fresh policy state.
- **`mixed`**: benign identities and all three attack pools run concurrently in one row.
  `attack="mixed"`, ASR is aggregated across attack types, and a single
  `unique_objectives` count is reported as unavailable because it would mix products,
  accounts and tokens. Benign impact in that row is still measured per labeled address.
- **`combined`**: the three attacks together with no setup phase (`attack="combined"`),
  as required by §7.1. Same aggregation caveat as `mixed`.
- Per-attack ASR, `unique_objectives` and token cost come from the separated
  `credential_stuffing`, `scraping` and `dow` workloads, never from the aggregate rows.

## 3. Deliberately not in this file

Owned by Member B and merged later from `eval/results_b.csv`: IsolationForest detector
precision/recall/FPR, model manifests, dashboard/user-facing behavior. WAF overhead is
now measured here from the decision stream; the detector's own scores stay with B.

Fields above that are empty in a given run are empty **with a status**, never zero:

- `time_to_map_insert_ms`, `time_to_first_xdp_drop_ms`, `agent_*`, `xdp_dropped_packets`
  require the kernel layer (later PR).
- `scoring_p50_ms`/`p95` require a running model and a per-request scoring duration.
- `time_to_redis_ban_ms` is empty when the run produced no ban (`C0`, benign, churn).
- For `honeypot`, `time_to_ban_ms` is decoy hit → first 403 follow-up, computed over every
  attempt in the run: the follow-up probes are `phase="followup"`, so a metric that reads
  only `phase="measured"` can never produce it. It is bounded below by the client's own
  probe cadence (one task per second, the ban check is 1 task in 4), so it says how soon a
  client *notices* the ban, not how long the WAF took. `time_to_redis_ban_ms` is the
  defense-side number (first measured decoy attempt → `p20:ban:<ip>.ts_ms`), normally a few
  ms because the WAF writes the ban while handling that same decoy request.
- `code_revision` gets a `-dirty` suffix when the run was produced from an uncommitted
  tree; a plain SHA means the tree was clean.

## 4. Raw run directory

```
eval/runs/<run_id>/
  manifest.json             # config, flags, seeds, identities, hashes, versions, revision, resources
  attempts-<workload>-<ip>-<pid>.jsonl   # one line per attempt, one file per process
  decisions.jsonl           # p20:stream:waf_decisions captured during the run (C1/C2+)
  bans.json                 # p20:ban:<ip> records at end of run (empty list = no ban)
  gate/gate.json            # gated DoW: {"measured": true, "ts_ms", "opened_utc"} once setup ended
  gate/setup-ready-*.json   # gated DoW: one marker per user that finished its setup login
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

`eval/labels.py` writes `run_id -> source IP -> benign|attack|probe` from the workload each
run actually executed and the addresses observed in its own records. It refuses to label a
run that emitted traffic from an undeclared address. Connection-churn traffic is labelled
`probe`, not `attack`: it exists to exercise the kernel sensor (`MASTER_PLAN` 3.4/IT-2),
has no ASR objective, and must not become an attack training class.

`--splits-out` additionally suggests disjoint `benign_fit`, `benign_calibration` and
`test` run groups (attacks are test-only). Only **C1** runs can appear in those groups,
because only observe mode writes `p20:stream:waf_features`; benign traffic measured in C0
or C2 is behaviour evidence, not training data. Probe runs are listed separately in
`probe_runs`. When no C1 observe-mode attack run exists, the file says so explicitly
(`attack_features: "unavailable"` plus a detail line) instead of implying that the
enforcement attack runs can be used for detector precision/recall. B's `ml/train.py` still
requires at least two independent benign run groups and rejects overlapping test/training
run IDs; the split file is a proposal, not a policy override.
