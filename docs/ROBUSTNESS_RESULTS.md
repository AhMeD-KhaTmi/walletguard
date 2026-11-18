# Fixed-policy robustness results

45 valid measured runs form 15 matched C0/C2/C3 triplets,
three independent repetitions at seeds1101–1103. The qualified volume model,
budgets, batching, strike/ban rules and Redis schema were held fixed. No model
was trained and no policy was adjusted from these outcomes. All targets were the
isolated synthetic Linux lab. Fifteen compressed-timing smoke captures are separate.

## Main findings

- Slow and distributed scraping/token-generation objectives have100% ASR in C0,
  C2 and C3. Every deliberately valid synthetic credential also succeeds; invalid
  guesses remain ordinary failures. Current per-identity controls do not stop these
  below-allowance and account-fanout scenarios.
- Within-capacity legitimate bursts:0/810 denied in both C2 and C3, no bans.
- Shared legitimate account: C2 denies308/540 (57.04%), C3 denies310/540 (57.41%);
  each has12 ban records across three reset runs (four source IPs per run).
- Above-burst-capacity legitimate demand: C2 denies1440/1890 (76.19%), C3 denies
  1425/1890 (75.40%); each has15 ban records (five source IPs per run).
- Zero unknown outcomes and no excluded/retried captures. Capture completeness
  passed; the security/comfort outcomes above did not all meet their targets.

C3 flags 1320/1500 distributed scrape requests and 240/240 token-generation requests,
but blocks none. Current anomaly bans require budget corroboration; these actors
stay inside individual allowances. Meanwhile C3 flags248/810 legitimate within-cap
burst requests without denying them. Removing corroboration is therefore not a
validated remedy. No account or policy changes were deployed by this study.

## Legitimate users

Counts pool three repetitions. Ban counts sum ban records across reset runs; the
same source IP can recur in multiple repetitions. FPR is observed policy denials divided by measured
benign attempts. Setup outcomes and other failures remain separate. A benign
label is not changed when traffic exceeds an allowance. Attack-only distributed
runs have no benign FPR denominator and are omitted from this table.

| Profile | Config | Benign attempts | Policy denials | FPR % | Benign bans | Errors/timeouts/unknowns | Setup unsuccessful | Comfort target |
|---|---|---:|---:|---:|---:|---:|---:|---|
| slow_mixed | C0 | 450 | 0 | 0.000 | 0 | 0/0/0 | 0 | pass |
| slow_mixed | C2 | 450 | 0 | 0.000 | 0 | 0/0/0 | 0 | pass |
| slow_mixed | C3 | 450 | 0 | 0.000 | 0 | 0/0/0 | 0 | pass |
| shared_account | C0 | 540 | 0 | 0.000 | 0 | 0/0/0 | 0 | pass |
| shared_account | C2 | 540 | 308 | 57.037 | 12 | 0/0/0 | 0 | FAIL |
| shared_account | C3 | 540 | 310 | 57.407 | 12 | 0/0/0 | 0 | FAIL |
| burst_within | C0 | 810 | 0 | 0.000 | 0 | 0/0/0 | 0 | pass |
| burst_within | C2 | 810 | 0 | 0.000 | 0 | 0/0/0 | 0 | pass |
| burst_within | C3 | 810 | 0 | 0.000 | 0 | 0/0/0 | 0 | pass |
| burst_above | C0 | 1890 | 0 | 0.000 | 0 | 0/0/0 | 0 | pass |
| burst_above | C2 | 1890 | 1440 | 76.190 | 15 | 0/0/0 | 0 | FAIL |
| burst_above | C3 | 1890 | 1425 | 75.397 | 15 | 0/0/0 | 0 | FAIL |

The comfort target is <=1% denials in each run, zero benign bans, zero unsuccessful
setup and no benign error/timeout/unknown/other-failure outcomes. This is a safety
criterion, not a capture-validity filter. Unfavorable captures remain in the study.

## Attack outcomes

ASR uses all measured malicious attempts, including failed synthetic guesses.
Known-valid credential ASR is a diagnostic subset; it does not replace the primary
denominator. Success means an actual login token, requested catalogue data, or
accounted token generation, using A's unchanged objective classifiers.

| Profile | Config | Attack | Attempts | Successes | ASR % | Blocked | Error/timeout/unknown | Known-valid login ASR % |
|---|---|---|---:|---:|---:|---:|---:|---:|
| slow_mixed | C0 | credential_stuffing | 45 | 13 | 28.889 | 0 | 0/0/0 | 100.000 |
| slow_mixed | C0 | scraping | 432 | 432 | 100.000 | 0 | 0/0/0 | — |
| slow_mixed | C0 | dow | 15 | 15 | 100.000 | 0 | 0/0/0 | — |
| slow_mixed | C2 | credential_stuffing | 45 | 13 | 28.889 | 0 | 0/0/0 | 100.000 |
| slow_mixed | C2 | scraping | 432 | 432 | 100.000 | 0 | 0/0/0 | — |
| slow_mixed | C2 | dow | 15 | 15 | 100.000 | 0 | 0/0/0 | — |
| slow_mixed | C3 | credential_stuffing | 45 | 13 | 28.889 | 0 | 0/0/0 | 100.000 |
| slow_mixed | C3 | scraping | 432 | 432 | 100.000 | 0 | 0/0/0 | — |
| slow_mixed | C3 | dow | 15 | 15 | 100.000 | 0 | 0/0/0 | — |
| distributed | C0 | credential_stuffing | 75 | 19 | 25.333 | 0 | 0/0/0 | 100.000 |
| distributed | C0 | scraping | 1500 | 1500 | 100.000 | 0 | 0/0/0 | — |
| distributed | C0 | dow | 240 | 240 | 100.000 | 0 | 0/0/0 | — |
| distributed | C2 | credential_stuffing | 75 | 19 | 25.333 | 0 | 0/0/0 | 100.000 |
| distributed | C2 | scraping | 1500 | 1500 | 100.000 | 0 | 0/0/0 | — |
| distributed | C2 | dow | 240 | 240 | 100.000 | 0 | 0/0/0 | — |
| distributed | C3 | credential_stuffing | 75 | 19 | 25.333 | 0 | 0/0/0 | 100.000 |
| distributed | C3 | scraping | 1500 | 1500 | 100.000 | 0 | 0/0/0 | — |
| distributed | C3 | dow | 240 | 240 | 100.000 | 0 | 0/0/0 | — |

The above-cap schedule has a periodic steady-state demand of42/24=1.75 requests/s
per IP. The50s observation includes three bursts,126 requests/IP (2.52/s over that
finite window), below the integrated initial-plus-refill allowance of130. Its
instantaneous burst still exceeds capacity30. Actual per-IP rates remain in JSON.

## Tokens, cost and harvesting

Server counters are independently cross-checked against the mock's exact tokens,
steps and simulated cost in every run. Slow mixed totals include benign tasks;
distributed runs are attack-only. No real provider charges are involved. Unique
product counts below are medians of per-run counts, not sums of repeated IDs.

| Profile | Config | Server output tokens, median | Simulated cost, median | Unique scraped products/run, median |
|---|---|---:|---:|---:|
| slow_mixed | C0 | 54000 | $1.268730 | 5000 |
| slow_mixed | C2 | 54000 | $1.268730 | 5000 |
| slow_mixed | C3 | 54000 | $1.268730 | 5000 |
| distributed | C0 | 216000 | $3.966480 | 5000 |
| distributed | C2 | 216000 | $3.966480 | 5000 |
| distributed | C3 | 216000 | $3.966480 | 5000 |

## Timing and model flags

Client percentiles use successful benign requests. Blocking can change that
surviving population, so read latency together with denial counts. Baseline deltas
are calculated inside each matched repetition before taking their median.
Detector flags are separate from enforcement. C0/C2 do not score ML inputs.

| Profile | Config | Client p50 ms | Client p95 ms | Δp50 vs C0 ms | Δp95 vs C0 ms | WAF p50 ms | WAF p95 ms | Benign model flags/scored |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| slow_mixed | C0 | 5.97 | 54.77 | 0.00 | 0.00 | — | — | — |
| slow_mixed | C2 | 10.13 | 58.04 | 4.25 | 4.55 | 6.71 | 16.17 | — |
| slow_mixed | C3 | 24.09 | 82.74 | 18.80 | 29.26 | 18.44 | 41.62 | 0/450 |
| shared_account | C0 | 21.94 | 55.24 | 0.00 | 0.00 | — | — | — |
| shared_account | C2 | 10.26 | 50.54 | -11.98 | -5.37 | 7.12 | 11.70 | — |
| shared_account | C3 | 29.10 | 84.35 | 5.99 | 28.43 | 19.63 | 43.29 | 0/540 |
| burst_within | C0 | 4.69 | 28.56 | 0.00 | 0.00 | — | — | — |
| burst_within | C2 | 14.51 | 40.46 | 9.82 | 10.99 | 14.04 | 26.85 | — |
| burst_within | C3 | 50.44 | 92.42 | 45.75 | 63.86 | 53.04 | 81.49 | 248/810 |
| burst_above | C0 | 4.71 | 16.26 | 0.00 | 0.00 | — | — | — |
| burst_above | C2 | 14.26 | 22.03 | 9.55 | 6.85 | 11.08 | 18.68 | — |
| burst_above | C3 | 52.50 | 73.87 | 47.79 | 56.90 | 39.86 | 68.37 | 1516/1890 |

## Next experiments, not changes deployed by this study

- Separate account-quota contention from evidence used for automatic IP bans.
  Preserve throttling and require prospective tests for legitimate shared accounts,
  within/above burst profiles, fast attacks and Redis outage behavior.
- Evaluate an explicitly scoped aggregate wallet/spending allowance across accounts.
  The current token bucket limits rate/burst per account; it is not a total-spend
  cap. Select future values from separate legitimate-demand calibration data.
- Add response-aware benign clients that honor Retry-After, alongside these fixed
  schedules. Keep both profiles and their labels; do not replace unfavorable data.
- Retain corroboration safeguards while studying stronger attribution: volume
  alone can flag legitimate bursts too. Simply banning every anomaly is not a
  demonstrated remedy. Valid synthetic credentials at ordinary rates remain an
  authentication-risk limit, distinct from request-volume control.

Every remedy requires a separate frozen design, new data and before/after checks.
No such policy or authentication change was made here. A can continue kernel work
in parallel; C4 alone is not evidence that these application-policy gaps are fixed.

## Evidence and scope

Measured source: `39040482748d717d11c7852b455abbac4fb74c40`. Model SHA-256:
`1eb84211004b6abe42cd2b8ec03e4b06b8504884ad0a8b9c1ca81ce2f55829e3`. [Frozen protocol](ROBUSTNESS_PROTOCOL.md),
[per-run CSV](evidence/robustness/results.csv),
[validated summaries/rates/flags/outcomes](evidence/robustness/validation.json).
Raw evidence is local at `eval/runs/robustness-v1/`. Compressed smoke validation
is under `docs/evidence/robustness/smoke/` and is not pooled with these measurements.

The independent validator checks the expected45-run matrix, clean source,
identity coverage, matching seeds/policy/model/workload/driver metadata, and API/
mock accounting. Per-IP actual request counts, peak one-second windows and rates
are retained. Failed or retried capture records stay in the raw output directory.

These new workload families test boundaries outside the model's earlier benign
training envelope. The earlier99.01% recall result remains valid only for its own
held-out distribution; it does not promise universal detection or blocking.
Fresh seeds do not establish robustness against every attacker or production
workload. Shared account contention and above-cap bursts remain legitimate demand. These
fixed-schedule clients continue planned actions after429 and do not implement
Retry-After backoff. That stress assumption matters for automatic-ban findings;
response-aware clients require their own prospective test profile.
No policy fix is claimed by this evaluation. Any remedy needs a separate prospective
experiment and fresh validation. A's real sensor/enforcement, C4 and final joint
IT-1–IT-6 acceptance remain separate integration work.
