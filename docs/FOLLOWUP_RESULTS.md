# Fairness, burst, scraping and hard-spend results

Nine fresh benign calibration runs, five separate pipeline smokes,93 component validation runs and12 additional combined validation runs use disjoint groups/seeds. Each measured arm has three repetitions; order reverses in repetition2. All119 captures remain preserved. The [prospective protocol](FAIRNESS_BURST_SPEND_PROTOCOL.md) fixes the methods and gates before validation. No model fitting or test-based policy adjustment occurred.

Component source `e85db2087a658907c0b741c545e5eb6957cb68ec`; combined-client source `f6de6d29213e460d12ad199668e67bd153d8fa42`. Their application/WAF/common/model trees match. The qualified model remains `1eb84211004b6abe42cd2b8ec03e4b06b8504884ad0a8b9c1ca81ce2f55829e3`. A-owned implementation and shared Redis schema2/ban reasons/TTLs remain unchanged.

## Acceptance and release

| Gate | Result |
|---|---|
| fairness | PASS |
| bursts | PASS |
| hard_spend | PASS |
| preserved_defenses | PASS |
| scraping_volume_slow | PASS |
| scraping_volume_distributed | PASS |
| combined_compatibility | PASS |

The fitted lane/IP/item policy is the qualified C2/C3 default. Hard spending remains opt-in with an explicitly initialized operator-chosen period and cap. [Effective release decision](evidence/followup/decision.json) · [Launch and replay instructions](FOLLOWUP_CONTROLS.md).

## Fitting and interpretation

- Whole tasks up to2,048 tokens use a9,000-capacity/1,800-token/s small lane. Larger tasks use47,000/5,500. Their sum is56,000/7,300; the pooled comparator uses exactly that same envelope. No role labels, client trust hints or special account lists enter admission. Each lane and the total satisfy C+R*elapsed; independent API/mock/audit totals agree.
- Benign burst peaks42 requests and800 items in1s,2,400 items in60s select IP capacity60 (refill2/s unchanged), product capacity1,000/refill50 items/s. Product costs use the API-clamped requested page size. Account40,000/2,400, output cap, strike/ban settings and model remain fixed.
- The hard period cap is1,000,000 synthetic micro-USD ($1), at input3/output15 micro-USD/token. It has no refill, expiry or automatic rotation. Whole-task reservations and idempotent known-unused refunds retain uncertain credit. Routine runtime reset/API restart preserve the ledger; missing/mismatched/unreachable authority cannot grant new funds. Normal default local-bucket fallback remains.
- Task-size lanes protect small work from large-task exhaustion. Identical small-task abuse, within-lane contention, idle stranded capacity and shared-fund exhaustion remain limitations. These results establish the tested policy, not universal fairness or perfect protection.

## Legitimate traffic and latency

FPR is measured benign policy denials / benign attempts, distinct from detector flags. Ban counts are records summed across resets, not lifetime-unique IPs. Successful-response client percentiles and paired C0 deltas are calculated per run before reporting their median. WAF overhead excludes downstream work and includes finalization.

| Profile | Config | Variant | Benign attempts | Denied | Bans | Client p50/p95 ms | Paired C0 delta p50/p95 ms | WAF p50/p95 ms |
|---|---|---|---:|---:|---:|---|---|---|
| fair_mixed | C0 | current | 285 | 0 | 0 | 19.78/74.20 | 0.00/0.00 | n/a/n/a |
| fair_mixed | C2 | current | 285 | 0 | 0 | 29.37/85.41 | 9.59/10.80 | 14.27/31.30 |
| fair_mixed | C2 | lanes | 285 | 0 | 0 | 25.23/80.48 | 4.05/6.28 | 13.31/35.01 |
| fair_mixed | C3 | lanes | 285 | 0 | 0 | 45.54/131.75 | 23.83/50.41 | 32.20/67.70 |
| fair_mixed | C2 | pooled | 285 | 3 | 0 | 33.50/83.28 | 7.92/14.69 | 14.13/35.00 |
| varied | C0 | current | 382 | 0 | 0 | 7.66/140.71 | 0.00/0.00 | n/a/n/a |
| varied | C2 | current | 378 | 0 | 0 | 13.83/131.02 | 6.17/-9.69 | 4.34/15.30 |
| varied | C2 | lanes | 381 | 0 | 0 | 12.34/153.10 | 6.03/12.27 | 4.57/16.76 |
| varied | C3 | lanes | 378 | 0 | 0 | 31.83/135.00 | 22.77/3.85 | 19.47/48.56 |
| burst_fixed | C0 | current | 1890 | 0 | 0 | 4.54/23.57 | 0.00/0.00 | n/a/n/a |
| burst_fixed | C2 | current | 1890 | 1440 | 15 | 13.20/16.26 | 8.51/-7.32 | 10.11/16.46 |
| burst_fixed | C2 | resource | 1890 | 0 | 0 | 15.31/27.36 | 10.78/10.35 | 14.61/21.96 |
| burst_fixed | C3 | resource | 1890 | 0 | 0 | 65.88/99.14 | 61.52/75.56 | 66.28/96.42 |
| burst_retry | C0 | current | 1890 | 0 | 0 | 6.27/22.92 | 0.00/0.00 | n/a/n/a |
| burst_retry | C2 | current | 1890 | 1380 | 15 | 12.99/30.05 | 6.81/4.48 | 8.34/18.69 |
| burst_retry | C2 | resource | 1890 | 0 | 0 | 17.09/29.44 | 10.96/6.02 | 15.67/23.90 |
| burst_retry | C3 | resource | 1890 | 0 | 0 | 67.47/99.98 | 61.20/81.69 | 67.28/98.26 |
| slow | C0 | current | 750 | 0 | 0 | 18.40/86.47 | 0.00/0.00 | n/a/n/a |
| slow | C2 | current | 750 | 0 | 0 | 24.63/79.46 | 3.66/-7.01 | 10.93/28.71 |
| slow | C2 | resource | 750 | 0 | 0 | 25.71/81.76 | 4.67/-5.20 | 11.86/28.44 |
| slow | C3 | resource | 750 | 0 | 0 | 43.35/114.07 | 24.95/31.16 | 27.34/59.67 |
| combined_burst | C0 | current | 1890 | 0 | 0 | 5.91/26.16 | 0.00/0.00 | n/a/n/a |
| combined_burst | C2 | current | 1890 | 1440 | 15 | 21.86/35.97 | 15.95/9.43 | 12.80/33.32 |
| combined_burst | C2 | combined | 1890 | 0 | 0 | 18.11/41.54 | 12.39/15.38 | 15.03/37.70 |
| combined_burst | C3 | combined | 1890 | 0 | 0 | 76.82/119.13 | 70.91/92.63 | 57.38/115.90 |

The combined gate additionally requires all630 planned benign requests to succeed in EVERY candidate run, not only a low denial rate among attempted work. This tests ten burst users alongside20 attack users. Setup/other failures and all-actor errors/timeouts/unknowns must be zero.

## Tokens and simulated spending

| Profile | Config | Variant | Median tokens | Median simulated USD | Wallet denials | Cap denials |
|---|---|---|---:|---:|---:|---:|
| fair_mixed | C0 | current | 370815.00 | 3.207645 | 0 | 0 |
| fair_mixed | C2 | current | 370815.00 | 3.207645 | 0 | 0 |
| fair_mixed | C2 | lanes | 302091.00 | 2.612673 | 36 | 0 |
| fair_mixed | C3 | lanes | 302091.00 | 2.612673 | 36 | 0 |
| fair_mixed | C2 | pooled | 365088.00 | 3.158064 | 6 | 0 |
| spend | C0 | current | 343620.00 | 2.974860 | 0 | 0 |
| spend | C2 | cap | 114540.00 | 0.991620 | 0 | 120 |
| spend | C3 | cap | 114540.00 | 0.991620 | 0 | 120 |
| combined_burst | C0 | current | 781092.00 | 6.772716 | 0 | 0 |
| combined_burst | C2 | current | 607062.00 | 5.255586 | 0 | 0 |
| combined_burst | C2 | combined | 311478.00 | 2.707074 | 234 | 0 |
| combined_burst | C3 | combined | 311478.00 | 2.707074 | 235 | 0 |

Every capped C2/C3 run charges991,620 micro-USD ($0.991620), below1,000,000; the ledger agrees with actual usage. Normal rate wallets are burst/sustained allowances and do not bound total lifetime spending. The strict cap intentionally stops work when shared funds run out. Allowlisted management traffic is exempt from WAF admission; real billing, Redis persistence/backups and period rotation are operational concerns outside the synthetic prototype.

## Attack-specific success and catalogue exposure

ASR includes all malicious objective attempts. Known-valid synthetic credential success is diagnostic, never a replacement denominator. The frozen>=10% scraping criterion measures successful page-delivery volume; it is named scraping_volume in reports. Unique catalogue products are measured per run, never summed across repetitions.

| Profile | Config | Variant | Attack | Attempts | Successes | ASR % | Blocked | Error/timeout/unknown | Median unique products/run | Valid login success/attempts |
|---|---|---|---|---:|---:|---:|---:|---|---:|---|
| fair_mixed | C0 | current | credential_stuffing | 36 | 9 | 25.00 | 0 | 0/0/0 | n/a | 9/9 |
| fair_mixed | C0 | current | scraping | 675 | 675 | 100.00 | 0 | 0/0/0 | 3000 | 0/0 |
| fair_mixed | C0 | current | dow | 180 | 180 | 100.00 | 0 | 0/0/0 | n/a | 0/0 |
| fair_mixed | C2 | current | credential_stuffing | 36 | 9 | 25.00 | 0 | 0/0/0 | n/a | 9/9 |
| fair_mixed | C2 | current | scraping | 675 | 675 | 100.00 | 0 | 0/0/0 | 3000 | 0/0 |
| fair_mixed | C2 | current | dow | 180 | 180 | 100.00 | 0 | 0/0/0 | n/a | 0/0 |
| fair_mixed | C2 | lanes | credential_stuffing | 36 | 9 | 25.00 | 0 | 0/0/0 | n/a | 9/9 |
| fair_mixed | C2 | lanes | scraping | 675 | 675 | 100.00 | 0 | 0/0/0 | 3000 | 0/0 |
| fair_mixed | C2 | lanes | dow | 180 | 144 | 80.00 | 36 | 0/0/0 | n/a | 0/0 |
| fair_mixed | C3 | lanes | credential_stuffing | 36 | 9 | 25.00 | 0 | 0/0/0 | n/a | 9/9 |
| fair_mixed | C3 | lanes | scraping | 675 | 675 | 100.00 | 0 | 0/0/0 | 3000 | 0/0 |
| fair_mixed | C3 | lanes | dow | 180 | 144 | 80.00 | 36 | 0/0/0 | n/a | 0/0 |
| fair_mixed | C2 | pooled | credential_stuffing | 36 | 9 | 25.00 | 0 | 0/0/0 | n/a | 9/9 |
| fair_mixed | C2 | pooled | scraping | 675 | 675 | 100.00 | 0 | 0/0/0 | 3000 | 0/0 |
| fair_mixed | C2 | pooled | dow | 180 | 177 | 98.33 | 3 | 0/0/0 | n/a | 0/0 |
| distributed | C0 | current | credential_stuffing | 60 | 15 | 25.00 | 0 | 0/0/0 | n/a | 15/15 |
| distributed | C0 | current | scraping | 1125 | 1125 | 100.00 | 0 | 0/0/0 | 5000 | 0/0 |
| distributed | C0 | current | dow | 180 | 180 | 100.00 | 0 | 0/0/0 | n/a | 0/0 |
| distributed | C2 | current | credential_stuffing | 60 | 15 | 25.00 | 0 | 0/0/0 | n/a | 15/15 |
| distributed | C2 | current | scraping | 1125 | 1125 | 100.00 | 0 | 0/0/0 | 5000 | 0/0 |
| distributed | C2 | current | dow | 180 | 180 | 100.00 | 0 | 0/0/0 | n/a | 0/0 |
| distributed | C2 | resource | credential_stuffing | 60 | 15 | 25.00 | 0 | 0/0/0 | n/a | 15/15 |
| distributed | C2 | resource | scraping | 1125 | 480 | 42.67 | 645 | 0/0/0 | 5000 | 0/0 |
| distributed | C2 | resource | dow | 180 | 180 | 100.00 | 0 | 0/0/0 | n/a | 0/0 |
| distributed | C3 | resource | credential_stuffing | 60 | 15 | 25.00 | 0 | 0/0/0 | n/a | 15/15 |
| distributed | C3 | resource | scraping | 1125 | 480 | 42.67 | 645 | 0/0/0 | 5000 | 0/0 |
| distributed | C3 | resource | dow | 180 | 180 | 100.00 | 0 | 0/0/0 | n/a | 0/0 |
| slow | C0 | current | credential_stuffing | 72 | 18 | 25.00 | 0 | 0/0/0 | n/a | 18/18 |
| slow | C0 | current | scraping | 720 | 720 | 100.00 | 0 | 0/0/0 | 5000 | 0/0 |
| slow | C0 | current | dow | 24 | 24 | 100.00 | 0 | 0/0/0 | n/a | 0/0 |
| slow | C2 | current | credential_stuffing | 72 | 18 | 25.00 | 0 | 0/0/0 | n/a | 18/18 |
| slow | C2 | current | scraping | 720 | 720 | 100.00 | 0 | 0/0/0 | 5000 | 0/0 |
| slow | C2 | current | dow | 24 | 24 | 100.00 | 0 | 0/0/0 | n/a | 0/0 |
| slow | C2 | resource | credential_stuffing | 72 | 18 | 25.00 | 0 | 0/0/0 | n/a | 18/18 |
| slow | C2 | resource | scraping | 720 | 621 | 86.25 | 99 | 0/0/0 | 5000 | 0/0 |
| slow | C2 | resource | dow | 24 | 24 | 100.00 | 0 | 0/0/0 | n/a | 0/0 |
| slow | C3 | resource | credential_stuffing | 72 | 18 | 25.00 | 0 | 0/0/0 | n/a | 18/18 |
| slow | C3 | resource | scraping | 720 | 621 | 86.25 | 99 | 0/0/0 | 5000 | 0/0 |
| slow | C3 | resource | dow | 24 | 24 | 100.00 | 0 | 0/0/0 | n/a | 0/0 |
| spend | C0 | current | credential_stuffing | 60 | 15 | 25.00 | 0 | 0/0/0 | n/a | 15/15 |
| spend | C0 | current | scraping | 1125 | 1125 | 100.00 | 0 | 0/0/0 | 5000 | 0/0 |
| spend | C0 | current | dow | 180 | 180 | 100.00 | 0 | 0/0/0 | n/a | 0/0 |
| spend | C2 | cap | credential_stuffing | 60 | 15 | 25.00 | 0 | 0/0/0 | n/a | 15/15 |
| spend | C2 | cap | scraping | 1125 | 1125 | 100.00 | 0 | 0/0/0 | 5000 | 0/0 |
| spend | C2 | cap | dow | 180 | 60 | 33.33 | 120 | 0/0/0 | n/a | 0/0 |
| spend | C3 | cap | credential_stuffing | 60 | 15 | 25.00 | 0 | 0/0/0 | n/a | 15/15 |
| spend | C3 | cap | scraping | 1125 | 1125 | 100.00 | 0 | 0/0/0 | 5000 | 0/0 |
| spend | C3 | cap | dow | 180 | 60 | 33.33 | 120 | 0/0/0 | n/a | 0/0 |
| fast | C0 | current | scraping | 5062 | 5062 | 100.00 | 0 | 0/0/0 | 5000 | 0/0 |
| fast | C2 | resource | scraping | 5186 | 90 | 1.74 | 5096 | 0/0/0 | 1000 | 0/0 |
| fast | C3 | resource | scraping | 2630 | 99 | 3.76 | 2531 | 0/0/0 | 1100 | 0/0 |
| combined_burst | C0 | current | credential_stuffing | 72 | 18 | 25.00 | 0 | 0/0/0 | n/a | 18/18 |
| combined_burst | C0 | current | scraping | 1512 | 1512 | 100.00 | 0 | 0/0/0 | 3000 | 0/0 |
| combined_burst | C0 | current | dow | 408 | 408 | 100.00 | 0 | 0/0/0 | n/a | 0/0 |
| combined_burst | C2 | current | credential_stuffing | 72 | 18 | 25.00 | 0 | 0/0/0 | n/a | 18/18 |
| combined_burst | C2 | current | scraping | 1512 | 701 | 46.36 | 811 | 0/0/0 | 3000 | 0/0 |
| combined_burst | C2 | current | dow | 408 | 319 | 78.19 | 89 | 0/0/0 | n/a | 0/0 |
| combined_burst | C2 | combined | credential_stuffing | 72 | 18 | 25.00 | 0 | 0/0/0 | n/a | 18/18 |
| combined_burst | C2 | combined | scraping | 1512 | 297 | 19.64 | 1215 | 0/0/0 | 2100 | 0/0 |
| combined_burst | C2 | combined | dow | 408 | 162 | 39.71 | 246 | 0/0/0 | n/a | 0/0 |
| combined_burst | C3 | combined | credential_stuffing | 72 | 18 | 25.00 | 0 | 0/0/0 | n/a | 18/18 |
| combined_burst | C3 | combined | scraping | 1512 | 279 | 18.45 | 1233 | 0/0/0 | 2100 | 0/0 |
| combined_burst | C3 | combined | dow | 408 | 162 | 39.71 | 246 | 0/0/0 | n/a | 0/0 |

Resource quotas reduce distributed scrape deliveries57.33% (160/375 per run) and slow deliveries13.75% (207/240), with zero benign denials in those candidate slow runs. All5,000 public catalogue products still remain extractable under the slow/distributed schedules. This is volume mitigation; unique-data access protection and indistinguishable low-rate abuse remain open. Valid compromised synthetic credentials can still succeed.

## Retry-After behavior

| Config | Variant | Actual attempts | Denied | Bans | Recorded429 backoffs | Completed wait seconds |
|---|---|---:|---:|---:|---:|---:|
| C0 | current | 1890 | 0 | 0 | 0 | 0.00 |
| C2 | current | 1890 | 1380 | 15 | 90 | 87.20 |
| C2 | resource | 1890 | 0 | 0 | 0 | 0.00 |
| C3 | resource | 1890 | 0 | 0 | 0 | 0.00 |

Each burst profile has1,890 counterfactual fixed-schedule opportunities over three runs. Response-aware clients delay their next attempt after429 and keep denials visible; they do not silently replay a missed action as success. Recorded waits exclude possible deadline-ending waits without a following stat update, so they are lower bounds. Waiting reduced baseline denials from1,440 to1,380, but did not prevent its15 ban records. Candidate burst variants completed all1,890 opportunities with zero denials/bans.

## Evidence and remaining work

- [Primary independent report](evidence/followup/validation.json) and [per-run CSV](evidence/followup/results.csv).
- [Combined independent report](evidence/followup/compatibility/validation.json) and [per-run CSV](evidence/followup/compatibility/results.csv).
- [Frozen benign fitting proof](evidence/followup/frozen_policy.json), [component smoke](evidence/followup/smoke/validation.json), [combined smoke](evidence/followup/compat-smoke/validation.json).
- Final checks: [133 app/contract tests](evidence/followup/application.xml), [109 evaluation tests](evidence/followup/evaluation.xml), [12 real HTTP probes](evidence/followup/http.json). Monetary tests cover concurrency, refunds, anomaly rejection, uncertainty, reset/restart and loss of Redis authority.
- Opened cohorts are excluded from independent future tuning. Broader fairness/adaptive small jobs and unique extraction need new experiments. A’s real kernel sensor/enforcement, augmented data/model, joint IT-1–IT-6, final C0–C4 benchmark, slides and rehearsals remain pending.
