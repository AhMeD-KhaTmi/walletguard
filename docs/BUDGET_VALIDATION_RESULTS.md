# Independent agent-budget validation

**Application-side policy blocking/ban targets passed.** This is the independent check of the predeclared 40,000-token capacity / 2,400 tokens/s candidate. The frozen C3 model and scoring path are unchanged. Two C2 requests were interrupted at Locust shutdown (GreenletExit) and remain unknown, not successes or blocks. Even treating them as denials leaves each affected run below 1%. Complete client-outcome status is reported separately. Real kernel integration and joint IT-6 remain pending.

## What changed and how it was selected

The initial 20,000 / 100-per-second allowance predates repeated agent context. Fresh calibration used seeds 101/102/103 and separate normal/varied-agent C1 captures. The fixed rule selected a two-task burst and 125% of peak rolling per-account 60s demand, rounded up. Among 1,035 measured chats, the largest task cost 19,044 tokens and the largest account window cost 113,550. This gives 40,000 capacity and 2,400 tokens/s. The [frozen fitting record](evidence/budget_calibration/frozen_policy.json) records the accepted run hashes.

One calibration capture was excluded in full because client transport errors prevented complete request-ID joins. Its original evidence was preserved, and a same-seed new-ID capture replaced it before fitting. The test seeds were not used to select or adjust values.

The burst doubles and sustained allowance increases 24-fold. This supports the declared multi-step workload and permits more usage than the original policy. Request/login/chat request limits, output cap, five-strike escalation, ban expiry, allowlist handling and Redis schema v2 remain unchanged. Private bucket idle cleanup follows the existing formula (now 34,334ms).

## Evidence and boundaries

- Candidate measured source: `9cd6f4a` on `codex/b-budget-calibration`, in a clean isolated checkout.
- 36 valid runs: 12 matched C0/C2/C3 triplets, three repetitions, independent seeds 201/202/203. Configuration order is reversed in repetition 2.
- Normal and varied benign traffic plus mixed traffic: 90s each; paced under-cap DoW: 45s, three attacker clients sharing the reserved attacker account, 2.1s per-user pauses.
- Real namespace IPv4 identities, disposable Redis, identical effective policy/model/mock settings within each triplet. No client is allowlisted.
- [Per-run results](evidence/budget_calibration/results.csv), [validated groups and independent server usage](evidence/budget_calibration/validation.json), and [predeclared protocol](BUDGET_CALIBRATION.md).
- Raw validation files: local `eval/runs/budget-validation-v1/`; calibration: local `ml/data/budget-calibration-v1/`. These generated files are outside Git history.
- Exact independent API/mock step, token and cost totals are checked on every run. Server totals can include setup calls; client metrics exclude setup. Mixed server totals include benign and attack usage.

## Legitimate-user safety

Counts below pool three repetitions. Run-level rates and ranges remain in the CSV/JSON. An anomaly flag is separate from a policy denial. Errors/timeouts/unknowns remain separate from blocks.

| Scenario | Config | Benign attempts | Denials | FPR % | Benign bans | Errors / timeouts / unknowns |
|---|---|---:|---:|---:|---:|---:|
| normal-benign | C0 | 1,115 | 0 | 0.000 | 0 | 0 / 0 / 0 |
| normal-benign | C2 | 1,117 | 0 | 0.000 | 0 | 0 / 0 / 1 |
| normal-benign | C3 | 1,119 | 0 | 0.000 | 0 | 0 / 0 / 0 |
| varied-benign | C0 | 1,145 | 0 | 0.000 | 0 | 0 / 0 / 0 |
| varied-benign | C2 | 1,129 | 0 | 0.000 | 0 | 0 / 0 / 1 |
| varied-benign | C3 | 1,128 | 0 | 0.000 | 0 | 0 / 0 / 0 |
| normal-mixed | C0 | 558 | 0 | 0.000 | 0 | 0 / 0 / 0 |
| normal-mixed | C2 | 558 | 0 | 0.000 | 0 | 0 / 0 / 0 |
| normal-mixed | C3 | 502 | 0 | 0.000 | 0 | 0 / 0 / 0 |

Historical original-policy results were 40/1,702 benign denials in C2 (2.350%) and 37/1,629 in C3 (2.271%), with one benign budget ban each. That earlier campaign used different seeds and did not include the varied-step scenario, so it is context rather than a matched old/new policy ablation. The regression also directly reproduces the original capacity failure: two large concurrent normal tasks returned [200,429]; the calibrated capacity accepts both and still throttles the third.

## Benign latency

Milliseconds; each cell is the median of three per-run percentiles. Baseline differences are computed within matched repetitions first. WAF timing excludes downstream execution. Source timing artifacts and ranges remain in the evidence.

| Scenario | Config | Client p50 | Client p95 | Δp50 vs C0 | Δp95 vs C0 | WAF p50 | WAF p95 |
|---|---|---:|---:|---:|---:|---:|---:|
| normal-benign | C0 | 6.387 | 97.210 | 0.000 | 0.000 | off | off |
| normal-benign | C2 | 11.409 | 109.449 | 4.388 | 12.239 | 3.346 | 11.871 |
| normal-benign | C3 | 29.491 | 127.644 | 23.195 | 23.821 | 20.709 | 51.725 |
| varied-benign | C0 | 7.704 | 139.293 | 0.000 | 0.000 | off | off |
| varied-benign | C2 | 9.369 | 129.160 | 1.665 | -14.238 | 3.792 | 12.037 |
| varied-benign | C3 | 29.163 | 153.788 | 22.218 | 42.499 | 19.989 | 53.606 |
| normal-mixed | C0 | 4.082 | 98.395 | 0.000 | 0.000 | off | off |
| normal-mixed | C2 | 6.496 | 94.723 | 2.186 | -9.202 | 2.692 | 7.411 |
| normal-mixed | C3 | 191.922 | 722.307 | 187.032 | 618.382 | 144.314 | 234.589 |

## Paced token exhaustion and mixed attacks

Paced DoW is the token-budget-specific probe. ASR medians below use measured malicious client attempts; unknowns are not treated as successful blocks. Output tokens/cost use independent server counters. This paced profile must not be compared directly to the earlier unpaced campaign.

| Config | Paced ASR % | Server output tokens, median | Simulated cost, median | Explicit token throttles, total | Unknowns, median |
|---|---:|---:|---:|---:|---:|
| C0 | 100.000 | 162,000 | $2.960415 | 0 | 0 |
| C2 | 41.270 | 70,200 | $1.278225 | 12 | 0 |
| C3 | 40.320 | 67,500 | $1.234872 | 12 | 0 |

Mixed per-attack outcomes pool all three runs. Workloads, account/source roles and objective definitions come from A’s unchanged scripts.

| Attack | Config | Malicious attempts | Successes | ASR % | Unknowns |
|---|---|---:|---:|---:|---:|
| credential_stuffing | C0 | 26,801 | 2,626 | 9.798 | 5 |
| credential_stuffing | C2 | 26,631 | 6 | 0.023 | 5 |
| credential_stuffing | C3 | 4,791 | 6 | 0.125 | 2 |
| scraping | C0 | 52,702 | 52,697 | 99.991 | 5 |
| scraping | C2 | 53,853 | 279 | 0.518 | 3 |
| scraping | C3 | 5,332 | 391 | 7.333 | 0 |
| dow | C0 | 4,144 | 4,144 | 100.000 | 0 |
| dow | C2 | 26,031 | 21 | 0.081 | 2 |
| dow | C3 | 4,298 | 23 | 0.535 | 5 |

## Model and remaining work

The model binary remains `bb0116a167318df1749a0edf5cf5b95362ccde59f6b8580d732ed82d05722ca1`. Its original held-out detector precision/recall/FPR remain 66.67% / 0.0397% / 1.047%. The current budget work does not improve detector recall or remove C3 scoring overhead.

Live C3 benign anomaly flags (among measured requests with a joined score) are diagnostic; they do not mean the request was blocked:

| Scenario | Scored benign requests | Model flags | Flag rate % |
|---|---:|---:|---:|
| normal-benign | 1,119 | 0 | 0.000 |
| varied-benign | 1,128 | 0 | 0.000 |
| normal-mixed | 502 | 1 | 0.199 |

Full candidate regression checks passed 82 application/contract tests, 109 evaluation tests and 12 HTTP checks; six collection smoke runs passed. [Candidate application XML](evidence/budget_calibration/candidate_application.xml), [eval XML](evidence/budget_calibration/candidate_evaluation.xml), [HTTP checks](evidence/budget_calibration/candidate_http.json). The saved burst-before XML intentionally records the reproduced old-policy failure.

Next B work: investigate model recall/benign coverage and scoring overhead using training/calibration data, then freeze a candidate and evaluate new held-out groups. An offline batching probe is only an optimization lead, not a measured live improvement. A continues the real sensor/enforcement handoff. Joint acceptance and the final C0–C4 campaign require that integration.

The present allowance is specific to the declared synthetic workload. Shared accounts, different agent settings, slow or distributed abuse and production pricing need their own policies/evidence. No universal safety or production-readiness claim is made.
