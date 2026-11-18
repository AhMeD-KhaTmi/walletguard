# Directional volume detector results

The candidate and original forest were evaluated once on the same fresh held-out
feature-version-3 rows. Four fresh benign fitting groups and two calibration
groups were separate from six benign and nine malicious test groups. All
request-ID join coverage, source, usage and split checks are recorded in the
linked evidence. No earlier test rows entered fitting or candidate selection.

## Detector acceptance

| Model | TP | FP | FN | TN | Precision % | Recall % | Benign flag rate % |
|---|---:|---:|---:|---:|---:|---:|---:|
| original | 15 | 10 | 21759 | 1584 | 60.000 | 0.069 | 0.627 |
| candidate | 21558 | 92 | 216 | 1502 | 99.575 | 99.008 | 5.772 |

Fixed offline acceptance (recall≥20%, precision≥90%, benign flags≤10%,
positive recall in every attack run): **passed**.

| Held-out run | Malicious rows | Detected | Recall % |
|---|---:|---:|---:|
| volume-test-credential_stuffing-721 | 2669 | 2633 | 98.651 |
| volume-test-credential_stuffing-731 | 2641 | 2605 | 98.637 |
| volume-test-credential_stuffing-741 | 2706 | 2670 | 98.670 |
| volume-test-dow-723 | 493 | 493 | 100.000 |
| volume-test-dow-733 | 496 | 496 | 100.000 |
| volume-test-dow-743 | 495 | 495 | 100.000 |
| volume-test-scraping-722 | 4098 | 4062 | 99.122 |
| volume-test-scraping-732 | 4036 | 4000 | 99.108 |
| volume-test-scraping-742 | 4140 | 4104 | 99.130 |

## Live safety and timing

The first live grid failed strict completeness: one varied C3 product request
ended in GreenletExit after0.412ms. That failed gate and all outcomes are
preserved in [the initial grid](evidence/volume_experiment/acceptance.json).
No model/threshold was retuned. A tested, opt-in supervisor driver changed worker
shutdown, then a separate confirmation used fresh seeds761–763.

Eighteen confirmation C0/C3 runs cover normal benign, varied benign and mixed traffic,
three repetitions each, independent seeds 761–763. Windows last 30s with 10
benign or 14 mixed users. Values are medians of per-run percentiles; raw ranges
and all unknowns remain in the JSON/CSV. Detector flags do not mean denials.

| Scenario | Config | Benign attempts | Denials | Unknown/errors/timeouts | Bans | Client p50 ms | Client p95 ms | Δp95 vs C0 ms | WAF p95 ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| normal-benign | C0 | 390 | 0 | 0 | 0 | 3.03 | 94.12 | 0.00 | off |
| normal-benign | C3 | 390 | 0 | 0 | 0 | 16.95 | 107.49 | 13.37 | 33.26 |
| varied-benign | C0 | 388 | 0 | 0 | 0 | 3.25 | 129.04 | 0.00 | off |
| varied-benign | C3 | 381 | 0 | 0 | 0 | 17.33 | 116.98 | 7.00 | 31.19 |
| normal-mixed | C0 | 199 | 0 | 0 | 0 | 3.26 | 92.07 | 0.00 | off |
| normal-mixed | C3 | 195 | 0 | 0 | 0 | 58.53 | 214.45 | 122.38 | 68.14 |

Fixed live safety gate (each run≤1% benign denials, zero benign bans and
zero benign unknown/errors/timeouts): **passed**.

Eligible for activation after both gates: **True**.
Candidate SHA-256: `1eb84211004b6abe42cd2b8ec03e4b06b8504884ad0a8b9c1ca81ce2f55829e3`.
C1/model source: `816145e4da027d113e9794bb575b528ccaa1e598`; confirmation source: `b1527870a7406bab1d75699e4ba1c3c0aee97b33`.

## Mixed-workload application outcomes

These pooled ASRs cover the three matched mixed-workload repetitions. They measure
all C3 controls together, not the forest alone. Unknown outcomes remain separate.

| Attack | Config | Malicious attempts | Successes | ASR % | Unknowns |
|---|---|---:|---:|---:|---:|
| credential_stuffing | C0 | 9290 | 861 | 9.268 | 0 |
| dow | C0 | 1457 | 1457 | 100.000 | 0 |
| scraping | C0 | 18708 | 18708 | 100.000 | 0 |
| credential_stuffing | C3 | 4037 | 2 | 0.050 | 0 |
| dow | C3 | 3772 | 21 | 0.557 | 0 |
| scraping | C3 | 5293 | 297 | 5.611 | 0 |

Residual abuse remains; detector recall is not the fraction of requests blocked.

## Interpretation and limits

The candidate is still a benign-only, 100-tree IsolationForest with seed42. It
uses one log-transformed intensity derived from request/task volume and a
benign-fitted directional gate. It does not introduce a hard rate-blocking rule.
The existing five-strike plus budget-corroboration ban rule, validated budgets,
bounded batching, allowlists and outage behavior are preserved. Feature version3
and Redis schema2 are unchanged. The previous model/artifacts stay immutable.

Fresh seeds exercise the same synthetic workload families, not unseen real-world
attack families. Short windows, fixed benign concurrency and mock pricing limit
generalization. Slower/distributed abuse can overlap legitimate volume. Live C0/C3
differences include all WAF controls; they cannot isolate the forest's marginal
blocking benefit or establish CPU savings. Real sensor/C4 and the final matched
C0–C4 benchmark remain pending. Report detector quality separately from combined
application enforcement and do not claim production readiness.

[Protocol](DETECTOR_VOLUME_EXPERIMENT.md) ·
[Confusion matrices](evidence/volume_experiment/evaluation.json) ·
[Acceptance and timing ranges](evidence/volume_confirmation/acceptance.json) ·
[Request-ID coverage](evidence/volume_experiment/join_coverage.json).

Local raw evidence: `ml/data/volume-v1/` and, if offline qualified,
`eval/runs/volume-live-v1/` (failed first grid),
`eval/runs/volume-driver-smoke-v1/` and `eval/runs/volume-confirmation-v1/`. These generated captures remain outside Git history.

## Activation and final regression

After both acceptance gates and the default startup probe passed, the qualified
artifact was installed at `ml/artifacts/model_base_volume_v1.joblib` and selected
as Config's default for enabled C3. Explicit historical model overrides remain.
The only runtime change after measured confirmation is this default path; the
confirmation had already loaded those exact frozen weights explicitly.

Final checks: 98 app/contract tests, 109 evaluation tests, 12 real-HTTP C0/C1/C2
checks, and a real-HTTP default C3 startup/eight-step chat/dashboard probe passed.
Re-training on the exact respective CSVs reproduces thresholds and every held-out
score for both the candidate (23,368 rows) and original (10,276 rows). The original
binary is byte-identical. Evidence is under `docs/evidence/volume_confirmation/`.
No held-out outcome was used to retune the candidate. Further model selection
requires new independent test groups.
