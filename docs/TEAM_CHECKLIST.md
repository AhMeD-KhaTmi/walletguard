# WalletGuard team checklist

## Done

- [x] **A:** Deliver attack and benign workloads, labeled C1 data, and the C0/C2 benchmark package.
- [x] **B:** Build the API, mock LLM, C2 defenses, and dashboard. Train and test the base C3 model locally.
- [x] **B:** Prepare and rehearse the C2/C3 application timing and benign metrics checks.

## Next — C2/C3 benchmark

- [x] **B:** Apply the professor's agent-loop, exact-token, latency and environment requirements. Refresh C1 data and the version-3 model. [Current update](PROFESSOR_UPDATE.md)
- [x] **B:** Publish the current agent app, frozen version-3 model, updated plans, journal and reports on `main` through [merged PR #2](https://github.com/AhMeD-KhaTmi/walletguard/pull/2). A can branch from `origin/main` now.
- [x] **B, authorized on A's track:** Enable C3 in the harness, fix failure and timeout handling, and save the app timing snapshot for each run. Tested on local branch `codex/c3-benchmark`.
- [x] **Both — integrate here:** Combined A's workloads and B's frozen model on the Linux VM. All 54 matched C2/C3 runs passed, with three repetitions per workload and configuration. [Results](C23_BENCHMARK_RESULTS.md)
- [x] **B, using A's metrics:** Report attack success, token usage, cost, benign false positives, latency, WAF overhead, and scoring time for C2/C3. Share these results and source changes with A.
- [x] **B:** Complete the current agent benchmark: 81 valid matched C0/C2/C3 runs, three repetitions per workload/configuration, with p50/p95 baseline differences. [Results](PROFESSOR_BENCHMARK_RESULTS.md). The previous 54 runs remain historical single-call evidence.
- [x] **B:** Calibrate whole-agent budgets on new data and complete 36 independent runs: zero observed benign denials/bans, with two shutdown-interrupted requests retained as unknowns. [Results](BUDGET_VALIDATION_RESULTS.md).
- [x] **B:** Collect nine fresh detector test groups and assess new profiles. Reject the final candidate (6.77% recall / 88.20% precision); preserve the original forest and all results. [Research record](MODEL_CALIBRATION_REVISIONS.md).
- [x] **B:** Validate scoring latency with twelve matched direct/batched runs using the original model. Mixed benign p95 median 712→291ms; one direct shutdown outcome remains unknown. [Results](SCORING_PERFORMANCE_RESULTS.md).
- [x] **B:** Diagnose low recall; freeze a new benign-only model, collect 21 fresh C1 groups, pass offline gates, preserve the first live failure, fix shutdown in B's opt-in driver, and pass 18 fresh live confirmations. Activate the qualified volume model after final startup checks. [Results](DETECTOR_VOLUME_RESULTS.md).

- [x] **B:** Publish budget calibration, validated batching, model rejection evidence and updated plans on `main` ([01d21d9](https://github.com/AhMeD-KhaTmi/walletguard/commit/01d21d934c7e6077afa713b1d4c707bc9655d68d)).

- [x] **B:** Publish the qualified volume model, lifecycle fix, evidence and master v1.5 on `main` ([fa95a24](https://github.com/AhMeD-KhaTmi/walletguard/commit/fa95a240e7e1d6159b81a7e68f054845df639249)).

## Application robustness follow-up

- [x] **B:** Complete five harder profiles in 45 matched C0/C2/C3 captures, three fresh repetitions, plus 15 separate pipeline smokes. Preserve unfavorable results and unchanged controls. [Results](ROBUSTNESS_RESULTS.md).
- [ ] **B:** Define prospective remedies for shared-account/burst collateral bans and aggregate wallet/harvesting limits, then calibrate on separate data and validate fresh groups. Keep earlier/current test groups out of tuning.
- [ ] **B:** Add response-aware benign clients that honor Retry-After alongside these fixed schedules; compare both explicitly.

## In parallel — C4 kernel work

- [ ] **A:** Deliver the app-scoped connect/execve sensor and Redis signals, plus expiring XDP enforcement or a documented generic/skb, tc/nftables/WAF fallback and its measured telemetry.
- [ ] **Both — integrate here:** Once A's kernel code runs on the VM and publishes real [Redis schema v2](../contract/redis_schema.md) signals, connect it to B's app in observe mode to collect sensor data.
- [ ] **B:** Train and evaluate the augmented model on separate runs with real sensor data. Enable C4 once the model and kernel are ready.
- [ ] **Both:** Run IT‑1–IT‑6 together, then complete the matched C0–C4 benchmark and publish the combined results. [Integration tests](MASTER_PLAN.md#8-integration-acceptance-tests)

## Finish

- [ ] **A:** Slides 2, 3, 4, 7, 9, 12, 13, 15. **B:** Slides 1, 5, 6, 10, 11, 14, 16, 18.
- [ ] **Both:** Slides 8 and 17, two demo rehearsals, and a backup recording.
