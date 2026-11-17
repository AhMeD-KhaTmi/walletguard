# WalletGuard team checklist

## Done

- [x] **A:** Deliver attack and benign workloads, labeled C1 data, and the C0/C2 benchmark package.
- [x] **B:** Build the API, mock LLM, C2 defenses, and dashboard. Train and test the base C3 model locally.
- [x] **B:** Prepare and rehearse the C2/C3 application timing and benign metrics checks.

## Next — C2/C3 benchmark

- [x] **B:** Apply the professor's agent-loop, exact-token, latency and environment requirements. Refresh C1 data and the version-3 model. [Current update](PROFESSOR_UPDATE.md)
- [x] **B:** Publish the current agent app, frozen version-3 model, updated plans, journal and reports on `codex/professor-agent-update`. [Coordination PR #2](https://github.com/AhMeD-KhaTmi/walletguard/pull/2). A can branch from it now.
- [x] **B, authorized on A's track:** Enable C3 in the harness, fix failure and timeout handling, and save the app timing snapshot for each run. Tested on local branch `codex/c3-benchmark`.
- [x] **Both — integrate here:** Combined A's workloads and B's frozen model on the Linux VM. All 54 matched C2/C3 runs passed, with three repetitions per workload and configuration. [Results](C23_BENCHMARK_RESULTS.md)
- [x] **B, using A's metrics:** Report attack success, token usage, cost, benign false positives, latency, WAF overhead, and scoring time for C2/C3. Share these results and source changes with A.
- [x] **B:** Complete the current agent benchmark: 81 valid matched C0/C2/C3 runs, three repetitions per workload/configuration, with p50/p95 baseline differences. [Results](PROFESSOR_BENCHMARK_RESULTS.md). The previous 54 runs remain historical single-call evidence.
- [ ] **B:** Calibrate whole-agent budgets on new data and retest independently: the current campaign exceeds the 1% benign FPR target and includes benign budget bans. Investigate very low detector recall and C3 scoring overhead before final acceptance.

## In parallel — C4 kernel work

- [ ] **A:** Deliver the app-scoped connect/execve sensor and Redis signals, plus expiring XDP enforcement or a documented generic/skb, tc/nftables/WAF fallback and its measured telemetry.
- [ ] **Both — integrate here:** Once A's kernel code runs on the VM and publishes real [Redis schema v2](../contract/redis_schema.md) signals, connect it to B's app in observe mode to collect sensor data.
- [ ] **B:** Train and evaluate the augmented model on separate runs with real sensor data. Enable C4 once the model and kernel are ready.
- [ ] **Both:** Run IT‑1–IT‑6 together, then complete the matched C0–C4 benchmark and publish the combined results. [Integration tests](MASTER_PLAN.md#8-integration-acceptance-tests)

## Finish

- [ ] **A:** Slides 2, 3, 4, 7, 9, 12, 13, 15. **B:** Slides 1, 5, 6, 10, 11, 14, 16, 18.
- [ ] **Both:** Slides 8 and 17, two demo rehearsals, and a backup recording.
