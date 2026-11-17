# Current agent-loop benchmark — C0/C2/C3

Measured 2026-11-17 on Ubuntu 22.04.5, kernel 6.8.0-149-generic, BTF present.

**81 runs are valid; security acceptance is incomplete.** The whole-agent budget policy blocks some legitimate traffic, and this base anomaly detector has very low recall. This report preserves the frozen results before any further calibration. C4 and joint IT-1–IT-6 remain pending.

## Evidence and reproduction

- Clean measured source: `aa51185caa87307672e4042683a9e6ccfbbfe59d`, local branch `codex/professor-agent-update`.
- Runtime `context-loop-v1`, default three steps, feature version 3, exact synthetic tokenizer `synthetic-whitespace-v1`.
- Frozen model SHA-256: `bb0116a167318df1749a0edf5cf5b95362ccde59f6b8580d732ed82d05722ca1`.
- [Per-run CSV](evidence/professor_benchmark/results.csv), [median/range CSV](evidence/professor_benchmark/summary.csv), and [validated metadata with independent usage counters](evidence/professor_benchmark/validated.json).
- Raw logs, manifests, labels, usage, bans, decisions and finalized timing snapshots: local `eval/runs/professor-aa51185/`.
- Local handoff archive: `eval/handoff/professor-agent3-aa51185.tar.gz` (80,172,140 bytes), containing measured source, C1 data, frozen model and 81 raw runs. [Archive checksum and inventory](evidence/professor_handoff.json). It has not been uploaded or pushed.
- Nine workloads/profiles × C0/C2/C3 × three repetitions, seeds 42/43/44. Order is reversed in repetition 2. No invalid attempts or retries.
- Private network namespace bridge with 15 distinct source IPs and disposable Redis. Each matched triplet shares source revision, policy, seed, workload settings, client timeout and mock latency. Actual attempt counts differ under the same concurrency/pacing when response times differ.
- Original durations retained: attack runs 45 seconds, probes 20 seconds, benign and mixed runs 90 seconds. Setup traffic is excluded from client metrics.
- Exact API/mock step, input-token, output-token and cost agreement in all 81 runs. Token/cost totals below use server counters, which can include setup calls; client ASR counts only measured attempts.

Reproduce from the measured source with its frozen model and dependencies:

```bash
bash scripts/run_c23_isolated.sh eval/runs/new-professor-campaign --baseline
```

Validate the preserved campaign from this checkout:

```bash
.venv/bin/python scripts/validate_professor_benchmark.py
```

The validator deliberately requires this frozen campaign’s revision, model hash and 81-run shape. A new calibration campaign needs separate evidence and validation expectations.

## Attack outcomes

Values are medians of three run-level client ASRs, in percent. ASR = successful malicious requests / all malicious attempts, including unknown outcomes in the denominator. Failed transport/timeout outcomes remain unknown; they are not evidence of a successful block. Min/max and per-attack rows are in the CSVs.

| Workload | C0 ASR % | C2 ASR % | C3 ASR % |
|---|---:|---:|---:|
| Credential stuffing | 9.62 | 0.00 | 0.00 |
| Scraping | 99.99 | 0.97 | 4.00 |
| DoW under-cap | 100.00 | 0.07 | 0.13 |
| DoW over-cap † | 0.00 | 0.00 | 0.00 |
| Combined attacks | 71.72 | 0.53 | 4.87 |
| Attacks mixed with benign traffic | 71.72 | 0.26 | 2.53 |

† **C0 over-cap ASR 0% does not mean the attack was prevented.** All 45 measured requests per repetition exceeded the fixed three-second client timeout. The three-step server tasks nevertheless finished: 135 mock calls, 4,330,350 input tokens, 4,320,000 output tokens and simulated cost $77.79105 per run. Each synthetic task takes roughly 4.8 seconds with the selected output/latency settings. C2/C3 rejected these tasks before generation, with zero unknown outcomes and zero server tokens. Keep this distinction in presentations; use server consumption to demonstrate this attack’s impact.

| DoW profile | C0 server output tokens | C2 | C3 |
|---|---:|---:|---:|
| dow-undercap | 2,016,900 | 8,100 | 8,100 |
| dow-overcap | 4,320,000 | 0 | 0 |

C3 does not improve every result over C2. In this campaign its scoring overhead reduces throughput and its residual scraping/mixed ASR is higher. These runs establish a comparison, not a claim that adding the current model always improves protection.

## Benign safety and latency

Across all benign-only and mixed runs, C0 denied 0/1,701 legitimate requests, C2 denied **40/1,702 (2.350%)**, and C3 denied **37/1,629 (2.271%)**. There were zero benign errors, timeouts or unknown outcomes. A budget ban affected benign IP `10.20.0.15` in `c2-benign-r3` and `c3-benign-r3` (one ban in each). **The initial ≤1% enforcement FPR and zero-benign-ban targets are unmet.**

The following benign-only latency values are medians of per-run percentiles, in milliseconds. Differences are calculated within each matched repetition before taking their median, so a delta need not equal a subtraction of table medians. Negative differences are retained in raw summaries. WAF overhead excludes downstream app/model latency; it is measured separately from client end-to-end latency.

| Configuration | Client p50 | Client p95 | Δp50 vs C0 | Δp95 vs C0 | WAF p50 | WAF p95 |
|---|---:|---:|---:|---:|---:|---:|
| C0 | 3.440 | 93.326 | 0.000 | 0.000 | off | off |
| C2 | 5.373 | 94.464 | 2.092 | 1.345 | 2.537 | 6.732 |
| C3 | 20.649 | 108.037 | 17.209 | 15.792 | 16.405 | 30.517 |

Under mixed load, benign client p95 medians were 96.847 ms (C0), 97.606 ms (C2), and 645.329 ms (C3). Matched p95 differences were +0.759 ms (C2) and +548.482 ms (C3). C3 WAF p95 was 217.564 ms; benchmark timing coverage exceeds 98% on each enforced run. This scoring cost is an open performance issue.

## Model evaluation and scope

Fresh C1 collection produced 10,650 rows: 187 fit, 187 calibration and 10,276 held-out rows (191 benign and 10,085 attack). The base model detected 4 attacks and falsely flagged 2 benign rows: precision **66.67%**, recall **0.0397%**, detector FPR **1.047%**. Recall was 4/737 for DoW and 0/3,845 stuffing and 0/5,503 scraping. These are detector-only scores, separate from combined WAF enforcement outcomes.

Historical version-2 detector metrics were precision 99.91%, recall 22.81%, FPR 0.78%. The new runtime, features, tokenizer and dataset all differ, so those numbers are historical context and cannot establish a matched regression magnitude. Both datasets/manifests are preserved. No threshold was retuned using the current held-out set or benchmark.

## Remaining work and integration

1. **B:** collect new calibration traffic, tune whole-agent budget/refill/strike policies for legitimate multi-step tasks, then evaluate new independent held-out runs. Freeze this campaign before tuning.
2. **B:** investigate benign coverage, detector features/threshold selection and scoring cost using training/calibration evidence; compare any candidate to the frozen base on a new held-out set. Do not present current C3 as a reliable independent detector.
3. **A:** implement app-scoped connect/execve sensing, real Redis signals and expiry/allowlist-safe enforcement. Record native XDP, generic/skb or approved fallback mode and actual telemetry.
4. **Both:** collect real sensor data, train the augmented model, pass IT-1–IT-6, and run a fresh matched C0–C4 campaign. Complete slides/rehearsals afterward.

The professor-required application behavior and measurement pipeline are implemented and tested at the current stage. Kernel enforcement, final safety acceptance and final C0–C4 evidence are not complete.
