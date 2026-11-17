# C2/C3 Linux VM benchmark

Historical single-call runtime and feature-version-2 evidence. The professor's
agent-loop update changes token accounting and traffic. Use the current
[professor update](PROFESSOR_UPDATE.md) for version-3 validation and benchmarks.

Measured 2026-11-17 at revision `193bddcc9f9d97e76f663c9bf34016ceed7a095f`
on branch `codex/c3-benchmark`. The frozen model and threshold from the C1
evaluation were used throughout. The model SHA-256 is
`591afffd16bac2bb45a13d5bf83fda7f2e10f09315df90f2bb15dc754fc4ddad`.

## Run coverage

- All **54 runs** were accepted, with 27 per configuration and three repetitions
  of each of nine workloads/profiles. No run required a retry. There were
  291,096 measured client attempts across the grid.
- Used the project's bridge and 15 real namespace client addresses on this
  Linux VM. Private user, mount and network namespaces contained the lab.
  The app used one Uvicorn worker, the synthetic HTTP LLM and disposable Redis.
- Each pair used the same revision, policy, client identities, rates, duration,
  seed and stable worker seeds. Seeds were 42, 43 and 44 by repetition. Config
  order reversed for repetition two. Existing workload windows were 45 seconds,
  with 20-second probes and 90-second benign/mixed runs.
- Captured finalized app timings after traffic drained. All HTTP responses
  joined uniquely to timings. Transport failures stayed in the client records,
  with minimum HTTP timing coverage **99.92%**. Scoring fields are null for C2.
- VM had four logical CPUs, kernel 6.8.0-149-generic, Python 3.11.18, Locust
  2.47.0 and scikit-learn 1.9.1. CPU/RSS and package versions are in the manifests.

## Benign safety and latency

Values below are medians of the three run metrics. Per-run values and ranges
are in the linked summary.

| Metric | C2 | C3 |
|---|---|---|
| Benign-only p95 client latency | 33.60 ms | 51.65 ms |
| Mixed-traffic benign p95 client latency | 36.96 ms | 396.01 ms |
| Benign-only finalized WAF overhead, mean per run | 3.29 ms | 18.45 ms |
| Mixed-traffic finalized WAF overhead, mean per run | 2.71 ms | 132.30 ms |
| Mixed-traffic app CPU, mean per run | 45.67% of one core | 94.97% of one core |

Across benign-only and mixed runs, C2 denied **0 of 1,705** benign requests and
C3 denied **0 of 1,653**. Neither config recorded benign transport errors,
timeouts or unknown outcomes. These are enforcement outcomes. The independent
C1 detector evaluation recorded three anomalous benign samples out of 387.

## Attack outcomes

Medians across three repetitions. ASR uses successful measured malicious
attempts divided by measured malicious attempts.

| Workload | C2 ASR | C3 ASR | C2 successful attempts | C3 successful attempts |
|---|---|---|---|---|
| Credential stuffing | 0.00% | 0.00% | 0 | 0 |
| Scraping | 0.96% | 3.91% | 92 | 100 |
| Under-cap DoW | 0.22% | 0.43% | 10 | 10 |
| Over-cap DoW | 0.00% | 0.00% | 0 | 0 |
| Combined | 0.56% | 5.04% | 103 | 136 |
| Mixed | 0.28% | 2.66% | 103 | 137 |

The under-cap workload generated 9,000 output tokens per run in both configs.
Per-run stuffing ASR was occasionally nonzero, which is retained in the CSV.

C3 added latency and did not reduce successful abuse in this grid. The
closed-loop clients wait for responses, so slower scoring also reduces their
number of attempts per fixed window. For example, mixed traffic's median
malicious attempt count was 36,684 in C2 and 5,150 in C3. Read ASR together with
the success counts, token usage, and attempt counts. These runs do not establish
the causal effect of the model at a fixed offered request rate.

## Evidence and reproduction

- [Per-run results](evidence/c23/results.csv)
- [Median and range summary](evidence/c23/summary.csv)
- [Validated benchmark metadata](evidence/c23_benchmark.json)
- Raw logs, manifests and snapshots are saved locally under
  `eval/runs/c23-193bddc/runs/`. Raw artifacts are excluded from Git.
- Raw archive is `eval/handoff/c23-193bddc.tar.gz` (about 39 MiB), SHA-256
  `f32b530796e8ecc19e286a60d0def303680fdcf0939c00614c9900f0563f73b7`.

With the recorded dependencies installed, a trusted frozen model in
`ml/model_base.joblib`, and the generated synthetic credentials present:

```bash
.venv/bin/python locust/data/make_creds.py
bash scripts/run_c23_isolated.sh /tmp/walletguard-c23-new-run
```

The wrapper requires Linux with rootless user/network/mount namespaces enabled,
`iproute2`, `redis-server`, `redis-cli` and Locust on PATH. It owns and cleans up
its Redis process. Its private network devices disappear when the namespace exits.

The harness fixes and all 54 runs are local work. Share the branch and evidence
with A before the final C0–C4 comparison. C4 and IT‑1–IT‑6 still require the
real sensor and XDP components.
