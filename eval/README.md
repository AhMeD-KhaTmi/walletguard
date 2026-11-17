# Member A — traffic, evaluation and data handoff

What this is: the client side of Project 20. Three runnable attacks, a benign
generator, real multi-IP identities, per-attempt truth records, run manifests, result
aggregation and the label file B's ML tooling needs.

What this is **not**: the kernel layer (`ebpf/`, second PR), the WAF, or B's latency/ML
measurements. Nothing here claims C3 or C4 results.

## 1. Where to find each deliverable

| Need | Path |
|---|---|
| Attack workloads | `locust/attack_credential_stuffing.py`, `locust/attack_scraping.py`, `locust/attack_dow.py` |
| Integration probes (decoy ban, connection churn) | `locust/attack_honeypot.py`, `locust/attack_churn.py` |
| Benign generator | `locust/benign.py` |
| Seeded synthetic credentials | `locust/data/make_creds.py` (output is git-ignored) |
| Identity plan (IP ↔ role ↔ accounts) | `eval/identities.json` |
| Namespace setup/cleanup | `scripts/make_netns.sh`, `scripts/teardown_netns.sh`, `eval/netns.py` |
| Per-attempt records and objective predicates | `eval/clientlog.py` |
| Run manifests | `eval/manifest.py` |
| Config orchestration (C0/C1/C2) | `eval/harness.py` |
| Result aggregation | `eval/compute_metrics.py` → `eval/results.csv` |
| Label file for ML | `eval/labels.py` → `eval/runs/labels.json` |
| Column definitions | `eval/schema.md` |

## 2. One-time setup on the lab VM

```bash
cd ~/walletguard
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -r locust/requirements.txt
python3 locust/data/make_creds.py --seed 42            # writes locust/data/creds_seed42.json

sudo bash scripts/make_netns.sh                        # bridge + 15 namespaces
sudo python3 eval/netns.py check                       # every declared address present
```

`scripts/make_netns.sh` is idempotent: it removes and recreates the namespaces and the
`p20br0` bridge. `scripts/teardown_netns.sh` removes exactly what the identity plan
declares and nothing else.

## 3. Identities (one source of truth)

| Role | Namespaces | Addresses |
|---|---|---|
| Management | host | `127.0.0.1`, `10.20.0.1` — the only allowlistable addresses |
| Benign | ns1–ns5 | `10.20.0.11–.15` (accounts `user1..user49`) |
| Credential stuffing | ns6–ns8 | `10.20.0.16–.18` |
| Scraping | ns9–ns11 | `10.20.0.19–.21` |
| Denial-of-Wallet | ns12–ns14 | `10.20.0.22–.24` (account `user50`) |
| Probes | ns15 | `10.20.0.25` (honeypot and churn, separate runs) |

Measured traffic never runs from a management address and is never allowlisted; the
harness refuses to start if an attacker or benign address is found in `p20:allowlist`.

## 4. Running one measured run

The harness starts the mock and API itself with explicit flags, verifies the effective
configuration through `/health`, resets runtime state, drives the workload from the
declared namespaces, archives evidence, then stops the services.

```bash
# C0 baseline, three attack IPs per attack
sudo .venv/bin/python eval/harness.py run --config C0 --workload credential_stuffing --duration 45s
sudo .venv/bin/python eval/harness.py run --config C0 --workload scraping           --duration 45s
sudo .venv/bin/python eval/harness.py run --config C0 --workload dow --profile undercap --duration 45s
sudo .venv/bin/python eval/harness.py run --config C0 --workload dow --profile overcap  --duration 45s

# Benign, probes, and the two combined workloads required by the plan
sudo .venv/bin/python eval/harness.py run --config C0 --workload benign    --duration 90s --users 10
sudo .venv/bin/python eval/harness.py run --config C0 --workload honeypot  --duration 20s
sudo .venv/bin/python eval/harness.py run --config C0 --workload churn     --duration 20s
sudo .venv/bin/python eval/harness.py run --config C0 --workload combined  --duration 45s
sudo .venv/bin/python eval/harness.py run --config C0 --workload mixed     --duration 90s

# Same set against C2 (buckets + honeypot), and C1 for ML collection
sudo .venv/bin/python eval/harness.py run --config C2 --workload scraping --duration 45s
sudo .venv/bin/python eval/harness.py run --config C1 --workload benign   --duration 90s --users 10
```

`dow` runs use the plan's setup → reset → measure sequence automatically: the attackers
log in at a normal rate (`phase="setup"`), the harness then clears buckets, bans, strikes
and streams while keeping `p20:app:session:*`, and only then does measured traffic start.
The handshake is file-based (`<run>/gate/`): each user writes a `setup-ready-*.json`
marker after its setup login, and the harness writes `gate.json` with `measured: true`
once every marker exists and state is reset. Files are used rather than Redis because the
clients run inside `ip netns exec`, whose loopback is not the host's. Use
`--no-setup-gate` only to debug the workload, never for a reported run.

`mixed` runs five benign identities concurrently with all three attack pools; `combined`
runs the three attacks together with no setup phase. Both are single rows whose ASR is
aggregated across attack types — per-attack ASR comes from the separated workloads, and
`unique_objectives` is reported as unavailable in those rows rather than invented.

`C3` and `C4` are refused on purpose: there is no trained model and no kernel layer yet.
`--dry-run` prints the exact commands without resetting or starting anything.
`--no-netns` runs from the host address and is only for a local smoke test.

Each run writes `eval/runs/<run_id>/` (see `eval/schema.md` §4).

## 5. Aggregating and labelling

```bash
.venv/bin/python eval/labels.py --runs eval/runs --out eval/runs/labels.json \
    --splits-out eval/runs/splits.json
.venv/bin/python eval/compute_metrics.py --runs eval/runs --out eval/results.csv \
    --json eval/runs/metrics.json --labels eval/runs/labels.json \
    --summary-out eval/summary.csv
```

`eval/summary.csv` is the plan's §7.2.6 summary: median, min and max per
`(config, workload)` over the **valid** repetitions, with the contributing run count in
the `repetitions` column. Per-run rows stay in `eval/results.csv`; the summary never
replaces them and never averages an invalid run in.

Minimum grid for a reportable number: **three repetitions per (config, workload)**, with
`--repetition 1|2|3` and varied execution order. Fewer repetitions still produce a valid
row, they just cannot be summarised as a median.

```bash
# The plan-compliant grid: 9 workloads x 3 repetitions, order rotated per repetition.
sudo ./eval/run_grid.sh C0
sudo ./eval/run_grid.sh C2
sudo ./eval/run_grid.sh C1 1     # C1 is benign-only data collection, not an attack grid
```

The grid reports each failed or invalid run and keeps going; its exit status is the number
of failures. Run `sudo ./eval/run_grid.sh C0 -- --dry-run` first to print the exact
commands without touching Redis or starting a service.

Aggregation needs at least three independent benign runs before `labels.py` can suggest
disjoint fit/calibration/test groups.

## 6. Running a single workload without the harness

```bash
sudo ip netns exec ns9 env P20_RUN_ID=manual-scrape-01 P20_RUNS_DIR=$PWD/eval/runs \
  P20_EXPECT_IP=10.20.0.19 P20_TIMEOUT=3 \
  .venv/bin/locust -f locust/attack_scraping.py --headless -u 2 -r 2 -t 30s \
  --host http://10.20.0.1:8000 --only-summary
```

Every workload honours `P20_RUN_ID`, `P20_RUNS_DIR`, `P20_SEED`, `P20_TIMEOUT` and
`P20_EXPECT_IP`. The expected address check makes a mis-targeted namespace fail loudly
instead of producing measurements from the wrong source IP.

## 7. Status

Implemented and unit-tested: identity plan, namespace command generation, credential
generator, objective predicates, attempt records, aggregation maths, label file.
Measured against a running application: **see the journal entry for the exact runs and
outcomes.** Anything not in that entry is unverified.

Known limitations to keep in the report:

* one Uvicorn worker, one VM; per-IP identity is client-side only, so NAT or a proxy
  would collapse it — `--no-proxy-headers` is mandatory;
* `time_to_ban_ms` for the honeypot workload is client-observed, not the kernel ban
  timestamp; kernel timings arrive with the second PR;
* keep-alive means scraping produces few TCP connections; the churn probe exists
  precisely because of that;
* the DoW account `user50` is shared by the three attacker IPs, so token-budget
  contention between them is expected and must be reported, not hidden;
* Windows is an authoring platform only: namespaces, measured runs and ASR numbers
  require the Linux VM.
