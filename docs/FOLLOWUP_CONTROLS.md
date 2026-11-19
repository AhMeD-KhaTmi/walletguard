# Qualified resource controls and optional spending

The fitted lane/IP/item controls are now the B-owned C2/C3 defaults after both
independent and combined gates passed. [Results](FOLLOWUP_RESULTS.md) ·
[Prospective protocol](FAIRNESS_BURST_SPEND_PROTOCOL.md). They preserve the validated
model/account quotas and do not enable C4. Absolute spending is opt-in with an
operator-chosen period and budget. The earlier baseline is explicitly replayable.

## Task-size wallet lanes

The fresh benign-only fit and combined acceptance qualify these default settings
(explicit flags shown for reproducibility):

```bash
WAF_MODE=enforce WAF_ML=1 \
WAF_WALLET_CAPACITY=56000 WAF_WALLET_REFILL_PER_S=7300 \
WAF_WALLET_SMALL_CAPACITY=9000 WAF_WALLET_SMALL_REFILL_PER_S=1800 \
WAF_WALLET_SMALL_TASK_MAX=2048 \
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Whole tasks up to2,048 synthetic tokens use the small lane; larger tasks use the
47,000-capacity/5,500-token/s general lane. The lanes cannot borrow, so their total
allowance remains56,000/7,300. Any account can submit either task size; no traffic
label or special account list enters the decision. This protects small tasks from
large-task exhaustion, not against identical small-task abuse. It can strand idle
capacity and cannot guarantee fairness within a lane. Setting all three SMALL
values0 selects the pooled comparator at the same total envelope. Setting total
wallet capacity/refill0 disables wallet admission entirely.

## Burst capacity and product-item quota

```bash
WAF_MODE=enforce WAF_ML=1 WAF_IP_CAPACITY=60 \
WAF_PRODUCTS_CAPACITY=1000 WAF_PRODUCTS_REFILL_PER_S=50 \
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The IP request refill remains2/s. Product quota cost is the requested page size,
clamped to the API's1..100 range. A100-item page costs five times a20-item page.
Invalid integer forms follow API validation; accepted forms like100.0 are charged
consistently. Item throttles return429/Retry-After without IP ban escalation.
Tail/empty pages can be conservatively overcharged. Scraping below the item rate,
additional source IPs and coordinated small requests remain limitations.

## Absolute synthetic spending period

Initialize the operator-chosen period once, using an isolated demo Redis:

```bash
.venv/bin/python scripts/init_spend_period.py \
  --redis-url redis://127.0.0.1:6379/0 \
  --period demo_2026_11_19 --cap-microusd 1000000
WAF_MODE=enforce WAF_ML=1 \
WAF_SPEND_PERIOD=demo_2026_11_19 WAF_SPEND_CAP_MICROUSD=1000000 \
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The allowance is$1 **simulated**, at input3/output15 micro-USD per token. Reserve
all agent iterations before any generation. Refund only known unused credit;
unknown/unreconciled generation retains the allocation. The ledger never refills
or expires; restarting the API, changing run IDs and routine runtime resets cannot
restore its balance. Reinitialization preserves an existing matching period and
rejects changing its cap. A different period explicitly creates a different budget.
Do not rotate period IDs automatically to evade exhaustion.

Exhaustion returns429/spend_cap with no scheduled Retry-After. Missing, mismatched
or unreachable ledger returns503 for capped chat admission. Other default local
bucket/outage behavior remains. Management-allowlisted requests bypass the WAF and
are outside this allowance. Real billing, Redis data durability, calendar rotation,
backups and multi-worker outage credit allocation are outside this prototype.
A hard cap intentionally stops further work when funds are exhausted; it cannot
promise uninterrupted legitimate use after an attacker spends all shared credit.

## Reproduce measurements

Use `scripts/run_budget_isolated.sh` with `P20_CAMPAIGN_SCRIPT` pointing to
`scripts/run_followup_calibration.py` or `scripts/run_followup_study.py`. Each
runner requires a new output directory and the latter requires the frozen policy.
See their `--help` for arguments. Never rerun into or tune from existing captures.
C0 is the same API with WAF off. B's supervised driver keeps deadlines bounded;
A's scenario/classification files remain unchanged. The response-aware benign
variant is `scripts/followup_retry_workload.py`. Every429 remains a logged denial;
completed backoff waits and counterfactual fixed-schedule opportunities are reported.
A deadline-ending wait may have no following attempt/stat update, so recorded wait
sums are a lower bound and not a claim of total user waiting time.

## Replay the preceding baseline exactly

```bash
WAF_MODE=enforce WAF_ML=1 WAF_ACCOUNT_PRESSURE_BANS=0 WAF_IP_CAPACITY=30 \
WAF_WALLET_CAPACITY=0 WAF_WALLET_REFILL_PER_S=0 \
WAF_WALLET_SMALL_CAPACITY=0 WAF_WALLET_SMALL_REFILL_PER_S=0 WAF_WALLET_SMALL_TASK_MAX=0 \
WAF_PRODUCTS_CAPACITY=0 WAF_PRODUCTS_REFILL_PER_S=0 \
WAF_SPEND_CAP_MICROUSD=0 WAF_SPEND_PERIOD= \
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

This matches the prior6b82e70 account-aware baseline. Older broad account-to-IP
escalation also needs WAF_ACCOUNT_PRESSURE_BANS=1. The original robustness case
names refer to its old30-request burst boundary; do not assume “above” still means
above a later capacity. Preserve old evidence and use recorded effective policies.
For exact cap-only measurements use followup_harness.py variantcap, which explicitly
disables wallet/item candidates and restores IP30. A manual spending cap can layer
onto current defaults, but its published cap-only timing/ASR figures describe that
recorded standalone configuration. Financial units remain synthetic only.
