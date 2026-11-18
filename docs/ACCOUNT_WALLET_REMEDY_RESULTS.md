# Account attribution and aggregate wallet remedy results

Fresh data: six benign C1 calibration runs (seeds1201–1203), 57 matched primary validation runs (1301–1303), and nine additional mixed-contention runs (1401–1403). Nineteen short pipeline smokes (1391) are separate. Every result is retained; no model training or test-based policy adjustment occurred. The [prospective protocol](ACCOUNT_WALLET_REMEDY_PROTOCOL.md) defines the gates and the mixed amendment before that data was opened.

Primary runtime source: `5b9c23f8f240963415cb89d41d5ac4094fe41017`. Mixed-client source: `16b250314f4a7ab94a814f109cb11b79b56d58e7`; application/WAF/model files are byte-identical between those sources. Independent reports check clean source, actual seeds, identities, supervised lifecycle, model hash, account budgets, private audit and independent API/mock accounting. Raw captures remain locally under `eval/runs/account-wallet-*`; compact reports include raw evidence hashes.

## Component decisions

- Account attribution acceptance: **PASS**.
- Aggregate allowance primary acceptance: **PASS**.
- Additional mixed-contention safety acceptance: **FAIL**.

Default account-pressure escalation is now disabled (`WAF_ACCOUNT_PRESSURE_BANS=0`).
The global allowance remains disabled (`WAF_WALLET_CAPACITY=0` and
`WAF_WALLET_REFILL_PER_S=0`) because mixed comfort failed. Its frozen opt-in
candidate remains available for research. Explicit legacy replay uses account
pressure1 and wallet0/0. See the [component decision](evidence/account_wallet_remedy/decision.json).

Mixed C2 denies2/95 legitimate requests in every repetition (2.11% each). C3 denies
2/95,0/95,2/95. Every run must meet<=1%, so pooled averages cannot qualify it.
There are zero unknown/error/timeout outcomes and no capture retries/exclusions.
The global bucket was never reached in shared-account runs; their attribution
result is unchanged by disabling that inactive allowance. Fair admission needs a
separate prospective experiment, rather than a threshold adjustment on these data.

## Shared legitimate account

Counts pool three independent resets. Ban counts are records across resets; they are not distinct lifetime IPs. Traffic remains benign when it exceeds the account chat allowance.

| Config | Policy | Attempts | Denials | FPR % | Blocked browsing | Ban records |
|---|---|---:|---:|---:|---:|---:|
| C2 | legacy | 540 | 310 | 57.41 | 120 | 12 |
| C2 | remedy | 540 | 192 | 35.56 | 0 | 0 |
| C3 | legacy | 540 | 317 | 58.70 | 123 | 13 |
| C3 | remedy | 540 | 192 | 35.56 | 0 | 0 |

Account quota denials stay429 with Retry-After. The remedy prevents account/global pressure from producing IP budget strikes or corroborating an anomaly ban; IP request/login pressure and honeypots still escalate. Existing active bans remain authoritative until expiry. Private `ip_budget` strikes isolate legacy broad budget strikes during migration. It does not remove the shared account quota or account-lockout exposure.

## Aggregate allowance and consumption

The six C1 captures are locally preserved under `ml/data/wallet-calibration-v1`.
Benign-only fitting fixed capacity40,000 and refill5,700 tokens/s before validation, using473 chats, largest task19,092, aggregate rolling1s peak28,176 and rolling60s peak272,871. Per-account40,000/2,400, batching32/2ms and the qualified model remain fixed.

| Config | Variant | Median charged tokens | Median simulated USD | Wallet denials | Token reduction per run |
|---|---|---:|---:|---:|---|
| C2 | legacy | 343620 | 2.974860 | 0 | reference |
| C2 | remedy | 274896 | 2.379888 | 36 | 20.00–20.00% |
| C3 | legacy | 343620 | 2.974860 | 0 | reference |
| C3 | remedy | 274896 | 2.379888 | 36 | 20.00–20.00% |

Every enforce-mode audit reconciles charged usage with API/mock totals and retains uncertain reservations. Retained tokens obey `capacity + refill_per_s * elapsed`; the elapsed interval brackets first admission through last completion. This is a burst/sustained aggregate token limit, **not an absolute daily/monthly spending cap**. Costs depend on input/output mix. Management allowlist exemptions and single-process outage scope still apply.

## Legitimate-user safety and latency

FPR means observed policy denials / measured benign attempts, separate from detector flags. Latency is successful benign responses only; paired C0 deltas are computed per repetition before reporting their median. There is no C0 burst pair in this prospective matrix, so no burst delta is invented. WAF overhead excludes downstream work.

| Profile | Config | Attempts | Denials | Bans | Median client p50/p95 ms | Median paired C0 delta p50/p95 ms | Median WAF p50/p95 ms |
|---|---|---:|---:|---:|---|---|---|
| normal | C0 | 382 | 0 | 0 | 9.85/139.84 | 0.00/0.00 | n/a/n/a |
| normal | C2 | 395 | 0 | 0 | 16.83/138.92 | 7.27/-0.93 | 7.89/26.68 |
| normal | C3 | 387 | 0 | 0 | 40.60/170.10 | 28.11/30.25 | 26.34/69.08 |
| varied | C0 | 376 | 0 | 0 | 10.56/208.73 | 0.00/0.00 | n/a/n/a |
| varied | C2 | 379 | 0 | 0 | 14.69/175.10 | 4.13/-33.63 | 5.23/18.16 |
| varied | C3 | 372 | 0 | 0 | 41.78/202.69 | 31.22/7.97 | 27.43/81.21 |
| burst_within | C2 | 810 | 0 | 0 | 16.56/52.73 | n/a/n/a | 16.25/38.27 |
| burst_within | C3 | 810 | 0 | 0 | 60.28/111.27 | n/a/n/a | 60.79/93.74 |
| wallet_mixed | C0 | 285 | 0 | 0 | 24.77/130.19 | 0.00/0.00 | n/a/n/a |
| wallet_mixed | C2 | 285 | 6 | 0 | 30.01/109.95 | 5.23/-20.24 | 16.37/47.33 |
| wallet_mixed | C3 | 285 | 4 | 0 | 57.51/146.45 | 32.74/18.39 | 41.06/89.62 |

## Attack-specific outcomes

All measured malicious objective attempts form each attack denominator. Known-valid synthetic login success is a diagnostic subset, not the primary ASR. The original A fast-scraping workload is unchanged. Mixed/distributed slow scripts are B-owned and use A’s unchanged client classification/logging.

| Profile | Config | Variant | Attack | Attempts | Successes | ASR % | Blocked | Error/timeout/unknown | Valid login success/attempts |
|---|---|---|---|---:|---:|---:|---:|---|---|
| distributed | C2 | legacy | credential_stuffing | 60 | 15 | 25.00 | 0 | 0/0/0 | 15/15 |
| distributed | C2 | legacy | scraping | 1125 | 1125 | 100.00 | 0 | 0/0/0 | 0/0 |
| distributed | C2 | legacy | dow | 180 | 180 | 100.00 | 0 | 0/0/0 | 0/0 |
| distributed | C2 | remedy | credential_stuffing | 60 | 15 | 25.00 | 0 | 0/0/0 | 15/15 |
| distributed | C2 | remedy | scraping | 1125 | 1125 | 100.00 | 0 | 0/0/0 | 0/0 |
| distributed | C2 | remedy | dow | 180 | 144 | 80.00 | 36 | 0/0/0 | 0/0 |
| distributed | C3 | legacy | credential_stuffing | 60 | 15 | 25.00 | 0 | 0/0/0 | 15/15 |
| distributed | C3 | legacy | scraping | 1125 | 1125 | 100.00 | 0 | 0/0/0 | 0/0 |
| distributed | C3 | legacy | dow | 180 | 180 | 100.00 | 0 | 0/0/0 | 0/0 |
| distributed | C3 | remedy | credential_stuffing | 60 | 15 | 25.00 | 0 | 0/0/0 | 15/15 |
| distributed | C3 | remedy | scraping | 1125 | 1125 | 100.00 | 0 | 0/0/0 | 0/0 |
| distributed | C3 | remedy | dow | 180 | 144 | 80.00 | 36 | 0/0/0 | 0/0 |
| fast_scraping | C0 | legacy | scraping | 4792 | 4792 | 100.00 | 0 | 0/0/0 | 0/0 |
| fast_scraping | C2 | remedy | scraping | 4954 | 279 | 5.63 | 4675 | 0/0/0 | 0/0 |
| fast_scraping | C3 | remedy | scraping | 2404 | 288 | 11.98 | 2116 | 0/0/0 | 0/0 |
| wallet_mixed | C0 | legacy | credential_stuffing | 36 | 9 | 25.00 | 0 | 0/0/0 | 9/9 |
| wallet_mixed | C0 | legacy | scraping | 675 | 675 | 100.00 | 0 | 0/0/0 | 0/0 |
| wallet_mixed | C0 | legacy | dow | 180 | 180 | 100.00 | 0 | 0/0/0 | 0/0 |
| wallet_mixed | C2 | remedy | credential_stuffing | 36 | 9 | 25.00 | 0 | 0/0/0 | 9/9 |
| wallet_mixed | C2 | remedy | scraping | 675 | 675 | 100.00 | 0 | 0/0/0 | 0/0 |
| wallet_mixed | C2 | remedy | dow | 180 | 135 | 75.00 | 45 | 0/0/0 | 0/0 |
| wallet_mixed | C3 | remedy | credential_stuffing | 36 | 9 | 25.00 | 0 | 0/0/0 | 9/9 |
| wallet_mixed | C3 | remedy | scraping | 675 | 675 | 100.00 | 0 | 0/0/0 | 0/0 |
| wallet_mixed | C3 | remedy | dow | 180 | 133 | 73.89 | 47 | 0/0/0 | 0/0 |

Final checks: **118 app/contract tests**, **109 evaluation tests**, and the
saved HTTP probes cover the resulting defaults, legacy replay, atomic admission,
refunds, real Redis outage/recovery, migration isolation, IP abuse and honeypots.
See [application XML](evidence/account_wallet_remedy/application.xml),
[evaluation XML](evidence/account_wallet_remedy/evaluation.xml), and
[HTTP results](evidence/account_wallet_remedy/http.json).

## Evidence and limits

- [Primary CSV](evidence/account_wallet_remedy/results.csv) and [independent validation](evidence/account_wallet_remedy/validation.json).
- [Mixed CSV](evidence/account_wallet_remedy/mixed/results.csv) and [independent validation](evidence/account_wallet_remedy/mixed/validation.json).
- [Frozen benign fitting policy and hashes](evidence/account_wallet_remedy/frozen_policy.json); [smoke report](evidence/account_wallet_remedy/smoke/validation.json).

No result establishes perfect protection. Slow/distributed scraping and valid compromised synthetic credentials remain concerns. Above-IP-capacity legitimate burst bans, response-aware clients, absolute spending caps and general fairness/isolation need separate prospective work. The new cohorts are now opened and cannot be used to tune a claimed independent replacement. A’s real sensor/enforcement, augmented model, IT-1–IT-6 and final C0–C4 remain pending.
