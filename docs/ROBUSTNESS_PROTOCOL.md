# Fixed-policy application robustness study

2026-11-18. Defined before fresh capture. Current main79f3d24 is already pushed.
This is an evaluation of the qualified C2/C3 defenses, not model training or tuning.
C0 controls establish that the workloads actually execute. No kernel/C4 claims.

## Frozen controls and measurement

- Same app, Redis schema2, feature version3, exact synthetic HTTP mock and tokenizer.
- Current qualified forest SHA256
  `1eb84211004b6abe42cd2b8ec03e4b06b8504884ad0a8b9c1ca81ce2f55829e3`.
- llm_tok capacity40,000/refill2,400 per second; ip_req capacity30/refill2 per second; login_ip capacity5/refill5 per minute;
  login_acct5/5 per900s; chat_req10/0.5s; ban/strike/output policies unchanged.
- B's supervised lifecycle driver, batching32/2ms, one worker, timeout3s and stop5s.
  Explicit source/hash/effective policy, worker seeds, scenario/identity mapping,
  usage and client attempts archived. No measured IP is allowlisted.
- Three repetitions at fresh seeds1101/1102/1103. Every profile has matched
  C0/C2/C3 runs. Config order C0/C2/C3, C3/C2/C0, C2/C0/C3 respectively; profile
  order rotates each repetition. Total45 valid captures. Smoke covers all
  five profiles in all three configs (15 eight-second runs, seed1191) before measurement.
  Smoke scales periods/phases by0.1 so every source participates; manifests label
  this altered timing. Smoke checks pipeline integrity only, not comfort/security.
- All actors synchronize on a common measured gate. Authenticated roles log in
  during setup; anonymous roles announce readiness without login. The harness
  resets runtime state while retaining sessions before opening the gate. Burst
  and DoW phases use that common clock, not variable worker startup times.
- Reset state and restart app/mock before every run. Preserve failures/exclusions;
  at most one same-seed new-ID retry for capture invalidity, not for poor security
  or benign outcomes. Record each exclusion; never replay until favorable results.
- Compare timing and usage only within matched profile/repetition. No held-out data
  or model parameters from earlier studies are changed. A-owned source stays read-only;
  explicitly identified B scripts reuse A's harness, objective classifiers and logger.

## Fresh profiles

| Profile | Duration | Sources/users | Declared behavior |
|---|---:|---|---|
| slow_mixed |72s|5 benign +9 attack IPs, one user each|Benign actions every2.4s; login guesses every15s/IP, 25% deliberately valid synthetic pairs with account rotation; scrapes every1.5s/IP; user50 eight-step/900-output tasks every45s/IP, staggered0/15/30s across its three sources |
| distributed |60s|14 attack IPs, one user each|Five login sources every13s with account rotation/25% valid pairs, five scraping sources every0.6s, four DoW sources using separate synthetic accounts46–49, three steps/900 output every3s/account |
| shared_account |36s|5 benign IPs, one user each|All legitimately use user1; each logs in once, then browses and performs a small three-step/120-output chat every2s. Tests account contention with per-IP demand inside allowance |
| burst_within |30s|5 benign IPs, two users each|Distinct legitimate accounts; each issues8 reads +one one-step/64-output chat in a burst every12s. Approximately18 requests/IP/burst, inside initial30 capacity and sustained2/s |
| burst_above |50s|5 benign IPs, two users each|Same legitimate roles,20 reads +one chat/user every24s (42 requests/IP/burst,1.75/s sustained). Deliberately crosses burst capacity while staying below sustained2/s; measure collateral throttles/bans, do not relabel users as attackers |

Slow DoW prompt120 words and reserve33,612/task give2,240.8 reserved tokens/s
across the three sources, below2,400/account/s with staggering. Distributed DoW
prompt100 words reserves5,727/task; one every3s is1,909/account/s, below allowance,
while all four accounts aggregate7,636 tokens/s. No global daily spending cap is
claimed. Actual task/start rates are reported rather than assuming ideal scheduling.
Slow/distributed credential targets rotate across synthetic accounts; invalid
credentials are ordinary attack failures, separate from WAF blocks. Account20–39
are used in distributed login probes; DoW uses46–49. Slow login targets30–49
exclude31/41 to avoid the benign sessions' fixed accounts.

The dedicated distributed profile reassigns existing namespace IPs in a separate
B-owned identity file: ns1–5 login, ns6–10 scraping, ns11–14 DoW; no benign users
in that run. Canonical identities.json is unchanged. Shared-account profile changes
only the benign account lists in a separate identity file. Record actual accounts
per source. No real credentials, external targets or forwarded-IP identity tricks.

## Finite-window burst-rate clarification

The above-cap profile has a periodic steady-state demand of42/24=1.75 requests/s
per IP. Its50s observation window contains three bursts (126 requests/IP), so
its finite-window average is2.52/s. The integrated initial-plus-refill allowance
is30+2*50=130 requests/IP, above total demand; the instantaneous42-request burst
still exceeds capacity30. Report actual finite-window rates alongside the periodic
rate; do not label the measured2.52/s average as below2/s. This clarifies the
frozen schedule without changing captures or acceptance criteria.

## Fixed client behavior clarification

The committed workload schedules are fixed and do not adapt to HTTP429/Retry-After;
subsequent already-planned actions continue, with no hidden retry loop. This follows
the frozen source and is material when interpreting legitimate burst/account bans.
It is not a test of response-aware clients that back off after a denial. Such clients
require a separate profile and fresh validation. No measured behavior changes here.

## Outcomes and interpretation fixed in advance

Report per-attack ASR, attempts/success/fail/blocked/timeout/error/unknown counts,
unique catalogue items, actual per-IP rates, tokens/cost and bans by role/reason.
Measure benign policy-denial FPR, all other unsuccessful outcomes, setup outcomes,
benign bans, client p50/p95 and paired deltas from C0, finalized WAF p50/p95 and
scoring p95. A model flag is separate from denial; report scored coverage and flag
rates for C3. Keep setup logins separate but expose legitimate setup denials.

Benign comfort target is <=1% policy denial per run, zero benign bans and no
unknown/errors/timeouts. Missing malicious-blocking targets are findings, not an
excuse to invalidate captures. For slow/distributed probes, report residual abuse
and whether any enforcement occurred; do not assert perfect prevention. Above-cap
legitimate bursts may fail comfort by design. Shared-account and within-policy
bursts can expose safety gaps. Preserve every unfavorable result. Any remedy needs
a separate prospective policy experiment and fresh validation groups.

These short synthetic profiles explore rate/account boundaries, not production
load capacity or a final C0–C4 benchmark. C4 waits for A's real sensor/enforcement.
