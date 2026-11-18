# Account attribution and aggregate wallet remedy experiment

2026-11-18. Frozen before new calibration/validation. Baseline main47f0e5f and
all prior robustness/model data remain immutable. No model training or threshold
change. This experiment addresses account-related IP bans and aggregate token
consumption; it does not claim to solve slow credential compromise or scraping.

## Candidate components

1. Scope-aware escalation: login_acct/chat_req/llm_tok and the new global wallet
   quota return their normal policy denial/retry. They do not add an IP budget
   strike or corroborate an anomaly ban. ip_req/login_ip escalation and honeypot
   bans remain. Existing active bans are respected until expiry; do not delete
   legitimate Redis bans during rollout. Legacy behavior remains replayable.
2. A service-wide token bucket on authenticated /chat, in addition to the existing
   per-account buckets. Reserve the whole agent task before backend calls, refund
   only known unused tokens; retain uncertain usage. Use the existing atomic Lua
   and locked conservative outage backend in waf/buckets.py. No new bucket math.
   Global pressure returns429/Retry-After and must not cause an IP ban.

This is an aggregate burst/sustained token allowance, not an absolute daily/monthly
spending cap. Total charged plus retained uncertain reservations must be bounded
by capacity + refill*elapsed over a run. Actual simulated USD depends on token mix.
It caps fanout across accounts, but an allowlisted management client bypasses WAF
as before; measured users are never exempt. Single-worker outage limitations stay.

## Fresh benign-only fitting rule

Capture C1 normal/varied benign, 10 users,60s each, seeds1201/1202/1203 (six groups).
Never fit from any earlier opened validation group or attack outcomes. Join feature
request IDs to measured successful benign chats with >=98% coverage and no benign
transport/unknown outcomes. Check exact independent API/mock accounting.

For whole-task reserve values at their actual start times across ALL accounts:
- Capacity = max(40,000,2*largest task,1.25*largest rolling1s aggregate demand),
  rounded up to5,000.
- Refill/s = 1.25*largest rolling60s aggregate demand/60, rounded up to50.

Freeze the resulting policy and hashes before validation. Per-account40,000/2,400,
request/login/chat limits, model, output cap, strike count and ban TTL stay fixed.
Record private wallet reserve/charge/refund audit separately; shared schema2 fields
and reasons are unchanged. New policy reason wallet_tok is an optional denial
reason, never a new ban reason. Document private keys and flag to A via handoff.

## Fresh validation and fixed gates

All runs use the same source/mock, supervised driver, namespace identities and
new seeds1301/1302/1303. Legacy and remedy are policy variants within C2/C3, not
new configurations. Reverse variant/config ordering in repetition2. Existing
robustness shapes are reused with new seeds and these explicitly recorded windows:
- Shared-account36s and distributed45s: matched legacy/remedy in both C2 and C3,
  three repetitions (24 runs). Shared fixed schedules still exceed the account
  chat allowance; throttling is expected and must remain visible.
- Normal and varied benign30s: matched C0 / remedy C2 / remedy C3, three repetitions
  (18 runs). Compare benign client deltas from matched C0.
- Within-capacity bursts30s: remedy C2/C3, three repetitions (six runs).
- Fast A scraping script10s: C0 / remedy C2/C3, three repetitions (nine runs).
Total57 acceptance captures, plus separate short smoke probes at seed1391.
All failures remain; at most one distinct-ID retry for invalid capture, never
for an unfavorable security/comfort result. No test-driven allowance adjustment.

Account-attribution gates: no IP bans or IP budget corroboration from pure account
pressure, no benign browsing403 in shared-account runs, and account chat throttles
still occur. Report the remaining benign denial rate; do not claim zero blocking.
IP floods/login-IP abuse and honeypots must still ban in focused/integration tests.

Wallet gates: each distributed remedy run has wallet_tok denials; measured total
known charged plus retained uncertain tokens obeys capacity+refill*elapsed. Compare
actual token/cost and ASR to matched legacy, requiring at least10% lower aggregate
charged tokens per distributed run. No benign bans/errors/timeouts/unknowns and
<=1% benign policy denials per normal/varied/within-burst run. Shared-account total
FPR is diagnostic because its workload deliberately exceeds chat quota.

Components may qualify separately: attribution can become default if its safety
and preserved-defense gates pass, even if the global candidate fails benign gates.
Global admission is enabled by default only if all wallet gates pass. Preserve a
failing candidate and do not retune it on these groups. Above-IP-capacity burst
bans, response-aware clients, hard total-spend caps and C4 remain separate work.

## Additional prospective mixed-contention gate (before mixed capture)

Before enabling the global default, require a fresh mixed-contention study at
seeds1401/1402/1403: matched C0 / remedy C2 / remedy C3,45s (nine captures).
Five benign sources/users run normal browsing/small chats alongside three login,
three scraping and four DoW sources/accounts47–50. Dedicated B identity map uses
ns15 as the fourth DoW source instead of a probe; canonical/A source stays intact.
Benign accounts are fixed to1/11/21/31/41. Existing distributed client timing is
used with explicit actual worker plans, source/hash and identity records.

The policy/model and the original57-run acceptance gates stay frozen. This adds
an independent safety requirement, not a replacement for unfavorable results:
<=1% benign denials per candidate mixed run, no benign bans, setup failures or
other unsuccessful outcomes; private audit must still obey conservation/bounds.
Do not tune from these data. If contention fails, leave global admission opt-in
and report the need for fairness/isolation; attribution can still qualify separately.
