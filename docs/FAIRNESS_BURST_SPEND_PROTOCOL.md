# Prospective fairness, bursts, harvesting and hard-spend experiments

2026-11-19. Baseline main6b82e70. All earlier opened groups stay immutable and
excluded from fitting. No model training/change. B owns the new clients/adapters;
A's ebpf/locust/eval files remain read-only. Existing defaults stay until gates pass.
Each family below has separate fresh seeds and acceptance; failures are retained.

## Mechanisms fixed before collection

- Wallet fairness: split one aggregate envelope into two disjoint task-size lanes.
  Whole-task reservations <=2,048 synthetic tokens use the small lane; other jobs
  use the general lane. No role/IP/account allowlists, client trust hints or labels
  enter admission. Lanes cannot borrow, so capacities/refills sum to the envelope.
  This protects small tasks from large-task exhaustion; it does not guarantee fair
  service between identical small tasks or eliminate contention within a lane.
- Bursts: fit IP burst capacity from fresh benign burst peaks, retaining2 requests/s.
  Existing sustained IP/login/honeypot defenses and account-aware escalation remain.
- Harvesting: a per-IP product-item bucket charges clamped requested per_page
  (1..100), rather than treating a100-item response like a20-item response.
  Exhaustion429s do not cause IP bans. Slow/distributed clients are tested honestly;
  indistinguishable low-rate scraping may remain allowed.
- Retry-After: B-owned response-aware benign clients honor server delay before
  their next attempt, bounded by the measurement deadline. Fixed schedules remain
  separate controls; log actual schedules and do not relabel denials as successes.
- Hard spend: opt-in, explicitly initialized, non-expiring Redis period ledger in
  integer simulated micro-USD (input3/output15 per token). Whole-task reservation,
  idempotent known-unused refund, uncertain retention. No automatic period reset,
  no refill and no period derived from an untrusted request. Runtime reset and API
  restart preserve the ledger. Missing/unreachable ledger rejects chat admission;
  default bucket/local-outage behavior is unchanged when cap is disabled. No real
  provider-price or production billing claim. A hard total cap intentionally stops
  all further work when exhausted; fairness cannot promise service without funds.

## Fresh fitting only

- Wallet C1 normal/varied,10users,60s, seeds2001/2002/2003 (six runs).
  Require all benign outcomes successful, clean source, >=98% feature joins and
  exact task/API/mock usage. For each size lane independently: capacity=max(4,000,
  2*largest task,1.25*rolling1s aggregate task reserves), rounded up1,000;
  refill=1.25*rolling60s peak/60 rounded up50/s (minimum50). Sum the two lanes for
  a matched pooled-envelope comparator. Threshold2,048 is fixed, not fitted.
- Burst C1 above-capacity profile,10users,50s, seeds2201/2202/2203 (three runs).
  IP capacity=1.25*largest per-IP rolling1s request count rounded up10 (minimum30).
  Product capacity=1.25*largest per-IP rolling1s item demand rounded up100;
  refill=1.25*largest per-IP rolling60s item demand/60 rounded up5/s (minimum5).
  Existing client labels and actual query costs supply the ledger; no attack fitting.
Freeze the resulting JSON/hash before any dependent validation.

## Validation matrix (three repetitions; reverse order in repetition2)

1. Fairness seeds2101–2103: mixed contention45s and varied benign30s, matched
   C0/current C2/lanes C2/lanes C3 (24 runs). Add pooled C2 mixed45s each seed
   (three captures) using exactly the same total envelope. Gate: <=1% benign
   denials in EVERY candidate run, zero benign bans/setup/other failures or
   errors/timeouts/unknowns; audit aggregate retained usage<=C+R*elapsed. Report
   attack-specific ASR and actual costs; do not promise perfect fairness.
2. Burst/harvesting seeds2301–2303: fixed above-capacity benign50s, the same
   response-aware benign50s, distributed attack45s and slow mixed120s, matched
   C0/current C2/candidate C2/candidate C3 (48 runs). Candidate uses fitted burst
   and product budgets, no wallet. Comfort<=1% per benign run and zero bans/setup/
   other failures. Harvesting gate: >=10% lower scraping successes per attack run
   than matched current C2; slow and distributed qualify separately. Report
   opportunities/retry delays alongside attempts, successes and unique products.
3. Hard cap seeds2401–2403: distributed attack45s, C0/capped C2/capped C3
   (nine runs). Period cap1,000,000 micro-USD ($1 simulated), no wallet/product
   candidate. Gate: API/mock exact cost<=cap; ledger known+uncertain<=cap; cap
   denials actually occur; no automatic resets. Request retries/restarts/Redis
   loss/refunds/concurrency also receive scratch-Redis integration tests.
4. Preserved defenses: A's original fast scraping10s against C0/candidate C2/C3,
   fresh seeds2501–2503 (nine runs). Require bans under both hardened modes,
   >=50% lower ASR than matched C0 and no unknowns. IP login/honeypot tests stay.

All raw captures, errors and unfavorable results remain. One distinct-ID retry is
allowed only for invalid collection, never for a failed acceptance gate. Record
source/model/policy/identity/client hashes and actual timing/seeds. Report benign
p50/p95 paired C0 deltas and finalized WAF overhead. No C4 claim. New mechanisms
remain opt-in unless their component AND compatibility gates pass; retaining
validated defaults is a valid outcome. Any follow-up requires unopened data.

Prospective clarification before any validation capture: the slow horizon is120s
(two minutes) to observe depletion beyond a short burst allowance, rather than72s.
No calibration outcomes or held-out results selected this horizon. Four separate
8s pipeline smokes use seed2601; their outcomes are not acceptance measurements.

## Prospective combined compatibility gate — before compatibility capture

Independent components cannot authorize a combined default. If all original
component/preserved-defense gates pass, run a separate fresh combined study:
seeds2701–2703,50s,30 users across the15-source mixed map (two users/source).
Five benign sources use the original above-capacity burst shape (ten users,
20 reads+one small chat/user at0/24/48s,630 planned legitimate requests). Other
roles use the distributed shape: six login, six scraping and eight DoW users,
with the four DoW accounts47–50. Metadata records each actual per-role plan.
WAF admission still uses no actor labels, trusted user hints or role allowlists.

Matched C0/current C2/combined C2/combined C3, three repetitions, reversed order
in repetition2 (12 captures). Combined means unchanged frozen lanes+resource
parameters, hard spend disabled. Separate8s C2 smoke uses2709. Gates for EVERY
candidate capture: exactly630 measured benign attempts, all successful; zero
benign bans/setup failures/other failures, zero all-actor errors/timeouts/unknowns;
exact usage and lane/total bounds. Report attack objectives and residual exposure.
No poor-outcome retries or tuning; one new-ID retry only for invalid collection.

Only if original component gates AND this compatibility gate pass may the fitted
lanes/IP/item controls become the C2/C3 defaults. The historical baseline remains
explicitly replayable. Hard spending always remains opt-in with a trusted period
and operator-selected cap. Otherwise keep current defaults and report the failed
gate. Fresh data is mandatory for any subsequent repair or additional claim.
