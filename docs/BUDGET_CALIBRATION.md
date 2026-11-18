# Multi-step agent budget calibration

Status: protocol frozen before fresh collection, 2026-11-17.
Branch: `codex/b-budget-calibration`. Owner: B. A's workloads/harness remain
unchanged; B's runner selects a separately identified benign workload in process.

## Problem and boundaries

The original 20,000-token burst / 100-token-per-second refill predates the agent
loop. Existing logs diagnose `llm_tok` denials escalating to budget bans and
blocking catalogue reads. Those old held-out runs and the 81-run benchmark stay
frozen: they will not select new policy values. The frozen version-3 model stays
unchanged. No allowlist exemptions, request/login limit increases or ban-rule
removals are part of this calibration.

## Fresh calibration

- Three repetitions, seeds **101/102/103**, C1 observe only, 120 seconds per run.
- Two separately named scenarios: A's unchanged `locust/benign.py` (10 users)
  and B's `scripts/agent_benign_workload.py` (10 users).
- B's scenario mixes browsing with short/long synthetic prompts, per-step output
  caps 64/120/180/256/320/500, and 1/3/5/8 agent steps. Browser-like headers,
  normal 0.8–4s pauses, five real source IPs and the benign account pools remain.
- Capture client attempts, exact usage, C1 features, decisions, model/environment
  metadata and workload-script hashes before each reset. No raw prompts/passwords
  or bearer tokens are exported in client records.

Fit only complete valid C1 runs explicitly marked `campaign_stage=calibration`.
Join measured successful chat requests to features/decisions by request ID and
account; use the whole-task reservation cost, not just the final output.

The rule is fixed before looking at the new observations:

1. Refill = 125% of the largest per-account token sum in any observed 60s window,
   divided by 60, rounded up to 50 tokens/s, with the old 100/s as a floor.
2. Capacity = twice the largest observed single-task cost, rounded up to 5,000
   tokens, with the old 20,000 as a floor. This covers two concurrent normal tasks.
3. Save run IDs, hashes, maximum task/window costs, selected values and the rule.
   Freeze this candidate before opening independent validation results.

These finite limits describe this synthetic lab's normal workload, not a general
production policy. Validate bursts/account sharing; do not claim universal safety.

## Independent validation

- Seeds **201/202/203**, three repetitions. Same code/policy/model/mock settings
  within matched C0/C2/C3 triplets; reverse configuration order in repetition 2.
- Normal and varied benign-only scenarios: 90s each. Mixed traffic using A's
  existing workload: 90s. A's paced under-cap DoW: 45s with 2.1s per-user pauses,
  reaching the token limit while staying below ordinary request limits.
- Reject failed/overrunning workers, incomplete labels/timings or token mismatches.
- Target each enforced benign-only campaign: zero benign auto-bans and <=1%
  policy-denied benign requests. Report mixed benign safety separately. Errors,
  timeouts and unknown outcomes are not counted as successful protection.
- Report counts, run-level ranges, successful benign p50/p95, matched C0 deltas,
  finalized WAF overhead, attack ASR and independent server token/cost totals.
- If a target fails, retain the failure and collect a new calibration/test split;
  never tune on seeds 201/202/203 and reuse them as a final acceptance test.

Full app/contract/eval regressions and HTTP checks accompany the candidate.
This can verify B's application-side safety; joint IT-6 and C4 remain pending.

## Frozen policy — independent validation complete

Six complete calibration captures contain **1,035 measured chats**. The largest
single task is **19,044 tokens** and the largest account's rolling 60s demand is
**113,550 tokens**. The predeclared rule selects **40,000 capacity / 2,400 tokens/s**.
The [frozen fitting record](evidence/budget_calibration/frozen_policy.json) lists
the exact accepted runs and their hashes. The original normal seed-101 capture
had nine chat timeouts and one connection error, so the complete capture was
excluded and replaced with a same-seed new run ID. Its original records remain
under the local collection's `excluded/` directory.

Only the token allowance changes. The request/login/chat request limits, output
cap, five-strike escalation, ban TTL, allowlist rules, model and scoring path stay
unchanged. As before, policies are finite: a third large task after the two-task
burst is throttled until tokens refill. The [36-run validation](BUDGET_VALIDATION_RESULTS.md)
reports zero observed benign denials/bans: 0/2,804 C2 and 0/2,749 C3 across
benign-only and mixed traffic. Two C2 client shutdown interruptions remain unknown,
not successes or blocks; even treating them as denials stays below the 1% target.
Paced DoW still causes token throttles, with substantial residual allowed usage.
Joint IT-6/C4 and model quality/performance are not completed by this result.
