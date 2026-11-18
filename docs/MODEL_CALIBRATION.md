# Base-model improvement protocol

Prepared before candidate training/evaluation. This work is separate from the
frozen budget-validation source `9cd6f4a`. Existing models and test artifacts stay
immutable. No candidate is activated while the budget campaign runs.

## Candidate fixed in advance

- Fit on the fresh C1 normal/varied benign runs with seeds 101 and 102; calibrate
  on both seed-103 benign runs. Use the accepted seed-101 replacement, never the
  excluded transport-error capture. Preserve run IDs and hashes in the split file.
- IsolationForest, 100 trees, seed 42, benign-only fitting. The candidate uses the
  lower 5th calibration percentile as a flagging threshold; no attack labels select
  it. Flags do not block alone: the existing five-strike plus budget-corroboration
  gate remains. The original 0.5-percentile model remains the frozen comparison.
- Use seven behavior/cost inputs: `req_10s`, `req_60s`, `fail_ratio_60s`,
  `mean_gap_s`, `std_gap_s`, `max_out_tokens`, `task_token_budget`, with `log1p`
  on these nonnegative values. This focuses the model on rates, failures and
  agent cost rather than rare route/header/payload combinations. It is a
  predeclared hypothesis, not an established improvement.
- Input feature contract stays version 3 with all 19 fields. The artifact must
  explicitly declare selected model inputs and transformation; old artifacts
  default to the full input list and identity transformation.
- Compare the frozen old model and candidate on the same preserved original
  held-out CSV, without tuning afterward. Also evaluate fresh C1 test groups:
  normal/varied benign seeds 301/302/303 (90s each), and credential stuffing,
  scraping and under-cap DoW with seeds 401/402/403 respectively (45s each).
  These groups never enter fitting/calibration.
- Export test rows only through explicit client/feature request-ID joins (>=98%
  coverage per run). Keep benign setup logins; exclude attacker setup logins from
  malicious detector truth. Record unmatched/excluded counts. Preserve the original
  historical test CSV unchanged for its before/after comparison.
- Internal candidate acceptance bar: detector recall >=20%, nonzero recall for
  each attack, precision >=90%, and benign detector flag rate <=10% on fresh groups.
  The application must still meet <=1% benign policy blocking and zero benign bans;
  a detector flag is not a denial. The wider flagging threshold deliberately trades
  standalone flag specificity for sensitivity behind the corroboration gate.
  These are research acceptance criteria, not professor-mandated percentages.
  Reject and preserve a failing candidate rather than retuning on its test data.

## Scoring performance

Use a bounded asynchronous microbatch queue: at most 32 rows/batch, 2ms collection
delay, 256 queued rows, one off-thread model call at a time. Size 1 gives the
single-request comparison mode. Backpressure/errors never bypass scoring. Test
cancellation, exceptions and shutdown; compare vectorized and individual scores.
Only this performance path is eligible independently of candidate model quality.

Run the full app/contract/eval regression and HTTP checks after the current
budget measurement finishes; avoid competing CPU-heavy work during that campaign.
Reproduce training on the preserved original dataset and report unchanged old-model
metrics before any model swap. If the candidate passes offline gates, freeze it
and validate C3 benign/mixed behavior and latency against the frozen baseline on
new seeds. Keep A's kernel and joint C4 acceptance separate.

Operational checks, predeclared before candidate metrics:

- Direct versus microbatch: frozen original model, same source/budgets/mock,
  seeds 601/602/603, normal benign 45s and mixed 90s, three repetitions each.
  Reverse mode order in repetition 2. Size 1 uses the original per-request
  off-thread path; size 32 uses the bounded queue. Compare actual p50/p95 and CPU,
  not just the offline batching probe. These are C3 execution variants, not new
  C0–C4 configurations.
- If the model passes offline gates: matched C0/C3 candidate normal/varied/mixed
  90s runs at seeds 501/502/503 (three repetitions), plus single 45s C0/C3 smoke
  replays of A's stuffing/scraping/paced DoW at seeds 511/512/513. Attack probes
  validate integration and do not replace the final three-repetition C0–C4 grid.
- Candidate benign safety: each benign-only and mixed group <=1% policy blocking,
  zero benign auto-bans, and errors/timeouts/unknowns reported separately. Keep all
  failed evidence; no test-driven threshold changes or silent candidate swaps.
