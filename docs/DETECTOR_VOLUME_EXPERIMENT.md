# Directional volume IsolationForest experiment

2026-11-18. Predeclared before new collection, training or acceptance metrics.
The previous opened test set is not used for fitting, calibration or selection.
All prior evidence/models remain immutable. Budgets and batching stay unchanged.

## Diagnosis and fixed hypothesis

The original forest assigns an unchanged normal score to a median benign row
when rates increase far beyond fitting support. Rejected v3 similarly gives
-0.612852 at req_10s=20/100/1000/10000 (req_60s=5x), above its -0.642989
anomaly threshold. These are synthetic probes anchored to benign fitting data,
not a parameter sweep over old held-out rows. Multiple inputs and cold-start
low-rate anomalies can dilute the high-volume signal.

IsolationForest splits between training min/max; scores depend on reached leaf
depth, so magnitude beyond the last split is not inherently extrapolated.
Source: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
The proposed scalar and low-volume gate are a hypothesis, not a proven remedy.

## One frozen candidate

- Inputs remain feature version 3. Select req_10s, req_60s, task_token_budget.
- For each input, scale = max(1, benign-fitting 95th percentile).
- Intensity = max(input/scale); forest input = log1p(intensity), one dimension.
- Fit 100-tree IsolationForest, seed 42, max_samples=auto, n_jobs=1, benign only.
- Directional scoring: intensity below the benign-fitting median gets normal
  score 0; otherwise use the forest's unmodified score_samples. This only removes
  low-volume anomaly flags. It never bypasses token buckets, strikes or bans.
- Threshold = lower fifth percentile of independent benign calibration scores,
  with strict score<threshold. No attack labels or held-out metrics choose it.
- Store inputs, scales, gate, transformation version, forest dimension, threshold,
  groups, dataset/source hashes and dependency versions in the artifact.
- Original artifact remains the deployed default until all gates pass. C3 remains
  C2 plus an IsolationForest-based detector; no new hard threshold enforcement,
  score penalty, supervised classifier, Redis field or feature-stream change.

## Fresh groups and fixed acceptance

All groups use disposable Redis, real namespace IPs, unchanged mock and budgets,
five-second worker stop timeout and strict request-ID joins >=98% per group.
No attacker or measured benign IP is allowlisted. Authentication setup is benign;
attacker setup is excluded from malicious truth. Preserve failed captures and
retry with a distinct run ID, same seed; never silently overwrite evidence.

- Fitting: normal and varied benign, seeds 701/702, 10 users, 60s (four groups).
- Calibration: both benign scenarios, seed 703, 10 users, 60s (two groups).
- Held-out: both benign scenarios seeds 711/712/713, 10 users, 60s; credential
  stuffing/scraping/under-cap DoW seeds 721/722/723 respectively with repetitions
  at seed+10 and seed+20, three attacker users, 30s (nine attack groups).
- All are C1. Split membership and IDs are declared before capture; no previous
  test data enter these groups. Compare the candidate and original on the same
  new held-out CSV once, after candidate artifact/hash are frozen.
- Preserve existing acceptance: recall >=20%, precision >=90%, benign detector
  flag rate <=10%, positive recall for every attack type. Report each attack/run
  and denominators. If failed, reject and stop; do not retune on these test rows.
- Only if offline gates pass: live matched C0/C3 normal/varied benign and mixed
  workloads, seeds 751/752/753, three repetitions, 30s per run (18 runs). Ten
  benign or fourteen mixed users. Reverse config order in repetition 2.
  Each C3 group must have <=1% benign policy denials, zero benign bans, and no
  benign errors/timeouts/unknowns. Report all attack unknowns separately.
  Compare p50/p95 client deltas and finalized WAF/scoring time; no unmeasured
  performance claim. Kernel/C4 and final joint benchmark remain pending.

Cold start, limited traffic diversity, bounded history, slower/distributed abuse,
and shorter windows constrain generalization. These are synthetic-lab acceptance
criteria, not a claim of production protection or professor-mandated percentages.

## Independent live confirmation after lifecycle failure

The frozen candidate passed offline acceptance (99.008% recall / 99.575%
precision / 5.772% benign flags), but the first 18-run live grid failed strict
completeness: one varied benign C3 product request ended in GreenletExit after
0.412ms. This remains a failed gate, not a successful request or a model denial.
No artifact/threshold change is allowed from these outcomes.

A's LoggedUser._past_deadline calls runner.quit from a user greenlet. Installed
Locust runners.py stop_users explicitly kills a current user that calls quit,
while other users may be in flight. The five-second stop timeout does not remove
this self-quit path. Keep A-owned files read-only; use an opt-in B lifecycle driver
that stops each expired user and lets a separate supervisor quit/drain the worker.
Request generation, classification, identity, timeouts, seeds and task weights
remain A's originals. The non-gated CLI watchdog is extended ten seconds, while
per-user measured deadlines remain unchanged; overrun rejection remains enabled.
Record the driver hash and lifecycle mode on every run.

Verify the adapter first with focused lifecycle tests and short normal/varied/
mixed C0/C3 smoke pairs. If these checks pass, run one new confirmation grid:
same 18 runs, 30s, three repetitions, fresh seeds761/762/763, reversed order in
rep2. Keep all original gate criteria, including zero benign unknown outcomes.
No model retuning, no replay-until-pass and no relaxation of the failed gate.
Acceptance requires the original offline gate plus this independently checked
confirmation. Preserve both grids and disclose the lifecycle-source change.
