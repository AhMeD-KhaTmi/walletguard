# Model candidate development record

## 2026-11-18 — retain rejected v1; broaden legitimate training coverage

Model/scoring source is frozen at `86f34e5` in a separate checkout. Retraining
the original benign dataset reproduces its threshold and every preserved test
score exactly. The current original artifact is unchanged.

The predeclared seven-input log1p candidate v1, fitted only on fresh ten-user
benign runs, reached 99.82% recall / 99.75% precision on the historical comparison
but flagged 25/191 benign rows (13.09%). That regression is unacceptable for
coverage of the already-known five-user normal workload. Preserve v1 and its
results; do not deploy it or describe it as a qualified model.

Before opening any metrics or feature values from the fresh 301–303/401–403
test groups, define v2 as follows:

- Keep the seven selected inputs, log1p, 100 trees, seed 42 and 5th-percentile
  flag threshold rule. No parameter sweep or threshold adjustment is permitted.
- Fit on the four fresh seed-101/102 benign groups **plus** the original
  `agent3-benign-1` fitting run. Calibrate on both fresh seed-103 groups **plus**
  the original `agent3-benign-2` calibration run. This covers five- and ten-user
  normal traffic and multi-step variability. No original or fresh test rows enter
  fitting/calibration.
- Preserve hashes and all group IDs in a new CSV/split manifest and separate v2
  artifact. Preserve v1; do not overwrite it.
- Require the historical benign flag rate to be <=10% as a compatibility gate,
  and apply the predeclared fresh-test recall/precision/per-attack/flag-rate bars.
  Application policy blocking must remain <=1% with zero benign auto-bans in
  independent live testing. A model flag alone remains nonblocking.
- The historical comparison has identified a development failure and is not an
  unbiased final estimate. The still-unopened fresh detector groups and new live
  seeds provide final validation. Do not tune from their outcomes.

The budget campaign is complete and independent of these research changes.
No model candidate has been activated in that campaign or on main.

## Pre-fresh-test final input profile

Broader v2 covers the prior normal workload better (19/191 historical flags,
9.95%), but its historical overall recall is only 8.72%, with most rate-based
stuffing/scraping missed. Preserve that failed development result too. These
historical comparisons are development/regression observations; no final-model
quality claim is based on them.

Before opening the fresh set, the final candidate uses only `req_10s`, `req_60s`
and `max_out_tokens`, all log1p. Gap/variance features depend strongly on scheduling
and concurrency; removing them also concentrates the forest on request volume
and per-step output demand rather than timing/payload correlations. The benign
fit/calibration groups, 100 trees, seed 42 and 5th-percentile rule remain exactly
the broadened v2 definitions. The generic artifact loader already supports this
explicit selection without changing input feature contract version 3.

This is the final development profile for the reserved fresh groups, whose data
and metrics have not been opened for model selection. Apply the original fresh
acceptance bars once and retain the outcome. Do not adjust this profile or its
threshold from those results. No old or new test rows are used in fitting.

## Fresh acceptance result — rejected, no deployment

All nine reserved C1 groups completed. Their request-ID-joined test CSV contains
11,590 rows: 2,308 benign and 9,282 malicious. Its SHA-256 is
`d8c1f33ad7d29e37a03cb50ad3788ee855b52479e6d55a461e7f72cce859c251`.
Each group has at least 99.75% join coverage. Benign setup logins are retained;
attacker setup logins are excluded from malicious detector truth.

| Model on the same fresh test | Precision | Recall | Benign detector flags |
|---|---:|---:|---:|
| Original frozen 19-input forest | 33.33% | 0.0646% | 0.520% |
| Final three-input log1p candidate | 88.20% | 6.77% | 3.64% |

The candidate has 628 TP, 84 FP, 8,654 FN and 2,224 TN. Its attack-specific recall
is 6/3,473 stuffing, 6/5,103 scraping and 616/706 DoW. It fails both the fixed
20% recall and 90% precision bars. Its 8.90% historical benign flag rate passes
the compatibility bar but does not override failed fresh acceptance.

Candidate SHA-256:
`1b4dc810cb605abecb063a6e2624b4fda32fe696174ecb1df7c1c17784d1f361`.
It is rejected and was never used for enforcement. The original model remains
active. Do not tune another candidate against this now-opened test set. Future
research requires a new protocol and fresh independent groups. Detector flags
remain separate from application denials; budget success does not repair recall.

The manifests, splits, historical comparisons and fresh confusion matrices are
preserved under `docs/evidence/model_calibration/`. Raw captures and candidate
weights remain in ignored local `ml/data/` directories. The generic input-profile
loader is compatible with the original artifact and does not activate a candidate.
Performance-only testing uses the original forest and is assessed independently.
