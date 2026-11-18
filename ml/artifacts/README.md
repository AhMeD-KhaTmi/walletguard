# C3 model artifacts

## Current qualified directional-volume model

`model_base_volume_v1.joblib` is the current default when C3 is enabled.
SHA-256: `1eb84211004b6abe42cd2b8ec03e4b06b8504884ad0a8b9c1ca81ce2f55829e3`.
Its adjacent JSON manifest records fitting/calibration IDs, scales, directional
gate, threshold, feature order, source/data hashes and dependencies. Input feature
version remains3 (19 fields); three selected inputs map to one forest dimension.
Required scikit-learn: **1.9.1**. Use the recorded environment; do not edit manifests
or load untrusted joblib files. The original comparison binary below is preserved.

Fresh detector results: precision99.58%, recall99.01%, benign detector flags5.77%.
Those flags are separate from blocking. Eighteen fresh live confirmation runs
record zero benign denials/unknowns/bans over966 C3 benign requests. The first
live grid failed completeness and is preserved. See
[full results](../../docs/DETECTOR_VOLUME_RESULTS.md) for protocol and limitations.

```bash
.venv/bin/python scripts/run_demo.py --mode enforce --model ml/artifacts/model_base_volume_v1.joblib
```

For A's harness, explicitly pass `--model ml/artifacts/model_base_volume_v1.joblib`.
Use B's recorded `scripts/budget_harness.py` adapter with `P20_SAFE_DRIVER=1` for
supervised deadline/draining behavior. The original harness/workloads are unchanged.

## Historical frozen agent-loop model

This repository-generated model is the frozen feature-version-3 base model used
in the 81-run professor-update campaign. It is supplied so A can run C3 after
cloning, without access to B's ignored local datasets. It is a research comparison
artifact with known low recall and scoring overhead; B is investigating both.

- Binary: `model_base_agent_v3.joblib`.
- Manifest: `model_base_agent_v3.json` (training/split hashes, feature order,
  threshold, seed, tokenizer, agent and dependency versions).
- SHA-256: `bb0116a167318df1749a0edf5cf5b95362ccde59f6b8580d732ed82d05722ca1`.
- Required scikit-learn version: **1.9.1**, as recorded by the original environment.
  The loader rejects a version mismatch. Use the recorded Python/dependency
  environment to replay this binary; do not edit its manifest to bypass checks.

With dependencies installed and Redis reachable, run from the repository root:

```bash
.venv/bin/python scripts/run_demo.py --mode enforce --model ml/artifacts/model_base_agent_v3.joblib
```

Alternatively, set `WAF_MODEL_PATH=ml/artifacts/model_base_agent_v3.joblib` when
starting C3 with the documented environment flags. Scripts that use the default
`ml/model_base.joblib` path can use a local copy:

```bash
cp ml/artifacts/model_base_agent_v3.joblib ml/model_base.joblib
cp ml/artifacts/model_base_agent_v3.json ml/model_base.json
```

Do not overwrite this frozen artifact during calibration; save candidate models
under new names. Detector precision is 66.67%, recall 0.0397%, benign detector FPR
1.047%. These are separate from combined WAF enforcement metrics. Read
`docs/PROFESSOR_BENCHMARK_RESULTS.md` before quoting any results.

Only load the trusted artifact supplied by this repository. Joblib model files
can execute Python during deserialization.
