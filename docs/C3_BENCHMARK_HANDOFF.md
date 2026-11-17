# C2 versus C3 benchmark handoff

Historical version-2 handoff. The professor's agent-loop requirements now govern
new collection, models and measurements. See [the current update](PROFESSOR_UPDATE.md).

Completed locally on 2026-11-17 in branch `codex/c3-benchmark`. All 54 matched
namespace runs passed. [Results and evidence](C23_BENCHMARK_RESULTS.md) record the
outcomes and limitations. The harness steps below are implemented in that branch
and copied into the working checkout for A to review and share.

This run compares the same application defenses with and without the base
IsolationForest. The C1 detector evaluation remains a separate result. Use the
same revision, policy, Linux VM, mock backend, workload, rate, account roles,
source-IP layout and seed for each C2/C3 pair.

## Member B artifacts ready

- Frozen model at `ml/model_base.joblib`, SHA-256
  `591afffd16bac2bb45a13d5bf83fda7f2e10f09315df90f2bb15dc754fc4ddad`.
  Transfer this artifact from B and verify its hash before C3. To rebuild with the
  [training instructions](../README.md#ml-workflow), verify the training source,
  dataset and split hashes and use the dependencies in [the model manifest](../ml/model_base.json).
  Check that the threshold remains `-0.6766539020512408`, the split IDs match,
  and the held-out counts match [the detector evaluation](evidence/c3_base_model.json).
  A rebuild at a different Git revision embeds a different revision string.
  Record the chosen binary's hash and keep it fixed for all C3 runs.
- [Detector evaluation](evidence/c3_base_model.json) and
  [local benchmark rehearsal](evidence/c3_benchmark_rehearsal.json).
- [Application metrics collector](../scripts/summarize_app_run.py) for labeled
  benign enforcement outcomes, successful benign latency, finalized WAF
  overhead and scoring latency. It joins by the actual HTTP request ID.

## Implemented harness changes for Member A to review

1. Enable C3 in the harness with `WAF_ML=1` and an explicit `WAF_MODEL_PATH`.
   Check the loaded model and put its SHA-256 in each C3 manifest. C2 runs with
   `WAF_ML=0`. Both use `WAF_MODE=enforce`, `WAF_BUCKETS=1`, `WAF_HONEYPOT=1`,
   and `WAF_EBPF_SIGNALS=0`. Keep the other policy settings constant.
2. Have invalid runs exit nonzero, pass the configured client timeout to each
   HTTP request, and retain unresolved generation outcomes. Keep the measured
   window fixed after any setup phase, and use reproducible per-client seeds
   derived from the paired seed and stable identities.
3. After the clients drain and before the API stops, save the final application
   timing snapshot for each run as described below. Save the existing harness
   outputs alongside it, including manifest, attempts, usage, decisions, bans,
   IP labels and CPU/RSS samples. Confirm readiness and source IPs on the VM.

## Run agreement

- Repeat each workload/profile three times in both configurations. Use
  stuffing, scraping, under-cap DoW, over-cap DoW, honeypot, connection churn,
  benign-only, combined and mixed as defined by the existing repetition grid.
  Reverse the config order for the second repetition and rotate workload order
  as the grid already does. Give every run its own directory and `P20_RUN_ID`.
- Reset the intended Redis runtime state and restart the app before each run.
  Use the same one-worker setup and `WAF_TELEMETRY_LIMIT` in both configs.
  The limit defaults to 10,000 records. For larger runs set it above the total
  expected HTTP requests, including setup, and verify `dropped_timings=0`.
- Capture the snapshot once from the management host, while the app is idle
  after the workers finish. Use the run's actual directory and labels file:

  ```bash
  curl --fail --silent --show-error http://127.0.0.1:8000/dashboard/evidence \
    > "$run_dir/app-evidence.json"
  .venv/bin/python scripts/summarize_app_run.py \
    --run-dir "$run_dir" --labels "$labels_json" \
    --app-evidence "$run_dir/app-evidence.json" > "$run_dir/app-metrics.json"
  ```

- The summary rejects a wrong run ID, marked-invalid manifest, truncated
  snapshot, unlabelled attempts or HTTP replies missing final app timings.
  The HTTP timing-coverage denominator includes transport failures. TCP-only
  churn probes contribute to the client/probe records and have no app timing.
  C2 scoring fields are null. C3 scoring includes the application call to the
  model. Compare finalized `waf_overhead_ms_mean` from this summary separately
  from decision-stream latency and client end-to-end latency.
- Join B's app metrics to A's attack results using `run_id`, `config`, `workload`
  and `repetition`. Report per-run counts, coverage, and the median and range by
  configuration and workload/profile. Use benign IP labels for enforcement FPR
  and preserve the held-out C1 dataset for detector evaluation.
