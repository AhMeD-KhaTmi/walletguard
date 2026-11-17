"""Run matched C2/C3 pairs in an already prepared WalletGuard network namespace."""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(REPO))

from eval.compute_metrics import COLUMNS, SUMMARY_METRICS, read_attempts, summarise, summarise_repetitions
from eval.labels import label_for
from scripts.summarize_app_run import summarize

WORKLOADS = {
    "stuffing": ("credential_stuffing", 45, []),
    "scraping": ("scraping", 45, []),
    "dow-under": ("dow", 45, ["--profile", "undercap"]),
    "dow-over": ("dow", 45, ["--profile", "overcap"]),
    "honeypot": ("honeypot", 20, []),
    "churn": ("churn", 20, []),
    "benign": ("benign", 90, ["--users", "10"]),
    "combined": ("combined", 45, []),
    "mixed": ("mixed", 90, []),
}
APP_FIELDS = (
    "benign_attempts", "benign_policy_denials", "false_positive_rate", "benign_errors",
    "benign_timeouts", "benign_unknown", "benign_unsuccessful_rate", "latency_p50_ms",
    "latency_p95_ms", "latency_p99_ms", "waf_overhead_ms_mean", "scoring_p50_ms",
    "scoring_p95_ms", "timing_coverage", "http_attempts", "timed_attempts",
    "waf_overhead_p50_ms", "waf_overhead_p95_ms",
)
BASELINE_FIELDS = ("latency_delta_p50_ms", "latency_delta_p95_ms")


def add_baseline_deltas(rows):
    key = lambda row: tuple(str(row.get(k, "")) for k in ("workload", "profile", "repetition", "seed"))
    baselines = {key(row): row for row in rows if row["config"] == "C0"}
    for row in rows:
        baseline = baselines.get(key(row))
        for percentile in (50, 95):
            field = f"latency_p{percentile}_ms"
            value = row.get(field)
            reference = baseline.get(field) if baseline else None
            row[f"latency_delta_p{percentile}_ms"] = (
                float(value) - float(reference)
                if value not in (None, "") and reference not in (None, "") else None
            )


def run_summary(run_dir, expected_model_hash):
    manifest = json.loads((run_dir / "manifest.json").read_text())
    run_id = manifest["run_id"]
    labels = {entry["ip"]: label_for(manifest["workload"], entry) for entry in manifest["identities"]}
    observed = {row["ip"] for row in read_attempts(run_dir) if row["phase"] == "measured"}
    if observed != set(labels):
        raise ValueError(f"incomplete identity coverage: {sorted(set(labels) - observed)}")
    if manifest["model_hash"] != (expected_model_hash if manifest["config"] == "C3" else None):
        raise ValueError("unexpected model hash")
    app = (summarize(run_dir, {run_id: labels}, json.loads((run_dir / "app-evidence.json").read_text()))
           if manifest["config"] != "C0" else {})
    result = summarise(run_dir, labels)
    if result["run_valid"] != "true":
        raise ValueError("invalid aggregate row")
    result.update({key: app[key] for key in APP_FIELDS if key in app})
    fields = set(result["unavailable_fields"].split(",")) - {""}
    for key in APP_FIELDS:
        if result.get(key) not in (None, ""):
            fields.discard(key)
    result["unavailable_fields"] = ",".join(sorted(fields))
    (run_dir / "app-metrics.json").write_text(json.dumps(app, indent=2) + "\n")
    (run_dir / "labels.json").write_text(json.dumps({run_id: labels}, indent=2) + "\n")
    return result


def write_csv(path, rows, fields):
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    tmp.replace(path)


def publish(out, rows):
    add_baseline_deltas(rows)
    write_csv(out / "results.csv", rows, list(dict.fromkeys([*COLUMNS, *APP_FIELDS, *BASELINE_FIELDS])))
    summary = summarise_repetitions(rows, [*SUMMARY_METRICS, "benign_attempts", "scoring_p50_ms",
                                          "scoring_p95_ms", "timing_coverage", "benign_unsuccessful_rate",
                                          "waf_overhead_p50_ms", "waf_overhead_p95_ms", *BASELINE_FIELDS])
    write_csv(out / "summary.csv", summary,
              ["config", "workload", "profile", "code_revision", "dow_pace_s",
               "metric", "repetitions", "median", "min", "max"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--redis-url", required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--model-sha256", required=True)
    parser.add_argument("--workload", action="append", choices=WORKLOADS)
    parser.add_argument("--smoke", action="store_true", help="one pair with short windows")
    parser.add_argument("--baseline", action="store_true", help="Include matched C0 runs for latency deltas")
    args = parser.parse_args()
    args.out = args.out.resolve()
    if hashlib.sha256(args.model.read_bytes()).hexdigest() != args.model_sha256:
        parser.error("model SHA-256 does not match the frozen artifact")
    args.out.mkdir(parents=True, exist_ok=False)
    runs = args.out / "runs"
    runs.mkdir()
    names = args.workload or list(WORKLOADS)
    rows = []
    failures = []
    for rep in range(1, 2 if args.smoke else 4):
        rotated = names[rep - 1:] + names[:rep - 1]
        for name in rotated:
            workload, duration, options = WORKLOADS[name]
            configs = ("C3", "C2") if rep % 2 == 0 else ("C2", "C3")
            if args.baseline:
                configs = ("C3", "C2", "C0") if rep % 2 == 0 else ("C0", "C2", "C3")
            for config in configs:
                base = f"{config.lower()}-{name}-r{rep}"
                for retry in range(2):
                    run_id = base if retry == 0 else base + "-retry"
                    command = [
                        sys.executable, "eval/harness.py", "--python", sys.executable,
                        "--runs", str(runs), "--redis-url", args.redis_url, "run",
                        "--config", config, "--workload", workload, "--repetition", str(rep),
                        "--seed", str(41 + rep), "--duration", f"{7 if args.smoke else duration}s",
                        "--model", str(args.model.resolve()), "--run-id", run_id, *options,
                    ]
                    print(shlex.join(command), flush=True)
                    with (args.out / f"{run_id}.log").open("w") as log:
                        child = subprocess.run(command, cwd=REPO, stdout=log, stderr=subprocess.STDOUT,
                                               env={**os.environ, "WAF_TELEMETRY_LIMIT": "100000"})
                    try:
                        if child.returncode:
                            raise ValueError(f"harness exit {child.returncode}")
                        rows.append(run_summary(runs / run_id, args.model_sha256))
                        publish(args.out, rows)
                        print(f"VALID {run_id} ({len(rows)} accepted)", flush=True)
                        break
                    except (OSError, ValueError, KeyError) as exc:
                        failures.append({"run_id": run_id, "reason": str(exc)})
                        (args.out / "failures.json").write_text(json.dumps(failures, indent=2) + "\n")
                        print(f"INVALID {run_id}: {exc}", flush=True)
                else:
                    return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
