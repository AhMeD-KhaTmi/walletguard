"""Collect only the predeclared fresh C1 detector test groups; never fit a model."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from eval.compute_metrics import read_attempts
from eval.export_features import export
from eval.labels import collect


def expected_runs():
    jobs = []
    for rep in [1, 2, 3]:
        for scenario in ["normal", "varied"]:
            jobs.append((f"model-test-{scenario}-benign-r{rep}", scenario, "benign", 300+rep, rep, 10, 90))
    for seed, workload in [(401, "credential_stuffing"), (402, "scraping"), (403, "dow")]:
        jobs.append((f"model-test-{workload}", "normal", workload, seed, 1, 3, 45))
    return jobs


def export_test(out):
    import pandas as pd

    labels, _ = collect(out / "runs")
    (out / "labels.json").write_text(json.dumps(labels, indent=2)+"\n")
    csvs = export(out / "runs", out / "labels.json", out / "features-csv")
    if len(csvs) != 9:
        raise ValueError("all nine held-out captures must contain feature rows")
    frames, coverage = [], []
    for source in csvs:
        run = out / "runs" / source.stem
        m = json.loads((run / "manifest.json").read_text())
        if m["invalid"] or m["config"] != "C1" or m.get("campaign_stage") != "validation":
            raise ValueError("detector test export requires valid held-out C1 captures")
        # All benign authentication is benign. Successful attacker setup logins
        # are not malicious objectives and are excluded, rather than mislabeled.
        attempts = [r for r in read_attempts(run) if m["workload"] == "benign" or r.get("phase") == "measured"]
        known_ids = [r["request_id"] for r in attempts if r.get("request_id")]
        ids = set(known_ids)
        if len(ids) != len(known_ids):
            raise ValueError("duplicate client request IDs in held-out capture")
        frame = pd.read_csv(source)
        if frame.request_id.duplicated().any():
            raise ValueError("duplicate feature request IDs in held-out capture")
        frame = frame[frame.request_id.isin(ids)]
        matched = len(set(frame.request_id))
        fraction = matched/len(attempts) if attempts else 0
        coverage.append({"run_id": m["run_id"], "client_attempts": len(attempts),
                         "joined_feature_rows": matched, "coverage": fraction,
                         "excluded_feature_rows": m["features"]["rows"]-len(frame)})
        if fraction < .98:
            raise ValueError("detector test request-ID coverage below the predeclared 98% gate")
        frames.append(frame)
    (out / "join_coverage.json").write_text(json.dumps(coverage, indent=2)+"\n")
    pd.concat(frames, ignore_index=True).to_csv(out / "test.csv", index=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--redis-url", required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    index = []
    for uid, scenario, workload, seed, rep, users, seconds in expected_runs():
        command = [sys.executable, "scripts/budget_harness.py", "--agent-scenario", scenario,
                   "--campaign-stage", "validation", "--runs", str(out / "runs"),
                   "--redis-url", args.redis_url, "--python", sys.executable,
                   "run", "--config", "C1", "--workload", workload, "--duration", f"{seconds}s",
                   "--seed", str(seed), "--repetition", str(rep), "--users", str(users), "--run-id", uid]
        print(f"START {uid}", flush=True)
        with (out / f"{uid}.log").open("w") as log:
            child = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                   env={**os.environ, "WAF_TELEMETRY_LIMIT": "100000"})
        path = out / "runs" / uid / "manifest.json"
        m = json.loads(path.read_text()) if path.exists() else {}
        if child.returncode or m.get("invalid") is not False:
            raise ValueError(f"invalid held-out capture {uid}; preserve log and resolve readiness")
        index.append({"run_id": uid, "seed": seed, "scenario": scenario, "workload": workload})
        (out / "index.json").write_text(json.dumps(index, indent=2)+"\n")
        print(f"VALID {uid} ({len(index)}/9)", flush=True)
    export_test(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
