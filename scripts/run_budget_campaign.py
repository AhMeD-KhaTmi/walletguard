"""Run predeclared budget calibration or independent validation in the private lab."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--redis-url", required=True)
    parser.add_argument("--stage", choices=["calibration", "validation", "smoke"], required=True)
    parser.add_argument("--model", type=Path, default=ROOT / "ml/artifacts/model_base_agent_v3.joblib")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    rows = []
    scenarios = [("normal", "benign", 10, []), ("varied", "benign", 10, [])]
    if args.stage == "validation":
        scenarios += [("normal", "mixed", 14, []),
                      ("normal", "dow", 3, ["--profile", "undercap", "--dow-pace", "2.1"])]
    repetitions = [1] if args.stage == "smoke" else [1, 2, 3]
    for rep in repetitions:
        seed = (100 if args.stage == "calibration" else 200 if args.stage == "validation" else 900) + rep
        for scenario, workload, users, options in scenarios:
            configs = ["C1"] if args.stage == "calibration" else (["C0", "C2", "C3"] if rep != 2 else ["C3", "C2", "C0"])
            for config in configs:
                run_id = f"budget-{args.stage}-{scenario}-{workload}-{config.lower()}-r{rep}"
                duration = 7 if args.stage == "smoke" else 120 if args.stage == "calibration" else 45 if workload == "dow" else 90
                command = [sys.executable, "scripts/budget_harness.py", "--agent-scenario", scenario,
                           "--campaign-stage", args.stage, "--runs", str(out / "runs"),
                           "--redis-url", args.redis_url, "--python", sys.executable,
                           "run", "--config", config, "--workload", workload,
                           "--duration", f"{duration}s", "--users", str(users), "--seed", str(seed),
                           "--repetition", str(rep), "--run-id", run_id, "--model", str(args.model), *options]
                print(f"START {run_id}", flush=True)
                with (out / f"{run_id}.log").open("w") as log:
                    process = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                             env={**os.environ, "WAF_TELEMETRY_LIMIT": "100000"})
                manifest_path = out / "runs" / run_id / "manifest.json"
                manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
                if process.returncode or manifest.get("invalid") is not False:
                    raise RuntimeError(f"invalid {run_id}: {manifest.get('invalid_reasons', [])}; see log")
                rows.append({"run_id": run_id, "seed": seed, "config": config,
                             "scenario": scenario, "workload": workload,
                             "manifest": str(manifest_path)})
                (out / "index.json").write_text(json.dumps(rows, indent=2)+"\n")
                print(f"VALID {run_id} ({len(rows)})", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
