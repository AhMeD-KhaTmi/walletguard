"""Separate model safety and matched direct/microbatch scoring experiments."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=["safety", "performance"], required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--redis-url", required=True)
    parser.add_argument("--candidate", type=Path)
    args = parser.parse_args()
    if args.stage == "safety" and (args.candidate is None or not args.candidate.is_file()):
        parser.error("safety runs require the frozen accepted candidate")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    jobs = []
    for rep in [1, 2, 3]:
        if args.stage == "performance":
            variants = [("direct", 1), ("batch", 32)]
            if rep == 2:
                variants.reverse()
            for workload, seconds in [("benign", 45), ("mixed", 90)]:
                for variant, size in variants:
                    jobs.append((f"perf-{workload}-{variant}-r{rep}", "C3", "normal", workload,
                                 600+rep, rep, seconds, variant, size,
                                 ROOT / "ml/artifacts/model_base_agent_v3.joblib", []))
        else:
            configs = ["C0", "C3"] if rep != 2 else ["C3", "C0"]
            for scenario, workload in [("normal", "benign"), ("varied", "benign"), ("normal", "mixed")]:
                for config in configs:
                    jobs.append((f"model-{scenario}-{workload}-{config.lower()}-r{rep}", config, scenario,
                                 workload, 500+rep, rep, 90, "candidate", 32, args.candidate, []))
    if args.stage == "safety":
        for seed, workload in [(511, "credential_stuffing"), (512, "scraping"), (513, "dow")]:
            for config in ["C0", "C3"]:
                jobs.append((f"model-{workload}-{config.lower()}-probe", config, "normal", workload,
                             seed, 1, 45, "candidate", 32, args.candidate,
                             ["--dow-pace", "2.1"] if workload == "dow" else []))
    index = []
    for uid, config, scenario, workload, seed, rep, seconds, variant, size, model, extra in jobs:
        users = 10 if workload == "benign" else 14 if workload == "mixed" else 3
        command = [sys.executable, "scripts/budget_harness.py", "--agent-scenario", scenario,
                   "--campaign-stage", "validation", "--runs", str(out / "runs"),
                   "--redis-url", args.redis_url, "--python", sys.executable,
                   "run", "--config", config, "--workload", workload, "--duration", f"{seconds}s",
                   "--users", str(users), "--seed", str(seed), "--repetition", str(rep),
                   "--run-id", uid, "--model", str(model.resolve()), *extra]
        print(f"START {uid}", flush=True)
        with (out / f"{uid}.log").open("w") as log:
            child = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                   env={**os.environ, "WAF_TELEMETRY_LIMIT": "100000",
                                        "WAF_SCORE_BATCH_SIZE": str(size), "WAF_SCORE_BATCH_WAIT_MS": "2"})
        path = out / "runs" / uid / "manifest.json"
        m = json.loads(path.read_text()) if path.exists() else {}
        if child.returncode or m.get("invalid") is not False:
            raise RuntimeError(f"invalid {uid}; preserve the capture and inspect its log")
        index.append({"run_id": uid, "variant": variant, "scenario": scenario,
                      "stage": args.stage, "model_sha256": hashlib.sha256(model.read_bytes()).hexdigest(),
                      "config": config, "workload": workload, "seed": seed, "repetition": rep})
        (out / "index.json").write_text(json.dumps(index, indent=2)+"\n")
        print(f"VALID {uid} ({len(index)}/{len(jobs)})", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
