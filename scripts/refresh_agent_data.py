"""Collect fresh version-3 C1 runs and train the base model on declared groups."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import shutil

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import pandas as pd

from eval.export_features import export
from eval.labels import collect
from ml.evaluate import evaluate
from ml.train import train
from waf.features import FEATURE_VERSION


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--redis-url", required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=args.resume)
    runs = out / "runs"
    runs.mkdir(exist_ok=args.resume)
    credentials = ROOT / "locust/data/creds_seed42.json"
    if not credentials.exists():
        subprocess.run([sys.executable, "locust/data/make_creds.py"], cwd=ROOT, check=True)
    benign = [f"agent3-benign-{i}" for i in range(1, 4)]
    attacks = {"credential_stuffing": "agent3-stuffing", "scraping": "agent3-scraping", "dow": "agent3-dow"}
    jobs = [(uid, "benign", 90, 41 + i) for i, uid in enumerate(benign)]
    jobs += [(uid, workload, 45, 51 + i) for i, (workload, uid) in enumerate(attacks.items())]
    for uid, workload, seconds, seed in jobs:
        manifest_path = runs / uid / "manifest.json"
        if manifest_path.is_file() and args.resume:
            existing = json.loads(manifest_path.read_text())
            if (existing.get("invalid") is False and existing.get("feature_version") == FEATURE_VERSION
                    and (runs / uid / "features.jsonl").is_file()):
                print(f"Preserving valid {uid}", flush=True)
                continue
            excluded = out / "excluded"
            excluded.mkdir(exist_ok=True)
            shutil.move(str(runs / uid), excluded / uid)
        command = [sys.executable, "eval/harness.py", "--python", sys.executable, "--runs", str(runs),
                   "--redis-url", args.redis_url, "run", "--config", "C1", "--workload", workload,
                   "--duration", f"{seconds}s", "--seed", str(seed), "--run-id", uid]
        print(f"Collecting {uid}", flush=True)
        with (out / f"{uid}.log").open("w") as log:
            subprocess.run(command, cwd=ROOT, check=True, stdout=log, stderr=subprocess.STDOUT)
        manifest = json.loads((runs / uid / "manifest.json").read_text())
        if manifest["invalid"] or manifest["feature_version"] != FEATURE_VERSION or not manifest["features"]["rows"]:
            raise ValueError(f"Invalid feature capture {uid}")
    labels, _ = collect(runs)
    labels_path = out / "labels.json"
    labels_path.write_text(json.dumps(labels, indent=2) + "\n")
    export(runs, labels_path, out / "features-csv")
    splits = {"benign_fit": benign[:1], "benign_calibration": benign[1:2],
              "test": benign[2:] + list(attacks.values())}
    splits_path = out / "splits.json"
    splits_path.write_text(json.dumps(splits, indent=2) + "\n")
    for name, ids in {"benign": benign[:2], "test": splits["test"]}.items():
        frames = [pd.read_csv(out / "features-csv" / (uid + ".csv")) for uid in sorted(ids)]
        pd.concat(frames, ignore_index=True).to_csv(out / f"{name}.csv", index=False)
    model = ROOT / "ml/model_base.joblib"
    train(out / "benign.csv", model, splits_path=splits_path)
    result = evaluate(model, out / "test.csv", splits_path=splits_path)
    (out / "evaluation.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
