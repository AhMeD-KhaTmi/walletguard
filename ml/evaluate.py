"""Evaluate a base detector on labeled runs excluded from fitting/calibration."""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pandas as pd

from waf.scoring import Scorer


def classification_metrics(truth, predicted):
    tp, fp = int((truth & predicted).sum()), int((~truth & predicted).sum())
    fn, tn = int((truth & ~predicted).sum()), int((~truth & ~predicted).sum())
    return {
        "rows": len(truth), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
    }


def evaluate(model_path, csv_path, *, splits_path=None):
    scorer = Scorer(model_path)
    frame = pd.read_csv(csv_path)
    if frame.empty or not {"run_id", "label", "feature_version", *scorer.features} <= set(frame.columns):
        raise ValueError("test data needs feature columns, run_id and labels")
    if frame.isna().any().any() or not set(frame.label) <= {"benign", "attack"}:
        raise ValueError("test labels must be benign or attack, without missing data")
    if not (frame.feature_version == scorer.manifest["feature_version"]).all():
        raise ValueError("test feature version mismatch")
    used = set(scorer.manifest["training_runs"] + scorer.manifest["calibration_runs"])
    run_ids = set(frame.run_id.astype(str))
    if used & run_ids:
        raise ValueError("test run IDs overlap training/calibration data")
    if splits_path is not None:
        raw_splits = Path(splits_path).read_bytes()
        if hashlib.sha256(raw_splits).hexdigest() != scorer.manifest.get("splits_sha256"):
            raise ValueError("evaluation splits must match the model's training manifest")
        if set(json.loads(raw_splits)["test"]) != run_ids:
            raise ValueError("test CSV must contain exactly the declared held-out runs")
    scores, timings = [], []
    for row in frame[scorer.features].to_dict("records"):
        started = time.perf_counter()
        scores.append(scorer.score(row))
        timings.append((time.perf_counter()-started)*1000)
    truth = (frame.label == "attack").to_numpy()
    predicted = np.array(scores) < scorer.threshold
    return {
        "kind": "detector_evaluation_not_combined_waf_evaluation",
        **classification_metrics(truth, predicted),
        "by_run": {str(run): classification_metrics(truth[indices], predicted[indices])
                   for run, indices in frame.groupby("run_id").indices.items()},
        "scoring_p50_ms": float(np.percentile(timings, 50)),
        "scoring_p95_ms": float(np.percentile(timings, 95)),
        "model_sha256": hashlib.sha256(Path(model_path).read_bytes()).hexdigest(),
        "test_sha256": hashlib.sha256(Path(csv_path).read_bytes()).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--csv", required=True)
    parser.add_argument("--splits", help="Verify the held-out run IDs against the model's split file")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = evaluate(args.model, args.csv, splits_path=args.splits)
    Path(args.output).write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
