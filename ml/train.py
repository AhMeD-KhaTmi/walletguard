"""Train on benign run groups; calibrate on separate benign run groups."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest

from waf.features import FEATURE_VERSION, FEATURES_BASE


def train(csv_path, output, *, seed=42, trees=100):
    path = Path(csv_path)
    frame = pd.read_csv(path)
    required = set(FEATURES_BASE) | {"run_id", "label", "feature_version"}
    if not required <= set(frame.columns) or frame.empty:
        raise ValueError("training data needs features, run_id and benign labels")
    if frame.isna().any().any() or set(frame.label) != {"benign"}:
        raise ValueError("training input must contain complete, benign-only rows")
    if not (frame.feature_version == FEATURE_VERSION).all():
        raise ValueError("training feature version mismatch")
    groups = sorted(frame.run_id.astype(str).unique())
    if len(groups) < 2:
        raise ValueError("at least two independent benign run groups are required")
    np.random.default_rng(seed).shuffle(groups)
    n_cal = max(1, math.ceil(len(groups)*.2))
    cal_groups, train_groups = groups[:n_cal], groups[n_cal:]
    x = frame[FEATURES_BASE].to_numpy(dtype=float)
    if not np.isfinite(x).all():
        raise ValueError("features must be finite")
    is_cal = frame.run_id.astype(str).isin(cal_groups).to_numpy()
    model = IsolationForest(n_estimators=trees, random_state=seed, contamination="auto", n_jobs=1)
    model.fit(x[~is_cal])
    threshold = float(np.percentile(model.score_samples(x[is_cal]), .5))
    artifact = {
        "model": model, "features": FEATURES_BASE, "feature_version": FEATURE_VERSION,
        "sklearn_version": sklearn.__version__, "threshold": threshold,
        "seed": seed, "trees": trees, "dataset_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "training_runs": train_groups, "calibration_runs": cal_groups,
        "training_rows": int((~is_cal).sum()), "calibration_rows": int(is_cal.sum()),
    }
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, output)
    manifest = {k: v for k, v in artifact.items() if k != "model"}
    output.with_suffix(".json").write_text(json.dumps(manifest, indent=2)+"\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--set", choices=["base", "ebpf"], default="base")
    parser.add_argument("--csv", required=True)
    parser.add_argument("--output", default="ml/model_base.joblib")
    args = parser.parse_args()
    if args.set == "ebpf":
        parser.error("augmented training awaits real sensor data and integration")
    print(json.dumps(train(args.csv, args.output), indent=2))


if __name__ == "__main__":
    main()
