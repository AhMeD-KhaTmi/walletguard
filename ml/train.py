"""Train on benign run groups; calibrate on separate benign run groups."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest

from waf.features import FEATURE_VERSION, FEATURES_BASE
from common.agent import AGENT_VERSION
from common.tokens import TOKENIZER_VERSION

FEATURE_UNITS = {
    "is_chat": "indicator", "is_login": "indicator", "is_products": "indicator",
    "is_other": "indicator", "body_size": "bytes", "prompt_tokens": "tokens",
    "max_out_tokens": "tokens", "prompt_entropy": "bits per character",
    "has_ua": "indicator", "has_accept_lang": "indicator", "req_10s": "requests",
    "req_60s": "requests", "distinct_paths_60s": "paths", "fail_ratio_60s": "fraction",
    "mean_gap_s": "seconds", "std_gap_s": "seconds", "window_saturated": "indicator",
    "agent_steps": "iterations", "task_token_budget": "tokens",
}
BEHAVIOR_FEATURES = ["req_10s", "req_60s", "fail_ratio_60s", "mean_gap_s",
                     "std_gap_s", "max_out_tokens", "task_token_budget"]
RATE_FEATURES = ["req_10s", "req_60s", "max_out_tokens"]


def split_groups(groups, seed, splits_path):
    if splits_path is None:
        np.random.default_rng(seed).shuffle(groups)
        n_cal = max(1, math.ceil(len(groups) * .2))
        return groups[n_cal:], groups[:n_cal]

    splits = json.loads(Path(splits_path).read_text())
    fit, cal, test = (splits.get(key) for key in ("benign_fit", "benign_calibration", "test"))
    if any(not isinstance(part, list) or not part or
           any(not isinstance(run, str) or not run for run in part) for part in (fit, cal, test)):
        raise ValueError("splits need nonempty run-ID lists for fitting, calibration and test")
    if len(set(fit + cal + test)) != len(fit + cal + test):
        raise ValueError("fit, calibration and test run IDs must be disjoint and unique")
    if set(fit + cal) != set(groups):
        raise ValueError("training CSV must contain exactly the declared fit and calibration runs")
    return fit, cal


def code_revision():
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1],
            check=True, capture_output=True, text=True, timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def train(csv_path, output, *, seed=42, trees=100, splits_path=None, feature_set="base",
          calibration_percentile=.5):
    if feature_set not in {"base", "behavior", "rate"}:
        raise ValueError("unknown model feature set")
    if not math.isfinite(calibration_percentile) or not 0 < calibration_percentile <= 10:
        raise ValueError("calibration percentile must be in (0, 10]")
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
    train_groups, cal_groups = split_groups(groups, seed, splits_path)
    model_features = {"base": FEATURES_BASE, "behavior": BEHAVIOR_FEATURES,
                      "rate": RATE_FEATURES}[feature_set]
    x = frame[model_features].to_numpy(dtype=float)
    if not np.isfinite(x).all():
        raise ValueError("features must be finite")
    if feature_set != "base":
        if (x < 0).any():
            raise ValueError("behavior model inputs must be nonnegative")
        x = np.log1p(x)
    is_cal = frame.run_id.astype(str).isin(cal_groups).to_numpy()
    model = IsolationForest(n_estimators=trees, random_state=seed, contamination="auto", n_jobs=1)
    model.fit(x[~is_cal])
    threshold = float(np.percentile(model.score_samples(x[is_cal]), calibration_percentile))
    artifact = {
        "model": model, "features": FEATURES_BASE, "feature_version": FEATURE_VERSION,
        "model_features": list(model_features), "feature_set": feature_set,
        "model_transform": "log1p" if feature_set != "base" else "identity",
        "agent_version": AGENT_VERSION, "tokenizer": TOKENIZER_VERSION,
        "feature_units": FEATURE_UNITS, "sklearn_version": sklearn.__version__,
        "dependencies": {"python": platform.python_version(), "numpy": np.__version__,
                         "pandas": pd.__version__, "scikit-learn": sklearn.__version__,
                         "joblib": joblib.__version__},
        "code_revision": code_revision(),
        "trainer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "threshold": threshold, "calibration_percentile": calibration_percentile,
        "seed": seed, "trees": trees, "dataset_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "training_runs": train_groups, "calibration_runs": cal_groups,
        "training_rows": int((~is_cal).sum()), "calibration_rows": int(is_cal.sum()),
    }
    if splits_path is not None:
        artifact["splits_sha256"] = hashlib.sha256(Path(splits_path).read_bytes()).hexdigest()
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
    parser.add_argument("--splits", help="JSON declaring benign_fit, benign_calibration and test run IDs")
    parser.add_argument("--output", default="ml/model_base.joblib")
    parser.add_argument("--features", choices=["base", "behavior", "rate"], default="base")
    parser.add_argument("--calibration-percentile", type=float, default=.5)
    args = parser.parse_args()
    if args.set == "ebpf":
        parser.error("augmented training awaits real sensor data and integration")
    print(json.dumps(train(args.csv, args.output, splits_path=args.splits,
                           feature_set=args.features,
                           calibration_percentile=args.calibration_percentile), indent=2))


if __name__ == "__main__":
    main()
