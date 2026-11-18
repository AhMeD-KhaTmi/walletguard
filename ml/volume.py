"""Benign-fitted scalar volume representation for a directional IsolationForest."""

import numpy as np

VOLUME_FEATURES = ["req_10s", "req_60s", "task_token_budget"]


def intensity(x, scales):
    scales = np.asarray(scales, dtype=float)
    if scales.shape != (3,) or not np.isfinite(scales).all() or (scales < 1).any():
        raise ValueError("invalid volume scales")
    if x.ndim != 2 or x.shape[1] != 3 or not np.isfinite(x).all() or (x < 0).any():
        raise ValueError("invalid volume inputs")
    return (x/scales).max(axis=1)


def fit_representation(x):
    scales = np.maximum(1, np.percentile(x, 95, axis=0))
    return {"scales": scales.tolist(), "gate": float(np.median(intensity(x, scales)))}


def score_volume(model, x, params):
    gate = params["gate"]
    if not isinstance(gate, (int, float)) or not np.isfinite(gate) or gate < 0:
        raise ValueError("invalid volume gate")
    values = intensity(x, params["scales"])
    scores = model.score_samples(np.log1p(values).reshape(-1, 1))
    return np.where(values < gate, 0.0, scores)
