"""Validated local model loader. Call scoring off the ASGI event loop."""

import math
from pathlib import Path

import joblib
import numpy as np
import sklearn

from waf.features import FEATURE_VERSION, FEATURES_BASE


class Scorer:
    def __init__(self, path):
        if not Path(path).is_file():
            raise ValueError(f"requested ML model is missing: {path}")
        data = joblib.load(path)  # Only load trusted, locally generated model artifacts.
        if data.get("feature_version") != FEATURE_VERSION or data.get("features") != FEATURES_BASE:
            raise ValueError("model feature manifest is incompatible with this application")
        if data.get("sklearn_version") != sklearn.__version__:
            raise ValueError("model sklearn version mismatch; retrain in this environment")
        self.model = data["model"]
        self.features = data["features"]
        self.threshold = float(data["threshold"])
        self.manifest = {k: v for k, v in data.items() if k != "model"}
        if not math.isfinite(self.threshold):
            raise ValueError("invalid anomaly threshold")

    def score(self, features):
        x = np.array([[features[f] for f in self.features]], dtype=float)
        if not np.isfinite(x).all():
            raise ValueError("nonfinite model input")
        return float(self.model.score_samples(x)[0])

    def is_anomalous(self, score):
        return score < self.threshold
