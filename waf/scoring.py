"""Validated local model loader. Call scoring off the ASGI event loop."""

import math
from pathlib import Path

import joblib
import numpy as np
import sklearn

from waf.features import FEATURE_VERSION, FEATURES_BASE
from common.agent import AGENT_VERSION
from common.tokens import TOKENIZER_VERSION
from ml.volume import VOLUME_FEATURES, score_volume, intensity


class Scorer:
    def __init__(self, path):
        if not Path(path).is_file():
            raise ValueError(f"requested ML model is missing: {path}")
        data = joblib.load(path)  # Only load trusted, locally generated model artifacts.
        if data.get("feature_version") != FEATURE_VERSION or data.get("features") != FEATURES_BASE:
            raise ValueError("model feature manifest is incompatible with this application")
        if data.get("agent_version") != AGENT_VERSION or data.get("tokenizer") != TOKENIZER_VERSION:
            raise ValueError("model agent/tokenizer manifest is incompatible with this application")
        if data.get("sklearn_version") != sklearn.__version__:
            raise ValueError("model sklearn version mismatch; retrain in this environment")
        self.model = data["model"]
        self.features = data["features"]
        self.transform = data.get("model_transform", "identity")
        self.model_features = data.get("model_features", self.features)
        if (not isinstance(self.model_features, list) or not self.model_features
                or any(not isinstance(f, str) for f in self.model_features)
                or len(set(self.model_features)) != len(self.model_features)
                or not set(self.model_features) <= set(self.features)
                or getattr(self.model, "n_features_in_", None) !=
                   (1 if self.transform == "volume-v1" else len(self.model_features))):
            raise ValueError("model input selection is incompatible")
        if self.transform not in {"identity", "log1p", "volume-v1"}:
            raise ValueError("unsupported model transformation")
        self.volume_parameters = data.get("volume_parameters")
        if self.transform == "volume-v1":
            if self.model_features != VOLUME_FEATURES or not isinstance(self.volume_parameters, dict):
                raise ValueError("invalid volume manifest")
            try:
                score_volume(self.model, np.zeros((1, 3)), self.volume_parameters)
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("invalid volume manifest") from exc
        self.threshold = float(data["threshold"])
        self.manifest = {k: v for k, v in data.items() if k != "model"}
        if not math.isfinite(self.threshold):
            raise ValueError("invalid anomaly threshold")

    def score(self, features):
        return float(self.score_many([features])[0])

    def score_many(self, rows):
        if not rows:
            return np.empty(0, dtype=float)
        x = np.array([[row[f] for f in self.model_features] for row in rows], dtype=float)
        if not np.isfinite(x).all():
            raise ValueError("nonfinite model input")
        if self.transform == "log1p":
            if (x < 0).any():
                raise ValueError("negative model input for log1p")
            x = np.log1p(x)
        scores = (score_volume(self.model, x, self.volume_parameters) if self.transform == "volume-v1"
                  else self.model.score_samples(x))
        if not np.isfinite(scores).all():
            raise ValueError("nonfinite model scores")
        return scores

    def is_anomalous(self, score):
        return score < self.threshold
