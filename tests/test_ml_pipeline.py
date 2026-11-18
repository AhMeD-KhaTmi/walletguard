import json
import joblib

import httpx
import numpy as np
import pandas as pd
import pytest

from app.main import create_app
from app.settings import Settings
from conftest import TEST_REDIS_URL
from ml.evaluate import evaluate
from ml.train import train
from waf.config import Config
from waf.features import FEATURE_VERSION, FEATURES_BASE
from waf.scoring import Scorer


def fixture_data(groups, *, attack=False):
    # Synthetic unit fixture, never presented as real training/attack evidence.
    rng = np.random.default_rng(42)
    rows = []
    for group in groups:
        for _ in range(25):
            values = dict(zip(FEATURES_BASE, rng.uniform(0, 10, len(FEATURES_BASE))))
            if attack:
                values = {k: v+10000 for k, v in values.items()}
            rows.append({**values, "run_id": group, "feature_version": FEATURE_VERSION, "label": "attack" if attack else "benign"})
    return pd.DataFrame(rows)


def test_grouped_training_evaluation_and_reproducibility(tmp_path):
    csv = tmp_path/"benign.csv"
    fixture_data(["train-a", "train-b", "train-c"]).to_csv(csv, index=False)
    one, two = tmp_path/"one.joblib", tmp_path/"two.joblib"
    first, second = train(csv, one, trees=10), train(csv, two, trees=10)
    assert first == second
    assert not set(first["training_runs"]) & set(first["calibration_runs"])
    row = fixture_data(["test-a"]).iloc[0].to_dict()
    assert Scorer(one).score(row) == Scorer(two).score(row)
    test = tmp_path/"test.csv"
    pd.concat([fixture_data(["test-a"]), fixture_data(["test-b"], attack=True)]).to_csv(test, index=False)
    metrics = evaluate(one, test)
    assert metrics["tp"]+metrics["fn"] == 25
    assert metrics["fp"]+metrics["tn"] == 25
    assert metrics["recall"] == metrics["tp"]/25
    assert metrics["false_positive_rate"] == metrics["fp"]/25
    assert metrics["scoring_p50_ms"] >= 0
    with pytest.raises(ValueError, match="overlap"):
        evaluate(one, csv)


def test_training_rejects_unlabeled_mixed_or_single_run_data(tmp_path):
    csv = tmp_path/"bad.csv"
    fixture_data(["only-one"]).to_csv(csv, index=False)
    with pytest.raises(ValueError, match="independent"):
        train(csv, tmp_path/"model.joblib")
    fixture_data(["a", "b"], attack=True).to_csv(csv, index=False)
    with pytest.raises(ValueError, match="benign-only"):
        train(csv, tmp_path/"model.joblib")


@pytest.mark.parametrize("profile,count", [("behavior", 7), ("rate", 3)])
def test_behavior_inputs_transform_and_vectorized_legacy_compatibility(tmp_path, profile, count):
    csv, model = tmp_path / "benign.csv", tmp_path / "behavior.joblib"
    data = fixture_data(["a", "b", "c"])
    data.to_csv(csv, index=False)
    train(csv, model, trees=10, feature_set=profile)
    scorer = Scorer(model)
    rows = fixture_data(["new"]).to_dict("records")
    assert scorer.transform == "log1p" and len(scorer.model_features) == count
    assert np.allclose(scorer.score_many(rows), [scorer.score(r) for r in rows], rtol=0, atol=1e-15)
    bad = {**rows[0], "req_10s": -1}
    with pytest.raises(ValueError, match="negative"):
        scorer.score(bad)
    legacy = tmp_path / "legacy.joblib"
    train(csv, legacy, trees=10)
    artifact = joblib.load(legacy)
    artifact.pop("model_features")
    artifact.pop("model_transform")
    joblib.dump(artifact, legacy)
    old = Scorer(legacy)
    x = np.array([[r[f] for f in FEATURES_BASE] for r in rows])
    assert np.array_equal(old.score_many(rows), old.model.score_samples(x))
    artifact["model_features"] = ["req_10s", "req_10s"]
    joblib.dump(artifact, legacy)
    with pytest.raises(ValueError, match="input selection"):
        Scorer(legacy)


def test_model_from_the_previous_feature_version_is_rejected(tmp_path):
    csv, model = tmp_path / "benign.csv", tmp_path / "model.joblib"
    fixture_data(["a", "b"]).to_csv(csv, index=False)
    train(csv, model, trees=10)
    data = joblib.load(model)
    data["feature_version"] = 2
    joblib.dump(data, model)
    with pytest.raises(ValueError, match="incompatible"):
        Scorer(model)


def test_declared_handoff_splits_and_per_run_metrics(tmp_path):
    csv, test = tmp_path / "benign.csv", tmp_path / "test.csv"
    splits, model = tmp_path / "splits.json", tmp_path / "model.joblib"
    fixture_data(["fit", "cal"]).to_csv(csv, index=False)
    groups = {"benign_fit": ["fit"], "benign_calibration": ["cal"], "test": ["benign", "attack"]}
    splits.write_text(json.dumps(groups))
    manifest = train(csv, model, trees=10, splits_path=splits)
    assert manifest["training_runs"] == ["fit"]
    assert manifest["calibration_runs"] == ["cal"]
    assert set(manifest["feature_units"]) == set(FEATURES_BASE)
    fixture_data(["benign"]).to_csv(test, index=False)
    with pytest.raises(ValueError, match="declared held-out"):
        evaluate(model, test, splits_path=splits)
    pd.concat([fixture_data(["benign"]), fixture_data(["attack"], attack=True)]).to_csv(test, index=False)
    result = evaluate(model, test, splits_path=splits)
    assert result["by_run"]["attack"]["tp"] == result["tp"]
    assert result["by_run"]["benign"]["false_positive_rate"] == result["false_positive_rate"]
    groups["test"].append("fit")
    splits.write_text(json.dumps(groups))
    with pytest.raises(ValueError, match="disjoint"):
        train(csv, model, trees=10, splits_path=splits)
    with pytest.raises(ValueError, match="training manifest"):
        evaluate(model, test, splits_path=splits)


async def test_real_model_can_load_in_application(tmp_path, redis_db, llm_url):
    data = tmp_path/"benign.csv"
    model = tmp_path/"model.joblib"
    fixture_data(["fixture-a", "fixture-b"]).to_csv(data, index=False)
    train(data, model, trees=10)
    policy = Config(mode="enforce", redis_url=TEST_REDIS_URL, enable_ml=True, model_path=str(model))
    app = create_app(Settings(redis_url=TEST_REDIS_URL, llm_base_url=llm_url, waf_mode="enforce"), policy)
    async with app.router.lifespan_context(app), httpx.AsyncClient(base_url="http://target", transport=httpx.ASGITransport(app=app, client=("10.20.0.21", 1234))) as c:
        assert (await c.get("/products")).status_code == 200
    row = redis_db.xrevrange("p20:stream:waf_decisions", count=1)[0][1]
    assert row["anomaly_score"] != ""
    assert app.state.runtime.timings[-1]["scoring_ms"] > 0


async def test_anomaly_alone_allows_but_corroboration_bans_and_refunds(redis_db, llm_url):
    class Anomalous:
        def score(self, features):
            return -1
        def is_anomalous(self, score):
            return True

    policy = Config(mode="enforce", redis_url=TEST_REDIS_URL)
    app = create_app(Settings(redis_url=TEST_REDIS_URL, llm_base_url=llm_url, waf_mode="enforce"), policy)
    app.state.runtime.scorer = Anomalous()  # Unit-controlled scorer, not a trained production model.
    async with app.router.lifespan_context(app), httpx.AsyncClient(base_url="http://target", transport=httpx.ASGITransport(app=app, client=("10.20.0.21", 1234))) as c:
        for _ in range(6):
            assert (await c.get("/products")).status_code == 200
        assert not redis_db.exists("p20:ban:10.20.0.21")
        login = await c.post("/login", json={"username": "user1", "password": "Passw0rd!1"})
        token = login.json()["token"]
        await app.state.runtime.waf.bans.strike("10.20.0.21", "budget")
        result = await c.post("/chat", json={"prompt": "hi", "agent_steps": 1, "max_output_tokens": 8}, headers={"authorization": f"Bearer {token}"})
        assert result.status_code == 403
    row = redis_db.xrevrange("p20:stream:waf_decisions", count=1)[0][1]
    assert row["reason"] == "anomaly"
    assert float(row["tokens_reserved"]) == float(row["tokens_refunded"]) == 9
    assert row["llm_tokens_charged"] == "0"
    assert not redis_db.exists("p20:app:usage:total")
