"""The manifest must repeat the seed the run actually used, not an environment default."""

from eval import manifest


def build(tmp_path, **overrides):
    kwargs = dict(
        run_id="seed-test", config="C2", workload="benign", attack=None, repetition=1,
        repo_root=tmp_path, target="http://10.20.0.1:8000", flags={"WAF_MODE": "enforce"},
        identities=[], accounts={}, duration_s=1.0, users=1, spawn_rate=1.0,
        client_timeout_s=3.0, datasets=[],
    )
    kwargs.update(overrides)
    return manifest.build(**kwargs)


def test_explicit_seed_wins_over_the_environment(tmp_path, monkeypatch):
    # The harness exports P20_SEED only into the child workload processes, so reading
    # it here used to stamp 42 on a run started with `--seed 7`.
    monkeypatch.setenv("P20_SEED", "42")
    assert build(tmp_path, seed=7)["seed"] == 7


def test_environment_seed_is_still_used_by_older_callers(tmp_path, monkeypatch):
    monkeypatch.setenv("P20_SEED", "13")
    assert build(tmp_path)["seed"] == 13
