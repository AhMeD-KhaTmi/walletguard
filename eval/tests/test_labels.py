import json

import pytest

from eval import labels


def write_run(tmp_path, run_id, workload, identities, attempts):
    run = tmp_path / run_id
    run.mkdir()
    (run / "manifest.json").write_text(json.dumps({
        "schema": "p20-run-manifest", "schema_version": 1,
        "run_id": run_id, "config": "C2", "workload": workload,
        "identities": identities,
    }), encoding="utf-8")
    with (run / "attempts-x.jsonl").open("w", encoding="utf-8") as handle:
        for ip in attempts:
            handle.write(json.dumps({"ip": ip}) + "\n")
    return run


def test_mixed_run_labels_each_identity_by_its_role(tmp_path):
    write_run(tmp_path, "mixed-r1", "mixed",
              [{"ns": "ns1", "ip": "10.20.0.11", "role": "benign"},
               {"ns": "ns9", "ip": "10.20.0.19", "role": "scraping"}],
              ["10.20.0.11", "10.20.0.19"])
    result, workloads = labels.collect(tmp_path)
    assert result["mixed-r1"] == {"10.20.0.11": "benign", "10.20.0.19": "attack"}
    assert workloads["mixed-r1"] == "mixed"


def test_attack_only_runs_are_labelled_attack(tmp_path):
    write_run(tmp_path, "combined-r1", "combined",
              [{"ns": "ns6", "ip": "10.20.0.16", "role": "credential_stuffing"}],
              ["10.20.0.16"])
    result, _ = labels.collect(tmp_path)
    assert result["combined-r1"] == {"10.20.0.16": "attack"}


def test_traffic_from_an_undeclared_address_is_refused(tmp_path):
    write_run(tmp_path, "benign-r1", "benign",
              [{"ns": "ns1", "ip": "10.20.0.11", "role": "benign"}],
              ["10.20.0.99"])
    with pytest.raises(ValueError, match="undeclared"):
        labels.collect(tmp_path)


def test_splits_need_three_benign_runs_and_keep_attacks_in_test():
    workloads = {"b1": "benign", "b2": "benign", "b3": "benign", "a1": "scraping"}
    splits = labels.suggest_splits(workloads)
    assert splits["status"] == "ok"
    assert splits["benign_fit"] == ["b1"]
    assert splits["benign_calibration"] == ["b2"]
    assert splits["test"] == ["b3", "a1"]


def test_churn_is_a_probe_not_an_attack(tmp_path):
    # Connection churn exercises the kernel sensor (MASTER_PLAN 3.4/IT-2); it has no
    # ASR objective, so it must not become an attack training class.
    write_run(tmp_path, "churn-r1", "churn",
              [{"ns": "ns15", "ip": "10.20.0.25", "role": "churn"}],
              ["10.20.0.25"])
    result, workloads = labels.collect(tmp_path)
    assert result["churn-r1"] == {"10.20.0.25": "probe"}
    assert workloads["churn-r1"] == "churn"


def test_splits_use_only_feature_producing_runs_and_keep_probes_out():
    workloads = {
        "c0-benign-r1": "benign",          # C0 writes no waf_features
        "c1-benign-r1": "benign", "c1-benign-r2": "benign", "c1-benign-r3": "benign",
        "churn-r1": "churn",
        "a1": "scraping",
    }
    configs = {"c0-benign-r1": "C0", "c1-benign-r1": "C1", "c1-benign-r2": "C1",
               "c1-benign-r3": "C1", "churn-r1": "C2", "a1": "C2"}
    splits = labels.suggest_splits(workloads, configs)
    assert splits["benign_fit"] == ["c1-benign-r1"]
    assert splits["benign_calibration"] == ["c1-benign-r2"]
    assert splits["test"] == ["c1-benign-r3", "a1"]
    assert splits["probe_runs"] == ["churn-r1"]
    # The attack runs exist, but none of them produced features.
    assert splits["attack_features"] == "unavailable"


def test_splits_exclude_c1_runs_without_an_archived_export():
    """A C1 run recorded before the feature archive existed must not train a model."""
    workloads = {
        "c1-benign-r1": "benign",          # old run, features deleted by the reset
        "c1-benign-f1": "benign", "c1-benign-f2": "benign", "c1-benign-f3": "benign",
        "c1-scraping-f1": "scraping", "c2-scraping-r1": "scraping",
    }
    configs = {run_id: ("C1" if "-f" in run_id or run_id == "c1-benign-r1" else "C2")
               for run_id in workloads}
    features = {"c1-benign-f1", "c1-benign-f2", "c1-benign-f3", "c1-scraping-f1"}
    splits = labels.suggest_splits(workloads, configs, features)
    assert splits["status"] == "ok"
    assert splits["benign_fit"] == ["c1-benign-f1"]
    assert splits["benign_calibration"] == ["c1-benign-f2"]
    assert splits["test"] == ["c1-benign-f3", "c1-scraping-f1"]
    assert splits["attack_features"] == ["c1-scraping-f1"]
    # The inventory still lists every attack run; only the split groups are filtered.
    assert splits["attack_runs"] == ["c1-scraping-f1", "c2-scraping-r1"]
    assert "c1-benign-r1" not in splits["benign_fit"]


def test_splits_without_enough_archived_benign_exports_are_insufficient():
    workloads = {"c1-benign-f1": "benign", "c1-benign-f2": "benign"}
    configs = {run_id: "C1" for run_id in workloads}
    splits = labels.suggest_splits(workloads, configs, set(workloads))
    assert splits["status"] == "insufficient_benign_runs"
    assert splits["benign_runs"] == ["c1-benign-f1", "c1-benign-f2"]


def test_feature_runs_requires_a_non_empty_archived_file(tmp_path):
    def make(run_id, *, rows=3, file="features.jsonl", write=True, info=True):
        run = tmp_path / run_id
        run.mkdir()
        manifest = {"run_id": run_id, "config": "C1", "workload": "benign"}
        if info:
            manifest["features"] = {"status": "ok", "rows": rows, "file": file}
        (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        if write and file:
            (run / file).write_text('{"ip": "10.20.0.11"}\n', encoding="utf-8")

    make("good")
    make("empty", rows=0)
    make("missing-file", write=False)
    make("not-applicable", rows=None, file=None, write=False)
    make("pre-archive", info=False)
    assert labels.feature_runs(tmp_path) == {"good"}
