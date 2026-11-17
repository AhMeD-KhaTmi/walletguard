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
