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
