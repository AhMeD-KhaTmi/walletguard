import json

import pandas as pd

from scripts.collect_model_test import expected_runs, export_test


def test_model_test_seeds_are_disjoint_from_training_and_budget_validation():
    jobs = expected_runs()
    seeds = {job[3] for job in jobs}
    assert not seeds & {101, 102, 103, 201, 202, 203}
    assert len({job[0] for job in jobs}) == len(jobs)


def test_test_export_keeps_benign_setup_and_excludes_attacker_setup(tmp_path):
    for uid, scenario, workload, seed, rep, users, seconds in expected_runs():
        p = tmp_path / "runs" / uid
        p.mkdir(parents=True)
        ip = "10.20.0.11" if workload == "benign" else "10.20.0.21"
        (p / "manifest.json").write_text(json.dumps({"run_id": uid, "seed": seed,
            "workload": workload, "identities": [{"ip": ip}], "invalid": False,
            "config": "C1", "campaign_stage": "validation", "features": {"rows": 2}}))
        features, attempts = [], []
        for phase in ["setup", "measured"]:
            rid = uid+'-'+phase
            features.append({"request_id": rid, "run_id": uid, "ip": ip, "feature_version": 3})
            attempts.append({"request_id": rid, "run_id": uid, "ip": ip, "phase": phase})
        (p / "features.jsonl").write_text(''.join(json.dumps(r)+'\n' for r in features))
        (p / "attempts-fixture.jsonl").write_text(''.join(json.dumps(r)+'\n' for r in attempts))
    export_test(tmp_path)
    frame = pd.read_csv(tmp_path / "test.csv")
    assert len(frame[frame.label == "benign"]) == 12
    attack = frame[frame.label == "attack"]
    assert len(attack) == 3
    assert all(rid.endswith('-measured') for rid in attack.request_id)
