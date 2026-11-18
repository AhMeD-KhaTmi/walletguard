import json

import pytest

from scripts.fit_agent_budgets import fit, select_policy
from scripts.summarize_budget_campaign import add_scenario_baseline_deltas


def test_budget_rule_covers_concurrent_tasks_and_refills_sustained_usage():
    # A known ledger is a unit fixture, not measured calibration evidence.
    result = select_policy([[(0, 18_000), (1000, 18_000), (60_001, 1000)]])
    assert result["capacity"] >= 36_000
    assert result["refill_per_s"] >= 36_000/60*1.25
    assert result["largest_account_60s_tokens"] == 36_000
    assert select_policy([[(0, 1)]])["capacity"] == 20_000
    with pytest.raises(ValueError):
        select_policy([])


@pytest.mark.parametrize("stage,config", [("validation", "C1"), ("calibration", "C2"), (None, "C1")])
def test_budget_fit_rejects_held_out_or_untagged_runs(tmp_path, stage, config):
    run = tmp_path / "not-calibration"
    run.mkdir()
    (run / "manifest.json").write_text(json.dumps({"campaign_stage": stage, "config": config,
                                                    "workload": "benign", "invalid": False,
                                                    "feature_version": 3}))
    with pytest.raises(ValueError, match="only valid fresh tagged"):
        fit(tmp_path)


def fixture_c1_runs(root):
    for seed in [101, 102, 103]:
        for scenario in ["normal", "varied"]:
            uid = f"fixture-{seed}-{scenario}"
            run = root / uid
            run.mkdir()
            (run / "manifest.json").write_text(json.dumps({"run_id": uid, "seed": seed,
                "benign_scenario": scenario, "campaign_stage": "calibration", "config": "C1",
                "workload": "benign", "invalid": False, "feature_version": 3}))
            (run / "features.jsonl").write_text(json.dumps({"request_id": uid, "task_token_budget": "1000"})+'\n')
            (run / "decisions.jsonl").write_text(json.dumps({"request_id": uid, "client_id": "user1",
                "llm_tokens_charged": "1000", "ts_ms": "1000"})+'\n')
            (run / "attempts-fixture.jsonl").write_text(json.dumps({"phase": "measured", "route": "/chat",
                "outcome": "success", "request_id": uid})+'\n')


def test_fit_joins_account_usage_without_combining_independent_runs(tmp_path):
    fixture_c1_runs(tmp_path)
    result = fit(tmp_path)
    assert result["candidate"]["measured_chat_tasks"] == 6
    assert result["candidate"]["largest_account_60s_tokens"] == 1000
    bad = tmp_path / "fixture-101-normal" / "features.jsonl"
    bad.write_text(json.dumps({"request_id": "fixture-101-normal", "task_token_budget": "1000.5"})+'\n')
    with pytest.raises(ValueError, match="positive integers"):
        fit(tmp_path)


def test_baseline_deltas_keep_benign_scenarios_separate_and_preserve_negative_values():
    rows = [{"scenario": scenario, "workload": "benign", "repetition": 1, "config": config,
             "latency_p50_ms": value, "latency_p95_ms": value}
            for scenario, config, value in [("normal", "C0", 10), ("normal", "C2", 9),
                                             ("varied", "C0", 100), ("varied", "C2", 120)]]
    add_scenario_baseline_deltas(rows)
    assert rows[1]["latency_delta_p95_ms"] == -1
    assert rows[3]["latency_delta_p95_ms"] == 20
