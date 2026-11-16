import json

from eval import compute_metrics


def make_run(tmp_path, workload, attempts, *, decisions=None, config="C2",
             readiness="ok", repetition=1):
    run = tmp_path / f"{workload}-{config.lower()}-r{repetition}"
    run.mkdir()
    (run / "manifest.json").write_text(json.dumps({
        "schema": "p20-run-manifest", "schema_version": 1,
        "run_id": run.name, "config": config, "workload": workload,
        "attack": None if workload == "benign" else workload,
        "repetition": repetition, "seed": 42, "duration_s": 40.0, "readiness": readiness,
    }), encoding="utf-8")
    with (run / "attempts-test-10.20.0.19-1.jsonl").open("w", encoding="utf-8") as handle:
        for attempt in attempts:
            handle.write(json.dumps(attempt) + "\n")
    if decisions is not None:
        with (run / "decisions.jsonl").open("w", encoding="utf-8") as handle:
            for entry in decisions:
                handle.write(json.dumps(entry) + "\n")
    return run


def attempt(**overrides):
    base = {"phase": "measured", "objective": True, "outcome": "success", "latency_ms": 10.0,
            "started_ms": 1_000, "ended_ms": 1_010, "ip": "10.20.0.19", "status": 200,
            "request_id": None, "client_id": None}
    base.update(overrides)
    return base


def test_scraping_asr_and_unique_products(tmp_path):
    run = make_run(tmp_path, "scraping", [
        attempt(product_ids=[1, 2, 3]),
        attempt(product_ids=[2, 3, 4]),
        attempt(outcome="blocked", status=429, product_ids=[]),
        attempt(outcome="unknown", status=None),
    ])
    row = compute_metrics.summarise(run)
    assert row["malicious_attempts"] == 4
    assert row["attack_success"] == 2
    assert row["unknown_outcomes"] == 1
    assert row["asr"] == 0.5
    assert row["unique_objectives"] == 4
    assert row["run_valid"] == "true"


def test_detection_uses_request_ids_and_reports_coverage(tmp_path):
    run = make_run(tmp_path, "scraping", [
        attempt(request_id="a"), attempt(request_id="b"), attempt(request_id="c"),
    ], decisions=[
        {"request_id": "a", "decision": "throttle"},
        {"request_id": "b", "decision": "allow"},
        {"request_id": "", "decision": "ban"},
    ])
    row = compute_metrics.summarise(run)
    assert row["detected_malicious_requests"] == 1
    assert row["observation_coverage"] == 0.6667
    assert row["detection_rate"] == 0.3333


def test_missing_decision_stream_is_unavailable_not_zero(tmp_path):
    run = make_run(tmp_path, "scraping", [attempt(request_id="a")])
    row = compute_metrics.summarise(run)
    assert row["detected_malicious_requests"] == ""
    assert row["detection_rate"] == ""
    assert "detected_malicious_requests" in row["unavailable_fields"]


def test_shadow_decisions_are_detection_but_denials_are_separate(tmp_path):
    run = make_run(tmp_path, "credential_stuffing", [
        attempt(outcome="blocked", status=429, client_id="user5"),
        attempt(outcome="fail", status=401, client_id="user6"),
    ], decisions=[
        {"request_id": None, "decision": "would_throttle"},
    ], config="C1")
    row = compute_metrics.summarise(run)
    assert row["attack_success"] == 0
    assert row["asr"] == 0.0
    assert row["benign_policy_denials"] == ""  # not a labeled benign run


def test_benign_fpr_uses_labeled_addresses_only(tmp_path):
    run = make_run(tmp_path, "benign", [
        attempt(objective=False, outcome="success"),
        attempt(objective=False, outcome="success"),
        attempt(objective=False, outcome="blocked", status=429),
        attempt(objective=False, outcome="timeout", status=None),
    ], decisions=[{"request_id": "x", "decision": "allow"}])
    labels = {run.name: {"10.20.0.19": "benign"}}
    row = compute_metrics.summarise(run, labels)
    assert row["benign_attempts"] == 4
    assert row["benign_policy_denials"] == 1
    assert row["false_positive_rate"] == 0.25
    assert row["benign_timeouts"] == 1


def test_honeypot_time_to_ban_is_client_observed(tmp_path):
    run = make_run(tmp_path, "honeypot", [
        attempt(intent="decoy_hit", started_ms=1_000, status=404),
        attempt(intent="ban_check", objective=False, started_ms=4_500, status=403),
        attempt(intent="decoy_hit", started_ms=6_000, status=403),
    ])
    row = compute_metrics.summarise(run)
    assert row["time_to_ban_ms"] == 3_500


def test_failed_readiness_invalidates_the_run(tmp_path):
    run = make_run(tmp_path, "dow", [attempt()], readiness="failed")
    row = compute_metrics.summarise(run)
    assert row["run_valid"] == "false"


def test_percentiles_ignore_blocked_and_failed_attempts(tmp_path):
    run = make_run(tmp_path, "scraping", [
        attempt(latency_ms=10.0), attempt(latency_ms=20.0), attempt(latency_ms=30.0),
        attempt(outcome="blocked", status=429, latency_ms=1.0),
    ])
    row = compute_metrics.summarise(run)
    assert row["latency_p50_ms"] == 20.0
    assert row["latency_p95_ms"] == 29.0


def test_run_with_no_attempts_is_never_valid(tmp_path):
    run = make_run(tmp_path, "benign", [])
    row = compute_metrics.summarise(run)
    assert row["measured_attempts"] == 0
    assert row["run_valid"] == "false"


def test_probe_workloads_report_measured_attempts(tmp_path):
    run = make_run(tmp_path, "churn", [
        attempt(intent="churn_tcp", status=None),
        attempt(intent="churn_http"),
    ])
    row = compute_metrics.summarise(run)
    assert row["measured_attempts"] == 2
    assert row["run_valid"] == "true"
