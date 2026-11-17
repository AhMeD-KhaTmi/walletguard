import json

from eval import compute_metrics


def make_run(tmp_path, workload, attempts, *, decisions=None, config="C2",
             readiness="ok", repetition=1, bans=None, extra=None):
    run = tmp_path / f"{workload}-{config.lower()}-r{repetition}"
    run.mkdir()
    manifest = {
        "schema": "p20-run-manifest", "schema_version": 1,
        "run_id": run.name, "config": config, "workload": workload,
        "attack": None if workload == "benign" else workload,
        "repetition": repetition, "seed": 42, "duration_s": 40.0, "readiness": readiness,
    }
    manifest.update(extra or {})
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with (run / "attempts-test-10.20.0.19-1.jsonl").open("w", encoding="utf-8") as handle:
        for attempt in attempts:
            handle.write(json.dumps(attempt) + "\n")
    if decisions is not None:
        with (run / "decisions.jsonl").open("w", encoding="utf-8") as handle:
            for entry in decisions:
                handle.write(json.dumps(entry) + "\n")
    if bans is not None:
        (run / "bans.json").write_text(json.dumps(bans), encoding="utf-8")
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
    # `ban_check` rows carry phase="followup" in the real workload
    # (locust/attack_honeypot.py); if the fixture pretends they are "measured", the
    # metric can pass here and still be unavailable on every real run.
    run = make_run(tmp_path, "honeypot", [
        attempt(intent="decoy_hit", started_ms=1_000, status=404),
        attempt(intent="ban_check", phase="followup", objective=False,
                started_ms=4_500, status=403),
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


def test_provenance_fields_come_from_the_manifest(tmp_path):
    run = make_run(tmp_path, "dow", [attempt()], extra={
        "code_revision": {"commit": "7849f3b", "dirty": False, "status": "ok"},
        "policy_hash": "abc123",
        "model_hash": None,
    })
    row = compute_metrics.summarise(run)
    assert row["code_revision"] == "7849f3b"
    assert row["policy_hash"] == "abc123"
    assert row["model_hash"] == ""
    assert row["manifest_path"].endswith("manifest.json")
    assert "model_hash" in row["unavailable_fields"].split(",")


def test_waf_overhead_comes_from_the_decision_stream(tmp_path):
    run = make_run(tmp_path, "scraping", [attempt(request_id="a")], decisions=[
        {"request_id": "a", "decision": "allow", "latency_ms": "2.0"},
        {"request_id": "b", "decision": "throttle", "latency_ms": "4.0"},
        {"request_id": "c", "decision": "allow", "latency_ms": ""},
    ])
    row = compute_metrics.summarise(run)
    assert row["waf_overhead_ms_mean"] == 3.0
    assert "waf_overhead_ms_mean" not in row["unavailable_fields"].split(",")


def test_redis_ban_timing_starts_at_the_first_measured_attempt(tmp_path):
    run = make_run(tmp_path, "honeypot", [
        attempt(intent="decoy_hit", ip="10.20.0.25", started_ms=1_000, status=404),
        attempt(intent="ban_check", ip="10.20.0.25", phase="followup", objective=False,
                started_ms=4_500, status=403),
    ], bans=[{"ip": "10.20.0.25", "reason": "honeypot", "ts_ms": 4_250}])
    row = compute_metrics.summarise(run)
    assert row["time_to_redis_ban_ms"] == 3_250
    # The client-observed number is a different quantity and stays separate.
    assert row["time_to_ban_ms"] == 3_500


def test_missing_ban_archive_marks_ban_timing_unavailable(tmp_path):
    run = make_run(tmp_path, "honeypot", [attempt(intent="decoy_hit", status=404)])
    row = compute_metrics.summarise(run)
    assert row["time_to_redis_ban_ms"] == ""
    assert "time_to_redis_ban_ms" in row["unavailable_fields"].split(",")


def test_uncommitted_tree_is_marked_dirty_in_the_revision(tmp_path):
    (tmp_path / "clean").mkdir()
    (tmp_path / "dirty").mkdir()
    clean = make_run(tmp_path / "clean", "scraping", [attempt()], extra={
        "code_revision": {"commit": "abc1234", "dirty": False, "status": "ok"}})
    dirty = make_run(tmp_path / "dirty", "scraping", [attempt()], extra={
        "code_revision": {"commit": "abc1234", "dirty": True, "status": "ok"}})
    assert compute_metrics.summarise(clean)["code_revision"] == "abc1234"
    assert compute_metrics.summarise(dirty)["code_revision"] == "abc1234-dirty"


def test_repetition_summary_reports_median_and_range_and_skips_invalid_runs():
    rows = [
        {"config": "C2", "workload": "scraping", "asr": "0.2", "run_valid": "true"},
        {"config": "C2", "workload": "scraping", "asr": "0.4", "run_valid": "true"},
        {"config": "C2", "workload": "scraping", "asr": "0.9", "run_valid": "false"},
    ]
    summary = compute_metrics.summarise_repetitions(rows, ["asr"])
    assert len(summary) == 1
    entry = summary[0]
    assert entry["repetitions"] == 2
    assert entry["median"] == 0.3
    assert entry["min"] == 0.2
    assert entry["max"] == 0.4


def test_repetition_summary_never_invents_a_value_from_empty_cells():
    rows = [{"config": "C0", "workload": "scraping", "asr": "0.1", "run_valid": "true"}]
    assert compute_metrics.summarise_repetitions(rows, ["time_to_redis_ban_ms"]) == []


def test_aggregate_workload_reports_asr_without_inventing_unique_objectives(tmp_path):
    run = make_run(tmp_path, "combined", [
        attempt(), attempt(outcome="blocked", status=403),
    ])
    row = compute_metrics.summarise(run)
    assert row["malicious_attempts"] == 2
    assert row["asr"] == 0.5
    assert row["unique_objectives"] == ""
    assert "unique_objectives" in row["unavailable_fields"].split(",")


def test_mixed_run_counts_benign_attempts_without_labels(tmp_path):
    run = make_run(tmp_path, "mixed", [
        attempt(ip="10.20.0.19"),
        attempt(ip="10.20.0.11", objective=False, outcome="blocked", status=403),
        attempt(ip="10.20.0.12", objective=False),
    ])
    row = compute_metrics.summarise(run)
    assert row["malicious_attempts"] == 1
    assert row["benign_attempts"] == 2
    assert row["benign_policy_denials"] == 1
    assert row["false_positive_rate"] == 0.5


def test_sampled_resources_are_reported_and_unsampled_ones_are_not_zero(tmp_path):
    run = make_run(tmp_path, "dow", [attempt()], extra={"resources": {
        "cpu_count": 4,
        "app": {"status": "ok", "cpu_pct": 12.5, "rss_mb_peak": 210.0},
        "agent": {"status": "not_used_in_this_run", "cpu_pct": None, "rss_mb_peak": None},
        "xdp_dropped_packets": None,
    }})
    row = compute_metrics.summarise(run)
    assert row["app_cpu_pct"] == 12.5
    assert row["app_rss_mb"] == 210.0
    assert row["agent_cpu_pct"] == ""
    assert row["xdp_dropped_packets"] == ""
    unavailable = row["unavailable_fields"].split(",")
    assert "agent_cpu_pct" in unavailable
    assert "xdp_dropped_packets" in unavailable
    assert "app_cpu_pct" not in unavailable
