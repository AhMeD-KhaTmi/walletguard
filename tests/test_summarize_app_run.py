import json

import pytest

from scripts.summarize_app_run import summarize
from waf.config import Config
from waf.state import State


@pytest.fixture
def run(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({
        "run_id": "r1", "config": "C3", "readiness": "ok", "invalid": False,
        "workload": "mixed", "repetition": 1,
    }))
    benign_ip, attack_ip, probe_ip = "127.0.0.2", "127.0.0.3", "127.0.0.4"
    attempts = [
        {"phase": "setup", "ip": benign_ip, "outcome": "success", "status": 200,
         "request_id": "setup", "latency_ms": 2000},
        {"phase": "measured", "ip": benign_ip, "outcome": "success", "status": 200,
         "request_id": "ok", "latency_ms": 4},
        {"phase": "measured", "ip": benign_ip, "outcome": "blocked", "status": 429,
         "request_id": "denied", "latency_ms": 1},
        {"phase": "measured", "ip": benign_ip, "outcome": "timeout", "status": None},
        {"phase": "measured", "ip": attack_ip, "outcome": "success", "status": 200,
         "request_id": "attack", "latency_ms": 999, "objective": False},
        {"phase": "measured", "ip": probe_ip, "outcome": "success", "route": "tcp://"},
    ]
    (tmp_path / "attempts-fixture.jsonl").write_text("".join(
        json.dumps({"run_id": "r1", **row}) + "\n" for row in attempts
    ))
    labels = {"r1": {benign_ip: "benign", attack_ip: "attack", probe_ip: "probe"}}
    evidence = {"run_id": "r1", "dropped_timings": 0, "timings": [
        {"run_id": "r1", "request_id": request_id, "waf_overhead_ms": overhead, "scoring_ms": 1}
        for request_id, overhead in [("setup", 100), ("ok", 2), ("denied", 4), ("attack", 6)]
    ]}
    return tmp_path, labels, evidence


def test_measured_labels_and_finalized_timings(run):
    result = summarize(*run)
    assert result["timed_attempts"] == 3 and result["timing_coverage"] == .75
    assert result["benign_attempts"] == 3 and result["benign_timeouts"] == 1
    assert result["false_positive_rate"] == 1 / 3 and result["benign_unsuccessful_rate"] == 2 / 3
    assert result["latency_p95_ms"] == 4
    assert result["waf_overhead_ms_mean"] == 4 and result["scoring_p95_ms"] == 1
    assert result["waf_overhead_p50_ms"] == 4 and result["waf_overhead_p95_ms"] == pytest.approx(5.8)


def test_baseline_percentile_deltas_keep_negative_values():
    from scripts.run_c23_benchmark import add_baseline_deltas

    base = {"config": "C0", "workload": "benign", "repetition": 1, "seed": 42,
            "latency_p50_ms": 10, "latency_p95_ms": 20}
    hardened = {**base, "config": "C2", "latency_p50_ms": 9, "latency_p95_ms": 25}
    unmatched = {**hardened, "seed": 43}
    add_baseline_deltas([base, hardened, unmatched])
    assert hardened["latency_delta_p50_ms"] == -1 and hardened["latency_delta_p95_ms"] == 5
    assert unmatched["latency_delta_p50_ms"] is None


def test_rejects_truncation_missing_replies_and_wrong_scoring(run):
    run_dir, labels, evidence = run
    with pytest.raises(ValueError, match="incomplete timings"):
        summarize(run_dir, labels, {**evidence, "dropped_timings": 1})
    with pytest.raises(ValueError, match="join uniquely"):
        summarize(run_dir, labels, {**evidence, "timings": evidence["timings"][:-1]})
    evidence["timings"][-1]["scoring_ms"] = 0
    with pytest.raises(ValueError, match="configured mode"):
        summarize(*run)


def test_runtime_timing_limit_has_a_bounded_override(monkeypatch):
    monkeypatch.setenv("WAF_TELEMETRY_LIMIT", "2")
    config = Config.from_env(mode="enforce", redis_url="redis://127.0.0.1/0")
    state = State(config)
    for row in ({"request_id": "a"}, {"request_id": "b"}, {"request_id": "c"}):
        state.timing(row)
    assert [row["request_id"] for row in state.timings] == ["b", "c"]
    assert state.dropped_timings == 1
