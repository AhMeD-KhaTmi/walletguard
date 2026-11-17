"""Unit tests for the harness's evidence rules (no traffic is started)."""

import json
from types import SimpleNamespace

from eval import harness


def test_dow_pacing_metadata_records_both_paced_and_burst():
    for pace in (0.0, 7.0):
        args = SimpleNamespace(workload="dow", profile="undercap", dow_pace=pace)
        assert harness.workload_metadata(args) == {"profile": "undercap", "dow_pace_s": pace}


def test_other_workloads_do_not_claim_dow_pacing():
    args = SimpleNamespace(workload="benign", profile="undercap", dow_pace=7)
    assert harness.workload_metadata(args) == {"profile": None, "dow_pace_s": None}


def test_clean_workers_produce_no_invalidation_reason():
    results = [{"ns": "ns1", "returncode": 0, "overran": False},
               {"ns": "ns2", "returncode": 0, "overran": False}]
    assert harness.invalid_reasons(results, late_traffic=False) == []


def test_crashed_worker_invalidates_the_run():
    """MASTER_PLAN 7.2.5: a worker that died leaves an incomplete denominator."""
    results = [{"ns": "ns6", "returncode": 0, "overran": False},
               {"ns": "ns7", "returncode": 1, "overran": False}]
    assert harness.invalid_reasons(results, late_traffic=False) == ["exit:ns7:1"]


def test_overrunning_worker_invalidates_the_run():
    results = [{"ns": "ns9", "returncode": 0, "overran": True}]
    assert harness.invalid_reasons(results, late_traffic=False) == ["overran:ns9"]


def test_late_traffic_is_still_reported_as_a_reason():
    results = [{"ns": "ns1", "returncode": 0, "overran": False}]
    assert harness.invalid_reasons(results, late_traffic=True) == ["late_traffic"]


class FakeRedis:
    def __init__(self, entries):
        self.entries = entries
        self.closed = False
        self.requested = None

    def xrange(self, key, min, max, count):  # noqa: A002 - redis client signature
        self.requested = key
        return self.entries

    def close(self):
        self.closed = True


def test_feature_stream_is_archived_with_a_hash(tmp_path, monkeypatch):
    fake = FakeRedis([("1-0", {"ip": "10.20.0.11", "run_id": "c1-benign-r1"})])
    monkeypatch.setattr(harness, "redis_client", lambda url: fake)
    info = harness.snapshot_features("redis://localhost/0", tmp_path / "features.jsonl")
    assert fake.requested == "p20:stream:waf_features"
    assert fake.closed is True
    assert info["rows"] == 1
    assert len(info["sha256"]) == 64
    row = json.loads((tmp_path / "features.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert row["stream_id"] == "1-0"
    assert row["ip"] == "10.20.0.11"


def test_empty_feature_stream_archives_zero_rows_not_an_error(tmp_path, monkeypatch):
    fake = FakeRedis([])
    monkeypatch.setattr(harness, "redis_client", lambda url: fake)
    info = harness.snapshot_features("redis://localhost/0", tmp_path / "features.jsonl")
    assert info["rows"] == 0
    assert (tmp_path / "features.jsonl").read_text(encoding="utf-8") == ""


def test_worker_meta_files_are_summarised_for_the_manifest(tmp_path):
    (tmp_path / "worker-10.20.0.16-321.json").write_text(json.dumps({
        "ip": "10.20.0.16", "pid": 321, "configured_seed": 42, "derived_seed": 42 ^ 321,
    }), encoding="utf-8")
    (tmp_path / "worker-10.20.0.11-123.json").write_text(json.dumps({
        "ip": "10.20.0.11", "pid": 123, "configured_seed": 42, "derived_seed": 42 ^ 123,
    }), encoding="utf-8")
    workers = harness.read_worker_meta(tmp_path)
    assert [worker["ip"] for worker in workers] == ["10.20.0.11", "10.20.0.16"]
    assert workers[0]["derived_seed"] == 42 ^ 123
