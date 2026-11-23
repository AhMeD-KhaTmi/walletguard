import json

import pytest

from ebpf.signals import RollingSignals, SignalPublisher, signal_hash


class FakeRedis:
    def __init__(self, schema="2"):
        self.data = {"p20:meta:schema_version": schema}
        self.ttls = {}
        self.transactional = []

    def get(self, key):
        return self.data.get(key)

    def pipeline(self, transaction=False):
        self.transactional.append(transaction)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def delete(self, key):
        self.data.pop(key, None)
        return self

    def hset(self, key, mapping):
        self.data[key] = mapping
        return self

    def expire(self, key, seconds):
        self.ttls[key] = seconds
        return self

    def execute(self):
        return True


def test_independent_windows_and_real_zero():
    signals = RollingSignals()
    ip = "10.20.0.25"
    now = 20_000_000_000
    signals.add("accepted", ip=ip, when_ns=now - 500_000_000)
    signals.add("accepted", ip=ip, when_ns=now - 5_000_000_000)
    signals.add("syn", ip=ip, when_ns=now - 5_000_000_000, value=3)
    signals.add("inbound_bytes", ip=ip, when_ns=now - 100, value=117)
    values = signals.snapshot(now_ns=now, ip=ip,
                              healthy={"accepted", "syn", "inbound_bytes", "failed"})
    assert values == {
        "conn_rate_1s": 1, "conn_rate_10s": 2, "syn_rate_10s": 3,
        "failed_conn_10s": 0, "bytes_in_10s": 117,
    }
    assert signals.snapshot(now_ns=now + 61_000_000_000, ip=ip,
                            healthy={"accepted"}) == {"conn_rate_1s": 0, "conn_rate_10s": 0}


def test_missing_probe_never_claims_a_measured_zero():
    signals = RollingSignals()
    signals.add("egress_conn", when_ns=1)
    host = signals.snapshot(now_ns=2, healthy={"egress_conn"})
    assert host == {"egress_conns_llm_60s": 1}
    assert json.loads(signal_hash(host, updated_ms=100)["available_fields"]) == [
        "egress_conns_llm_60s"]
    assert signal_hash({}, updated_ms=100)["available_fields"] == "[]"


def test_publish_replaces_stale_fields_and_sets_correct_ttls():
    signals = RollingSignals()
    signals.add("accepted", ip="10.20.0.25", when_ns=1)
    signals.add("inbound_bytes", ip="10.20.0.25", when_ns=1, value=80)
    redis = FakeRedis()
    publisher = SignalPublisher(redis, signals)
    publisher.publish(now_ns=2, updated_ms=100,
                      healthy={"accepted", "inbound_bytes", "egress_conn"})
    ip = "p20:sig:ip:10.20.0.25"
    assert redis.ttls == {ip: 60, "p20:sig:host": 120}
    assert all(redis.transactional)
    assert redis.data[ip]["conn_rate_1s"] == "1"
    assert redis.data[ip]["bytes_in_10s"] == "80"
    assert redis.data["p20:sig:host"]["egress_conns_llm_60s"] == "0"
    publisher.publish(now_ns=3, updated_ms=101, healthy=set())
    assert "conn_rate_1s" not in redis.data[ip]
    assert "bytes_in_10s" not in redis.data[ip]
    assert redis.data[ip]["available_fields"] == "[]"
    assert redis.data[ip]["updated_ms"] == "101"
    publisher.publish(now_ns=60_000_000_002, updated_ms=102, healthy={"accepted"})
    assert ip not in signals.active_ips(60_000_000_002)
    # The old Redis key is no longer refreshed; it will expire at its own TTL.
    assert redis.ttls[ip] == 60


def test_mock_egress_is_host_scoped_and_cannot_pose_as_a_client_ip():
    signals = RollingSignals()
    signals.add("egress_conn", when_ns=1)
    signals.add("egress_bytes", when_ns=1, value=42)
    signals.add("unexpected_exec", when_ns=1)
    host = signals.snapshot(
        now_ns=2, healthy={"egress_conn", "egress_bytes", "unexpected_exec"})
    assert host == {
        "egress_conns_llm_60s": 1,
        "egress_bytes_llm_60s": 42,
        "unexpected_exec_count": 1,
    }
    assert signals.snapshot(now_ns=2, healthy={"egress_conn", "egress_bytes"},
                            ip="10.20.0.25") == {}
    with pytest.raises(ValueError, match="must not be attributed"):
        signals.add("egress_bytes", ip="10.20.0.25", when_ns=1, value=1)


def test_wrong_schema_and_invalid_measurements_are_rejected():
    signals = RollingSignals()
    redis = FakeRedis(schema="1")
    with pytest.raises(RuntimeError, match="schema v2"):
        SignalPublisher(redis, signals).publish(now_ns=1, updated_ms=2, healthy=set())
    with pytest.raises(ValueError, match="source IPv4"):
        signals.add("accepted", ip="127.0.0.1:8000", when_ns=1)
    with pytest.raises(ValueError, match="positive"):
        signals.add("inbound_bytes", ip="10.20.0.25", when_ns=1, value=-1)
    with pytest.raises(ValueError, match="mixed"):
        signal_hash({"conn_rate_1s": 1, "egress_bytes_llm_60s": 2}, updated_ms=100)
