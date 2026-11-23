import json
import socket
import struct
from types import SimpleNamespace

import pytest

from ebpf.sensor import event_record


def test_app_connect_is_host_scoped_not_a_fake_client_ip():
    destination = "127.0.0.1"
    event = SimpleNamespace(kind=1, ip=struct.unpack("=I", socket.inet_aton(destination))[0],
                            port=8001, result=-115, pid=310, comm=b"python3\x00",
                            ts_ns=19_800_000_000)
    row = event_record(event, "sensor-probe", utc_ms=1700000020000,
                       monotonic_ns=20_000_000_000)
    assert row["type"] == "connect"
    assert row["ip"] == ""
    assert row["ts_ms"] == "1700000019800"
    assert row["run_id"] == "sensor-probe"
    assert json.loads(row["detail"]) == {
        "dst_ip": destination, "dst_port": 8001, "connect_result": -115}


def test_descendant_exec_contains_no_prompt_or_client_ip():
    event = SimpleNamespace(kind=2, ip=0, port=0, result=0, pid=311,
                            comm=b"date\x00", ts_ns=100)
    row = event_record(event, "probe", utc_ms=1, monotonic_ns=100)
    assert row["ip"] == ""
    assert row["type"] == "execve"
    assert json.loads(row["detail"]) == {"attribution": "API descendant exec"}
    with pytest.raises(ValueError, match="unknown kernel event"):
        event_record(SimpleNamespace(kind=8), "probe")


def test_accepted_socket_has_real_peer_ip_not_backend_destination():
    peer = "10.20.0.25"
    event = SimpleNamespace(kind=3, ip=struct.unpack("=I", socket.inet_aton(peer))[0],
                            port=8000, result=0, pid=310, comm=b"uvicorn\x00",
                            ts_ns=20_000_000_000)
    row = event_record(event, "probe", utc_ms=1000, monotonic_ns=20_000_000_000)
    assert row["type"] == "accept"
    assert row["ip"] == peer
    assert json.loads(row["detail"]) == {"api_port": 8000}


def test_syn_packet_is_independent_and_never_attributed_to_current_pid():
    peer = "10.20.0.25"
    event = SimpleNamespace(kind=4, ip=struct.unpack("=I", socket.inet_aton(peer))[0],
                            port=8000, result=0, pid=999, comm=b"unrelated",
                            ts_ns=20_000_000_000)
    row = event_record(event, "probe", utc_ms=1000, monotonic_ns=20_000_000_000)
    assert row["type"] == "syn"
    assert row["ip"] == peer
    assert row["pid"] == row["comm"] == ""
    assert json.loads(row["detail"]) == {
        "api_port": 8000, "retransmissions": "included"}


def test_mock_egress_bytes_are_host_scoped_and_keep_the_destination_in_detail():
    event = SimpleNamespace(kind=6, ip=struct.unpack("=I", socket.inet_aton("127.0.0.1"))[0],
                            port=8001, result=42, pid=310, comm=b"python\x00",
                            ts_ns=20_000_000_000)
    row = event_record(event, "probe", utc_ms=1000, monotonic_ns=20_000_000_000)
    assert row["type"] == "egress_bytes"
    assert row["ip"] == ""
    assert row["pid"] == "310"
    assert json.loads(row["detail"]) == {
        "dst_ip": "127.0.0.1", "dst_port": 8001, "tcp_payload_bytes": 42}


def test_failed_connection_is_a_packet_scoped_locally_rejected_syn():
    peer = "10.20.0.25"
    event = SimpleNamespace(
        kind=7, ip=struct.unpack("=I", socket.inet_aton(peer))[0],
        port=8000, result=0, pid=999, comm=b"unrelated",
        ts_ns=20_000_000_000,
    )
    row = event_record(event, "probe", utc_ms=1000,
                       monotonic_ns=20_000_000_000)
    assert row["type"] == "failed_conn"
    assert row["ip"] == peer
    assert row["pid"] == row["comm"] == ""
    assert json.loads(row["detail"]) == {
        "api_port": 8000,
        "definition": "local TCP reset for inbound SYN",
    }


def test_received_payload_bytes_have_source_peer_and_no_fake_http_attribution():
    peer = "10.20.0.25"
    event = SimpleNamespace(kind=5, ip=struct.unpack("=I", socket.inet_aton(peer))[0],
                            port=8000, result=82, pid=310, comm=b"python\x00",
                            ts_ns=20_000_000_000)
    row = event_record(event, "probe", utc_ms=1000, monotonic_ns=20_000_000_000)
    assert row["type"] == "inbound_bytes"
    assert row["ip"] == peer and row["pid"] == "310"
    assert json.loads(row["detail"]) == {
        "api_port": 8000, "tcp_payload_bytes": 82,
        "retransmissions": "excluded (TCP delivered)"}
