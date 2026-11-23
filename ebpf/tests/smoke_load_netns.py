"""Opt-in connection-churn smoke on the canonical ns15 bridge path.

Run only with DB15 empty and no other DB15/test/API traffic active:
    sudo python3 -m ebpf.tests.smoke_load_netns

This is a controlled count/byte consistency check, not a benchmark, C4
or IT-2 claim: 100 client connections (10 workers) from ns15 each deliver
exactly 100 bytes to an owned listener. It checks accept/SYN/byte
accounting and that no perf loss was reported.

The sensor's stdout is drained for the whole run. A blocked pipe can stall
the perf callback past the 10-second count window, which looks like a lost
kernel event but is a harness defect.

The listener also waits on stdin before calling accept(). on_accept is a
kretprobe, so an accept() invocation already blocked at attach time is never
observed. Gating the loop means all 100 accept entries happen after attach.
"""

import json
import select
import socket
import subprocess
import sys
import threading
import time

import redis

from ebpf.tests.smoke_accept_redis import stop_owned_process, wait_for_attachment


URL = "redis://127.0.0.1:6379/15"
PORT = 18002
PEER = "10.20.0.25"
BIND = "10.20.0.1"
CONNECTIONS = 100
PAYLOAD_BYTES = 100
RUN_ID = "sensor-load-netns-smoke"
SERVER = """
import json,socket,sys
N=100; SIZE=100
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[1],18002))
s.listen(128)
print("READY",flush=True)
input()  # parent releases only after the kretprobes are attached
total=0
for _ in range(N):
    c,_=s.accept()
    c.settimeout(5)
    got=0
    while got<SIZE:
        data=c.recv(SIZE-got)
        if not data:
            break
        got+=len(data)
    total+=got
    c.close()
s.close()
print(json.dumps({"accepted":N,"received_bytes":total}),flush=True)
"""
CLIENT = """
import concurrent.futures,json,socket,sys
N=100
payload=b"x"*100
def one(_):
    with socket.create_connection((sys.argv[1],18002),timeout=5) as s:
        s.sendall(payload)
    return len(payload)
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
    sent=sum(pool.map(one,range(N)))
print(json.dumps({"connections":N,"sent_bytes":sent}),flush=True)
"""


def require_lab_network():
    address = subprocess.run(
        ["ip", "netns", "exec", "ns15", "ip", "-4", "-o", "addr", "show"],
        check=True, capture_output=True, text=True,
    ).stdout
    if f"{PEER}/24" not in address:
        raise RuntimeError("ns15 lacks the canonical 10.20.0.25/24 address")
    with socket.socket() as reservation:
        reservation.bind((BIND, PORT))


def main():
    require_lab_network()
    r = redis.Redis.from_url(
        URL, decode_responses=True, socket_connect_timeout=2, socket_timeout=2)
    if r.dbsize() != 0:
        raise RuntimeError("DB 15 is not empty; refusing to modify it")
    keys = (
        "p20:meta:schema_version",
        f"p20:sig:ip:{PEER}",
        "p20:sig:host",
        "p20:stream:ebpf_events",
    )
    server = sensor = None
    created = False
    try:
        if not r.set(keys[0], "2", nx=True):
            raise RuntimeError("schema key appeared concurrently; aborting")
        created = True
        server = subprocess.Popen(
            [sys.executable, "-u", "-c", SERVER, BIND],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE, text=True,
        )
        ready, _, _ = select.select([server.stdout], [], [], 5)
        if not ready or server.stdout.readline().strip() != "READY":
            raise RuntimeError(f"listener did not bind {BIND}:{PORT}")
        sensor = subprocess.Popen([
            sys.executable, "-u", "-m", "ebpf.sensor",
            "--pid", str(server.pid), "--api-port", str(PORT),
            "--run-id", RUN_ID, "--redis-url", URL, "--duration", "45",
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        wait_for_attachment(sensor)
        # The sensor prints every event. Drain its pipe during the run or a
        # full pipe can block the callback and make the last event look missing.
        sensor_lines = []

        def drain_sensor():
            for line in sensor.stdout:
                sensor_lines.append(line)

        drain = threading.Thread(target=drain_sensor, daemon=True)
        drain.start()
        time.sleep(11)
        if sensor.poll() is not None or server.poll() is not None:
            raise RuntimeError("listener or sensor exited before the load")
        # The listener must enter accept() only now, after on_accept (a
        # kretprobe) is attached; a call blocked at attach time is invisible.
        server.stdin.write("GO\n")
        server.stdin.flush()
        client = subprocess.run(
            ["ip", "netns", "exec", "ns15", sys.executable, "-c", CLIENT, BIND],
            check=True, capture_output=True, text=True, timeout=30,
        )
        print(client.stdout.strip(), flush=True)
        served, _, _ = select.select([server.stdout], [], [], 10)
        if not served:
            raise RuntimeError("owned listener did not report its final count")
        server_result = json.loads(server.stdout.readline())
        print(json.dumps(server_result, sort_keys=True), flush=True)
        assert server_result == {
            "accepted": CONNECTIONS,
            "received_bytes": CONNECTIONS * PAYLOAD_BYTES,
        }, server_result
        lost = [line.strip() for line in sensor_lines
                if '"lost_perf_events"' in line]

        # Each event is added to the in-memory window before it is written to
        # the stream, so a complete accept count there means the sensor has
        # processed the whole load. Only then is a published window meaningful.
        deadline = time.monotonic() + 10
        events = []
        while time.monotonic() < deadline:
            events = [e for _, e in r.xrange(keys[3])]
            if sum(e.get("type") == "accept" for e in events) >= CONNECTIONS:
                break
            time.sleep(0.1)
        accepted = [e for e in events if e.get("type") == "accept"]
        syns = [e for e in events if e.get("type") == "syn"]
        inbound = [e for e in events if e.get("type") == "inbound_bytes"]
        failures = [e for e in events if e.get("type") == "failed_conn"]
        execs = [e for e in events if e.get("type") == "execve"]
        accept_stamps = sorted(int(e["ts_ms"]) for e in accepted)
        print(json.dumps({
            "stream_counts": {"accept": len(accepted), "syn": len(syns),
                              "inbound_bytes": len(inbound),
                              "failed_conn": len(failures),
                              "execve": len(execs)},
            "accept_ts_ms": ([accept_stamps[0], accept_stamps[-1]]
                             if accept_stamps else []),
            "perf_loss_reported": bool(lost),
        }, sort_keys=True), flush=True)
        assert not lost, lost
        # Never poll a row when an event is already missing: after 10s the
        # window legitimately expires and its zeros hide the real defect.
        assert len(accepted) == CONNECTIONS, (
            f"stream has {len(accepted)} accept events for {CONNECTIONS} "
            "connections; check the attach gate")

        row = {}
        host = {}
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            row = r.hgetall(keys[1])
            host = r.hgetall(keys[2])
            # SYN events arrive on the packet path (softirq CPUs) while accepts
            # come from the API process, so one snapshot can contain every
            # accept but only most SYNs. Wait for a publish that has all three.
            if (int(row.get("conn_rate_10s", "0")) == CONNECTIONS
                    and int(row.get("bytes_in_10s", "0"))
                    == CONNECTIONS * PAYLOAD_BYTES
                    and int(row.get("syn_rate_10s", "0")) >= CONNECTIONS):
                break
            time.sleep(0.1)
        fields = set(json.loads(row.get("available_fields", "[]")))
        host_fields = set(json.loads(host.get("available_fields", "[]")))
        print(json.dumps({"ip_row": row, "host_row": host,
                          "row_updated_ms": row.get("updated_ms")},
                         sort_keys=True), flush=True)
        assert fields == {
            "conn_rate_1s", "conn_rate_10s", "syn_rate_10s",
            "failed_conn_10s", "bytes_in_10s"}, row
        assert int(row["conn_rate_10s"]) == CONNECTIONS, row
        assert int(row["syn_rate_10s"]) >= CONNECTIONS, row
        assert int(row["bytes_in_10s"]) == CONNECTIONS * PAYLOAD_BYTES, row
        assert int(row["failed_conn_10s"]) == 0, row
        assert 0 < r.pttl(keys[1]) <= 60_000, row
        assert host_fields == {
            "egress_bytes_llm_60s", "egress_conns_llm_60s",
            "unexpected_exec_count"}, host
        assert host["egress_bytes_llm_60s"] == "0", host
        assert host["egress_conns_llm_60s"] == "0", host
        assert host["unexpected_exec_count"] == "0", host
        assert 0 < r.pttl(keys[2]) <= 120_000, host

        assert len(accepted) == CONNECTIONS, len(accepted)
        assert all(e["ip"] == PEER and e["pid"] == str(server.pid)
                   for e in accepted), accepted[:2]
        assert len(syns) >= CONNECTIONS, len(syns)
        assert all(e["ip"] == PEER and e["pid"] == "" for e in syns), syns[:2]
        assert sum(json.loads(e["detail"])["tcp_payload_bytes"]
                   for e in inbound) == CONNECTIONS * PAYLOAD_BYTES, inbound[:2]
        assert all(e["ip"] == PEER and e["pid"] == str(server.pid)
                   for e in inbound), inbound[:2]
        assert not failures and not execs, (failures[:2], execs[:2])
        print(json.dumps({
            "result": "LOAD-NETNS-OK",
            "peer": PEER,
            "connections": CONNECTIONS,
            "payload_bytes": CONNECTIONS * PAYLOAD_BYTES,
            "conn_rate_10s": row["conn_rate_10s"],
            "syn_rate_10s": row["syn_rate_10s"],
            "bytes_in_10s": row["bytes_in_10s"],
            "failed_conn_10s": row["failed_conn_10s"],
            "accept_events": len(accepted),
            "syn_events": len(syns),
            "inbound_events": len(inbound),
            "perf_loss_reported": bool(lost),
            "available_fields": sorted(fields),
            "run_id": RUN_ID,
        }, sort_keys=True), flush=True)
    finally:
        stop_owned_process(sensor)
        stop_owned_process(server)
        if sensor is not None:
            if "drain" in locals():
                drain.join(timeout=5)
                lines = list(sensor_lines)
            else:
                lines = sensor.stdout.readlines() if sensor.stdout else []
            # Do not echo ~300 per-event lines; the stream summary above is the
            # evidence. Any line that is not a load event is worth showing.
            other = []
            load_events = 0
            for line in lines:
                text = line.strip()
                try:
                    kind = json.loads(text).get("type")
                except ValueError:
                    kind = None
                if kind in {"accept", "syn", "inbound_bytes"}:
                    load_events += 1
                else:
                    other.append(text)
            print(json.dumps({"sensor_lines": len(lines),
                              "load_event_lines": load_events,
                              "sensor_other_lines": other[:20]},
                             sort_keys=True), flush=True)
        if created:
            r.delete(*keys)
        print(json.dumps({"scratch_db15_size_after": r.dbsize()}), flush=True)


if __name__ == "__main__":
    main()
