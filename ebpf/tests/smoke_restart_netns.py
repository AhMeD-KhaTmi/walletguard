"""Opt-in restart/stale-signal smoke on the canonical ns15 bridge path.

Run only with DB15 empty and no other DB15/test/API traffic active:
    sudo python3 -m ebpf.tests.smoke_restart_netns

Phase 1 measures one connection, stops the sensor and requires the per-IP
signal hash to expire instead of leaving stale values. Phase 2 starts a new
sensor and requires measured fields to be absent (not zero) until a full
10-second healthy window, then present again.

Only reserved DB15 and an owned listener on 10.20.0.1:18004 are used. This is
a lifecycle check, not a benchmark, C4 or IT-2 claim.
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
PORT = 18004
PEER = "10.20.0.25"
BIND = "10.20.0.1"
PAYLOAD_BYTES = 100
RUN_ID = "sensor-restart-netns-smoke"
RUN_ID2 = "sensor-restart-netns-smoke-2"
IP_FIELDS = {"conn_rate_1s", "conn_rate_10s", "syn_rate_10s",
             "failed_conn_10s", "bytes_in_10s"}
HOST_FIELDS = {"egress_bytes_llm_60s", "egress_conns_llm_60s",
               "unexpected_exec_count"}
SERVER = """
import json,socket,sys
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[1],18004))
s.listen(8)
print("READY",flush=True)
input()  # released only after the accept kretprobe is attached
c,_=s.accept()
c.settimeout(5)
got=b""
while len(got)<100:
    d=c.recv(100-len(got))
    if not d:
        break
    got+=d
c.close()
s.close()
print(json.dumps({"accepted":1,"received_bytes":len(got)}),flush=True)
"""
CLIENT = """
import socket,sys
with socket.create_connection((sys.argv[1],18004),timeout=5) as s:
    s.sendall(b"x"*100)
print("SENT",flush=True)
"""


class Drain:
    """Keep the sensor's per-event stdout from blocking on a full pipe."""

    def __init__(self, proc):
        self.lines = []
        self._thread = threading.Thread(target=self._read, args=(proc,), daemon=True)
        self._thread.start()

    def _read(self, proc):
        for line in proc.stdout:
            self.lines.append(line)

    def join(self, timeout=5):
        self._thread.join(timeout=timeout)


def require_lab_network():
    address = subprocess.run(
        ["ip", "netns", "exec", "ns15", "ip", "-4", "-o", "addr", "show"],
        check=True, capture_output=True, text=True,
    ).stdout
    if f"{PEER}/24" not in address:
        raise RuntimeError("ns15 lacks the canonical 10.20.0.25/24 address")
    with socket.socket() as reservation:
        reservation.bind((BIND, PORT))


def start_listener():
    server = subprocess.Popen(
        [sys.executable, "-u", "-c", SERVER, BIND],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE, text=True,
    )
    ready, _, _ = select.select([server.stdout], [], [], 5)
    if not ready or server.stdout.readline().strip() != "READY":
        stop_owned_process(server)
        raise RuntimeError(f"listener did not bind {BIND}:{PORT}")
    return server


def start_sensor(pid, run_id, duration):
    return subprocess.Popen([
        sys.executable, "-u", "-m", "ebpf.sensor",
        "--pid", str(pid), "--api-port", str(PORT),
        "--run-id", run_id, "--redis-url", URL, "--duration", str(duration),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def send_one(server):
    server.stdin.write("GO\n")
    server.stdin.flush()
    client = subprocess.run(
        ["ip", "netns", "exec", "ns15", sys.executable, "-c", CLIENT, BIND],
        check=True, capture_output=True, text=True, timeout=20,
    )
    if client.stdout.strip() != "SENT":
        raise RuntimeError(f"client did not send: {client.stdout!r}")
    served, _, _ = select.select([server.stdout], [], [], 10)
    if not served:
        raise RuntimeError("listener did not report its final count")
    result = json.loads(server.stdout.readline())
    if result != {"accepted": 1, "received_bytes": PAYLOAD_BYTES}:
        raise RuntimeError(f"listener result {result!r}")


def wait_for_ip_row(r, key, accept, timeout, require_syn=False):
    deadline = time.monotonic() + timeout
    row = {}
    while time.monotonic() < deadline:
        row = r.hgetall(key)
        if (row.get("conn_rate_10s") == str(accept)
                and row.get("bytes_in_10s") == str(accept * PAYLOAD_BYTES)
                and (not require_syn
                     or int(row.get("syn_rate_10s", "0")) >= accept)):
            return row
        time.sleep(0.1)
    return row


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
    server = server2 = sensor = sensor2 = None
    drains = []
    created = False
    try:
        if not r.set(keys[0], "2", nx=True):
            raise RuntimeError("schema key appeared concurrently; aborting")
        created = True

        # Phase 1: measure one connection, then stop the sensor.
        server = start_listener()
        sensor = start_sensor(server.pid, RUN_ID, 60)
        wait_for_attachment(sensor)
        drain = Drain(sensor)
        drains.append(drain)
        time.sleep(11)
        if sensor.poll() is not None or server.poll() is not None:
            raise RuntimeError("listener or sensor exited before the connection")
        send_one(server)
        row = wait_for_ip_row(r, keys[1], 1, 10, require_syn=True)
        host = r.hgetall(keys[2])
        assert set(json.loads(row.get("available_fields", "[]"))) == IP_FIELDS, row
        assert int(row["syn_rate_10s"]) >= 1, row
        assert int(row["failed_conn_10s"]) == 0, row
        assert 0 < r.pttl(keys[1]) <= 60_000, row
        assert set(json.loads(host.get("available_fields", "[]"))) == HOST_FIELDS, host
        assert host["egress_bytes_llm_60s"] == "0", host
        assert host["egress_conns_llm_60s"] == "0", host
        assert host["unexpected_exec_count"] == "0", host
        assert 0 < r.pttl(keys[2]) <= 120_000, host
        print(json.dumps({"phase1": "measured", "peer": PEER,
                          "conn_rate_10s": row["conn_rate_10s"],
                          "bytes_in_10s": row["bytes_in_10s"],
                          "ip_ttl_ms": r.pttl(keys[1]),
                          "host_ttl_ms": r.pttl(keys[2]),
                          "run_id": RUN_ID}, sort_keys=True), flush=True)

        stop_owned_process(sensor)
        drain.join()
        stopped = time.monotonic()
        while time.monotonic() - stopped < 70 and r.exists(keys[1]):
            time.sleep(1)
        expired_after = round(time.monotonic() - stopped, 1)
        assert not r.exists(keys[1]), (
            "stale per-IP signal hash survived 70s after the sensor stopped")
        host_ttl = r.pttl(keys[2])
        assert 0 < host_ttl <= 120_000, host_ttl
        print(json.dumps({"phase1": "STALE-OK",
                          "ip_key_expired_after_s": expired_after,
                          "host_key_pttl_ms": host_ttl,
                          "host_key_still_present": r.exists(keys[2]) == 1},
                         sort_keys=True), flush=True)

        # Phase 2: a fresh sensor must not publish values before its own window.
        server2 = start_listener()
        sensor2 = start_sensor(server2.pid, RUN_ID2, 40)
        wait_for_attachment(sensor2)
        drain2 = Drain(sensor2)
        drains.append(drain2)
        deadline = time.monotonic() + 5
        host2 = {}
        while time.monotonic() < deadline:
            host2 = r.hgetall(keys[2])
            if host2.get("available_fields") == "[]":
                break
            time.sleep(0.1)
        assert host2.get("available_fields") == "[]", host2
        assert not (set(host2) & HOST_FIELDS), host2
        print(json.dumps({"phase2": "unavailable-before-window",
                          "host_row": host2}, sort_keys=True), flush=True)

        # Deliver one connection before the window opens, so the measured event
        # is still inside the first published 10-second window.
        time.sleep(7)
        send_one(server2)
        time.sleep(2)
        row2 = wait_for_ip_row(r, keys[1], 1, 6, require_syn=True)
        host2 = r.hgetall(keys[2])
        assert set(json.loads(row2.get("available_fields", "[]"))) == IP_FIELDS, row2
        assert int(row2["conn_rate_10s"]) == 1, row2
        assert int(row2["bytes_in_10s"]) == PAYLOAD_BYTES, row2
        assert set(json.loads(host2.get("available_fields", "[]"))) == HOST_FIELDS, host2
        assert host2["egress_bytes_llm_60s"] == "0", host2
        assert host2["egress_conns_llm_60s"] == "0", host2
        assert host2["unexpected_exec_count"] == "0", host2

        events = [e for _, e in r.xrange(keys[3])
                  if e.get("run_id") == RUN_ID2]
        accepted = [e for e in events if e.get("type") == "accept"]
        syns = [e for e in events if e.get("type") == "syn"]
        inbound = [e for e in events if e.get("type") == "inbound_bytes"]
        assert len(accepted) == 1, accepted
        assert accepted[0]["ip"] == PEER and accepted[0]["pid"] == str(server2.pid), accepted
        assert len(syns) == 1 and syns[0]["ip"] == PEER and syns[0]["pid"] == "", syns
        assert len(inbound) == 1 and inbound[0]["ip"] == PEER, inbound
        assert json.loads(inbound[0]["detail"])["tcp_payload_bytes"] == PAYLOAD_BYTES
        print(json.dumps({"phase2": "RESTART-OK", "peer": PEER,
                          "conn_rate_10s": row2["conn_rate_10s"],
                          "bytes_in_10s": row2["bytes_in_10s"],
                          "accept_events": len(accepted),
                          "syn_events": len(syns),
                          "inbound_events": len(inbound),
                          "run_id": RUN_ID2}, sort_keys=True), flush=True)
    finally:
        stop_owned_process(sensor2)
        stop_owned_process(sensor)
        stop_owned_process(server2)
        stop_owned_process(server)
        for index, drain in enumerate(drains, 1):
            drain.join()
            other = [line.strip() for line in drain.lines
                     if '"type"' not in line]
            print(json.dumps({"drain": index, "sensor_lines": len(drain.lines),
                              "sensor_other_lines": other}, sort_keys=True),
                  flush=True)
        if created:
            r.delete(*keys)
        print(json.dumps({"scratch_db15_size_after": r.dbsize()}), flush=True)


if __name__ == "__main__":
    main()
