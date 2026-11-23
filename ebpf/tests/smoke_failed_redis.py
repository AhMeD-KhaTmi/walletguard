"""Opt-in VM smoke for the narrow failed-connection kernel definition.

Run only with TCP port 18001 free and scratch Redis DB 15 empty:
    sudo python3 -m ebpf.tests.smoke_failed_redis

The test sends one loopback SYN to a closed port. It expects the local TCP
stack's reset path to produce one source-scoped failed connection. This is not
an HTTP failure, client timeout, load benchmark or C4 test.
"""

import json
import socket
import subprocess
import sys
import time

import redis

from ebpf.tests.smoke_accept_redis import stop_owned_process, wait_for_attachment


URL = "redis://127.0.0.1:6379/15"
PORT = 18001
PEER = "127.0.0.1"
RUN_ID = "sensor-failed-conn-smoke"
TARGET = """
print("READY",flush=True)
input()
"""


def main():
    # Prove the port is free before touching Redis, then close the reservation
    # so the controlled SYN reaches the kernel's no-listener reset path.
    with socket.socket() as reservation:
        reservation.bind((PEER, PORT))

    r = redis.Redis.from_url(
        URL, decode_responses=True, socket_connect_timeout=2, socket_timeout=2)
    if r.dbsize() != 0:
        raise RuntimeError("DB 15 is not empty; do not modify another test's state")
    keys = (
        "p20:meta:schema_version",
        f"p20:sig:ip:{PEER}",
        "p20:sig:host",
        "p20:stream:ebpf_events",
    )
    target = sensor = None
    created = False
    try:
        if not r.set(keys[0], "2", nx=True):
            raise RuntimeError("schema key appeared concurrently; aborting")
        created = True
        target = subprocess.Popen(
            [sys.executable, "-u", "-c", TARGET],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True,
        )
        if target.stdout.readline().strip() != "READY":
            raise RuntimeError("owned target process did not become ready")
        sensor = subprocess.Popen([
            sys.executable, "-u", "-m", "ebpf.sensor",
            "--pid", str(target.pid), "--api-port", str(PORT),
            "--run-id", RUN_ID, "--redis-url", URL, "--duration", "20",
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        wait_for_attachment(sensor)
        time.sleep(11)
        if sensor.poll() is not None:
            raise RuntimeError("sensor exited before the controlled SYN")
        try:
            socket.create_connection((PEER, PORT), timeout=3)
            raise AssertionError("closed test port unexpectedly accepted a connection")
        except ConnectionRefusedError:
            pass

        deadline = time.monotonic() + 5
        row = {}
        while time.monotonic() < deadline:
            row = r.hgetall(keys[1])
            if int(row.get("failed_conn_10s", "0")) == 1:
                break
            time.sleep(0.1)
        fields = set(json.loads(row.get("available_fields", "[]")))
        assert "failed_conn_10s" in fields, row
        assert int(row["failed_conn_10s"]) == 1, row
        assert int(row["syn_rate_10s"]) >= 1, row
        assert int(row["conn_rate_10s"]) == 0, row
        assert 0 < r.pttl(keys[1]) <= 60_000, row

        events = [fields for _, fields in r.xrange(keys[3])]
        failures = [event for event in events if event.get("type") == "failed_conn"]
        accepted = [event for event in events if event.get("type") == "accept"]
        assert len(failures) == 1 and not accepted, events
        assert failures[0]["ip"] == PEER, failures
        assert failures[0]["pid"] == failures[0]["comm"] == "", failures
        assert json.loads(failures[0]["detail"]) == {
            "api_port": PORT,
            "definition": "local TCP reset for inbound SYN",
        }, failures
        print(json.dumps({
            "result": "FAILED-CONN-OK",
            "peer": PEER,
            "failed_conn_10s": row["failed_conn_10s"],
            "syn_rate_10s": row["syn_rate_10s"],
            "conn_rate_10s": row["conn_rate_10s"],
            "available_fields": sorted(fields),
            "failed_events": len(failures),
            "accept_events": len(accepted),
            "run_id": RUN_ID,
        }, sort_keys=True), flush=True)
    finally:
        stop_owned_process(sensor)
        if target is not None and target.poll() is None:
            target.stdin.write("STOP\n")
            target.stdin.flush()
        stop_owned_process(target)
        if sensor is not None:
            for line in sensor.stdout:
                print(line.rstrip(), flush=True)
        if created:
            r.delete(*keys)
        print(json.dumps({"scratch_db15_size_after": r.dbsize()}), flush=True)


if __name__ == "__main__":
    main()
