"""Opt-in perf-loss handling smoke on the canonical ns15 bridge path.

Run only with DB15 empty and no other DB15/test/API traffic active:
    sudo python3 -m ebpf.tests.smoke_loss_netns

An owned idle process is the sensor target and nothing listens on the API port,
so every connection attempt is a SYN plus a locally reset connection. The smoke
measures one refusal, pauses the sensor with SIGSTOP, forces more events than a
deliberately tiny test-only perf ring can hold, resumes it, and requires:

  * a nonzero `lost_perf_events` report;
  * both Redis hashes to withdraw measured fields (not publish zeros) while the
    10-second post-loss window is incomplete;
  * fields to return after a full loss-free window.

Only DB15 and 10.20.0.1:18005 are used. This is a loss-handling check, not a
benchmark, C4 or IT-2 claim.
"""

import json
import signal
import socket
import subprocess
import sys
import threading
import time

import redis

from ebpf.tests.smoke_accept_redis import stop_owned_process, wait_for_attachment


URL = "redis://127.0.0.1:6379/15"
PORT = 18005
PEER = "10.20.0.25"
BIND = "10.20.0.1"
BURST_ATTEMPTS = 2000
RUN_ID = "sensor-loss-netns-smoke"
IP_FIELDS = {"conn_rate_1s", "conn_rate_10s", "syn_rate_10s",
             "failed_conn_10s", "bytes_in_10s"}
HOST_FIELDS = {"egress_bytes_llm_60s", "egress_conns_llm_60s",
               "unexpected_exec_count"}
IDLE = """
import sys,time
print("READY",flush=True)
time.sleep(120)
"""
CLIENT = """
import json,socket,sys
n=int(sys.argv[2]); counts={}
for _ in range(n):
    s=socket.socket(); s.settimeout(1)
    code=s.connect_ex((sys.argv[1],18005))
    counts[str(code)]=counts.get(str(code),0)+1
    s.close()
print(json.dumps({"attempts":n,"errno_counts":counts}),flush=True)
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

    def lost(self):
        found = []
        for line in list(self.lines):
            if '"lost_perf_events"' not in line:
                continue
            try:
                found.append(json.loads(line)["lost_perf_events"])
            except (ValueError, KeyError):
                continue
        return found

    def join(self, timeout=5):
        self._thread.join(timeout=timeout)


def require_lab_network():
    address = subprocess.run(
        ["ip", "netns", "exec", "ns15", "ip", "-4", "-o", "addr", "show"],
        check=True, capture_output=True, text=True,
    ).stdout
    if f"{PEER}/24" not in address:
        raise RuntimeError("ns15 lacks the canonical 10.20.0.25/24 address")
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex((BIND, PORT)) == 0:
            raise RuntimeError(f"{BIND}:{PORT} must be closed for this smoke")


def burst(count):
    return subprocess.run(
        ["ip", "netns", "exec", "ns15", sys.executable, "-c", CLIENT, BIND,
         str(count)],
        check=True, capture_output=True, text=True, timeout=60,
    ).stdout.strip()


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
    idle = sensor = None
    drain = None
    created = False
    try:
        if not r.set(keys[0], "2", nx=True):
            raise RuntimeError("schema key appeared concurrently; aborting")
        created = True
        idle = subprocess.Popen(
            [sys.executable, "-u", "-c", IDLE],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        if idle.stdout.readline().strip() != "READY":
            raise RuntimeError("idle target process did not start")
        # A deliberately tiny ring makes overflow deterministic and fast; the
        # production default stays 64 pages per CPU.
        sensor = subprocess.Popen([
            sys.executable, "-u", "-m", "ebpf.sensor",
            "--pid", str(idle.pid), "--api-port", str(PORT),
            "--run-id", RUN_ID, "--redis-url", URL, "--duration", "120",
            "--perf-page-cnt", "1",
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        wait_for_attachment(sensor)
        drain = Drain(sensor)
        time.sleep(11)
        if sensor.poll() is not None:
            raise RuntimeError("sensor exited before the baseline refusal")

        refused = json.loads(burst(1))
        assert refused["errno_counts"] == {"111": 1}, refused
        deadline = time.monotonic() + 10
        row = host = {}
        while time.monotonic() < deadline:
            row, host = r.hgetall(keys[1]), r.hgetall(keys[2])
            if (row.get("failed_conn_10s") == "1"
                    and int(row.get("syn_rate_10s", "0")) >= 1):
                break
            time.sleep(0.1)
        assert row.get("failed_conn_10s") == "1", row
        assert int(row["syn_rate_10s"]) >= 1, row
        assert row["conn_rate_10s"] == "0" and row["bytes_in_10s"] == "0", row
        assert set(json.loads(row["available_fields"])) == IP_FIELDS, row
        assert set(json.loads(host["available_fields"])) == HOST_FIELDS, host
        print(json.dumps({"baseline": "REFUSAL-OK", "peer": PEER,
                          "failed_conn_10s": row["failed_conn_10s"],
                          "syn_rate_10s": row["syn_rate_10s"],
                          "conn_rate_10s": row["conn_rate_10s"],
                          "bytes_in_10s": row["bytes_in_10s"]},
                         sort_keys=True), flush=True)

        # Stop userspace polling so the tiny ring overflows while the kernel
        # keeps producing SYN/failed events.
        sensor.send_signal(signal.SIGSTOP)
        try:
            burst_result = burst(BURST_ATTEMPTS)
        finally:
            sensor.send_signal(signal.SIGCONT)
        print(json.dumps({"burst": json.loads(burst_result),
                          "perf_page_cnt": 1}, sort_keys=True), flush=True)
        if sensor.poll() is not None:
            raise RuntimeError("sensor exited while paused")

        deadline = time.monotonic() + 25
        rows = (row, host)
        while time.monotonic() < deadline and not drain.lost():
            rows = (r.hgetall(keys[1]), r.hgetall(keys[2]))
            time.sleep(0.2)
        lost = drain.lost()
        assert lost and sum(lost) > 0, (
            "ring overflow produced no lost_perf_events report", lost,
            rows[0], rows[1])
        print(json.dumps({"loss_reported": lost,
                          "ip_row": rows[0], "host_row": rows[1]},
                         sort_keys=True), flush=True)

        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            row, host = r.hgetall(keys[1]), r.hgetall(keys[2])
            if (row.get("available_fields") == "[]"
                    and host.get("available_fields") == "[]"):
                break
            time.sleep(0.2)
        assert r.exists(keys[1]) == 1 and r.exists(keys[2]) == 1, (
            "unavailable state must be an empty hash, not a missing key",
            r.exists(keys[1]), r.exists(keys[2]))
        assert row.get("available_fields") == "[]", row
        assert host.get("available_fields") == "[]", host
        assert not (set(row) & IP_FIELDS), row
        assert not (set(host) & HOST_FIELDS), host
        print(json.dumps({"after_loss": "UNAVAILABLE-OK",
                          "ip_row": row, "host_row": host},
                         sort_keys=True), flush=True)

        # A complete loss-free 10s window must restore measured fields.
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            row, host = r.hgetall(keys[1]), r.hgetall(keys[2])
            if (set(json.loads(row.get("available_fields", "[]"))) == IP_FIELDS
                    and set(json.loads(host.get("available_fields", "[]")))
                    == HOST_FIELDS):
                break
            time.sleep(0.2)
        assert set(json.loads(row.get("available_fields", "[]"))) == IP_FIELDS, row
        assert set(json.loads(host.get("available_fields", "[]"))) == HOST_FIELDS, host

        events = [e for _, e in r.xrange(keys[3])]
        accepted = [e for e in events if e.get("type") == "accept"]
        syns = [e for e in events if e.get("type") == "syn"]
        inbound = [e for e in events if e.get("type") == "inbound_bytes"]
        failures = [e for e in events if e.get("type") == "failed_conn"]
        assert not accepted and not inbound, (accepted[:2], inbound[:2])
        assert len(syns) >= 1 and len(failures) >= 1, (
            len(syns), len(failures))
        assert all(e["ip"] == PEER and e["pid"] == "" for e in syns), syns[:2]
        print(json.dumps({"result": "LOSS-OK", "peer": PEER,
                          "lost_perf_events": lost,
                          "perf_page_cnt": 1,
                          "syn_rate_10s": row["syn_rate_10s"],
                          "failed_conn_10s": row["failed_conn_10s"],
                          "conn_rate_10s": row["conn_rate_10s"],
                          "accept_events": len(accepted),
                          "syn_events": len(syns),
                          "inbound_events": len(inbound),
                          "failed_events": len(failures),
                          "run_id": RUN_ID}, sort_keys=True), flush=True)
    finally:
        if sensor is not None and sensor.poll() is None:
            sensor.send_signal(signal.SIGCONT)
        stop_owned_process(sensor)
        stop_owned_process(idle)
        if drain is not None:
            drain.join()
            other = [line.strip() for line in drain.lines
                     if '"type"' not in line
                     and '"lost_perf_events"' not in line]
            print(json.dumps({"sensor_lines": len(drain.lines),
                              "sensor_other_lines": other[:20]},
                             sort_keys=True), flush=True)
        if created:
            r.delete(*keys)
        print(json.dumps({"scratch_db15_size_after": r.dbsize()}), flush=True)


if __name__ == "__main__":
    main()
