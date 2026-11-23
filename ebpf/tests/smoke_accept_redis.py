"""Opt-in Linux/BCC integration smoke on an EMPTY Redis DB 15.

Run only when no application test or DB-15 experiment is active:
    sudo python3 -m ebpf.tests.smoke_accept_redis
    sudo python3 -m ebpf.tests.smoke_accept_redis --verify-exec
Use --netns for the existing canonical ns15 probe identity. Neither mode
is a C4 or real API benchmark.
"""

import argparse
import json
import select
import socket
import subprocess
import sys
import time

import redis


URL = "redis://127.0.0.1:6379/15"
PORT = 18000
SERVER = """
import subprocess
import socket
import sys
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[1],18000))
s.listen(1)
print("READY",flush=True)
command=input()  # parent releases this only after the probes are attached
if command=="EXEC":
    subprocess.run(["/bin/true"],check=True)
c,_=s.accept()
c.close()
s.close()
"""


def stop_owned_process(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def wait_for_attachment(proc):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        readable, _, _ = select.select([proc.stdout], [], [], 1)
        if readable:
            line = proc.stdout.readline()
            if not line:
                break
            print(line.rstrip(), flush=True)
            try:
                if json.loads(line).get("sensor") == "attached":
                    return
            except (ValueError, AttributeError):
                pass  # BCC may emit plain compiler diagnostics first.
        if proc.poll() is not None:
            break
    raise RuntimeError("sensor failed to attach within 30s; see output above")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--netns", action="store_true",
                        help="use existing ns15 10.20.0.25 -> p20br0 10.20.0.1")
    parser.add_argument("--verify-exec", action="store_true",
                        help="fork/exec /bin/true from the target after attachment")
    args = parser.parse_args()
    peer = "10.20.0.25" if args.netns else "127.0.0.1"
    bind = "10.20.0.1" if args.netns else "127.0.0.1"
    run_id = "sensor-redis-netns-smoke" if args.netns else "sensor-redis-smoke"
    keys = ("p20:meta:schema_version", f"p20:sig:ip:{peer}",
            "p20:sig:host", "p20:stream:ebpf_events")
    if args.netns:
        address = subprocess.run(
            ["ip", "netns", "exec", "ns15", "ip", "-4", "-o", "addr", "show"],
            check=True, capture_output=True, text=True,
        ).stdout
        if "10.20.0.25/" not in address:
            raise RuntimeError("ns15 lacks canonical probe IPv4 10.20.0.25")
    r = redis.Redis.from_url(URL, decode_responses=True,
                             socket_connect_timeout=2, socket_timeout=2)
    if r.dbsize() != 0:
        raise RuntimeError("DB 15 is not empty; do not modify another test's state")
    server = sensor = None
    created = False
    try:
        if not r.set(keys[0], "2", nx=True):
            raise RuntimeError("schema key appeared concurrently; aborting")
        created = True
        server = subprocess.Popen(
            [sys.executable, "-u", "-c", SERVER, bind], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True,
        )
        ready, _, _ = select.select([server.stdout], [], [], 5)
        if not ready or server.stdout.readline().strip() != "READY":
            raise RuntimeError("local test listener did not bind port 18000")
        sensor = subprocess.Popen([
            sys.executable, "-u", "-m", "ebpf.sensor",
            "--pid", str(server.pid), "--api-port", str(PORT),
            "--run-id", run_id, "--redis-url", URL, "--duration", "20",
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        wait_for_attachment(sensor)
        # The schema accepts a zero only after a full healthy 10s window.
        time.sleep(11)
        server.stdin.write("EXEC\n" if args.verify_exec else "ACCEPT\n")
        server.stdin.flush()
        if args.netns:
            subprocess.run([
                "ip", "netns", "exec", "ns15", sys.executable, "-c",
                "import socket,sys; s=socket.create_connection((sys.argv[1],18000),timeout=3);s.close()",
                bind,
            ], check=True, timeout=5)
        else:
            with socket.create_connection((bind, PORT), timeout=3):
                pass
        deadline = time.monotonic() + 5
        row = {}
        while time.monotonic() < deadline:
            row = r.hgetall(keys[1])
            host = r.hgetall(keys[2])
            exec_ready = (not args.verify_exec
                          or int(host.get("unexpected_exec_count", "0")) == 1)
            if int(row.get("conn_rate_10s", "0")) >= 1 and exec_ready:
                break
            time.sleep(0.1)
        fields = set(json.loads(row.get("available_fields", "[]")))
        assert fields == {"conn_rate_1s", "conn_rate_10s", "syn_rate_10s",
                          "bytes_in_10s"}, row
        assert int(row["conn_rate_10s"]) == 1, row
        assert int(row["syn_rate_10s"]) >= 1, row
        # This listener accepts and closes without reading request data.
        assert int(row["bytes_in_10s"]) == 0, row
        assert 0 <= int(time.time() * 1000) - int(row["updated_ms"]) <= 3000, row
        assert 0 < r.pttl(keys[1]) <= 60_000
        host_fields = set(json.loads(host["available_fields"]))
        # The egress probe is attached but this listener never talks to the
        # mock port, so both host counters are real measured zeros.
        assert host_fields == {
            "egress_bytes_llm_60s", "egress_conns_llm_60s",
            "unexpected_exec_count"}, host
        assert host["egress_bytes_llm_60s"] == host["egress_conns_llm_60s"] == "0", host
        assert int(host["unexpected_exec_count"]) == int(args.verify_exec), host
        assert 0 < r.pttl(keys[2]) <= 120_000
        events = [fields for _, fields in r.xrange(keys[3])]
        accepted = [e for e in events if e.get("type") == "accept"]
        syns = [e for e in events if e.get("type") == "syn"]
        execs = [e for e in events if e.get("type") == "execve"]
        assert len(accepted) == 1 and accepted[0]["ip"] == peer, events
        assert syns and all(e["ip"] == peer for e in syns), events
        assert accepted[0]["pid"] == str(server.pid), accepted
        assert json.loads(accepted[0]["detail"]) == {"api_port": PORT}, accepted
        assert len(execs) == int(args.verify_exec), execs
        if args.verify_exec:
            assert execs[0]["pid"] and execs[0]["comm"] == "true", execs
            assert execs[0]["ip"] == "", execs
        print(json.dumps({
            "result": "REDIS-ACCEPT-OK", "peer": peer,
            "conn_rate_10s": row["conn_rate_10s"],
            "syn_rate_10s": row["syn_rate_10s"],
            "available_fields": sorted(fields),
            "host_available_fields": sorted(host_fields),
            "ip_ttl_ms": r.pttl(keys[1]), "host_ttl_ms": r.pttl(keys[2]),
            "accept_events": len(accepted), "run_id": run_id,
            "unexpected_exec_count": host["unexpected_exec_count"],
            "exec_events": len(execs),
        }, sort_keys=True), flush=True)
    finally:
        stop_owned_process(sensor)
        stop_owned_process(server)
        if sensor is not None:
            for line in sensor.stdout:
                print(line.rstrip(), flush=True)
        if created:
            # The DB was empty before this test; never FLUSHDB or touch DB 0.
            r.delete(*keys)


if __name__ == "__main__":
    main()
