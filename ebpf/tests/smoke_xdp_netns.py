"""Opt-in XDP ban-enforcement smoke on the canonical ns15 bridge path.

Run with root on the prepared lab VM, only while DB15 is empty:
    sudo python3 -m ebpf.tests.smoke_xdp_netns

It starts an owned host listener on 10.20.0.1:18006, attaches the real XDP
loader to p20br0, and checks:

* pub/sub ban installation (time to drop) and a timed-out client, not a reset;
* per-IP kernel drop telemetry in ``p20:xdp:drops``;
* no collateral for a control namespace, and no accept reaching the listener;
* missed-pubsub reconciliation in both directions (add without PUBLISH,
  delete without PUBLISH);
* allowlist removal when an address is newly allowlisted, and re-installation
  after it is removed while the ban still exists;
* local/management addresses are never installed;
* kernel-side TTL expiry after SIGKILL: the XDP program is still attached but
  the client succeeds once the ban TTL passes;
* a restarted loader reconciles the stale map away while preserving published
  drop counters;
* graceful stop detaches the program.

This is not a C4 performance or production-rate claim. All keys live in DB15
and are removed at the end.
"""

import json
import os
import select
import socket
import subprocess
import sys
import threading
import time

import redis

from ebpf.tests.smoke_accept_redis import stop_owned_process
from ebpf.xdp_ban import xdp_attachment

URL = "redis://127.0.0.1:6379/15"
IFACE = "p20br0"
PORT = 18006
BIND = "10.20.0.1"
BANNED = "10.20.0.25"
BANNED_NS = "ns15"
CONTROL = "10.20.0.11"
CONTROL_NS = "ns1"
MANAGEMENT = "10.20.0.1"
BAN_KEY = f"p20:ban:{BANNED}"
MANAGEMENT_BAN_KEY = f"p20:ban:{MANAGEMENT}"
ALLOWLIST = "p20:allowlist"
DROPS = "p20:xdp:drops"
SCHEMA = "p20:meta:schema_version"
CHANNEL = "p20:ch:ban"
RUN_ID = "xdp-ban-netns-smoke"

SERVER = """
import json,socket,sys,threading
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[1],int(sys.argv[2])))
s.listen(64)
print("READY",flush=True)
def handle(c):
    try:
        c.settimeout(2)
        c.recv(64)
        c.sendall(b"OK")
    except OSError:
        pass
    finally:
        c.close()
while True:
    c,a=s.accept()
    print(json.dumps({"accept":a[0]}),flush=True)
    threading.Thread(target=handle,args=(c,),daemon=True).start()
"""

CLIENT = """
import json,socket,sys,time
t=time.monotonic()
try:
    with socket.create_connection((sys.argv[1],int(sys.argv[2])),
                                  timeout=float(sys.argv[3])) as s:
        s.sendall(b"ping")
        data=s.recv(8)
    out={"connected":True,"reply":data.decode("utf-8","replace")}
except Exception as e:
    out={"connected":False,"error":type(e).__name__}
out["ms"]=round((time.monotonic()-t)*1000,1)
print(json.dumps(out),flush=True)
"""


class Tail:
    """Drain a loader's stdout without ever blocking the test process."""

    def __init__(self, proc):
        self.proc = proc
        self.lines = []
        self.events = []
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        for line in self.proc.stdout:
            text = line.rstrip()
            self.lines.append(text)
            try:
                event = json.loads(text)
            except ValueError:
                continue
            self.events.append((time.monotonic(), event))

    def wait_event(self, predicate, timeout, label, start=0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for stamp, event in list(self.events[start:]):
                if predicate(event):
                    return stamp, event
            if self.proc.poll() is not None:
                break
            time.sleep(0.02)
        raise RuntimeError(
            f"loader event '{label}' not observed; recent output: "
            f"{self.lines[-8:]}")

    def attach(self, timeout=30):
        return self.wait_event(
            lambda event: event.get("xdp") == "attached", timeout, "attach")[1]


def attempt(ns, timeout=1.5):
    result = subprocess.run(
        ["ip", "netns", "exec", ns, sys.executable, "-c", CLIENT,
         BIND, str(PORT), str(timeout)],
        capture_output=True, text=True, timeout=timeout + 10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"client in {ns} failed: {result.stderr.strip()}")
    return json.loads(result.stdout.strip().splitlines()[-1])


def ban_payload(ip, ttl_s=30):
    return json.dumps({
        "ip": ip, "reason": "xdp-smoke", "source": "waf",
        "ts_ms": int(time.time() * 1000), "ttl_s": ttl_s,
    }, sort_keys=True)


def publish_ban(r, ip, ttl_s=30):
    r.set(f"p20:ban:{ip}", ban_payload(ip, ttl_s), ex=ttl_s)
    r.publish(CHANNEL, json.dumps(
        {"op": "add", "ip": ip, "ttl_s": ttl_s, "reason": "xdp-smoke"},
        sort_keys=True))


def wait_drops(r, predicate, timeout, label):
    deadline = time.monotonic() + timeout
    last = {}
    while time.monotonic() < deadline:
        last = r.hgetall(DROPS)
        if predicate(last):
            return last
        time.sleep(0.02)
    raise RuntimeError(f"drop telemetry '{label}' not met: {last}")


def wait_absent(r, key, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if r.exists(key) == 0:
            return
        time.sleep(0.05)
    raise RuntimeError(f"{key} still exists after {timeout}s")


def require_lab_network():
    if os.geteuid() != 0:
        raise RuntimeError("XDP attach requires root; run with sudo")
    for ns, ip in ((BANNED_NS, BANNED), (CONTROL_NS, CONTROL)):
        output = subprocess.run(
            ["ip", "netns", "exec", ns, "ip", "-4", "-o", "addr", "show"],
            check=True, capture_output=True, text=True,
        ).stdout
        if f"{ip}/24" not in output:
            raise RuntimeError(f"{ns} lacks the canonical {ip}/24 address")
    output = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "dev", IFACE],
        check=True, capture_output=True, text=True,
    ).stdout
    if f"{BIND}/24" not in output:
        raise RuntimeError(f"{IFACE} lacks the canonical {BIND}/24 address")
    if xdp_attachment(IFACE):
        raise RuntimeError(
            f"{IFACE} already has an XDP program; refusing to take it over")
    with socket.socket() as reservation:
        reservation.bind((BIND, PORT))


def main():
    require_lab_network()
    r = redis.Redis.from_url(
        URL, decode_responses=True, socket_connect_timeout=2,
        socket_timeout=2)
    if r.dbsize() != 0:
        raise RuntimeError("DB 15 is not empty; refusing to modify it")
    created_schema = False
    server = None
    loader = None
    tails = []
    accepts = []
    try:
        if not r.set(SCHEMA, "2", nx=True):
            raise RuntimeError("schema key appeared concurrently; aborting")
        created_schema = True

        server = subprocess.Popen(
            [sys.executable, "-u", "-c", SERVER, BIND, str(PORT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        ready, _, _ = select.select([server.stdout], [], [], 5)
        if not ready or server.stdout.readline().strip() != "READY":
            raise RuntimeError(f"listener did not bind {BIND}:{PORT}")

        def drain_server():
            for line in server.stdout:
                try:
                    accepts.append(json.loads(line)["accept"])
                except ValueError:
                    continue

        threading.Thread(target=drain_server, daemon=True).start()

        baseline = attempt(BANNED_NS)
        control = attempt(CONTROL_NS)
        assert baseline["connected"] and baseline["reply"] == "OK", baseline
        assert control["connected"] and control["reply"] == "OK", control

        loader = subprocess.Popen([
            sys.executable, "-u", "-m", "ebpf.xdp_ban",
            "--iface", IFACE, "--redis-url", URL, "--run-id", RUN_ID,
            "--reconcile-interval", "0.5", "--publish-interval", "0.5",
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        tail = Tail(loader)
        tails.append(tail)
        attached = tail.attach()
        print(json.dumps(attached, sort_keys=True), flush=True)
        wait_drops(r, lambda d: d.get("map_size") == "0", 5, "initial map")

        # 1. Pub/sub add: immediate reconcile, no SYN reaches the listener.
        accepts_before = accepts.count(BANNED)
        started = time.monotonic()
        publish_ban(r, BANNED)
        stamp, _ = tail.wait_event(
            lambda event: (event.get("xdp") == "sync"
                           and BANNED in event.get("added", [])),
            3, "ban added")
        sync_ms = round((stamp - started) * 1000, 1)
        assert sync_ms <= 1000, sync_ms
        banned = attempt(BANNED_NS, timeout=1.2)
        assert not banned["connected"], banned
        assert banned["error"] in {"TimeoutError", "timeout"}, banned
        drops = wait_drops(
            r, lambda d: int(d.get("total_dropped_pkts", "0")) >= 1
            and int(d.get(f"dropped_pkts:{BANNED}", "0")) >= 1,
            4, "first per-IP drop")
        assert drops["map_size"] == "1", drops
        assert accepts.count(BANNED) == accepts_before, (
            "a dropped SYN reached the listener", accepts)
        control = attempt(CONTROL_NS)
        assert control["connected"], control
        assert f"dropped_pkts:{CONTROL}" not in drops, drops
        print(json.dumps({
            "step": "pubsub", "sync_ms": sync_ms, "banned": banned,
            "control": control, "drops": drops,
        }, sort_keys=True), flush=True)

        # 2. Missed pub/sub: periodic reconcile covers both directions.
        r.delete(BAN_KEY)
        wait_drops(r, lambda d: d.get("map_size") == "0", 3,
                   "unban without pubsub")
        assert attempt(BANNED_NS)["connected"]
        r.set(BAN_KEY, ban_payload(BANNED), ex=30)
        wait_drops(r, lambda d: d.get("map_size") == "1", 3,
                   "ban without pubsub")
        banned = attempt(BANNED_NS, timeout=1.2)
        assert not banned["connected"], banned
        print(json.dumps({"step": "missed_pubsub", "banned": banned},
                         sort_keys=True), flush=True)

        # 3. Allowlist removes an installed entry; removal restores it.
        r.sadd(ALLOWLIST, BANNED)
        wait_drops(r, lambda d: d.get("map_size") == "0", 3,
                   "allowlisted removal")
        assert attempt(BANNED_NS)["connected"]
        r.srem(ALLOWLIST, BANNED)
        wait_drops(r, lambda d: d.get("map_size") == "1", 3,
                   "allowlist removal restores ban")
        banned = attempt(BANNED_NS, timeout=1.2)
        assert not banned["connected"], banned
        print(json.dumps({"step": "allowlist", "banned": banned},
                         sort_keys=True), flush=True)

        # 4. A ban for a local/management address is never installed.
        publish_ban(r, MANAGEMENT, ttl_s=5)
        time.sleep(1.2)
        drops = r.hgetall(DROPS)
        assert drops.get("map_size") == "1", drops
        assert f"dropped_pkts:{MANAGEMENT}" not in drops, drops
        assert attempt(CONTROL_NS)["connected"]
        r.delete(MANAGEMENT_BAN_KEY)
        print(json.dumps({"step": "local_exclusion", "drops": drops},
                         sort_keys=True), flush=True)

        # 5. Kernel-side TTL expiry with the loader dead (SIGKILL).
        assert r.expire(BAN_KEY, 3), "ban key was already gone before expiry test"
        refresh_marks = len(tail.events)
        tail.wait_event(
            lambda event: (event.get("xdp") == "sync"
                           and BANNED in event.get("refreshed", [])),
            3, "shortened TTL refresh", start=refresh_marks)
        time.sleep(0.6)  # let one publish include the pre-kill counters
        before_kill = r.hgetall(DROPS)
        loader.kill()
        loader.wait(timeout=5)
        still_attached = xdp_attachment(IFACE)
        assert still_attached, "SIGKILL unexpectedly detached the XDP program"
        wait_absent(r, BAN_KEY, 6)
        time.sleep(0.3)  # outlast the millisecond-rounded monotonic deadline
        expired_client = attempt(BANNED_NS, timeout=2)
        assert expired_client["connected"], expired_client
        assert r.exists(BAN_KEY) == 0
        print(json.dumps({
            "step": "expiry_agent_dead", "xdp_link": still_attached,
            "before_kill": before_kill, "expired_client": expired_client,
        }, sort_keys=True), flush=True)

        # 6. Restart reconciles the stale map away, preserving published totals.
        loader = subprocess.Popen([
            sys.executable, "-u", "-m", "ebpf.xdp_ban",
            "--iface", IFACE, "--redis-url", URL, "--run-id", RUN_ID,
            "--reconcile-interval", "0.5", "--publish-interval", "0.5",
            "--replace-existing", "--keep-drops",
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        tail = Tail(loader)
        tails.append(tail)
        restarted = tail.attach()
        restarted_drops = wait_drops(
            r, lambda d: d.get("map_size") == "0", 5, "restart reconcile")
        assert int(restarted_drops["total_dropped_pkts"]) >= int(
            before_kill["total_dropped_pkts"]), restarted_drops
        assert int(restarted_drops[f"dropped_pkts:{BANNED}"]) >= int(
            before_kill[f"dropped_pkts:{BANNED}"]), restarted_drops
        assert attempt(BANNED_NS)["connected"]

        # 7. Graceful stop detaches; traffic is unaffected afterwards.
        loader.terminate()
        loader.wait(timeout=10)
        assert not xdp_attachment(IFACE), xdp_attachment(IFACE)
        assert attempt(BANNED_NS)["connected"]
        print(json.dumps({
            "step": "restart_and_stop", "restarted": restarted,
            "drops": restarted_drops, "xdp_link": xdp_attachment(IFACE),
        }, sort_keys=True), flush=True)

        print(json.dumps({
            "result": "XDP-BAN-OK",
            "iface": IFACE,
            "mode": attached["mode"],
            "attach_failures": attached.get("attach_failures", {}),
            "sync_ms": sync_ms,
            "accepted_sources": {ip: accepts.count(ip)
                                 for ip in sorted(set(accepts))},
            "run_id": RUN_ID,
        }, sort_keys=True), flush=True)
    finally:
        stop_owned_process(loader)
        stop_owned_process(server)
        if xdp_attachment(IFACE):
            subprocess.run(["ip", "link", "set", "dev", IFACE, "xdp", "off"],
                           check=False, capture_output=True)
        for tail in tails:
            tail.thread.join(timeout=2)
        if tails:
            other = []
            for line in tails[-1].lines:
                try:
                    kind = json.loads(line).get("xdp")
                except ValueError:
                    kind = None
                if kind not in {"attached", "sync"}:
                    other.append(line)
            print(json.dumps({
                "loader_lines": len(tails[-1].lines),
                "loader_other_lines": other[-10:],
                "attach_failure_lines": [
                    line for line in tails[0].lines
                    if "xdp_attach_attempt" in line][:4],
            }, sort_keys=True), flush=True)
        for key in list(r.scan_iter("p20:ban:*")) + [ALLOWLIST, DROPS]:
            if created_schema:
                r.delete(key)
        if created_schema:
            r.delete(SCHEMA)
        print(json.dumps({"scratch_db15_size_after": r.dbsize()}), flush=True)


if __name__ == "__main__":
    main()
