"""Opt-in real FastAPI/C1 source-IP smoke on an empty scratch Redis DB 15.

Run on the lab VM only, with no API, traffic or DB15 experiment active:
    sudo python3 -m ebpf.tests.smoke_api_netns
    sudo python3 -m ebpf.tests.smoke_api_netns --verify-inbound-bytes
    sudo python3 -m ebpf.tests.smoke_api_netns --verify-egress
Uses ns15 requests; this is not a C4 or load benchmark.
"""

import argparse
import hashlib
import json
import http.client
import pathlib
import socket
import subprocess
import sys
import threading
import time
import os

import redis

from ebpf.tests.smoke_accept_redis import stop_owned_process, wait_for_attachment


ROOT = pathlib.Path(__file__).resolve().parents[2]
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
URL = "redis://127.0.0.1:6379/15"
PEER = "10.20.0.25"
API = "10.20.0.1"
RUN_ID = "sensor-api-netns-smoke"
LOGIN_ACCOUNT = hashlib.sha256(b"user1").hexdigest()
OWN_KEYS = (
    "p20:meta:schema_version",
    "p20:allowlist",
    f"p20:sig:ip:{PEER}", "p20:sig:host", "p20:stream:ebpf_events",
    "p20:stream:waf_decisions", "p20:stream:waf_features",
    f"p20:win:{PEER}", f"p20:shadow:bkt:ip_req:{PEER}",
    f"p20:shadow:bkt:products:{PEER}",
    # /login and /chat observe-mode budgets and app accounting created below.
    f"p20:shadow:bkt:login_ip:{PEER}",
    f"p20:shadow:bkt:login_acct:{LOGIN_ACCOUNT}",
    "p20:shadow:bkt:chat_req:user1", "p20:shadow:bkt:llm_tok:user1",
    "p20:app:usage:total", "p20:app:usage:user1",
)
CLIENT = """
import http.client,json,sys
c=http.client.HTTPConnection(sys.argv[1],8000,timeout=4)
c.request("GET","/products?page=1&per_page=1",headers={"Connection":"close"})
r=c.getresponse()
data=json.loads(r.read())
assert r.status==200 and data["total"]==5000 and len(data["items"])==1,(r.status,data)
print(json.dumps({"http_status":r.status,"products_total":data["total"]}))
c.close()
"""
RAW_CLIENT = """
import http.client,json,socket,sys
request=b"GET /products?page=1&per_page=1 HTTP/1.1\\r\\nHost: 10.20.0.1\\r\\nConnection: close\\r\\n\\r\\n"
with socket.create_connection((sys.argv[1],8000),timeout=4) as s:
    s.sendall(request)
    response=http.client.HTTPResponse(s)
    response.begin()
    data=json.loads(response.read())
    assert response.status==200 and data["total"]==5000 and len(data["items"])==1,(response.status,data)
    print(json.dumps({"http_status":response.status,"products_total":data["total"],
                      "request_bytes":len(request)}))
"""
EGRESS_CLIENT = """
import http.client,json,sys
c=http.client.HTTPConnection(sys.argv[1],8000,timeout=20)
c.request("POST","/login",body=json.dumps({"username":"user1","password":"Passw0rd!1"}),
          headers={"Content-Type":"application/json"})
r=c.getresponse(); login=json.loads(r.read()); assert r.status==200,(r.status,login)
c.close()
c=http.client.HTTPConnection(sys.argv[1],8000,timeout=20)
c.request("POST","/chat",body=json.dumps({"prompt":"hello world","max_output_tokens":8,"agent_steps":1}),
          headers={"Content-Type":"application/json","Authorization":"Bearer "+login["token"]})
r=c.getresponse(); chat=json.loads(r.read()); assert r.status==200,(r.status,chat)
print(json.dumps({"http_status":r.status,"tokens_in":chat["usage"]["tokens_in"],
                  "tokens_out":chat["usage"]["tokens_out"],
                  "agent_steps":chat["agent_steps"]}))
c.close()
"""


def require_lab_network():
    address = subprocess.run(
        ["ip", "netns", "exec", "ns15", "ip", "-4", "-o", "addr", "show"],
        check=True, capture_output=True, text=True,
    ).stdout
    if f"{PEER}/24" not in address:
        raise RuntimeError("ns15 lacks the canonical 10.20.0.25/24 address")
    with socket.socket() as sock:
        sock.bind((API, 0))  # Fail before writing Redis if the bridge is absent.
    if not VENV_PYTHON.is_file():
        raise RuntimeError(f"missing VM app interpreter: {VENV_PYTHON}")


class CountingProxy:
    """Test-only byte counter between the API and its loopback mock.

    It does not modify B's app or mock. Client-to-upstream bytes received
    here are an independent observation of what the API actually sent.
    """

    def __init__(self, listen_addr, upstream_addr):
        self.addr = listen_addr
        self.upstream = upstream_addr
        self.total = 0
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(listen_addr)
        self.sock.listen(128)
        self.sock.settimeout(0.2)

    def start(self):
        threading.Thread(target=self._serve, daemon=True).start()

    def reset(self):
        with self.lock:
            self.total = 0

    def count(self):
        with self.lock:
            return self.total

    def close(self):
        self.stopped.set()
        self.sock.close()

    def _serve(self):
        while not self.stopped.is_set():
            try:
                client, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._pump, args=(client,), daemon=True).start()

    def _pump(self, client):
        try:
            upstream = socket.create_connection(self.upstream, timeout=5)
            upstream.settimeout(None)
        except OSError:
            client.close()
            return

        def forward(src, dst, count_from_client):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    if count_from_client:
                        with self.lock:
                            self.total += len(data)
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        workers = [
            threading.Thread(target=forward, args=(client, upstream, True), daemon=True),
            threading.Thread(target=forward, args=(upstream, client, False), daemon=True),
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        client.close()
        upstream.close()


def listen(host, port):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
        sock.listen(128)
        return sock
    except BaseException:
        sock.close()
        raise


def start_service(module, listener, env):
    return subprocess.Popen(
        [str(VENV_PYTHON), "-u", "-m", "uvicorn", module,
         "--fd", str(listener.fileno()), "--no-proxy-headers",
         "--log-level", "warning"],
        cwd=ROOT, env=env, pass_fds=(listener.fileno(),),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def wait_healthy(proc, host, port, *, api=False):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"service exited early: {proc.stdout.read()}")
        try:
            conn = http.client.HTTPConnection(host, port, timeout=0.5)
            try:
                conn.request("GET", "/health")
                response = conn.getresponse()
                body = json.loads(response.read())
                if response.status == 200 and (not api or body["dependencies"] == {
                        "redis": "ok", "mock_llm": "ok"}):
                    return
            finally:
                conn.close()
        except (OSError, ValueError, KeyError):
            pass
        finally:
            time.sleep(0.1)
    raise RuntimeError(f"service never became healthy on {host}:{port}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--verify-inbound-bytes", action="store_true",
                       help="compare kernel TCP-delivered bytes to one exact HTTP request")
    modes.add_argument("--verify-egress", action="store_true",
                       help="verify API->mock egress bytes/connections with one chat task")
    args = parser.parse_args()
    require_lab_network()
    r = redis.Redis.from_url(URL, decode_responses=True,
                             socket_connect_timeout=2, socket_timeout=2)
    if r.dbsize() != 0:
        raise RuntimeError("DB 15 is not empty; refusing to modify it")
    env = {**os.environ, "REDIS_URL": URL, "WAF_MODE": "observe",
           "WAF_BUCKETS": "1", "WAF_HONEYPOT": "1", "WAF_ML": "0",
           "WAF_EBPF_SIGNALS": "0", "WAF_SPEND_CAP_MICROUSD": "0",
           "WAF_WALLET_CAPACITY": "0", "WAF_WALLET_REFILL_PER_S": "0",
           "WAF_SPEND_PERIOD": "", "P20_RUN_ID": RUN_ID,
           "LLM_BASE_URL": "http://127.0.0.1:8001"}
    processes = []
    listeners = []
    proxy = None
    try:
        # Canonical management source, not an attacker; health should bypass C1.
        r.sadd("p20:allowlist", API)
        # The mock listens on an ephemeral loopback port behind a test-only
        # counting proxy on the contracted 8001. Reserve every socket; never
        # stop or reuse an unrelated server.
        mock_listener = listen("127.0.0.1", 0)
        mock_port = mock_listener.getsockname()[1]
        proxy = CountingProxy(("127.0.0.1", 8001), ("127.0.0.1", mock_port))
        proxy.start()
        listeners.append(mock_listener)
        listeners.append(listen(API, 8000))
        for module, listener in zip(("app.llm_service:app", "app.main:app"), listeners):
            processes.append(start_service(module, listener, env))
        for listener in listeners:
            listener.close()
        listeners.clear()
        wait_healthy(processes[0], "127.0.0.1", mock_port)
        wait_healthy(processes[1], API, 8000, api=True)
        proxy.reset()  # Count only API traffic after the health checks.
        route = "/chat" if args.verify_egress else "/products"
        script = EGRESS_CLIENT if args.verify_egress else (
            RAW_CLIENT if args.verify_inbound_bytes else CLIENT)
        sensor = subprocess.Popen([
            sys.executable, "-u", "-m", "ebpf.sensor", "--pid", str(processes[1].pid),
            "--api-port", "8000", "--mock-port", "8001", "--run-id", RUN_ID,
            "--redis-url", URL, "--duration", "40" if args.verify_egress else "25",
        ], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        processes.append(sensor)
        wait_for_attachment(sensor)
        time.sleep(11)  # The health gate requires a full ten-second window.
        if sensor.poll() is not None or processes[1].poll() is not None:
            raise RuntimeError("API or sensor exited before the request")
        client = subprocess.run(
            ["ip", "netns", "exec", "ns15", sys.executable, "-c", script, API],
            check=True, capture_output=True, text=True, timeout=40,
        )
        print(client.stdout.strip(), flush=True)
        client_result = json.loads(client.stdout)
        wanted = 2 if args.verify_egress else 1
        deadline = time.monotonic() + 10
        row = {}
        decision = {}
        host = {}
        while time.monotonic() < deadline:
            row = r.hgetall(f"p20:sig:ip:{PEER}")
            host = r.hgetall("p20:sig:host")
            decisions = [fields for _, fields in r.xrange("p20:stream:waf_decisions")]
            matching = [fields for fields in decisions
                        if fields.get("ip") == PEER and fields.get("route") == route]
            if matching:
                decision = matching[-1]
            ready = int(row.get("conn_rate_10s", "0")) >= wanted and decision
            if args.verify_egress:
                # Wait for a publish that already contains every byte the
                # counting proxy saw, so the event-stream sum cannot lag it.
                ready = (ready and proxy.count() > 0
                         and int(host.get("egress_bytes_llm_60s", "0")) == proxy.count())
            if ready:
                break
            time.sleep(0.1)
        assert int(row.get("conn_rate_10s", "0")) == wanted, row
        assert int(row.get("syn_rate_10s", "0")) >= 1, row
        assert set(json.loads(row["available_fields"])) == {
            "conn_rate_1s", "conn_rate_10s", "syn_rate_10s",
            "bytes_in_10s"}, row
        assert decision["mode"] == "observe" and decision["run_id"] == RUN_ID, decision
        assert decision["ip"] == PEER and decision["sensor_status"] == "not_used", decision
        events = [fields for _, fields in r.xrange("p20:stream:ebpf_events")]
        accepted = [e for e in events if e.get("type") == "accept" and e.get("ip") == PEER]
        syns = [e for e in events if e.get("type") == "syn" and e.get("ip") == PEER]
        assert len(accepted) == wanted and all(
            e["pid"] == str(processes[1].pid) for e in accepted), events
        assert syns and all(e["pid"] == "" for e in syns), events
        assert int(row["bytes_in_10s"]) > 0, row
        egress_checked = proxy_bytes = None
        if args.verify_egress:
            egress = [e for e in events if e.get("type") == "egress_bytes"
                      and json.loads(e["detail"])["dst_port"] == 8001]
            assert egress and all(e["pid"] == str(processes[1].pid) for e in egress), events
            assert all(e["ip"] == "" for e in egress), events
            egress_checked = sum(json.loads(e["detail"])["tcp_payload_bytes"]
                                 for e in egress)
            proxy_bytes = proxy.count()
            assert egress_checked > 0 and egress_checked == proxy_bytes, {
                "kernel_egress": egress_checked, "proxy_received": proxy_bytes}
            assert set(json.loads(host["available_fields"])) >= {
                "egress_bytes_llm_60s", "egress_conns_llm_60s"}, host
            assert int(host["egress_bytes_llm_60s"]) == proxy_bytes, {
                "client_result": client_result, "proxy_received": proxy_bytes, "host": host}
            assert int(host["egress_conns_llm_60s"]) >= 1, host
            assert 0 < r.pttl("p20:sig:host") <= 120_000, host
        assert 0 < r.pttl(f"p20:sig:ip:{PEER}") <= 60_000, row
        print(json.dumps({
            "result": "API-NETNS-OK", "asgi_ip": decision["ip"],
            "kernel_peer": accepted[0]["ip"], "syn_events": len(syns),
            "accept_events": len(accepted), "conn_rate_10s": row["conn_rate_10s"],
            "syn_rate_10s": row["syn_rate_10s"], "mode": decision["mode"],
            "run_id": RUN_ID, "route": route,
            "inbound_bytes": row["bytes_in_10s"],
            "egress_bytes_checked": egress_checked,
            "egress_bytes_proxy": proxy_bytes,
            "egress_bytes_llm_60s": host.get("egress_bytes_llm_60s"),
            "egress_conns_llm_60s": host.get("egress_conns_llm_60s"),
        }, sort_keys=True), flush=True)
    finally:
        for listener in listeners:
            listener.close()
        for proc in reversed(processes):
            stop_owned_process(proc)
            for line in proc.stdout:
                print(line.rstrip(), flush=True)
        if proxy is not None:
            proxy.close()
        # Only this single empty-DB run's session and known keys; never FLUSHDB.
        # Login is the only session writer here, so its random-token key is ours.
        session_keys = list(r.scan_iter(match="p20:app:session:*"))
        r.delete(*OWN_KEYS, *session_keys)
        print(json.dumps({"scratch_db15_size_after": r.dbsize(),
                          "session_keys_deleted": len(session_keys)}), flush=True)


if __name__ == "__main__":
    main()
