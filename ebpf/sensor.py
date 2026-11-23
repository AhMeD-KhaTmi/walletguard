"""Observe real app-scoped connect(), accepted sockets and descendant execve.

Only inet_csk_accept on the API process/port contributes to Redis connection
signals; SYN packets are separate. An outbound connect syscall (including
EINPROGRESS) is not accepted. API receive bytes become available only
after the attached receive probe has observed a full healthy window.
"""

import argparse
import json
import pathlib
import socket
import struct
import time

from ebpf.signals import RollingSignals, SignalPublisher


SOURCE = pathlib.Path(__file__).with_name("bpf") / "sensor.c"


def event_record(event, run_id: str, *, utc_ms: int | None = None,
                 monotonic_ns: int | None = None) -> dict[str, str]:
    kind = int(event.kind)
    if kind not in (1, 2, 3, 4, 5, 6, 7):
        raise ValueError(f"unknown kernel event kind: {kind}")
    destination = socket.inet_ntoa(struct.pack("=I", int(event.ip))) if kind in (1, 6) else ""
    peer = socket.inet_ntoa(struct.pack("=I", int(event.ip))) if kind in (3, 4, 5, 7) else ""
    detail = ({"dst_ip": destination, "dst_port": int(event.port),
               "connect_result": int(event.result)}
              if kind == 1 else
              {"api_port": int(event.port)} if kind == 3 else
              {"api_port": int(event.port), "retransmissions": "included"} if kind == 4 else
              {"api_port": int(event.port), "tcp_payload_bytes": int(event.result),
               "retransmissions": "excluded (TCP delivered)"} if kind == 5 else
              {"dst_ip": destination, "dst_port": int(event.port),
               "tcp_payload_bytes": int(event.result)} if kind == 6 else
              {"api_port": int(event.port),
               "definition": "local TCP reset for inbound SYN"} if kind == 7 else
              {"attribution": "API descendant exec"})
    utc_ms = time.time_ns() // 1_000_000 if utc_ms is None else utc_ms
    monotonic_ns = time.monotonic_ns() if monotonic_ns is None else monotonic_ns
    # Kernel ktime and Python monotonic use the same monotonic clock on Linux.
    # Never put a packet destination in the contract's client-source "ip" field.
    event_ms = utc_ms - (monotonic_ns - int(event.ts_ns)) // 1_000_000
    return {
        "type": {1: "connect", 2: "execve", 3: "accept", 4: "syn",
                 5: "inbound_bytes", 6: "egress_bytes", 7: "failed_conn"}[kind],
        "ip": peer,  # observed packet or socket peer; host events stay empty
        "pid": str(int(event.pid)) if kind not in (4, 7) else "",
        "comm": (bytes(event.comm).split(b"\0", 1)[0].decode("utf-8", "replace")
                 if kind not in (4, 7) else ""),
        "detail": json.dumps(detail, sort_keys=True, separators=(",", ":")),
        "ts_ms": str(event_ms),
        "run_id": run_id,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True, help="API process host PID")
    parser.add_argument("--mock-port", type=int, default=8001)
    parser.add_argument("--api-port", type=int, default=8000)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--redis-url", help="opt-in event stream; must use schema v2")
    parser.add_argument("--duration", type=float, default=0,
                        help="seconds to observe (0 means until Ctrl+C)")
    parser.add_argument("--perf-page-cnt", type=int, default=64,
                        help="test-only perf ring size per CPU in pages (default 64)")
    args = parser.parse_args()
    if args.pid <= 1 or not pathlib.Path(f"/proc/{args.pid}").is_dir():
        parser.error("--pid must be a currently running host process")
    if (not 1 <= args.mock_port <= 65535 or not 1 <= args.api_port <= 65535
            or args.duration < 0):
        parser.error("invalid API/mock port or duration")
    if (not 1 <= args.perf_page_cnt <= 1024
            or args.perf_page_cnt & (args.perf_page_cnt - 1)):
        parser.error("--perf-page-cnt must be a power of two between 1 and 1024")
    if not args.run_id or len(args.run_id) > 128:
        parser.error("--run-id must be nonempty and at most 128 characters")

    # BCC is supplied by the system Python on the Ubuntu VM, not by .venv.
    from bcc import BPF

    client = None
    if args.redis_url:
        import redis
        client = redis.Redis.from_url(args.redis_url, decode_responses=True,
                                      socket_connect_timeout=2, socket_timeout=2)
        if client.get("p20:meta:schema_version") != "2":
            raise RuntimeError("Redis schema v2 is required for kernel events")
    bpf = BPF(src_file=str(SOURCE), cflags=[
        f"-DAPI_PID={args.pid}", f"-DMOCK_PORT={args.mock_port}",
        f"-DAPI_PORT={args.api_port}",
    ])
    bpf.attach_kretprobe(event="inet_csk_accept", fn_name="on_accept")
    syn_attached = False
    try:
        bpf.attach_kprobe(event="tcp_v4_rcv", fn_name="on_syn")
        syn_attached = True
    except Exception as exc:  # Optional probe: absence cannot become measured zero.
        print(json.dumps({"syn_probe": "unavailable", "reason": str(exc)}), flush=True)
    failed_conn_attached = False
    try:
        bpf.attach_kprobe(event="tcp_v4_send_reset", fn_name="on_failed_syn")
        failed_conn_attached = True
    except Exception as exc:
        print(json.dumps({"failed_conn_probe": "unavailable", "reason": str(exc)}),
              flush=True)
    inbound_bytes_attached = False
    try:
        bpf.attach_kprobe(event="tcp_cleanup_rbuf", fn_name="on_inbound_bytes")
        inbound_bytes_attached = True
    except Exception as exc:
        print(json.dumps({"inbound_bytes_probe": "unavailable", "reason": str(exc)}),
              flush=True)
    egress_bytes_attached = False
    try:
        # Attach return first. If entry attachment fails, no pending map item
        # can exist and the return probe cannot emit a partial measurement.
        bpf.attach_kretprobe(event="tcp_sendmsg", fn_name="on_egress_return")
        bpf.attach_kprobe(event="tcp_sendmsg", fn_name="on_egress_enter")
        egress_bytes_attached = True
    except Exception as exc:
        print(json.dumps({"egress_bytes_probe": "unavailable", "reason": str(exc)}),
              flush=True)
    signals = RollingSignals()
    publisher = SignalPublisher(client, signals) if client is not None else None
    attached_ns = time.monotonic_ns()
    loss_ns = attached_ns
    lost_events = 0
    reported_drops = 0
    perf_lost_records = 0

    def receive(cpu, data, size):
        event = bpf["events"].event(data)
        record = event_record(event, args.run_id)
        if publisher is not None and int(event.kind) in (1, 2, 3, 4, 5, 6, 7):
            channel = {1: "egress_conn", 2: "unexpected_exec",
                       3: "accepted", 4: "syn",
                       5: "inbound_bytes", 6: "egress_bytes",
                       7: "failed"}[int(event.kind)]
            if int(event.kind) in (1, 2, 6):
                # Host-scoped: the mock destination is never a client identity.
                signals.add(channel, when_ns=int(event.ts_ns),
                            value=int(event.result) if int(event.kind) == 6 else 1)
            else:
                signals.add(channel, ip=record["ip"], when_ns=int(event.ts_ns),
                            value=int(event.result) if int(event.kind) == 5 else 1)
        print(json.dumps(record, sort_keys=True), flush=True)
        if client is not None:
            client.xadd("p20:stream:ebpf_events", record, maxlen=10_000,
                        approximate=True)

    def lost(count):
        nonlocal perf_lost_records, loss_ns
        perf_lost_records += count
        loss_ns = time.monotonic_ns()
        print(json.dumps({"perf_lost_records": perf_lost_records,
                          "run_id": args.run_id}), flush=True)

    bpf["events"].open_perf_buffer(receive, lost_cb=lost,
                                   page_cnt=args.perf_page_cnt)
    print(json.dumps({"sensor": "attached", "pid": args.pid,
                      "api_port": args.api_port, "mock_port": args.mock_port,
                      "perf_page_cnt": args.perf_page_cnt,
                      "loss_detector": "perf_submit_return",
                      "run_id": args.run_id,
                      "syn_probe": "attached" if syn_attached else "unavailable",
                      "failed_conn_probe": "attached" if failed_conn_attached else "unavailable",
                      "inbound_bytes_probe": "attached" if inbound_bytes_attached else "unavailable",
                      "egress_bytes_probe": "attached" if egress_bytes_attached else "unavailable",
                      "unexpected_exec_policy": "all post-attach API-descendant execs",
                      "signals": "accepted TCP, SYN, receive, mock-egress and unexpected-exec after a full 10s healthy window"
                      if publisher is not None else "disabled (no Redis URL)"}),
          flush=True)
    end = time.monotonic() + args.duration if args.duration else None
    next_publish = time.monotonic() + 1
    try:
        while end is None or time.monotonic() < end:
            bpf.perf_buffer_poll(timeout=200)
            # bpf_perf_event_output failures are counted in the probe itself:
            # the kernel does not emit PERF_RECORD_LOST for this path.
            drops = bpf["submit_dropped"][0].value
            if drops > reported_drops:
                lost_events += drops - reported_drops
                reported_drops = drops
                loss_ns = time.monotonic_ns()
                print(json.dumps({"lost_perf_events": lost_events,
                                  "run_id": args.run_id}), flush=True)
            now = time.monotonic()
            if publisher is not None and now >= next_publish:
                now_ns = time.monotonic_ns()
                # A complete 10s window must pass after attach or any perf loss.
                if now_ns - max(attached_ns, loss_ns) >= 10_000_000_000:
                    publisher.publish(healthy={"accepted"}
                                      | ({"syn"} if syn_attached else set())
                                      | ({"failed"} if failed_conn_attached else set())
                                      | ({"inbound_bytes"} if inbound_bytes_attached else set())
                                      | ({"egress_conn", "egress_bytes"}
                                         if egress_bytes_attached else set())
                                      | {"unexpected_exec"},
                                      now_ns=now_ns)
                else:
                    publisher.publish(healthy=set(), now_ns=now_ns)
                next_publish = now + 1
    except KeyboardInterrupt:
        pass
    print(json.dumps({"sensor": "stopped", "lost_perf_events": lost_events,
                      "perf_lost_records": perf_lost_records}),
          flush=True)


if __name__ == "__main__":
    main()
