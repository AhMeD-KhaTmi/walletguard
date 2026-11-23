# Member A kernel sensor — work in progress

Follow `MASTER_PLAN.md` sections 3.1, 6 and 8 and `contract/redis_schema.md`
version 2. This is the independent Member A kernel branch, not a C4 result.
XDP ban enforcement is documented separately in
[`XDP_ENFORCEMENT.md`](XDP_ENFORCEMENT.md).

## Verification boundary (2026-11-20)

The Ubuntu 24.04.5 VM has kernel `6.8.0-149-generic`, BTF, BCC, bpftool 7.4,
clang 18, nftables 1.0.9 and tc 6.1. A standalone BCC execve kprobe was loaded
and emitted one event (`BCC-PROBE-ATTACHED`, `BCC-EVENT-OBSERVED`). This only
proves the toolchain and probe loading, **not** application attribution, real
signals, Redis publication, or any XDP drop.

`ebpf/signals.py` is the first stage of the producer. The BCC sensor's
connect/exec event probes passed one controlled Python process test.
The API-PID/port-scoped `inet_csk_accept` probe and its
connection-count-to-Redis integration passed controlled loopback and
namespace smokes. The separate `tcp_v4_rcv` probe captured a real SYN
alongside one accepted socket in each. After restoring the canonical
bridge/namespaces, the real FastAPI/C1 observe-only smoke returned 200 for
one ns15 `/products` request: B's ASGI decision IP, the kernel SYN and
the accepted socket in API PID3339 all identified 10.20.0.25.
The three implemented IP fields were available; DB15 returned to size
zero. This does **not** verify high-load retransmission behavior, B's
consumption of signals or C4.

The sensor scopes `connect()` to the configured API process and port 8001
(including loopback). Its explicit execution policy treats every exec by a
descendant forked from the API **after attachment** as unexpected; descendants
already alive at attachment are outside this attribution and are not backfilled.
The target API PID itself is not called a descendant. A connect syscall
returning EINPROGRESS is **not** proof of a
completed TCP connection. The contract's `ip` is blank for these host-level
events; connect destination IPv4/port and syscall result go in sanitized
`detail`. It never reads request bodies, credentials or prompts. Runtime
records are optional; `--redis-url` requires Redis schema v2 before writing
the bounded `p20:stream:ebpf_events`. Process descendants already running
before attachment are not tracked. Event clock translation and loss handling
require VM checks before calling this reliable telemetry.

The accepted-connection probe runs only in the target API PID at local port
8000, reads the accepted IPv4 peer from the returned socket, and emits a
separate `accept` event. It is not an independently measured SYN, failed
connect or TCP byte count. With `--redis-url`, its `conn_rate_1s/10s`
can become available after a complete ten-second window without perf losses;
SYN and inbound bytes require their own attached hooks and healthy window.

`on_accept` is a kretprobe. A return probe can only fire for an invocation
whose entry was hooked, so an `accept()`/`inet_csk_accept` call already
blocked at attach time is **not observed when it returns**. That costs exactly
one accept event: whichever connection satisfies the pending call. The VM load
smoke reproduced this three times (99 accepts for 100 accepted connections,
with 100 SYN and 100 received-byte events and no perf loss). Operational rule:
attach while the API is not in its accept loop, or make exactly one warm-up
request after attach and before the measurement window; the smoke now gates
its listener's accept loop on attachment instead.

Failed-connect is defined narrowly below; unexpected exec and API-to-mock
egress is a separate, host-scoped probe. The `tcp_v4_rcv`
probe filters incoming IPv4 SYN packets
by destination API port independently of the API process; unlike the
accepted socket it runs in a packet context and **cannot claim a PID**.
It includes SYN retransmissions and makes `syn_rate_10s` available only
if the hook attaches and a complete no-loss window has elapsed. One
loopback and one namespace SYN have been observed in separate smokes, and the
gated 100-connection churn delivered all 100 SYN events to the stream.
SYNs are emitted from packet/softirq context on per-CPU buffers while accepts
come from the API process, so a snapshot published a few milliseconds after a
load can contain every accept but only part of the SYN set (97 of 100 in one
run). The smoke therefore waits for a publish containing all three counts.
The gated 100-connection churn then passed once on the VM with
`conn_rate_10s=100`, `bytes_in_10s=10000` and `syn_rate_10s=100`, so controlled
count/byte consistency is verified for that load. Retransmission exclusion is
still untested: `bytes_in_10s` counts TCP-delivered bytes, while SYN counts
include retransmissions by definition.
Lost perf events suspend
availability for a fresh ten-second window. Per-IP publishing stops 60
seconds after the last observed per-IP event so Redis TTL can expire; no
fictitious zero is refreshed forever. One real API/netns request was
checked; independent load/count accuracy remains pending.

The new, unverified failed-connection probe has one narrow event definition:
an inbound IPv4 SYN to the configured API port for which the local kernel
enters `tcp_v4_send_reset`. It identifies the packet source but cannot claim
an API PID. This covers a local TCP rejection such as a closed listening port;
it does **not** mean failed login, malformed HTTP, client abandonment or every
TCP timeout. If that optional hook cannot attach, `failed_conn_10s` remains
unavailable. `smoke_failed_redis.py` tests one loopback SYN to an owned,
pre-checked closed port and requires one failure, zero accepts and DB15 cleanup.

The new, unverified `smoke_load_netns.py` is a controlled churn check, not a
benchmark or IT-2: 100 ns15 connections each deliver exactly 100 bytes to an
owned listener on 10.20.0.1:18002. It requires exactly 100 accepts and 10,000
delivered bytes, at least 100 SYN observations (retransmissions are included by
definition), zero failed connections/execs/mock egress, and no reported perf
loss. Only loopback/bridge traffic is used, and DB15 must be empty.

Three VM runs failed only the accept-count assertion (99) although the owned
listener accepted 100 connections and received 10,000 bytes. The third run's
diagnostics were decisive: 99 accept / 100 SYN / 100 inbound-byte events, no
perf loss, and the signal row had aged out to zeros before it was read. Cause:
the listener entered `accept()` before the kretprobe attached, so one blocked
invocation was never observed (see the attach-boundary note above). The harness
now gates the accept loop on attachment, drains stdout from attach time, waits
for 100 accept events in the stream, fails fast on a short stream count, and
reads the signal row well inside the window.

The fifth VM run passed the gated check: 100 accept / 100 SYN / 100
inbound-byte events, `conn_rate_10s=100`, `bytes_in_10s=10000`,
`syn_rate_10s=100`, `failed_conn_10s=0`, zero exec/mock egress, no perf loss,
and DB15 zero before and after. Controlled high-load count/byte consistency is
verified once for 100 connections and 10,000 delivered bytes. This is not a
benchmark or IT-2, and it does not exercise retransmissions or sustained load.

`smoke_restart_netns.py` (verified once on the VM) tests lifecycle rather than
traffic: one measured connection, stop the sensor, require the per-IP hash to
expire inside its 60-second TTL instead of staying stale, then start a second
sensor and require host fields to be absent (not zero) until a full 10-second
window, followed by one measured connection. The VM run expired the IP hash
60.1s after the stop (TTL 59.9s at the last publish), left the host key alive
with a bounded TTL, published `available_fields=[]` before the second window,
then measured exactly one accept/SYN/inbound event with `conn_rate_10s=1` and
`bytes_in_10s=100`. A run takes about 90 seconds because of the TTL wait.

`smoke_loss_netns.py` (new, unverified) exercises perf-loss handling: one
refused connection is measured, the sensor is paused, a burst is generated
against a closed API port, and after resume it requires a nonzero
`lost_perf_events`, both hashes to withdraw measured fields (without deleting
the keys or publishing zeros), and fields to return only after a full loss-free
window. To make overflow deterministic the sensor accepts a test-only
`--perf-page-cnt` (default 64, never used in measurement runs); the smoke passes
1 page.

The first VM loss run exposed a real gap: with a 1-page ring the sensor
received only 64 of about 4,002 submitted events, reported no loss, and kept
publishing stale zeros. BCC's `lost_cb` observes `PERF_RECORD_LOST`, which the
kernel does not emit when `bpf_perf_event_output` drops a full ring. Each probe
now uses a helper that checks the submission return and atomically increments a
`submit_dropped` array on failure; userspace publishes `lost_perf_events` from
that counter (and keeps `perf_lost_records` separate for any real LOST record).
The first drop withdraws availability until a full loss-free window has passed.

The rerun passed: 2,000 refusals against the closed API port with a 1-page ring
produced `lost_perf_events=3937`, both hashes were replaced by
`available_fields=[]` while the window was incomplete, and all five IP fields
plus three host fields returned after a loss-free window. The bounded stream
held 33 SYN and 32 failed-connection events, no accept or inbound bytes, and
DB15 returned to zero. This verifies the withdrawal/recovery mechanism for one
forced-overflow case; it is not a production-loss probability or C4 claim.

`ebpf/tests/smoke_accept_redis.py` is an opt-in, **non-benchmark** VM integration
check. It refuses to run unless reserved scratch Redis DB 15 is empty, binds
only 127.0.0.1:18000, verifies one actual accepted peer, schema-v2 available
fields, timestamp, key TTLs and the bounded event stream, then deletes only
its four own keys and stops only its own two processes. Do not run it
concurrently with B's DB-15 tests or other DB-15 experiments; it does not
touch live DB 0, the app, or the measured run archive.

The `--netns` variant, verified once on the VM, instead binds only
10.20.0.1:18000 on the existing lab bridge and invokes one client from
the pre-existing `ns15` probe source 10.20.0.25. It refuses a missing or
misaddressed namespace before changing Redis and checks the observed
SYN/accepted peer against that source. It creates/deletes no network
interfaces or namespaces; other DB15 isolation and cleanup rules apply.
The verified `--verify-exec` option makes that owned target process
fork/exec `/bin/true` only after sensor attachment. It requires one host-scoped
`execve` event (`comm=true`) and `unexpected_exec_count=1`; without the option,
the same attached policy published a measured zero. Both controlled VM runs
passed and returned DB15 to empty.

`ebpf/tests/smoke_api_netns.py` passed once as a real-API
development smoke. It starts owned Uvicorn API/C1 observe at
10.20.0.1:8000 and owned mock at 127.0.0.1:8001 with DB15 only, attaches
the sensor to the actual API PID, then sends one ns15 `/products` request.
It compares B's ASGI decision source IP to the kernel SYN/accepted peer
and checks the available IP fields. It refuses a nonempty DB15, does
not use `run_demo.py` (which binds only loopback), stops its processes,
temporarily allowlists only the canonical bridge management IP in DB15,
and deletes only listed scratch keys. The `/chat` mode also deletes the
temporary login session, observe-mode budget keys and app usage counters
that request creates; wallet lanes are disabled for this kernel test, and
DB15 must still be empty before the run. It does not enable
`WAF_EBPF_SIGNALS` or count as IT-2/C4.
The opt-in `--verify-inbound-bytes` variant passed once before byte
signal publication: one fixed raw HTTP request sent 80 bytes and the
kernel reported 80 TCP-delivered bytes from ns15 in API PID3595.
`bytes_in_10s` remained unavailable in that run. Redis publication of
that measured field is **unverified** pending the next VM run.
The `--verify-egress` variant passed one controlled VM run: it logs in and
sends one `/chat` through ns15 behind a test-only counting proxy on
127.0.0.1:8001. The kernel `egress_bytes` sum, the published
host byte total and the proxy's independently received byte count to
agreed exactly at 248 bytes (202+46). The proxy is local test scaffolding;
it does not modify B's app or mock. This is one smoke, not IT-3's
calibration and separate validation workload.

## Producer boundary

The pure-Python rolling accumulator accepts kernel monotonic timestamps and
explicit positive measurements. Its fields and windows are:

| Channel | Output field | Window | Scope |
|---|---|---:|---|
| `accepted` | `conn_rate_1s`, `conn_rate_10s` | 1s, 10s | API peer IP |
| `syn` | `syn_rate_10s` | 10s | API peer IP |
| `failed` | `failed_conn_10s` | 10s | API peer IP |
| `inbound_bytes` | `bytes_in_10s` | 10s | API peer IP |
| `egress_bytes` | `egress_bytes_llm_60s` | 60s | API to mock |
| `egress_conn` | `egress_conns_llm_60s` | 60s | API to mock |
| `unexpected_exec` | `unexpected_exec_count` | 60s | post-attach API descendant |

`tcp_cleanup_rbuf` attached in an idle VM BCC smoke and measured one
80-byte real API request as an optional API
receive hook. Positive `copied` bytes are filtered by API PID, local
port and accepted IPv4 peer; TCP-delivered payload excludes packets
discarded as retransmissions. The new producer advertises `bytes_in_10s`
only if this hook attaches and a full 10s loss-free window has elapsed.
This publication path and higher-load byte accuracy remain unverified.

The API-to-mock egress probe pairs `tcp_sendmsg`
entry/return in the API PID with destination port 8001 and counts only
bytes accepted by TCP (`tcp_sendmsg` return value), not wire or control
bytes. It is host-scoped: `ip` stays empty, the loopback destination
appears only in `detail`, and it can never pose as a client identity.
`egress_conns_llm_60s` currently reuses the existing scoped connect event
for the mock port. In the verified run it returned EINPROGRESS and later
positive sends corroborated that controlled connection, but the connect
counter alone remains an attempt counter rather than a general completed-
connection detector. Both host fields become available only after this probe
attaches and a complete loss-free window has elapsed, so a failed attach
stays unavailable rather than zero. General connection-count and load
accuracy remain pending.

The unexpected-exec publication path uses the deny-all post-attach descendant
policy above. Its controlled positive and measured-zero VM smokes passed.

The Redis writer requires `p20:meta:schema_version=2`, publishes
`p20:sig:ip:<observed IPv4>` with TTL 60s and `p20:sig:host` with TTL 120s,
and writes UTC epoch `updated_ms`. Only healthy, actually measured channels
appear in `available_fields`; a healthy probe with no events in a complete
window may publish a real zero. Inactive, unimplemented or loss-affected probes
are unavailable, not zero. Entire hash replacement within a Redis transaction
prevents old fields surviving a probe failure. Redis/network errors stop this
publisher; it does not fabricate success or persist stale values.

**Still pending:** failed-connection VM measurement, loss/restart behavior,
independent high-load counters,
TCP byte direction/retransmission semantics, B's signal consumption,
XDP and all joint integration tests. The application currently rejects
C4; this producer must never be used to bypass its readiness check.
