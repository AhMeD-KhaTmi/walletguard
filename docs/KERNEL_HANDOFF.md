# Kernel layer handoff — Member A to Member B

Branch: `codex/member-a-kernel`. Prepared 2026-11-23 from the working checkout
after VM verification. This handoff covers the **sensor and XDP consumer**
only. It is not a C4 result: no real WAF decision has yet been joined to a
kernel drop, and no matched C0–C4 campaign has run.

Read with:

- [`KERNEL_SENSOR.md`](KERNEL_SENSOR.md) — probe boundaries, loss detection,
  what each field does and does not mean.
- [`XDP_ENFORCEMENT.md`](XDP_ENFORCEMENT.md) — ban validation, TTL semantics,
  measured attach mode and drop evidence.
- [`../contract/redis_schema.md`](../contract/redis_schema.md) — schema v2
  keys, fields and TTLs.

## What is in the branch

```
ebpf/sensor.py            app-scoped probes + rolling Redis signal publisher
ebpf/bpf/sensor.c         BCC probes, emit() drop accounting
ebpf/signals.py           rolling windows, availability, schema-v2 writer
ebpf/xdp_ban.py           XDP ban consumer, reconciler, drop telemetry
ebpf/tests/test_*.py      32 unit cases (sensor, signals, XDP helpers)
ebpf/tests/smoke_*.py     7 opt-in VM smokes (DB15 only)
docs/KERNEL_SENSOR.md     sensor evidence and boundaries
docs/XDP_ENFORCEMENT.md   enforcement evidence and limits
```

`app/`, `waf/`, `ml/`, `contract/` are untouched.

## Startup order

1. Redis with schema v2 in the DB you use:
   `p20:meta:schema_version` must equal `2`. The sensor refuses to publish and
   the XDP loader refuses to attach otherwise.
2. Start the API (one worker) and note its host PID.
3. Start the sensor **before measuring**, so `inet_csk_accept` returns are
   observable. If it attaches after the API's accept loop is already blocked in
   `accept()`, send one warm-up request before the measured window.
4. Start the XDP loader only if you want enforcement for that run.

```
# sensor (system Python: BCC bindings + redis-py), run from the repo root
sudo python3 ebpf/sensor.py --pid <API_PID> --run-id <RUN_ID> \
    --redis-url redis://127.0.0.1:6379/0

# optional enforcement
sudo python3 ebpf/xdp_ban.py --iface p20br0 \
    --redis-url redis://127.0.0.1:6379/0 --run-id <RUN_ID>
```

DB15 is used only by the smokes; normal runs use DB0. The sensor's
`--redis-url` is optional, but without it signals are not published (events
still print and no Redis stream is written). The `--duration` flag exists for
bounded experiments; `0` means until Ctrl+C.

## Readiness checks

Sensor startup prints `{"sensor": "attached", ...}` with one status per probe:

- `syn_probe`, `failed_conn_probe`, `inbound_bytes_probe`,
  `egress_bytes_probe` are `attached` or `unavailable`. An `unavailable` probe
  withdraws its channel from every published hash — it is never published as a
  measured zero.
- `loss_detector` is `perf_submit_return`; `lost_perf_events` on stdout is the
  authoritative drop count (the kernel does not emit `PERF_RECORD_LOST` for
  `bpf_perf_event_output`).

XDP startup prints `{"xdp": "attached", "mode": ..., "evidence": ...}`. Expected
on this lab VM: native fails with `Operation not supported` and generic/skb is
selected. Confirm `prog/xdp` with `ip -details link show dev p20br0`, or read
the printed `evidence`.

## Signals you can consume

`p20:sig:ip:<ip>` (TTL 60 s):

| Field | Source | Meaning |
|---|---|---|
| `conn_rate_1s`, `conn_rate_10s` | kretprobe `inet_csk_accept` on the API PID/port | accepted API connections per source IPv4 |
| `syn_rate_10s` | kprobe `tcp_v4_rcv` | inbound IPv4 SYNs to the API port |
| `failed_conn_10s` | kprobe `tcp_v4_send_reset` | inbound SYNs for which the local kernel sent a reset |
| `bytes_in_10s` | kretprobe `tcp_cleanup_rbuf`, API PID | TCP-delivered payload bytes; retransmissions excluded |

`p20:sig:host` (TTL 120 s):

| Field | Source | Meaning |
|---|---|---|
| `egress_bytes_llm_60s` | kretprobe `tcp_sendmsg`, API PID to mock port | payload bytes handed to TCP (headers excluded) |
| `egress_conns_llm_60s` | scoped `connect` syscall | connect **attempts** to the mock port, not completed connections |
| `unexpected_exec_count` | `sched_process_exec` for API descendants | every post-attach descendant exec, counted per exec |

Every hash also carries `updated_ms` and `available_fields` (a JSON array of
the fields that were genuinely measured in this publication). Treat a missing
field as "unknown", never as zero: a stopped sensor lets IP hashes expire
(60 s) and replaces the host hash with one whose `available_fields` excludes
the unhealthy channels. `p20:stream:ebpf_events` (maxlen ~10 000) carries the
per-event records when `--redis-url` is set; it is a debugging stream, not the
signal contract.

## Enforcement you can rely on

`p20:ban:<ip>` remains B's source of truth. The loader never writes bans,
never extends a TTL, and ignores records whose value is not a JSON object with
`ip` equal to the key. It installs the remaining Redis TTL as a kernel
`CLOCK_MONOTONIC` deadline, so a SIGKILLed loader cannot keep an expired ban
dropping. `p20:allowlist` members and every local host IPv4 are excluded on
every reconcile. Pub/sub gives immediate reconciliation; the periodic scan
(default 2 s) covers missed messages, deletion and expiry.

`p20:xdp:drops` is written with `total_dropped_pkts`, `dropped_pkts:<ip>`,
`map_size` and `updated_ms` as absolute values. `--keep-drops` preserves a
published base across a restart.

Two operational notes:

- Attach the loader before the measured window. It replaces an existing XDP
  program only with `--replace-existing`.
- SIGINT/SIGTERM detaches. If a loader was SIGKILLed, either reuse it (the map
  is empty and expired entries stop dropping on their own) or restart with
  `--replace-existing --keep-drops`.

## Verified evidence

Unit tests: `.venv/bin/python -m pytest ebpf/tests -q` → **32 passed**.

| Smoke | Verified result |
|---|---|
| `smoke_accept_redis` | accept/SYN publication, unexpected-exec attribution |
| `smoke_api_netns` | real FastAPI: identity match, inbound 80 B, egress 248 B cross-checked by a proxy |
| `smoke_failed_redis` | one closed-port SYN → `failed_conn_10s=1`, no accept |
| `smoke_load_netns` | 100 connections × 100 B → 100/100/100 counts, no loss |
| `smoke_loss_netns` | forced ring overflow → `lost_perf_events=3937`, fields withdrawn then restored |
| `smoke_restart_netns` | 60 s per-IP expiry, restart publishes only healthy fields |
| `smoke_xdp_netns` | `XDP-BAN-OK`: generic/skb, ban in map 1.0 ms after `PUBLISH`, `TimeoutError` not reset, per-IP drops, missed-pubsub both ways, allowlist, local exclusion, kernel expiry with the agent dead, restart, detach, DB15 0 |

All smokes refuse a non-empty DB15 and never flush it. Run from the repo root
with system Python:

```
.venv/bin/python -m pytest ebpf/tests -q
sudo python3 -m ebpf.tests.smoke_accept_redis
sudo python3 -m ebpf.tests.smoke_api_netns
sudo python3 -m ebpf.tests.smoke_failed_redis
sudo python3 -m ebpf.tests.smoke_load_netns
sudo python3 -m ebpf.tests.smoke_loss_netns
sudo python3 -m ebpf.tests.smoke_restart_netns
sudo python3 -m ebpf.tests.smoke_xdp_netns
```

## What is still open (joint)

- No run has set `WAF_EBPF_SIGNALS=1`; signal consumption, feature freshness
  and the augmented model are untested.
- IT-1/IT-4: no ban written by the real middleware has been joined to a
  kernel drop; time-to-ban from the first request is unmeasured.
- IT-2/IT-3: features from live signals and byte↔token calibration on real
  `/chat` workloads are open.
- IT-5: Redis outage/recovery and agent death together with B's local
  fallback.
- IT-6 and the matched C0–C4 campaign remain joint work.
- IPv6, tagged VLANs, native XDP and the bridge's inter-client forwarding path
  are outside this backend. Generic/skb performance is not characterized.

## Failure and recovery

| Situation | Expected behavior |
|---|---|
| Sensor stopped | IP hashes expire within 60 s; host hash publishes `available_fields` without unhealthy channels |
| Perf ring overflow | availability withdrawn until a full 10 s loss-free window |
| XDP loader SIGKILLed | program stays attached; stored deadlines expire; restart with replacement flags |
| Redis unreachable | existing map retained (no fail-open flush), publish skipped, pub/sub retried |
| API restarted | sensor `--pid` is stale; restart the sensor (new PID) |
| XDP attach refused | check for an existing program; use `--replace-existing` only for this loader |
| Both XDP modes fail | no kernel-drop claim; use the documented tc/nftables consumer of the same bans |
