# Member A XDP ban enforcement

Follow `MASTER_PLAN.md` sections 3.2 and 6, `contract/redis_schema.md`
version 2 and `docs/member_A_plan.md` section 6. This is the independent
Member A kernel branch, not a C4 result. The loader and smoke were statically
checked on Windows and then **verified on the lab VM on 2026-11-23** in
generic/skb mode; native XDP is unavailable on the bridge. The measured
numbers and remaining limits are below.

## What it enforces

`ebpf/xdp_ban.py` is a consumer, not a ban writer. It reads `p20:ban:<ip>`
records (B's bans, optionally A's own future hard-threshold bans), validates
that the value is a JSON object whose `ip` equals the key, and installs the
source IPv4 in an XDP map. It never writes or extends a ban.

The XDP program drops only untagged IPv4 frames whose source address is in
the map. Non-IPv4 and malformed frames pass. The contract's ban JSON is the
source of truth; a malformed value or key/value mismatch is ignored rather
than guessed. Entries in `p20:allowlist` and any local host IPv4 (loopback,
the bridge address, every address reported by `ip -4 -o addr show`) are never
installed, even if a ban key exists. This prevents a bad ban from cutting off
the API or the agent's own Redis path.

Scope: attaching to the bridge master `p20br0` covers frames delivered to the
host (the API's `10.20.0.1` path), not frames the bridge forwards between
client ports. That matches this lab's threat path; a production deployment
would attach at the physical ingress for each tenant. IPv6 and tagged VLAN
frames are outside this version and pass.

## Lifetime and reconciliation

Redis TTL is mirrored into the XDP value as an absolute `CLOCK_MONOTONIC`
deadline derived from the remaining PTTL. Consequences:

- A ban key edited with `EXPIRE` is lengthened or shortened at the next
  reconcile.
- A key without an expiry is **not** installed; there is no permanent-drop
  fallback.
- If the loader is killed, the program stays attached but the stored deadline
  still expires, so an expired ban cannot keep dropping. A restarted loader
  removes the stale map entry once the Redis key is gone.

`p20:ch:ban` triggers an immediate full reconcile (SCAN + GET + PTTL), and a
full scan also runs every `--reconcile-interval` seconds (default 2.0; the
smoke uses 0.5). The periodic scan is the recovery path for missed pub/sub
messages, deletion without a notification and Redis TTL expiry. If Redis is
unreachable, the existing kernel map is retained (no fail-open flush) and
publishing is skipped; the loader retries the pub/sub connection. This does
not promise Redis availability while the agent is down.

## Backend and mode

The loader attaches to one interface (default `p20br0`; the plan's starter
used `eth0`). `--mode auto` tries native/driver XDP first and falls back to
generic/skb; the observed attempt and failure reason are printed. If both
fail, the process exits with a message that the documented tc/nftables
consumer (using the same Redis bans) must be used instead — no kernel-drop
claim is made. `--replace-existing` is required to take over a program already
on the interface, and is the recovery path after a hard kill.

Success evidence is printed as `xdp: attached` with `mode`, `requested_mode`,
`evidence` (the `ip -details` line or `bpftool net` entry) and any failed
attempts. `has_xdp()` checks both `ip -details link show` for `prog/xdp` and
`bpftool net` because iproute2 renderings vary.

## Launch

The loader requires `p20:meta:schema_version=2` in the target Redis DB and
refuses to take over an existing program without `--replace-existing`.

```
sudo python3 ebpf/xdp_ban.py --iface p20br0 \
    --redis-url redis://127.0.0.1:6379/0
```

Restart after a hard kill (the program stays attached, so replacement is
explicit), keeping already published totals:

```
sudo python3 ebpf/xdp_ban.py --iface p20br0 \
    --redis-url redis://127.0.0.1:6379/0 --replace-existing --keep-drops
```

SIGINT/SIGTERM reconciles one last time, removes the program and prints
`xdp: stopped` with `detached`.

## Drop telemetry

`p20:xdp:drops` is written by the loader:

- `total_dropped_pkts`: cumulative kernel drops since the loader's counter
  base;
- `dropped_pkts:<ip>`: cumulative drops attributed to that source by the XDP
  program;
- `map_size`: installed ban entries;
- `updated_ms`: publication time.

Counters are read from `BPF_HASH(drop_by_ip)` and `BPF_ARRAY(drop_count)` and
written as absolute values (not increments), so a repeated publication cannot
double count. A fresh loader deletes the hash at startup (reset per run);
`--keep-drops` instead reads the prior total and per-IP values as a base, so a
restart does not erase published evidence. Drops that occur while the loader
is dead cannot be published by it; that limitation is not hidden.

## Measured lab run (2026-11-23)

Ubuntu 24.04.5, kernel `6.8.0-149-generic`, canonical `p20br0` bridge at
`10.20.0.1/24`, DB15 empty, `sudo python3 -m ebpf.tests.smoke_xdp_netns`.
Unit suite: 32 passed.

| Check | Measured result |
|---|---|
| Native XDP on `p20br0` | failed: `Operation not supported` (bridge master has no driver XDP) |
| Selected backend | generic/skb; `prog/xdp id 337 name xdp_drop_banned ...` |
| Local addresses excluded | `10.20.0.1`, `127.0.0.1`, `172.25.236.217` |
| `PUBLISH` ban → map entry | 1.0 ms (limit 1000 ms) |
| Banned ns15 client | `TimeoutError` after 1202.3 ms; no SYN reached the listener |
| Control ns1 client | `OK`, 1.1 ms; no per-IP drop field |
| First drop telemetry | `total_dropped_pkts=1`, `dropped_pkts:10.20.0.25=1`, `map_size=1` |
| Missed pub/sub | delete → unblocked, create → blocked with the periodic 0.5 s scan only |
| Allowlist | added → entry removed and unblocked; removed → ban restored and blocked |
| Ban on `10.20.0.1` | not installed (`map_size` stayed 1), no per-IP field, control unaffected |
| Loader SIGKILL | program stayed attached (`id 337`); Redis key expired; client `OK` in 1.4 ms |
| Restart (`--replace-existing --keep-drops`) | new program `id 340`, `map_size=0`, total and per-IP totals preserved at 6 |
| Graceful stop | `detached: true`, no `prog/xdp`, client `OK` |
| Scratch DB15 | 0 after the run |

Six drops had accumulated by the expiry step. The listener accepted 3
connections from ns1 and 6 from ns15 across the whole run; every ns15 accept
lies in a deliberately unblocked phase (baseline, deletion without pub/sub,
allowlist, post-expiry, restart, after stop), so no banned SYN was delivered.

## Controlled smoke

`ebpf/tests/smoke_xdp_netns.py` (root, DB15 empty, canonical bridge) starts a
host listener on `10.20.0.1:18006`, attaches the loader, and requires:

1. a pub/sub ban to be enforced in <=1 s; the client times out (blocked SYN),
   never `ECONNREFUSED`, and the listener sees no accept from the banned IP;
2. `total_dropped_pkts` and `dropped_pkts:10.20.0.25` to rise while a control
   namespace (10.20.0.11) still connects;
3. deletion and creation **without** `PUBLISH` to reconcile within the
   periodic interval (missed-pubsub path);
4. adding the IP to `p20:allowlist` to remove the map entry, and removing it
   to restore the still-present ban;
5. a ban for 10.20.0.1 to be excluded and not appear in per-IP telemetry;
6. a shortened TTL to be reflected, then SIGKILL the loader and require the
   program to remain attached while the client succeeds after the Redis TTL
   passes (kernel deadline, no reconcile);
7. a restarted loader with `--replace-existing --keep-drops` to reconcile
   `map_size` to zero while keeping published totals;
8. graceful stop to detach and leave traffic working.

Every key is removed in `finally`; DB15 size is printed. This is not a
throughput, production-loss, IPv6, VLAN or C4 claim, and generic/skb mode is
not characterized for performance here.

The smoke writes contract-shaped ban records itself, so it proves the consumer
and the kernel path, not B's middleware end to end: joint time-to-ban (IT-4)
and C4 remain open. Only IPv4 frames delivered to the host through the bridge
master are covered; frames the bridge forwards between client ports, IPv6 and
tagged VLAN traffic are outside this backend.
