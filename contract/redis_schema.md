# Redis Bridge — operational schema version 2

Agent/runtime revision, 2026-11-17. Key names, ban shapes and TTLs stay at
operational schema v2. Feature payloads now declare `feature_version=3`, adding
`agent_steps` and `task_token_budget`. Models and CSVs must match that version.
Decision records add optional `tokenizer` and `agent_steps_completed` fields.
`llm_tokens_charged` aggregates every confirmed agent step and is a lower bound
when accounting is marked uncertain. Private usage hashes add `agent_steps`.
Each client `/chat` with confirmed usage increments `requests` once, including
a task that fails after some completed steps. Mock usage counts backend calls.

Operational target, 2026-11-16. The WAF decision writer is implemented and tested
independently; the kernel side and joint contract acceptance remain pending.
See `../docs/MASTER_PLAN.md` for policy and experiment definitions.

The original plans proposed version 1. Version 2 explicitly defines shadow
decisions, signal availability/units and correlation metadata before the first
integrated implementation. Do not label existing starter output as v2 compliant.
Both original plans link to this specification. No key or TTL is silently renamed.

## Shared keys and ownership

All times named `*_ms` are UTC epoch milliseconds unless explicitly stated as
durations. Redis scalar/stream/hash values are strings on the wire; parse numbers
explicitly. Source IP is IPv4 observed by ASGI/kernel, never a forwarded header.

| Key/channel | Type | Writer → reader | Fields/value | Lifetime |
|---|---|---|---|---|
| `p20:meta:schema_version` | String | Joint → both | `2` | Persistent |
| `p20:ban:<ip>` | JSON string | B; A only for hard-threshold bans → both | ip, reason, source, ts_ms, ttl_s | Redis TTL equals remaining ban lifetime; default new ban 600s |
| `p20:ch:ban` | Pub/sub | Ban writer → agent | op, ip, ttl_s, reason | Notification only |
| `p20:sig:ip:<ip>` | Hash | A → B | conn_rate_1s, conn_rate_10s, syn_rate_10s, failed_conn_10s, bytes_in_10s, updated_ms, available_fields | TTL 60s |
| `p20:sig:host` | Hash | A → B | egress_bytes_llm_60s, egress_conns_llm_60s, unexpected_exec_count, updated_ms, available_fields | TTL 120s |
| `p20:stream:ebpf_events` | Stream | A → B/eval | type, ip, pid, comm, detail, ts_ms, run_id | Approximately 10,000 entries |
| `p20:stream:waf_decisions` | Stream | B → A/eval | See decision fields below | Approximately 200,000 entries |
| `p20:stream:waf_features` | Stream | B → ML | run_id, request_id, ts_ms, ip, method, route, feature_version, features and availability flags | Observe only; approximately 500,000 entries |
| `p20:xdp:drops` | Hash | A → B/eval | total_dropped_pkts, dropped_pkts:<ip>, map_size, updated_ms | Persistent; reset per run |
| `p20:allowlist` | Set | Joint → both | Management IPv4 addresses | Persistent; preserved on reset |

The agent must read Redis PTTL, not restart a full `ttl_s` duration on resync.
Ban reasons are `honeypot`, `budget`, `anomaly`, `ebpf_conn_flood`; source is `waf`
or `ebpf`. `ttl_s` is the original policy duration. `op` is `add` or `del`; deletion
uses `ttl_s=0`. Notifications are hints; Redis keys are authoritative.

No new bans for allowlisted IPs. Reconciliation removes existing map entries when
the IP is newly allowlisted. Expiry and allowlist behavior must also work after
missed messages. Runtime map expiry uses a monotonic clock, not UTC clock values.

## Signal semantics

Despite historical `rate` names, `conn_rate_1s` and `conn_rate_10s` are accepted TCP
connection **counts** in rolling 1s/10s windows for the target API/source IP.
`syn_rate_10s` is the independently measured incoming SYN packet count over 10s
(document retransmission counting). `failed_conn_10s` counts observed failed TCP
connection attempts under an explicitly documented sensor event definition; it
does not mean failed HTTP logins. `bytes_in_10s` is received TCP payload bytes for
the API/source IP; document retransmission handling.

`egress_bytes_llm_60s` is API→mock TCP payload bytes over 60s, filtered to the
configured mock connection. `egress_conns_llm_60s` counts API→mock connections.
`unexpected_exec_count` is a rolling 60s count of process executions attributed
to the app PID/cgroup that violate the configured execution policy. A's sensor
specification must define attribution and event boundaries, then test them.
Bidirectional mock byte details needed by IT-3 go in scoped `ebpf_events` detail
records and archived telemetry; do not reinterpret the outgoing byte field.

`available_fields` is a JSON array of actually measured field names. Required
numeric fields may use `0` as a serialization placeholder only when absent from
this array; readers must never interpret such placeholders as measured zero.
Old writers without availability metadata are not v2 compliant.
B accepts IP signals at age 0–3s and host signals at age 0–5s. Missing, stale or
future-dated values beyond a documented clock tolerance are unavailable, even if
the Redis TTL has not expired. Test and record clock alignment.

## WAF decision fields

Required fields preserve the original names:

- `ts_ms`: decision timestamp; completion timing is correlated separately.
- `ip`, `client_id`: observed IPv4 and authenticated account, or empty client ID.
- `route`: normalized path, without session credentials or prompt content.
- `decision`: `allow`, `throttle`, `block`, `ban`, `would_throttle`,
  `would_block`, or `would_ban`.
- `reason`: policy reason; empty for unqualified allowance. ML-only flags may
  use `anomalous_strike` with `allow`.
- `anomaly_score`: raw `score_samples`, lower is more anomalous; empty if unused.
- `llm_tokens_charged`: actual input plus output usage when known, otherwise empty
  when uncertain; zero only when known that no tokens were generated.
- `latency_ms`: WAF work duration excluding app/mock execution, measured through
  the pre-emission point. Finalized full overhead including this stream write is
  retained in the correlated timing artifact described in the master plan.

Version 2 additionally requires `run_id`, server-generated `request_id`,
`schema_version=2`, `mode`, `tokens_reserved`, `tokens_refunded`,
`accounting_status` (`known`, `uncertain`, or `not_applicable`) and
`sensor_status` (`fresh`, `unavailable`, or `not_used`). Do not trust arbitrary
client request IDs as authoritative. A must capture API-returned IDs when present;
requests dropped before ASGI are tracked with A's separate client attempt IDs.

Observe decisions describe hypothetical enforcement only. No real bans/strikes or
enforcement bucket mutation are permitted. Actual API status and client outcomes
come from separate request records, not from the shadow verdict.

## Private namespaces and state

| Prefix | Owner / purpose |
|---|---|
| `p20:bkt:*` | B / enforcement buckets |
| `p20:shadow:*` | B / observe-mode buckets and strikes |
| `p20:strike:*` | B / typed budget/anomaly strike state |
| `p20:win:*` | B / behavioral request history |
| `p20:app:*` | B / sessions and usage |
| `p20:eval:*` | A / run counters and objective records |

These are not cross-layer input APIs. Document new private prefixes here before
use if they could be confused with shared state. No new Lua bucket math outside
`waf/buckets.py`; the only non-Redis implementation is its explicit outage backend.

Reset run state only while traffic is stopped. Coordinate clearing runtime streams,
signals, usage, local histories and kernel maps/counters; preserve schema version
and management allowlist. Keep archived run artifacts outside reset scope. A schema
mismatch or missing required fields invalidates integration readiness. Future
shared shape/unit/TTL changes require updates in both member plans, this file and
the journal, plus a schema-version bump.
