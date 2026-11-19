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

The validated agent-budget calibration changes only B's private `llm_tok` policy:
40,000 capacity and 2,400 tokens/s. The existing
private bucket expiry formula stays `ceil(capacity/refill_per_s*2000)+1000` ms;
it yields 34,334ms for this token bucket, versus 401,000ms for the initial policy.
This is idle bucket cleanup after more than two full refill intervals. Shared ban,
signal, session and stream shapes/TTLs do not change; operational schema remains 2.
See `../docs/BUDGET_CALIBRATION.md`; A must record the effective policy per run.

Reset run state only while traffic is stopped. Coordinate clearing runtime streams,
signals, usage, local histories and kernel maps/counters; preserve schema version
and management allowlist. Keep archived run artifacts outside reset scope. A schema
mismatch or missing required fields invalidates integration readiness. Future
shared shape/unit/TTL changes require updates in both member plans, this file and
the journal, plus a schema-version bump.

## Account attribution and optional wallet allowance — private state

B's qualified default uses `WAF_ACCOUNT_PRESSURE_BANS=0` to keep account quota
throttles from adding IP budget strikes/corroboration. Existing IP/honeypot bans
and existing Redis bans are still honored. `WAF_WALLET_CAPACITY` plus
`WAF_WALLET_REFILL_PER_S` enable a single service-wide token bucket on authenticated
chat, using the same whole-task token units and atomic Lua/outage backend. Both
are zero to disable. They are policy variants of C2/C3, not new configurations.
The earlier pooled40,000/5,700-token/s policy failed mixed comfort and remains
historical. The later qualified lane default is specified below. Legacy account
escalation is replayable with account pressure1 and wallet0/0. See the fresh
component results in `../docs/ACCOUNT_WALLET_REMEDY_RESULTS.md`.

- `p20:bkt:wallet:global`: private B token bucket, same hash shape/idle-expiry math
  as other buckets. Observe uses `p20:shadow:bkt:wallet:global` exclusively.
- `p20:app:wallet_audit`: private B stream, reset with other app state, bounded to
  200,000 approximate entries. Fields: run_id, request_id, ts_ms, ip, mode, reason,
  reserved/refunded/charged token counts, uncertain flag, capacity/refill_per_s.
  This is diagnostic private state, not a kernel input or shared decision schema.
  During outage records fall back to the existing bounded process-local evidence.
- `wallet_tok` is a request denial reason (429/Retry-After), never a ban reason.
  `wallet_task_exceeds_capacity` is permanent policy rejection400, with any
  earlier account reservation refunded. Shared reasons/keys/fields/TTLs and schema2
  are unchanged. A should archive B's supplied wallet audit for measured replays.

This controls aggregate burst/sustained token consumption, not an absolute
period/daily/monthly monetary cap. For one worker, conservative local fallback and
recovery apply. Unknown outage history starts without a new burst; no refund is
made for uncertain generation. Existing per-account quota and reservation remain.

Current IP-attributable strikes use private `p20:strike:ip_budget:<ip>` (and
shadow equivalent), with the existing strike value/expiry semantics. This isolates
legacy broad `budget` strikes after rollout without deleting old state. Existing
p20:ban keys remain authoritative and are not reclassified or removed. Shared ban
reason remains `budget`; A's consumers need no new ban-reason handling.

## Prospective fairness/resource/spend controls — private B state

The fitted lane/IP/item controls are qualified defaults after independent component
and combined acceptance in `docs/FOLLOWUP_RESULTS.md`. Hard spending stays opt-in.
The historical earlier pooled40,000/5,700 candidate remains a failed comparison.
Shared schema2, ban reasons, signal TTLs and A-owned consumers are unchanged.

- `WAF_WALLET_SMALL_CAPACITY`, `WAF_WALLET_SMALL_REFILL_PER_S` and
  `WAF_WALLET_SMALL_TASK_MAX` partition the existing total wallet allowance into
  two non-borrowing task-size lanes. All three zero selects the original pooled
  allowance. Private buckets: `p20:bkt:wallet:small` and `:general`, shadow-prefixed
  in C1. Their capacity/refill sum exactly to the configured wallet envelope.
  Audit adds optional `lane`; normal token units/refunds/outage backend apply.
- `WAF_IP_CAPACITY` overrides only IP burst capacity; request refill stays2/s.
- `WAF_PRODUCTS_CAPACITY` / `WAF_PRODUCTS_REFILL_PER_S` enable private
  `p20:bkt:products:<ip>` (and shadow equivalent). Cost is requested per_page
  clamped1..100. Valid empty/tail pages can be conservatively overcharged. Invalid
  integer query fields remain API validation errors. `products_items`429 never
  adds an IP strike or corroborates an anomaly; impossible item cost gets400.
- `WAF_SPEND_CAP_MICROUSD` / `WAF_SPEND_PERIOD` enable an absolute synthetic
  period allowance. Period is trusted operator config, never a client header.
  Initialize explicitly with `scripts/init_spend_period.py`; it cannot overwrite
  an existing cap/used balance. Private `p20:spend:<period>` is a persistent hash:
  `cap` integer micro-USD, `used` known charged plus retained reservations, and
  `r:<request_id>` outstanding amounts. No TTL, refill or automatic rotation.
  Runtime reset deliberately preserves this namespace, including setup resets;
  restoring/resetting periods is an operator action outside the campaign helper.
  Redis persistence/backups are an operational responsibility. Missing/lost or
  mismatched authority returns503, never creates fresh money. In Redis outage,
  optional capped chat admission returns503; normal buckets retain their existing
  local fallback and cached-session browsing works. Hard cap disabled by default.
  `spend_cap` exhaustion429 has no Retry-After (no scheduled refill) and causes no
  IP ban. Whole-task integer reservations use synthetic input3/output15 micro-USD
  per token; prices are shared in common/pricing.py. Known unused credit refunds
  idempotently; uncertain/unreconciled usage retains credit. Allowlisted management
  requests still bypass WAF, so the cap covers non-exempt application admission.
- Private `p20:app:spend_audit`: bounded200,000 entries, fields run_id, request_id,
  period, reserved, charged, refunded, uncertain, reconciled, cap. Runtime-reset
  scope includes this diagnostic stream, but never the authoritative ledger.
  C1 uses only shadow ledger keys and cannot consume the enforcement period.

A should record these optional flags/effective budgets before new comparisons;
B's budget_harness adapter records them. These change policy variants, not C0–C4.

### Qualified default policy (2026-11-19, masterv1.8)

Total wallet56,000/7,300, small9,000/1,800 (whole task<=2,048), general47,000/5,500;
IP capacity60/refill2/s; item capacity1,000/refill50/s; hard spend0/empty period.
Account40,000/2,400 and operational schema2 remain unchanged. Setting wallet total
capacity/refill0/0 also defaults all SMALL fields to0 unless explicitly supplied.
Explicitly zero all SMALL fields to select a pooled positive allowance. Historical
replay must set wallet/SMALL/products0, IP30 and the recorded account-pressure flag;
B's historical remedy adapter now sets those flags explicitly. Private strike
namespace ip_budget remains; existing ban keys stay authoritative until expiry.
