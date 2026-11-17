# API handoff — Member B to Member A

Updated 2026-11-17 for master plan v1.3 and the professor's conditions.
`POST /chat` accepts `agent_steps` (strict integer, 1–8, default 3) in addition
to prompt and per-step `max_output_tokens`. It simulates catalogue lookups,
grows context, and makes one new local mock HTTP connection per step. Response
`iterations` contains each step's exact usage, and `usage` sums all completed
steps. `text` is the last completion. `X-Agent-Steps` and `X-Tokenizer` expose
the step count and tokenizer identity. Counters include completed `agent_steps`.

`synthetic-whitespace-v1` counts Unicode whitespace-delimited words exactly,
including zero for empty input. Generated words match output counts. Mock latency
is deterministic and configurable through `MOCK_TOKENS_PER_S`, `MOCK_BASE_MS`,
`MOCK_JITTER_MS`, `MOCK_DELAY_CAP_S` and `MOCK_SEED`. Record the mock health
configuration in every run. `/_metrics/usage` on the mock supplies independent
call/token totals for cross-checks. Real-provider compatibility is optional.

WAF reservation covers all repeated inputs, outputs and tool markers before
any agent call. If later steps fail, counters retain confirmed earlier usage.
Timeouts leave the remaining generation uncertain and keep the reservation.
Features are version 3. Use freshly collected C1 data and matching models.
The earlier single-call data and benchmarks are retained as historical evidence.

Independent application handoff, 2026-11-16. See `../README.md` for launch/reset steps
and `../docs/MASTER_PLAN.md` for experiment rules. `openapi.json` is exported from
the current baseline app. It does not certify completed WAF or kernel integration.

| Endpoint | Behavior |
|---|---|
| `POST /login` | JSON username/password; returns `token`; unknown user and wrong password both 401 with deliberately distinct messages |
| `POST /logout` | Bearer session; deletes the server session; idempotent with an already-expired token |
| `GET /products?page=1&per_page=100` | 5,000 synthetic products; per_page capped at 100; no C0 request throttle |
| `POST /chat` | Bearer session plus prompt/max_output_tokens/agent_steps; repeated mock calls; returns text, total usage and iteration trace |
| `GET /_metrics/usage` | Redis total requests, tokens_in, tokens_out, cost_usd; empty object before use; numbers are Redis strings |
| `GET /health` | 200 when Redis and mock respond; 503 otherwise; reports mode and simulated-cost label |
| `GET /openapi.json`, `/docs` | Machine contract and interactive docs |
| `GET /` | Public demo interface for login, products and chat |
| `GET /dashboard`, `/dashboard/data` | Read-only management UI/snapshot, restricted by actual loopback or allowlisted connection IP |
| `GET /dashboard/evidence` | Same restricted management access; bounded local timings and outage records, no session tokens |

Synthetic accounts: `user1` through `user50`; matching passwords are
`Passw0rd!1` through `Passw0rd!50`. Login sessions expire after 3,600 seconds.
Never use real credentials. Tokens are random and must not enter logs/artifacts.

`max_output_tokens` defaults to 256 and must be a positive JSON integer (not bool,
float or string). The baseline mock generates at most 32,000 output tokens per
call, with no per-user token budget in C0. The hardened output cap applies per
step in the same API/backend. Exact synthetic counting uses `common/tokens.py`.

Headers `X-Tokens-In`, `X-Tokens-Out`, `X-Cost-USD` match response usage; header
cost is rounded to six decimal places. JSON cost/counters retain more precision.
Prices are synthetic: $0.003 per 1,000 input tokens and $0.015 per 1,000 output
tokens. Redis usage tracks both total and authenticated account counters.

Local mock: `http://127.0.0.1:8001`, `POST /complete`, `GET /health`. Only the API
calls this backend; attack scripts target API port 8000. Observe the API process's
backend connection for IT-3; do not mix in Redis traffic or management health calls.
Run Uvicorn for the target with `--no-proxy-headers` to preserve the actual source IP.

Honeypot policy for the later C2 milestone: `/admin-backup`, `/internal/export`,
`/.env`, trailing slashes and path descendants. C0 naturally returns 404 at those
paths and does not ban. `/robots.txt` advertises two decoys.

Failure semantics: missing/expired bearer 401, malformed input
422, unreachable/invalid backend 502, backend timeout 504, Redis-dependent failures
503 when no valid cached identity can be established. Existing cached sessions
keep their original expiry during an outage; known completed generation usage is
retained locally when Redis accounting fails. The response includes `X-Usage-Store`
(`redis` or `local_uncertain_redis_commit`). Do not automatically merge local/Redis
totals, since a failed transport may hide a successful Redis commit. Unknown
generation after timeout retains its reservation and logs uncertain usage.

C2 returns 429 with Retry-After for budgets, 400 for output/cost policy violations,
404 on the first honeypot hit and 403 for active bans. C1 logs `would_*` and forwards
without real bans/budget mutations. Decisions have schema-v2 correlation fields;
the response has a server-generated `X-Request-ID` for non-management WAF requests.
WAF reserves/refunds and actual charged usage are distinct fields. Local timing
artifacts include logging/finalization overhead and exclude downstream execution.

Attack scripts and the namespace harness are present. Preserve older benchmark
evidence and rerun the current agent runtime before presenting final results.
Real sensor/enforcement and XDP validation remain pending with A.
