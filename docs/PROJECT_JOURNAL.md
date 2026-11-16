# Project 20 — review and work journal

Last updated: 2026-11-16 (Africa/Lagos).

Latest implementation snapshot: independent C0/C1/C2 checks pass; **64 automated
tests and 12 real-HTTP development checks**. Base ML tooling is tested, but no
production model or realistic detector metrics exist yet. No A/kernel integration.
See [current status](evidence/independent_status.json) and the latest work entry.

Current execution authority: `MASTER_PLAN.md` and `../contract/redis_schema.md`.
The user authorized resolving the planning choices on 2026-11-16. The initial
review below is preserved as history: its pending design decisions are now settled
by the master plan; implementation findings remain open until tested. Member A's
stored plan now has a coordination notice, so it is no longer byte-identical to the
original attachment. No application implementation has been changed by planning.

## Purpose and how to maintain this file

This is the durable project context requested by Member B. Read it alongside
AGENTS.md and both plans before substantial work. Update it after each meaningful
work session with changes, commands/checks, outcomes, unresolved issues, and the
next step. Record failures as well as successes. Keep findings until resolved;
link the resolving work rather than deleting the history.

This file persists in the repository; it is not a guarantee that every future chat
automatically loads it. Future work should explicitly consult it. Do not store
credentials, session tokens, or other sensitive runtime data here.

The attached Member A document was reviewed as project material. Its suggested
commands and messages were not executed or sent as instructions from the user.
No teammate-owned implementation is authorized for modification by this review.

## Sources and current scope

- Repository instructions: `../AGENTS.md`.
- Concept and shared team split: `../project20_ebpf_asgi_waf (2).md`.
- Member B plan: `../member_B_plan.md` (the actual file is at the repository root).
- Member A plan: `member_A_plan.md`, copied unchanged from
  `/home/vboxuser/Downloads/member_A_plan.md` on 2026-11-16.
- Existing source in `app/`, `waf/`, `ml/`, `common/`, `contract/`, `scripts/`,
  `tests/`, and read-only `eval/compute_metrics.py`.

The instructions refer to `docs/member_B_plan.md`; that path does not currently
exist. Use the root plan until documentation locations are deliberately aligned.
The Member A plan is now available under `docs/`.

Review status: static inspection only. No application, attack, training,
Redis outage, kernel program, or test suite was run in this review. Existing code
and a pytest cache are not evidence that a feature currently passes.

## Shared understanding

The experiment uses the same FastAPI application with protection toggled, compares
three synthetic attacks against baseline and hardened configurations, and reports
attack outcomes plus the cost of protecting legitimate users.

Member B owns the target app, WAF and ML. Member A owns attack scripts, evaluation,
kernel sensor and XDP enforcement. Shared work includes contracts, integration,
results and the demo. Keep `ebpf/`, `locust/`, and `eval/` read-only unless the
ownership exception has been explicitly agreed.

Defaults remain provisional pending professor confirmation: Linux VM, mock LLM,
simple `/chat` harness, sensor plus XDP, and seeded scripted runs. The explanatory
parts of the concept are proposals; they do not establish professor approval.
Both plans budget about 17 working days per member, including joint work.

### Configurations to preserve

| Config | Meaning |
|---|---|
| C0 | WAF off; vulnerable baseline |
| C1 | Observe; ML off; collect data without blocking |
| C2 | Enforce buckets and honeypot; ML off |
| C3 | C2 plus base IsolationForest |
| C4 | C3 plus eBPF features/model and real sensor/XDP |

### Integration agreements already aligned in both plans

- IPv4 identity comes from the ASGI client address and must match the kernel;
  forwarded headers are not trusted. Account identity additionally scopes LLM budgets.
- Redis is the ban source of truth. Normal bans originate in the WAF; A's
  optional hard-threshold bans use the same shape and reason `ebpf_conn_flood`.
- Ban JSON fields: `ip`, `reason`, `source`, `ts_ms`, `ttl_s`; default TTL 600s.
- IP signal TTL 60s; host signal TTL 120s. Times are UTC epoch milliseconds.
- B publishes ban notifications; A also periodically reconciles the map.
- Allowlisted management IPs are exempt; attacker and measured benign IPs must
  remain subject to protection for representative evaluation.
- App token accounting and WAF reservations share `common/tokens.py`.
- Model training uses benign data, with held-out labeled data for evaluation.
- IT-1 through IT-6 cover bans down, signals up, cost cross-check, closed-loop
  timing, failures, and benign-client behavior.

## Priority findings — integration and measurement

These are open findings, not approved design changes. A = Member A, B = Member B.

| ID | Priority / owner | Finding and required next action |
|---|---|---|
| INT-01 | High / joint | `app/mock_llm.py` is an in-process function, while A's plan expects a network LLM endpoint. IT-3 cannot measure its LLM egress as written. Agree whether to expose the same mock through a local HTTP service or explicitly revise the test. Keep the backend identical across compared configurations. |
| INT-02 | High / joint | Network bytes and token counts have different units. A 10% comparison needs a defined mapping, traffic direction, protocol overhead allowance, observation window and workload calibration. Do not claim bytes equal tokens or cost. |
| INT-03 | High / joint | `contract/` lacks the written shared schema and OpenAPI export. Freeze version 1, allowed decision values, signal units, private prefixes, TTLs and result definitions before independent implementation drifts. |
| INT-04 | High / A | A's planned harness uses Locust failure counts for ASR although its attacks mark blocked replies as Locust successes. Its own note acknowledges the problem. Add objective-specific attempt/hit records; exclude setup logins and management calls from attack denominators. |
| INT-05 | High / A | The planned harness loops over C0–C4 labels without restarting/configuring the app or managing sensor/XDP state. Labels alone do not change protection. Record and verify the actual configuration for each run. |
| INT-06 | High / joint | Current `eval/compute_metrics.py` counts all non-allow decisions as false positives without labels. It cannot establish FPR on mixed traffic. Use run-specific benign/attacker labels and report actual benign harm separately from observe-mode hypothetical decisions. Ask A to address this in their track. |
| INT-07 | High / joint | Planned time-to-ban polling starts after the attack finishes and uses a placeholder IP. Define separate times to Redis ban, map insertion, and first attributable XDP drop, collecting events while the attack runs. |
| INT-08 | High / joint | C0 has no WAF decision stream; XDP-dropped requests never reach that stream either. ASR denominators and end-to-end latency require client-side records, including timeouts. Per-IP drop telemetry is needed for attribution. |
| INT-09 | Medium / joint | A's proposed result schema is per config/attack but suggests merging B metrics on config only. Agree run IDs, repetition IDs, workload, seed, IP/account roles and join keys to avoid mixing unrelated measurements. |
| INT-10 | High / joint | Reset script clears only some Redis state. A's proposed evaluation counters, kernel counters/maps, sensor in-memory history and surviving agent state need coordinated reset/readiness checks. Avoid clearing live signals mid-measurement. |
| INT-11 | Medium / joint | Observe-mode `would_*` decisions extend the concept's four-value decision enum. B explicitly proposes them; freeze this extension with A and document consumer behavior before relying on it. |
| INT-12 | Medium / joint | IT-2 says the anomaly score rises, but B uses `score_samples`, where lower means more anomalous. Define the direction precisely, or state that abnormality/strikes increase. |
| INT-13 | High / joint | WAF local buckets alone do not keep the whole app functional during a Redis outage: login sessions and usage accounting also depend on Redis. Define the expected behavior of authenticated requests and telemetry during IT-5. |

## Confirmed findings in Member B's current code

Confirmed means visible in source, not reproduced at runtime.

| ID | Priority | Evidence and action |
|---|---|---|
| B-01 | High | `waf/middleware.py` and bucket/ban helpers propagate Redis failures; there is no local bucket fallback. Implement the required degraded protection and test recovery. Resolve the convention tension between Redis-only Lua math and a Redis-independent fallback explicitly. |
| B-02 | High | Observe mode still executes bucket/ban checks and can return before `features.extract`. It also changes budget/strike state. Collect all intended observations and define shadow decisions without letting early verdicts censor the dataset. |
| B-03 | High | `ChatIn.max_output_tokens` has no lower bound; WAF reservation adds negative output counts, whereas the mock produces at least one token. A sufficiently negative cost can increase bucket balance. Align validation and reservation for valid inputs in the same app across C0–C4. |
| B-04 | High | If ML bans after an LLM reservation, the returned ban verdict loses `reserved` and the denied branch does not refund. Ensure reserved budget is returned whenever generation does not occur; also cover exceptions, cancellation and unsuccessful requests. |
| B-05 | High | `_log` writes the reservation as `llm_tokens_charged`, not observed actual usage after refund. Define and log actual charged usage consistently for evaluation. |
| B-06 | High | ML requested with a missing model silently creates no scorer. Make effective ML state explicit and prevent measured C3/C4 runs from silently behaving like C2. |
| B-07 | Medium | The current overhead timer stops before ban writing, feature recording, decision logging and refund. Treat it as partial decision time until full WAF overhead is measured excluding app/LLM execution. |
| B-08 | Medium | `features.extract` duplicates token estimation instead of using `estimate_tokens`. Route every estimate through the common helper. |
| B-09 | Medium | The per-IP event list retains only 100 events, so 10s/60s request counts saturate during high-rate traffic. Decide how to retain accurate bounded-window statistics. |
| B-10 | Medium | eBPF features do not inspect `updated_ms`; stale values can be used until TTL expiry. Specify freshness and missing-sensor behavior and train/evaluate accordingly. Host-wide egress also affects all clients; it is not per-client attribution. |
| B-11 | Medium | Model scoring is synchronous in the async request path. Measure it and move costly scoring off the event loop as required by project conventions. |
| B-12 | Medium | Training randomly splits adjacent rows with overlapping traffic history. Use separate sessions/runs or an appropriate temporal/group split for credible held-out evaluation; preserve a separate threshold-calibration set. |
| B-13 | Medium | There are no datasets, model artifacts or model evaluation script in the visible tree. `ml/export.py` also hardcodes the default Redis connection and does not preserve stream IDs as columns. Add run identity, timestamps and labels to the collection/export design. |
| B-14 | Medium | `add_strike` uses separate INCR and EXPIRE calls. An interruption between them can leave a strike key without TTL. Make the increment/initial expiry operation atomic. |
| B-15 | Medium | Lua accepts unvalidated cost/capacity/rate. A cost above capacity can never succeed although the code returns a finite retry. Define input validation and permanent-denial behavior, retaining atomic take/refund. |
| B-16 | Medium | `reset_state.sh` can continue after Docker/Redis errors and still print success. Make reset failure observable before relying on reproducibility claims. |
| B-17 | Medium | Only `tests/test_buckets.py` exists. Add meaningful middleware, ban, observe-mode, accounting, concurrency and outage tests using isolated Redis DB 15 where required. |
| B-18 | Medium | `path.startswith(honeypot_paths)` also matches extra suffixes. Specify exact versus descendant honeypot matching so legitimate paths are not accidentally banned. |

Additional behavior to verify during implementation: ASGI body replay and
disconnect handling, malformed payloads, reservation/actual reconciliation on
errors, shared-account contention, allowlist races and logging failures. These
are test targets, not claims of demonstrated vulnerabilities.

The baseline's deliberately weak authentication and unrestricted valid traffic
are intentional experiment behavior. Preserve those properties in C0 while
correcting accounting and invalid-input inconsistencies.

## Member A plan review — concerns to hand off

These findings concern snippets in `docs/member_A_plan.md`; the actual `ebpf/`
and `locust/` implementations are absent from this checkout. Do not describe them
as tested defects in implemented code. Verify kernel/tool details against official
documentation and the target VM before implementation.

- **Sensor hook:** the accept snippet reads a socket argument from an entry
  probe. Review the target function signature and whether the accepted socket
  must be obtained at return. Confirm correct source address and app/port filtering.
- **Signal semantics:** `syn_rate_10s` is copied from accepted connections;
  failed connections and input bytes are zero placeholders. Publish measured
  quantities or explicitly mark them unavailable; define whether `*_rate_10s`
  means a window count or a per-second rate.
- **Keep-alive:** many HTTP requests may reuse one connection. IT-2 needs a
  connection-churn scenario rather than assuming every scraping request adds a
  connection. Preserve realistic keep-alive in the other experiments.
- **Exec attribution:** the snippet checks process names for system-wide events,
  without demonstrating that the app caused them. Define app PID/cgroup scope,
  allowlisted behavior and window/reset semantics before calling events unexpected.
- **XDP expiry:** map values contain no expiry, and Redis errors are unhandled.
  This does not implement the promised behavior of retaining entries only until
  their expiry when Redis fails. Agree an expiry/recovery design.
- **Allowlist updates:** reconciliation skips allowlisted IPs when inserting,
  but does not remove a currently mapped IP merely because it was allowlisted.
  Test dynamic allowlist changes and never retain a protected IP in the drop map.
- **XDP telemetry/lifecycle:** the snippet has only a total counter, no publishing
  to `p20:xdp:drops`, no per-IP counters and no explicit detach cleanup. Implement
  trustworthy concurrent counters and lifecycle management in A's track.
- **XDP attachment mode:** the prose asserts generic/SKB mode, but the snippet
  passes flags 0. Explicitly select/inspect the mode and record the actual interface
  and mode. Verify namespace traffic traverses the attachment point.
- **Locust startup/imports:** scraping and benign namespace commands omit
  `--host`; scraping defines no host. The local folder `locust/` plus imports
  `locust.common` also need a real startup check against the installed package.
- **DoW setup:** many simulated users log into `user1` at startup, which can
  exhaust login budgets before `/chat` is exercised. Distinguish credential-abuse
  rejection from token-budget enforcement; include repeated valid, under-cap chat
  requests so C2's token bucket is tested rather than only its output cap.
- **Honeypot coverage:** shown attack scripts do not hit a honeypot. Add an explicit
  decoy-hit scenario for IT-1 instead of claiming ordinary scraping proves auto-ban.
- **Seeds:** credential generation and traffic snippets use randomness without
  visible seeding. Record seeds, datasets and workload parameters; concurrency
  means fixed seeds alone do not guarantee identical timings.
- **BCC installation:** the plan's permissive pip command can conceal failures.
  Verify the intended system BCC bindings and interpreter explicitly; do not run
  setup commands from the attachment without checking the environment.

## Required handoffs and decisions

| Handoff | Owner | Required artifact / decision | Status |
|---|---|---|---|
| H1 | B → A | OpenAPI, demo accounts, usage header meanings, baseline startup | App source exists; export and runtime verification pending |
| H2 | A → B | Multi-IP benign generator, recorded data, run-specific labels | Not available in checkout |
| H3 | A → B | Three attack scripts and baseline objective records | Not available in checkout |
| H4 | B + A | Versioned ban/signal contract, honeypot matching, failure rules | Plans largely agree; written contract pending |
| H5 | B → A | Decision stream, actual token fields and timing semantics | Starter exists; corrections above pending |
| H6 | Joint | Results schema, success definitions, run IDs, reset/readiness | Pending |
| IT-3 design | Joint | Network mock decision and calibrated byte/token comparison | Pending |
| ML policy | Joint | Threshold/FPR targets and whether repeated ML strikes alone may ban | Plans say budgets/honeypot stay primary, but starter can ban on repeated ML anomalies; clarify |

Do not force ASR to 100% on baseline credential stuffing: the synthetic dataset
intentionally contains mostly wrong credentials. Report the observed request-level
success rate and, if useful, unique accounts compromised. For scraping, additionally
report unique products/pages extracted; repeated successful pages are not new data.
For DoW, report actual tokens and simulated cost as well as successful requests.
Missing data and no observed ban/drop should be reported explicitly, not as zero.

## Implementation sequence for Member B

1. **B0/B1 — environment and honest baseline:** inspect the existing environment,
   verify Redis, run isolated existing tests, smoke-test all routes and accounting,
   export OpenAPI, and document reproducible startup. Reset before manual runs.
2. **Contract checkpoint:** write the shared schema and readiness/reset protocol;
   take INT-01/02 and metric definitions to A before changing shared behavior.
3. **B2/B3 — C2:** correct accounting and validation, atomic operations, bans,
   observe behavior and Redis degradation. Add targeted tests and compare A's
   attacks on C0/C2. Do not claim attack validation until their scripts exist.
4. **B4 — C1 then C3:** collect representative labeled multi-IP traffic, train only
   on benign training data, calibrate thresholds, evaluate on separate runs and
   report precision/recall/FPR/scoring time. Never train on fabricated eBPF zeros
   and present the result as a real eBPF-augmented model.
5. **C4:** train with real sensor data; run IT-1 through IT-6 jointly, including
   missing/stale signals, Redis failure, map expiry and benign traffic.
6. **B5/B6:** repeat matched workloads at least three times, record latency
   percentiles, full WAF overhead, CPU/memory and model time, then build slides
   and rehearse. Verify official security mappings/citations before publication.

## Work log

### 2026-11-16 — initial concept/B review (earlier in this chat)

- Read the concept, Member B plan, repository instructions and starter source.
- Explained B's ownership and staged milestones to the user.
- Noted that the standalone A plan was missing at that time.
- Made no implementation changes or runtime claims.

### 2026-11-16 — combined A/B review and persistent journal

User request: review both plans, create a Markdown file with all current remarks,
and record future work steps here as persistent project context.

Completed:

1. Read `/home/vboxuser/Downloads/member_A_plan.md` in full.
2. Compared ownership, Redis fields/TTLs, configs, handoffs and integration tests
   with the concept and Member B plan reviewed earlier in the same chat.
3. Re-read the existing app, WAF, ML, token helper, reset script, test and metrics
   source; inventoried visible project files using `rg --files`.
4. Copied A's plan unchanged to `docs/member_A_plan.md` for repository context.
5. Created this journal with evidence-qualified findings and next steps.
6. Checked the saved journal and compared the copied plan against its source.

Files added: `docs/member_A_plan.md`, `docs/PROJECT_JOURNAL.md`.
Application, ML, attack, kernel and evaluation code changes: none.
Tests, attacks, training, Redis reset and service changes: not run for this review.
Documentation checks: journal exists and is readable; copied A plan matches source.

Next action: begin B0/B1 environment and baseline verification. Keep unresolved
shared design decisions visible while completing independent baseline work.

### 2026-11-16 — consolidated execution plan

User request: both members agree; choose and write the best organized plan.

Completed:

1. Re-read the journal and repository instructions; consolidated the concept and
   both previously reviewed member plans into `docs/MASTER_PLAN.md`.
2. Settled the local HTTP mock, calibrated traffic cross-check, corroborated ML
   policy, complete observe-mode collection, bounded outage/recovery behavior and
   run-based evaluation definitions. Preserved C0–C4 meanings and ownership.
3. Added `contract/redis_schema.md` as the operational version 2 specification,
   explicitly covering availability metadata, correlation and shadow decisions.
   This flags changes to both tracks via notices in both member plans.
4. Added coordination notices to the original plans; corrected plan paths in
   AGENTS.md and added the journal/master-plan reading workflow and the explicit
   local-bucket fallback exception required by the agreed outage behavior.
5. Checked local Markdown links, required sections, config flag names and document
   presence. One initial patch failed to match a context line; no file changed
   from that attempt, and a corrected patch applied successfully.

Design status: journal INT-01–13 and B-01–18 now have a planned disposition in
master-plan section 10. These are not closed implementation findings.
Runtime status: tests, service operations, attacks, training and kernel checks
were not run; no performance/security outcomes are claimed.
Teammate implementation status: `ebpf/`, `locust/`, `eval/` remain untouched.
Next action: master-plan G0 and B0/B1 environment/baseline verification.

### 2026-11-16 — visual scope and B0/B1 started

User authorized adding the visual app/dashboard, starting implementation, testing
each step and maintaining this journal.

- Added visual scope, security boundary, staged delivery and browser checks to
  master plan v1.1. No visual implementation yet.
- Re-read instructions, master plan, journal, both member-plan summaries and source.
- Environment: system Python 3.10.12; existing `.venv` Python 3.11.18 is suitable.
  `.venv/bin/python -m pip check` reports no broken requirements. Dependencies are
  installed; no reinstall/replacement was needed. Docker is absent; system Redis
  tools and an existing Redis service are present.
- Initial Redis and pytest checks failed inside the sandbox because socket access
  is restricted. An approved `redis-cli` check outside the sandbox returned PONG.
  The initial pytest failure was connectivity, not a demonstrated bucket defect.
- The initial pytest run also reported an unset async fixture loop-scope warning;
  make the intended function scope explicit when adding integration fixtures.
- Existing test rerun with local socket access is in progress. Next: reliable
  scoped reset, baseline smoke tests, HTTP mock and OpenAPI handoff.

### 2026-11-16 — B0/B1 first implementation and verification

Completed steps:

1. **Visual planning:** master plan v1.1 now assigns B a demo page (login,
   products and chat) and a read-only management dashboard. Added management-IP
   restrictions, real/missing telemetry states, staged delivery and browser QA.
   Both original plans link to the added scope. No custom interface is built yet.
2. **Initial test:** reran `.venv/bin/python -m pytest -q` with permitted local
   socket access. Existing bucket test passed (1 test, 2.19s). Redis DB 15 only.
3. **Reset:** replaced the Docker-only shell implementation with a fail-fast
   wrapper plus `scripts/reset_state.py`, honoring REDIS_URL and deleting only
   documented P20 runtime keys. Preserves allowlist, schema, unknown and unrelated
   keys. Explicitly states it cannot reset process/kernel state. Reset success
   and failure behavior were tested using scratch DB 15 and a closed local port.
4. **Network mock:** added `app/llm_service.py` exposing `/complete` and `/health`.
   It uses the existing synthetic estimator/pricing/output cap. The target now
   calls this backend through a lifespan-managed asynchronous HTTP client, with
   no automatic generation retry. This supplies a real network path for A's
   future sensor; no eBPF measurement or IT-3 calibration has been performed.
5. **API correctness:** added shared request/response schemas and environment
   settings. Positive strict integer output counts are required in API and mock;
   zero, negative, boolean, float and string values are rejected. The same API
   is used in every mode; C0 valid requests remain unlimited. Usage counters now
   include requests/input/output/cost for both account and total.
6. **Lifecycle/status:** Redis and HTTP clients are opened/closed through FastAPI
   lifespan. Added `/health` for Redis/mock connectivity and mode. Session-store,
   backend and usage-store failures have explicit HTTP errors. This is not the
   later full cached-auth/local-accounting/WAF-fallback implementation. Health
   does not yet verify model loading or kernel readiness.
7. **Tests:** added real-HTTP-mock integration fixtures with a reserved ephemeral
   loopback socket; each Redis fixture flushes scratch DB 15 and cleans up. Tests
   cover 1,000 baseline invalid login attempts without throttling, a full 5,000
   product crawl, repeated 32,000-token chat, exact usage/cost reconciliation,
   session validity/expiry, invalid output, missing/invalid/timed-out backend,
   readiness, OpenAPI and scoped reset. Explicit async fixture loop scope removes
   the previous deprecation warning. No WAF module was changed.
8. **Test result:** expanded suite passed 17/17 (6.96s). Final rerun after the
   conftest-import cleanup also passed; machine-readable evidence is saved in
   `docs/evidence/b0_b1_tests.xml`.
9. **Real network smoke:** ran owned API and mock Uvicorn subprocesses on reserved
   ephemeral loopback ports, with all WAF flags off and Redis DB 15. Ran
   `bash scripts/reset_state.sh` before the check and after stopping both processes.
   `scripts/smoke_baseline.py` verified health, login, products, chat, usage delta,
   negative-output rejection and `/docs`/OpenAPI. All checks passed. Temporary
   processes stopped; 3 created runtime keys were removed. No DB 0 reset occurred.
10. **Handoff:** exported `contract/openapi.json`; wrote `contract/api_handoff.md`
    with accounts, routes, headers, mock port, failure semantics and pending A
    dependencies. Added README startup/reset/test instructions and `.gitignore`.
    Target startup uses `--no-proxy-headers` to preserve connection identity.
11. **Documentation/evidence checks:** `bash -n scripts/reset_state.sh` passed.
    Local Markdown links and fences, expected OpenAPI paths, and sanitized smoke
    report were checked. Dependency versions/Python are recorded in
    `docs/evidence/b0_b1_environment.json`. No bearer session or password from a
    runtime response was saved in test/smoke evidence.

Useful commands:

```bash
.venv/bin/python -m pip check
.venv/bin/python -m pytest -q --junitxml=docs/evidence/b0_b1_tests.xml
bash -n scripts/reset_state.sh
# With an owned C0 API/mock running, reset the selected development Redis first:
REDIS_URL=redis://127.0.0.1:6379/0 bash scripts/reset_state.sh
.venv/bin/python scripts/smoke_baseline.py --output docs/evidence/b0_b1_smoke.json
```

The stored smoke report used temporary ports which are now closed. README contains
the repeatable 8000/8001 startup procedure. The reset command above clears sessions;
stop traffic before executing it. Tests require database 15 exclusively.

Evidence:

- [Functional smoke report](evidence/b0_b1_smoke.json)
- [Test report](evidence/b0_b1_tests.xml)
- [Environment snapshot](evidence/b0_b1_environment.json)
- [API contract](../contract/openapi.json)

Finding status: B-03's invalid-output validation is corrected and tested; B-16's
Redis-reset failure reporting is corrected and tested. INT-01's HTTP backend is
implemented, but real eBPF observation/IT-3 remain pending. B-17 test coverage has
started; WAF/bans/outage tests remain required with their implementation. Other
previously identified middleware/ML issues remain open.

Implementation notes: an initial combined delete/add patch for the same file was
rejected by patch validation without applying changes; corrected patches applied.
No teammate-owned code, model, signal key or shared TTL was changed. No Docker
installation/service replacement, kernel modification, model training or attack
script execution occurred.

Gate status: B0 environment/basic Redis testing verified. B1 baseline functional
checks and OpenAPI are ready for development handoff. G0/G1 as joint acceptance
gates remain partial: A's network namespaces, attack scripts, sensor and objective
logs are absent here. No ASR, defense effectiveness, final benchmark or complete
failure-resilience claim is made.

Next work: build the demo interface on the verified API, then the basic restricted
dashboard status view. Connect real WAF/ML/kernel telemetry as those components
are implemented, test each addition and keep advancing C2 independently of A's
pending traffic handoff. Consult the Sites skill before beginning website UI work.

### 2026-11-16 — demo UI and restricted dashboard, before integration

User request: implement the visual milestone and stop before the integration
point. Scope was the demo application and management dashboard on the verified
baseline. No Person A component was connected, executed or edited. This session
does not claim that all B2–B4 defenses or joint acceptance gates are complete.

Completed steps:

1. Read the Sites skill and used its local-only workflow in the existing FastAPI
   checkout. No hosted Site was created or published. Read browser QA, screenshots
   and troubleshooting guidance as needed.
2. Added `app/templates/index.html` with login, catalogue pagination, mock chat,
   response text, input/output usage and clearly labeled simulated cost. Added
   local CSS/JS under `app/static/`; no frontend build or external assets required.
3. Added the read-only `/dashboard` page and `/dashboard/data` through `app/web.py`.
   The snapshot reads dependency health, actual accounted chat usage, the latest
   20 schema-v2-marked B decision records and WAF-written ban TTLs. It scans at
   most 200 ban keys for display, batches value/TTL reads, labels truncation and
   never reads A's signal hashes, XDP maps or attack-evaluation records.
4. Restricted both dashboard HTML and data by actual ASGI source address:
   loopback or exact Redis management allowlist entry. Forwarded headers do not
   grant access. Unknown nonlocal callers are denied if Redis is unreachable.
   Dashboard HTML is stored outside the public static-assets mount, preventing
   an alternate unprotected `/assets/dashboard.html` path.
5. Added CSP/no-store/nosniff headers for HTML and no-store for snapshot data.
   UI renders response/telemetry strings with textContent, not innerHTML. Session
   bearer stays in page memory only. Added `POST /logout` to revoke the actual
   server session. No management writes, attack generator or reset controls added.
6. Dashboard refresh is manual by default, with optional five-second polling
   paused while the tab is hidden. Missing/stale/unverified state is labeled;
   no fake kernel counters, ASR, detection rates or enabled-model claims appear.
   Corrupt/non-finite usage is unavailable rather than fabricated zero.
7. Added `scripts/run_demo.py`: launches owned API/mock subprocesses on reserved
   loopback ports with C0 flags and `--no-proxy-headers`, waits for dependencies,
   and stops both on Ctrl+C. It fails on occupied ports and never automatically
   resets data or replaces existing services. README contains the one-command
   launch procedure and access/polling/session limits.
8. Added `tests/test_web.py` covering public app/assets, protected HTML/data and
   redirect variants, spoofed headers, loopback/allowlisted management access,
   real counters, redaction, legacy telemetry, corrupt counters, Redis outage,
   read-only behavior and logout revocation. The existing baseline tests remain.
9. First expanded suite: 26/26 passed (7.57s). After corruption/read-only cases and
   error-state fixes, final suite: **31/31 passed (7.46s)**. All Redis integration
   tests used scratch DB 15. Final report: `docs/evidence/ui_tests.xml`.
10. Browser QA on owned C0 API/mock at 8765/8766: invalid login showed the intended
    error; valid login enabled chat; one real HTTP mock call produced 13 input
    tokens, 128 output tokens and simulated cost $0.001959. Next catalogue page
    showed Products 6–10. Sign out confirmed server revocation. Dashboard reflected
    that actual usage, connected Redis/mock, C0 protection off and disconnected
    integration. Manual/automatic refresh controls worked; polling was turned off.
11. Responsive QA at a 390×844 viewport showed stacked cards and no page-level
    horizontal overflow (document width 375, viewport 390). Inspected both mobile
    pages and saved four screenshots. Restored the default browser viewport.
    Browser console check returned no errors on the checked demo page.
12. Visual inspection caught a font shorthand typo; corrected it, reloaded and
    confirmed computed sans-serif typography. An offscreen pagination click from
    the browser helper failed; scrolling and the fresh accessibility button
    reference succeeded. No application pagination defect was observed.
13. `node --check` was unavailable because Node is not installed. No dependency
    was installed solely for it; actual browser execution verified the JavaScript
    interaction paths. A documentation patch initially failed context validation
    without changing files and was reapplied correctly.
14. The first temporary preview ended between QA and a later navigation. Reopened
    the current build in a retained terminal. The old browser error tab could not
    navigate due to its data-URL policy state; a fresh tab in the same browser
    successfully verified the final dashboard and connected dependencies. That
    clean snapshot correctly showed zero usage after the scratch reset.
15. Regenerated `contract/openapi.json` and updated the API handoff/README for the
    new logout and management routes. No existing target route was removed.
    Final preview services were stopped and scratch Redis runtime state cleaned.

Evidence (screenshots show synthetic development data, not benchmark results):

- [Desktop demo](evidence/demo_desktop.jpg)
- [Desktop dashboard](evidence/dashboard_desktop.jpg)
- [Mobile demo](evidence/demo_mobile.jpg)
- [Mobile dashboard](evidence/dashboard_mobile.jpg)
- [31-test report](evidence/ui_tests.xml)

Useful commands:

```bash
# Run from the repository root, with Redis already available:
.venv/bin/python scripts/run_demo.py
# Open http://127.0.0.1:8000/ and http://127.0.0.1:8000/dashboard
# Ctrl+C shuts down both owned services.
.venv/bin/python -m pytest -q --junitxml=docs/evidence/ui_tests.xml
```

Stop boundary: no eBPF loading, namespace changes, XDP synchronization, external
deployment, trained-model integration, A attack execution or final evaluation.
WAF middleware, buckets, bans and ML source were not changed in this UI milestone.
Their outstanding findings from the initial review remain open. The dashboard's
schema check is a display gate, not certification of WAF correctness.

Next work, only when requested: advance B2/B3 application defenses and their tests,
then real-data ML preparation. Joint integration still requires A's artifacts;
do not infer readiness from the presence of a polished interface.

### 2026-11-16 — independent application defenses in progress

User authorized continuing B-owned work before integration and requested a full
test at the end. Re-read current instructions, plans, journal and app/WAF/ML code.

Implementation underway:

- Replaced import-time policy globals with validated per-application Config.
- Added atomic Redis budgets plus locked monotonic local fallback and conservative
  reconnect limits; parameter validation rejects impossible costs.
- Added atomic ban/pubsub and strike TTL logic, precise honeypot boundaries,
  allowlist checks, typed strikes and expiring local ban snapshots/reconciliation.
- Reworked ASGI decisions, bounded body inspection/replay, exact generation-state
  accounting/refunds, complete non-enforcing C1 collection and schema-v2 output.
- Added bounded cached sessions and local outage accounting/events. Redis failures
  no longer automatically turn known completed generations into lost usage or retries.
- Replaced truncated 100-event features with bounded 60s windows and saturation
  flags using the common token estimator. No kernel data is read; C4 startup is
  explicitly rejected until integration is implemented.
- Prepared grouped benign-only model training, independent labeled evaluation and
  explicit model manifest loading; no real data/model artifact has been generated.
- Added regression/concurrency/outage/observe-mode tests on Redis DB 15. Full
  suite is being run and failures will be resolved before completion claims.

Status: active implementation, not a passed acceptance gate. No Person A source
or running system has been changed. Final test/evidence entry will follow.

### 2026-11-16 — independent defenses completed and full available test run

Scope: continue Member B-owned work before integration and run a full test at the
end. Implementation is independent of A's missing traffic/kernel artifacts. This
entry completes the in-progress entry above; old review findings remain as history.

Implemented:

1. `waf/config.py`: per-app validated policy, strict environment flags, shared
   budget definitions, run ID/model path and bounded caches/history. No import-time
   CFG instance remains. App and WAF mode/Redis URL must agree.
2. `waf/buckets.py`: atomic server-time Lua take/refund; finite positive parameter
   validation; explicit rejection when cost can never fit capacity; capped refunds.
   Locked local monotonic mirrors protect during Redis errors. Dirty balances
   reconcile by minimum on recovery; unknown balances start empty. Evicted dirty
   history is treated conservatively, not as a free full bucket.
3. `waf/bans.py`: precise decoy matching; atomic allowlist-aware ban write/pubsub;
   typed atomic strike counters and expiry. Local strike updates are locked;
   outage strike counts survive reconnect without extending their window. Cached
   bans expire locally; pending WAF bans reconcile with remaining lifetime, bounded
   by the original deadline. All incoming contract ban reasons use the same read
   behavior; this does not constitute running A's producer.
4. `waf/state.py`: bounded snapshots, cached session deadlines that do not extend
   Redis expiry, local logout revocation tombstones, local outage accounting/events,
   and nonfatal telemetry. Redis command retry is disabled to avoid silently
   repeating mutable operations after uncertain transport failure. No automatic
   merge/double-charge of uncertain Redis commits occurs.
5. `waf/middleware.py`: enforce/observe state separation, bounded ASGI body prefix
   inspection with original chunk replay, disconnect handling, request IDs,
   account/IP/request/token policy, precise strikes/ban verdicts, and full known
   reservation cleanup. Decisions preserve actual charged usage separately from
   reserve/refund. Unknown generation after timeout/invalid backend response retains
   its reservation conservatively. Duplicate authorization headers use the same
   first-value interpretation as FastAPI, preventing mismatched budget/accounting
   identities. Scoring runs off the event loop.
6. C1 collects intended samples even when a shadow verdict would deny. It writes
   neither real budgets/strikes nor real bans. Oversized input gets a bounded,
   explicitly truncated feature view but is replayed to the baseline API in full.
   Shadow state lives under `p20:shadow:*`.
7. `waf/features.py`: common token estimator; 60s Redis histories rather than a
   silently truncated 100-event list; configurable 10,000-event bound with explicit
   saturation; local history source on outage. No eBPF feature reader is connected.
8. API: shared runtime/cache for WAF and app authentication, explicit dependency
   health/control flags, exact usage scope for middleware finalization and
   `X-Usage-Store` on chat responses. Existing cached users can continue during a
   Redis outage when local budgets admit them; admitted new session writes fail
   explicitly. Revoked/expired local sessions are not resurrected.
9. Redis schema: C1/C2 initialize a missing version marker to 2; mismatches fail
   startup instead of being silently accepted. A startup Redis outage is recorded
   locally and does not disable local protection. The shared field names/TTLs
   remain those in schema v2; no kernel interface was secretly redefined.
10. ML: grouped benign-run fitting/calibration, seed 42, feature/version/dataset
    manifests, compatible-model loader, off-thread scoring, and held-out labeled
    evaluation with overlap rejection. Lower score means more anomalous. Repeated
    ML anomalies require an existing budget strike before banning; anomaly-only
    traffic is not auto-banned. Augmented/kernel corroboration is not enabled.
11. Export tooling retains stream IDs, run/request identity and explicit labels;
    unknown labels cannot be used as benign training data. C3 requires a real
    compatible saved model; absent/incompatible models fail explicitly. C4 and
    `--set ebpf` explicitly report integration pending. **No production model was
    trained or swapped** because no realistic CSV dataset exists in this checkout.
12. Management: bounded `/dashboard/evidence` exports full WAF timing spans,
    outage records/totals and drop/eviction counters without session tokens or
    prompts. Both JSON management endpoints remain connection-IP protected.
    Dashboard displays real current decisions and application enforcement, while
    clearly retaining the pre-kernel-integration boundary. Polling defaults off.
13. `scripts/run_demo.py --mode enforce` launches C2; `--mode observe` launches C1;
    default remains C0. It keeps ML/kernel disabled and owns only its processes.
    Updated README, OpenAPI, API handoff, master-plan progress and both plan notices.

Testing progression and corrections:

- First expanded suite: 47/48 passed. The one failing expectation attempted a new
  account during an outage: the unknown local account budget correctly denied it
  before persistence. The test was corrected to use an admitted, previously known
  account to exercise the required session-store 503. No fail-open change was made.
- Subsequent suites passed 52, 54, 58 and 61 tests as model-tooling, real outages,
  header/cancellation, recovery and schema cases were added.
- **Final full suite: 64/64 passed in 10.91s.** Saved JUnit report includes baseline,
  UI/access control, reset, atomic concurrency, actual/partial/unused refund,
  cancellation, output/token policies, honeypot/pubsub/TTL, cross-IP account limits,
  complete observation, outage/recovery, corrupt state and model-tooling checks.
- Real-outage tests start a disposable Redis on an ephemeral loopback port and
  use its DB 15. They terminate/restart only that owned process, proving cached
  authentication, local charge/ban behavior, expiry and recovery. The existing
  Redis service was not stopped or reconfigured. Other mutable Redis tests use
  the designated main-service scratch DB 15, flushed per test.
- ML tests train small deterministic synthetic fixtures only into pytest temporary
  paths. They validate manifests, splits, metric arithmetic, reproducibility and
  application model loading. These are not realistic detector performance numbers.
  Before/after real precision/recall/FPR: unavailable, because no prior or new
  production model/data exists. Do not present unit-fixture scores as project results.
- **12/12 real-HTTP developer probes passed twice**, including a rerun on the final
  code. Separate owned API processes tested C0/C1/C2 login bursts, catalogue bursts,
  large-output policy and decoy behavior against the actual HTTP mock. They reset
  scratch runtime state and restart per workload. C0 processed abuse; C2 throttled/
  blocked it; C1 forwarded with matching feature/decision counts and no real bans.
  This is not A's Locust attack evaluation, not final ASR and not realistic benign FPR.
- Browser C2 check: synthetic login succeeded; request for 32,000 output tokens
  showed `max_output_exceeds_policy`; subsequent 64-token request succeeded with
  9 input tokens, 64 output tokens and simulated $0.000987. Logout revoked the
  session. Dashboard showed those real allow/block decisions, connected Redis/mock,
  application enforcement, and disconnected ML/kernel. Saved screenshot/evidence.
- Python compilation and train/evaluate/export CLI help entry points passed.
  Updated OpenAPI and documentation/evidence checks were performed. Patch-context
  validation rejected a few draft edits without applying them; corrected patches
  were applied. No runtime test failures remain in the final suite.

Evidence and commands:

- [Full test report](evidence/application_defenses_tests.xml)
- [Real HTTP development checks](evidence/application_http_checks.json)
- [C2 dashboard screenshot](evidence/c2_dashboard.jpg)
- [C2 bounded process-local evidence](evidence/c2_local_evidence.json)
- [Independent status and source hashes](evidence/independent_status.json)

```bash
.venv/bin/python -m pytest -q --junitxml=docs/evidence/application_defenses_tests.xml
.venv/bin/python scripts/check_application.py
.venv/bin/python -m compileall -q app waf ml scripts tests
.venv/bin/python scripts/run_demo.py --mode enforce
```

Final cleanup: all test/probe/preview-owned app, mock and disposable Redis processes
were stopped; browser session signed out; 7 final scratch runtime keys were reset.
DB 0 was not reset, and teammate-owned `ebpf/`, `locust/`, `eval/` remain untouched.
No external deployment, credentials, real paid LLM, production model, or trained
augmented detector was introduced.

Resolved independently: B-01–09, B-11/12, B-14–16 and B-18 have implementations and
targeted checks (B-03/B-16 began in earlier work). B-13/B-17 are partially complete:
tooling/tests exist, but real data, detector metrics and A's attack validation are
still absent. B-10 and the C4 signal/expiry/model path await actual integration.
The WAF's prepared C3 path is not a claim of a production-ready trained detector.

Remaining gates and limitations:

- A must supply the three Locust attacks plus realistic multi-IP benign traffic,
  per-run IP/account labels and objective logs. Then collect multiple C1 runs,
  train/calibrate a base model and report independent precision/recall/FPR/time.
- Actual sensor signals, model freshness/fallback, augmented training, XDP and
  IT-1–6 joint runs remain pending. C4 startup is intentionally blocked for now.
- Final repeated ASR/latency/CPU-memory results and data-dependent slides need the
  matched real workloads. Available dev timings are not a final benchmark.
- Local fallback is one-worker and bounded; process restart/identity churn can lose
  local context. Unknown bucket balances stay conservative. Redis network blackholes
  can incur configured socket timeouts; tests cover service shutdown/refusal, not
  every possible network-failure latency. Unknown in-flight generation/commit can
  retain budget or need separate accounting reconciliation; no blind retries occur.
- Continue logging every further implementation/test session here. Next useful
  handoff is A's traffic and labels; no unsupported integration claim should be made.

### 2026-11-16 — updated Member B progress checklist

User requested marking their plan's checklist to track their current position.

- Updated `member_B_plan.md` section 13 against the saved 64-test report, 12 HTTP
  checks, independent status and previous work log.
- Checked B0 and independent B2/B3 implementation. Kept B1/H1, B4, the complete
  bridge deliverable and reproduction item partial; did not imply delivery to A,
  Git commits, trained production models or joint tests had occurred.
- Added completed visual/outage work, links to evidence and ordered next actions.
- Left final measurements, slides/video, full integration and oral readiness open.
- Documentation-only change: verified evidence counts and local links; no services
  started, no application changes and no unnecessary test rerun.

Next action: share the prepared handoff artifacts with A and obtain their traffic
scripts/labels. No message was sent automatically.

### 2026-11-16 — prepared the updated Member A plan for handoff

User asked whether A's plan needed changes before sending it. Reviewed the plan
against the implemented API handoff, schema v2 and current independent status.

- Added a prominent current-handoff section to `docs/member_A_plan.md`, stating
  B's implemented components, the immediate attack/benign/label deliverables and
  the fact that production ML/C4 are not ready yet.
- Listed required evaluation corrections: objective-based ASR, real config switching,
  run-key joins, labeled FPR, concurrent event capture, accounting/timing meanings,
  coordinated resets and distinct token-budget/honeypot/churn experiments.
- Listed required sensor/XDP design checks: v2 availability/units, scoped attribution,
  HTTP mock traffic, calibrated byte/token comparison, map expiry, reconciliation,
  dynamic allowlist handling and real per-IP telemetry.
- Kept old examples explicitly subordinate; corrected the old config-only merge
  instruction and unverified XDP-mode claim. No kernel function/tooling assertion
  was presented as verified; A must validate those details on the target VM.
- Added links to the files that must accompany the plan. No message or file was
  sent to A, and no teammate-owned implementation was edited.
- Documentation-only checks: local links/fences and required handoff topics.
  Runtime tests were not rerun because application code did not change.

Next action: user shares the updated plan with the linked contracts/master plan;
A supplies traffic scripts and run labels before full kernel integration.

### 2026-11-16 — connected walletguard GitHub repository

User explicitly requested linking and pushing this project to
`https://github.com/AhMeD-KhaTmi/walletguard.git`.

- The workspace had an empty `.git` directory, not a usable Git repository.
- `git ls-remote --symref` reached the remote and returned no existing refs;
  there was no remote history to overwrite or merge.
- Initialized branch `main` and added `origin` with the user-provided URL.
- No global identity was configured. Set repository-local name `AhMeD-KhaTmi`
  and email `AhMeD-KhaTmi@users.noreply.github.com`; global settings were untouched.
- Added ignores for local assistant/cloud configuration directories alongside
  virtualenv, caches and `.env` files. Checked source/evidence for common real
  credential/private-key patterns; none were found. Synthetic demo accounts remain.
- Preparing the initial commit with code, plans, contracts and saved test evidence.
  Push verification is recorded separately once GitHub confirms it.
- No application code changed; existing 64-test and 12-probe evidence is retained.

### 2026-11-16 — initial commit ready; GitHub push awaits authentication

- Created initial commit `b7a83ab` on `main`: application/WAF, UI, ML tooling,
  contracts, plans and independent test evidence (64 files). Whitespace check
  passed after removing an extra blank line at the end of requirements.txt;
  dependency entries and application behavior were unchanged.
- Confirmed virtualenv, caches, .env and local configuration directories were not
  staged. No force push, remote overwrite or branch deletion was attempted.
- `git push -u origin main` failed with: `could not read Username for
  'https://github.com': No such device or address`. This environment has no
  configured GitHub HTTPS credentials. The remote has not received this commit.
- Checked the plugin directory: GitHub is available but not connected; suggested
  its connection. The user must authenticate through a secure GitHub flow before
  an authenticated push can complete. Never request a token pasted into the chat.
- Project is linked locally to the requested origin and remains committed locally.
  Record successful remote verification in a later entry after authentication.

Next action: connect GitHub or configure Git HTTPS/SSH authentication, then run
`git push -u origin main` and verify local/remote branch heads match.

### 2026-11-16 — authenticated GitHub publication resumed

- User connected GitHub; the connected account is AhMeD-KhaTmi and has push access
  to the requested public walletguard repository. The repository was still empty.
- Retrying command-line HTTPS push still lacked a Git credential helper, so used
  the authenticated GitHub repository tools instead of requesting a pasted token.
- Initialized remote main with the current README, commit
  `ed31f81b6a2c25199f9a33e9b580edf69b01e6fa`.
- Uploading all 64 reviewed tracked files with their original executable modes.
  Local initial history will be preserved on a backup branch before main is
  aligned to the verified GitHub history. No force push or remote overwrite is used.
- Final publication verification will be recorded after the remote head and file
  tree have been checked. Existing application test evidence remains unchanged.

### 2026-11-16 — README team credit and interrupted upload recovery

- User requested adding Member A's email to the README. Added a Team table with
  B's GitHub identity and A's Attack & Kernel responsibilities/contact:
  `amantounsi@gmail.com`. This is README credit, not a repository invitation.
- A large screenshot read was truncated during blob upload; hash verification
  rejected it before any full-project tree was published. Switched to bounded
  reads. The turn was interrupted during that recovery, so publication is being
  resumed after checking the actual remote branch rather than assuming success.
- The remote bootstrap README commit remains the baseline for the complete tree.
  Text files can be submitted directly in the Git tree; binary files are uploaded
  with bounded reads and exact hash checks. No credentials or local configuration
  are included. Original local commits will remain on a backup branch.

### Template for later work entries

Date and task:

- User scope / relevant decisions:
- Files and behaviors changed:
- Checks and exact useful commands:
- Observed results and evidence paths:
- Resolved finding IDs:
- Remaining issues / external dependencies:
- Next action:
