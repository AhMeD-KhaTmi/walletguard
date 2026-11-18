# Project 20 — review and work journal

Last updated: 2026-11-18 (Africa/Lagos).

Latest snapshot: calibrated agent budgets pass 36 independent C0/C2/C3 runs
with zero observed benign policy denials/bans (two C2 shutdown interruptions
remain unknown). Model/scoring code passes 91 app/contract tests, 109 evaluation
tests and 12 HTTP checks. Fresh detector acceptance rejected the replacement
model; the original forest stays active. Twelve matched scoring runs validate bounded batching; mixed benign p95
median falls from 712ms to 291ms. One direct shutdown outcome remains unknown. Real kernel/C4 integration remains pending. See the latest dated entry,
`BUDGET_VALIDATION_RESULTS.md` and `MODEL_CALIBRATION_REVISIONS.md`.

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

### 2026-11-16 — full project published to walletguard

- Published all 64 reviewed files, including the README Team section with Member A
  and `amantounsi@gmail.com`, through the authenticated GitHub connection.
- Verified the complete GitHub tree SHA exactly matches the local committed tree:
  `57dada3909cfdd2989649ffbce9a23fdca749ab1`. Binary files were uploaded from bounded
  reads and individually verified against their Git blob hashes.
- Created project commit `fa16bbddb6a868829b31d26bc08af77974b17f5d` and advanced
  remote `main` without force from the known README bootstrap. `git ls-remote`
  confirmed that exact published head.
- Repository: `https://github.com/AhMeD-KhaTmi/walletguard`.
- This follow-up documentation records the verified publication and updates the
  checklist's commit status. Original local history is retained on
  `local-initial-history`; local `main` is aligned to track the GitHub branch.
- No runtime code changed in this publishing task. Existing 64-test/12-probe
  evidence remains valid; local caches, environments, .env and assistant/cloud
  configuration were excluded. No repository invitation or email message was sent.
- Command-line HTTPS Git still needs its own credential setup for future direct
  pushes; the connected GitHub tools successfully published this project without
  exposing or requesting tokens. Public fetch and remote verification work normally.

### 2026-11-16 — created Member A's AI-agent launch guide

- User requested a Markdown file explaining exactly what A's agent should read
  and push for B to review before integration.
- Added `docs/MEMBER_A_AGENT_HANDOFF.md` with the human's Member A launch prompt,
  exact reading order, ownership boundaries, current readiness, first traffic/data
  PR checklist, later kernel checklist, measurement rules and branch/PR workflow.
- Explicitly addressed the root AGENTS.md's Member B perspective: A's human should
  authorize their own track in the agent prompt; shared rules/B ownership remain.
- Prioritized attack scripts, multi-IP benign traffic and run labels before XDP,
  and required truthful test evidence plus independent train/calibration/test runs.
- Linked the guide from README. No application or teammate implementation changed;
  no invitation, message, integration or runtime test was performed by this edit.
- Checked local links, Markdown fences and required handoff topics. Existing
  runtime results are unchanged; documentation does not require rerunning them.

Publication: include the guide, README link and this journal entry in a
documentation-only GitHub update; verify the remote tree matches the local commit.
Next action: A reads the guide after cloning and submits the first traffic/data PR.

### 2026-11-16 — redesigned the repository README

- User requested a professional README. Reorganized it around WalletGuard's
  identity, threat/defense overview, clear readiness table, real screenshots,
  architecture, ordered quick start, validation, ML workflow, docs and team.
- Preserved Member A's email and the agent handoff link. Added static stack/status
  badges tied to actual files; explicitly labeled 64 tests/12 probes as recorded
  local evidence, not live CI or final integration results.
- Kept operational details in collapsible/manual sections, including source-IP
  identity, scratch DB 15, reset boundaries, mock-only costs, local fallback and
  missing production models/kernel integration. Documented redis-server as a
  prerequisite for the disposable outage-test cases.
- No runtime/dependency changes. Checked documentation links, fences, screenshot
  paths and consistency with launcher/settings and saved evidence. No unnecessary
  application test rerun for this presentation-only edit.

Publication: include README and journal in a documentation-only GitHub update,
checking the remote head and resulting tree before synchronizing local main.
### 2026-11-17 — Member A: gated DoW, §7.3 columns and grid tooling

Member A's track (`member-a/traffic-handoff`). `app/`, `waf/`, `ml/`, `contract/`
and `ebpf/` were not modified. Every traffic check ran on the p20 VM
(`172.25.235.250`, Ubuntu 24.04, Python 3.12.3, 4 cores); no traffic was run by the
assistant.

Delivered for MASTER_PLAN §7.1/§7.2/§7.3/§8:

- Gated DoW (`setup → reset → measure`): users log in once with `phase="setup"`, the
  harness waits for one marker file per user, clears runtime policy state with
  `scripts/reset_state.py --keep-sessions`, then opens the measured window. The gate
  uses files in the run directory, not Redis, because workload processes run inside
  `ip netns exec` and a network namespace has its own loopback.
- §7.3 column contract: provenance (`code_revision`, `policy_hash`), `app_cpu_pct`/
  `app_rss_mb` from a `/proc` sampler, `bans.json` archive with
  `time_to_redis_ban_ms`, `waf_overhead_ms_mean`, and unavailable-not-zero semantics
  for kernel/model fields.
- `mixed` and `combined` workloads with per-role identities and role labels; ASR for
  those rows is an aggregate and per-attack ASR comes from the separated workloads.
- Three repetitions with rotated order (`eval/run_grid.sh`), plus median/range
  summary output; a failed run is reported and re-run, never averaged in.

Checks and observed results:

- `.venv/bin/python -m pytest eval/tests -q` → **77 passed** (VM).
- Gated DoW smoke, C0, 30 s requested: 3 setup logins, 1231 measured attempts,
  `duration_s` 33.14, `wall_duration_s` 34.57, 0 bans, 0 non-zero exits,
  `invalid false`, `gate.json` `{"measured": true}`, 3 markers.
- C2 honeypot smoke, 20 s: 20 decisions archived, exactly one ban
  (`10.20.0.25`, `honeypot`, ttl 600), `time_to_redis_ban_ms` **2 ms**,
  `time_to_ban_ms` **5030 ms** (bounded by the client's 1 s probe cadence),
  `measured_attempts` 16 excluding the `phase="followup"` probes, 0 non-zero exits.
- Aggregating 13 development runs at `7849f3b` (dev evidence only, parked outside the
  repository in `~/p20-runs-dev`) gave C0 → C2 ASR: stuffing 0.1002 → 0.0,
  DoW over-cap 0.9667 → 0.0, scraping 0.9997 → 0.0081, benign FPR 0.0 in both
  configs. `app_cpu_pct` and `time_to_redis_ban_ms` were empty there, as they should
  be: those runs predate the sampler and `bans.json`.

Five defects in this tooling were found by the smoke runs and fixed before any
measured set was produced:

1. Locust discovered the `GatedUser` base class as a runnable user (no tasks) and
   wrote 3 × 323 MB of traceback with zero attempts; `abstract` must be declared on
   the subclass itself. Guard test added.
2. `deadline` existed only after `on_start` armed it, but a gated user's setup login
   also calls `send()`; the setup phase died with `AttributeError`.
3. The gate first used Redis at `127.0.0.1` from inside the namespaces, where nothing
   listens; replaced by the run-directory file handshake.
4. The setup-login count shadowed the config-flags dict in `run()`, crashing after
   traffic and losing the manifest; both renamed.
5. `time_to_ban_ms` was computed over `phase="measured"` while the real follow-up
   probes are `phase="followup"`, so it could never be produced; the unit-test fixture
   had the wrong phase and hid it. Also, the CSV dropped the manifest's `dirty` flag,
   so an uncommitted tree was stamped as a clean commit; it now ends in `-dirty`.

Open questions for Member B (not modified here):

- C2 scraping stopped at exactly 90 successes = 3 IPs × the `ip_req` capacity of 30,
  while capacity 30 + 2/s over 45 s implies ≈120 per IP. Either the bucket refill in
  `waf/buckets.py` does not accrue as configured, or successes are only attributed to
  the initial burst. Must be explained or reported, not smoothed over.
- C2 stuffing reached exactly ASR 0.0 with 200/2000 valid credentials. The plausible
  mechanism (the `ip_req` flood consumes the allowance before `login_ip` is charged)
  needs confirmation from the owner of `waf/`.

Limitations and next action: the 13-run aggregation is development evidence at
`7849f3b`, single-repetition, without `bans.json` or resource samples. The final set is
57 runs (27 C0 + 27 C2 + 3 C1 benign) at this commit, followed by `labels.py` and
`compute_metrics.py --summary-out`; results and this journal's numbers are then
committed separately.

### 2026-11-17 — Member A: measured C0/C2/C1 set (57 runs at `71f24b9`)

Scope: `member-a/traffic-handoff`. `app/`, `waf/`, `ml/`, `contract/` and `ebpf/` were
not modified. All traffic ran on the p20 VM (Ubuntu 24.04, Python 3.12.3, 4 cores,
`172.25.235.250`); no measurement was produced on Windows.

Provenance (checked from the manifests, not asserted):

```
manifests: 57
revisions: Counter({('71f24b9', False): 57})
configs:   Counter({'C0': 27, 'C2': 27, 'C1': 3})
dirty or wrong: 0
```

27 runs per config = 9 workloads × 3 repetitions with the execution order rotated per
repetition; 3 C1 benign runs are the observe-mode collection. Grids exited `0`:
`grid finished: 0 failed run(s)` and `exit=0` for both C0 and C2. The rows below were
aggregated by the tooling committed with this entry from runs whose manifests record
`71f24b9`; `eval/runs/` stays on the VM (gitignored), the derived files are in `eval/`.

Median of the three valid repetitions (C0 → C2):

| workload | attempts C0 → C2 | successes C0 → C2 | ASR C0 → C2 |
|---|---|---|---|
| scraping | 10 754 → 10 695 | 10 752 → **90** | 0.9998 → **0.0084** |
| credential stuffing | 4 751 → 4 694 | 471 → **0** (0, 0, 1) | 0.0991 → **0.0** |
| DoW over-cap | 90 → 4 901 | 90 → **0** | 1.0 → **0.0** |
| DoW under-cap | 1 811 → 4 814 | 1 811 → **10** | 1.0 → **0.0021** |
| combined | 18 431 → 21 895 | 13 850 → 100 | 0.7462 → 0.0046 |
| mixed | 35 581 → 42 910 | 26 652 → 103 | 0.7443 → 0.0024 |
| benign (FPR) | — | 0 denials both configs | 0.0 → 0.0 |

Benign impact and cost, same medians:

| metric | C0 | C2 |
|---|---|---|
| benign p50 / p95 | 4.755 / 32.662 ms | 7.073 / 35.294 ms |
| WAF overhead mean | WAF off | 3.168 ms (C1 observe: 4.196 ms) |
| combined tokens_out | 1 644 300 | 9 000 |
| combined simulated cost | $25.18 | $0.138 |
| app CPU, benign | 1.35 % | 2.23 % |
| app CPU, mixed | 29.55 % | 32.29 % |

Bans archived in C2 (all three repetitions identical): 0 for `benign`; 1 for
`honeypot` (reason `honeypot`, ttl 600); 1 for `churn`; 3 for each single attack; 9 for
`combined` and `mixed` (one per attacker address). No `anomaly` ban exists, which is
correct because `ml` is off in C2. Honeypot timing: `time_to_redis_ban_ms` **2 ms**
(server side, written while handling the decoy request) versus `time_to_ban_ms`
10 068 ms, which is the client's own probe cadence and must not be quoted as defense
latency. Budget bans land at 228–423 ms (`combined` 228, scraping 423, stuffing 262,
DoW under 311, DoW over 969).

Findings that need an owner in `waf/` (not modified here):

- C2 scraping stops at exactly **90 successes in every repetition** = 3 addresses × the
  `ip_req` capacity 30, while capacity 30 + 2/s over 45 s implies ≈120 per address. Either
  the refill does not accrue as configured, or successes are only counted from the
  initial burst.
- C2 credential stuffing is 0, 0 and 1 success over ~4 700 attempts with 200/2 000 valid
  credentials. The plausible mechanism (the `ip_req` flood consumes the allowance before
  `login_ip` is charged) needs confirmation; the ban reason is only `budget`, so this
  data cannot attribute it to a specific bucket.
- C2 under-cap DoW — designed to stay under the **token** budget — is banned after
  exactly **10 successes in all three repetitions** (311 ms). The stop is therefore the
  request-rate/shared budget, not token accounting; the under-cap row cannot be used to
  claim that token budgets stopped it. C2 over-cap is clean: 0 of 4 901 succeeded.
- `mixed` (103 successes) exceeds `combined` (100 = 90 scraping + 10 under-cap DoW). The
  aggregate row does not attribute per attack by design; per-attack ASR must come from
  the separated workloads.

Four aggregation defects were found and fixed before this entry was written; the traffic
was not re-run:

1. `dow` was summarised as one workload, mixing under-cap (1 811 attempts at C0) with
   over-cap (90), producing C0 medians of 935.5 attempts and 5 successes that no run ever
   produced. `profile` is now part of the result row and of the summary grouping key.
2. Connection churn was labelled `attack` in `labels.json` while `compute_metrics.py`
   treated it as a non-malicious probe. Churn is now labelled `probe` and kept out of the
   ML groups, per `MASTER_PLAN.md` 3.4/IT-2 (it exists to exercise kernel signals).
3. The suggested split drew benign fit/calibration runs from every config, including C0
   and C2, which write no `p20:stream:waf_features`. Splits are now restricted to C1.
4. `harness.py` wrote the `--profile` argparse default into every manifest, so 51 of 57
   runs carried `profile: "undercap"`. Manifests are immutable evidence, so the reader
   (`compute_metrics.py`) now reports a profile only for `dow`, and the harness no longer
   writes it for other workloads.

Still unavailable — do not plan around it:

- `p20:stream:waf_features` export. The stream is B's, and its export format should be
  specified by its owner rather than invented here; without it there is no feature
  matrix and no IsolationForest training.
- C1 observe-mode **attack** runs, so detector precision/recall (`MASTER_PLAN` 6.4) is
  not computable: `eval/splits.json` states `attack_features: "unavailable"`. The three
  C1 benign runs give fit/calibration/held-out benign groups only.
- Every kernel column (`time_to_map_insert_ms`, `time_to_first_xdp_drop_ms`, `agent_*`,
  `xdp_dropped_packets`): `ebpf/` is empty. C4 cannot start, and C3 needs a trained model.

`eval/schema.md` is now version 2 (adds `profile`, the DoW grouping rule, the probe label
and the C1-only split rule); `pytest eval/tests -q` → **82 passed** on the VM.

### 2026-11-17 — Member A: evidence fixes from B's review (no new traffic)

Scope: `member-a/traffic-handoff`; `app/`, `waf/`, `ml/`, `contract/`, `ebpf/` untouched.
B asked for four harness corrections, a C1 feature export, raw logs and an `llm_tok`
denial run. This entry covers the part that needs no new traffic; the rest is listed
below as still open.

Implemented, with `pytest eval/tests -q` → **94 passed** on the VM (12 new tests):

1. **A crashed or overrunning worker now invalidates the run.** `invalid_reasons()`
   combines late traffic, a non-zero exit and a worker terminated at the deadline;
   `manifest.invalid_reasons` names the worker, and `run_valid` follows it
   (MASTER_PLAN 7.2.5). Previously only `late_traffic` set `invalid`, so a worker that
   died mid-budget could still produce a "valid" row with a short denominator.
2. **The seed actually used is recorded.** `manifest.build(seed=...)` is now passed
   `--seed` instead of reading `P20_SEED` from the environment, which the harness only
   exported to the child processes — a `--seed 7` run would have been stamped 42. Each
   workload process also writes `worker-<ip>-<pid>.json` with `configured_seed` and
   `derived_seed = seed ^ pid`, collected into `manifest.workers`.
3. **Benign latency uses benign requests only** (MASTER_PLAN 7.3). `latency_p50/p95/p99_ms`
   now filter `objective=false`, so `combined`, `dow`, `scraping`, stuffing and the probe
   workloads report the latency columns as unavailable instead of publishing attack
   latency as a benign percentile. Attack latency remains in the per-attempt JSONL.
4. **C1 features are archived before the reset.** `snapshot_features()` copies
   `p20:stream:waf_features` to `<run>/features.jsonl` with `rows` and `sha256` in
   `manifest.features`. C0/C2 record `status: not_applicable`, which is not the
   same claim as an empty export. Rows already carry the WAF's `run_id` and `ip`, so
   they join to `labels.json` without re-deriving identities.

`eval/schema.md` is now version 3 (seed provenance, benign-only latency, the invalidation
rule, `features.jsonl`/`worker-*.json` in the run directory). No traffic was re-run: the
three derived artifacts were regenerated from the same 57 run directories, all still
stamped `71f24b9` and `run_valid=true`:

```
rows 57   valid {'true': 57}   configs {'C0': 27, 'C1': 3, 'C2': 27}
latency present for ['benign', 'mixed']; unavailable for the other six workloads
summary rows 159 (was 198; the removed rows are the three latency metrics for
attack-only/probe groups, not changed ASR, FPR, ban or cost values)
```

Still open, and not claimed as done:

- **No C1 feature file exists yet.** The archive step is new, and the three existing C1
  runs were reset before it existed, so their features cannot be recovered. New C1
  benign runs (three, for fit/calibration/test) plus labeled C1 attack runs are required
  before C3.
- **No `llm_tok` denial run exists.** The under-cap DoW is stopped by `ip_req` after
  10 successes, so token accounting never runs; a paced run under the request-rate
  capacity is needed, and the bucket attribution remains B's to confirm.
- **Raw per-run logs are not shared yet.** They stay on the VM under `eval/runs/`; the
  handoff needs a tar with a manifest, not a commit of runtime logs.
- The 57 existing manifests have `workers: []` because they predate the per-process
  seed record. Their derived seeds cannot be reconstructed.

Limitation to keep visible: `worker-*.json` and `features.jsonl` are inside the run
directory, so a run copied out without them loses that provenance — the manifest records
the counts and hashes, not the rows themselves.

### 2026-11-17 — Member A: paced DoW, feature-gated splits, handoff packaging (no new traffic)

Scope: `member-a/traffic-handoff`; `app/`, `waf/`, `ml/`, `contract/`, `ebpf/` untouched.
Second part of B's request, still without traffic: the three runs he needs cannot be
produced until the harness can reach `llm_tok`, can exclude featureless runs from splits,
and can hand over runtime evidence without committing it.

Implemented, with `pytest eval/tests -q` → **99 passed** on the VM (5 new tests):

1. **`llm_tok` is reachable with a paced DoW.** `locust/attack_dow.py` reads
   `P20_DOW_PACE_S` and uses `constant(pace)` instead of `between(0, 0.05)` when it is
   non-zero; `eval/harness.py` exposes `--dow-pace`, default `0` so the existing
   enforcement runs are unchanged. At the default burst the attacker account spends its
   10 `chat_req` tokens in under a second, so `ip_req`/`chat_req` throttle and
   strike-ban before `llm_tok` accounting runs; a paced run stays inside the request-rate
   bucket while it drains tokens.
2. **Splits only name runs that can train.** `labels.feature_runs()` requires
   `manifest.features.rows > 0` *and* the referenced file to exist. `suggest_splits()`
   filters both benign and attack candidates through it, so a C1 run recorded before the
   archive step can no longer land in fit or calibration. `attack_features` is now always
   written — a list when C1 attack features exist, `"unavailable"` plus a detail line
   otherwise — instead of being omitted on the successful path. `attack_runs` keeps the
   full inventory; `test` includes only runs that carry features.
3. **The handoff is reproducible.** `eval/package_handoff.sh` builds
   `features/<run_id>.jsonl`, `manifests/`, `raw/<run_id>/` (attempts, decisions, bans,
   logs), `labels.json`, `splits.json`, `results.csv`, `summary.csv` and a generated
   `HANDOFF.md` with per-file row counts and SHA-256, then prints the archive SHA-256. It
   exits non-zero when no run has a feature export, because such an archive cannot start
   C3.
4. **Manifest documentation corrected.** `manifest.build` merges `extra` at the top
   level, so the real keys are `manifest.features`, `manifest.workers` and
   `manifest.invalid_reasons`. `eval/README.md`, `eval/schema.md` and the previous journal
   entry said `manifest.extra.*`; the code was already right and only the docs changed.

Two of the five new tests initially failed on the VM for test-side reasons, both fixed:
`attack_features` was only set on the unavailable path, and Locust stores
`constant(7)`/`between(...)` as `lambda instance: ...`, so the tests must call
`wait_time(None)` rather than `wait_time()`. `bash -n eval/package_handoff.sh` →
`shell-ok` (bash is not installed on the Windows authoring machine, so the script is
syntax-checked only on the VM).

No artifacts were regenerated in this commit: the existing 57 runs are unchanged, and
`splits.json` must not be rewritten until C1 runs with archived features exist — as of
this commit it would correctly report `insufficient_benign_runs`.

### 2026-11-17 — Member A: labeled feature CSVs and usage records in the handoff (no new traffic)

B's checklist asks for the feature exports as **CSV** next to manifests, `labels.json` and
`splits.json`, and for the raw records to include usage data. The archive was JSONL-only,
so the same rows are now also rendered to CSV:

- `eval/export_features.py` reads each `<run>/features.jsonl`, joins the label from
  `labels.json` (`run_id -> ip -> benign/attack`), and writes
  `features-csv/<run_id>.csv` with identity columns first (`stream_id`, `run_id`, `ip`,
  `label`, `feature_version`, `ts_ms`, `method`, `route`) and then the feature columns.
  An address absent from the labels file is written as `unknown`, matching
  `ml/export.py`; it is never guessed benign. A run with an empty or missing export
  produces no CSV, and the command exits non-zero when no run has features.
- The result has every column `ml/train.py` validates (`FEATURES_BASE` plus `run_id`,
  `label`, `feature_version`), so it can be passed to `--csv` without conversion.
- `eval/package_handoff.sh` now runs that rendering when at least one export exists and
  fails loudly if it cannot, and copies `usage.json` (`/_metrics/usage` before/after) and
  `worker-*.json` (derived seeds) into `raw/<run_id>/` alongside attempts, decisions,
  bans and logs.

Three new tests cover the CSV join, the `unknown` fallback and the skip/no-export case.
No traffic was run and no artifact was regenerated; `bash -n eval/package_handoff.sh` is
checked on the VM because bash is not installed on the Windows authoring machine.

### 2026-11-17 — reviewed Member A's traffic and evaluation handoff

- Reviewed [draft PR #1](https://github.com/AhMeD-KhaTmi/walletguard/pull/1) at
  `5895cc44a4eb02dc8b374ffaf80a350bddce9bef` in a detached checkout based on
  `ca1375eb4879883cb6687672e1fb70e5fc89afab`. The PR adds Locust scenarios,
  an evaluation harness, namespace setup helpers, labels and split metadata,
  and 57 reported aggregate runs (27 C0, 3 C1, 27 C2). The eBPF track is a
  later handoff. Local `main` stayed on its original commit.
- Diff whitespace, Python compilation and shell syntax checks passed. The
  detached evaluation suite passed all 82 tests with one Locust/gevent import
  warning. All 64 existing application and contract tests passed with test
  Redis URLs redirected to the disposable instance in the detached checkout
  and `P20_PYTHON` pointed to the existing environment. The temporary changes
  to the two test files were reverted. Loopback runs used the real mock LLM,
  API and Locust workloads with `--no-netns`. Namespace and C4 verification
  remain pending. The 57 reported runs lack their per-run artifacts in the PR,
  so their source records could not be independently audited.
- Short loopback scraping runs succeeded on 854 of 856 C0 attempts and 30 of
  1,040 C2 attempts. C2 decisions recorded 30 allows, four `ip_req` throttles,
  one `budget` ban and 1,002 subsequent `banned` blocks. The quick ban explains
  why an abusive IP cannot keep using the bucket refill during this run. The
  over-cap chat probe recorded 12 of 12 C0 objective successes and 0 of 502
  in C2, where the decision stream included `max_output_exceeds_policy`.
  Credential stuffing, using the verified synthetic seed-42 dataset, went
  from 24 of 289 to 1 of 403. Its first C2 throttles were `login_ip`. Under-cap
  chat went from 196 of 196 to 10 of 487, with `chat_req` throttles and a
  `budget` ban in C2. A separate workload must elicit `llm_tok` denials to
  demonstrate the token budget under traffic.
- **Run validity.** `eval/harness.py` only sets `invalid` on late traffic and
  exits zero after it logs worker failures. A fault injection made one of three
  scraping workers exit 71. The harness returned 0 and `eval/compute_metrics.py`
  marked the partial run valid. Require every identity to finish and contribute
  the expected traffic before accepting a benchmark row.
- **C1 training input.** A loopback C1 run left 15 feature rows in Redis and no
  feature archive. The next run's reset clears `p20:stream:waf_features`. Export
  each C1 stream before reset and share it with its run/IP labels. Preserve
  disjoint benign fit, calibration and test runs and collect labeled C1 attack
  features for held-out detector evaluation. C0 and C2 attack rows supply ASR
  evidence. `eval/splits.json` records the absence of corresponding C1 features.
- **Measurement fidelity.** The smoke runs requested seed `53` and recorded
  `42`. Traffic RNG also incorporates the process ID. A simulated Locust read
  timeout passed through its HTTP client and was recorded as `http_0` with
  `unresolved=false`. The request calls do not consume the configured client
  timeout. A gated DoW run requested for two seconds ran for roughly five due
  to the client deadline grace. In a mixed fixture the evaluator included
  attack traffic in benign latency (190.5 ms p95 versus 10 ms benign-only)
  and counted a non-objective request from an attack-labeled IP as benign.
- Next action is to request these fixes and evidence from Member A before
  merging or using the run aggregates as final results. Review artifacts live
  under `/tmp/walletguard-review-runs.mns1p3z0` and
  `/tmp/walletguard-review-runs.b_jx6ujj` for this session.

### 2026-11-17 — verified Member A's updated traffic handoff and C1 data

- Reviewed PR #1 at `414a9a59ad577e85d5749e71cca62689d65629bb` in a detached
  worktree. Read A's new `docs/TRAFFIC_HANDOFF_2026-11-17.md` and journal.
  GitHub lists `traffic-handoff-20261117` as a prerelease. Its asset size and
  GitHub-reported SHA-256 match A's handoff. The full 141 MB archive transfer
  timed out locally. Verified the downloaded feature exports directly against
  their manifest hashes and audited the benchmark evidence available in the
  downloaded portion. Local `main` stayed at `ca1375e`.
- All six C1 CSVs match their feature JSONL exports and committed run/IP
  labels. Verified feature version, finite model inputs, disjoint groups and
  **15,613 rows**. The three benign runs contain 364, 401 and 387 rows from five
  IPs per run. The attack runs contain 4,171 stuffing, 7,000 scraping and
  3,290 under-cap DoW rows. The dataset unblocks B4 base-model work.
- Ran the existing `ml/train.py` and `ml/evaluate.py` logic on the delivered
  data in `/tmp/walletguard-c1-verified.qbf51j4u`, with a temporary model.
  Seed 42 selected `c1-benign-f1` for fitting and `c1-benign-f2` for calibration.
  On 14,848 held-out rows, detector precision was 99.91%, recall 22.81%, and
  FPR 0.78% (3 of 387 benign rows). DoW recall was 3,290 of 3,290, stuffing
  3 of 4,171, and scraping 6 of 7,000. These are detector-only results from
  the initial model. Preserve the held-out groups and use separate calibration
  data for any threshold tuning. No model was installed in the project.
- Archive metadata matched Git's labels, splits, results and summary after
  newline normalization. Inspected all 118 manifests, including 54 clean
  `4764f4b` runs with three repetitions per C0/C2 workload/profile. Recomputed
  eight corrected rows from their raw records and matched the published values.
  A's separate paced C2 probe reports 12 `llm_tok` throttles. Its committed
  row corroborates 29 of 66 successful attempts and a first Redis ban at
  91,642 ms. The paced probe's decision trace was outside the data audited.
- All 106 evaluation tests and 64 application/contract regression tests passed.
  The app tests used temporary Redis fixture URLs and `P20_PYTHON` in the review
  worktree. C1 loopback runs recorded the requested seed `53` and archived all
  feature rows (15 and 16). An injected worker exit 71 produced `invalid=true`
  and the aggregator excluded it. The CLI still returned 0, which the grid uses
  for failure counts. With Locust 2.47.0 the configured `timeout` was
  absent from the Requests call and an injected `ReadTimeout` still became
  `http_0` with `unresolved=false`. Gated DoW still adds three seconds to the
  client deadline. Benign metrics select `objective=false`; the source labels
  do not control that selection. Treat benchmark handling and timing as review
  findings before final acceptance.
- Next action for B is base-model work using the verified C1 files. A can fix
  the remaining harness issues and submit the separate eBPF/XDP handoff.
  Keep full C4 and IT-1–IT-6 verification pending.

### Template for later work entries

Date and task:

- User scope / relevant decisions:
- Files and behaviors changed:
- Checks and exact useful commands:
- Observed results and evidence paths:
- Resolved finding IDs:
- Remaining issues / external dependencies:
- Next action:

### 2026-11-17 — Member A: 63-run handoff checkpoint

- Added six measured runs: three C1 benign, C1 stuffing, C1 scraping,
  and C2 paced under-cap DoW. Aggregation reports 63 rows, 63 valid.
- Five archived C1 feature exports; C1 DoW collection remains pending.
- Paced C2 DoW: 29 successful attempts, 37 blocked, no unknown outcomes;
  first llm_tok throttle at 56537 ms, first Redis ban at 91642 ms.
- Fixed packaging of absent optional raw files; ignored eval/handoff/.
- VM checks: 102 pytest tests passed; shell syntax passed; packaging
  completed with 63 runs and five feature exports.
- Limitations: paced and unpaced under-cap runs currently share a summary
  group; pacing is absent from the measured run's manifest. Older C0/C2
  runs predate the latest harness fixes. These remain open.
- Next: collect C1 DoW, correct summary separation and finish benchmark
  reruns before producing the final handoff. No push authorized here.

### 2026-11-17 — C1 DoW received; pacing and summary comparability corrections

- Fast-forwarded the Windows branch to VM checkpoint bf681ed. The seven Windows
  working changes matched that checkpoint exactly; preserved them in a named stash.
- User verified C1 DoW at clean bf681ed: valid, no invalid reasons, 3290 feature
  rows, SHA-256 8a5a21f4d7dd80c1423fdaca10f6155575dc1356760126c526d7b817693b2d6f.
  This completes collection for all three C1 attack types; final aggregation pending.
- Harness now records effective dow_pace_s for future standalone DoW manifests.
  Historical manifests are not edited or assigned inferred pace values.
- Result schema v4 adds dow_pace_s. Summary grouping additionally separates code
  revision and pacing, preventing the 0eecf88 paced probe from joining the 71f24b9
  burst benchmark. Missing pacing stays unavailable, not zero.
- Four regression tests added for metadata, legacy missing values, revision and
  pacing separation. User reports 106 passed on the Linux VM.
- Only eval/ and shared docs changed. Next: user runs eval tests on VM, commit and
  synchronize clean revision before corrected C0/C2 benchmark reruns. No push.

### 2026-11-17 — Final PR #1 data and corrected benchmark delivery

- User completed 54 corrected C0/C2 runs at clean 4764f4b, three repetitions per
  each of nine workload/profile shapes per config, with varied execution order.
- User ran final aggregation/validation (FINAL-DATA-CHECK-OK) and verified the
  downloaded archive SHA-256. Artifact review shows 118 result rows, 118 valid;
  six complete labeled feature CSVs and matching JSONL exports, including C1 DoW.
- Archive labels/splits/results/summary match the working artifacts after line
  ending normalization. C0 intentionally has no decisions stream; C1/C2 decision
  records and all configs' usage/bans are included. Historical provenance remains
  unchanged, with unavailable pacing/worker metadata explicitly disclosed.
- Delivery asset: p20-handoff-4764f4be4548-20261117T152204Z.tar.gz,
  141492605 bytes; SHA-256
  84d0ab8c5b6f176ecab76fbcd9e422feeeca78d0ee0183a353c90f16d35cd55f.
- Added docs/TRAFFIC_HANDOFF_2026-11-17.md with B's requested deliverables,
  corrected benchmark selection, token-budget evidence, limitations and next steps.
  Current ml/train.py internally selects fit/calibration from at least two benign
  groups; f1 alone must not be represented as a sufficient training input.
- User authorized branch push and final archive Release upload. Publication is
  the next action; no merge to main, no B-owned code changes, no C3/C4 claims.
- Publication completed: delivery commit 351a0cd pushed to
  member-a/traffic-handoff; Release traffic-handoff-20261117 published at that
  commit with the archive and .sha256 attachment. GitHub reports the expected
  asset size and matching SHA-256 digest. The code/data release is marked
  prerelease, not a completed C3/C4 system release. Main was not modified.

### 2026-11-17 — integrated the traffic handoff and completed the C3 base model

- Fetched Member A's branch from GitHub and fast-forwarded local `main` from
  `ca1375e` to the reviewed `414a9a5`. Preserved A's journal entries and both B
  review entries. Continued locally in `ml/`, the demo launcher, tests and shared
  docs. GitHub publication was outside this update.
- Copied the six verified C1 CSVs to `ml/data/c1/` and assembled 765 benign
  fit/calibration rows and 14,848 held-out rows. `ml/train.py` and `ml/evaluate.py`
  now accept `--splits eval/splits.json`, enforce exact assignments and report
  counts by run. Verified the dataset, split, trainer and model hashes before
  saving [C3 evidence](evidence/c3_base_model.json). A second training run
  reproduced the manifest and model binary byte for byte. The adjacent manifest
  records dependency versions, feature units, the checked-out revision and the
  exact trainer source hash for the local edits.
- Trained 100 IsolationForest trees with seed 42 using `c1-benign-f1` and froze
  the 0.5th percentile threshold (`-0.6766539020512408`) on `c1-benign-f2`.
  On the separate held-out groups, precision was **99.91%** (3,299/3,302), recall
  **22.81%** (3,299/14,461) and benign detector FPR **0.78%** (3/387). DoW recall
  was 3,290/3,290, stuffing 3/4,171, and scraping 6/7,000. Held-out rows were
  used only for measurement. Any threshold tuning needs independent calibration
  data and a fresh held-out evaluation.
- Added `scripts/run_demo.py --mode enforce --model ml/model_base.joblib`.
  Rapid stop/start during testing exposed a local port reuse issue. Set
  `SO_REUSEADDR` for the reserved loopback sockets and verified consecutive
  launches on the same pair of ports.
- Ran 65 app/contract tests, 106 eval tests and 12 existing HTTP checks. App
  tests and original HTTP checks ran against a separate disposable Redis with
  fixture URLs redirected in a temporary copy. The split regression covers
  exact grouping, overlap rejection and run-level metrics.
- Ran A's three attack scripts and benign workload over loopback in each of
  C0/C2/C3. Used a clean disposable Redis reset before each run, one Locust user,
  three-second attack deadlines and six-second benign deadlines, with Locust
  2.47.0. Explicit per-user deadlines were needed after Locust's process shutdown
  stalled in a trial. C3 exposed real anomaly scores, logged ten anomaly strikes
  during the DoW run, and showed scoring timings in `/dashboard/evidence`. The
  three measured benign requests succeeded. These short checks confirm the app
  path and do not establish an enforcement FPR or improved attack ASR over C2.
- B4's C3 base-model work is complete. A's pending harness corrections and
  matched multi-IP VM repetitions remain required for final measurements. C4
  and augmented training require A's real sensor/XDP handoff and joint IT-1–6.

### 2026-11-17 — prepared the C2/C3 benchmark up to Member A's handoff

- Confirmed the remote traffic PR remains at `414a9a5`. Its CLI still rejects
  C3, and the worker exit-status, effective HTTP timeout and measured-window
  findings above remain open. Kept the frozen model, threshold and held-out
  split; SHA-256 of the model remains
  `591afffd16bac2bb45a13d5bf83fda7f2e10f09315df90f2bb15dc754fc4ddad`.
- Added `scripts/summarize_app_run.py`. It joins measured client requests to
  final timings by request ID, uses the run's source-IP labels for benign
  enforcement metrics, and reports coverage, benign latency, WAF overhead and
  scoring latency. It rejects marked-invalid runs, timing retention loss and
  unjoinable HTTP responses. TCP-only probes do not count as missing app timing.
- Added `WAF_TELEMETRY_LIMIT`, preserving the existing 10,000-row default and
  allowing a larger bounded buffer on both benchmark configurations. The
  [benchmark handoff](C3_BENCHMARK_HANDOFF.md) records the model fingerprint,
  required harness changes, matched run order, and how to capture and join
  the app snapshot while the API is still up.
- Ran three paired mixed-traffic rehearsals over real HTTP against disposable
  Redis. Each run used five distinct loopback source IPs, 83 measured requests,
  separate login setup and matched request counts. Confirmed all 498 measured
  HTTP requests joined to finalized app timings and that Redis saw the actual
  client source IPs. C2 and C3 each denied 0 of 54 benign requests. These
  fixed-count rehearsals verify the pipeline. The matched Linux namespace run
  is the benchmark. Summaries are in [C3 rehearsal evidence](evidence/c3_benchmark_rehearsal.json).
  Raw local records are under `/tmp/walletguard-c3-rehearsal.qq0b84_k`.
- `pytest -q tests contract` passed 68 tests, `pytest -q eval/tests` passed
  106 tests, and `scripts/check_application.py` passed all 12 HTTP checks.
  The app suite and HTTP checks used temporary fixture URLs and disposable
  Redis. Verified the handoff links, trial evidence and model hash.
- Member B's benchmark preparation is complete. The next step needs Member A
  to enable C3 and add the after-drain capture to the harness, resolve the
  worker/timeout/window findings, and deliver the paired VM run artifacts.
  The separate C4 work still awaits the real kernel handoff.

### 2026-11-17 — added the shared team checklist

- Added [TEAM_CHECKLIST.md](TEAM_CHECKLIST.md) with current status, owners,
  and the two points where A and B need to combine their work for C2/C3 and C4.
- Checked the checklist against the two member plans and the master plan,
  including integration order and slide ownership. Verified the local links.

### 2026-11-17 — verified C3 can run on this VM without kernel handoff

- Host `sudo -n` requires a password. A private user, network and mount
  namespace created all 15 client namespaces with `scripts/make_netns.sh` and
  verified their addresses with `eval/netns.py check`. `/run/netns` was mounted
  on a private tmpfs and the host network was outside the experiment.
- Used the existing harness in a disposable Python process with the old C3
  availability guard bypassed for the smoke run. Captured `/dashboard/evidence`
  before teardown. Application readiness confirmed C3 with the frozen model,
  and all eight measured benign requests from five declared client namespaces
  joined to app timing records. No requests were denied. Raw smoke evidence is
  in `/tmp/walletguard-rootless-c3.zbAGyR`.
- The C2/C3 grid can run independently of A's kernel work on this VM. The shared
  harness still needs the durable C3, failure, timeout and timing-capture changes
  before a full matched run. The smoke did not edit A-owned files or complete a
  benchmark checklist item.

### 2026-11-17 — started the full C2/C3 benchmark in an isolated checkout

- User authorized completing the harness fixes and matched runs. Created local
  branch `codex/c3-benchmark` at `/tmp/walletguard-c3-grid` and committed the
  benchmark source as `193bddcc9f9d97e76f663c9bf34016ceed7a095f`. Main retains
  its independent app changes. The benchmark uses the frozen C3 model hash
  `591afffd16bac2bb45a13d5bf83fda7f2e10f09315df90f2bb15dc754fc4ddad`.
- Harness changes include model loading and hashing, nonzero exit for invalid
  runs, effective Locust timeouts and status-zero error classification,
  stable worker seeds, and capture of the final app timing snapshot before
  shutdown. Gated chat now uses a shared fixed deadline. TCP-only churn
  records represent successful connections without an HTTP response.
- The eval and app-metrics suites passed 111 tests. Six namespace smoke runs
  passed across C2/C3 for under-cap DoW, churn and mixed workloads. Verified
  the same worker seeds and timeout in the paired smoke manifests and that
  only C3 recorded a model hash. Started the full sequential grid at the
  plan's workload durations under `eval/runs/c23-193bddc/`.

### 2026-11-17 — completed the 54-run C2/C3 Linux benchmark

- All 54 runs were accepted on their first attempt, with three repetitions
  per workload/profile/config and 291,096 measured attempts. Verified the clean
  benchmark revision `193bddc`, model hash, matched per-pair policy, namespaces,
  durations, rate/concurrency, stable worker seeds and timeouts. Raw evidence is
  under `eval/runs/c23-193bddc/`. Captured all HTTP responses' finalized timings;
  minimum HTTP timing coverage was 99.92% including transport-failed attempts.
- Archived raw evidence locally at `eval/handoff/c23-193bddc.tar.gz`, SHA-256
  `f32b530796e8ecc19e286a60d0def303680fdcf0939c00614c9900f0563f73b7`.
  The standalone eval suite passed 108 tests, plus the 68 application/contract
  tests and 12 real HTTP checks above.
- Copied the tested harness changes and runner from the isolated branch into
  the working checkout with pre-copy checks against each file's original
  contents. A-owned source changes are explicitly authorized by this task.
  The branch retains the exact measured code. Full application/contract
  regression passed 68 tests and the 12 HTTP checks passed. Eval/app-metrics
  regression passed 111 tests. A failed-worker injection verified both the
  nonzero CLI result and `exit:ns9:71` in the invalid manifest.
- Saved [per-run CSV](evidence/c23/results.csv),
  [median/range CSV](evidence/c23/summary.csv),
  [validated metadata](evidence/c23_benchmark.json) and
  [interpretation/reproduction](C23_BENCHMARK_RESULTS.md). Model, threshold,
  input features, and C1 test split remain frozen.
- Zero benign policy denials across 1,705 C2 and 1,653 C3 requests in the
  benign-only and mixed runs. Median benign-only p95 latency was 33.60 ms in
  C2 and 51.65 ms in C3. Mixed benign p95 was 36.96 versus 396.01 ms. Mixed
  finalized mean WAF overhead was 2.71 versus 132.30 ms. Median under-cap DoW
  successes were 10 for both configs, with 9,000 output tokens in both.
- C3 did not reduce successful abuse in the measured workloads. Closed-loop
  clients sent fewer attempts when responses were slower, so report the
  attempt counts and successful-request totals alongside ASR. No tuning was
  performed after measuring the held-out data or benchmark outcomes.
- Both checklist tasks are complete locally. The next collaboration with A is
  review/sharing of the benchmark branch and delivery of sensor/XDP code for
  C4. Final C0–C4 results and IT-1–IT-6 remain pending. No remote branch was
  changed during the local benchmark.

### 2026-11-17 — adopted the professor's agent and measurement requirements

- Read and visually checked all four pages of the user-supplied
  `docs/masterplan_vs_professor_diff.pdf`. Updated master plan to v1.3 and
  replaced both members' current execution instructions. The PDF reports the
  approval conditions and offers implementation suggestions. Optional live
  OpenAI/Ollama compatibility remains optional.
- Implemented a bounded simulated catalogue loop for `/chat`, default three
  steps and strict range 1–8. Each step grows context and opens a new local
  HTTP mock connection. Responses contain each step's usage and aggregate
  headers. The app charges confirmed partial usage on a later failure.
- Chose exact synthetic whitespace tokenization, version
  `synthetic-whitespace-v1`. The common estimator entry point now counts actual
  words in synthetic input/output. It has no provider-tokenizer equivalence.
  Seeded configurable latency and independent mock usage counters are recorded
  in run evidence. Whole-task WAF reservation accounts for repeated inputs,
  all outputs and deterministic tool markers. Uncertain generation retains the
  reservation, and known failures refund the unused balance.
- Moved features to version 3 with agent step and task-budget fields. Old
  models are rejected at readiness. Preserved the old binary under local
  `ml/data/historical/` and its manifest in
  `docs/evidence/model_base_v2_manifest.json`. Old C1/benchmark results are
  explicitly historical. Updated OpenAPI, API/Redis docs, the demo trace, and
  repository instructions so future work follows the professor's conditions.
- Environment check passed Ubuntu 22.04.5, kernel 6.8.0-149-generic and BTF.
  A's plan specifies app-scoped connect/execve and native-to-generic XDP with
  tc/nftables/WAF fallback recorded by backend and actual evidence. Real
  sensor/enforcement implementation remains the upcoming A handoff.
- Collected six fresh C1 runs with 10,650 feature rows. A missing generated
  credential file stopped the first attack capture at readiness. Generated the
  synthetic seed-42 file, preserved the failed manifest under the collection's
  excluded directory, and resumed after the three valid benign captures.
  Fit/calibration each used 187 rows and the held-out set used 10,276 rows.
  Base model precision was 66.67%, recall 0.0397%, benign detector FPR 1.047%
  (2/191). The low recall is recorded without tuning against held-out data.
- Application/contract tests passed 75 cases, eval tests passed 109, and all
  12 original HTTP checks passed. Six C0/C2/C3 namespace smoke runs passed.
  Created the clean measured snapshot `aa51185` on local branch
  `codex/professor-agent-update` and started 81 matched C0/C2/C3 runs at the
  existing workload durations. Current raw output is
  `eval/runs/professor-aa51185/`. Final validation follows completion.

### 2026-11-17 — finalized the professor-update campaign and current plans

- Completed **81 valid runs**, 27 per configuration C0/C2/C3, over nine profiles
  and three repetitions with seeds 42/43/44. No invalid attempts or retries.
  Verified all 27 matched triplets have identical policy, seed, source roles,
  timeout, duration and mock settings. All manifests identify clean measured
  source `aa51185caa87307672e4042683a9e6ccfbbfe59d`.
- Added `scripts/validate_professor_benchmark.py` and ran it against every raw
  manifest and usage snapshot. Independent API/mock steps, input/output tokens
  and cost agree in all 81 runs. Enforced-run finalized timing coverage exceeds
  98%. This post-run validator is the only Python/script addition after the
  measured snapshot; app/WAF/model/eval runtime source still matches it exactly.
- Published `docs/PROFESSOR_BENCHMARK_RESULTS.md` and per-run/aggregate/validated
  evidence under `docs/evidence/professor_benchmark/`. C0 over-cap clients time out
  on all 45 attempts per run, while server counters prove 4.32 million output
  tokens and simulated cost $77.79105. Its client ASR 0% is an unknown-outcome
  lower bound, not evidence of prevention. C2/C3 generate zero tokens for that
  profile. Kept the timeout and workload unchanged across configurations.
- Safety targets remain **unmet**: C2 denies 40/1,702 benign requests (2.350%),
  C3 denies 37/1,629 (2.271%); each has one benign budget auto-ban. No benign
  errors, timeouts or unknown outcomes. C3's new model has only 0.0397% held-out
  detector recall, and mixed-load client p95 is 645.329 ms versus C0's 96.847 ms.
  Recorded independent budget calibration, detector investigation and fresh
  held-out retesting as B's remaining work. No tuning used these held-out results.
- Verified the C3 browser interface with synthetic user1: prompt `hello world`,
  three steps and eight output tokens per step. Visible inputs were 2/19/36,
  output 8/8/8, totals 57 input and 24 output, simulated cost $0.000531.
  Stopped the disposable preview API/mock/Redis after inspection. An initial
  preview approval request hit a usage-limit rejection; after the user's
  continuation, the approved retry and browser check completed successfully.
- Preserved current 12 HTTP checks in `docs/evidence/professor_http_checks.json`;
  updated the professor metadata with 75 app/contract tests, 109 eval tests,
  six namespace smoke runs and the browser result. One known Locust/gevent
  monkeypatch warning occurred during eval tests; all cases passed.
- Updated master plan, both current member checklists, README and simple team
  checklist. The 81-run measurement task is checked; final security acceptance,
  independent calibration, real sensor/enforcement and C0–C4 integration remain
  unchecked. Original starter examples and version-2 evidence remain historical.
- Packaged source aa51185, fresh C1 data, frozen model and all 81 raw runs in local
  `eval/handoff/professor-agent3-aa51185.tar.gz`, 80,172,140 bytes, SHA-256
  `96059c0be3a11ba0eb9a77a8043bb8f7bfb04b9c06efc83e3f5b90dbaa9e753a`.
  Inventory/checksum: `docs/evidence/professor_handoff.json`. Nothing was pushed
  or sent to A during this session.
- Final checks: benchmark validator passes, pooled benign denominators and zero
  benign errors/timeouts/unknowns rechecked, current plan/report local links resolve,
  `git diff --check` passes. No source runtime changes followed the completed
  regression suites or campaign.

Next: share the prepared update with A; B can independently calibrate budgets
and investigate detector performance. The next joint integration consumes A's
real sensor and tested enforcement backend, followed by augmented training and
IT-1–IT-6. Current acceptance failures must remain visible until fresh tests pass.

### 2026-11-17 — prepared the parallel-work publication

- The user authorized publishing the current work so A can develop in parallel.
  Checked the remote main head before pushing; it remains `ca1375eb`. The clean
  local review branch contains the integrated traffic work and professor update.
- Updated `docs/MEMBER_A_AGENT_HANDOFF.md` to start from the professor-update branch
  and proceed to kernel work. Its original first-PR instructions are now explicitly
  historical. A reads the current professor report and team checklist before work.
- Included the repository-generated frozen C3 model and manifest in `ml/artifacts/`
  so a fresh clone can run C3. Verified SHA-256
  `bb0116a167318df1749a0edf5cf5b95362ccde59f6b8580d732ed82d05722ca1` and successful
  runtime loader validation with 19 features. Documented dependency compatibility,
  startup commands and known detector limitations. No model retraining or runtime
  behavior changed. Large raw datasets/campaign archives remain outside Git history.
- Publishing on `codex/professor-agent-update` preserves remote main and lets A
  create an independent kernel branch from the shared tested source. Push outcome
  will be recorded after remote verification.

- Terminal push could not authenticate (no GitHub username/credential available).
  The connected GitHub app reports repository push permission. Publishing an
  equivalent complete source tree through that app instead; preserving original
  local commits including aa51185 in `docs/evidence/professor_source.bundle`.
  `git bundle verify` passes, and checksum/prerequisite metadata is saved beside it.
  This changes publication commit IDs, not the measured runtime file contents.

- Automatic approval review rejected uploading the Git history bundle because it
  could expose unreviewed historical files beyond the requested project-file push.
  Excluded that bundle and its metadata from the publication; it remains only in
  /tmp locally. Continuing with reviewed current files, the frozen model and
  explicit runtime provenance. No workaround is used to publish the rejected archive.

### 2026-11-17 — published the professor update for parallel work

- Published reviewed current files through the connected GitHub app on
  `codex/professor-agent-update`, initial commit
  `f053386d3cd2e7d8076cfca4785ec08b7ca37a50`. Remote tree
  `36d898fa9b15ab120eaea1f1c0bd503db99b21ba` exactly matches local checkpoint
  `e99aec6`; GitHub publication commit IDs differ because app-based commits were
  used instead of an authenticated terminal push.
- Fetched the remote branch and verified its frozen model's SHA-256 matches
  `bb0116a167318df1749a0edf5cf5b95362ccde59f6b8580d732ed82d05722ca1`.
  Confirmed remote main stayed at `ca1375eb`. No force push or merge was performed.
- Opened draft coordination PR #2:
  https://github.com/AhMeD-KhaTmi/walletguard/pull/2 . It explicitly lists the
  already-integrated A traffic handoff, professor changes, checks and open safety/
  model issues. A starts a separate kernel branch from the published update and
  reads `docs/MEMBER_A_AGENT_HANDOFF.md` first. No message was sent to A directly.
- Checked off the sharing task. The current source, model/manifest, plans, journal
  and summarized benchmark evidence are on GitHub. The 80 MB full raw-run package
  stays local. The rejected history bundle was excluded from the published tree.
- This final publication follow-up changes only the journal, checklist and
  publication provenance. Earlier application/eval tests and the frozen campaign
  remain applicable; no runtime source or model was changed after those checks.

### 2026-11-17 — merged the shared update into main

- The user clarified that the current project should be on main for parallel work.
  Rechecked remote main/head and verified main was an ancestor of the tested
  publication branch; there were no newer main changes or conflicts.
- Compared every saved measured runtime file and the frozen model hash to the
  published branch; all match the tested source. GitHub reports no commit status
  checks; the earlier local test/campaign evidence remains the validation basis.
- Marked PR #2 ready and merged it with expected head
  `76a5dc27224d381875d8eac04ab7bae303328b94`, without force. Merge commit:
  `f0c8f120780712a6b0f7facc49b40244bf146ace`.
- Updated A's current handoff and the sharing checklist to start from origin/main.
  Both members should create separate work branches from main and submit PRs.
  Budget/model calibration, sensor/enforcement and joint acceptance remain pending.
- This follow-up changes documentation/provenance only. No model/runtime changes
  require a new benchmark. Verify the final main tree and model after publication.

### 2026-11-17 — started independent Member B token-budget calibration

- Created `codex/b-budget-calibration` from synchronized main `a05542a`, leaving
  A free to develop the kernel layer. Main and the frozen model/81-run campaign
  stay unchanged during this work.
- Diagnosed the existing benign failures: `llm_tok` 429s for a legitimate shared
  account accumulated five budget strikes, then its IP ban also blocked catalogue
  requests. The initial 20,000-token capacity / 100-token-per-second refill predates
  repeated agent context. Existing failures identify the mechanism only; they do
  not select the replacement values.
- Wrote `docs/BUDGET_CALIBRATION.md` before new collection: C1 seeds 101/102/103,
  normal and varied-agent benign traffic, 120s each. Fixed the fitting rule in
  advance (125% peak 60s per-account demand and two-task burst). Independent
  validation uses seeds 201/202/203, C0/C2/C3, with normal/varied benign traffic,
  mixed traffic and paced under-cap DoW. Freeze the candidate before validation.
- Added B-owned scripts for a varied-step benign workload, explicit harness
  adaptation/metadata, private namespace orchestration, campaign execution and
  calibration fitting. A's `locust/`, `eval/` and `ebpf/` files were not edited.
  The adapter explicitly records the selected workload file/hash and effective
  policy; it uses A's original capture, timeout, invalidation and reset behavior.
- Calibration fitting rejects held-out/untagged/non-C1 runs and requires unique
  client/feature/decision joins with exact whole-task usage. Four new focused
  tests pass; the private launcher passes shell syntax checking. Next: namespace
  smoke check, six fresh C1 captures, fit/freeze and separate validation.

- Smoke attempt `budget-smoke-v1` stopped at readiness before traffic because
  Locust was missing from the virtualenv. Preserved its failed manifest/log.
  Installed the project's workload requirements with Locust 2.47.0; its Redis
  constraint moved the client from 8.1.0 to 6.4.0. Saved environment metadata and
  reran the full checks using an owned disposable Redis/DB 15: 79 app/contract,
  109 eval tests (one existing gevent warning), and 12 HTTP probes passed.
- All six clean-source C0/C2/C3 namespace smoke runs in `budget-smoke-v2` passed.
  API/mock step and token counts agree for both benign scenarios. Evidence for
  these baseline checks is under `docs/evidence/budget_calibration/`.
- Starting six 120s C1 calibration captures from a clean dedicated worktree;
  source is isolated from any subsequent report/helper edits. No policy values
  or model thresholds have changed yet.

- Collected all six C1 worker-valid captures (2,985 feature rows initially), with
  clean source `3cbb1f2` and exact API/mock totals. The stricter fitting gate
  rejected normal seed-101 run 1: nine client ReadTimeouts and one ConnectionError
  prevent complete request-ID joins. Server logs show no corresponding app
  exception; the cause of that transport interval is not established. Preserved
  the entire capture under `ml/data/budget-calibration-v1/excluded/`, including
  a rejection record, and started a full same-seed repetition with a new retry ID.
  No candidate was fitted from the incomplete run and no validation data was used.
- Added a regression for two concurrent eight-step normal tasks on one account.
  It reproduces `[200, 429]` under the original capacity, where the desired
  calibrated burst is `[200, 200]` with a later over-budget task still throttled.
  The expected old-policy failure XML is preserved. Six calibration/helper tests
  pass, including rejection of fractional costs and separation of normal/varied
  C0 baseline references. The validation summarizer now verifies all 36 planned
  runs, matched triplets, labeled benign bans and independent usage totals.
- A small offline probe on 32 calibration feature rows found identical scores
  when batched (max difference 0), with 177.11ms total single scoring versus
  7.00ms in one vectorized call. Saved it as an offline optimization lead, not a
  live latency claim. The frozen model/scoring path remains unchanged in this
  budget campaign so the allowance's effect can be measured independently.

- The same-seed replacement completed without chat transport failures. The six
  accepted calibration captures now contain 3,046 feature rows and 1,035 measured
  chats. The largest task costs 19,044 tokens; peak per-account 60s demand is
  113,550 tokens. The predeclared rule selects **40,000 capacity / 2,400 tokens/s**.
  Saved accepted run hashes and the fixed rule in
  `docs/evidence/budget_calibration/frozen_policy.json` before validation.
- Applied only those default token values in `waf/config.py`. Request/login/chat
  request limits, output cap, strike thresholds, ban expiry and scoring/model are
  unchanged. Updated capacity-sensitive tests and documented the derived private
  bucket cleanup TTL (34,334ms); shared TTLs/schema remain unchanged. Master plan
  v1.4 and both member plans explicitly mark independent validation as pending.

- Candidate regressions passed **82 app/contract tests**, **109 eval tests** and
  **12 HTTP probes**, all against owned disposable Redis/DB 15. The shared-account
  burst reproducer now passes: two large tasks succeed and a third is throttled
  without banning ordinary browsing. Saved candidate XML/HTTP evidence under
  `docs/evidence/budget_calibration/`. Frozen model SHA-256 is unchanged.
- Freezing the candidate source for the 36 independent validation runs: three
  repetitions at seeds 201/202/203, normal/varied benign, mixed and paced DoW,
  matched C0/C2/C3. No adjustment may use these results as calibration data.

- Independent validation is running from clean source `9cd6f4a` in
  `/tmp/walletguard-budget-validation`; artifacts are under
  `eval/runs/budget-validation-v1/`. After 24/36 runs, normal/varied benign-only
  C2 has 0 denials/0 bans over 1,498 requests and C3 has 0/0 over 1,495. These
  are interim counts, not final acceptance. First paced DoW server outputs are
  162,000 C0 / 70,200 C2 / 67,500 C3 tokens, with explicit token throttles in both
  enforced modes. The higher allowance supports normal agents but permits more
  residual abuse; do not describe it as complete attack prevention.
- Added post-run reporting for explicit token throttles, mixed per-attack outcomes
  and benign model flags separate from policy denials. No runtime/model changes
  enter the frozen budget campaign. Six accepted calibration CSVs are exported
  with labels for future independently split model work.
- Prepared a separate `codex/b-model-calibration` checkout at
  `/tmp/walletguard-model-work` for the next B phase. Its protocol is fixed before
  training: seven behavioral/cost inputs with log1p, 100-tree IsolationForest,
  seed 42, benign 101/102 fit and 103 calibration, a 5th-percentile flag threshold
  behind the unchanged corroboration gate, plus fresh C1 test seeds 301–303 and
  401–403. Original models/evidence stay immutable and budgets remain frozen.
- Prepared backward-compatible model input/transform manifests and bounded
  asynchronous microbatch scoring (32 rows, 2ms collection, 256 queued rows).
  Five focused queue tests passed in 0.06s with normal local event-loop/thread
  wakeups. The restricted test process stalled on cross-thread wakeups and was
  terminated by its timeout; the same tests pass with ordinary socket permissions.
  No production runtime workaround was added for that execution restriction.
  Full ML regressions/training are deferred until the measured budget run ends.

### 2026-11-18 — completed independent budget validation; continued model work

- All **36 runs** completed at source `9cd6f4a`, forming 12 matched C0/C2/C3
  triplets, seeds 201/202/203. The post-run validator checked clean code, identical
  scenario/policy settings within each triplet, full source coverage and exact
  independent API/mock tokens/steps/cost. Report:
  `docs/BUDGET_VALIDATION_RESULTS.md`; evidence in
  `docs/evidence/budget_calibration/results.csv` and `validation.json`.
- Policy safety targets met: **0/2,804 C2** and **0/2,749 C3** observed benign
  denials, zero benign bans across normal/varied benign and mixed runs. C2 has two
  unresolved `GreenletExit` requests at worker shutdown (one product read, one
  chat, each under 1ms). They remain unknown, not successes or blocked requests.
  Even the conservative per-run unknown-as-denial bound remains below 1%. The
  JSON keeps policy-safety and complete-client-outcome status distinct; strict
  complete-outcome status is false for the two affected C2 groups.
- Paced DoW medians: C0 outputs 162,000 tokens, C2 70,200 and C3 67,500. C2/C3
  each record 12 explicit token throttles across their three runs. Median ASR is
  100% / 41.27% / 40.32%. Report the allowance/security tradeoff and residual abuse;
  this is not full attack prevention. The original 81-run data remains frozen.
- Updated the current plans, checklist, README and Redis private-TTL notes to
  distinguish completed budget calibration from pending model/kernel work. No
  shared key/shape/TTL, request cap, strike limit, ban TTL or allowlist was changed.
- The separate model/scoring source passed **90 app/contract tests**, **109 eval
  tests**, and **12 HTTP probes**. Its adapter adds Locust's five-second graceful
  stop timeout to avoid the observed client-shutdown interruptions in future
  campaigns; it records that option without editing A's harness/workloads.
- Model source `86f34e5` reproduced the original forest's threshold and every
  preserved test score exactly. Candidate v1 (seven log1p inputs, fresh benign
  fit/calibration, 5th-percentile flags) achieved 99.82% historical recall but
  flagged 25/191 historical benign rows (13.09%); preserved and rejected it.
  Its hash is `8332d8a41b9a347eff8b9231680adc93c4c4f7e3b0b7eea6fd59432fa1e38d76`.
- Before opening fresh test metrics, defined v2 by adding only the original
  benign fitting run to fitting and its separate calibration run to calibration,
  covering both five- and ten-user normal traffic. Features, seed, tree count and
  percentile stay fixed; no held-out rows enter training. The still-unopened
  fresh C1 test set is collecting seeds 301–303 and 401–403. Revision rationale is
  in the local `docs/MODEL_CALIBRATION_REVISIONS.md`; v1 is not silently replaced.
  No new model has been deployed on main or in the completed budget campaign.

### 2026-11-18 — fresh model acceptance failed; isolate scoring performance

- Completed nine independent C1 test groups at clean source `86f34e5`: six
  normal/varied benign groups at seeds 301–303 and three attack groups at seeds
  401–403. Explicit request-ID joins yield 11,590 rows (2,308 benign / 9,282
  malicious), CSV SHA-256
  `d8c1f33ad7d29e37a03cb50ad3788ee855b52479e6d55a461e7f72cce859c251`.
- Preserved v1 and v2 development failures. Before opening fresh results,
  fixed final v3 to three log1p inputs (request rates and max output), with
  unchanged broadened benign groups, trees, seed and calibration rule. The
  revision record explains the historical comparisons and development bias.
- Final candidate hash
  `1b4dc810cb605abecb063a6e2624b4fda32fe696174ecb1df7c1c17784d1f361`
  achieved 628 TP / 84 FP / 8,654 FN / 2,224 TN: precision 88.20%, recall
  6.77%, benign detector flags 3.64%. Recall and precision fail the previously
  fixed >=20% / >=90% gates. Rejected it; no candidate live-safety campaign or
  deployment is authorized by those failed gates. Fresh test rows must not be
  reused to tune another candidate.
- Frozen original model remains active. On the same fresh groups its recall is
  0.0646%, precision 33.33%, benign detector flags 0.520%. These low-recall
  results remain explicit; budget enforcement does not establish model quality.
- Both explicit training input profiles and the scoring prototype now pass
  **91 app/contract tests**, **109 eval tests**, **12 HTTP checks**. Evidence:
  `docs/evidence/model_calibration/prototype_*`. Reproduced original training
  still matches every historical score and threshold exactly.
- Matched performance-only campaign is running at clean source `c220319` in
  `/tmp/walletguard-model-performance`, original model unchanged. Twelve C3
  direct/batched runs cover benign and mixed workloads at seeds 601–603.
  Each run records batching settings and a five-second Locust stop timeout.
  A's `eval/`, `locust/` and `ebpf/` files remain untouched.

### 2026-11-18 — recovered interrupted scoring campaign

- The environment restarted and cleared the temporary worktrees. Seven completed
  captures are intact. Mixed direct repetition 2 had empty manifest/ban/usage/app
  JSON snapshots despite appearing in the index; it is excluded and preserved
  under `eval/runs/model-performance-v1/excluded-restart/`. Repetition 3 had no
  manifest and did not start successfully. Do not treat those as valid results.
- Restored detached source `c220319` and its synthetic credential fixture. Replayed
  mixed direct seed 602 and the four seed-603 runs with identical commands, model,
  budgets, duration and batching settings. The same-seed reverse order for mixed
  repetition 2 remains batch then direct, with the restart between them. Record
  this interruption as a limitation; raw captures preserve both attempts.
- Updated stale journal summary, model research evidence and both plans. Model
  replacement remains rejected; source profile support alone does not deploy it.

### 2026-11-18 — completed scoring performance validation

- All twelve clean-source runs passed capture validation, matched as six pairs.
  Report `docs/SCORING_PERFORMANCE_RESULTS.md`; CSV/JSON under
  `docs/evidence/model_calibration/performance.*`. Validator checks matching
  source/model/policy/seeds/workloads, identities, timing and API/mock totals.
- Median benign p95: direct 128.56ms vs batch 120.18ms. Mixed-load benign p95:
  direct 712.05ms vs batch 291.50ms. Mixed scoring p95: 165.39ms vs 52.99ms.
  Keep bounded batching (32 rows, 2ms, capacity 256) as the default. Original
  model/threshold remain unchanged; size 1 retains the direct comparison path.
- Batched benign outcomes: zero denials/unknowns/bans over 1,088 requests.
  Direct: zero denials/bans over 1,044, with one 0.858ms chat GreenletExit at
  shutdown retained as unknown. Five-second graceful stopping reduces but does
  not eliminate every interruption. Earlier commentary claiming complete direct
  outcomes was premature; the final report includes the unknown explicitly.
- Mixed CPU median rises from 91.12% to 96.75% of one core as throughput changes;
  do not claim CPU-per-request savings. No C0 performance pair was measured in
  this campaign. C0 overhead evidence remains in the earlier matched campaigns.
- Final check command initially used a nonexistent contract/tests directory, then
  a pytest entrypoint missing repository imports. Corrected to python -m pytest
  tests contract in a private network namespace with disposable Redis DB15.
  These invocation failures did not indicate a runtime test failure.

- Final isolated regression completed: **91 app/contract tests**, **109 evaluation
  tests** (one known gevent monkey-patching warning), **12 real-HTTP checks**.
  Results: `docs/evidence/model_calibration/final_*`. Disposable Redis and every
  owned service stopped afterward. `git diff --check` passes; A-owned source
  directories have no changes from main. Original model SHA-256 remains `bb0116…ca1`.
- Next: publish reviewed source/reports to main, preserve ignored raw captures
  locally, and keep recall improvement and A's real kernel/C4 integration open.
