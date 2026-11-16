# Project 20

Repository: [AhMeD-KhaTmi/walletguard](https://github.com/AhMeD-KhaTmi/walletguard).

## Team

| Member | Track | Responsibilities | Contact |
|---|---|---|---|
| [AhMeD-KhaTmi](https://github.com/AhMeD-KhaTmi) — Member B | Application & Intelligence | FastAPI target, mock LLM, ASGI WAF, ML tooling and dashboard | GitHub profile |
| Member A | Attack & Kernel | Synthetic attack/benign traffic, evaluation harness, eBPF sensor and XDP enforcement | [amantounsi@gmail.com](mailto:amantounsi@gmail.com) |

Both members share the Redis contract, integration tests, final measurements and
presentation. See the [coordinated plan](docs/MASTER_PLAN.md) for ownership and handoffs.

**Member A's AI agent:** start with [the agent handoff guide](docs/MEMBER_A_AGENT_HANDOFF.md)
for the exact reading order, first PR deliverables and submission workflow.

Member B's FastAPI target, HTTP mock LLM and application-defense starter.
Current execution plan: [docs/MASTER_PLAN.md](docs/MASTER_PLAN.md).
Work history and remaining issues: [docs/PROJECT_JOURNAL.md](docs/PROJECT_JOURNAL.md).

## Current status

The target calls a separate mock over HTTP, reports synthetic usage, and implements
C2 application budgets/bans plus complete C1 observation and bounded Redis-outage
handling. The base ML tooling is ready for labeled data. Joint attack validation,
production model training and kernel acceptance gates remain pending. The demo interface and
management dashboard are implemented at `/` and `/dashboard`; `/docs` remains
the interactive API view. The dashboard shows application enforcement while
labeling pending ML/kernel readiness explicitly. No Person A component is connected.
The current WAF emits schema-v2 decisions; legacy records are not reinterpreted.

## Local development

Quick start after Redis is reachable (uses C0 and binds both services to loopback):

```bash
.venv/bin/python scripts/run_demo.py
```

To run C2 instead, use `.venv/bin/python scripts/run_demo.py --mode enforce`.
For C1 use `--mode observe`. Restart when switching mode and reset runtime state
before comparisons. The launcher keeps ML and eBPF disabled in all three modes.

Open [demo app](http://127.0.0.1:8000/) or
[management dashboard](http://127.0.0.1:8000/dashboard).
Ctrl+C stops both owned processes. This launcher does not automatically clear
Redis data and will fail if its ports are already in use; it never stops unrelated
servers. The separate-service instructions below also remain supported.

Use Python 3.11+ (`.venv/bin/python --version`). The existing virtualenv may already
be installed; check it before recreating it. For a fresh environment:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Start a local Redis service if one is not already listening. Docker is optional:
`docker run -d --name p20-redis -p 127.0.0.1:6379:6379 redis:7`.
An existing system Redis works too. Do not replace another running instance.

In terminal 1, start the mock on loopback:

```bash
.venv/bin/python -m uvicorn app.llm_service:app --host 127.0.0.1 --port 8001
```

Stop existing experiment traffic/agents, then reset and start C0 in terminal 2:

```bash
export REDIS_URL=redis://127.0.0.1:6379/0
bash scripts/reset_state.sh
WAF_MODE=off WAF_BUCKETS=0 WAF_HONEYPOT=0 WAF_ML=0 WAF_EBPF_SIGNALS=0 \
LLM_BASE_URL=http://127.0.0.1:8001 \
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Use `--host 0.0.0.0` for the API only when namespace clients must reach the target
in the isolated lab VM. Keep the mock on loopback. One Uvicorn worker is the target.
Keep `--no-proxy-headers`: source identity must come from the connection, including
when a client sends `X-Forwarded-For` from a locally trusted proxy address.
`LLM_TIMEOUT_S` defaults to 10 seconds. There is no paid LLM integration.

In terminal 3:

```bash
.venv/bin/python scripts/smoke_baseline.py
.venv/bin/python -m pytest -q
```

The tests use and flush Redis **database 15**, which must be reserved for tests.
They launch and clean up their own mock process on an ephemeral loopback port.
Local socket permission is needed; socket denial is an environment failure, not
evidence that Redis or a bucket implementation is broken.

Open [interactive API docs](http://127.0.0.1:8000/docs) and
[dependency health](http://127.0.0.1:8000/health).
For Person A's handoff, see [contract/api_handoff.md](contract/api_handoff.md).

## Reset boundaries

`bash scripts/reset_state.sh` honors `REDIS_URL`, works without Docker, and fails
with a nonzero exit code if Redis cannot be reached. It removes documented P20
runtime keys, preserving the allowlist, schema version, unknown keys and unrelated
projects. It also removes app sessions. It does not reset a running process's local
history or kernel maps/counters: stop/restart/reconcile those separately as the
master plan requires. Do not use it while a measured experiment is running.

## Limits of this milestone

Dashboard access is checked from the actual ASGI connection address: loopback or
an exact member of `p20:allowlist`. Both HTML and JSON routes are restricted; the
HTML is outside the public assets directory. Requests from remote clients cannot
gain access by supplying forwarded-IP headers. Continue using `--no-proxy-headers`.
Do not expose this management interface through a reverse proxy without revisiting
the deployment boundary. The app's demo accounts are synthetic, not dashboard auth.

Dashboard usage is actual completed chat accounting, not all HTTP requests.
Manual refresh is the default; optional 5s polling pauses when the page is hidden.
Pause polling during benchmarks. Recent WAF entries are shown only with the
schema-v2 marker, and ban snapshots show only WAF-written bans (first 200 scanned
keys, with truncation labeled). Kernel signals/maps and attack metrics are not
queried. Unknown telemetry is displayed as unavailable rather than zero.

The demo stores the bearer session only in page memory; reloading requires signing
in again. The Sign out action also revokes the server session through `POST /logout`.
No token is stored in localStorage or sessionStorage. Rendered prompts/responses
and telemetry use text nodes; HTML pages have a same-origin CSP and no-store cache
policy. No dashboard reset, ban or configuration-changing controls are included.

The health endpoint verifies Redis/mock connectivity, reports mode and actual
application control flags; it is not XDP readiness. C3 requires an existing
compatible base model and fails explicitly if it is absent. C4 currently rejects
startup with an integration-pending message, rather than pretending to use signals.
Backend timeouts are never retried automatically because generation may have occurred.
Independent mock usage reconciliation and runtime sensor cross-checks remain joint work.

## Independent defenses and outage behavior

Requests and login attempts use Redis Lua budgets. Chat reserves estimated input
plus permitted maximum output; known unused tokens are refunded, while uncertain
generation retains its reservation. Repeated budget denials ban; precise decoy
paths immediately ban. C1 records all observations without real enforcement state.
ML anomalies alone do not ban: they need repeated anomalies and budget corroboration.

During Redis failure, one-worker local buckets retain known balances and unknown
balances start empty and refill. Cached sessions remain valid only to their original
expiry; admitted new logins needing persistence return 503. Known local/Redis bans
expire normally and local bans reconcile on recovery. Bucket recovery takes the
smaller local/Redis balance, never a fresh full burst. These guarantees are local
to one worker; restarting loses local outage context and must invalidate a measured run.

Completed generations during usage-store errors retain local accounting and return
`X-Usage-Store: local_uncertain_redis_commit`. A transport failure may mean Redis
committed before disconnecting; local totals are never automatically double-added.
Export bounded process-local evidence before restart using the management-only
`GET /dashboard/evidence` endpoint. It includes timings, outage totals/events and
dropped-record/cache-eviction counts, with no bearer sessions or prompt content.
Snapshot caches default to 4,096 identities; feature windows to 10,000 events per
IP; telemetry to 10,000 records. Saturated history is explicitly flagged. Under
identity churn these bounds can evict context; this is a prototype limitation.

Run the full suite and separate real-HTTP developer probes:

```bash
.venv/bin/python -m pytest -q --junitxml=docs/evidence/application_defenses_tests.xml
.venv/bin/python scripts/check_application.py
```

Both use scratch DB 15; do not run them concurrently with another DB-15 test or
preview. Outage tests stop only a disposable Redis created by the test, never the
existing service. The HTTP probe starts/stops owned mock/API processes and resets
DB-15 runtime state per workload. It is **not** A's Locust/ASR evaluation.

## ML data workflow — real data still required

Collect C1 runs with distinct `P20_RUN_ID` values and multiple actual source IPs.
Create a label JSON mapping run ID → IP → `benign` or `attack`, then export:

```bash
.venv/bin/python ml/export.py --labels ml/data/labels.json --output ml/data/all.csv
.venv/bin/python ml/train.py --set base --csv ml/data/benign.csv --output ml/model_base.joblib
.venv/bin/python ml/evaluate.py --model ml/model_base.joblib --csv ml/data/test.csv --output ml/model_base_evaluation.json
```

Prepare benign training/calibration input and an independent labeled test CSV
from the export before those last two commands. They require feature columns,
`feature_version=2`, `run_id` and `label`. At least two independent benign run
groups are required; final test run IDs must not overlap fit/calibration IDs.
Exclude truncated/invalid collection samples and preserve manifests. Outputs record
dataset hashes, feature order, threshold, seed and sklearn version. Load only
trusted locally generated joblib files. `--set ebpf` is deliberately unavailable
before real sensor integration. Test models use temporary synthetic fixtures only;
no production model or realistic precision/recall/FPR is claimed yet.

Do not commit real keys, bearer sessions, credential dumps or private prompts.
