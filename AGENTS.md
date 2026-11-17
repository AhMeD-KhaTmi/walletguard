# AGENTS.md

Guidance for Codex (or any AI coding assistant) working in this repository.

## Current execution context

Before non-trivial work, read `docs/MASTER_PLAN.md`, `docs/PROJECT_JOURNAL.md`,
`member_B_plan.md`, and `docs/member_A_plan.md`. The master plan contains the
coordinated decisions authorized on 2026-11-16 and supersedes conflicting starter
examples in the original plans. `contract/redis_schema.md` specifies operational
schema version 2; it is a target specification, not a claim that current code
implements it. Preserve ownership boundaries and C0–C4 meanings. Update the journal
after meaningful work with files, checks, outcomes and next steps.

## Project

**Project 20: eBPF / Behavioral Runtime Intrusion Detection & Automated Token-Bucket ASGI WAF Against LLM "Denial-of-Wallet"** — Pillar IV: API Security. ISG Tunis, Master SSI (2026-2027), Secure Coding & AI Agent Security.

A two-person Red-vs-Blue security project. We attack a deliberately vulnerable FastAPI/LLM app (credential stuffing, layer-7 scraping, LLM token-exhaustion Denial-of-Wallet), then defend it with a two-layer Blue Team: an ASGI behavioral WAF (Redis token buckets, honeypot auto-ban, IsolationForest anomaly scoring) and an eBPF kernel layer (runtime sensor + XDP packet drop). The two layers are connected only through Redis (the "Redis Bridge" contract in Section 4). We must demonstrate the attacks succeeding against the vulnerable baseline and then being deterministically detected, blocked, or auto-remediated by the hardened system, with quantitative Attack Success Rate (ASR) and latency metrics.

## I am Member B ("Application & Intelligence" track).

I own `app/`, `waf/`, `ml/`. My teammate (Member A, "Attack & Kernel" track) owns `ebpf/`, `locust/`, `eval/`. `contract/` and `docs/` are shared. Full plans: `member_B_plan.md` (mine) and `docs/member_A_plan.md` (teammate's) — read both before making non-trivial changes, since this system only works as the two halves together.

**Professor-approved execution requirements (2026-11-17, master plan v1.3):**
Use Ubuntu 22.04/24.04, kernel >=5.15 and BTF. `/chat` runs a bounded simulated
agent loop over the local mock with growing context, exact synthetic token counts,
configurable deterministic latency and aggregate/per-step usage. Features are
version 3, so use compatible data and models. A's sensor covers scoped connect
and execve activity. Native XDP may fall back to generic/skb, tc/nftables or WAF
enforcement with an explicit backend/mode and evidence. Report per-attack ASR,
benign FPR, p50/p95 client deltas from matched C0 and finalized WAF p50/p95.
See `docs/masterplan_vs_professor_diff.pdf` and both updated member plans.

## Repository layout

```
app/        # MINE: FastAPI baseline app, mock LLM, token accounting
waf/        # MINE: ASGI middleware — token buckets, honeypot, strikes, IsolationForest scoring
ml/         # MINE: feature extraction, IsolationForest training/eval, saved models
ebpf/       # TEAMMATE'S: BCC sensor, XDP program, Redis-sync agent — do not edit without asking
locust/     # TEAMMATE'S: attack + benign traffic scenarios — do not edit without asking
eval/       # TEAMMATE'S: evaluation harness (ASR, detection rate, time-to-ban)
contract/   # SHARED: Redis key/stream schema, fake_ebpf.py, fake_waf.py, integration tests
docs/       # SHARED: both member plans, slides, diagrams, results
common/     # SHARED: tiny helpers used by both sides (e.g. token estimation) — keep dependency-free
scripts/    # SHARED: reset_state.sh, environment setup helpers
```

Treat `ebpf/`, `locust/`, `eval/` as read-only reference unless my teammate asked me to change them — changes there must stay consistent with his plan.

## Environment

- Target OS: **Linux VM** (eBPF/XDP require it; my own parts run fine on Linux/Mac/WSL2 too, but keep testing on Linux since the full integration only works there).
- Python 3.11+, virtualenv at `.venv`.
- Redis (run via Docker: `docker run -d --name p20-redis -p 6379:6379 redis:7`).
- Install: `pip install -r requirements.txt` (fastapi, uvicorn[standard], redis, scikit-learn, numpy, pandas, joblib, pytest, pytest-asyncio, httpx).
- `pytest.ini` sets `asyncio_mode = auto`.

## Commands

```bash
# Run the target app, WAF off (vulnerable baseline)
WAF_MODE=off uvicorn app.main:app --host 0.0.0.0 --port 8000

# Run the hardened app (buckets + honeypot + IsolationForest)
WAF_MODE=enforce WAF_ML=1 uvicorn app.main:app --host 0.0.0.0 --port 8000

# Collect training data without blocking anything
WAF_MODE=observe WAF_ML=0 uvicorn app.main:app --host 0.0.0.0 --port 8000

# Tests
pytest

# Reset all runtime state before a measured run (always do this first)
bash scripts/reset_state.sh

# Train IsolationForest (base model, then eBPF-augmented model)
python ml/train.py --set base --csv ml/data/benign.csv
python ml/train.py --set ebpf --csv ml/data/benign.csv
```

There is no build step. Never commit real credentials, real LLM API keys, or anything beyond the synthetic demo accounts already in `app/main.py`.

## Configurations (keep these five consistent across app, docs and eval)

| Config | Meaning | Key env vars |
|---|---|---|
| C0 | Vulnerable baseline | `WAF_MODE=off` |
| C1 | Observe only (data collection) | `WAF_MODE=observe WAF_ML=0` |
| C2 | Buckets + honeypot | `WAF_MODE=enforce WAF_BUCKETS=1 WAF_HONEYPOT=1 WAF_ML=0` |
| C3 | C2 + IsolationForest | `WAF_MODE=enforce WAF_BUCKETS=1 WAF_HONEYPOT=1 WAF_ML=1` |
| C4 | C3 + eBPF signals/XDP | adds `WAF_EBPF_SIGNALS=1`, teammate's sensor + XDP loader running |

The baseline and hardened app must be **the same code**, only the middleware toggled by `WAF_MODE`/flags — never fork a separate "vulnerable" copy, or the ASR comparison becomes invalid.

## The Redis Bridge contract (do not change without updating both sides)

All keys use prefix `p20:`. Full schema lives in `contract/` and in both member plans — treat it as the one source of truth for key names and shapes. Summary of what I write vs read:

**I write:** `p20:ban:<ip>` (JSON: ip, reason, source, ts_ms, ttl_s — reasons: `honeypot`, `budget`, `anomaly`), `p20:ch:ban` (pub/sub, `{"op":"add","ip","ttl_s","reason"}`), `p20:stream:waf_decisions` (ts_ms, ip, client_id, route, decision, reason, anomaly_score, llm_tokens_charged, latency_ms — this `latency_ms` is **WAF overhead only**, never end-to-end), `p20:stream:waf_features` (observe mode only).

**I read:** `p20:sig:ip:<ip>` (conn_rate_1s/10s, syn_rate_10s, failed_conn_10s, bytes_in_10s, updated_ms — TTL 60s), `p20:sig:host` (egress_bytes_llm_60s, egress_conns_llm_60s, unexpected_exec_count, updated_ms — TTL 120s), `p20:allowlist` (never ban/throttle these IPs — mine and his harness/host IPs only, **never** an attacker IP).

**Rules I must always follow:**
- Identity = source IPv4 address as seen by the ASGI scope (`scope["client"][0]`) — never trust `X-Forwarded-For` in this setup.
- Redis is the source of truth for bans; I only *write* bans, I never assume the eBPF side's map state.
- I am the primary decision-maker for bans (honeypot, budget, anomaly). My teammate's agent only makes its own hard-threshold ban (`ebpf_conn_flood`) using the same key format — don't special-case that reason differently.
- If Redis is unreachable, fall back to local in-memory buckets rather than failing open or failing closed outright — confirm this behavior still holds before changing middleware error handling.
- Any change to a shared key name, field, or TTL must be reflected in `contract/` and flagged to the teammate — do not silently rename or restructure these.

## Conventions

- Python, type-annotated where practical, `async def` throughout the FastAPI app and WAF (the whole stack is ASGI — never introduce blocking I/O in the request path without `asyncio.to_thread`).
- Token counting goes through `common/tokens.py::estimate_tokens`, the exact
  synthetic whitespace tokenizer. Whole-task reservation uses
  `common/agent.py::reserve_tokens` for repeated inputs and all outputs.
- Redis Lua scripts in `waf/buckets.py` own normal token-bucket math. The approved Redis-outage exception is a locked process-local backend in that same module, with equivalent policy semantics and conservative recovery as specified in `docs/MASTER_PLAN.md`. Do not implement bucket math in other modules; keep take/refund atomic within each backend.
- New WAF behavior should be added as a new check inside `WAFMiddleware._decide`, returning a `Verdict`, not as a separate middleware layer, unless there's a specific reason to split it.
- Config values (bucket capacities/rates, ban TTL, strike limits, honeypot paths) live in `waf/config.py::Config` — don't hardcode them elsewhere.
- New Redis keys outside the shared contract must be prefixed `p20:` and documented as "private" in `contract/` if they could be confused with shared state.

## Testing expectations

- Any change to `waf/buckets.py`, `waf/bans.py`, or `waf/middleware.py` needs a corresponding test in `tests/` (see `tests/test_buckets.py` for the pattern) using a scratch Redis DB (`redis://localhost:6379/15`), flushed at the start of the test.
- Before claiming a feature works, run it against at least one of my teammate's attack scripts in `locust/` (read-only reference) against configs C0 and C2/C3, and check `eval/results.csv` or `p20:stream:waf_decisions` for the expected effect — don't just unit-test in isolation.
- Run `bash scripts/reset_state.sh` before any manual or measured run so results are reproducible.
- IsolationForest changes: re-run `ml/train.py` on the same `ml/data/*.csv`, and report precision/recall/false-positive rate before and after — don't swap the model without these numbers.

## What not to do

- Don't edit `ebpf/`, `locust/`, or `eval/` without flagging it — that's the teammate's track, and silent changes there break his plan/checklist.
- Don't add real LLM API keys, real leaked-credential lists, or any non-synthetic sensitive data — this project uses a mock LLM and synthetic credentials only (see `docs/member_A_plan.md` Section 3.2 for how the synthetic credential dataset is generated).
- Don't change the five configs' (C0-C4) meaning or env var names without updating both plans and `eval/schema.md`.
- Don't claim OWASP/CWE IDs, citations, or official terminology from memory in `docs/` slides — these must be verified against the current official sources before being presented (see `member_B_plan.md` Section 9 and `docs/member_A_plan.md` Section 9 for the lists needing verification).
