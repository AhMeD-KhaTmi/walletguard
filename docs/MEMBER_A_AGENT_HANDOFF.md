# Start here — Member A's AI agent

Repository: [AhMeD-KhaTmi/walletguard](https://github.com/AhMeD-KhaTmi/walletguard).
Prepared 2026-11-16 for the **Attack & Kernel** track.

## Application robustness findings — 2026-11-18

Read `docs/ROBUSTNESS_RESULTS.md` before interpreting earlier model accuracy as
broad protection. Forty-five fresh fixed-policy runs expose allowed slow/distributed
abuse and collateral shared-account/large-burst bans. Within-capacity bursts remain
a separate successful control. This study changed no app/WAF/model/Redis contract
or A-owned source. The existing model and budgets remain the baseline; B owns the
prospective application remedies. Continue sensor/enforcement work in parallel,
and coordinate any future policy version before the final matched C0–C4 campaign.

## Current model/lifecycle handoff — 2026-11-18

Use the qualified `ml/artifacts/model_base_volume_v1.joblib` explicitly for new
C3 runs, with the recorded sklearn1.9.1 environment. B's current model achieves
99.01% detector recall /99.58% precision on fresh labeled groups. Benign flags
are5.77%, separate from blocking. Independent confirmation records zero benign
C3 denials/unknowns/bans over966 requests. Read `docs/DETECTOR_VOLUME_RESULTS.md`.

The initial live grid failed due to one GreenletExit at shutdown. Its evidence
remains preserved. B's opt-in supervised driver fixes the self-quit lifecycle
path while preserving your workload/request/classification files. For measured
replays, invoke `scripts/budget_harness.py` with `P20_SAFE_DRIVER=1`; its manifests
record driver hash and mode. See `scripts/locust_deadline_driver.py` and protocol.
A may later incorporate this fix into A-owned plumbing; no such files were edited.

Validated llm_tok remains40,000 capacity /2,400 tokens/s; batching32/2ms remains.
Feature version3 and Redis schema2 remain. Preserve the original frozen model and
all previous campaigns. Your next task remains real sensor/enforcement delivery;
joint real-signal C1 collection, augmented training and C4 follow that handoff.

## Historical handoff — professor update, 2026-11-17

PR #2 is merged. Start from `main`. Fetch it, then create your own
work branch from that remote branch; keep any existing local work committed first.

```bash
git fetch origin
git switch -c codex/member-a-kernel origin/main
```

The first traffic/data handoff described below has already been integrated.
**Your next work is the real kernel sensor and enforcement backend**, following
the current checklist at the top of `docs/member_A_plan.md`. Do not repeat PR #1.

Read the required files in section 2, plus `docs/PROFESSOR_UPDATE.md`,
`docs/PROFESSOR_BENCHMARK_RESULTS.md`, and `docs/TEAM_CHECKLIST.md`. The current
runtime uses a three-step simulated agent by default, feature version 3 and exact
synthetic token counting. Preserve Redis schema v2. B's budget/model calibration
continues independently; use the frozen model for comparison without retuning it.

The frozen compatible C3 model is included at
`ml/artifacts/model_base_agent_v3.joblib`, with its manifest and setup instructions
in `ml/artifacts/README.md`. Its low recall and scoring overhead are known open
issues. C1/C2 can be used for sensor development without ML. C4 stays gated until
real signals, enforcement telemetry and an augmented model are ready.

Deliver app-attributed `connect`/`execve` events and real Redis signals, then tested
XDP native/generic or an explicitly recorded approved fallback. Include freshness,
ban expiry, allowlist, reconciliation and per-IP enforcement evidence. Submit a
separate branch/PR and update the journal. The next joint step is real-signal C1
collection and IT-1–IT-6, followed by final C0–C4 measurements.

The publication uses GitHub's connected app because terminal Git credentials are
unavailable. The remote publication commit can therefore differ from local source
commit IDs, while its complete file tree is verified against the prepared branch.
Measured runtime provenance is recorded in
`docs/evidence/professor_publication.json`; original local commits and full raw
captures stay in B's local evidence package. This branch contains the reviewed
current files and frozen model needed for your work.

The original launch instruction and PR #1 checklist below are historical guidance;
the current handoff above and current member plan supersede their old status.

## 1. Human launch instruction

Member A should paste this into their agent after cloning the repository:

> I am Member A, responsible for the Attack & Kernel track. Read
> `docs/MEMBER_A_AGENT_HANDOFF.md` first, then every required document it lists.
> The root AGENTS.md describes Member B's ownership perspective; for my work I
> authorize changes to `ebpf/`, `locust/`, and `eval/`. Preserve Member B's app,
> WAF and ML code and the shared Redis contract. Start with the traffic/data
> handoff on a separate branch, test it, update the journal and open a pull request.
> Do not merge or push directly to main. Report what was tested and what remains
> unverified. Do not wait for the kernel layer before submitting the first handoff.

The agent should follow its human's explicit role instruction. This guide does
not authorize changing account permissions, exposing services publicly, sending
messages or modifying Member B's components without coordination.

## 2. Read these files in this order

Paths are relative to the repository root; Markdown links below work from this file.

| Order | Exact file | What to understand |
|---|---|---|
| 1 | [AGENTS.md](../AGENTS.md) | Shared rules, ownership, safety, tests; interpret the B-specific folder restriction through your human's Member A instruction |
| 2 | [docs/MASTER_PLAN.md](MASTER_PLAN.md) | Current agreed architecture, C0–C4, gates, evaluation and integration acceptance |
| 3 | [docs/member_A_plan.md](member_A_plan.md) | Read the **Current handoff** section first; original snippets below are superseded where they conflict |
| 4 | [docs/PROJECT_JOURNAL.md](PROJECT_JOURNAL.md) | Read latest status/work entries and unresolved findings; do not repeat completed B work |
| 5 | [member_B_plan.md](../member_B_plan.md) | B's responsibilities, dependencies and section 13 progress checklist |
| 6 | [contract/redis_schema.md](../contract/redis_schema.md) | Schema v2: exact keys/fields, units, availability, expiry and decision meanings |
| 7 | [contract/api_handoff.md](../contract/api_handoff.md) | API routes, synthetic accounts, usage headers and failure semantics |
| 8 | [contract/openapi.json](../contract/openapi.json) | Machine-readable request/response contract |
| 9 | [README.md](../README.md) | Current setup, local modes, reset and test commands |
| 10 | [docs/evidence/independent_status.json](evidence/independent_status.json) | Saved independent results and explicit remaining work |

For the project background, also read
[project20_ebpf_asgi_waf (2).md](../project20_ebpf_asgi_waf%20%282%29.md).
The master plan and versioned contract govern execution; do not copy old starter
code blindly. Flag any new disagreement rather than silently changing a shared rule.

Read relevant source as reference before coding: `app/main.py`, `app/schemas.py`,
`app/llm_service.py`, `waf/config.py`, `waf/middleware.py`, `common/tokens.py`,
`scripts/reset_state.py`, and the tests for the behavior your work depends on.

## 3. Ownership and current state

You implement `locust/`, `eval/` and `ebpf/`. B implements `app/`, `waf/` and `ml/`.
Contracts, documentation and setup helpers are shared: identify their changes
explicitly in your PR and coordinate before changing behavior. Keep common helpers
dependency-free. Do not rewrite the root AGENTS.md to erase the other member's rules.

B has implemented the baseline, HTTP mock, C1 observation, C2 budgets/bans, Redis
outage handling, UI/dashboard and base ML tooling. The saved check run passed
64 automated tests and 12 real-HTTP developer probes. Re-run relevant checks on
your actual checkout; these counts do not guarantee your environment is ready.

There is **no production ML model or realistic detector evaluation yet**. C3 needs
a trained compatible base model; C4 explicitly rejects startup until integration
is implemented. Do not remove those readiness checks to make a demo appear ready.
The developer probes are not your Locust attack scenarios or final ASR results.

## 4. First PR — traffic and data handoff

Suggested branch: `member-a/traffic-handoff`. Deliver this before finishing XDP.

- [ ] Three runnable synthetic attack scenarios: credential stuffing, catalogue
  scraping and LLM token-exhaustion. Use explicit target host configuration.
- [ ] Seeded synthetic credential generator/data; no real leaked credentials.
- [ ] A realistic benign generator with varied browsing/chat, accounts, pauses and
  payload sizes, from multiple **real source IPv4 addresses**.
- [ ] Reproducible namespace/veth setup and cleanup for the isolated Linux VM,
  with management, benign and attacker identities recorded separately.
- [ ] Separate account pools and source IPs for measured benign/attack traffic.
  Never put either pool on `p20:allowlist`; that is for management only.
- [ ] Client attempt/objective records, including timeouts and unknown outcomes.
  Exclude login/setup/management calls from malicious chat denominators.
- [ ] C0 baseline evidence and C2 comparisons when runnable. Include repeated
  under-cap chat so output-cap rejection does not hide whether token budgets work.
- [ ] Explicit honeypot and connection-churn probes; ordinary scraping does not
  guarantee decoy hits or new TCP connections because keep-alive reuses connections.
- [ ] Multiple independently identified C1 collection runs and a label JSON using
  `run_id -> source IP -> benign/attack`. Set API `P20_RUN_ID` for each run.
- [ ] Raw feature exports or a reproducible collection/export procedure, plus run
  manifests containing seeds, rates, concurrency, durations, account/IP roles,
  dataset hashes, software versions and code revision.
- [ ] Tests, exact launch commands, expected outcomes, cleanup and limitations.

Use `locust/` for workloads and synthetic datasets, `eval/` for client objective
logging/harness/run manifests, and shared `scripts/` only for documented helpers.
File names can follow your detailed plan. Include a small manifest/README explaining
where B should find each deliverable and how to reproduce it.

Example **shape only** for labels (replace run IDs/IPs with actual observed values):

```json
{
  "benign-run-001": {"10.20.0.11": "benign", "10.20.0.12": "benign"},
  "attack-run-001": {"10.20.0.21": "attack"}
}
```

Do not fabricate traffic rows, sensor signals or performance results. B needs
separate run groups for model fitting/calibration and a held-out labeled test.
Do not put runtime passwords, bearer tokens, real prompts or private captures in
shared logs. Document synthetic generation inputs without dumping request secrets.

## 5. Evaluation rules your implementation must preserve

- Count genuine attack objectives, not Locust's generic success/failure flag.
  Use the master plan's attack-specific ASR definitions and report actual synthetic
  token cost, unique accounts/products and unresolved outcomes separately.
- Switch the actual processes/flags for each config; verify readiness before a run.
  Join results by `(run_id, config, workload, repetition)`, not config alone.
- Use labeled benign attempts for FPR; shadow `would_*` decisions are not real
  denials. WAF logs cannot count packets dropped before ASGI or C0 requests.
- Record client-side end-to-end latency separately from WAF `latency_ms`. Collect
  ban/map/drop timestamps during traffic and use actual IPs, not placeholders.
- Reset runtime state **before** measured runs. Stop traffic first; coordinate
  Redis, local process histories and kernel state. The Redis helper does not reset
  your kernel maps. Preserve management allowlist/schema and archive old evidence.
- Update `eval/schema.md` to match master-plan section 7. Keep final measurements
  separate from developer probes. Missing data/events are unavailable, not zero.

## 6. Later PR — kernel layer and integration preparation

Suggested branch: `member-a/kernel-layer`, based on reviewed current main.

- [ ] Scoped sensor: correct peer IP, API connection windows, independent SYN/
  failure/byte measurements and app-attributed exec events. Verify kernel/tooling
  assumptions on the VM using official documentation; validate BCC installation.
- [ ] Schema-v2 producer with correct TTLs, `updated_ms`, units and `available_fields`.
  Do not label placeholder zeroes as measured quantities.
- [ ] Observe API-to-HTTP-mock traffic on port 8001, including local loopback.
  Attack clients target API port 8000. The local demo launcher binds loopback;
  namespace tests need the API bound to `0.0.0.0` in the isolated VM, with
  `--no-proxy-headers`. Keep the mock loopback-only.
- [ ] Calibrated directional byte/usage cross-check. TCP bytes, tokens and money
  have different units; account for JSON/protocol overhead and retransmissions.
- [ ] Expiring XDP ban map, remaining Redis PTTL, allowlist handling, pub/sub plus
  reconciliation, per-IP drop telemetry and owned-interface cleanup.
- [ ] Expiry still works when the agent dies; newly allowlisted IPs leave the map.
  Record actual attach interface/mode instead of assuming generic/native behavior.
- [ ] `contract/fake_waf.py` or equivalent controlled bridge tests; explicit failure
  and recovery checks; no claims that mock signals prove real integration.

B remains the normal ban decision-maker. Optional kernel hard-threshold bans use
the existing `ebpf_conn_flood` contract. C4 signal reading, augmented model training
and IT-1–6 acceptance are joint work, not something to bypass on B's behalf.

## 7. How to submit your work to B

After accepting the collaborator invitation and authenticating Git:

```bash
git clone https://github.com/AhMeD-KhaTmi/walletguard.git
cd walletguard
git switch -c member-a/traffic-handoff
# Implement and test only the agreed first handoff.
git add <reviewed-file-paths>
git diff --cached --check
git commit -m "Add reproducible attack and benign traffic handoff"
git push -u origin member-a/traffic-handoff
```

Open a pull request **from your branch into `main`**. Do not merge it, push directly
to main, force-push B's branches, or overwrite B's working tree. B will review and
test the proposed changes in an isolated checkout before updating their branch.

The PR description must state: what changed, deliverable paths, commands/tests
actually run, observed outcomes, environment requirements, shared-contract changes
(if any), known failures and remaining integration work. Link committed sanitized
evidence; attach/link larger artifacts with a manifest rather than silently omitting
them. Do not claim C3/C4 results when their readiness dependencies are absent.

Update `docs/PROJECT_JOURNAL.md` after meaningful work, preserving existing history.
Record files changed, test commands/results, evidence paths and next steps. Reserved
Redis DB 15 is flushed by B's tests: never run those tests against a database holding
anything valuable or concurrently with another DB-15 experiment.

Your final message to your human should include the **PR URL**, branch, test summary,
and a short “ready for B / still pending” list. Your human sends the PR URL to B.
No automatic email/chat message to B is authorized by this guide.
