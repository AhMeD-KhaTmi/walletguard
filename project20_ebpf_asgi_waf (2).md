# Project 20: eBPF / Behavioral Runtime Intrusion Detection & Automated Token-Bucket ASGI WAF Against LLM "Denial-of-Wallet"

> This file is a complete replacement for the two screenshot pages the project was taken from.
> Sections 1-3 and 8-9 reproduce what is written in the source. Sections 4-7 and 10 are explanations and suggestions added to help you understand and execute the project. They are clearly labeled as such.

---

## 1. Source Document Information

| Field | Value |
|---|---|
| Institution | Higher Institute of Management of Tunis (ISG Tunis) / Institut Supérieur de Gestion de Tunis (logo: "Since 1969") |
| Course | Secure Coding & AI Agent Security |
| Program | Master SSI (2026-2027) |
| Project number | Project 20 |
| Security pillar | Pillar IV: API Security |
| Page of the project booklet | Page 15 |
| Prepared by | Chaouki Bayoudhi |

---

## 2. Project Title (exact)

**Project 20: eBPF / Behavioral Runtime Intrusion Detection & Automated Token-Bucket ASGI WAF Against LLM 'Denial-of-Wallet'**

(The title is followed by a stray `//` in the source. It looks like a formatting leftover and carries no meaning.)

---

## 3. Project Card (verbatim content)

**Project 20 - Security Pillar:** Pillar IV: API Security

**Core AppSec, Agent Harness & Security Stack:**
FastAPI/Django ASGI + Redis Token Bucket + IsolationForest + Locust

**Red-Team Exploit vs. Blue-Team Defense & Verification Architecture:**

- **Red:** Credential stuffing, layer-7 scraping & LLM token-exhaustion Denial-of-Wallet
- **Blue:** ASGI behavioral WAF with Redis token-bucket budgets, payload anomaly scoring & honeypot auto-ban

---

## 4. Plain-Language Summary (added explanation)

You build a small web/API application that sits in front of (or wraps) an LLM. First you leave it **vulnerable** (the "baseline"). Then you attack it as a **Red Team** with three kinds of abuse:

1. **Credential stuffing**: automated login attempts using leaked username/password pairs.
2. **Layer-7 scraping**: bots harvesting data through the application layer (HTTP/API level).
3. **LLM token-exhaustion "Denial-of-Wallet"**: sending requests designed to burn as many paid LLM tokens as possible, so the victim loses money instead of (or in addition to) losing availability.

Then you play **Blue Team** and build a two-layer defense: an **eBPF runtime layer** at the Linux kernel level (behavioral runtime intrusion detection, and optionally kernel-level dropping of banned clients), plus a **behavioral Web Application Firewall (WAF)** implemented as ASGI middleware. The WAF uses:

- **Redis token buckets** to give each client/key/IP a budget (requests and LLM tokens),
- **Payload anomaly scoring** (IsolationForest) to detect abnormal requests,
- **A honeypot with auto-ban** to catch and block bots automatically.

Finally you **measure** the result: the attack must succeed against the baseline, and then be detected, blocked, or auto-remediated by your defense, with numbers (Attack Success Rate and latency).

---

## 5. Key Concepts Explained (added explanation)

### 5.1 Denial-of-Wallet (DoW)
An attack on pay-per-use services (LLM APIs charge per input/output token). Instead of crashing the service, the attacker makes it expensive: huge prompts, requests that force very long outputs, repeated calls, or abuse of an agent loop. The victim's cloud/LLM bill explodes. Related to **OWASP LLM Top 10: Unbounded Consumption**.

### 5.2 Credential Stuffing
Attackers replay large lists of leaked credentials against a login endpoint, hoping users reused passwords. Signs: many failed logins from many IPs/accounts, low request rate per IP (to evade simple limits), consistent timing.

### 5.3 Layer-7 Scraping
Bots that mimic legitimate clients at the HTTP/application layer to bulk-extract content or data. Hard to catch with network-level filters because each request looks valid. Needs behavioral detection (request patterns, endpoint sequences, rates).

### 5.4 ASGI
Asynchronous Server Gateway Interface, the async successor to WSGI for Python web apps. **FastAPI** is ASGI-native, and **Django** supports ASGI. A WAF written as an **ASGI middleware** sees every request before it reaches your route handlers, so it can inspect, score, throttle, or reject it.

### 5.5 Redis Token Bucket
A rate-limiting algorithm: each client has a bucket that holds up to N tokens and refills at a fixed rate. Each request spends tokens; if the bucket is empty, the request is rejected (HTTP 429). Redis is used as shared, fast, atomic storage (typically via Lua scripts or atomic commands) so limits work across multiple workers/instances. "Budgets" in this project means you can have separate buckets, for example:
- requests per minute per IP,
- login attempts per account,
- **LLM tokens per user/API key per time window** (the key defense against Denial-of-Wallet).

### 5.6 IsolationForest (scikit-learn)
An unsupervised anomaly-detection algorithm. It isolates points with random splits, and anomalies are isolated in fewer splits. Here it is used for **payload anomaly scoring**: you extract features from requests (payload size, prompt length, entropy, number of fields, request rate, endpoint, headers, etc.), train on normal traffic, and score new requests. A high anomaly score contributes to blocking or throttling.

### 5.7 Honeypot Auto-Ban
A decoy endpoint, hidden link, or fake field that no legitimate user should touch (for example a path listed in `robots.txt` as disallowed, or a hidden form field). Any client hitting it is almost certainly a bot, so it is **automatically banned** (for example IP/key stored in Redis with a TTL).

### 5.8 Locust
An open-source Python load-testing tool. Here it is used as the **attack generator** for the Red Team: simulating credential stuffing, scraping and token-exhaustion traffic, and for measuring latency under load.

### 5.9 eBPF (mentioned in the title)
Extended Berkeley Packet Filter: a Linux kernel technology that runs sandboxed programs in the kernel to observe or filter system calls, network events, etc. with low overhead. It is used for **runtime intrusion detection** at the OS/network level. **In this project eBPF is a required component** (it is in the title). It acts as the kernel-level runtime sensor and enforcer that complements the application-level ASGI WAF: it watches the host (connections, processes, outbound LLM traffic) and can drop banned IPs before they ever reach the Python app. See the design in Section 7 and the plan in Section 12.

### 5.10 Behavioral WAF
A WAF that decides based on **behavior over time** (rates, sequences, anomalies, budgets) rather than only static signatures like "block requests containing `<script>`".

---

## 6. Red Team vs Blue Team Breakdown (added explanation)

| Red-Team Attack (from source) | What it does | Blue-Team Control (from source) | How the control stops it |
|---|---|---|---|
| Credential stuffing | Mass login attempts with leaked credentials | Redis token-bucket budgets (per IP and per account), honeypot auto-ban | Limits attempts per identity; bans clients that trip decoys |
| Layer-7 scraping | Bulk automated data extraction via valid-looking requests | Payload anomaly scoring (IsolationForest), token buckets, honeypot auto-ban | Flags abnormal request patterns; throttles; bans bots that follow decoy links |
| LLM token-exhaustion Denial-of-Wallet | Forces excessive LLM token consumption and cost | Redis token-bucket budgets (token budgets), payload anomaly scoring | Caps tokens per client/window; flags abnormally large or crafted prompts |

---

## 7. Suggested Architecture (added explanation, adapt as needed)

The title says **"eBPF / Behavioral Runtime Intrusion Detection & Automated Token-Bucket ASGI WAF"**, so the Blue Team has **two cooperating layers**:

- **Layer A: eBPF runtime layer (kernel/host).** Observes and optionally enforces at the OS level.
- **Layer B: ASGI behavioral WAF (application).** Token buckets, anomaly scoring, honeypot.

```
        RED TEAM (Locust)                              BLUE TEAM
  +---------------------------+     +-------------------------------------------------+
  | Credential stuffing       |     | LAYER A - eBPF (Linux kernel)                    |
  | Layer-7 scraping          | --> |  - XDP program: drops packets from banned IPs   |
  | LLM token-exhaustion DoW  |     |    (reads a BPF hash map of banned IPs)         |
  +---------------------------+     |  - kprobes/tracepoints: connect/accept rates,   |
                                    |    execve (unexpected processes), egress bytes  |
                                    |    to the LLM provider, per-PID/per-IP counters |
                                    |  - User-space agent (Python/BCC) reads events   |
                                    +------------------------+------------------------+
                                                             |  events / bans (via Redis)
                                    +------------------------v------------------------+
                                    | LAYER B - ASGI Behavioral WAF (middleware)       |
                                    |  1. Ban check (Redis)                            |
                                    |  2. Honeypot routes -> auto-ban                  |
                                    |  3. Token buckets (Redis): requests + LLM tokens |
                                    |  4. IsolationForest anomaly score                |
                                    |  5. Decision: allow / throttle (429) / block     |
                                    +------------------------+------------------------+
                                                             |
                                               FastAPI / Django ASGI app
                                                             |
                                                  LLM backend (or mock)
```

**How the two layers cooperate (suggested design):**
- **Detection signals from eBPF** (connection bursts, abnormal outbound byte volume to the LLM API, suspicious processes) are published to Redis and added to the anomaly features / strikes used by the WAF.
- **Bans decided by the WAF** (honeypot hit, budget exhausted repeatedly, high anomaly score) are written to Redis, and the eBPF agent copies them into a **BPF map** so the **XDP program drops the attacker's packets in the kernel**. This is the "auto-remediation".
- **Egress monitoring** with eBPF gives an independent measurement of real LLM traffic (bytes/connections), which helps verify that the token budgets really cap the cost.

**Suggested request flow:**
1. Packet arrives. XDP checks the banned-IP map and drops it if listed.
2. The ASGI WAF identifies the client (IP, API key, user, fingerprint) and checks the Redis ban list.
3. If the request hits a honeypot route, add the client to the ban list with a TTL (the eBPF agent syncs it into the XDP map) and reject.
4. Consume tokens from the request bucket and, for LLM calls, estimate and consume from the LLM-token bucket. If empty, return 429.
5. Extract features (including eBPF-derived ones) and compute the IsolationForest score. Above threshold means block or throttle; borderline adds a strike.
6. Forward the request to the app. After the response, reconcile real token usage against the budget.
7. Log every decision for the metrics (ASR, latency, detection rate, time-to-ban).

---

## 8. Mandatory Deliverables (verbatim content)

**Mandatory Deliverables (Theoretical Presentation + Red-vs-Blue Prototype)**

- **Theoretical Presentation (Slides):** Formal threat model (CWE / OWASP Top 10 / OWASP LLM & Agentic Top 10 mapping), custom architecture and attack/defense sequence diagrams drawn by your team, installation and tool configuration steps, and a cited comparison matrix of defense mechanisms.
- **Red-vs-Blue Executable Prototype:** Demonstrate the attack succeeding against the vulnerable baseline and being deterministically detected, blocked, or auto-remediated by your hardened Blue-Team implementation with quantitative Attack Success Rate (ASR) and latency metrics.

(This deliverables box appears on a separate page with the ISG Tunis header, so it is most likely the common requirement for all projects in the booklet, applied here to Project 20.)

---

## 9. Official Security Standards & Documentation References (from source)

- **OWASP API Security Project** - https://owasp.org/www-project-api-security/
- **Scikit-Learn IsolationForest** - https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html

(The source shows these as hyperlinks with only their names visible. The URLs above are the standard official pages. Verify them when you open the original document.)

---

## 10. Deliverables Explained in Detail + Execution Checklist (added explanation)

### 10.1 Theoretical Presentation (Slides): what each requirement means

| Requirement in source | What you should produce |
|---|---|
| Formal threat model | Assets, actors, entry points, attack scenarios, impact, likelihood (STRIDE or similar is a reasonable method) |
| CWE / OWASP Top 10 / OWASP LLM & Agentic Top 10 mapping | A table mapping each attack to identifiers (see suggestions below) |
| Custom architecture | Your own diagram of the vulnerable baseline and of the hardened system |
| Attack/defense sequence diagrams drawn by your team | Original sequence diagrams (not copied) for each attack and how the WAF reacts |
| Installation and tool configuration steps | Reproducible setup: FastAPI/Django, Redis, scikit-learn, Locust, (eBPF tooling if used), with config values |
| Cited comparison matrix of defense mechanisms | Table comparing e.g. fixed-window vs token bucket vs sliding window, signature WAF vs behavioral WAF, IsolationForest vs other detectors, with citations |

**Suggested mappings (verify against the current official lists before citing):**

- OWASP API Security Top 10 (2023): API2 Broken Authentication (credential stuffing), API4 Unrestricted Resource Consumption (DoW, scraping), API6 Unrestricted Access to Sensitive Business Flows (scraping/automation).
- OWASP Top 10 for LLM Applications: Unbounded Consumption (Denial-of-Wallet).
- OWASP Top 10 for Agentic Applications: pick the items related to resource abuse and tool/agent misuse that match your design.
- CWE candidates: CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-770 (Allocation of Resources Without Limits or Throttling), CWE-400 (Uncontrolled Resource Consumption), CWE-799 (Improper Control of Interaction Frequency).

### 10.2 Red-vs-Blue Executable Prototype: what each requirement means

| Requirement in source | What to build/show |
|---|---|
| Vulnerable baseline | The app with no rate limits, no anomaly detection, no budgets |
| Attack succeeding | Locust scripts for the three attacks that visibly work against the baseline (accounts compromised/guessed, data scraped, tokens/cost burned) |
| Deterministically detected, blocked, or auto-remediated | Repeatable runs (fixed seeds, fixed datasets) where the WAF consistently returns 429/403 or bans the client |
| Hardened Blue-Team implementation | ASGI middleware with Redis token buckets, IsolationForest scoring, honeypot auto-ban |
| Quantitative ASR | Attack Success Rate = successful malicious requests / total malicious requests, for baseline vs hardened, per attack type |
| Latency metrics | Request latency with and without the WAF (p50, p95, p99), to show the overhead of the defense |

### 10.3 Checklist

- [ ] Choose FastAPI or Django (ASGI) and set up the vulnerable baseline
- [ ] Add (or mock) an LLM endpoint with token counting
- [ ] Set up Redis
- [ ] Write the Locust Red-Team scenarios: credential stuffing, scraping, token exhaustion
- [ ] Record baseline results (ASR, cost/tokens burned, latency)
- [ ] Implement token-bucket middleware (requests + LLM tokens)
- [ ] Collect normal traffic, extract features, train and tune IsolationForest, set thresholds
- [ ] Implement honeypot routes + auto-ban with TTL in Redis
- [ ] Implement the eBPF sensor (connection, execve and egress monitoring) and publish events to Redis
- [ ] Implement the XDP drop program + BPF map of banned IPs, synced from the Redis ban list
- [ ] Re-run the attacks against the hardened version and record ASR and latency
- [ ] Check for false positives with legitimate traffic
- [ ] Build slides: threat model, mappings, architecture, sequence diagrams, setup steps, comparison matrix with citations
- [ ] Prepare a deterministic live demo of baseline vs hardened

---

## 11. Notes and Ambiguities to Be Aware Of

1. **eBPF is part of the project.** It is in the title, so it is treated as a required component. The stack line does not list an eBPF tool, so you choose it yourself (this plan recommends BCC with Python, see Section 12). It must run on Linux, so plan your environment early.
2. **"Agent Harness"** in the stack heading suggests the LLM/agent part of your system (the thing being protected and abused) should be included in the prototype, even if it is a mock.
3. The stray `//` under the title is not part of the project.
4. The deliverables page and the project card are on different pages of the booklet (project card on page 15), so confirm with the original document whether any extra project-specific requirements exist.

---

## 12. Execution Plan (added suggestion)

> **Two-person team:** Section 13 splits this plan equally between two members and defines the integration point between them. Read Section 12 for the technical content of each phase and Section 13 for who does what.

Durations are estimates for one person or a small team. Compress or stretch them to your real deadline. The order matters more than the durations: build the vulnerable baseline and attacks first, because every later result is measured against them.

### Phase 0 - Environment and scope (1-2 days)
- Use a **Linux machine or VM** (native Linux, or a Linux VM). eBPF needs a recent kernel (5.x or newer is comfortable). On Windows, WSL2 may lack some kernel features, so a full VM is the safer choice. Check with `uname -r`.
- Tools: Python 3.11+, Docker/docker-compose, Redis, scikit-learn, Locust, FastAPI (or Django), **BCC** (Python eBPF toolkit) and optionally `bpftrace` for quick experiments. Root privileges are needed to load eBPF programs.
- Decide: FastAPI vs Django (FastAPI is simpler for ASGI middleware), real LLM vs a **mock LLM endpoint** that returns fake token counts (recommended, so attacks cost nothing).
- Write the scope in one page: assets, attacks, metrics, what "success" means.
- **Output:** a working `docker-compose` or setup script, and a repo skeleton.

### Phase 1 - Vulnerable baseline (2-3 days)
- Endpoints: `/login`, a data endpoint worth scraping (for example `/products` or `/articles`), `/chat` (LLM call with prompt in, tokens out), plus a `/metrics` or logging for usage.
- Deliberately no rate limits, no budgets, no monitoring.
- Token accounting: count input/output tokens per request and log them with a cost estimate.
- **Output:** baseline app running, logging requests, tokens and cost.

### Phase 2 - Red Team attacks and baseline metrics (3-4 days)
- Locust scenarios:
  1. **Credential stuffing:** a wordlist of username/password pairs (with a few valid ones) against `/login`, with rotating IPs or headers if you want realism.
  2. **Layer-7 scraping:** paginated crawling of the data endpoint at human-like and bot-like speeds.
  3. **Denial-of-Wallet:** very long prompts, prompts forcing max-length outputs, many parallel `/chat` calls.
- Also create a **benign traffic** scenario (normal users) for false-positive and latency testing.
- Record baseline: attack success per scenario, tokens/cost burned, latency, error rate.
- **Output:** attack scripts, fixed seeds and datasets, baseline results table. This proves "the attack succeeds against the vulnerable baseline".

### Phase 3 - Blue Layer B, part 1: token buckets and honeypot (3-4 days)
- ASGI middleware with Redis token buckets, using an atomic Lua script. Buckets: requests per IP, login attempts per IP and per account, **LLM tokens per key/user per window**.
- Return 429 with `Retry-After`. Add configuration for capacity and refill rate.
- Honeypot routes (a hidden link, a disallowed `robots.txt` path, a trap form field). A hit means an immediate ban with TTL in Redis.
- Strike system: repeated 429s escalate to a ban.
- **Output:** middleware, config, tests. Re-run Phase 2 attacks and note the improvement.

### Phase 4 - Blue Layer B, part 2: payload anomaly scoring (3-4 days)
- Features per request or per client window: payload size, prompt length, estimated tokens, character entropy, number of parameters, request interval statistics, endpoint sequence, failed-login ratio.
- Train **IsolationForest** on benign traffic from the Locust benign scenario. Tune `contamination` and the score threshold. Save the model.
- Integrate in the middleware: score, then allow, throttle or add strikes.
- Evaluate: detection rate, false-positive rate on benign traffic, scoring latency.
- **Output:** training notebook/script, model, evaluation numbers.

### Phase 5 - Blue Layer A: eBPF (5-7 days, the riskiest part, start experiments early)
Build it in two steps so you always have something working.

**Step 5.1: observability (sensor).**
- Attach to tracepoints/kprobes (for example `sys_enter_connect`, `inet_csk_accept`, `sched_process_exec`, and TCP send/receive probes).
- Collect: new connections per source IP per second, outbound connections and bytes from the app process to the LLM provider, unexpected `execve` from the app process (runtime intrusion signal).
- A user-space Python agent reads the events (perf/ring buffer), aggregates them, and publishes signals to Redis (for example `ebpf:conn_rate:<ip>`, `ebpf:egress_bytes`).
- Feed these signals into the IsolationForest features and strike logic.

**Step 5.2: enforcement (auto-remediation).**
- Write an **XDP** program with a BPF hash map of banned IPs that returns `XDP_DROP` for them.
- The agent watches the Redis ban list and updates the map (add on ban, remove on TTL expiry).
- Demonstrate: after a honeypot hit or repeated budget violations, the attacker's packets are dropped in the kernel and no longer reach the app. Measure **time-to-ban**.
- **Output:** eBPF programs, agent, a demo showing the drop. If time is short, keep 5.1 fully working and present 5.2 as a smaller proof of concept.

### Phase 6 - Integration and evaluation (3-4 days)
- Run the full matrix: {baseline, hardened with Layer B only, hardened with Layer A + B} x {credential stuffing, scraping, DoW, benign}.
- Metrics to report:

| Metric | Definition |
|---|---|
| Attack Success Rate (ASR) | successful malicious requests / total malicious requests, per attack type |
| Detection rate | malicious clients flagged or banned / total malicious clients |
| False-positive rate | benign requests blocked or throttled / total benign requests |
| Time-to-ban | time from first malicious request to the ban taking effect |
| Cost/tokens burned | LLM tokens consumed by the attacker, baseline vs hardened |
| Latency | p50, p95, p99 of benign requests: baseline vs WAF vs WAF + eBPF |
| Overhead | CPU and memory used by the WAF and the eBPF agent |

- Make runs **deterministic and repeatable** (fixed seeds, scripted runs, one command to reproduce), because the deliverable asks for deterministic detection.
- **Output:** results tables and graphs.

### Phase 7 - Slides and demo (3-4 days, start the threat model during Phase 1)
- Slides: threat model, CWE / OWASP API Top 10 / OWASP LLM and Agentic Top 10 mapping, your own architecture and attack/defense sequence diagrams (drawn by you), installation and configuration steps, cited comparison matrix of defense mechanisms, and the results from Phase 6.
- Comparison matrix ideas: fixed window vs sliding window vs token bucket; signature WAF vs behavioral WAF; IsolationForest vs other anomaly detectors; app-layer WAF vs eBPF/XDP enforcement.
- Demo script: show the baseline being abused, then the same attacks failing against the hardened system, with the live numbers. Prepare a recorded backup in case the live demo fails.
- **Output:** final slides, repo, demo script, backup video.

### Suggested repository layout
```
project20/
  app/                 # FastAPI/Django ASGI app + mock LLM
  waf/                 # ASGI middleware: buckets, honeypot, anomaly scoring
  ml/                  # feature extraction, IsolationForest training, model
  ebpf/                # BCC programs (sensor + XDP) and the user-space agent
  locust/              # Locust attack and benign scenarios, datasets
  eval/                # scripts computing ASR, latency, FP rate, graphs
  docs/                # slides, diagrams, threat model
  docker-compose.yml
  README.md
```

### Main risks and how to handle them
| Risk | Mitigation |
|---|---|
| eBPF will not load (kernel, permissions, WSL2) | Test a hello-world BCC program in Phase 0. Use a full Linux VM. |
| eBPF takes longer than planned | Deliver Step 5.1 (sensor) first, 5.2 (XDP) as proof of concept. |
| IsolationForest causes false positives | Train on realistic benign traffic, tune thresholds, combine with budgets so it never decides alone. |
| Results not reproducible | Fixed seeds, scripted runs, one-command reproduction. |
| Real LLM costs money | Use a mock LLM with simulated token counts. |
| Unsure whether eBPF scope is sensor-only or sensor + enforcement | Ask your instructor which is expected, but plan for both as above. |

---

## 13. Two-Person Team Split (added suggestion)

The project is divided into **two equal tracks**, each with its own Red and Blue content, joined by **one main integration point** (the Redis Bridge, Section 13.4). Call the members **Member A** and **Member B** (decide who is who in the first meeting).

### 13.1 The split at a glance

| | **Member A: "Attack & Kernel" track** | **Member B: "Application & Intelligence" track** |
|---|---|---|
| Red Team | Owns all three attacks (credential stuffing, layer-7 scraping, LLM token-exhaustion Denial-of-Wallet), the benign-traffic generator and Locust | Owns the vulnerable target the attacks hit (baseline app, mock LLM, token accounting) |
| Blue Team | **eBPF layer**: kernel sensor + XDP enforcement + user-space agent | **ASGI WAF layer**: Redis token buckets, honeypot, strikes/auto-ban, IsolationForest anomaly scoring |
| Measures | ASR, detection rate, time-to-ban, tokens/cost burned, XDP drops, eBPF overhead | Latency (p50/p95/p99), false-positive rate, WAF CPU/memory, model scoring time |
| Stack | Linux VM, BCC (Python eBPF), XDP, Locust, Redis client | FastAPI/Django ASGI, Redis (Lua), scikit-learn IsolationForest |
| Slide sections | 8 slides | 8 slides |
| Joint | Integration slide, live demo, final evaluation run, rehearsal | Integration slide, live demo, final evaluation run, rehearsal |

**Why this split is fair:** each member builds one attack-side or target-side component and one defense component, writes the same number of slides, produces half of the metrics, and explains one of the two Blue layers. Each person depends on the other, which is what forces the integration.

### 13.2 Work packages and effort (person-days, estimates)

**Member A**

| ID | Work package | Days |
|---|---|---|
| A0 | Linux VM, kernel check (`uname -r`), install BCC/bpftrace, hello-world eBPF program, network namespaces/veth for multiple attacker IPs | 1 |
| A1 | Red Team: Locust scenarios for credential stuffing, layer-7 scraping and token-exhaustion DoW; credential and scraping datasets; **benign-traffic generator**; fixed seeds | 3.5 |
| A2 | Baseline measurement run and **evaluation harness** (ASR, detection rate, time-to-ban, tokens/cost burned, results CSV) | 1.5 |
| A3 | eBPF **sensor**: connection/accept rates per source IP, outbound connections and bytes to the LLM provider, unexpected `execve`; user-space agent publishing to Redis | 3 |
| A4 | eBPF **XDP enforcement**: banned-IP BPF map, `XDP_DROP` program, agent syncing Redis bans into the map, drop counters, optional hard-threshold bans | 3 |
| A5 | Slides (A part, Section 13.6) and demo script (attack side) | 2 |
| | **Subtotal** | **14** |

**Member B**

| ID | Work package | Days |
|---|---|---|
| B0 | Repo, `docker-compose`/setup script, Redis, Python environment, CI-style test command | 1 |
| B1 | **Vulnerable baseline**: FastAPI/Django ASGI app with `/login`, a scrapable data endpoint, `/chat`; mock LLM; token accounting and cost logging; OpenAPI spec published early | 2.5 |
| B2 | **Token-bucket ASGI middleware**: request buckets, login buckets (per IP and per account), LLM-token budgets, atomic Redis Lua script, 429 with `Retry-After` | 2.5 |
| B3 | **Honeypot routes + strike system + auto-ban writer** (writes ban keys with TTL) | 1.5 |
| B4 | **IsolationForest**: feature extraction (including eBPF features), training on benign data, threshold tuning, integration in the middleware, evaluation | 3.5 |
| B5 | Latency, overhead and false-positive measurement (baseline vs WAF vs WAF + eBPF) | 1 |
| B6 | Slides (B part, Section 13.6) and demo script (defense side) | 2 |
| | **Subtotal** | **14** |

**Joint work (both members, together):** contract workshop (0.5 day), integration and integration tests (1.5 days), final three-configuration evaluation run and rehearsal (1 day) = **3 days each**.

**Total per member: about 17 working days (roughly 3.5 to 4 weeks).** If your deadline is shorter, cut scope in this order: (1) XDP enforcement stays but only for one IP at a time, (2) fewer attack variants, (3) simpler features for IsolationForest. Never cut: the baseline, the three attacks, token buckets, honeypot auto-ban, IsolationForest, the eBPF sensor, the integration test and the metrics.

### 13.3 Hand-offs between the two tracks (supporting contracts)

| # | Hand-off | From | To | When | Content |
|---|---|---|---|---|---|
| H1 | **Target API contract** | B | A | Day 2 | OpenAPI spec of `/login`, data endpoint, `/chat`; test accounts; how token usage is reported (response field/header) |
| H2 | **Benign-traffic dataset** | A | B | End of week 1 | Benign Locust scenario + recorded request features, so B can train IsolationForest |
| H3 | **Attack scripts + baseline run** | A | B | Week 2 | Lets B verify the middleware against real attacks and tune budgets |
| H4 | **Ban format and honeypot paths** | B | A | Day 2 | Needed by A to build the XDP map sync (see 13.4) |
| H5 | **Decision log** | B | A | Week 2 | WAF decision stream used by A's evaluation harness |
| H6 | **Results schema** | A + B | A + B | Week 1 | One `results.csv` format so both members' metrics merge without rework |

### 13.4 THE integration point: the Redis Bridge

The two Blue layers (eBPF in the kernel, ASGI WAF in the application) are connected **only through Redis**, using a shared, versioned contract. It is **bidirectional**:

```
   eBPF layer (Member A)                               ASGI WAF layer (Member B)
  +--------------------------+     signals (up)      +-----------------------------+
  | sensor: conn rates,      | --------------------> | anomaly features, strikes,  |
  | egress bytes, exec alerts|   p20:sig:*           | budget tightening           |
  |                          |   p20:stream:ebpf_*   |                             |
  | XDP drop map             | <-------------------- | decisions: honeypot, budget,|
  | (banned IPs)             |     bans (down)       | anomaly -> ban              |
  +--------------------------+   p20:ban:<ip>        +-----------------------------+
                                 p20:ch:ban (pub/sub)
                         Redis = single source of truth
```

**Why this is the integration point:** signals flow **up** (kernel observations improve application decisions) and bans flow **down** (application decisions become kernel-level drops). This closes the loop required by "deterministically detected, blocked, or auto-remediated".

#### Redis contract (schema version 1)

All keys use the prefix `p20:`. Time is always **epoch milliseconds, UTC**.

| Key / channel | Type | Writer | Reader | Content | Expiry |
|---|---|---|---|---|---|
| `p20:meta:schema_version` | String | both | both | `"1"` | none |
| `p20:ban:<ip>` | String (JSON) | B (WAF); A only for hard-threshold bans | A (agent), B | `{"ip","reason","source","ts_ms","ttl_s"}` where reason is `honeypot`, `budget`, `anomaly` or `ebpf_conn_flood`, and source is `waf` or `ebpf` | TTL = ban duration (default 600 s) |
| `p20:ch:ban` | Pub/Sub | B (and A for its own bans) | A, B | `{"op":"add"|"del","ip","ttl_s","reason"}` for instant sync | n/a |
| `p20:sig:ip:<ip>` | Hash | A | B | `conn_rate_1s`, `conn_rate_10s`, `syn_rate_10s`, `failed_conn_10s`, `bytes_in_10s`, `updated_ms` | 60 s |
| `p20:sig:host` | Hash | A | B | `egress_bytes_llm_60s`, `egress_conns_llm_60s`, `unexpected_exec_count`, `updated_ms` | 120 s |
| `p20:stream:ebpf_events` | Stream | A | B, eval | `type` (`conn_burst`, `egress_spike`, `unexpected_exec`), `ip`, `pid`, `comm`, `detail`, `ts_ms` | trimmed (about 10,000 entries) |
| `p20:stream:waf_decisions` | Stream | B | A (eval harness) | `ts_ms`, `ip`, `client_id`, `route`, `decision` (`allow`, `throttle`, `block`, `ban`), `reason`, `anomaly_score`, `llm_tokens_charged`, `latency_ms` | trimmed |
| `p20:xdp:drops` | Hash | A | B, eval | `total_dropped_pkts`, `dropped_pkts:<ip>`, `map_size`, `updated_ms` | none |
| `p20:allowlist` | Set | both | both | IPs that must never be banned (VM host, test runner, Redis host, your own machines) | none |

Keys private to one member (for example the token-bucket state `p20:bucket:*`, honeypot state, model files) are **not** part of the contract and may change freely.

#### Rules both members must follow

1. **Identity = source IPv4 address** as seen by the kernel. The WAF must use the same address (do not trust `X-Forwarded-For` in the test setup). Beware of Docker NAT hiding the real client address: run the app on the VM or with host networking, and generate multiple attacker IPs with Linux network namespaces + veth. Do not rely on loopback for XDP tests, it behaves differently from a real interface.
2. **Redis is the source of truth for bans.** The eBPF agent reconciles the BPF map against Redis every 2 seconds in addition to reacting to pub/sub messages, so a missed message never leaves a stale map.
3. **Single decision-maker for normal bans: the WAF.** The only exception is the eBPF agent's hard-threshold ban (`ebpf_conn_flood`), meant to protect the host when the app is overloaded. It uses the same key format.
4. **Never ban the allowlist.** Both sides check `p20:allowlist` before banning or dropping (otherwise you will lock yourselves out of your own VM).
5. **Failure behavior (agree at the contract workshop):** if the eBPF agent stops, the WAF keeps working with app-layer protection only. If Redis is unavailable, the WAF falls back to local in-memory buckets (recommended) and the agent keeps its current map until entries expire.
6. **Contract changes** require both members to agree and the `schema_version` to be bumped.
7. **Develop in parallel using mocks:** A writes `fake_waf.py` (publishes bans, reads signals) and B writes `fake_ebpf.py` (publishes signals, reads bans). Each member can then test their layer alone before the real integration.

#### Integration tests (acceptance criteria for the bridge)

| ID | Test | Pass condition |
|---|---|---|
| IT-1 | **WAF to eBPF:** attacker IP hits a honeypot route | Ban key created; IP appears in the XDP BPF map in **1 second or less**; attacker's next packets are dropped (drop counter rises, requests time out); after the TTL the entry is removed and traffic flows again |
| IT-2 | **eBPF to WAF:** connection burst from an attacker IP | `p20:sig:ip:<ip>` updated within 2 seconds; the IsolationForest score or strike count for that IP rises; the WAF then throttles or bans |
| IT-3 | **Cost cross-check (DoW):** attacker drives LLM usage | The eBPF egress volume to the LLM endpoint and the WAF's token accounting agree within an agreed tolerance (for example 10 percent); a mismatch raises an alert |
| IT-4 | **Closed loop:** full attack run | Time-to-ban measured from the first malicious request to the first XDP drop, recorded in the results |
| IT-5 | **Failure modes:** stop the agent, then stop Redis | App-layer protection continues; behavior matches the failure rules above |
| IT-6 | **No false bans:** benign traffic run | Zero bans (or the agreed false-positive rate) for benign clients |

### 13.5 Timeline (about 4 weeks, adjust to your deadline)

| Week | Member A | Member B | Joint |
|---|---|---|---|
| **1** | A0 environment; start A1 (credential stuffing, scraping scripts); write `fake_waf.py` | B0 setup; B1 baseline app + mock LLM; publish OpenAPI (H1); start B2 | **Day 1: contract workshop** (Redis schema, results schema, failure rules, allowlist). **Checkpoint IC0:** contract frozen, mocks exist |
| **2** | Finish A1 (DoW + benign generator, H2); A2 baseline run; start A3 sensor | Finish B2; B3 honeypot + strikes; start B4 (needs H2) | **Checkpoint IC1:** baseline results recorded, attacks succeed against the baseline |
| **3** | Finish A3; A4 XDP + sync; (bridge: publish signals, sync bans) | Finish B4; B5 measurements; read eBPF signals as features | **Checkpoint IC2:** IT-1 and IT-2 pass with real components |
| **4** | A5 slides; final evaluation | B6 slides; final evaluation | Integration tests IT-3 to IT-6; **full three-configuration run** (baseline, WAF only, WAF + eBPF); **Checkpoint IC3:** demo rehearsal (twice), recorded backup demo |

**Key dependencies (do not let these slip):** H1 (API spec) blocks A1; H2 (benign dataset) blocks B4; H4 (ban format) blocks A4.

### 13.6 Slide split (18 slides, 8 each + 2 joint)

| # | Slide | Owner |
|---|---|---|
| 1 | Title, context, problem (Denial-of-Wallet, API abuse) | B |
| 2 | Formal threat model (assets, actors, entry points, impact) | A |
| 3 | Attack catalogue: credential stuffing, layer-7 scraping, LLM token exhaustion | A |
| 4 | Mapping: CWE + OWASP API Security Top 10 | A |
| 5 | Mapping: OWASP Top 10 for LLM Applications + OWASP Agentic Top 10 | B |
| 6 | Architecture of the hardened system (app, WAF, Redis, LLM) | B |
| 7 | eBPF layer architecture (sensor, XDP, agent) | A |
| 8 | **Integration: the Redis Bridge** (signals up, bans down, contract, tests) | **Joint** |
| 9 | Attack sequence diagrams (3 attacks, drawn by you) | A |
| 10 | Defense sequence diagrams (3 defenses, drawn by you) | B |
| 11 | Installation and configuration: app, Redis, WAF, scikit-learn | B |
| 12 | Installation and configuration: Linux/VM, BCC, XDP, Locust, namespaces | A |
| 13 | Cited comparison matrix 1: where to enforce (eBPF/XDP vs iptables/nftables vs reverse-proxy WAF vs in-app middleware) | A |
| 14 | Cited comparison matrix 2: rate limiting (fixed window, sliding window, token bucket) and detection (signature WAF vs behavioral WAF, IsolationForest vs other detectors) | B |
| 15 | Results: ASR, detection rate, time-to-ban, tokens/cost burned | A |
| 16 | Results: latency (p50/p95/p99), overhead, false positives | B |
| 17 | **Live demo** (baseline abused, then the same attacks failing) | **Joint** |
| 18 | Conclusion, limits, future work, references | B |

References listed on slides: **OWASP API Security Project** (cited by A for the mapping) and **Scikit-Learn IsolationForest** (cited by B for the model), plus the sources behind the comparison matrices.

### 13.7 Coverage matrix: every element of the project and who owns it

Nothing from the original project description is left unassigned.

| Element from the project description | Owner | Where |
|---|---|---|
| Title: **eBPF** | A | A3, A4 |
| Title: **Behavioral Runtime Intrusion Detection** | A (kernel signals) + B (anomaly scoring) | A3 + B4, linked by the bridge |
| Title: **Automated Token-Bucket ASGI WAF** | B | B2, B3 |
| Title: **LLM "Denial-of-Wallet"** | A (attack) + B (budget defense) + both (cost cross-check IT-3) | A1, B2, IT-3 |
| Security Pillar IV: **API Security** | A (OWASP API mapping) + B (API app and controls) | Slides 4, 6 |
| Stack: **FastAPI/Django ASGI** | B | B1, B2 |
| Stack: **Redis Token Bucket** | B | B2 |
| Stack: **IsolationForest** | B | B4 |
| Stack: **Locust** | A | A1, A2 |
| "Agent Harness" (the LLM/agent being protected and abused) | B (mock LLM/agent) + A (attacks on it) | B1, A1 |
| Red: **credential stuffing** | A | A1 |
| Red: **layer-7 scraping** | A | A1 |
| Red: **LLM token-exhaustion Denial-of-Wallet** | A | A1 |
| Blue: **ASGI behavioral WAF** | B | B2, B3, B4 |
| Blue: **Redis token-bucket budgets** | B | B2 |
| Blue: **payload anomaly scoring** | B | B4 |
| Blue: **honeypot auto-ban** | B (detection + ban decision) + A (kernel-level drop of banned IPs) | B3 + A4, IT-1 |
| Deliverable: formal threat model | A | Slide 2 |
| Deliverable: CWE mapping | A | Slide 4 |
| Deliverable: OWASP (API) Top 10 mapping | A | Slide 4 |
| Deliverable: OWASP LLM & Agentic Top 10 mapping | B | Slide 5 |
| Deliverable: custom architecture | A (eBPF) + B (hardened system) + joint (bridge) | Slides 6, 7, 8 |
| Deliverable: attack sequence diagrams (drawn by the team) | A | Slide 9 |
| Deliverable: defense sequence diagrams (drawn by the team) | B | Slide 10 |
| Deliverable: installation and tool configuration steps | A (eBPF, Linux, Locust) + B (app, Redis, WAF, ML) | Slides 11, 12 |
| Deliverable: cited comparison matrix of defense mechanisms | A (enforcement placement) + B (rate limiting and detection) | Slides 13, 14 |
| Deliverable: vulnerable baseline | B | B1 |
| Deliverable: attack succeeding against the baseline | A | A2 |
| Deliverable: deterministic detection / blocking / auto-remediation | B (app layer) + A (kernel layer) + joint (IT-1, IT-4) | B2-B4, A4 |
| Deliverable: quantitative **Attack Success Rate (ASR)** | A | A2, slide 15 |
| Deliverable: quantitative **latency metrics** | B | B5, slide 16 |
| Reference: OWASP API Security Project | A | Slide 4 |
| Reference: Scikit-Learn IsolationForest | B | B4, slide 14 |
| Determinism and repeatability | A (attack seeds, scripted runs) + B (model seed, fixed thresholds) | A2, B4 |
| Live demo | Joint | Slide 17 |

### 13.8 Working agreements (keeps the split equal and the project coherent)

- **Cross-review:** every pull request from A is reviewed by B and vice versa. Each member must understand the other's layer.
- **Cross-knowledge rule:** both members must be able to explain the **whole** project in the oral presentation, including the other member's layer at a high level. Hold a 30-minute walkthrough in week 3 where each member explains their layer to the other.
- **Presentation:** split speaking time equally. Suggested: B opens (slides 1, 5, 6), A continues (2, 3, 4, 7), joint slide 8, then alternate 9 to 16, joint demo, B concludes.
- **Sync:** 15-minute daily check-in; one integration session at each checkpoint (IC0 to IC3).
- **One repo, clear ownership:** `app/`, `waf/`, `ml/` belong to B; `ebpf/`, `locust/`, `eval/` belong to A; `contract/` (Redis schema, mocks, integration tests) and `docs/` are shared.
- **Blocked or late:** if one member is blocked for more than a day, the other pairs with them. If A3/A4 (eBPF) slip, B helps with the Linux environment and test harness. If B4 (IsolationForest) slips, A helps with feature extraction and data.
- **Definition of done for each work package:** code committed, tests or a demo script, a short README, and the metrics it contributes already written to `results.csv`.

### 13.9 Updated repository layout with ownership

```
project20/
  app/        # B: FastAPI/Django ASGI app, mock LLM, token accounting
  waf/        # B: ASGI middleware: token buckets (Lua), honeypot, strikes, ban writer
  ml/         # B: feature extraction, IsolationForest training, saved model
  ebpf/       # A: BCC sensor, XDP program, user-space agent (Redis sync)
  locust/     # A: credential stuffing, scraping, DoW, benign scenarios, datasets
  eval/       # A: evaluation harness, ASR/detection/time-to-ban; B adds latency/FP scripts
  contract/   # SHARED: Redis schema doc, fake_waf.py, fake_ebpf.py, integration tests IT-1..IT-6
  docs/       # SHARED: slides, diagrams, threat model, results
  docker-compose.yml  # B (Redis + app); the eBPF agent runs on the host/VM (A)
  README.md   # SHARED
```
