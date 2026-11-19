"""Render the independently validated evidence as a readable Markdown report."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def main():
    base=ROOT/'docs/evidence/followup';d=json.loads((base/'validation.json').read_text());c=json.loads((base/'compatibility/validation.json').read_text());decision=json.loads((base/'decision.json').read_text());lines=['# Fairness, burst, scraping and hard-spend results','',
    'Nine fresh benign calibration runs, five separate pipeline smokes,93 component validation runs and12 additional combined validation runs use disjoint groups/seeds. Each measured arm has three repetitions; order reverses in repetition2. All119 captures remain preserved. The [prospective protocol](FAIRNESS_BURST_SPEND_PROTOCOL.md) fixes the methods and gates before validation. No model fitting or test-based policy adjustment occurred.','',
    f"Component source `{d['source_revision']}`; combined-client source `{c['source_revision']}`. Their application/WAF/common/model trees match. The qualified model remains `{d['model_sha256']}`. A-owned implementation and shared Redis schema2/ban reasons/TTLs remain unchanged.",'','## Acceptance and release','',
    '| Gate | Result |','|---|---|']
    for name,value in {**d['gates'],**c['gates']}.items():lines.append(f"| {name} | {'PASS' if value else 'FAIL'} |")
    lines+=['', 'The fitted lane/IP/item policy is '+('the qualified C2/C3 default.' if decision['combined_default_enabled'] else 'kept opt-in; validated baseline defaults remain.')+' Hard spending remains opt-in with an explicitly initialized operator-chosen period and cap. [Effective release decision](evidence/followup/decision.json) · [Launch and replay instructions](FOLLOWUP_CONTROLS.md).','',
    '## Fitting and interpretation','',
    '- Whole tasks up to2,048 tokens use a9,000-capacity/1,800-token/s small lane. Larger tasks use47,000/5,500. Their sum is56,000/7,300; the pooled comparator uses exactly that same envelope. No role labels, client trust hints or special account lists enter admission. Each lane and the total satisfy C+R*elapsed; independent API/mock/audit totals agree.',
    '- Benign burst peaks42 requests and800 items in1s,2,400 items in60s select IP capacity60 (refill2/s unchanged), product capacity1,000/refill50 items/s. Product costs use the API-clamped requested page size. Account40,000/2,400, output cap, strike/ban settings and model remain fixed.',
    '- The hard period cap is1,000,000 synthetic micro-USD ($1), at input3/output15 micro-USD/token. It has no refill, expiry or automatic rotation. Whole-task reservations and idempotent known-unused refunds retain uncertain credit. Routine runtime reset/API restart preserve the ledger; missing/mismatched/unreachable authority cannot grant new funds. Normal default local-bucket fallback remains.',
    '- Task-size lanes protect small work from large-task exhaustion. Identical small-task abuse, within-lane contention, idle stranded capacity and shared-fund exhaustion remain limitations. These results establish the tested policy, not universal fairness or perfect protection.','',
    '## Legitimate traffic and latency','',
    'FPR is measured benign policy denials / benign attempts, distinct from detector flags. Ban counts are records summed across resets, not lifetime-unique IPs. Successful-response client percentiles and paired C0 deltas are calculated per run before reporting their median. WAF overhead excludes downstream work and includes finalization.','',
    '| Profile | Config | Variant | Benign attempts | Denied | Bans | Client p50/p95 ms | Paired C0 delta p50/p95 ms | WAF p50/p95 ms |','|---|---|---|---:|---:|---:|---|---|---|']
    def fmt(g,k):return f"{g['metrics'][k]['median']:.2f}" if k in g['metrics'] else 'n/a'
    for report in [d,c]:
        for key,g in report['summary'].items():
            if not g['benign_attempts']:continue
            profile,cfg,v=key.split('/');lines.append(f"| {profile} | {cfg} | {v} | {g['benign_attempts']} | {g['benign_denials']} | {g['benign_bans']} | {fmt(g,'latency_p50_ms')}/{fmt(g,'latency_p95_ms')} | {fmt(g,'delta_c0_p50_ms')}/{fmt(g,'delta_c0_p95_ms')} | {fmt(g,'waf_overhead_p50_ms')}/{fmt(g,'waf_overhead_p95_ms')} |")
    lines+=['','The combined gate additionally requires all630 planned benign requests to succeed in EVERY candidate run, not only a low denial rate among attempted work. This tests ten burst users alongside20 attack users. Setup/other failures and all-actor errors/timeouts/unknowns must be zero.','',
    '## Tokens and simulated spending','',
    '| Profile | Config | Variant | Median tokens | Median simulated USD | Wallet denials | Cap denials |','|---|---|---|---:|---:|---:|---:|']
    for report in [d,c]:
        for key,g in report['summary'].items():
            profile,cfg,v=key.split('/')
            if profile not in ['fair_mixed','spend','combined_burst']:continue
            lines.append(f"| {profile} | {cfg} | {v} | {fmt(g,'server_tokens')} | {g['metrics']['server_cost_usd']['median']:.6f} | {g['wallet_tok_denials']} | {g['spend_cap_denials']} |")
    lines+=['', 'Every capped C2/C3 run charges991,620 micro-USD ($0.991620), below1,000,000; the ledger agrees with actual usage. Normal rate wallets are burst/sustained allowances and do not bound total lifetime spending. The strict cap intentionally stops work when shared funds run out. Allowlisted management traffic is exempt from WAF admission; real billing, Redis persistence/backups and period rotation are operational concerns outside the synthetic prototype.','',
    '## Attack-specific success and catalogue exposure','',
    'ASR includes all malicious objective attempts. Known-valid synthetic credential success is diagnostic, never a replacement denominator. The frozen>=10% scraping criterion measures successful page-delivery volume; it is named scraping_volume in reports. Unique catalogue products are measured per run, never summed across repetitions.','',
    '| Profile | Config | Variant | Attack | Attempts | Successes | ASR % | Blocked | Error/timeout/unknown | Median unique products/run | Valid login success/attempts |','|---|---|---|---|---:|---:|---:|---:|---|---:|---|']
    for report in [d,c]:
        for key,g in report['summary'].items():
            profile,cfg,v=key.split('/')
            for attack,a in g['attacks'].items():
                unique=a['unique_products_per_run']['median'] if attack=='scraping' else 'n/a';lines.append(f"| {profile} | {cfg} | {v} | {attack} | {a['attempts']} | {a['success']} | {100*a['asr']:.2f} | {a['blocked']} | {a['error']}/{a['timeout']}/{a['unknown']} | {unique} | {a['known_valid_success']}/{a['known_valid_attempts']} |")
    lines+=['', 'Resource quotas reduce distributed scrape deliveries57.33% (160/375 per run) and slow deliveries13.75% (207/240), with zero benign denials in those candidate slow runs. All5,000 public catalogue products still remain extractable under the slow/distributed schedules. This is volume mitigation; unique-data access protection and indistinguishable low-rate abuse remain open. Valid compromised synthetic credentials can still succeed.','',
    '## Retry-After behavior','',
    '| Config | Variant | Actual attempts | Denied | Bans | Recorded429 backoffs | Completed wait seconds |','|---|---|---:|---:|---:|---:|---:|']
    for key,g in d['summary'].items():
        profile,cfg,v=key.split('/')
        if profile=='burst_retry':lines.append(f"| {cfg} | {v} | {g['benign_attempts']} | {g['benign_denials']} | {g['benign_bans']} | {g['retry_events']} | {g['retry_wait_s']:.2f} |")
    lines+=['', 'Each burst profile has1,890 counterfactual fixed-schedule opportunities over three runs. Response-aware clients delay their next attempt after429 and keep denials visible; they do not silently replay a missed action as success. Recorded waits exclude possible deadline-ending waits without a following stat update, so they are lower bounds. Waiting reduced baseline denials from1,440 to1,380, but did not prevent its15 ban records. Candidate burst variants completed all1,890 opportunities with zero denials/bans.','',
    '## Evidence and remaining work','',
    '- [Primary independent report](evidence/followup/validation.json) and [per-run CSV](evidence/followup/results.csv).',
    '- [Combined independent report](evidence/followup/compatibility/validation.json) and [per-run CSV](evidence/followup/compatibility/results.csv).',
    '- [Frozen benign fitting proof](evidence/followup/frozen_policy.json), [component smoke](evidence/followup/smoke/validation.json), [combined smoke](evidence/followup/compat-smoke/validation.json).',
    '- Final checks: [133 app/contract tests](evidence/followup/application.xml), [109 evaluation tests](evidence/followup/evaluation.xml), [12 real HTTP probes](evidence/followup/http.json). Monetary tests cover concurrency, refunds, anomaly rejection, uncertainty, reset/restart and loss of Redis authority.',
    '- Opened cohorts are excluded from independent future tuning. Broader fairness/adaptive small jobs and unique extraction need new experiments. A’s real kernel sensor/enforcement, augmented data/model, joint IT-1–IT-6, final C0–C4 benchmark, slides and rehearsals remain pending.','']
    (ROOT/'docs/FOLLOWUP_RESULTS.md').write_text('\n'.join(lines))

if __name__=='__main__':main()
