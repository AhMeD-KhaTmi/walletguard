"""Independent admission/accounting and before/after acceptance for wallet remedies."""
import argparse
from collections import defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
from statistics import median
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))
from scripts.run_remedy_experiment import jobs
from scripts.robustness_cases import MODEL_SHA256
from scripts.run_c23_benchmark import run_summary
from eval.compute_metrics import read_attempts,percentile
from eval.labels import label_for
from scripts.robustness_cases import worker_plan


def report(root,policy_path,out,smoke=False,mixed=False):
    index=json.loads((root/'index.json').read_text());expected=jobs('smoke' if smoke else 'validation')
    if mixed:
        expected=[dict(profile='wallet_mixed',config=c,variant='legacy' if c=='C0' else 'remedy',
                       seed=1400+r,rep=r,seconds=45,users=15,workload='mixed')
                  for r in [1,2,3] for c in ['C0','C2','C3']]
    key=lambda e:(e['profile'],e['config'],e['variant'],e['seed'],e['rep'])
    if len(index)!=len(expected) or {key(e) for e in index}!={key(e) for e in expected}:raise ValueError('incomplete fresh matrix')
    policy=json.loads(policy_path.read_text())['candidate'];policy_hash=hashlib.sha256(policy_path.read_bytes()).hexdigest()
    rows=[];manifests={};groups=defaultdict(list);revisions=set();details={}
    for e in index:
        run=root/'runs'/e['run_id'];m=json.loads((run/'manifest.json').read_text());candidate=e['variant']=='remedy'
        if (m['invalid'] or m['code_revision']['dirty'] or m['seed']!=e['seed']
            or m['workload']!=e['workload'] or m['users']!=e['users'] or m['repetition']!=e['rep']
            or m['effective_policy']['budgets']['llm_tok']!=[40000,2400.0]
            or m['effective_policy']['strike_limit']!=5 or m['effective_policy']['ban_ttl_s']!=600
            or m['duration_requested']!=f"{e['seconds']}s" or m['remedy']['variant']!=e['variant']
            or m['remedy']['profile']!=e['profile'] or m['remedy']['smoke_only']!=smoke
            or m['worker_lifecycle']!='supervised_deadline_v1'
            or m['effective_policy']['account_pressure_bans']==candidate
            or m['effective_policy']['wallet_capacity']!=(policy['capacity'] if candidate else 0)
            or m['effective_policy']['wallet_refill_per_s']!=(policy['refill_per_s'] if candidate else 0)
            or m['remedy']['policy_sha256']!=policy_hash):raise ValueError('protocol mismatch '+run.name)
        revisions.add(m['code_revision']['commit']);manifests[key(e)]=m
        if mixed:
            expected_workers={i['ip']:worker_plan('distributed',i['role'],i['ns'],0,i.get('accounts',())) for i in m['identities']}
            if m.get('mixed_contention_workers')!=expected_workers:raise ValueError('mixed worker plan mismatch')
            if len(expected_workers)!=15 or len([i for i in m['identities'] if i['role']=='benign'])!=5:raise ValueError('mixed actors missing')
        row=run_summary(run,MODEL_SHA256);row.update(profile=e['profile'],variant=e['variant'])
        labels={i['ip']:label_for(m['workload'],i) for i in m['identities']}
        attempts=read_attempts(run);measured=[a for a in attempts if a['phase']=='measured']
        benign=[a for a in measured if labels[a['ip']]=='benign'];bans=json.loads((run/'bans.json').read_text())
        setup=[a for a in attempts if a['phase']=='setup' and labels[a['ip']]=='benign']
        row.update(benign_attempts=len(benign),benign_denials=sum(a['outcome']=='blocked' for a in benign),
            benign_bans=sum(labels.get(b['ip'])=='benign' for b in bans),
            benign_setup_unsuccessful=sum(a['outcome']!='success' for a in setup),
            benign_other_unsuccessful=sum(a['outcome'] not in ['success','blocked'] for a in benign),
            benign_browse_blocked=sum(a['route']=='/products' and a['outcome']=='blocked' for a in benign),
            benign_chat_blocked=sum(a['route']=='/chat' and a['outcome']=='blocked' for a in benign),
            all_unknown=sum(a['outcome'] in ['unknown','error','timeout'] for a in measured),ban_records=len(bans))
        row['benign_fpr']=row['benign_denials']/len(benign) if benign else None
        attacks={}
        for attack in ['credential_stuffing','scraping','dow']:
            items=[a for a in measured if a.get('objective') and a.get('attack')==attack]
            if not items:continue
            counts={v:sum(a['outcome']==v for a in items) for v in ['success','fail','blocked','error','timeout','unknown']}
            counts.update(attempts=len(items),asr=counts['success']/len(items),
                known_valid_attempts=sum(a.get('credential_kind')=='valid_demo' for a in items),
                known_valid_success=sum(a.get('credential_kind')=='valid_demo' and a['outcome']=='success' for a in items),
                unique_products=len({p for a in items if a['outcome']=='success' for p in a.get('product_ids',[])}))
            attacks[attack]=counts
        raw_names={'manifest.json','usage.json','bans.json','wallet_audit.jsonl','wallet_bucket.json','app-evidence.json','decisions.jsonl'}
        raw_names.update(p.name for pattern in ['attempts-*.jsonl','worker-*.json'] for p in run.glob(pattern))
        details[e['run_id']]=dict(attacks=attacks,files={name:hashlib.sha256((run/name).read_bytes()).hexdigest()
            for name in sorted(raw_names) if (run/name).is_file()})
        for p in [50,95]:row[f'latency_p{p}_ms']=percentile([a['latency_ms'] for a in benign if a['outcome']=='success'],p/100)
        usage=json.loads((run/'usage.json').read_text());api,mock=usage['after'],usage['mock_after']
        if (any(int(api.get(a,0))!=int(mock[b]) for a,b in [('tokens_in','tokens_in'),('tokens_out','tokens_out'),('agent_steps','calls')])
            or not math.isclose(float(api.get('cost_usd',0)),float(mock['cost_usd']),abs_tol=1e-7)):
            raise ValueError('API/mock totals differ')
        row.update(server_tokens=int(mock['tokens_in'])+int(mock['tokens_out']),server_tokens_out=int(mock['tokens_out']),server_cost_usd=float(mock['cost_usd']))
        audit=[json.loads(line) for line in (run/'wallet_audit.jsonl').read_text().splitlines() if line]
        decisions=[] if e['config']=='C0' else [json.loads(line) for line in (run/'decisions.jsonl').read_text().splitlines() if line]
        row['wallet_denials']=sum(d['reason']=='wallet_tok' and d['decision']=='throttle' for d in decisions)
        row['account_chat_denials']=sum(d['reason']=='chat_req' and d['decision']=='throttle' for d in decisions)
        if candidate:
            retained=sum(float(a['reserved'])-float(a['refunded']) for a in audit)
            charged=sum(float(a['charged']) for a in audit)
            chats=[a for a in measured if a['route']=='/chat']
            elapsed=max(0,(max(int(a['ts_ms']) for a in audit)-min(a['started_ms'] for a in chats))/1000) if chats and audit else 0
            bound=policy['capacity']+policy['refill_per_s']*elapsed
            if any(a['run_id']!=e['run_id'] or float(a['refunded'])>float(a['reserved']) or float(a['refunded'])<0 for a in audit):raise ValueError('invalid private reservation audit')
            if retained>bound+1e-5 or charged!=row['server_tokens']:raise ValueError('wallet conservation/accounting failed')
            row.update(wallet_retained=retained,wallet_charged=charged,wallet_bound=bound,wallet_elapsed_s=elapsed)
        else:
            if audit:raise ValueError('disabled wallet unexpectedly produced enforcement audit')
        rows.append(row);groups[(e['profile'],e['config'],e['variant'])].append(row)
    if len(revisions)!=1:raise ValueError('source drift')
    for profile in sorted({e['profile'] for e in index}):
        for rep in ([1] if smoke else [1,2,3]):
            entries=[e for e in index if e['profile']==profile and e['rep']==rep]
            base=manifests[key(entries[0])]
            for e in entries:
                m=manifests[key(e)]
                for field in ['identities','seed','duration_requested','users','workload_sha256','worker_driver_sha256','mock','scoring_policy','code_revision']:
                    if base[field]!=m[field]:raise ValueError('unmatched '+field)
                if mixed:
                    for field in ['mixed_contention_workers','mixed_contention_source_sha256']:
                        if base[field]!=m[field]:raise ValueError('unmatched '+field)
                # Existing per-account/request policy remains identical across both variants.
                for field in ['budgets','strike_limit','strike_window_s','ban_ttl_s','max_output_cap']:
                    if base['effective_policy'][field]!=m['effective_policy'][field]:raise ValueError('unmatched legacy policy')
    rowmap={(r['profile'],r['config'],r['variant'],r['repetition']):r for r in rows}
    for r in rows:
        base=rowmap.get((r['profile'],'C0','legacy',r['repetition']))
        for p in [50,95]:
            value=r.get(f'latency_p{p}_ms');prior=base.get(f'latency_p{p}_ms') if base else None
            r[f'delta_c0_p{p}_ms']=float(value)-float(prior) if value not in (None,'') and prior not in (None,'') else None
    shared=[r for r in rows if r['profile']=='shared_account' and r['variant']=='remedy']
    fast=[r for r in rows if r['profile']=='fast_scraping' and r['variant']=='remedy']
    attribution_pass=all(r['benign_bans']==0 and r['benign_browse_blocked']==0 and r['account_chat_denials']>0
                          and r['benign_other_unsuccessful']==0 and r['benign_setup_unsuccessful']==0 for r in shared) and all(r['ban_records']>0 and r['all_unknown']==0 for r in fast)
    safe=[r for r in rows if r['profile'] in (['wallet_mixed'] if mixed else ['normal','varied','burst_within']) and r['variant']=='remedy']
    benign_pass=all(r['benign_attempts']>0 and r['benign_fpr']<=.01 and r['benign_bans']==0
                  and r['benign_other_unsuccessful']==0 and r['benign_setup_unsuccessful']==0 for r in safe)
    distributed=[r for r in rows if r['profile']=='distributed' and r['variant']=='remedy']
    for r in distributed:
        base=rowmap[(r['profile'],r['config'],'legacy',r['repetition'])]
        r['token_reduction']=1-r['server_tokens']/base['server_tokens']
    wallet_pass=benign_pass and all(r['wallet_denials']>0 and r['token_reduction']>=.10 and r['all_unknown']==0 for r in distributed)
    summary={}
    for (profile,cfg,variant),items in sorted(groups.items()):
        result={k:sum(r[k] for r in items) for k in ['benign_attempts','benign_denials','benign_bans','benign_browse_blocked','benign_chat_blocked','benign_setup_unsuccessful','benign_other_unsuccessful','all_unknown','wallet_denials','ban_records']}
        result['metrics']={}
        result['attacks']={}
        for attack in ['credential_stuffing','scraping','dow']:
            samples=[details[r['run_id']]['attacks'][attack] for r in items if attack in details[r['run_id']]['attacks']]
            if samples:
                counts={k:sum(s[k] for s in samples) for k in ['attempts','success','fail','blocked','error','timeout','unknown','known_valid_attempts','known_valid_success']}
                counts['asr']=counts['success']/counts['attempts'];result['attacks'][attack]=counts
        for metric in ['server_tokens','server_tokens_out','server_cost_usd','latency_p50_ms','latency_p95_ms','delta_c0_p50_ms','delta_c0_p95_ms',
                       'waf_overhead_p50_ms','waf_overhead_p95_ms','scoring_p95_ms','token_reduction','asr']:
            vals=[float(r[metric]) for r in items if r.get(metric) not in (None,'')]
            if vals:result['metrics'][metric]=dict(median=median(vals),min=min(vals),max=max(vals))
        summary[f'{profile}/{cfg}/{variant}']=result
    out.mkdir(parents=True,exist_ok=True)
    with (out/'results.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(dict.fromkeys(k for r in rows for k in r)));w.writeheader();w.writerows(rows)
    result=dict(runs=len(rows),smoke_only=smoke,mixed_contention=mixed,
                attribution_gate_passed=attribution_pass if not mixed else None,
                benign_wallet_gate_passed=benign_pass,wallet_gate_passed=wallet_pass,
                source_revision=next(iter(revisions)),policy=policy,summary=summary,details=details,model_sha256=MODEL_SHA256,
                validator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),kernel_integrated=False,deployed=False)
    (out/'validation.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--runs',type=Path,required=True);p.add_argument('--policy',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--smoke',action='store_true');p.add_argument('--mixed',action='store_true');a=p.parse_args()
    print(json.dumps(report(a.runs,a.policy,a.out,a.smoke,a.mixed),indent=2))
