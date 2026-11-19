"""Independent component acceptance; preserve every unfavorable fresh result."""
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
from scripts.run_followup_study import jobs
from scripts.run_c23_benchmark import run_summary
from scripts.robustness_cases import MODEL_SHA256
from eval.compute_metrics import read_attempts,percentile
from eval.labels import label_for


def report(root,policy_path,out,smoke=False,compatibility=False):
    from scripts.run_followup_compatibility import jobs as compat_jobs
    index=json.loads((root/'index.json').read_text());expected=(compat_jobs if compatibility else jobs)(smoke);key=lambda e:(e['profile'],e['config'],e['variant'],e['rep'],e['seed'])
    if len(index)!=len(expected) or {key(e) for e in index}!={key(e) for e in expected}:raise ValueError('incomplete prospective matrix')
    policy=json.loads(policy_path.read_text());digest=hashlib.sha256(policy_path.read_bytes()).hexdigest();rows=[];details={};manifests={};revisions=set()
    for e in index:
        run=root/'runs'/e['run_id'];m=json.loads((run/'manifest.json').read_text());f=m['followup'];p=m['effective_policy'];v=e['variant']
        if (m['invalid'] or m['code_revision']['dirty'] or m['config']!=e['config'] or m['seed']!=e['seed'] or m['repetition']!=e['rep'] or m['users']!=e['users'] or m['duration_requested']!=f"{e['seconds']}s" or m['workload']!=e['workload'] or f['profile']!=e['profile'] or f['variant']!=v or f['smoke_only']!=smoke or f['policy_sha256']!=digest or m['worker_lifecycle']!='supervised_deadline_v1' or p['account_pressure_bans'] or p['budgets']['llm_tok']!=[40000,2400.]):raise ValueError('protocol/source mismatch '+run.name)
        want_wallet=v in ['lanes','pooled','combined'];want_resource=v in ['resource','combined'];want_spend=v=='cap';want_lanes=v in ['lanes','combined']
        if (p['wallet_capacity']!=(policy['wallet_capacity'] if want_wallet else 0) or p['wallet_refill_per_s']!=(policy['wallet_refill_per_s'] if want_wallet else 0) or p['wallet_small_capacity']!=(policy['lanes']['small']['capacity'] if want_lanes else 0) or p['wallet_small_refill_per_s']!=(policy['lanes']['small']['refill_per_s'] if want_lanes else 0) or p['wallet_small_task_max']!=(2048 if want_lanes else 0) or p['products_capacity']!=(policy['products_capacity'] if want_resource else 0) or p['products_refill_per_s']!=(policy['products_refill_per_s'] if want_resource else 0) or p['budgets']['ip_req']!=[policy['ip_capacity'] if want_resource else 30,2.] or p['spend_cap_microusd']!=(1000000 if want_spend else 0) or p['spend_period']!=(e['run_id'] if want_spend else '')):raise ValueError('incorrect effective candidate policy')
        revisions.add(m['code_revision']['commit']);manifests[key(e)]=m;row=run_summary(run,MODEL_SHA256);row.update(profile=e['profile'],variant=v,family=e['family'])
        labels={i['ip']:label_for(m['workload'],i) for i in m['identities']};attempts=read_attempts(run);measured=[a for a in attempts if a['phase']=='measured'];benign=[a for a in measured if labels[a['ip']]=='benign'];bans=json.loads((run/'bans.json').read_text())
        row.update(benign_attempts=len(benign),benign_denials=sum(a['outcome']=='blocked' for a in benign),benign_bans=sum(labels.get(b['ip'])=='benign' for b in bans),benign_other_unsuccessful=sum(a['outcome'] not in ['success','blocked'] for a in benign),benign_setup_unsuccessful=sum(a['phase']=='setup' and labels[a['ip']]=='benign' and a['outcome']!='success' for a in attempts),all_unknown=sum(a['outcome'] in ['error','timeout','unknown'] for a in measured),ban_records=len(bans))
        row['benign_fpr']=row['benign_denials']/len(benign) if benign else None
        for q in [50,95]:row[f'latency_p{q}_ms']=percentile([a['latency_ms'] for a in benign if a['outcome']=='success'],q/100)
        u=json.loads((run/'usage.json').read_text());api,mock=u['after'],u['mock_after']
        if any(int(api.get(k,0))!=int(mock[k]) for k in ['tokens_in','tokens_out']) or int(api.get('agent_steps',0))!=int(mock['calls']) or not math.isclose(float(api.get('cost_usd',0)),float(mock['cost_usd']),abs_tol=1e-7):raise ValueError('API/mock usage mismatch')
        micro=int(mock['tokens_in'])*3+int(mock['tokens_out'])*15
        row.update(server_tokens=int(mock['tokens_in'])+int(mock['tokens_out']),cost_microusd=micro,server_cost_usd=float(mock['cost_usd']))
        decisions=[] if e['config']=='C0' else [json.loads(x) for x in (run/'decisions.jsonl').read_text().splitlines()]
        for reason in ['wallet_tok','products_items','spend_cap']:row[reason+'_denials']=sum(d['reason']==reason for d in decisions)
        audit=[json.loads(x) for x in (run/'wallet_audit.jsonl').read_text().splitlines()]
        if want_wallet:
            charged=sum(float(a['charged']) for a in audit);retained=sum(float(a['reserved'])-float(a['refunded']) for a in audit);chats=[a for a in measured if a['route']=='/chat']
            elapsed=max(0,(max(int(a['ts_ms']) for a in audit)-min(a['started_ms'] for a in chats))/1000) if audit and chats else 0
            bound=policy['wallet_capacity']+policy['wallet_refill_per_s']*elapsed
            if charged!=row['server_tokens'] or retained>bound+1e-5 or any(a['run_id']!=e['run_id'] or float(a['refunded'])<0 or float(a['refunded'])>float(a['reserved']) for a in audit):raise ValueError('wallet accounting/bound failed')
            row.update(wallet_retained=retained,wallet_bound=bound)
            if want_lanes:
                if any(float(a['reserved'])>0 and a['lane'] not in ['small','general'] for a in audit):raise ValueError('unknown reservation lane')
                for lane in ['small','general']:
                    spent=sum(float(a['reserved'])-float(a['refunded']) for a in audit if a['lane']==lane)
                    allowance=policy['lanes'][lane]['capacity']+policy['lanes'][lane]['refill_per_s']*elapsed
                    if spent>allowance+1e-5:raise ValueError('lane token envelope exceeded')
                    row['wallet_'+lane+'_retained']=spent
        elif audit:raise ValueError('disabled wallet emitted audit')
        ledger=json.loads((run/'spend_ledger.json').read_text())
        if want_spend:
            used=int(ledger['used']);pending=sum(int(value) for k,value in ledger.items() if k.startswith('r:'))
            if int(ledger['cap'])!=1000000 or used>1000000 or used!=micro+pending:raise ValueError('absolute spend conservation failed')
            row.update(spend_used=used,spend_pending=pending)
        attacks={}
        for attack in ['credential_stuffing','scraping','dow']:
            a=[x for x in measured if x.get('objective') and x.get('attack')==attack]
            if not a:continue
            counts={k:sum(x['outcome']==k for x in a) for k in ['success','fail','blocked','error','timeout','unknown']};counts.update(attempts=len(a),asr=counts['success']/len(a),unique_products=len({p for x in a if x['outcome']=='success' for p in x.get('product_ids',[])}),known_valid_attempts=sum(x.get('credential_kind')=='valid_demo' for x in a),known_valid_success=sum(x.get('credential_kind')=='valid_demo' and x['outcome']=='success' for x in a));attacks[attack]=counts
        stats=[json.loads(p.read_text()) for p in (run/'gate').glob('retry-*.json')]
        row.update(retry_events=sum(s['retry_events'] for s in stats),retry_wait_s=sum(s['wait_s'] for s in stats))
        if e['profile'] in ['burst_fixed','burst_retry','combined_burst']:row['fixed_schedule_opportunities']=(10 if compatibility else e['users'])*21*math.ceil(e['seconds']/24)
        names={'manifest.json','usage.json','bans.json','decisions.jsonl','app-evidence.json','wallet_audit.jsonl','spend_audit.jsonl','spend_ledger.json','private_buckets.json'};names.update(p.name for p in run.glob('attempts-*.jsonl'))
        details[e['run_id']]=dict(attacks=attacks,files={n:hashlib.sha256((run/n).read_bytes()).hexdigest() for n in sorted(names) if (run/n).is_file()});rows.append(row)
    if len(revisions)!=1:raise ValueError('source drift')
    for e in index:
        partners=[x for x in index if x['profile']==e['profile'] and x['rep']==e['rep']];base=manifests[key(partners[0])];m=manifests[key(e)]
        for k in ['identities','seed','duration_requested','users','workload_sha256','worker_driver_sha256','mock','scoring_policy','code_revision','tokenizer','client_timeout_s']:
            if m[k]!=base[k]:raise ValueError('unmatched '+k)
        for k in ['workers','helper_sha256']:
            if m['followup'][k]!=base['followup'][k]:raise ValueError('unmatched helper/worker plan')
    rowmap={(r['profile'],r['config'],r['variant'],r['repetition']):r for r in rows}
    comfort=lambda r:r['benign_attempts']>0 and r['benign_fpr']<=.01 and r['benign_bans']==0 and r['benign_other_unsuccessful']==0 and r['benign_setup_unsuccessful']==0
    for r in rows:
        base=rowmap.get((r['profile'],'C0','current',r['repetition']))
        for q in [50,95]:r[f'delta_c0_p{q}_ms']=float(r[f'latency_p{q}_ms'])-float(base[f'latency_p{q}_ms']) if base and r.get(f'latency_p{q}_ms') not in (None,'') and base.get(f'latency_p{q}_ms') not in (None,'') else None
        if r['profile'] in ['slow','distributed'] and r['variant']=='resource' and not smoke:
            b=rowmap[(r['profile'],'C2','current',r['repetition'])];before=details[b['run_id']]['attacks']['scraping']['success'];after=details[r['run_id']]['attacks']['scraping']['success'];r['scraping_reduction']=1-after/before
    selected=lambda **kw:[r for r in rows if all(r[k]==v for k,v in kw.items())]
    gates=dict(fairness=all(comfort(r) and r['all_unknown']==0 for r in selected(variant='lanes')),bursts=all(comfort(r) and r['all_unknown']==0 for r in rows if r['profile'] in ['burst_fixed','burst_retry'] and r['variant']=='resource'),hard_spend=all(r['cost_microusd']<=1000000 and r['spend_cap_denials']>0 and r['all_unknown']==0 for r in selected(variant='cap')),preserved_defenses=all(r['ban_records']>0 and float(r['asr'])<=.5 and r['all_unknown']==0 for r in selected(profile='fast',variant='resource')))
    for profile in ['slow','distributed']:gates['scraping_volume_'+profile]=all(r.get('scraping_reduction',0)>=.10 and r['all_unknown']==0 and (comfort(r) if r['benign_attempts'] else True) for r in selected(profile=profile,variant='resource'))
    if compatibility:
        candidates=selected(variant='combined')
        gates={'combined_compatibility':bool(candidates) and all(comfort(r) and r['benign_attempts']==(210 if smoke else 630) and r['benign_denials']==0 and r['all_unknown']==0 for r in candidates)}
    groups=defaultdict(list)
    for r in rows:groups[(r['profile'],r['config'],r['variant'])].append(r)
    summary={}
    for group,items in groups.items():
        result={k:sum(r[k] for r in items) for k in ['benign_attempts','benign_denials','benign_bans','benign_other_unsuccessful','benign_setup_unsuccessful','all_unknown','ban_records','wallet_tok_denials','products_items_denials','spend_cap_denials','retry_events','retry_wait_s']};result['metrics']={};result['attacks']={}
        for k in ['latency_p50_ms','latency_p95_ms','delta_c0_p50_ms','delta_c0_p95_ms','waf_overhead_p50_ms','waf_overhead_p95_ms','server_tokens','server_cost_usd','scraping_reduction']:
            vals=[float(r[k]) for r in items if r.get(k) not in (None,'')]
            if vals:result['metrics'][k]=dict(median=median(vals),min=min(vals),max=max(vals))
        for attack in ['credential_stuffing','scraping','dow']:
            samples=[details[r['run_id']]['attacks'][attack] for r in items if attack in details[r['run_id']]['attacks']]
            if samples:
                counts={k:sum(x[k] for x in samples) for k in ['attempts','success','fail','blocked','error','timeout','unknown','known_valid_attempts','known_valid_success']};counts['asr']=counts['success']/counts['attempts'];counts['unique_products_per_run']={k:fn([x['unique_products'] for x in samples]) for k,fn in [('median',median),('min',min),('max',max)]};result['attacks'][attack]=counts
        summary['/'.join(group)]=result
    out.mkdir(parents=True,exist_ok=True)
    with (out/'results.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(dict.fromkeys(k for r in rows for k in r)));w.writeheader();w.writerows(rows)
    result=dict(runs=len(rows),smoke_only=smoke,compatibility=compatibility,gates=gates,policy=policy,summary=summary,details=details,source_revision=next(iter(revisions)),model_sha256=MODEL_SHA256,validator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),kernel_integrated=False,candidates_deployed=False)
    (out/'validation.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runs',type=Path,required=True);p.add_argument('--policy',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--smoke',action='store_true');p.add_argument('--compatibility',action='store_true');a=p.parse_args();r=report(a.runs,a.policy,a.out,a.smoke,a.compatibility);print(json.dumps({k:v for k,v in r.items() if k not in ['details','summary','policy']},indent=2))
