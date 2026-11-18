"""Validate fixed-policy robustness runs without discarding unfavorable outcomes."""
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
from scripts.robustness_cases import CASES,MODEL_SHA256
from scripts.run_c23_benchmark import run_summary
from eval.compute_metrics import read_attempts,percentile
from eval.labels import label_for


def peak_window(stamps,width=1000):
    stamps=sorted(stamps);left=0;peak=0
    for right,ts in enumerate(stamps):
        while ts-stamps[left]>=width:left+=1
        peak=max(peak,right-left+1)
    return peak


def summarize(root,out,smoke=False):
    index=json.loads((root/'index.json').read_text());reps=[1] if smoke else [1,2,3]
    expected={(name,rep,cfg) for name in CASES for rep in reps for cfg in ['C0','C2','C3']}
    if len(index)!=len(expected) or {(e['profile'],e['repetition'],e['config']) for e in index}!=expected:
        raise ValueError('incomplete profile/config/repetition matrix')
    threshold=json.loads((ROOT/'ml/artifacts/model_base_volume_v1.json').read_text())['threshold']
    rows=[];triplets=defaultdict(dict);revisions=set();details={};groups=defaultdict(list)
    for entry in index:
        run=root/'runs'/entry['run_id'];m=json.loads((run/'manifest.json').read_text());profile=entry['profile'];spec=CASES[profile]
        robust=m['robustness'];cfg=entry['config'];rep=entry['repetition']
        if (m['invalid'] or m['code_revision']['dirty'] or robust['profile']!=profile
                or robust['specification']!=spec or robust['smoke_only']!=smoke
                or robust['time_scale']!=(.1 if smoke else 1.0)
                or m['duration_requested']!=f"{8 if smoke else spec['seconds']}s"
                or m['seed']!=(1191 if smoke else 1100+rep)
                or m['worker_lifecycle']!='supervised_deadline_v1'
                or m['effective_policy']['budgets']['llm_tok']!=[40000,2400.0]
                or m['scoring_policy']['batch_size']!=32):raise ValueError('protocol mismatch '+run.name)
        revisions.add(m['code_revision']['commit']);row=run_summary(run,MODEL_SHA256)
        labels={e['ip']:label_for(spec['workload'],e) for e in m['identities']}
        attempts=read_attempts(run);measured=[a for a in attempts if a['phase']=='measured']
        benign=[a for a in measured if labels[a['ip']]=='benign']
        setup=[a for a in attempts if a['phase']=='setup' and labels[a['ip']]=='benign']
        bans=json.loads((run/'bans.json').read_text())
        row.update(profile=profile,benign_attempts=len(benign),
            benign_policy_denials=sum(a['outcome']=='blocked' for a in benign),
            benign_bans=sum(labels.get(b['ip'])=='benign' for b in bans),
            benign_setup_attempts=len(setup),benign_setup_unsuccessful=sum(a['outcome']!='success' for a in setup))
        for outcome in ['success','fail','blocked','error','timeout','unknown']:
            row['benign_'+outcome]=sum(a['outcome']==outcome for a in benign)
        row['benign_policy_fpr']=row['benign_policy_denials']/len(benign) if benign else None
        row['benign_unsuccessful_rate']=sum(a['outcome']!='success' for a in benign)/len(benign) if benign else None
        row['benign_comfort_passed']=(row['benign_policy_fpr']<=.01 and row['benign_bans']==0
            and row['benign_setup_unsuccessful']==0 and sum(row['benign_'+k] for k in ['error','timeout','unknown','fail'])==0) if benign else None
        successful=[a['latency_ms'] for a in benign if a['outcome']=='success']
        for p in [50,95]:row[f'latency_p{p}_ms']=percentile(successful,p/100)
        decisions=[] if cfg=='C0' else [json.loads(line) for line in (run/'decisions.jsonl').read_text().splitlines() if line]
        scores={d['request_id']:float(d['anomaly_score']) for d in decisions if d.get('request_id') and d.get('anomaly_score') not in (None,'')}
        scored=[a for a in benign if a.get('request_id') in scores]
        row['benign_model_scored']=len(scored) if cfg=='C3' else None
        row['benign_model_flags']=sum(scores[a['request_id']]<threshold for a in scored) if cfg=='C3' else None
        usage=json.loads((run/'usage.json').read_text());api,mock=usage['after'],usage['mock_after']
        if (any(int(api.get(a,0))!=int(mock[b]) for a,b in [('tokens_in','tokens_in'),('tokens_out','tokens_out'),('agent_steps','calls')])
            or not math.isclose(float(api.get('cost_usd',0)),float(mock['cost_usd']),abs_tol=1e-7)):
            raise ValueError('independent server usage mismatch')
        for name in ['tokens_in','tokens_out','cost_usd']:row['server_'+name]=mock[name]
        attackers={}
        for attack in ['credential_stuffing','scraping','dow']:
            items=[a for a in measured if a.get('objective') and a.get('attack')==attack]
            if not items:continue
            counts={k:sum(a['outcome']==k for a in items) for k in ['success','fail','blocked','error','timeout','unknown']}
            counts.update(attempts=len(items),asr=counts['success']/len(items),
                known_valid_attempts=sum(a.get('credential_kind')=='valid_demo' for a in items),
                known_valid_success=sum(a.get('credential_kind')=='valid_demo' and a['outcome']=='success' for a in items),
                unique_products=len({v for a in items for v in a.get('product_ids',[]) if a['outcome']=='success'}),
                tokens_out=sum(a.get('tokens_out',0) for a in items),
                model_scored=sum(a.get('request_id') in scores for a in items),
                model_flags=sum(scores[a['request_id']]<threshold for a in items if a.get('request_id') in scores))
            attackers[attack]=counts
        per_ip={ip:dict(attempts=sum(a['ip']==ip for a in measured),
                attempts_per_requested_second=sum(a['ip']==ip for a in measured)/(8 if smoke else spec['seconds']),
                peak_attempts_1s=peak_window([a['started_ms'] for a in measured if a['ip']==ip]),
                role=next(e['role'] for e in m['identities'] if e['ip']==ip)) for ip in labels}
        details[run.name]=dict(attacks=attackers,per_ip=per_ip,
            bans_by_reason={reason:sum(b.get('reason')==reason for b in bans) for reason in sorted({b.get('reason','') for b in bans})},
            benign_model_flag_rate=row['benign_model_flags']/len(scored) if scored else None)
        rows.append(row);groups[(profile,cfg)].append(row);triplets[(profile,rep)][cfg]=m
    if len(revisions)!=1:raise ValueError('source changed within campaign')
    for triplet in triplets.values():
        base=triplet['C0']
        for m in triplet.values():
            for key in ['identities','seed','policy_hash','effective_policy_hash','client_timeout_s','duration_requested',
                        'users','spawn_rate','mock','tokenizer','agent_version','workload_sha256','code_revision',
                        'worker_driver_sha256','robustness','scoring_policy']:
                if m[key]!=base[key]:raise ValueError('unmatched '+key)
    baselines={(r['profile'],r['repetition']):r for r in rows if r['config']=='C0'}
    for row in rows:
        base=baselines[(row['profile'],row['repetition'])]
        for p in [50,95]:
            key=f'latency_p{p}_ms';row[f'delta_p{p}_ms']=float(row[key])-float(base[key]) if row[key] is not None and base[key] is not None else None
    summary={}
    for (profile,cfg),items in groups.items():
        g={k:sum(r[k] for r in items) for k in ['benign_attempts','benign_policy_denials','benign_bans','benign_success',
            'benign_fail','benign_error','benign_timeout','benign_unknown','benign_setup_attempts','benign_setup_unsuccessful']}
        g['comfort_passed']=all(r['benign_comfort_passed'] for r in items) if g['benign_attempts'] else None
        g['benign_model_scored']=sum(r['benign_model_scored'] or 0 for r in items) if cfg=='C3' else None
        g['benign_model_flags']=sum(r['benign_model_flags'] or 0 for r in items) if cfg=='C3' else None
        g['benign_model_flag_rate']=g['benign_model_flags']/g['benign_model_scored'] if g['benign_model_scored'] else None
        g['metrics']={}
        for k in ['latency_p50_ms','latency_p95_ms','delta_p50_ms','delta_p95_ms','waf_overhead_p50_ms','waf_overhead_p95_ms',
                  'scoring_p95_ms','server_tokens_out','server_cost_usd','app_cpu_pct']:
            values=[float(r[k]) for r in items if r.get(k) not in (None,'')]
            if values:g['metrics'][k]=dict(median=median(values),min=min(values),max=max(values))
        g['attacks']={}
        for attack in ['credential_stuffing','scraping','dow']:
            entries=[details[r['run_id']]['attacks'][attack] for r in items if attack in details[r['run_id']]['attacks']]
            if entries:
                counts={k:sum(e[k] for e in entries) for k in ['attempts','success','fail','blocked','error','timeout','unknown','tokens_out','model_scored','model_flags','known_valid_attempts','known_valid_success']}
                counts['asr']=counts['success']/counts['attempts']
                counts['known_valid_asr']=counts['known_valid_success']/counts['known_valid_attempts'] if counts['known_valid_attempts'] else None
                products=[e['unique_products'] for e in entries]
                counts['unique_products_per_run']=dict(median=median(products),min=min(products),max=max(products))
                g['attacks'][attack]=counts
        summary.setdefault(profile,{})[cfg]=g
    out.mkdir(parents=True,exist_ok=True)
    with (out/'results.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(dict.fromkeys(k for r in rows for k in r)));w.writeheader();w.writerows(rows)
    result=dict(kind='fixed_policy_robustness_smoke' if smoke else 'fixed_policy_robustness_study',runs=len(rows),
                triplets=len(triplets),source_revision=next(iter(revisions)),model_sha256=MODEL_SHA256,summary=summary,
                run_details=details,kernel_integrated=False,policy_changed=False,model_retrained=False)
    result['validator_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (out/'validation.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--runs',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--smoke',action='store_true');a=p.parse_args();r=summarize(a.runs,a.out,a.smoke)
    print(json.dumps(dict(runs=r['runs'],triplets=r['triplets'],summary=r['summary']),indent=2))
