"""Independently verify source, splits and matched live evidence before activation."""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
from statistics import median
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))
from scripts.run_volume_experiment import jobs
from eval.compute_metrics import read_attempts


def verify_usage(run):
    usage=json.loads((run/'usage.json').read_text());api,mock=usage['after'],usage['mock_after']
    if any(int(api.get(a,0))!=int(mock[b]) for a,b in
           [('tokens_in','tokens_in'),('tokens_out','tokens_out'),('agent_steps','calls')]):
        raise ValueError('API/mock mismatch '+run.name)
    if not math.isclose(float(api.get('cost_usd',0)),float(mock['cost_usd']),abs_tol=1e-7):
        raise ValueError('API/mock cost mismatch')


def report(experiment,live,out,confirmation=False):
    index=json.loads((experiment/'index.json').read_text());planned=jobs()
    if len(index)!=21 or {j['run_id'].removesuffix('-retry') for j in index}!={j['run_id'] for j in planned}:
        raise ValueError('incomplete independent groups')
    revisions=set()
    for job in index:
        run=experiment/'runs'/job['run_id'];m=json.loads((run/'manifest.json').read_text())
        if m['invalid'] or m['code_revision']['dirty'] or m['config']!='C1' or m['seed']!=job['seed']:
            raise ValueError('invalid C1 capture')
        revisions.add(m['code_revision']['commit']);verify_usage(run)
    if len(revisions)!=1:raise ValueError('source changed during collection')
    frozen=json.loads((experiment/'frozen.json').read_text());evaluation=json.loads((experiment/'evaluation.json').read_text())
    sha=hashlib.sha256((experiment/'candidate.joblib').read_bytes()).hexdigest()
    if sha!=frozen['model_sha256'] or sha!=evaluation['models']['candidate']['model_sha256']:
        raise ValueError('candidate changed after freezing')
    rows=[];live_pass=False;summary={};mixed_attacks={}
    if live.exists():
        rows=json.loads((live/'results.json').read_text())
        if len(rows)!=18:raise ValueError('incomplete live grid')
        pair={};live_revisions=set()
        for row in rows:
            run=live/'runs'/row['run_id'];m=json.loads((run/'manifest.json').read_text());verify_usage(run)
            if m['invalid'] or m['code_revision']['dirty'] or (not confirmation and m['code_revision']['commit'] not in revisions):
                raise ValueError('invalid live source')
            live_revisions.add(m['code_revision']['commit'])
            if confirmation and (m.get('worker_lifecycle')!='supervised_deadline_v1' or
                m.get('worker_driver_sha256')!=hashlib.sha256((ROOT/'scripts/locust_deadline_driver.py').read_bytes()).hexdigest()):
                raise ValueError('unrecorded lifecycle change')
            if (m['seed']!=(760 if confirmation else 750)+row['repetition'] or m['duration_requested']!='30s'
                    or m['effective_policy']['budgets']['llm_tok']!=[40000,2400.0]
                    or m['effective_policy']['strike_limit']!=5
                    or m['effective_policy']['max_output_cap']!=1024
                    or m['scoring_policy']['batch_size']!=32):
                raise ValueError('live protocol mismatch')
            if m['model_hash']!=(sha if row['config']=='C3' else None):raise ValueError('unexpected model')
            if row['workload']=='mixed':
                for attempt in read_attempts(run):
                    if attempt['phase']!='measured' or not attempt.get('objective') or not attempt.get('attack'):
                        continue
                    key=f"{row['config']}-{attempt['attack']}"
                    counts=mixed_attacks.setdefault(key,dict(attempts=0,success=0,unknown=0))
                    counts['attempts']+=1;counts['success']+=attempt['outcome']=='success'
                    counts['unknown']+=attempt['outcome'] in ['unknown','error','timeout']
            key=(row['scenario'],row['workload'],row['repetition'])
            pair.setdefault(key,{})[row['config']]=m
        expected={(s,w,r) for s,w in [('normal','benign'),('varied','benign'),('normal','mixed')] for r in [1,2,3]}
        if len(live_revisions)!=1:raise ValueError('live source changed')
        if set(pair)!=expected or any(set(p)!={'C0','C3'} for p in pair.values()):raise ValueError('unmatched live grid')
        for p in pair.values():
            for key in ['seed','identities','policy_hash','effective_policy_hash','duration_requested',
                        'workload_sha256','users','spawn_rate','mock','tokenizer','agent_version','scoring_policy']:
                if p['C0'][key]!=p['C3'][key]:raise ValueError('unmatched '+key)
        live_pass=all(r['benign_attempts']>0 and r['benign_policy_denials']/r['benign_attempts']<=.01
                      and r['benign_unknown']==0 and r['benign_auto_bans']==0 for r in rows)
        baselines={(r['scenario'],r['workload'],r['repetition']):r for r in rows if r['config']=='C0'}
        for row in rows:
            baseline=baselines[(row['scenario'],row['workload'],row['repetition'])]
            for percentile in [50,95]:
                key=f'latency_p{percentile}_ms'
                row[f'latency_delta_p{percentile}_ms']=float(row[key])-float(baseline[key])
        for scenario,workload in [('normal','benign'),('varied','benign'),('normal','mixed')]:
            group={}
            for config in ['C0','C3']:
                items=[r for r in rows if (r['scenario'],r['workload'],r['config'])==(scenario,workload,config)]
                g={k:sum(r[k] for r in items) for k in ['benign_attempts','benign_policy_denials','benign_unknown','benign_auto_bans']}
                for metric in ['latency_p50_ms','latency_p95_ms','waf_overhead_p50_ms','waf_overhead_p95_ms',
                               'scoring_p95_ms','app_cpu_pct','asr','unknown_outcomes',
                               'latency_delta_p50_ms','latency_delta_p95_ms']:
                    vals=[float(r[metric]) for r in items if r.get(metric) not in (None,'')]
                    if vals:g[metric]=dict(median=median(vals),min=min(vals),max=max(vals))
                group[config]=g
            summary[f'{scenario}-{workload}']=group
    result=dict(offline_gate_passed=evaluation['offline_gate_passed'],live_gate_passed=live_pass,
                eligible_for_activation=evaluation['offline_gate_passed'] and live_pass,
                deployed=False,model_sha256=sha,source_revision=next(iter(revisions)),
                live_source_revision=next(iter(live_revisions)) if rows else None,
                lifecycle_confirmation=confirmation,
                c1_runs=21,live_runs=len(rows),summary=summary,kernel_integrated=False,
                mixed_attacks={key:{**v,'asr':v['success']/v['attempts']} for key,v in mixed_attacks.items()},
                note='Short synthetic workload windows; no production or C4 acceptance claim.')
    out.mkdir(parents=True,exist_ok=True)
    (out/'acceptance.json').write_text(json.dumps(result,indent=2)+'\n')
    if rows:
        with (out/'live.csv').open('w',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=list(dict.fromkeys(k for r in rows for k in r)))
            writer.writeheader();writer.writerows(rows)
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--experiment',type=Path,required=True)
    p.add_argument('--live',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--confirmation',action='store_true')
    a=p.parse_args();print(json.dumps(report(a.experiment,a.live,a.out,a.confirmation),indent=2))
