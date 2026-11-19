"""Fresh benign-only fitting; fixed rules in FAIRNESS_BURST_SPEND_PROTOCOL.md."""
import argparse
from collections import deque
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))
from eval.compute_metrics import read_attempts


def peak(rows,width):
    q=deque();total=0;maximum=0
    for ts,cost in sorted(rows):
        while q and ts-q[0][0]>=width:total-=q.popleft()[1]
        q.append((ts,cost));total+=cost;maximum=max(maximum,total)
    return maximum


def fit(root,index):
    if len(index)!=9:raise ValueError('nine fresh benign groups required')
    expected={(p,2000+r) for p in ['normal','varied'] for r in [1,2,3]}|{('burst',2200+r) for r in [1,2,3]}
    if {(e['profile'],e['seed']) for e in index}!=expected:raise ValueError('wrong calibration cohorts')
    lanes={name:dict(largest=0,peak1s=0,peak60s=0,tasks=0) for name in ['small','general']}
    ip_peak=item_peak=item_60=0;proof=[]
    for e in index:
        run=root/'runs'/e['run_id'];m=json.loads((run/'manifest.json').read_text());attempts=read_attempts(run)
        if m['invalid'] or m['code_revision']['dirty'] or m['seed']!=e['seed'] or m['config']!='C1' or any(a['outcome']!='success' for a in attempts):raise ValueError('invalid benign fitting capture')
        measured=[a for a in attempts if a['phase']=='measured'];raw=[json.loads(x) for x in (run/'features.jsonl').read_text().splitlines()];features={a['request_id']:a for a in raw}
        if len(features)!=len(raw) or sum(a.get('request_id') in features for a in measured)/len(measured)<.98:raise ValueError('feature joins incomplete')
        usage=json.loads((run/'usage.json').read_text());api,mock=usage['after'],usage['mock_after']
        if any(int(api.get(k,0))!=int(mock[k]) for k in ['tokens_in','tokens_out']) or not math.isclose(float(api.get('cost_usd',0)),float(mock['cost_usd']),abs_tol=1e-7):raise ValueError('accounting mismatch')
        if e['profile']!='burst':
            records={name:[] for name in lanes}
            for a in measured:
                if a['route']!='/chat':continue
                cost=int(float(features[a['request_id']]['task_token_budget']))
                if cost!=a['tokens_in']+a['tokens_out']:raise ValueError('task reserve mismatch')
                records['small' if cost<=2048 else 'general'].append((a['started_ms'],cost))
            for name,rows in records.items():
                s=lanes[name];s['tasks']+=len(rows);s['largest']=max(s['largest'],max((x[1] for x in rows),default=0));s['peak1s']=max(s['peak1s'],peak(rows,1000));s['peak60s']=max(s['peak60s'],peak(rows,60000))
        else:
            for ip in {a['ip'] for a in measured}:
                rows=[a for a in measured if a['ip']==ip];items=[(a['started_ms'],min(100,max(1,int(a['per_page'])))) for a in rows if a['route']=='/products']
                ip_peak=max(ip_peak,peak([(a['started_ms'],1) for a in rows],1000));item_peak=max(item_peak,peak(items,1000));item_60=max(item_60,peak(items,60000))
        proof.append(dict(run_id=e['run_id'],seed=e['seed'],profile=e['profile'],source=m['code_revision'],files={n:hashlib.sha256((run/n).read_bytes()).hexdigest() for n in ['manifest.json','features.jsonl','usage.json']}))
    for s in lanes.values():
        if not s['tasks']:raise ValueError('empty size lane')
        s.update(capacity=math.ceil(max(4000,2*s['largest'],1.25*s['peak1s'])/1000)*1000,refill_per_s=max(50,math.ceil(1.25*s['peak60s']/60/50)*50))
    return dict(small_task_max=2048,lanes=lanes,wallet_capacity=sum(x['capacity'] for x in lanes.values()),wallet_refill_per_s=sum(x['refill_per_s'] for x in lanes.values()),ip_capacity=max(30,math.ceil(1.25*ip_peak/10)*10),products_capacity=math.ceil(1.25*item_peak/100)*100,products_refill_per_s=max(5,math.ceil(1.25*item_60/60/5)*5),burst_peaks=dict(requests_1s=ip_peak,items_1s=item_peak,items_60s=item_60),calibration=proof,frozen_before_validation=True)


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--redis-url',required=True);a=p.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False);index=[]
    for family,profiles,base,duration in [('wallet',['normal','varied'],2000,60),('burst',['burst'],2200,50)]:
        for rep in [1,2,3]:
            for profile in profiles:
                uid=f'followup-cal-{profile}-r{rep}'
                cmd=([sys.executable,'scripts/robustness_harness.py','--robust-profile','burst_above'] if profile=='burst' else [sys.executable,'scripts/budget_harness.py','--agent-scenario',profile])
                cmd+=['--campaign-stage','calibration','--runs',str(out/'runs'),'--redis-url',a.redis_url,'--python',sys.executable,'run','--config','C1','--workload','benign','--duration',f'{duration}s','--users','10','--seed',str(base+rep),'--repetition',str(rep),'--run-id',uid]
                print('START '+uid,flush=True)
                with (out/(uid+'.log')).open('w') as log:r=subprocess.run(cmd,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,env={**os.environ,'P20_SAFE_DRIVER':'1','WAF_ACCOUNT_PRESSURE_BANS':'0','WAF_WALLET_CAPACITY':'0','WAF_WALLET_REFILL_PER_S':'0','WAF_TELEMETRY_LIMIT':'100000'})
                if r.returncode:raise ValueError('failed calibration '+uid)
                index.append(dict(profile=profile,seed=base+rep,run_id=uid));(out/'index.json').write_text(json.dumps(index,indent=2)+'\n');print(f'VALID {uid} ({len(index)}/9)',flush=True)
    policy=fit(out,index);(out/'frozen_policy.json').write_text(json.dumps(policy,indent=2)+'\n');print('FOLLOWUP_POLICY_FROZEN '+json.dumps({k:v for k,v in policy.items() if k not in ['calibration','lanes']}),flush=True)

if __name__=='__main__':main()
