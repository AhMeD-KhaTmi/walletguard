"""Prospective calibration and matched policy-variant validation; never train ML."""
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
from scripts.robustness_cases import MODEL_SHA256

PROFILES={'shared_account':('benign',5,36),'distributed':('combined',14,45),
          'normal':('benign',10,30),'varied':('benign',10,30),
          'burst_within':('benign',10,30),'fast_scraping':('scraping',3,10)}


def select_policy(ledgers):
    peaks={1000:0,60000:0};largest=0;count=0
    for rows in ledgers:
        for width in peaks:
            window=deque();total=0
            for ts,cost in sorted(rows):
                if not math.isfinite(ts) or type(cost)is not int or cost<=0:raise ValueError('bad calibration task')
                while window and ts-window[0][0]>=width:total-=window.popleft()[1]
                window.append((ts,cost));total+=cost;peaks[width]=max(peaks[width],total)
        largest=max(largest,max((c for _,c in rows),default=0));count+=len(rows)
    if not count:raise ValueError('empty calibration')
    return dict(capacity=math.ceil(max(40000,2*largest,1.25*peaks[1000])/5000)*5000,
                refill_per_s=math.ceil(1.25*peaks[60000]/60/50)*50,
                largest_task=largest,peak_1s=peaks[1000],peak_60s=peaks[60000],tasks=count)


def fit(out,index):
    ledgers=[];proof=[]
    if len(index)!=6 or {(j['profile'],j['seed']) for j in index}!={(s,n) for s in ['normal','varied'] for n in [1201,1202,1203]}:
        raise ValueError('wrong fresh calibration groups')
    for j in index:
        run=out/'runs'/j['run_id'];m=json.loads((run/'manifest.json').read_text())
        rows=read_attempts(run)
        if m['invalid'] or m['config']!='C1' or m['code_revision']['dirty'] or any(r['outcome']!='success' for r in rows):raise ValueError('invalid benign calibration capture')
        raw=list(map(json.loads,(run/'features.jsonl').read_text().splitlines()))
        features={r['request_id']:r for r in raw}
        if len(features)!=len(raw):raise ValueError('duplicate feature request IDs')
        measured=[r for r in rows if r['phase']=='measured']
        if sum(r.get('request_id') in features for r in measured)/len(measured)<.98:raise ValueError('insufficient join coverage')
        usage=json.loads((run/'usage.json').read_text());api,mock=usage['after'],usage['mock_after']
        if (any(int(api.get(a,0))!=int(mock[b]) for a,b in [('tokens_in','tokens_in'),('tokens_out','tokens_out'),('agent_steps','calls')])
                or not math.isclose(float(api.get('cost_usd',0)),float(mock['cost_usd']),abs_tol=1e-7)):
            raise ValueError('independent accounting mismatch')
        chats=[r for r in rows if r['phase']=='measured' and r['route']=='/chat'];ledger=[]
        for row in chats:
            rid=row.get('request_id')
            if not rid or rid not in features:raise ValueError('missing measured chat feature')
            c=float(features[rid]['task_token_budget'])
            if not c.is_integer() or int(c)!=row['tokens_in']+row['tokens_out']:raise ValueError('task reserve/accounting mismatch')
            ledger.append((row['started_ms'],int(c)))
        ledgers.append(ledger);proof.append(dict(run_id=j['run_id'],seed=j['seed'],profile=j['profile'],
            files={f:hashlib.sha256((run/f).read_bytes()).hexdigest() for f in ['manifest.json','features.jsonl','usage.json']}))
    return dict(candidate=select_policy(ledgers),calibration=proof,frozen_before_validation=True,
                rule='max(40000,two largest task,1.25 peak1s);1.25 peak60s/60;round5000 and50/s')


def jobs(stage):
    if stage=='calibration':
        return [dict(profile=p,config='C1',variant='legacy',seed=1200+r,rep=r,seconds=60,users=10,workload='benign')
                for r in [1,2,3] for p in ['normal','varied']]
    result=[]
    for rep in ([1] if stage=='smoke' else [1,2,3]):
        for profile,(workload,users,seconds) in PROFILES.items():
            variants=([('C2','legacy'),('C2','remedy'),('C3','legacy'),('C3','remedy')]
                      if profile in ['shared_account','distributed'] else
                      [('C0','legacy'),('C2','remedy'),('C3','remedy')] if profile in ['normal','varied','fast_scraping']
                      else [('C2','remedy'),('C3','remedy')])
            if rep==2:variants.reverse()
            for cfg,variant in variants:
                result.append(dict(profile=profile,config=cfg,variant=variant,seed=1391 if stage=='smoke' else 1300+rep,
                                   rep=rep,seconds=8 if stage=='smoke' else seconds,users=users,workload=workload))
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--stage',choices=['calibration','smoke','validation'],required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--redis-url',required=True);p.add_argument('--policy',type=Path)
    a=p.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False);index=[]
    model=ROOT/'ml/artifacts/model_base_volume_v1.joblib'
    if hashlib.sha256(model.read_bytes()).hexdigest()!=MODEL_SHA256:raise ValueError('model changed')
    for job in jobs(a.stage):
        base=f"remedy-{a.stage}-{job['profile']}-{job['config'].lower()}-{job['variant']}-r{job['rep']}"
        for attempt in range(2):
            uid=base+('-retry' if attempt else '')
            command=[sys.executable,'scripts/remedy_harness.py','--remedy-profile',job['profile'],'--policy-variant',job['variant'],
                *(['--global-policy',str(a.policy.resolve())] if a.policy else []),*(['--remedy-smoke'] if a.stage=='smoke' else []),
                '--campaign-stage','calibration' if a.stage=='calibration' else 'smoke' if a.stage=='smoke' else 'validation',
                '--runs',str(out/'runs'),'--redis-url',a.redis_url,'--python',sys.executable,'run','--config',job['config'],
                '--workload',job['workload'],'--duration',f"{job['seconds']}s",'--users',str(job['users']),
                '--seed',str(job['seed']),'--repetition',str(job['rep']),'--run-id',uid,'--model',str(model)]
            print('START '+uid,flush=True)
            with (out/(uid+'.log')).open('w') as log:
                child=subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,
                    env={**os.environ,'WAF_TELEMETRY_LIMIT':'100000','WAF_SCORE_BATCH_SIZE':'32','WAF_SCORE_BATCH_WAIT_MS':'2'})
            try:
                m=json.loads((out/'runs'/uid/'manifest.json').read_text())
                if child.returncode or m['invalid'] or m['code_revision']['dirty']:raise ValueError('invalid capture')
                if a.stage=='calibration' and any(r['outcome']!='success' for r in read_attempts(out/'runs'/uid)):raise ValueError('incomplete calibration traffic')
            except (OSError,ValueError,KeyError) as exc:
                with (out/'excluded.jsonl').open('a') as f:f.write(json.dumps(dict(run_id=uid,reason=str(exc)))+'\n')
                if attempt:raise
                print('EXCLUDED '+uid,flush=True);continue
            index.append({**job,'run_id':uid});tmp=out/'index.tmp';tmp.write_text(json.dumps(index,indent=2)+'\n');tmp.replace(out/'index.json')
            print(f"VALID {uid} ({len(index)}/{len(jobs(a.stage))})",flush=True);break
    if a.stage=='calibration':
        (out/'frozen_policy.json').write_text(json.dumps(fit(out,index),indent=2)+'\n')
        print('FROZEN '+(out/'frozen_policy.json').read_text(),flush=True)

if __name__=='__main__':main()
