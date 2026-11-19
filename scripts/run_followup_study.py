"""Fixed prospective variants and independent seeds; never retry poor outcomes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))
import redis
from waf.buckets import SPEND_INIT_LUA
from scripts.robustness_cases import MODEL_SHA256


def jobs(smoke=False):
    rows=[]
    for rep in [1,2,3]:
        for profile,workload,users,seconds,family,seedbase in [('fair_mixed','mixed',15,45,'fairness',2100),('varied','benign',10,30,'fairness',2100),('burst_fixed','benign',10,50,'resource',2300),('burst_retry','benign',10,50,'resource',2300),('distributed','combined',14,45,'resource',2300),('slow','mixed',14,120,'resource',2300),('spend','combined',14,45,'spend',2400),('fast','scraping',3,10,'preserved',2500)]:
            if family=='fairness':arms=[('C0','current'),('C2','current'),('C2','lanes'),('C3','lanes')]+([('C2','pooled')] if profile=='fair_mixed' else [])
            elif family=='spend':arms=[('C0','current'),('C2','cap'),('C3','cap')]
            elif family=='preserved':arms=[('C0','current'),('C2','resource'),('C3','resource')]
            else:arms=[('C0','current'),('C2','current'),('C2','resource'),('C3','resource')]
            if rep==2:arms.reverse()
            for config,variant in arms:
                rows.append(dict(profile=profile,workload=workload,users=users,seconds=seconds,family=family,seed=seedbase+rep,rep=rep,config=config,variant=variant))
    if smoke:
        rows=[r for r in rows if r['rep']==1 and r['config']=='C2' and (r['profile'],r['variant']) in [('fair_mixed','lanes'),('burst_retry','resource'),('distributed','resource'),('spend','cap')]]
        rows=[{**r,'seconds':8,'seed':2601} for r in rows]
    return rows


def main():
    p=argparse.ArgumentParser();p.add_argument('--redis-url',required=True);p.add_argument('--policy',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--smoke',action='store_true');a=p.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False);index=[]
    if hashlib.sha256((ROOT/'ml/artifacts/model_base_volume_v1.joblib').read_bytes()).hexdigest()!=MODEL_SHA256:raise ValueError('model changed')
    for j in jobs(a.smoke):
        base=f"followup-{'smoke' if a.smoke else 'validation'}-{j['profile']}-{j['config'].lower()}-{j['variant']}-r{j['rep']}"
        for attempt in range(2):
            uid=base+('-retry' if attempt else '')
            if j['variant']=='cap':
                with redis.Redis.from_url(a.redis_url) as r:
                    if r.eval(SPEND_INIT_LUA,1,'p20:spend:'+uid,1000000)<0:raise ValueError('spend period policy mismatch')
            cmd=[sys.executable,'scripts/followup_harness.py','--profile',j['profile'],'--variant',j['variant'],'--policy',str(a.policy.resolve()),*(['--smoke-only'] if a.smoke else []),'--campaign-stage','smoke' if a.smoke else 'validation','--runs',str(out/'runs'),'--redis-url',a.redis_url,'--python',sys.executable,'run','--config',j['config'],'--workload',j['workload'],'--users',str(j['users']),'--duration',f"{j['seconds']}s",'--seed',str(j['seed']),'--repetition',str(j['rep']),'--run-id',uid,'--model',str(ROOT/'ml/artifacts/model_base_volume_v1.joblib')]
            print('START '+uid,flush=True)
            with (out/(uid+'.log')).open('w') as f:c=subprocess.run(cmd,cwd=ROOT,stdout=f,stderr=subprocess.STDOUT,env={**os.environ,'WAF_TELEMETRY_LIMIT':'100000'})
            try:
                m=json.loads((out/'runs'/uid/'manifest.json').read_text())
                if c.returncode or m['invalid'] or m['code_revision']['dirty']:raise ValueError('invalid capture')
            except (ValueError,OSError,KeyError) as error:
                print(f'INVALID {uid}: {error}',flush=True)
                if attempt:raise
                continue
            break
        index.append({**j,'run_id':uid});temp=out/'index.tmp';temp.write_text(json.dumps(index,indent=2)+'\n');temp.replace(out/'index.json');print(f'VALID {uid} ({len(index)}/{len(jobs(a.smoke))})',flush=True)
    print('FOLLOWUP_CAPTURES_COMPLETE',flush=True)

if __name__=='__main__':main()
