"""Fresh combined rollout gate; original component results cannot qualify it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))
from scripts.robustness_cases import MODEL_SHA256


def jobs(smoke=False):
    result=[]
    for rep in ([1] if smoke else [1,2,3]):
        arms=[('C2','combined')] if smoke else [('C0','current'),('C2','current'),('C2','combined'),('C3','combined')]
        if rep==2:arms.reverse()
        for config,variant in arms:result.append(dict(profile='combined_burst',family='compatibility',workload='mixed',users=30,seconds=8 if smoke else 50,seed=2709 if smoke else 2700+rep,rep=rep,config=config,variant=variant))
    return result


def main():
    p=argparse.ArgumentParser();p.add_argument('--redis-url',required=True);p.add_argument('--policy',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--smoke',action='store_true');a=p.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False);index=[]
    if hashlib.sha256((ROOT/'ml/artifacts/model_base_volume_v1.joblib').read_bytes()).hexdigest()!=MODEL_SHA256:raise ValueError('model changed')
    for j in jobs(a.smoke):
        base=f"compat-{'smoke' if a.smoke else 'validation'}-{j['config'].lower()}-{j['variant']}-r{j['rep']}"
        for attempt in range(2):
            uid=base+('-retry' if attempt else '')
            cmd=[sys.executable,'scripts/followup_harness.py','--profile',j['profile'],'--variant',j['variant'],'--policy',str(a.policy.resolve()),*(['--smoke-only'] if a.smoke else []),'--campaign-stage','smoke' if a.smoke else 'validation','--runs',str(out/'runs'),'--redis-url',a.redis_url,'--python',sys.executable,'run','--config',j['config'],'--workload','mixed','--users','30','--duration',f"{j['seconds']}s",'--seed',str(j['seed']),'--repetition',str(j['rep']),'--run-id',uid,'--model',str(ROOT/'ml/artifacts/model_base_volume_v1.joblib')]
            print('START '+uid,flush=True)
            with (out/(uid+'.log')).open('w') as log:c=subprocess.run(cmd,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,env={**os.environ,'WAF_TELEMETRY_LIMIT':'100000'})
            try:
                m=json.loads((out/'runs'/uid/'manifest.json').read_text())
                if c.returncode or m['invalid'] or m['code_revision']['dirty']:raise ValueError('invalid capture')
            except (ValueError,KeyError,OSError) as error:
                print('INVALID '+uid+': '+str(error),flush=True)
                if attempt:raise
                continue
            break
        index.append({**j,'run_id':uid});temp=out/'index.tmp';temp.write_text(json.dumps(index,indent=2)+'\n');temp.replace(out/'index.json');print(f'VALID {uid} ({len(index)}/{len(jobs(a.smoke))})',flush=True)
    print('COMPATIBILITY_CAPTURES_COMPLETE',flush=True)

if __name__=='__main__':main()
