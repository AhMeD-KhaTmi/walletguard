"""Fresh safety gate for legitimate users competing with account-fanout spending."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--redis-url',required=True)
    p.add_argument('--policy',type=Path,required=True);a=p.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    index=[]
    for rep in [1,2,3]:
        for config in (['C3','C2','C0'] if rep==2 else ['C0','C2','C3']):
            variant='legacy' if config=='C0' else 'remedy';uid=f'wallet-mixed-{config.lower()}-r{rep}'
            cmd=[sys.executable,'scripts/remedy_harness.py','--remedy-profile','wallet_mixed','--policy-variant',variant,
                 '--global-policy',str(a.policy.resolve()),'--campaign-stage','validation','--runs',str(out/'runs'),
                 '--redis-url',a.redis_url,'--python',sys.executable,'run','--config',config,'--workload','mixed',
                 '--duration','45s','--users','15','--seed',str(1400+rep),'--repetition',str(rep),'--run-id',uid,
                 '--model',str(ROOT/'ml/artifacts/model_base_volume_v1.joblib')]
            print('START '+uid,flush=True)
            with (out/(uid+'.log')).open('w') as log:
                c=subprocess.run(cmd,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,env={**os.environ,'WAF_TELEMETRY_LIMIT':'100000'})
            m=json.loads((out/'runs'/uid/'manifest.json').read_text())
            if c.returncode or m['invalid'] or m['code_revision']['dirty']:raise ValueError('invalid mixed capture')
            index.append(dict(profile='wallet_mixed',config=config,variant=variant,seed=1400+rep,rep=rep,
                              seconds=45,users=15,workload='mixed',run_id=uid))
            tmp=out/'index.tmp';tmp.write_text(json.dumps(index,indent=2)+'\n');tmp.replace(out/'index.json')
            print(f'VALID {uid} ({len(index)}/9)',flush=True)

if __name__=='__main__':main()
