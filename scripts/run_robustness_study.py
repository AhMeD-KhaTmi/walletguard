"""Run the fixed-policy robustness matrix without fitting or changing defenses."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))
from scripts.robustness_cases import CASES,MODEL_SHA256
from scripts.run_c23_benchmark import run_summary


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--redis-url',required=True);p.add_argument('--smoke',action='store_true');a=p.parse_args()
    model=ROOT/'ml/artifacts/model_base_volume_v1.joblib'
    if hashlib.sha256(model.read_bytes()).hexdigest()!=MODEL_SHA256:raise ValueError('qualified model changed')
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False);index=[]
    for rep in ([1] if a.smoke else [1,2,3]):
        names=list(CASES);names=names[rep-1:]+names[:rep-1]
        configs=['C0','C2','C3'] if rep==1 else ['C3','C2','C0'] if rep==2 else ['C2','C0','C3']
        for name in names:
            spec=CASES[name]
            for config in configs:
                base=f"robust-{'smoke' if a.smoke else 'validation'}-{name}-{config.lower()}-r{rep}"
                for attempt in range(2):
                    uid=base+('-retry' if attempt else '')
                    command=[sys.executable,'scripts/robustness_harness.py','--robust-profile',name,
                             *(['--robust-smoke'] if a.smoke else []),'--campaign-stage','smoke' if a.smoke else 'validation',
                             '--runs',str(out/'runs'),'--redis-url',a.redis_url,'--python',sys.executable,
                             'run','--config',config,'--workload',spec['workload'],'--duration',f"{8 if a.smoke else spec['seconds']}s",
                             '--users',str(spec['users']),'--seed',str(1191 if a.smoke else 1100+rep),
                             '--repetition',str(rep),'--run-id',uid,'--model',str(model)]
                    print('START '+uid,flush=True)
                    with (out/(uid+'.log')).open('w') as log:
                        child=subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,
                            env={**os.environ,'WAF_TELEMETRY_LIMIT':'100000','WAF_SCORE_BATCH_SIZE':'32','WAF_SCORE_BATCH_WAIT_MS':'2'})
                    try:
                        run=out/'runs'/uid;m=json.loads((run/'manifest.json').read_text())
                        if child.returncode or m['invalid'] or m['code_revision']['dirty']:raise ValueError('invalid capture')
                        run_summary(run,MODEL_SHA256)
                    except (ValueError,KeyError,OSError) as exc:
                        with (out/'excluded.jsonl').open('a') as f:f.write(json.dumps(dict(run_id=uid,reason=str(exc)))+'\n')
                        print('EXCLUDED '+uid+': '+str(exc),flush=True)
                        if attempt:raise
                        continue
                    index.append(dict(run_id=uid,profile=name,repetition=rep,config=config,seed=m['seed']))
                    tmp=out/'index.tmp';tmp.write_text(json.dumps(index,indent=2)+'\n');tmp.replace(out/'index.json')
                    print(f'VALID {uid} ({len(index)}/{15 if a.smoke else 45})',flush=True)
                    break

if __name__=='__main__':main()
