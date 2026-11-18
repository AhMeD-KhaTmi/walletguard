"""Live acceptance of the frozen offline-qualified volume candidate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))
from eval.compute_metrics import read_attempts
from eval.labels import label_for
from scripts.run_c23_benchmark import run_summary


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--experiment',type=Path,required=True)
    p.add_argument('--redis-url',required=True)
    p.add_argument('--confirmation',action='store_true')
    p.add_argument('--smoke',action='store_true');a=p.parse_args()
    if (a.confirmation or a.smoke) and os.environ.get('P20_SAFE_DRIVER')!='1':
        raise ValueError('confirmation/smoke requires the recorded safe lifecycle driver')
    seed_base=860 if a.smoke else 760 if a.confirmation else 750
    duration=7 if a.smoke else 30
    experiment=a.experiment.resolve();gate=json.loads((experiment/'evaluation.json').read_text())
    if gate['offline_gate_passed'] is not True:raise ValueError('offline acceptance failed; do not run candidate')
    model=experiment/'candidate.joblib';sha=hashlib.sha256(model.read_bytes()).hexdigest()
    if sha!=gate['models']['candidate']['model_sha256']:raise ValueError('candidate changed after acceptance')
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False);index=[]
    for rep in ([1] if a.smoke else [1,2,3]):
        for scenario,workload,users in [('normal','benign',10),('varied','benign',10),('normal','mixed',14)]:
            for config in (['C3','C0'] if rep==2 else ['C0','C3']):
                uid=f'volume-live-{scenario}-{workload}-{config.lower()}-{rep}'
                cmd=[sys.executable,'scripts/budget_harness.py','--agent-scenario',scenario,
                     '--campaign-stage','validation','--runs',str(out/'runs'),'--redis-url',a.redis_url,
                     '--python',sys.executable,'run','--config',config,'--workload',workload,
                     '--duration',f'{duration}s','--users',str(users),'--seed',str(seed_base+rep),'--repetition',str(rep),
                     '--run-id',uid,'--model',str(model)]
                print('START '+uid,flush=True)
                with (out/(uid+'.log')).open('w') as log:
                    child=subprocess.run(cmd,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,
                                         env={**os.environ,'WAF_TELEMETRY_LIMIT':'100000'})
                run=out/'runs'/uid;m=json.loads((run/'manifest.json').read_text())
                if child.returncode or m['invalid'] or m['code_revision']['dirty']:raise ValueError('invalid capture '+uid)
                row=run_summary(run,sha);labels={e['ip']:label_for(workload,e) for e in m['identities']}
                benign=[r for r in read_attempts(run) if r['phase']=='measured' and labels[r['ip']]=='benign']
                row.update(scenario=scenario,benign_attempts=len(benign),
                    benign_policy_denials=sum(r['outcome']=='blocked' for r in benign),
                    benign_unknown=sum(r['outcome'] in ['unknown','error','timeout'] for r in benign),
                    benign_auto_bans=sum(labels.get(b['ip'])=='benign' for b in json.loads((run/'bans.json').read_text())))
                index.append(row);(out/'results.json').write_text(json.dumps(index,indent=2)+'\n')
                print(f'VALID {uid} ({len(index)}/18)',flush=True)
    passed=all(r['benign_attempts']>0 and r['benign_policy_denials']/r['benign_attempts']<=.01
               and r['benign_unknown']==0 and r['benign_auto_bans']==0 for r in index)
    result={'live_safety_gate_passed':passed,'runs':len(index),'model_sha256':sha,'deployed':False,
            'confirmation':a.confirmation,'smoke_only':a.smoke,
            'note':'Candidate remains inactive until final combined acceptance review.'}
    (out/'acceptance.json').write_text(json.dumps(result,indent=2)+'\n');print('LIVE_GATE '+str(passed),flush=True)

if __name__=='__main__':main()
