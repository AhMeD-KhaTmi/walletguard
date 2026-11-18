"""Frozen benign-only volume experiment: capture, fit, freeze, then test once."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import math

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from eval.compute_metrics import read_attempts
from eval.export_features import export
from eval.labels import collect


def jobs():
    result = []
    for seed in [701, 702, 703]:
        for scenario in ['normal', 'varied']:
            result.append(dict(run_id=f'volume-{scenario}-{seed}', scenario=scenario, workload='benign',
                               seed=seed, users=10, seconds=60,
                               split='calibration' if seed == 703 else 'fit', rep=1))
    for rep, seed in enumerate([711, 712, 713], 1):
        for scenario in ['normal', 'varied']:
            result.append(dict(run_id=f'volume-test-{scenario}-{seed}', scenario=scenario,
                               workload='benign', seed=seed, users=10, seconds=60, split='test', rep=rep))
    for workload, base in [('credential_stuffing', 721), ('scraping', 722), ('dow', 723)]:
        for rep in [1, 2, 3]:
            seed = base+10*(rep-1)
            result.append(dict(run_id=f'volume-test-{workload}-{seed}', scenario='normal',
                               workload=workload, seed=seed, users=3, seconds=30, split='test', rep=rep))
    return result


def capture(job, out, redis_url):
    for attempt in range(2):
        uid = job['run_id'] + ('-retry' if attempt else '')
        run = out/'runs'/uid
        command = [sys.executable, 'scripts/budget_harness.py', '--agent-scenario', job['scenario'],
                   '--campaign-stage', 'calibration' if job['split'] != 'test' else 'validation',
                   '--runs', str(out/'runs'), '--redis-url', redis_url, '--python', sys.executable,
                   'run', '--config', 'C1', '--workload', job['workload'], '--seed', str(job['seed']),
                   '--repetition', str(job['rep']), '--duration', f"{job['seconds']}s",
                   '--users', str(job['users']), '--run-id', uid]
        print('START '+uid, flush=True)
        with (out/(uid+'.log')).open('w') as log:
            child = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                   env={**os.environ, 'WAF_TELEMETRY_LIMIT': '100000'})
        try:
            m = json.loads((run/'manifest.json').read_text())
            if child.returncode or m.get('invalid') is not False or m['code_revision']['dirty']:
                raise ValueError('invalid or dirty capture')
            attempts = read_attempts(run)
            if job['split'] != 'test' and any(a['outcome'] != 'success' for a in attempts):
                raise ValueError('incomplete benign fitting/calibration traffic')
            usage = json.loads((run/'usage.json').read_text())
            api, mock = usage['after'], usage['mock_after']
            if (any(int(api.get(a, 0)) != int(mock[b]) for a,b in
                    [('tokens_in','tokens_in'),('tokens_out','tokens_out'),('agent_steps','calls')])
                    or not math.isclose(float(api.get('cost_usd',0)),float(mock['cost_usd']),abs_tol=1e-7)):
                raise ValueError('API/mock totals differ')
            return {**job, 'run_id':uid}
        except (ValueError, KeyError, OSError) as exc:
            rejection = {'run_id':uid,'reason':str(exc)}
            with (out/'excluded.jsonl').open('a') as f:f.write(json.dumps(rejection)+'\n')
            print('EXCLUDED '+json.dumps(rejection),flush=True)
    raise RuntimeError('two rejected attempts; no model fitting permitted')


def export_rows(out, accepted):
    import pandas as pd
    labels, _ = collect(out/'runs')
    (out/'labels.json').write_text(json.dumps(labels,indent=2)+'\n')
    paths = {p.stem:p for p in export(out/'runs',out/'labels.json',out/'features-csv')}
    frames, coverage = {}, []
    for job in accepted:
        uid=job['run_id'];run=out/'runs'/uid
        attempts=[a for a in read_attempts(run) if job['workload']=='benign' or a['phase']=='measured']
        ids=[a['request_id'] for a in attempts if a.get('request_id')]
        if len(ids)!=len(set(ids)):raise ValueError('duplicate client request IDs')
        frame=pd.read_csv(paths[uid])
        if frame.request_id.duplicated().any():raise ValueError('duplicate feature request IDs')
        frame=frame[frame.request_id.isin(set(ids))]
        fraction=len(frame)/len(attempts) if attempts else 0
        if fraction<.98:raise ValueError('request-ID coverage below 98%')
        frames[uid]=frame
        coverage.append(dict(run_id=uid,attempts=len(attempts),joined=len(frame),coverage=fraction,
                             unknown=sum(a['outcome'] in ['unknown','error','timeout'] for a in attempts)))
    (out/'join_coverage.json').write_text(json.dumps(coverage,indent=2)+'\n')
    return frames


def acceptance(model, csv_path):
    import numpy as np
    import pandas as pd
    from waf.scoring import Scorer
    from ml.evaluate import classification_metrics
    scorer=Scorer(model);frame=pd.read_csv(csv_path)
    used=set(scorer.manifest['training_runs']+scorer.manifest['calibration_runs'])
    if used & set(frame.run_id):raise ValueError('test leakage')
    scores=scorer.score_many(frame[scorer.features].to_dict('records'))
    truth=(frame.label=='attack').to_numpy();predicted=np.array(scores)<scorer.threshold
    result=classification_metrics(truth,predicted)
    result['by_run']={str(run):classification_metrics(truth[ix],predicted[ix])
                      for run,ix in frame.groupby('run_id').indices.items()}
    result['model_sha256']=hashlib.sha256(Path(model).read_bytes()).hexdigest()
    return result


def main():
    import pandas as pd
    from ml.train import train
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True);parser.add_argument('--redis-url',required=True)
    args=parser.parse_args();out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    planned=jobs();(out/'planned.json').write_text(json.dumps(planned,indent=2)+'\n')
    accepted=[]
    for job in planned:
        if job['split']=='test':continue
        accepted.append(capture(job,out,args.redis_url))
        (out/'index.json').write_text(json.dumps(accepted,indent=2)+'\n')
        print(f'VALID {accepted[-1]["run_id"]} ({len(accepted)}/21)',flush=True)
    frames=export_rows(out,accepted)
    pd.concat(list(frames.values()),ignore_index=True).to_csv(out/'benign.csv',index=False)
    # Resolve actual replacement IDs for benign splits; tests have no retries yet.
    splits={'benign_fit':[j['run_id'] for j in accepted if j['split']=='fit'],
            'benign_calibration':[j['run_id'] for j in accepted if j['split']=='calibration'],
            'test':[j['run_id'] for j in planned if j['split']=='test']}
    (out/'splits.json').write_text(json.dumps(splits,indent=2)+'\n')
    candidate=out/'candidate.joblib'
    manifest=train(out/'benign.csv',candidate,splits_path=out/'splits.json',feature_set='volume',calibration_percentile=5)
    frozen={'manifest':manifest,'model_sha256':hashlib.sha256(candidate.read_bytes()).hexdigest(),
            'test_metrics_opened':False}
    (out/'frozen.json').write_text(json.dumps(frozen,indent=2)+'\n')
    print('FROZEN '+frozen['model_sha256'],flush=True)
    for job in planned:
        if job['split']!='test':continue
        accepted.append(capture(job,out,args.redis_url))
        (out/'index.json').write_text(json.dumps(accepted,indent=2)+'\n')
        print(f'VALID {accepted[-1]["run_id"]} ({len(accepted)}/21)',flush=True)
    frames=export_rows(out,accepted)
    pd.concat([frames[j['run_id']] for j in accepted if j['split']=='test'],ignore_index=True).to_csv(out/'test.csv',index=False)
    models={name:acceptance(model,out/'test.csv') for name,model in
            [('original',ROOT/'ml/artifacts/model_base_agent_v3.joblib'),('candidate',candidate)]}
    c=models['candidate'];passed=(c['recall']>=.2 and c['precision']>=.9 and c['false_positive_rate']<=.1
        and all(v['recall']>0 for k,v in c['by_run'].items() if v['recall'] is not None))
    result={'models':models,'offline_gate_passed':passed,'deployed':False,
            'test_sha256':hashlib.sha256((out/'test.csv').read_bytes()).hexdigest(),
            'bars':{'recall':.2,'precision':.9,'maximum_benign_flag_rate':.1}}
    (out/'evaluation.json').write_text(json.dumps(result,indent=2)+'\n')
    print('OFFLINE_GATE '+str(passed),flush=True)


if __name__=='__main__':main()
