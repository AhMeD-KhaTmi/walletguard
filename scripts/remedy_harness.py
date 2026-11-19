"""Recorded remedy variants and private audit capture; A-owned harness is unchanged."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))
import redis
from eval import harness,identities
from scripts import budget_harness,robustness_harness
from scripts.robustness_cases import worker_plan


def main():
    p=argparse.ArgumentParser(add_help=False)
    p.add_argument('--remedy-profile',choices=['normal','varied','shared_account','distributed','burst_within','fast_scraping','wallet_mixed'],required=True)
    p.add_argument('--policy-variant',choices=['legacy','remedy'],required=True)
    p.add_argument('--global-policy',type=Path)
    p.add_argument('--remedy-smoke',action='store_true')
    a,rest=p.parse_known_args();candidate=a.policy_variant=='remedy';policy=None
    if candidate:
        if a.global_policy is None:raise ValueError('frozen global policy required')
        policy=json.loads(a.global_policy.read_text())['candidate']
    os.environ.update(WAF_ACCOUNT_PRESSURE_BANS='0' if candidate else '1',
                      WAF_WALLET_SMALL_CAPACITY='0',WAF_WALLET_SMALL_REFILL_PER_S='0',WAF_WALLET_SMALL_TASK_MAX='0',
                      WAF_PRODUCTS_CAPACITY='0',WAF_PRODUCTS_REFILL_PER_S='0',WAF_IP_CAPACITY='30',
                      WAF_SPEND_CAP_MICROUSD='0',WAF_SPEND_PERIOD='',
                      WAF_WALLET_CAPACITY=str(policy['capacity'] if policy else 0),
                      WAF_WALLET_REFILL_PER_S=str(policy['refill_per_s'] if policy else 0),P20_SAFE_DRIVER='1')
    original=harness.workload_metadata
    def metadata(args):
        result={**original(args),'remedy':dict(profile=a.remedy_profile,variant=a.policy_variant,
             account_pressure_bans=not candidate,wallet=policy,smoke_only=a.remedy_smoke,
             policy_sha256=hashlib.sha256(a.global_policy.read_bytes()).hexdigest() if a.global_policy else None)}
        if a.remedy_profile=='wallet_mixed':
            result['mixed_contention_source_sha256']={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
                for name in ['scripts/remedy_mixed_identities.json','scripts/robustness_cases.py','scripts/robustness_workload.py']}
            result['mixed_contention_workers']={e['ip']:worker_plan('distributed',e['role'],e['ns'],0,e.get('accounts',()))
                                                for e in identities.identities_for(args.data,args.workload)}
        return result
    harness.workload_metadata=metadata
    if a.remedy_profile=='wallet_mixed':
        original_command=harness.workload_command
        def command(args,entry,run_dir):
            argv,env,log=original_command(args,entry,run_dir)
            env.update(P20_ROBUST_PROFILE='distributed',P20_ROLE=entry['role'],P20_ROBUST_TIME_SCALE='1')
            return argv,env,log
        harness.workload_command=command
        harness.WORKLOADS={**harness.WORKLOADS,'mixed':('scripts/robustness_workload.py',15,None)}
        harness.SETUP_GATED_WORKLOADS=set(harness.SETUP_GATED_WORKLOADS)|{'mixed'}
        rest=['--identities',str(ROOT/'scripts/remedy_mixed_identities.json'),'--agent-scenario','normal',*rest]
        delegate=budget_harness.main
    elif a.remedy_profile in ['shared_account','distributed','burst_within']:
        delegate=robustness_harness.main
        rest=['--robust-profile',a.remedy_profile,*(['--robust-smoke'] if a.remedy_smoke else []),*rest]
    else:
        delegate=budget_harness.main
        rest=['--agent-scenario','varied' if a.remedy_profile=='varied' else 'normal',*rest]
    sys.argv=[sys.argv[0],*rest];result=delegate()
    rurl=rest[rest.index('--redis-url')+1];runs=Path(rest[rest.index('--runs')+1]);uid=rest[rest.index('--run-id')+1]
    run=ROOT/runs/uid
    with redis.Redis.from_url(rurl,decode_responses=True,socket_timeout=2) as r:
        audit=[row for _,row in r.xrange('p20:app:wallet_audit')]
        (run/'wallet_audit.jsonl').write_text(''.join(json.dumps(v)+'\n' for v in audit))
        (run/'wallet_bucket.json').write_text(json.dumps(r.hgetall('p20:bkt:wallet:global'),indent=2)+'\n')
    return result

if __name__=='__main__':raise SystemExit(main())
