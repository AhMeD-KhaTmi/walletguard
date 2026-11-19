"""B-owned experimental variants around the unchanged A evaluation harness."""
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
from scripts import budget_harness
from scripts.robustness_cases import worker_plan


def main():
    p=argparse.ArgumentParser(add_help=False);p.add_argument('--profile',required=True,choices=['fair_mixed','varied','burst_fixed','burst_retry','distributed','slow','spend','fast','combined_burst']);p.add_argument('--variant',required=True,choices=['current','pooled','lanes','resource','cap','combined']);p.add_argument('--policy',type=Path,required=True);p.add_argument('--smoke-only',action='store_true');a,rest=p.parse_known_args()
    policy=json.loads(a.policy.read_text());uid=rest[rest.index('--run-id')+1];variant=a.variant
    env=dict(WAF_ACCOUNT_PRESSURE_BANS='0',WAF_WALLET_CAPACITY='0',WAF_WALLET_REFILL_PER_S='0',WAF_WALLET_SMALL_CAPACITY='0',WAF_WALLET_SMALL_REFILL_PER_S='0',WAF_WALLET_SMALL_TASK_MAX='0',WAF_PRODUCTS_CAPACITY='0',WAF_PRODUCTS_REFILL_PER_S='0',WAF_SPEND_CAP_MICROUSD='0',WAF_SPEND_PERIOD='',WAF_IP_CAPACITY='30',P20_SAFE_DRIVER='1')
    if variant in ['pooled','lanes','combined']:
        env.update(WAF_WALLET_CAPACITY=str(policy['wallet_capacity']),WAF_WALLET_REFILL_PER_S=str(policy['wallet_refill_per_s']))
        if variant in ['lanes','combined']:env.update(WAF_WALLET_SMALL_CAPACITY=str(policy['lanes']['small']['capacity']),WAF_WALLET_SMALL_REFILL_PER_S=str(policy['lanes']['small']['refill_per_s']),WAF_WALLET_SMALL_TASK_MAX='2048')
    if variant in ['resource','combined']:env.update(WAF_IP_CAPACITY=str(policy['ip_capacity']),WAF_PRODUCTS_CAPACITY=str(policy['products_capacity']),WAF_PRODUCTS_REFILL_PER_S=str(policy['products_refill_per_s']))
    if variant=='cap':env.update(WAF_SPEND_CAP_MICROUSD='1000000',WAF_SPEND_PERIOD=uid)
    os.environ.update(env)
    original_command=harness.workload_command;original_metadata=harness.workload_metadata
    shapes=dict(fair_mixed='distributed',burst_fixed='burst_above',burst_retry='burst_above',distributed='distributed',slow='slow_mixed',spend='distributed',combined_burst='distributed')
    shape_for=lambda role:'burst_above' if a.profile=='combined_burst' and role=='benign' else shapes[a.profile]
    if a.profile in shapes:
        shape=shapes[a.profile];workload=rest[rest.index('--workload')+1]
        script='scripts/followup_retry_workload.py' if a.profile=='burst_retry' else 'scripts/robustness_workload.py'
        harness.WORKLOADS={**harness.WORKLOADS,workload:(script,15,None)};harness.SETUP_GATED_WORKLOADS=set(harness.SETUP_GATED_WORKLOADS)|{workload}
        identity=('scripts/remedy_mixed_identities.json' if a.profile in ['fair_mixed','combined_burst'] else 'scripts/robustness_identities/distributed.json' if a.profile in ['distributed','spend'] else None)
        if identity:rest=['--identities',str(ROOT/identity),*rest]
        def command(args,entry,run_dir):
            argv,child,log=original_command(args,entry,run_dir);child.update(P20_ROBUST_PROFILE=shape_for(entry['role']),P20_ROLE=entry['role'],P20_ROBUST_TIME_SCALE='1');return argv,child,log
        harness.workload_command=command
    def metadata(args):
        workers=({i['ip']:[worker_plan(shape_for(i['role']),i['role'],i['ns'],n,i.get('accounts',())) for n in range(max(1,args.users//len(identities.identities_for(args.data,args.workload))))] for i in identities.identities_for(args.data,args.workload)} if a.profile in shapes else {})
        return {**original_metadata(args),'followup':dict(profile=a.profile,variant=variant,smoke_only=a.smoke_only,policy_sha256=hashlib.sha256(a.policy.read_bytes()).hexdigest(),env=env,workers=workers,helper_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in ['scripts/followup_harness.py','scripts/followup_retry_workload.py','scripts/followup_retry.py','scripts/robustness_workload.py','scripts/robustness_cases.py','common/pricing.py']})}
    harness.workload_metadata=metadata
    sys.argv=[sys.argv[0],'--agent-scenario','varied' if a.profile=='varied' else 'normal',*rest];result=budget_harness.main()
    run=Path(rest[rest.index('--runs')+1])/uid
    with redis.Redis.from_url(rest[rest.index('--redis-url')+1],decode_responses=True,socket_timeout=2) as r:
        for key,name in [('p20:app:wallet_audit','wallet_audit.jsonl'),('p20:app:spend_audit','spend_audit.jsonl')]:
            (run/name).write_text(''.join(json.dumps(v)+'\n' for _,v in r.xrange(key)))
        (run/'spend_ledger.json').write_text(json.dumps(r.hgetall('p20:spend:'+uid),indent=2)+'\n')
        (run/'private_buckets.json').write_text(json.dumps({k:r.hgetall(k) for k in r.scan_iter('p20:bkt:*') if ':products:' in k or ':wallet:' in k},indent=2)+'\n')
    return result

if __name__=='__main__':raise SystemExit(main())
