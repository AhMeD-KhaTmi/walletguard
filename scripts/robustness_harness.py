"""Explicit profile/identity adapter around B's adapter and A's read-only harness."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))
from scripts import budget_harness
from scripts.robustness_cases import CASES,worker_plan,scale_plan
from eval import harness,identities


def main():
    p=argparse.ArgumentParser(add_help=False);p.add_argument('--robust-profile',choices=CASES,required=True)
    p.add_argument('--robust-smoke',action='store_true')
    opts,remainder=p.parse_known_args();profile=opts.robust_profile;spec=CASES[profile]
    if '--identities' in remainder:raise ValueError('profile owns its declared identity map')
    if '--workload' not in remainder or remainder[remainder.index('--workload')+1]!=spec['workload']:
        raise ValueError('workload must match predeclared robustness profile')
    os.environ['P20_SAFE_DRIVER']='1'
    harness.WORKLOADS={**harness.WORKLOADS,spec['workload']:('scripts/robustness_workload.py',spec['users'],None)}
    harness.SETUP_GATED_WORKLOADS=set(harness.SETUP_GATED_WORKLOADS)|{spec['workload']}
    if profile in {'distributed','shared_account'}:
        remainder=['--identities',str(ROOT/'scripts/robustness_identities'/f'{profile}.json'),*remainder]
    base_command=harness.workload_command;base_metadata=harness.workload_metadata
    def command(args,entry,run_dir):
        argv,env,log=base_command(args,entry,run_dir)
        env.update(P20_ROBUST_PROFILE=profile,P20_ROLE=entry['role'],P20_ROBUST_TIME_SCALE='.1' if opts.robust_smoke else '1')
        return argv,env,log
    def metadata(args):
        expected=identities.identities_for(args.data,args.workload)
        users=max(1,args.users//len(expected))
        plans={e['ip']:[scale_plan(worker_plan(profile,e['role'],e['ns'],i,e.get('accounts',())),.1 if opts.robust_smoke else 1.0) for i in range(users)] for e in expected}
        helpers={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in
                 ['scripts/robustness_cases.py','scripts/robustness_workload.py','scripts/robustness_harness.py']}
        return {**base_metadata(args),'robustness':{'profile':profile,'specification':spec,'smoke_only':opts.robust_smoke,'time_scale':.1 if opts.robust_smoke else 1.0,
                    'workers':plans,'helper_sha256':helpers,
                    'setup_strategy':'all users ready at common measured gate; only authenticated roles log in',
                    'credential_source':'synthetic demo pairs, known-valid one in four; separate from original credential list'}}
    harness.workload_command=command;harness.workload_metadata=metadata
    sys.argv=[sys.argv[0],*remainder];return budget_harness.main()

if __name__=='__main__':raise SystemExit(main())
