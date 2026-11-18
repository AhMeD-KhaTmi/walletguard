"""Fixed fresh robustness cases; dependency-free policy-independent definitions."""
MODEL_SHA256='1eb84211004b6abe42cd2b8ec03e4b06b8504884ad0a8b9c1ca81ce2f55829e3'
CASES={
 'slow_mixed':dict(workload='mixed',seconds=72,users=14),
 'distributed':dict(workload='combined',seconds=60,users=14),
 'shared_account':dict(workload='benign',seconds=36,users=5),
 'burst_within':dict(workload='benign',seconds=30,users=10),
 'burst_above':dict(workload='benign',seconds=50,users=10),
}


def worker_plan(profile,role,ns,user_index=0,accounts=()):
    number=int(ns.removeprefix('ns'))
    if role=='benign':
        account='user1' if profile=='shared_account' else list(accounts)[user_index%len(accounts)]
        return dict(account=account,period_s=2.0 if profile=='shared_account' else 24.0 if profile=='burst_above' else 12.0 if profile=='burst_within' else 2.4,
                    phase_s=0.0,reads=20 if profile=='burst_above' else 8 if profile=='burst_within' else 1)
    if role=='credential_stuffing':
        return dict(account=None,period_s=13.0 if profile=='distributed' else 15.0,phase_s=0.0,rank=number-1 if profile=='distributed' else number-6)
    if role=='scraping':
        return dict(account=None,period_s=.6 if profile=='distributed' else 1.5,phase_s=0.0,
                    rank=number-6 if profile=='distributed' else number-9,sources=5 if profile=='distributed' else 3)
    if role=='dow':
        rank=number-11 if profile=='distributed' else number-12
        return dict(account=f'user{46+rank}' if profile=='distributed' else 'user50',
                    period_s=3.0 if profile=='distributed' else 45.0,
                    phase_s=0.0 if profile=='distributed' else rank*15.0,
                    steps=3 if profile=='distributed' else 8,output=900,
                    prompt_words=100 if profile=='distributed' else 120)
    raise ValueError('unsupported role')


def credential_target(profile,rank,ordinal):
    pool=list(range(20,40)) if profile=='distributed' else [n for n in range(30,50) if n not in {31,41}]
    sources=5 if profile=='distributed' else 3
    number=pool[(ordinal*sources+rank)%len(pool)]
    return f'user{number}'


def scale_plan(plan,scale=1.0):
    if scale not in {1.0,.1}:raise ValueError('only fixed smoke or measurement timing is allowed')
    return {**plan,'period_s':plan['period_s']*scale,'phase_s':plan['phase_s']*scale}
