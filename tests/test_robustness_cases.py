import json
from pathlib import Path

import pytest

from common.agent import reserve_tokens
from eval.identities import load,identities_for,assert_allowlist_safe
from scripts.robustness_cases import CASES,worker_plan,credential_target,scale_plan
from waf.config import Config


def test_profiles_really_exercise_declared_policy_boundaries():
    # Historical robustness-v1 boundaries were defined against capacity30.
    cfg=Config(budgets={**Config().budgets,'ip_req':(30,2.)});ip_cap,ip_rate=cfg.budgets['ip_req'];tok_cap,tok_rate=cfg.budgets['llm_tok']
    slow=worker_plan('slow_mixed','dow','ns12')
    task=reserve_tokens(' '.join(['synthetic']*slow['prompt_words']),slow['output'],slow['steps'])
    assert task<tok_cap and 3*task/slow['period_s']<tok_rate
    phases=[worker_plan('slow_mixed','dow',f'ns{n}')['phase_s'] for n in [12,13,14]]
    assert phases==[0,15,30] and task/15<tok_rate
    distributed=worker_plan('distributed','dow','ns11')
    task=reserve_tokens(' '.join(['synthetic']*distributed['prompt_words']),distributed['output'],distributed['steps'])
    assert task/distributed['period_s']<tok_rate<4*task/distributed['period_s']
    shared=worker_plan('shared_account','benign','ns1',accounts=['user1'])
    assert 2/shared['period_s']<ip_rate
    assert 5/shared['period_s']>cfg.budgets['chat_req'][1]
    assert 5*reserve_tokens('synthetic '*10,120,3)/shared['period_s']<tok_rate
    within=worker_plan('burst_within','benign','ns1',accounts=['user1'])
    above=worker_plan('burst_above','benign','ns1',accounts=['user1'])
    assert 2*(within['reads']+1)<=ip_cap<2*(above['reads']+1)
    assert 2*(above['reads']+1)/above['period_s']<ip_rate
    # Three finite-window bursts fit initial-plus-refill total, but not capacity.
    assert 3*2*(above['reads']+1)<=ip_cap+ip_rate*CASES['burst_above']['seconds']
    assert 1/worker_plan('distributed','credential_stuffing','ns1')['period_s']<cfg.budgets['login_ip'][1]


def test_custom_identity_maps_are_valid_and_never_allowlisted():
    for name in ['shared_account','distributed']:
        data=load(Path('scripts/robustness_identities')/(name+'.json'))
        assert_allowlist_safe(data,set(data['management']['hosts']))
        entries=identities_for(data,CASES[name]['workload'])
        assert len(entries)==(5 if name=='shared_account' else 14)
        assert len({e['ip'] for e in entries})==len(entries)
    shared=load('scripts/robustness_identities/shared_account.json')
    assert all(e['accounts']==['user1'] for e in shared['benign'])


def test_credentials_and_accounts_remain_synthetic_and_role_separated():
    targets={credential_target('distributed',r,k) for r in range(5) for k in range(20)}
    assert targets=={f'user{i}' for i in range(20,40)}
    dow={worker_plan('distributed','dow',f'ns{n}')['account'] for n in range(11,15)}
    assert dow=={'user46','user47','user48','user49'} and not targets & dow
    slow={credential_target('slow_mixed',r,k) for r in range(3) for k in range(18)}
    assert not slow & {'user1','user11','user21','user31','user41','user50'}
    assert worker_plan('burst_within','benign','ns1',0,['user1','user2'])['account']!='user2'
    assert worker_plan('burst_within','benign','ns1',1,['user1','user2'])['account']=='user2'


def test_smoke_scaling_is_explicit_and_all_slow_sources_fit_window():
    for ns in ['ns12','ns13','ns14']:
        plan=worker_plan('slow_mixed','dow',ns)
        assert scale_plan(plan,.1)['phase_s']<8
        assert scale_plan(plan,1)==plan
    with pytest.raises(ValueError):scale_plan(plan,.5)
