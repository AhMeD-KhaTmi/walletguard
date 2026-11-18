import asyncio
import json
from dataclasses import replace

import httpx
import pytest
import redis.asyncio as aioredis

from app.main import create_app
from app.settings import Settings
from conftest import TEST_REDIS_URL
from waf.config import Config


def client(app,ip):
    return httpx.AsyncClient(base_url='http://target',transport=httpx.ASGITransport(app=app,client=(ip,1234)))


async def setup_app(llm_url,**options):
    options.setdefault('account_pressure_bans',False)
    cfg=Config(mode='enforce',redis_url=TEST_REDIS_URL,**options)
    return create_app(Settings(redis_url=TEST_REDIS_URL,llm_base_url=llm_url,waf_mode='enforce'),cfg)


async def test_account_login_pressure_does_not_ban_or_corroborate(redis_db,llm_url):
    app=await setup_app(llm_url)
    async with app.router.lifespan_context(app):
        for n in range(5):
            async with client(app,f'10.20.0.{10+n}') as c:
                assert (await c.post('/login',json={'username':'user1','password':'wrong'})).status_code==401
        for n in range(7):
            ip=f'10.20.0.{25+n}'
            async with client(app,ip) as c:
                response=await c.post('/login',json={'username':'user1','password':'wrong'})
                assert response.status_code==429 and response.json()['error']=='login_acct'
                assert not await app.state.runtime.waf.bans.has_budget_strike(ip)
                assert not await app.state.runtime.waf.bans.has_budget_strike(ip,'ip_budget')
                assert (await c.get('/products')).status_code==200



async def test_shared_chat_quota_keeps_browsing_and_refuses_ip_ban(redis_db,llm_url):
    base=Config();budgets={**base.budgets,'chat_req':(1,.001)}
    app=await setup_app(llm_url,budgets=budgets)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        login=await c.post('/login',json={'username':'user1','password':'Passw0rd!1'})
        auth={'authorization':'Bearer '+login.json()['token']}
        body={'prompt':'hello','agent_steps':1,'max_output_tokens':8}
        assert (await c.post('/chat',headers=auth,json=body)).status_code==200
        for _ in range(7):
            r=await c.post('/chat',headers=auth,json=body)
            assert r.status_code==429 and r.json()['error']=='chat_req'
        assert not await app.state.runtime.waf.bans.has_budget_strike('10.20.0.11')
        assert not await app.state.runtime.waf.bans.has_budget_strike('10.20.0.11','ip_budget')
        assert (await c.get('/products')).status_code==200
        assert not redis_db.exists('p20:ban:10.20.0.11')


@pytest.mark.parametrize('account_pressure_bans',[False,True])
async def test_global_reservation_spans_accounts_and_refunds_rejected_account(redis_db,llm_url,account_pressure_bans):
    app=await setup_app(llm_url,wallet_capacity=150,wallet_refill_per_s=.001,account_pressure_bans=account_pressure_bans)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as a,client(app,'10.20.0.12') as b:
        auth=[]
        for n,c in enumerate([a,b],1):
            r=await c.post('/login',json={'username':f'user{n}','password':f'Passw0rd!{n}'})
            auth.append({'authorization':'Bearer '+r.json()['token']})
        body={'prompt':'hi','max_output_tokens':100,'agent_steps':1}
        assert (await a.post('/chat',headers=auth[0],json=body)).status_code==200
        for _ in range(7):
            r=await b.post('/chat',headers=auth[1],json=body)
            assert r.status_code==429 and r.json()['error']=='wallet_tok'
        assert (await b.get('/products')).status_code==200
        assert not redis_db.exists('p20:ban:10.20.0.12')
        assert float(redis_db.hget('p20:bkt:llm_tok:user2','tokens'))>39999
        usage=await b.get('/_metrics/usage')
        assert int(redis_db.hget('p20:app:usage:total','tokens_out'))==100
        audit=[row for _,row in redis_db.xrange('p20:app:wallet_audit')]
        assert sum(float(r['charged']) for r in audit)==101


async def test_wallet_refund_on_downstream_validation_and_permanent_rejection(redis_db,llm_url):
    app=await setup_app(llm_url,wallet_capacity=150,wallet_refill_per_s=.001)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        r=await c.post('/login',json={'username':'user1','password':'Passw0rd!1'})
        auth={'authorization':'Bearer '+r.json()['token']}
        bad={'prompt':'hi','max_output_tokens':8,'agent_steps':1,'extra':'invalid'}
        # API forbids? Use injected downstream refusal independent of input-schema configuration.
        async def reject(scope,receive,send):
            await send({'type':'http.response.start','status':422,'headers':[]})
            await send({'type':'http.response.body','body':b''})
        original=app.state.runtime.waf.app;app.state.runtime.waf.app=reject
        try:assert (await c.post('/chat',headers=auth,json=bad)).status_code==422
        finally:app.state.runtime.waf.app=original
        assert float(redis_db.hget('p20:bkt:wallet:global','tokens'))>=149.9
        big=await c.post('/chat',headers=auth,json={'prompt':'hi','max_output_tokens':200,'agent_steps':1})
        assert big.status_code==400 and big.json()['error']=='wallet_task_exceeds_capacity'
        assert float(redis_db.hget('p20:bkt:llm_tok:user1','tokens'))>39999


def test_wallet_configuration_is_paired_and_finite():
    for options in [dict(wallet_capacity=1),dict(wallet_refill_per_s=1),dict(wallet_capacity=float('nan'))]:
        with pytest.raises(ValueError):Config(**options)


def test_qualified_account_default_legacy_replay_and_wallet_opt_in(monkeypatch):
    monkeypatch.delenv('WAF_ACCOUNT_PRESSURE_BANS',raising=False)
    monkeypatch.delenv('WAF_WALLET_CAPACITY',raising=False)
    monkeypatch.delenv('WAF_WALLET_REFILL_PER_S',raising=False)
    assert Config().account_pressure_bans is False
    current=Config.from_env(mode='enforce',redis_url=TEST_REDIS_URL)
    assert current.account_pressure_bans is False
    assert current.wallet_capacity==current.wallet_refill_per_s==0
    monkeypatch.setenv('WAF_ACCOUNT_PRESSURE_BANS','1')
    assert Config.from_env(mode='enforce',redis_url=TEST_REDIS_URL).account_pressure_bans is True
    monkeypatch.setenv('WAF_WALLET_CAPACITY','40000')
    monkeypatch.setenv('WAF_WALLET_REFILL_PER_S','5700')
    opt_in=Config.from_env(mode='enforce',redis_url=TEST_REDIS_URL)
    assert opt_in.wallet_capacity==40000 and opt_in.wallet_refill_per_s==5700


async def test_concurrent_wallet_admission_cannot_overspend(redis_db,llm_url):
    app=await setup_app(llm_url,wallet_capacity=150,wallet_refill_per_s=.001)
    async with app.router.lifespan_context(app):
        async def request(n):
            async with client(app,f'10.20.0.{10+n}') as c:
                r=await c.post('/login',json={'username':f'user{n}','password':f'Passw0rd!{n}'})
                return await c.post('/chat',headers={'authorization':'Bearer '+r.json()['token']},
                                    json={'prompt':'hi','max_output_tokens':100,'agent_steps':1})
        responses=await asyncio.gather(*(request(n) for n in range(1,5)))
        assert sorted(r.status_code for r in responses)==[200,429,429,429]
        assert int(redis_db.hget('p20:app:usage:total','tokens_out'))==100


from test_real_outage import disposable_redis


async def test_wallet_keeps_known_local_balance_and_conservative_recovery(disposable_redis,llm_url):
    url,start=disposable_redis;process=start()
    cfg=Config(mode='enforce',redis_url=url,account_pressure_bans=False,wallet_capacity=1000,wallet_refill_per_s=.001)
    app=create_app(Settings(redis_url=url,llm_base_url=llm_url,waf_mode='enforce'),cfg)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        login=await c.post('/login',json={'username':'user1','password':'Passw0rd!1'})
        auth={'authorization':'Bearer '+login.json()['token']};body={'prompt':'hi','max_output_tokens':8,'agent_steps':1}
        assert (await c.post('/chat',headers=auth,json=body)).status_code==200
        process.terminate();process.wait(timeout=5)
        assert (await c.post('/chat',headers=auth,json=body)).status_code==200
        await asyncio.sleep(.01)
        process=start()
        assert (await c.post('/chat',headers=auth,json=body)).status_code==401
        login=await c.post('/login',json={'username':'user1','password':'Passw0rd!1'})
        auth={'authorization':'Bearer '+login.json()['token']}
        assert (await c.post('/chat',headers=auth,json=body)).status_code==200
        balance=float(await app.state.runtime.r.hget('p20:bkt:wallet:global','tokens'))
        assert 972<=balance<974


async def test_legacy_account_strikes_cannot_corroborate_candidate_anomaly(redis_db,llm_url):
    class Anomalous:
        def score(self,row):return -1
        def is_anomalous(self,score):return True
    app=await setup_app(llm_url);app.state.runtime.scorer=Anomalous()
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        assert (await c.get('/products')).status_code==200  # ASGI builds middleware lazily.
        await app.state.runtime.waf.bans.strike('10.20.0.11','budget')
        for _ in range(6):assert (await c.get('/products')).status_code==200
        assert not redis_db.exists('p20:ban:10.20.0.11')
        await app.state.runtime.waf.bans.strike('10.20.0.11','ip_budget')
        assert (await c.get('/products')).status_code==403


async def test_candidate_still_bans_ip_login_abuse(redis_db,llm_url):
    app=await setup_app(llm_url)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        for _ in range(12):await c.post('/login',json={'username':'user1','password':'wrong'})
        assert (await c.get('/products')).status_code==403
        assert redis_db.exists('p20:strike:ip_budget:10.20.0.11')
        assert json.loads(redis_db.get('p20:ban:10.20.0.11'))['reason']=='budget'


async def test_uncertain_generation_retains_both_reservations(redis_db,llm_url):
    app=await setup_app(llm_url,wallet_capacity=150,wallet_refill_per_s=.001)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        login=await c.post('/login',json={'username':'user1','password':'Passw0rd!1'})
        auth={'authorization':'Bearer '+login.json()['token']}
        async def uncertain(scope,receive,send):
            scope['p20.generation']='uncertain'
            raise RuntimeError('generation outcome unknown')
        app.state.runtime.waf.app=uncertain
        with pytest.raises(RuntimeError,match='outcome unknown'):
            await c.post('/chat',headers=auth,json={'prompt':'hi','max_output_tokens':8,'agent_steps':1})
        assert 140<float(redis_db.hget('p20:bkt:wallet:global','tokens'))<142
        audit=redis_db.xrevrange('p20:app:wallet_audit',count=1)[0][1]
        assert audit['uncertain']=='1' and float(audit['refunded'])==0


def test_wallet_rule_uses_global_rolling_demand_not_max_account():
    from scripts.run_remedy_experiment import select_policy,jobs
    p=select_policy([[(0,10000),(500,20000),(1100,10000)]])
    assert p['capacity']==40000 and p['refill_per_s']==850
    assert p['peak_1s']==30000 and p['peak_60s']==40000
    assert len(jobs('validation'))==57
    with pytest.raises(ValueError):select_policy([])


async def test_known_short_generation_refunds_both_budgets(redis_db,llm_url):
    from types import SimpleNamespace
    app=await setup_app(llm_url,wallet_capacity=150,wallet_refill_per_s=.001)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        login=await c.post('/login',json={'username':'user1','password':'Passw0rd!1'})
        auth={'authorization':'Bearer '+login.json()['token']}
        async def short(scope,receive,send):
            scope['p20.generation']='completed'
            scope['p20.usage']=SimpleNamespace(tokens_in=1,tokens_out=3)
            await send({'type':'http.response.start','status':200,'headers':[]})
            await send({'type':'http.response.body','body':b'{}'})
        app.state.runtime.waf.app=short
        assert (await c.post('/chat',headers=auth,json={'prompt':'hi','max_output_tokens':8,'agent_steps':1})).status_code==200
        assert 145.9<float(redis_db.hget('p20:bkt:wallet:global','tokens'))<146.1
        audit=redis_db.xrevrange('p20:app:wallet_audit',count=1)[0][1]
        assert float(audit['reserved'])==9 and float(audit['refunded'])==5 and float(audit['charged'])==4


def test_mixed_contention_has_real_benign_and_four_disjoint_dow_accounts():
    from eval.identities import load,identities_for
    from scripts.robustness_cases import worker_plan
    data=load('scripts/remedy_mixed_identities.json');entries=identities_for(data,'mixed')
    assert len(entries)==15 and len({e['ip'] for e in entries})==15
    benign={worker_plan('distributed',e['role'],e['ns'],0,e.get('accounts',()))['account'] for e in entries if e['role']=='benign'}
    dow={worker_plan('distributed',e['role'],e['ns'],0)['account'] for e in entries if e['role']=='dow'}
    assert benign=={'user1','user11','user21','user31','user41'}
    assert dow=={'user47','user48','user49','user50'} and not benign & dow
