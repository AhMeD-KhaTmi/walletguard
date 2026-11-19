import asyncio
from dataclasses import replace
import json
from types import SimpleNamespace
import httpx
import pytest
from app.main import create_app
from app.settings import Settings
from common.pricing import cost_microusd,reserve_microusd
from conftest import TEST_REDIS_URL
from scripts.reset_state import reset
from scripts.run_followup_calibration import peak
from test_account_wallet_remedies import client,setup_app
from waf.buckets import SPEND_INIT_LUA,SpendLedger
from waf.config import Config


async def auth(c,n=1):
    r=await c.post('/login',json={'username':f'user{n}','password':f'Passw0rd!{n}'})
    assert r.status_code==200
    return {'authorization':'Bearer '+r.json()['token']}


def initialize(r,period='unit',cap=1000):
    assert r.eval(SPEND_INIT_LUA,1,'p20:spend:'+period,cap)==1


async def test_large_jobs_cannot_use_small_lane(redis_db,llm_url):
    app=await setup_app(llm_url,wallet_capacity=300,wallet_refill_per_s=.002,wallet_small_capacity=100,wallet_small_refill_per_s=.001,wallet_small_task_max=50)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        headers=await auth(c)
        large={'prompt':'hi','max_output_tokens':199,'agent_steps':1}
        assert (await c.post('/chat',headers=headers,json=large)).status_code==200
        assert (await c.post('/chat',headers=headers,json=large)).json()['error']=='wallet_tok'
        assert (await c.post('/chat',headers=headers,json={'prompt':'hi','max_output_tokens':49,'agent_steps':1})).status_code==200
        assert float(redis_db.hget('p20:bkt:wallet:small','tokens'))<51
        assert float(redis_db.hget('p20:bkt:wallet:general','tokens'))<1
        assert not redis_db.keys('p20:ban:*')


async def test_size_lane_known_refunds_go_to_owner(redis_db,llm_url):
    app=await setup_app(llm_url,wallet_capacity=300,wallet_refill_per_s=.002,wallet_small_capacity=100,wallet_small_refill_per_s=.001,wallet_small_task_max=50)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        headers=await auth(c)
        async def short(scope,receive,send):
            scope['p20.generation']='completed';scope['p20.usage']=SimpleNamespace(tokens_in=1,tokens_out=3)
            await send({'type':'http.response.start','status':200,'headers':[]});await send({'type':'http.response.body','body':b'{}'})
        app.state.runtime.waf.app=short
        assert (await c.post('/chat',headers=headers,json={'prompt':'hi','max_output_tokens':49,'agent_steps':1})).status_code==200
        assert 95.9<float(redis_db.hget('p20:bkt:wallet:small','tokens'))<96.1
        assert not redis_db.exists('p20:bkt:wallet:general')


async def test_items_charge_clamped_page_size_without_ban(redis_db,llm_url):
    app=await setup_app(llm_url,products_capacity=100,products_refill_per_s=.001)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        assert (await c.get('/products?per_page=100000')).status_code==200
        for _ in range(7):
            r=await c.get('/products?per_page=20');assert r.status_code==429 and r.json()['error']=='products_items' and int(r.headers['retry-after'])>0
        assert not redis_db.keys('p20:strike:ip_budget:*') and not redis_db.keys('p20:ban:*')
        assert (await c.get('/products?per_page=100.0')).status_code==429
        assert (await c.get('/products?per_page=bad')).status_code==422
        assert (await c.get('/products?per_page=10&page=bad')).status_code==422


async def test_fitted_burst_does_not_remove_sustained_ip_ban(redis_db,llm_url):
    b=Config().budgets;app=await setup_app(llm_url,budgets={**b,'ip_req':(60,.001)})
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        for _ in range(42):assert (await c.get('/products')).status_code==200
        for _ in range(25):await c.get('/products')
        assert (await c.get('/products')).status_code==403
        assert json.loads(redis_db.get('p20:ban:10.20.0.11'))['reason']=='budget'


async def test_cap_reserves_across_accounts_and_never_refills(redis_db,llm_url):
    initialize(redis_db,cap=1518);app=await setup_app(llm_url,spend_period='unit',spend_cap_microusd=1518)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as a,client(app,'10.20.0.12') as b:
        aa=await auth(a);bb=await auth(b,2);body={'prompt':'hi','max_output_tokens':100,'agent_steps':1}
        assert (await a.post('/chat',headers=aa,json=body)).status_code==200
        assert (await b.post('/chat',headers=bb,json=body)).json()['error']=='spend_cap'
        assert int(redis_db.hget('p20:spend:unit','used'))==1503
        assert redis_db.ttl('p20:spend:unit')==-1
        assert not redis_db.keys('p20:ban:*')


async def test_cap_concurrent_admission_and_idempotent_refund(redis_db,llm_url):
    initialize(redis_db,cap=1518);app=await setup_app(llm_url,spend_period='unit',spend_cap_microusd=1518)
    async with app.router.lifespan_context(app):
        async def call(n):
            async with client(app,f'10.20.0.{10+n}') as c:
                a=await auth(c,n);return (await c.post('/chat',headers=a,json={'prompt':'hi','max_output_tokens':100,'agent_steps':1})).status_code
        assert sorted(await asyncio.gather(*(call(n) for n in range(1,5))))==[200,429,429,429]
        ledger=SpendLedger(app.state.runtime)
        assert (await ledger.reserve('p20:spend:unit',1518,15,'stable'))[0]==1
        assert (await ledger.reserve('p20:spend:unit',1518,15,'stable'))[0]==1
        assert await ledger.finish('p20:spend:unit','stable',3)==12
        assert await ledger.finish('p20:spend:unit','stable',3)==0
        assert int(redis_db.hget('p20:spend:unit','used'))==1506


async def test_cap_missing_and_policy_mismatch_do_not_create_money(redis_db,llm_url):
    app=await setup_app(llm_url,spend_period='unit',spend_cap_microusd=2000)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        a=await auth(c);body={'prompt':'hi','max_output_tokens':8,'agent_steps':1}
        assert (await c.post('/chat',headers=a,json=body)).status_code==503
        initialize(redis_db,cap=1000)
        assert (await c.post('/chat',headers=a,json=body)).status_code==503
        assert int(redis_db.hget('p20:spend:unit','used'))==0
        assert not redis_db.keys('p20:app:usage:*')


async def test_cap_uncertain_retains_reservation(redis_db,llm_url):
    initialize(redis_db);app=await setup_app(llm_url,spend_period='unit',spend_cap_microusd=1000)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        a=await auth(c)
        async def uncertain(scope,receive,send):
            scope['p20.generation']='started'
            await send({'type':'http.response.start','status':504,'headers':[]});await send({'type':'http.response.body','body':b''})
        app.state.runtime.waf.app=uncertain
        assert (await c.post('/chat',headers=a,json={'prompt':'hi','max_output_tokens':8,'agent_steps':1})).status_code==504
        assert int(redis_db.hget('p20:spend:unit','used'))==123
        assert redis_db.xrevrange('p20:app:spend_audit',count=1)[0][1]['uncertain']=='1'


async def test_cap_survives_runtime_reset_and_new_app(redis_db,llm_url):
    initialize(redis_db);app=await setup_app(llm_url,spend_period='unit',spend_cap_microusd=1000)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        a=await auth(c);assert (await c.post('/chat',headers=a,json={'prompt':'hi','max_output_tokens':8,'agent_steps':1})).status_code==200
    reset(redis_db);assert int(redis_db.hget('p20:spend:unit','used'))==123
    assert redis_db.eval(SPEND_INIT_LUA,1,'p20:spend:unit',1000)==0
    assert redis_db.eval(SPEND_INIT_LUA,1,'p20:spend:unit',2000)==-1
    other=await setup_app(llm_url,spend_period='unit',spend_cap_microusd=1000,run_id='new_api_run')
    async with other.router.lifespan_context(other),client(other,'10.20.0.11') as c:
        a=await auth(c);assert (await c.post('/chat',headers=a,json={'prompt':'hi','max_output_tokens':8,'agent_steps':1})).status_code==200
    assert int(redis_db.hget('p20:spend:unit','used'))==246


def test_optional_policy_validation_and_exact_prices():
    assert reserve_microusd('hi',8,1)==cost_microusd(1,8)==123
    assert peak([(0,20),(500,30),(1000,50)],1000)==80
    for kwargs in [dict(products_capacity=1,products_refill_per_s=0),dict(wallet_small_capacity=100),dict(spend_cap_microusd=1),dict(spend_period='../bad',spend_cap_microusd=1),dict(spend_cap_microusd=2**53,spend_period='x')]:
        with pytest.raises(ValueError):Config(**kwargs)


async def test_cap_known_short_usage_refunds_money_and_both_lanes(redis_db,llm_url):
    initialize(redis_db);app=await setup_app(llm_url,spend_period='unit',spend_cap_microusd=1000,wallet_capacity=300,wallet_refill_per_s=.002,wallet_small_capacity=100,wallet_small_refill_per_s=.001,wallet_small_task_max=50)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        a=await auth(c)
        async def short(scope,receive,send):
            scope['p20.generation']='completed';scope['p20.usage']=SimpleNamespace(tokens_in=1,tokens_out=3)
            await send({'type':'http.response.start','status':200,'headers':[]});await send({'type':'http.response.body','body':b'{}'})
        app.state.runtime.waf.app=short
        assert (await c.post('/chat',headers=a,json={'prompt':'hi','max_output_tokens':8,'agent_steps':1})).status_code==200
        assert int(redis_db.hget('p20:spend:unit','used'))==48
        assert 95.9<float(redis_db.hget('p20:bkt:wallet:small','tokens'))<96.1
        assert float(redis_db.hget('p20:bkt:llm_tok:user1','tokens'))>39995


from test_real_outage import disposable_redis


async def test_optional_hard_cap_refuses_unknown_money_during_redis_loss(disposable_redis,llm_url):
    import redis as sync_redis
    url,start=disposable_redis;process=start()
    with sync_redis.Redis.from_url(url) as r:r.eval(SPEND_INIT_LUA,1,'p20:spend:unit',1000)
    cfg=Config(mode='enforce',redis_url=url,spend_period='unit',spend_cap_microusd=1000)
    app=create_app(Settings(redis_url=url,llm_base_url=llm_url,waf_mode='enforce'),cfg)
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        a=await auth(c);body={'prompt':'hi','max_output_tokens':8,'agent_steps':1}
        assert (await c.post('/chat',headers=a,json=body)).status_code==200
        assert (await c.get('/products')).status_code==200
        process.terminate();process.wait(timeout=5)
        assert (await c.post('/chat',headers=a,json=body)).status_code==503
        assert (await c.get('/products')).status_code==200
        process=start()  # Redis lost the durable authority: no implicit new period.
        a=await auth(c)
        assert (await c.post('/chat',headers=a,json=body)).status_code==503
        assert not await app.state.runtime.r.exists('p20:spend:unit')


def test_retry_delay_is_finite_positive_and_only_for_429():
    from scripts.followup_retry import retry_delay
    for status,value,want in [(429,'2',2),(429,'nan',0),(429,'-1',0),(429,'bad',0),(200,'3',0)]:
        assert retry_delay(SimpleNamespace(status_code=status,headers={'Retry-After':value}))==want


async def test_cap_reservation_refunded_when_anomaly_bans_before_forward(redis_db,llm_url):
    initialize(redis_db);app=await setup_app(llm_url,spend_period='unit',spend_cap_microusd=1000)
    class Anomalous:
        def score(self,features):return -1
        def is_anomalous(self,score):return True
    app.state.runtime.scorer=Anomalous()
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        for _ in range(5):assert (await c.get('/products')).status_code==200
        a=await auth(c)
        await app.state.runtime.waf.bans.strike('10.20.0.11','ip_budget')
        assert (await c.post('/chat',headers=a,json={'prompt':'hi','max_output_tokens':8,'agent_steps':1})).status_code==403
        assert int(redis_db.hget('p20:spend:unit','used'))==0
        assert not redis_db.hget('p20:app:usage:total','tokens_out')


async def test_released_defaults_admit_fitted_burst_and_use_both_lanes(redis_db,llm_url,monkeypatch):
    for name in ['WAF_ACCOUNT_PRESSURE_BANS','WAF_IP_CAPACITY','WAF_WALLET_CAPACITY','WAF_WALLET_REFILL_PER_S','WAF_WALLET_SMALL_CAPACITY','WAF_WALLET_SMALL_REFILL_PER_S','WAF_WALLET_SMALL_TASK_MAX','WAF_PRODUCTS_CAPACITY','WAF_PRODUCTS_REFILL_PER_S','WAF_SPEND_CAP_MICROUSD','WAF_SPEND_PERIOD','WAF_ML']:
        monkeypatch.delenv(name,raising=False)
    app=create_app(Settings(redis_url=TEST_REDIS_URL,llm_base_url=llm_url,waf_mode='enforce'))
    async with app.router.lifespan_context(app),client(app,'10.20.0.11') as c:
        a=await auth(c)
        for _ in range(42):assert (await c.get('/products?per_page=20')).status_code==200
        for output,steps in [(49,1),(500,3)]:
            assert (await c.post('/chat',headers=a,json={'prompt':'hi','max_output_tokens':output,'agent_steps':steps})).status_code==200
        assert redis_db.exists('p20:bkt:wallet:small') and redis_db.exists('p20:bkt:wallet:general')
        assert redis_db.exists('p20:bkt:products:10.20.0.11')
        assert not redis_db.keys('p20:spend:*') and not redis_db.keys('p20:ban:*')
