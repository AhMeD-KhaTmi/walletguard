"""B-owned boundary workloads using A's unchanged client logger and classifiers."""
import os
from pathlib import Path
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import gevent
from locust import task
from locust.exception import StopUser
from eval.clientlog import classify_chat, classify_login, classify_products
from eval.workload import GatedUser, env_list, env_float
from scripts.robustness_cases import worker_plan, credential_target, scale_plan
from common.tokens import estimate_tokens

PROFILE=os.environ['P20_ROBUST_PROFILE']
ROLE=os.environ.get('P20_ROLE','benign')


class RobustUser(GatedUser):
    abstract=False
    workload='benign' if ROLE=='benign' else ROLE
    attack=None if ROLE=='benign' else ROLE

    def wait_time(self):return 0

    def on_start(self):
        super().on_start()
        self.plan=scale_plan(worker_plan(PROFILE,ROLE,os.environ['P20_WORKER_ID'],self.user_index,
                              env_list('P20_BENIGN_ACCOUNTS')),float(os.environ.get('P20_ROBUST_TIME_SCALE','1')))
        self.ordinal=0;self.valid_phase=self.rng.randrange(4)
        self.account=self.plan['account']
        if self.account:
            # Keep setup failures visible; do not silently drop users without a token.
            self.login(self.account,f'Passw0rd!{self.account[4:]}',phase='setup',objective=False)
        self.await_measured_phase()
        self.next_at=self.deadline-env_float('P20_DEADLINE_S',0)+self.plan['phase_s']

    def browser_headers(self):
        return {'User-Agent':'WalletGuard synthetic browser','Accept-Language':'en-US','Accept':'application/json'}

    def browse(self,page,per_page=20,malicious=False):
        expected=list(range((page-1)*per_page+1,page*per_page+1))
        self.send(request=lambda:self.client.get('/products',params={'page':page,'per_page':per_page},
                                                headers=self.browser_headers()),
                  classify=lambda r:classify_products(r,expected_ids=expected,record_ids=malicious),
                  route='/products',method='GET',intent=f'page:{page}',objective=malicious,
                  client_id=self.account,page=page,per_page=per_page,robust_profile=PROFILE)

    def chat(self,words,output,steps,malicious=False):
        prompt=' '.join(['synthetic']*words)
        self.send(request=lambda:self.client.post('/chat',json={'prompt':prompt,'max_output_tokens':output,
                    'agent_steps':steps},headers={**self.browser_headers(),**self.auth}),
                  classify=classify_chat,route='/chat',method='POST',intent=f'agent:{steps}:{output}',
                  objective=malicious,unknown_on_timeout=True,client_id=self.account,
                  max_output_tokens=output,agent_steps=steps,prompt_tokens=estimate_tokens(prompt),
                  prompt_chars=len(prompt),robust_profile=PROFILE)

    @task
    def cycle(self):
        remaining=self.next_at-time.monotonic()
        if remaining>0:
            gevent.sleep(min(remaining,max(0,self.deadline-time.monotonic())))
        if self._past_deadline():raise StopUser()
        k=self.ordinal;self.ordinal+=1;self.next_at+=self.plan['period_s']
        if ROLE=='credential_stuffing':
            account=credential_target(PROFILE,self.plan['rank'],k)
            valid=(k+self.valid_phase)%4==0
            password=f'Passw0rd!{account[4:]}' if valid else 'SyntheticWrongPassword'
            self.send(request=lambda:self.client.post('/login',json={'username':account,'password':password}),
                      classify=classify_login,route='/login',method='POST',intent=f'synthetic-credential:{k}',
                      objective=True,credential_kind='valid_demo' if valid else 'synthetic_invalid',
                      client_id=account,robust_profile=PROFILE)
        elif ROLE=='scraping':
            page=(k*self.plan['sources']+self.plan['rank'])%50+1
            self.browse(page,100,True)
        elif ROLE=='dow':
            self.chat(self.plan['prompt_words'],self.plan['output'],self.plan['steps'],True)
        elif PROFILE.startswith('burst_'):
            for n in range(self.plan['reads']):self.browse((k*self.plan['reads']+n)%60+1)
            self.chat(10,64,1)
        elif PROFILE=='shared_account':
            self.browse(k%60+1);self.chat(10,120,3)
        elif k%3==0:self.chat(10,120,3)
        else:self.browse(k%60+1)
