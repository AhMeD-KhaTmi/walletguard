"""B's response-aware variant; original fixed-schedule client stays unchanged."""
import json
import math
import os
from pathlib import Path
import time
import gevent
from locust.exception import StopUser
from scripts.robustness_workload import RobustUser as _Base
_Base.abstract=True


from scripts.followup_retry import retry_delay


class ResponsiveUser(_Base):
    abstract=False
    def on_start(self):
        self.retry_until=0.0;self.retry_wait_total=0.0;self.retry_events=0
        super().on_start()

    def send(self,*,request,phase='measured',**kwargs):
        started=time.monotonic();wait=max(0,self.retry_until-started) if phase=='measured' else 0
        if wait:
            gevent.sleep(min(wait,max(0,self.deadline-started)) if self.deadline else wait)
            self.retry_wait_total+=time.monotonic()-started
            if self.deadline and time.monotonic()>=self.deadline:raise StopUser()
        def call():
            response=request();delay=retry_delay(response)
            if phase=='measured' and delay:
                self.retry_events+=1;self.retry_until=time.monotonic()+delay
            return response
        row=super().send(request=call,phase=phase,retry_policy='honor_retry_after_v1',retry_wait_s=time.monotonic()-started,**kwargs)
        gate=Path(os.environ['P20_GATE_DIR']);target=gate/f'retry-{os.environ["P20_WORKER_ID"]}-{self.user_index}.json'
        target.write_text(json.dumps(dict(retry_events=self.retry_events,wait_s=self.retry_wait_total)))
        return row
