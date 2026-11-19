"""Explicitly initialize an empty synthetic spending period; never overwrite/reset."""
import argparse
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,''}:sys.path.insert(0,str(ROOT))
import redis
from waf.buckets import SPEND_INIT_LUA
from waf.config import Config


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--redis-url',required=True);p.add_argument('--period',required=True);p.add_argument('--cap-microusd',type=int,required=True);a=p.parse_args()
    Config(spend_period=a.period,spend_cap_microusd=a.cap_microusd)
    with redis.Redis.from_url(a.redis_url,decode_responses=True,socket_timeout=2) as r:
        status=r.eval(SPEND_INIT_LUA,1,'p20:spend:'+a.period,a.cap_microusd)
    if status<0:raise ValueError('existing period cap differs; no state overwritten')
    print('Created period' if status else 'Existing period preserved')

if __name__=='__main__':main()
