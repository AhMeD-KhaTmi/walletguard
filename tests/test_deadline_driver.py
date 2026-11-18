from types import SimpleNamespace
import gevent
from scripts.locust_deadline_driver import past_deadline, supervise


def test_expired_user_does_not_quit_other_users(monkeypatch):
    monkeypatch.setattr('scripts.locust_deadline_driver.time.monotonic',lambda:10)
    user=SimpleNamespace(deadline=9)
    assert past_deadline(user)
    user.deadline=11;assert not past_deadline(user)
    user.deadline=None;assert not past_deadline(user)


def test_supervisor_quits_outside_user_greenlet():
    import time
    deadline=time.monotonic()+.1;calls=[]
    user=SimpleNamespace(deadline=deadline)
    class Worker:
        args=(user,)
    worker=Worker()
    runner=SimpleNamespace(user_greenlets=[worker],quit=lambda:calls.append(gevent.getcurrent()))
    supervisor=gevent.spawn(supervise,SimpleNamespace(runner=runner))
    supervisor.join(timeout=1)
    assert supervisor.ready() and supervisor.exception is None
    assert calls==[supervisor]
