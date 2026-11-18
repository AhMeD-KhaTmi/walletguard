"""B's opt-in worker lifecycle adapter; A's request/scenario code stays unchanged."""
import time


def past_deadline(user):
    # Stop only this user. A supervisor owns process-wide quit outside user tasks.
    return user.deadline is not None and time.monotonic() >= user.deadline


def supervise(environment):
    import gevent
    latest = None
    while True:
        runner = environment.runner
        users = [g.args[0] for g in runner.user_greenlets if g.args]
        deadlines = [u.deadline for u in users if getattr(u, 'deadline', None) is not None]
        if deadlines:
            latest = max([latest] + deadlines) if latest is not None else max(deadlines)
        if latest is not None and time.monotonic() >= latest:
            runner.quit()
            return
        gevent.sleep(.05)


def main():
    # Match Locust's normal early monkey-patching, before network client imports.
    from gevent import monkey
    monkey.patch_all()
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from locust import events
    from eval.workload import LoggedUser
    import gevent
    LoggedUser._past_deadline = past_deadline
    @events.test_start.add_listener
    def start_supervisor(environment, **kwargs):
        gevent.spawn(supervise, environment)
    from locust.main import main as locust_main
    locust_main()


if __name__ == '__main__': main()
