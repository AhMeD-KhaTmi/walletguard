"""Guard against Locust discovering a helper base class as a runnable user.

Locust instantiates every ``User`` subclass visible in the locustfile's namespace,
including imported ones. A base class without tasks therefore crashes the whole
workload at start ("No tasks defined on GatedUser"). These tests load each workload
file exactly as Locust does and assert the invariant that broke on 2026-11-17.
"""

import importlib.util
import pathlib
import sys

import pytest

locust = pytest.importorskip("locust")
from locust import User  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
LOCUST_DIR = ROOT / "locust"
FILES = [
    "benign.py",
    "attack_credential_stuffing.py",
    "attack_scraping.py",
    "attack_dow.py",
    "attack_honeypot.py",
    "attack_churn.py",
]
MIXED_ROLES = ["benign", "credential_stuffing", "scraping", "dow"]


def load(filename: str, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, LOCUST_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    # Locust's own loader registers the locustfile in sys.modules before executing it;
    # mirror that so class creation sees a fully importable module.
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def runnable_users(module) -> list[tuple[str, type]]:
    return [
        (name, obj) for name, obj in vars(module).items()
        if isinstance(obj, type) and issubclass(obj, User)
        and not getattr(obj, "abstract", False)
    ]


@pytest.mark.parametrize("filename", FILES)
def test_each_workload_exposes_runnable_users_with_tasks(filename, monkeypatch):
    monkeypatch.setenv("P20_SETUP_GATE", "1")
    module = load(filename, f"p20_test_{filename[:-3]}")
    runnable = runnable_users(module)
    assert runnable, f"{filename} defines no runnable user"
    for name, cls in runnable:
        assert getattr(cls, "tasks", None), (
            f"{filename}:{name} is discoverable by Locust but has no tasks; "
            "mark it abstract = True")


def test_dow_pace_is_a_fixed_per_user_gap(monkeypatch):
    """A paced under-cap run is what lets the WAF reach llm_tok (B's request)."""
    monkeypatch.setenv("P20_SETUP_GATE", "1")
    monkeypatch.setenv("P20_DOW_PACE_S", "7")
    module = load("attack_dow.py", "p20_test_attack_dow_paced")
    assert module.PACE_S == 7.0
    wait = module.TokenExhaustionUser.wait_time
    # Locust stores `constant(7)` as `lambda instance: 7.0`: the instance argument is
    # required but unused, so call it the way Locust does.
    assert wait(None) == 7.0


def test_dow_pace_defaults_to_the_unpaced_burst(monkeypatch):
    monkeypatch.setenv("P20_SETUP_GATE", "1")
    monkeypatch.delenv("P20_DOW_PACE_S", raising=False)
    module = load("attack_dow.py", "p20_test_attack_dow_unpaced")
    assert module.PACE_S == 0.0
    # `between(0, 0.05)` is not a fixed wait: it still yields values in its range.
    assert 0.0 <= module.TokenExhaustionUser.wait_time(None) <= 0.05


@pytest.mark.parametrize("role", MIXED_ROLES)
def test_mixed_workload_selects_exactly_one_runnable_user(role, monkeypatch):
    monkeypatch.setenv("P20_ROLE", role)
    module = load("mixed.py", f"p20_test_mixed_{role}")
    runnable = runnable_users(module)
    assert len(runnable) == 1, f"mixed.py as {role} exposed {[n for n, _ in runnable]}"
    assert getattr(runnable[0][1], "tasks", None)


def test_gated_base_class_is_not_runnable():
    from eval.workload import GatedUser

    assert getattr(GatedUser, "abstract", False) is True


def test_gated_user_can_send_its_setup_login_before_the_gate_opens():
    """The setup login happens before the measured phase, so no deadline is armed yet.

    Regression: `deadline` used to be created only by `on_start` for non-gated users,
    so a gated user's setup login raised AttributeError and the run died with
    "setup logins did not finish" and zero attempt records (2026-11-17).
    """
    from eval.workload import GatedUser, LoggedUser

    user = object.__new__(GatedUser)
    assert user.deadline is None
    assert user._past_deadline() is False
    assert LoggedUser.deadline is None
