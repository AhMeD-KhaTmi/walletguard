"""The gated DoW control channel.

Clients run inside ``ip netns exec``, so their loopback is not the host's; the gate
therefore uses files in the run directory, which every identity shares. These tests
exercise the handshake without starting Locust or traffic.
"""

import json
import time
from types import SimpleNamespace

import pytest

from eval import harness
from eval.workload import GatedUser


def _gated(ip: str = "10.20.0.22") -> GatedUser:
    user = object.__new__(GatedUser)
    user.log = SimpleNamespace(ip=ip)
    return user


def test_wait_for_setup_requires_every_marker(tmp_path):
    gate = tmp_path / "gate"
    gate.mkdir()
    (gate / "setup-ready-10.20.0.22-1-aa.json").write_text("{}")
    (gate / "setup-ready-10.20.0.23-2-bb.json").write_text("{}")
    assert harness.wait_for_setup(gate, 3, timeout=0.3) is False
    (gate / "setup-ready-10.20.0.24-3-cc.json").write_text("{}")
    assert harness.wait_for_setup(gate, 3, timeout=3.0) is True


def test_wait_for_setup_ignores_missing_directory(tmp_path):
    assert harness.wait_for_setup(tmp_path / "absent", 1, timeout=0.2) is False


def test_write_gate_replaces_atomically(tmp_path):
    gate = tmp_path / "gate"
    harness.write_gate(gate, {"abort": True})
    harness.write_gate(gate, {"measured": True})
    assert json.loads((gate / "gate.json").read_text())["measured"] is True
    assert not list(gate.glob(".gate-*.tmp"))


def test_gated_user_requires_the_harness(tmp_path, monkeypatch):
    monkeypatch.delenv("P20_GATE_DIR", raising=False)
    with pytest.raises(RuntimeError, match="P20_GATE_DIR"):
        _gated().await_measured_phase()


def test_gated_user_rejects_a_relative_gate_dir(monkeypatch):
    # Path("") is Path("."); a relative gate dir would silently poll the cwd.
    monkeypatch.setenv("P20_GATE_DIR", "")
    with pytest.raises(RuntimeError, match="P20_GATE_DIR"):
        _gated().await_measured_phase()
    monkeypatch.setenv("P20_GATE_DIR", "eval/runs")
    with pytest.raises(RuntimeError, match="absolute"):
        _gated().await_measured_phase()


def test_gated_user_writes_one_marker_per_user(tmp_path, monkeypatch):
    monkeypatch.setenv("P20_GATE_DIR", str(tmp_path))
    monkeypatch.setenv("P20_GATE_TIMEOUT", "0")
    with pytest.raises(RuntimeError, match="never opened"):
        _gated().await_measured_phase()
    assert len(list(tmp_path.glob("setup-ready-10.20.0.22-*.json"))) == 1


def test_gated_user_arms_its_deadline_when_the_gate_opens(tmp_path, monkeypatch):
    monkeypatch.setenv("P20_GATE_DIR", str(tmp_path))
    monkeypatch.setenv("P20_DEADLINE_S", "30")
    harness.write_gate(tmp_path, {"measured": True})
    user = _gated()
    before = time.monotonic()
    user.await_measured_phase()
    assert user.deadline is not None and user.deadline > before


def test_gated_user_stops_when_the_harness_aborts(tmp_path, monkeypatch):
    from locust.exception import StopUser

    monkeypatch.setenv("P20_GATE_DIR", str(tmp_path))
    harness.write_gate(tmp_path, {"abort": True})
    with pytest.raises(StopUser):
        _gated().await_measured_phase()
