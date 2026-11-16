import os
import subprocess

from conftest import ROOT, TEST_REDIS_URL


def test_reset_is_scoped_and_preserves_management_state(redis_db):
    keep = {"p20:allowlist": "", "p20:meta:schema_version": "2", "other-project": "keep", "p20:unknown": "keep"}
    redis_db.sadd("p20:allowlist", "127.0.0.1")
    for key, value in keep.items():
        if key != "p20:allowlist":
            redis_db.set(key, value)
    runtime = ["p20:app:usage:total", "p20:ban:10.0.0.1", "p20:shadow:test", "p20:eval:hits:chat", "p20:stream:ebpf_events", "p20:xdp:drops"]
    for key in runtime:
        redis_db.set(key, "remove")
    result = subprocess.run(
        ["bash", "scripts/reset_state.sh"], cwd=ROOT,
        env={**os.environ, "REDIS_URL": TEST_REDIS_URL},
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "6 keys removed" in result.stdout
    assert all(not redis_db.exists(k) for k in runtime)
    assert all(redis_db.exists(k) for k in keep)


def test_reset_failure_does_not_claim_success():
    result = subprocess.run(
        ["bash", "scripts/reset_state.sh", "--redis-url", "redis://127.0.0.1:1/15"],
        cwd=ROOT, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode != 0
    assert "Reset failed" in result.stderr
    assert "keys removed" not in result.stdout
