import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
import redis

ROOT = Path(__file__).resolve().parents[1]
TEST_REDIS_URL = "redis://127.0.0.1:6379/15"


@pytest.fixture
def redis_db():
    """Designated scratch DB only; never use application DB 0 in automated tests."""
    with redis.Redis.from_url(
        TEST_REDIS_URL, decode_responses=True,
        socket_connect_timeout=2, socket_timeout=2,
    ) as client:
        client.flushdb()
        yield client
        client.flushdb()


@pytest.fixture(scope="session")
def llm_url():
    """A real HTTP backend, using a reserved socket and our own subprocess only."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.llm_service:app",
             "--fd", str(listener.fileno()), "--log-level", "error"],
            cwd=ROOT, pass_fds=(listener.fileno(),),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        url = f"http://127.0.0.1:{port}"
        try:
            with httpx.Client(timeout=0.25, trust_env=False) as client:
                for _ in range(100):
                    if process.poll() is not None:
                        pytest.fail("HTTP mock exited before readiness")
                    try:
                        if client.get(url + "/health").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(0.05)
                else:
                    pytest.fail("HTTP mock did not become ready")
            yield url
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
