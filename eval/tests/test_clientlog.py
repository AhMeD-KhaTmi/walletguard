import json
from types import SimpleNamespace

import pytest

from eval import clientlog


class FakeResponse:
    def __init__(self, status=200, body=None, headers=None, content=b""):
        self.status_code = status
        self._body = body if body is not None else {}
        self.headers = headers or {}
        self.content = content

    def json(self):
        return self._body


def test_login_objective_needs_a_token():
    assert clientlog.classify_login(FakeResponse(200, {"token": "abc"}))[0] == "success"
    assert clientlog.classify_login(FakeResponse(200, {}))[0] == "fail"
    assert clientlog.classify_login(FakeResponse(401))[1] == "invalid_credentials"
    assert clientlog.classify_login(FakeResponse(429))[0] == "blocked"
    assert clientlog.classify_login(FakeResponse(403))[0] == "blocked"
    assert clientlog.classify_login(FakeResponse(500))[0] == "error"


def test_product_objective_needs_the_requested_data():
    page = FakeResponse(200, {"items": [{"id": 1}, {"id": 2}]})
    assert clientlog.classify_products(page, expected_ids=[1, 2])[0] == "success"
    assert clientlog.classify_products(page, expected_ids=[1, 9])[0] == "fail"
    assert clientlog.classify_products(FakeResponse(200, {"items": []}))[0] == "fail"
    assert clientlog.classify_products(FakeResponse(429))[0] == "blocked"


def test_product_ids_are_recorded_only_when_requested():
    page = FakeResponse(200, {"items": [{"id": 7}, {"id": 8}]})
    _, _, with_ids = clientlog.classify_products(page, record_ids=True)
    _, _, without_ids = clientlog.classify_products(page)
    assert with_ids["product_ids"] == [7, 8]
    assert "product_ids" not in without_ids


def test_chat_objective_is_accounted_usage_not_http_200():
    assert clientlog.classify_chat(FakeResponse(200, headers={"X-Tokens-Out": "900"}))[0] == "success"
    assert clientlog.classify_chat(FakeResponse(200, headers={"X-Tokens-Out": "0"}))[0] == "fail"
    assert clientlog.classify_chat(FakeResponse(400))[1] == "output_policy"
    assert clientlog.classify_chat(FakeResponse(429))[0] == "blocked"
    _, _, metrics = clientlog.classify_chat(
        FakeResponse(200, headers={"X-Tokens-In": "10", "X-Tokens-Out": "20",
                                  "X-Cost-USD": "0.000330"}))
    assert metrics["tokens_in"] == 10 and metrics["tokens_out"] == 20
    assert metrics["cost_usd"] == pytest.approx(0.00033)


def test_execute_records_intent_before_sending_and_keeps_timeouts(tmp_path):
    log = clientlog.AttemptLog(workload="dow", attack="dow", root=tmp_path,
                               target="http://127.0.0.1:8000", run_id="r1", ip="10.20.0.22")

    def slow():
        raise TimeoutError("read timed out")

    row = clientlog.execute(log, request=slow, classify=clientlog.classify_chat,
                            route="/chat", method="POST", intent="chat:900",
                            objective=True, unknown_on_timeout=True)
    assert row["outcome"] == "unknown"
    assert row["unresolved"] is True
    assert row["started_ms"] <= row["ended_ms"]
    assert row["attempt_id"]
    log.close()

    lines = next(tmp_path.glob("attempts-*.jsonl")).read_text().splitlines()
    assert json.loads(lines[0])["intent"] == "chat:900"


def test_transport_error_is_not_a_success(tmp_path):
    log = clientlog.AttemptLog(workload="scraping", attack="scraping", root=tmp_path,
                               target="http://127.0.0.1:8000", run_id="r2", ip="10.20.0.19")

    class ConnectError(Exception):
        pass

    def broken():
        raise ConnectError("connection refused")

    row = clientlog.execute(log, request=broken, classify=clientlog.classify_products,
                            route="/products", method="GET", intent="page:1")
    assert row["outcome"] == "error"
    assert row["reason"] == "ConnectError"
    log.close()


def test_request_id_and_response_size_are_captured(tmp_path):
    log = clientlog.AttemptLog(workload="scraping", attack="scraping", root=tmp_path,
                               target="http://127.0.0.1:8000", run_id="r3", ip="10.20.0.20")
    response = FakeResponse(200, {"items": [{"id": 1}]},
                            headers={"x-request-id": "abc123"}, content=b"x" * 42)
    row = clientlog.execute(log, request=lambda: response,
                            classify=clientlog.classify_products,
                            route="/products", method="GET", intent="page:1")
    assert row["request_id"] == "abc123"
    assert row["response_bytes"] == 42
    log.close()


def test_no_secret_is_written(tmp_path):
    log = clientlog.AttemptLog(workload="credential_stuffing", attack="credential_stuffing",
                               root=tmp_path, target="http://127.0.0.1:8000",
                               run_id="r4", ip="10.20.0.16")
    response = FakeResponse(200, {"token": "super-secret-token"})
    clientlog.execute(log, request=lambda: response, classify=clientlog.classify_login,
                      route="/login", method="POST", intent="cred:c00001", objective=True,
                      credential_kind="valid")
    log.close()
    text = next(tmp_path.glob("attempts-*.jsonl")).read_text()
    assert "super-secret-token" not in text
    assert "Passw0rd" not in text


def test_local_ipv4_requires_an_absolute_url():
    with pytest.raises(ValueError):
        clientlog.local_ipv4("10.20.0.1:8000")


def test_shutdown_interruption_is_unknown_not_a_failure(tmp_path):
    """Locust kills the user greenlet mid-request: the server may have answered."""
    log = clientlog.AttemptLog(workload="scraping", attack="scraping", root=tmp_path,
                               target="http://127.0.0.1:8000", run_id="r5", ip="10.20.0.19")

    class GreenletExit(BaseException):
        pass

    def killed():
        raise GreenletExit()

    with pytest.raises(GreenletExit):
        clientlog.execute(log, request=killed, classify=clientlog.classify_products,
                          route="/products", method="GET", intent="page:1")
    log.close()
    row = json.loads(next(tmp_path.glob("attempts-*.jsonl")).read_text())
    assert row["outcome"] == "unknown"
    assert row["unresolved"] is True


def test_status_zero_read_timeout_preserves_uncertain_generation(tmp_path):
    log = clientlog.AttemptLog(workload="dow", root=tmp_path, run_id="r", ip="10.20.0.22")
    response = SimpleNamespace(status_code=0, error=TimeoutError("read timed out"))
    row = clientlog.execute(log, request=lambda: response, classify=clientlog.classify_chat,
                            route="/chat", method="POST", intent="chat:900", unknown_on_timeout=True)
    log.close()
    assert row["outcome"] == "unknown" and row["unresolved"] is True


def test_backend_timeout_retains_unknown_agent_outcome():
    outcome, reason, _ = clientlog.classify_chat(FakeResponse(504))
    assert outcome == "unknown" and reason == "backend_generation_timeout"


def test_worker_meta_records_the_seed_the_process_used(tmp_path):
    """MASTER_PLAN 6.2/7.2.1: the configured seed alone cannot reproduce a worker."""
    log = clientlog.AttemptLog(workload="scraping", root=tmp_path,
                               target="http://127.0.0.1:8000", run_id="r6", ip="10.20.0.19")
    written = log.worker_meta(configured_seed=42, derived_seed=42 ^ 4321,
                              timeout_s=3.0, target="http://127.0.0.1:8000")
    assert written is not None
    # Several users share one Locust process: the record is written once, not per user.
    assert log.worker_meta(configured_seed=42, derived_seed=42 ^ 4321,
                           timeout_s=3.0) is None
    files = list(tmp_path.glob("worker-*.json"))
    assert len(files) == 1
    meta = json.loads(files[0].read_text(encoding="utf-8"))
    assert meta["configured_seed"] == 42
    assert meta["derived_seed"] == 42 ^ 4321
    assert meta["ip"] == "10.20.0.19"
    assert "token" not in files[0].read_text(encoding="utf-8").lower()
    log.close()
