"""Small C0 functional check; not an attack benchmark or measured ASR run."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx


def smoke(base_url: str) -> dict:
    with httpx.Client(base_url=base_url, timeout=10, trust_env=False) as client:
        health = client.get("/health")
        health.raise_for_status()
        assert health.json()["waf_mode"] == "off", "Use C0 for this check"
        before = client.get("/_metrics/usage")
        before.raise_for_status()
        start = before.json()
        products = client.get("/products", params={"page": 1, "per_page": 100})
        products.raise_for_status()
        assert products.json()["total"] == 5000
        assert len(products.json()["items"]) == 100
        unknown = client.post("/login", json={"username": "absent", "password": "synthetic-wrong"})
        assert unknown.status_code == 401
        login = client.post("/login", json={"username": "user1", "password": "Passw0rd!1"})
        login.raise_for_status()
        headers = {"authorization": "Bearer " + login.json()["token"]}
        chat = client.post("/chat", headers=headers, json={"prompt": "baseline smoke check", "max_output_tokens": 50})
        chat.raise_for_status()
        usage = chat.json()["usage"]
        assert int(chat.headers["x-tokens-out"]) == usage["tokens_out"] == 50
        invalid = client.post("/chat", headers=headers, json={"prompt": "invalid input", "max_output_tokens": -1})
        assert invalid.status_code == 422
        after = client.get("/_metrics/usage")
        after.raise_for_status()
        totals = after.json()
        assert int(totals["requests"]) - int(start.get("requests", 0)) == 1
        assert int(totals["tokens_out"]) - int(start.get("tokens_out", 0)) == 50
        spec = client.get("/openapi.json")
        spec.raise_for_status()
        assert "/chat" in spec.json()["paths"]
        assert client.get("/docs").status_code == 200
        return {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "kind": "development_smoke_not_attack_evaluation",
            "base_url": base_url,
            "health": health.json(),
            "checks": {
                "products": "pass", "invalid_login": "pass", "login": "pass",
                "http_mock_chat": "pass", "usage_delta": "pass",
                "negative_output_rejected": "pass", "openapi_and_docs": "pass",
            },
            "chat_usage": usage,
            "cost_is_simulated": True,
            "session_credentials_saved": False,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = json.dumps(smoke(args.base_url), indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report)
    print(report, end="")


if __name__ == "__main__":
    main()
