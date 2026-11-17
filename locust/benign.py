"""Benign traffic generator: realistic browsing and chat from several real IPs.

This is B's false-positive and training-data source, so it must look like people,
not like a load test: log in once, browse a few catalogue pages, read for a while,
ask short chat questions with modest output sizes, pause between actions, and use
browser-like headers.

Accounts come from the benign pool (`user1..user49`); the reserved Denial-of-Wallet
account `user50` is never used here.

    P20_BENIGN_ACCOUNTS=user1,user2 locust -f locust/benign.py --headless \
        -u 2 -r 1 -t 120s --host http://10.20.0.1:8000
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from locust import between, task  # noqa: E402

from eval.clientlog import classify_chat, classify_products  # noqa: E402
from eval.workload import LoggedUser, env_float, env_list  # noqa: E402

PROMPTS = (
    "What is the warranty on product 122?",
    "Compare the first two items on the accessories page.",
    "Write a short product description for a stainless steel water bottle.",
    "Summarise this delivery note: two boxes arrived, one was dented.",
    "Which products are under 20 dollars?",
    "Draft a polite reply to a customer asking about a late shipment.",
    "Explain the return policy in one sentence.",
    "Give me three gift ideas for a cyclist.",
)


class BenignUser(LoggedUser):
    workload = "benign"
    attack = None

    def on_start(self) -> None:
        super().on_start()
        accounts = env_list("P20_BENIGN_ACCOUNTS") or [f"user{i}" for i in range(1, 50)]
        self.account = self.rng.choice(accounts)
        self.login(self.account, f"Passw0rd!{self.account[4:]}", phase="setup",
                   objective=False)

    def wait_time(self) -> float:
        return self.rng.uniform(env_float("P20_BENIGN_MIN_WAIT", 0.8),
                                env_float("P20_BENIGN_MAX_WAIT", 4.0))

    def _headers(self) -> dict[str, str]:
        return {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
        }

    @task(5)
    def browse_catalogue(self) -> None:
        page = self.rng.randint(1, 60)
        per_page = self.rng.randint(10, 25)

        def call():
            return self.client.get("/products", params={"page": page, "per_page": per_page},
                                   headers=self._headers(), name="/products",
                                   catch_response=False)

        self.send(request=call, classify=classify_products, route="/products", method="GET",
                  intent=f"browse:{page}", objective=False, page=page, per_page=per_page,
                  client_id=self.account)

    @task(3)
    def ask_chat(self) -> None:
        prompt = self.rng.choice(PROMPTS)
        if self.rng.random() < 0.3:  # occasionally a longer, more realistic prompt
            prompt = prompt + " " + "Please keep it brief and mention the price. " * self.rng.randint(1, 4)
        max_out = self.rng.choice((120, 180, 256, 320, 500))

        def call():
            return self.client.post(
                "/chat", json={"prompt": prompt, "max_output_tokens": max_out},
                headers={**self._headers(), **self.auth}, name="/chat",
                catch_response=False,
            )

        self.send(request=call, classify=classify_chat, route="/chat", method="POST",
                  intent=f"chat:{max_out}", objective=False, client_id=self.account,
                  max_output_tokens=max_out, prompt_chars=len(prompt))

    @task(1)
    def idle_page_view(self) -> None:
        """A cheap read of the first page, like a returning user."""
        def call():
            return self.client.get("/products", params={"page": 1, "per_page": 20},
                                   headers=self._headers(), name="/products (home)",
                                   catch_response=False)

        self.send(request=call, classify=classify_products, route="/products", method="GET",
                  intent="home", objective=False, client_id=self.account)
