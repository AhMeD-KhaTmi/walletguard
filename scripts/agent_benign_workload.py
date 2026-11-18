"""B's explicitly identified multi-step benign Locust scenario (not A's workload)."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from locust import task
from common.tokens import estimate_tokens
from eval.clientlog import classify_chat, classify_products
from eval.workload import LoggedUser, env_list


class AgentBenignUser(LoggedUser):
    workload = "benign"
    attack = None

    def on_start(self):
        super().on_start()
        pool = env_list("P20_BENIGN_ACCOUNTS") or [f"user{i}" for i in range(1, 50)]
        self.account = self.rng.choice(pool)
        self.login(self.account, f"Passw0rd!{self.account[4:]}", phase="setup", objective=False)

    def wait_time(self):
        return self.rng.uniform(.8, 4.0)

    def _headers(self):
        return {"User-Agent": "Mozilla/5.0 WalletGuard synthetic browser",
                "Accept": "application/json", "Accept-Language": "en-US,en;q=0.9"}

    @task(6)
    def browse(self):
        page = self.rng.randint(1, 60)
        self.send(request=lambda: self.client.get(
            "/products", params={"page": page, "per_page": 20}, headers=self._headers()),
            classify=classify_products, route="/products", method="GET", objective=False,
            intent=f"browse:{page}", client_id=self.account)

    @task(3)
    def chat(self):
        steps = self.rng.choice((1, 3, 3, 3, 5, 5, 8))
        output = self.rng.choice((64, 120, 180, 256, 320, 500))
        prompt = "Compare these synthetic catalogue items and summarise their warranty. "
        prompt += "price delivery warranty bicycle bottle notebook " * self.rng.randint(0, 18)
        self.send(request=lambda: self.client.post(
            "/chat", json={"prompt": prompt, "max_output_tokens": output, "agent_steps": steps},
            headers={**self._headers(), **self.auth}), classify=classify_chat, route="/chat",
            method="POST", intent=f"agent:{steps}:{output}", objective=False,
            client_id=self.account, agent_steps=steps, max_output_tokens=output,
            prompt_tokens=estimate_tokens(prompt), prompt_chars=len(prompt))
