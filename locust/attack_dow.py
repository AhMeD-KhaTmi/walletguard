"""LLM token-exhaustion (Denial-of-Wallet) against `POST /chat`.

Two deliberately separate profiles (master plan 7.1):

``under-cap``  repeated requests at ``max_output_tokens=900`` so the per-account
              token budget is exhausted by legitimate-looking payloads;
``over-cap``   ``max_output_tokens=32000`` so the hardened output cap is the control
              under test and the baseline burns the most tokens.

Success is *accounted generation*: HTTP 200 with ``X-Tokens-Out > 0``. A client
timeout is recorded as an unknown outcome because the backend may still have
generated tokens. Setup login uses the reserved attacker account and is excluded
from the malicious denominator (`phase="setup"`).

    P20_DOW_PROFILE=overcap locust -f locust/attack_dow.py --headless \
        -u 2 -r 2 -t 40s --host http://10.20.0.1:8000
"""

from __future__ import annotations

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from locust import between, task  # noqa: E402

from eval.clientlog import classify_chat  # noqa: E402
from eval.workload import LoggedUser, env_int  # noqa: E402

BASE_PROMPT = "Summarize the following synthetic support transcript for the catalogue team."
PROFILES = {"undercap": 900, "overcap": 32_000}


class TokenExhaustionUser(LoggedUser):
    workload = "dow"
    attack = "dow"
    wait_time = between(0, 0.05)

    def on_start(self) -> None:
        super().on_start()
        self.profile = os.environ.get("P20_DOW_PROFILE", "undercap")
        if self.profile not in PROFILES:
            raise RuntimeError(f"P20_DOW_PROFILE must be one of {sorted(PROFILES)}")
        self.max_output = env_int("P20_MAX_OUTPUT", PROFILES[self.profile])
        account = os.environ.get("P20_ATTACKER_ACCOUNT", "user50")
        password = os.environ.get("P20_ATTACKER_PASSWORD") or f"Passw0rd!{account[4:]}"
        self.account = account
        # Setup traffic: authenticated once at a normal rate, charged separately.
        self.login(account, password, phase="setup", objective=False)

    @task
    def exhaust_tokens(self) -> None:
        prompt = " ".join(self.rng.choice([BASE_PROMPT, BASE_PROMPT, "Customer: " + "abc " * 40])
                          for _ in range(self.rng.randint(1, 6)))

        def call():
            return self.client.post(
                "/chat", json={"prompt": prompt, "max_output_tokens": self.max_output},
                headers=self.auth, name="/chat", catch_response=False,
            )

        self.send(request=call, classify=classify_chat, route="/chat", method="POST",
                  intent=f"chat:{self.max_output}", objective=True, unknown_on_timeout=True,
                  profile=self.profile, client_id=self.account,
                  max_output_tokens=self.max_output, prompt_chars=len(prompt))
