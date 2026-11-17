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

``P20_DOW_PACE_S`` is the fixed gap between chat attempts per user (0 = the default
unpaced burst, used for the enforcement ASR runs). A paced under-cap run stays inside
`ip_req`/`chat_req` while it drains `llm_tok`, which is the only way the WAF can reach
token accounting and log an `llm_tok` throttle; the unpaced burst is stopped by the
request-rate bucket first, so it can never exercise that path.

    P20_DOW_PROFILE=overcap locust -f locust/attack_dow.py --headless \
        -u 2 -r 2 -t 40s --host http://10.20.0.1:8000
"""

from __future__ import annotations

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from locust import between, constant, task  # noqa: E402
from locust.exception import StopUser  # noqa: E402

from eval.clientlog import classify_chat  # noqa: E402
from eval.workload import GatedUser, LoggedUser, env_int  # noqa: E402

BASE_PROMPT = "Summarize the following synthetic support transcript for the catalogue team."
PROFILES = {"undercap": 900, "overcap": 32_000}
# Fixed per-user spacing for the token-accounting run; 0 keeps the original burst.
PACE_S = max(0.0, float(os.environ.get("P20_DOW_PACE_S") or 0.0))
# Harness sets P20_SETUP_GATE=1 for the standalone DoW workload: authenticate first,
# then wait for the measured phase to be opened with fresh policy state.
SETUP_GATE = os.environ.get("P20_SETUP_GATE") == "1"


class TokenExhaustionUser(GatedUser if SETUP_GATE else LoggedUser):  # type: ignore[misc]
    workload = "dow"
    attack = "dow"
    abstract = False
    gated = SETUP_GATE
    wait_time = constant(PACE_S) if PACE_S > 0 else between(0, 0.05)

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
        if SETUP_GATE:
            # Still announce and wait, so the harness is never left blocked on setup.
            self.await_measured_phase()
        if self.token is None:
            # Without a session the measured phase would measure a login failure, not
            # token exhaustion. Stop this user; zero measured attempts invalidates the run.
            raise StopUser()

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
