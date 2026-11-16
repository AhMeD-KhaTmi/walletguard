"""Credential stuffing: seeded synthetic credential list against `POST /login`.

Success is a valid demo login token (master plan 7.1), not Locust's status flag.
The username/password values are never written to the attempt log; only the dataset
entry id and whether that entry is a known-valid demo account.

    locust -f locust/attack_credential_stuffing.py --headless -u 5 -r 5 -t 60s \
        --host http://10.20.0.1:8000
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from locust import between, task  # noqa: E402

from eval.clientlog import classify_login  # noqa: E402
from eval.workload import LoggedUser, load_creds  # noqa: E402


class CredentialStuffingUser(LoggedUser):
    workload = "credential_stuffing"
    attack = "credential_stuffing"
    wait_time = between(0, 0.05)

    def on_start(self) -> None:
        super().on_start()
        self.entries = load_creds()["entries"]

    @task
    def attempt_login(self) -> None:
        entry = self.rng.choice(self.entries)

        def call():
            return self.client.post(
                "/login",
                json={"username": entry["username"], "password": entry["password"]},
                name="/login", catch_response=False,
            )

        self.send(request=call, classify=classify_login, route="/login", method="POST",
                  intent=f"cred:{entry['id']}", objective=True,
                  credential_kind=entry["kind"], client_id=entry["username"])
