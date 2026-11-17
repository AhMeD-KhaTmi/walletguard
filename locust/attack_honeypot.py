"""Explicit decoy (honeypot) probe plus an immediate ban follow-up check.

Ordinary scraping does not guarantee a decoy hit, so this is its own workload.
Each cycle hits one decoy path and then a normal page, which makes the client-observed
ban time visible: the first follow-up answered with 403 after the decoy 404.

    locust -f locust/attack_honeypot.py --headless -u 1 -r 1 -t 20s \
        --host http://10.20.0.1:8000
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from locust import constant, task  # noqa: E402

from eval.clientlog import classify_probe  # noqa: E402
from eval.workload import LoggedUser  # noqa: E402

DECOYS = ("/admin-backup", "/admin-backup/", "/internal/export", "/internal/export/", "/.env")


class HoneypotProbeUser(LoggedUser):
    workload = "honeypot"
    attack = "honeypot"
    wait_time = constant(1)

    @task(3)
    def hit_decoy(self) -> None:
        path = self.rng.choice(DECOYS)

        def call():
            return self.client.get(path, name="decoy", catch_response=False)

        self.send(request=call, classify=classify_probe, route=path, method="GET",
                  intent="decoy_hit", objective=True)

    @task(1)
    def check_ban(self) -> None:
        def call():
            return self.client.get("/products", params={"page": 1, "per_page": 1},
                                   name="/products (ban check)", catch_response=False)

        self.send(request=call, classify=classify_probe, route="/products", method="GET",
                  intent="ban_check", objective=False, phase="followup")
