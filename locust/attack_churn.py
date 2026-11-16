"""Connection-churn probe: new TCP connections with and without an HTTP request.

HTTP keep-alive means request rate and accepted-connection rate are different
measurements (master plan 6). This workload forces fresh connections:

* ``churn_http``  GET with ``Connection: close`` - accepted connection + request;
* ``churn_tcp``   connect and close without sending a request - accepted connection
  only, which is what the kernel connection counters must see.

    locust -f locust/attack_churn.py --headless -u 2 -r 2 -t 20s \
        --host http://10.20.0.1:8000
"""

from __future__ import annotations

import pathlib
import socket
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from locust import between, task  # noqa: E402

from eval.clientlog import classify_probe  # noqa: E402
from eval.workload import LoggedUser  # noqa: E402


def tcp_connect_only(target: str, timeout: float) -> None:
    parts = urlsplit(target)
    with socket.create_connection((parts.hostname, parts.port or 80), timeout=timeout):
        pass


class ConnectionChurnUser(LoggedUser):
    workload = "churn"
    attack = "churn"
    wait_time = between(0.05, 0.2)

    @task(2)
    def churn_http(self) -> None:
        def call():
            return self.client.get("/products", params={"page": 1, "per_page": 1},
                                   headers={"Connection": "close"},
                                   name="/products (new connection)", catch_response=False)

        self.send(request=call, classify=classify_probe, route="/products", method="GET",
                  intent="churn_http", objective=True, connection_mode="close")

    @task(1)
    def churn_tcp(self) -> None:
        def call():
            return tcp_connect_only(self.host, self.client.timeout)

        self.send(request=call, classify=lambda _: ("success", "tcp_connected", {}),
                  route="tcp://", method="CONNECT", intent="churn_tcp", objective=True,
                  connection_mode="connect_close")
