"""Catalogue scraping: sequential `GET /products` pages from several source IPs.

Success is the requested product data arriving (master plan 7.1). Product ids are
recorded so the evaluator can report *unique products harvested*, which a request
count cannot express.

    locust -f locust/attack_scraping.py --headless -u 5 -r 5 -t 60s \
        --host http://10.20.0.1:8000
"""

from __future__ import annotations

import math
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from locust import between, task  # noqa: E402

from eval.clientlog import classify_products  # noqa: E402
from eval.workload import LoggedUser, env_int  # noqa: E402


class ScrapingUser(LoggedUser):
    workload = "scraping"
    attack = "scraping"
    wait_time = between(0, 0.02)

    def on_start(self) -> None:
        super().on_start()
        self.per_page = max(1, min(100, env_int("P20_PER_PAGE", 100)))
        self.total = env_int("P20_TOTAL_PRODUCTS", 5000)
        self.pages = max(1, math.ceil(self.total / self.per_page))
        self.page = max(1, env_int("P20_START_PAGE", 1))

    @task
    def fetch_page(self) -> None:
        page, self.page = self.page, (self.page % self.pages) + 1
        start = (page - 1) * self.per_page + 1
        expected = list(range(start, min(start + self.per_page, self.total + 1)))

        def call():
            return self.client.get("/products", params={"page": page, "per_page": self.per_page},
                                   name="/products", catch_response=False)

        self.send(request=call,
                  classify=lambda response: classify_products(
                      response, expected_ids=expected, record_ids=True),
                  route="/products", method="GET", intent=f"page:{page}", objective=True,
                  page=page, per_page=self.per_page)
