"""One validated policy configuration; environment is read per application."""

import os
import math
from dataclasses import dataclass, field


def flag(name: str, default: str) -> bool:
    value = os.getenv(name, default)
    if value not in {"0", "1"}:
        raise ValueError(f"{name} must be 0 or 1")
    return value == "1"


@dataclass(frozen=True)
class Config:
    mode: str = "off"
    redis_url: str = "redis://127.0.0.1:6379/0"
    enable_buckets: bool = True
    enable_honeypot: bool = True
    enable_ml: bool = False
    use_ebpf_signals: bool = False
    run_id: str = "development"
    model_path: str = "ml/artifacts/model_base_volume_v1.joblib"
    honeypot_paths: tuple[str, ...] = ("/admin-backup", "/internal/export", "/.env")
    ban_ttl_s: int = 600
    strike_limit: int = 5
    strike_window_s: int = 300
    max_output_cap: int = 1024
    max_body_bytes: int = 1_000_000
    max_events: int = 10_000
    max_clients: int = 4096
    allowlist_cache_s: int = 60
    telemetry_limit: int = 10_000
    scoring_batch_size: int = 32
    scoring_batch_wait_ms: float = 2.0
    scoring_queue_capacity: int = 256
    # Qualified on independent account-attribution validation; legacy opt-in remains.
    account_pressure_bans: bool = False
    # Opt-in only: mixed-contention validation failed the benign comfort gate.
    wallet_capacity: float = 0.0
    wallet_refill_per_s: float = 0.0
    decisions_stream: str = "p20:stream:waf_decisions"
    features_stream: str = "p20:stream:waf_features"
    allowlist_key: str = "p20:allowlist"
    budgets: dict = field(default_factory=lambda: {
        "ip_req": (30, 2.0), "login_ip": (5, 5/60),
        "login_acct": (5, 5/900), "chat_req": (10, .5),
        # Frozen benign agent calibration; see docs/BUDGET_CALIBRATION.md.
        "llm_tok": (40_000, 2_400.0),
    })

    def __post_init__(self):
        if self.mode not in {"off", "observe", "enforce"}:
            raise ValueError("invalid WAF mode")
        for value in (self.ban_ttl_s, self.strike_limit, self.strike_window_s,
                      self.max_output_cap, self.max_body_bytes, self.max_events,
                      self.max_clients, self.allowlist_cache_s, self.telemetry_limit,
                      self.scoring_batch_size, self.scoring_queue_capacity):
            if type(value) is not int or value <= 0:
                raise ValueError("policy bounds must be positive integers")
        if (not math.isfinite(self.scoring_batch_wait_ms) or not 0 <= self.scoring_batch_wait_ms <= 50
                or self.scoring_batch_size > 64):
            raise ValueError("invalid scoring batch bounds")
        if set(self.budgets) != {"ip_req", "login_ip", "login_acct", "chat_req", "llm_tok"}:
            raise ValueError("missing or unknown bucket policy")
        if (type(self.account_pressure_bans) is not bool
                or any(isinstance(v, bool) for v in (self.wallet_capacity, self.wallet_refill_per_s))
                or not all(math.isfinite(float(v)) and v >= 0 for v in
                    (self.wallet_capacity, self.wallet_refill_per_s))
                or bool(self.wallet_capacity) != bool(self.wallet_refill_per_s)):
            raise ValueError("wallet capacity/refill must both be zero or positive finite")
        if any(not math.isfinite(float(v)) or v <= 0 for pair in self.budgets.values() for v in pair):
            raise ValueError("bucket capacity and refill rate must be positive and finite")

    @classmethod
    def from_env(cls, *, mode: str, redis_url: str):
        return cls(
            mode=mode, redis_url=redis_url,
            enable_buckets=flag("WAF_BUCKETS", "1"),
            enable_honeypot=flag("WAF_HONEYPOT", "1"),
            enable_ml=flag("WAF_ML", "0"),
            use_ebpf_signals=flag("WAF_EBPF_SIGNALS", "0"),
            run_id=os.getenv("P20_RUN_ID", "development"),
            model_path=os.getenv("WAF_MODEL_PATH", "ml/artifacts/model_base_volume_v1.joblib"),
            telemetry_limit=int(os.getenv("WAF_TELEMETRY_LIMIT", "10000")),
            scoring_batch_size=int(os.getenv("WAF_SCORE_BATCH_SIZE", "32")),
            scoring_batch_wait_ms=float(os.getenv("WAF_SCORE_BATCH_WAIT_MS", "2")),
            account_pressure_bans=flag("WAF_ACCOUNT_PRESSURE_BANS", str(int(cls.account_pressure_bans))),
            wallet_capacity=float(os.getenv("WAF_WALLET_CAPACITY", str(cls.wallet_capacity))),
            wallet_refill_per_s=float(os.getenv("WAF_WALLET_REFILL_PER_S", str(cls.wallet_refill_per_s))),
        )
