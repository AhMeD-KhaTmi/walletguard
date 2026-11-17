"""Behavioral ASGI protection. No dependency on the kernel/attack track."""

import asyncio
import hashlib
import ipaddress
import json
import math
import time
import uuid
from dataclasses import dataclass
from starlette.datastructures import Headers

from common.tokens import TOKENIZER_VERSION
from common.agent import DEFAULT_AGENT_STEPS, MAX_AGENT_STEPS, reserve_tokens
from waf.bans import BanStore
from waf.buckets import TokenBucket
from waf.features import FEATURE_VERSION, FeatureStore


@dataclass
class Verdict:
    decision: str = "allow"
    reason: str = ""
    status: int = 200
    retry_after: float = 0
    reserved: tuple | None = None


async def buffer_body(receive, limit):
    """Inspect a bounded prefix and replay original ASGI chunks without truncation."""
    messages, prefix, length = [], bytearray(), 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return None, None, False
        if message["type"] != "http.request":
            continue
        chunk = message.get("body", b"")
        if chunk or not message.get("more_body", False):
            messages.append(message)
        length += len(chunk)
        prefix.extend(chunk[:max(0, limit+1-len(prefix))])
        if length > limit or not message.get("more_body", False):
            break
    iterator = iter(messages)

    async def replay():
        return next(iterator, None) or await receive()

    return bytes(prefix), replay, length > limit


async def send_error(send, verdict, request_id):
    body = json.dumps({"error": verdict.reason}).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
               (b"x-request-id", request_id.encode())]
    if verdict.retry_after:
        headers.append((b"retry-after", str(max(1, math.ceil(verdict.retry_after))).encode()))
    await send({"type": "http.response.start", "status": verdict.status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class WAFMiddleware:
    def __init__(self, app, *, state):
        self.app, self.state, self.cfg = app, state, state.config
        self.tb = TokenBucket(state, max_keys=5*self.cfg.max_clients)
        self.bans = BanStore(state, shadow=self.cfg.mode == "observe")
        self.features = FeatureStore(state)
        state.waf = self

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        cfg = self.cfg
        started = time.perf_counter()
        ip = scope.get("client", ("unknown", 0))[0]
        path, method = scope["path"], scope["method"]
        try:
            local = ipaddress.ip_address(ip).is_loopback
        except ValueError:
            local = False
        operations = path in {"/health", "/_metrics/usage"} or path == "/dashboard" or path.startswith("/dashboard/")
        if (operations and local) or await self.state.allowlisted(ip):
            return await self.app(scope, receive, send)
        # Deny remote management traffic before recording it as application behavior.
        # Its dedicated route guard owns the HTTP 403 and does not consume budgets.
        if path == "/dashboard" or path.startswith("/dashboard/"):
            return await self.app(scope, receive, send)
        request_id = uuid.uuid4().hex
        scope["p20.request_id"] = request_id
        headers = Headers(scope=scope)  # Same first-value semantics as FastAPI Header.
        body, replay, oversize = await buffer_body(receive, cfg.max_body_bytes)
        if body is None:
            return
        try:
            parsed = json.loads(body or b"{}")
            parsed = parsed if isinstance(parsed, dict) else {}
        except (ValueError, UnicodeError):
            parsed = {}
        user = await self.state.user(headers.get("authorization"))
        extracted = {}
        score = None
        scoring_ms = 0
        if cfg.mode == "observe" or self.state.scorer:
            extracted = await self.features.extract(ip, path, headers, parsed, len(body))
            if self.state.scorer:
                before = time.perf_counter()
                score = await asyncio.to_thread(self.state.scorer.score, extracted)
                scoring_ms = (time.perf_counter()-before)*1000
        if cfg.mode == "observe":
            await self.state.log(cfg.features_stream, {
                **extracted, "run_id": cfg.run_id, "request_id": request_id,
                "ts_ms": int(time.time()*1000), "ip": ip, "method": method,
                "route": path, "feature_version": FEATURE_VERSION,
                "body_truncated": int(oversize),
            }, 500_000)
        verdict = await self._decide(ip, user, method, path, parsed, oversize, score)
        decision_ms = int(time.time()*1000)
        downstream = 0.0
        status = 0
        refunded = 0.0
        forwarded = False

        async def wrapper(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message = {**message, "headers": [*message.get("headers", []), (b"x-request-id", request_id.encode())]}
            await send(message)

        try:
            if cfg.mode == "enforce" and verdict.decision != "allow":
                if verdict.decision == "ban":
                    await self.bans.ban(ip, verdict.reason)
                status = verdict.status
                await send_error(send, verdict, request_id)
            else:
                forwarded = True
                before = time.perf_counter()
                try:
                    await self.app(scope, replay, wrapper)
                finally:
                    downstream = time.perf_counter()-before
        finally:
            usage = scope.get("p20.usage")
            generation = scope.get("p20.generation", "not_started")
            known = generation in {"not_started", "not_generated", "completed"} or not forwarded
            charged = usage.tokens_in+usage.tokens_out if usage else 0 if known else ""
            if verdict.reserved:
                key, reserve = verdict.reserved
                if known:
                    refunded = max(0, reserve-(charged or 0))
                    await asyncio.shield(self.tb.refund(key, cfg.budgets["llm_tok"][0], refunded))
            await self.features.record(ip, path, status)
            shown = verdict.decision
            if cfg.mode == "observe" and shown != "allow":
                shown = "would_"+shown
            fields = {
                "schema_version": "2", "run_id": cfg.run_id, "request_id": request_id,
                "ts_ms": decision_ms, "ip": ip, "client_id": user or "", "route": path,
                "decision": shown, "reason": verdict.reason, "mode": cfg.mode,
                "anomaly_score": score if score is not None else "",
                "llm_tokens_charged": charged, "tokens_reserved": verdict.reserved[1] if verdict.reserved else 0,
                "tokens_refunded": refunded, "accounting_status": ("known" if known else "uncertain") if path == "/chat" else "not_applicable",
                "sensor_status": "not_used", "latency_ms": round((time.perf_counter()-started-downstream)*1000, 3),
                "agent_steps_completed": scope.get("p20.agent_steps_completed", 0),
                "tokenizer": TOKENIZER_VERSION,
            }
            await self.state.log(cfg.decisions_stream, fields, 200_000)
            self.state.timing({"request_id": request_id, "run_id": cfg.run_id,
                                       "waf_overhead_ms": (time.perf_counter()-started-downstream)*1000,
                                       "scoring_ms": scoring_ms, "degraded": self.tb.degraded})

    async def _decide(self, ip, user, method, path, body, oversize, score):
        cfg = self.cfg
        if oversize:
            return Verdict("block", "body_too_large", 413)
        if await self.bans.is_banned(ip):
            return Verdict("block", "banned", 403)
        if cfg.enable_honeypot and any(path == p or path.startswith(p+"/") for p in cfg.honeypot_paths):
            return Verdict("ban", "honeypot", 404)
        verdict = await self._budgets(ip, user, method, path, body) if cfg.enable_buckets else Verdict()
        if verdict.decision == "throttle":
            if await self.bans.strike(ip, "budget") >= cfg.strike_limit:
                verdict.decision, verdict.reason = "ban", "budget"
            return verdict
        if verdict.decision != "allow":
            return verdict
        if score is not None and self.state.scorer.is_anomalous(score):
            count = await self.bans.strike(ip, "anomaly")
            if count >= cfg.strike_limit and await self.bans.has_budget_strike(ip):
                return Verdict("ban", "anomaly", 403, reserved=verdict.reserved)
            verdict.reason = "anomalous_strike"
        return verdict

    async def _budgets(self, ip, user, method, path, body):
        cfg = self.cfg
        prefix = "p20:shadow:bkt:" if cfg.mode == "observe" else "p20:bkt:"

        async def take(name, identity, cost=1):
            capacity, rate = cfg.budgets[name]
            key = f"{prefix}{name}:{identity}"
            if cost > capacity:
                return Verdict("block", "token_cost_exceeds_capacity", 400)
            ok, _, retry = await self.tb.take(key, capacity, rate, cost)
            return Verdict() if ok else Verdict("throttle", name, 429, retry_after=retry)

        result = await take("ip_req", ip)
        if result.decision != "allow":
            return result
        if path == "/login" and method == "POST":
            result = await take("login_ip", ip)
            if result.decision != "allow":
                return result
            account = body.get("username")
            if isinstance(account, str) and account:
                result = await take("login_acct", hashlib.sha256(account.encode()).hexdigest())
                if result.decision != "allow":
                    return result
        if path == "/chat" and method == "POST" and user:
            output, prompt = body.get("max_output_tokens", 256), body.get("prompt")
            steps = body.get("agent_steps", DEFAULT_AGENT_STEPS)
            if (type(output) is not int or output < 1 or not isinstance(prompt, str)
                    or type(steps) is not int or not 1 <= steps <= MAX_AGENT_STEPS):
                return Verdict()  # The shared API schema owns invalid-input responses.
            if output > cfg.max_output_cap:
                return Verdict("block", "max_output_exceeds_policy", 400)
            result = await take("chat_req", user)
            if result.decision != "allow":
                return result
            reserve = reserve_tokens(prompt, output, steps)
            result = await take("llm_tok", user, reserve)
            if result.decision == "allow":
                result.reserved = (f"{prefix}llm_tok:{user}", reserve)
            return result
        return Verdict()
