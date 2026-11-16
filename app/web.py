"""Local UI and read-only management views, before the Member A integration."""

import ipaddress
import json
import math
import time
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse
from redis.exceptions import RedisError

STATIC = Path(__file__).with_name("static")
PAGES = Path(__file__).with_name("templates")
PAGE_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
}


async def require_management(request: Request) -> None:
    """Use the connection source, never headers, to restrict management pages."""
    host = request.client.host if request.client else ""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise HTTPException(403, "management access only")
    if address.is_loopback:
        return
    try:
        if await request.app.state.redis.sismember("p20:allowlist", host):
            return
    except RedisError:
        pass  # Unknown nonlocal management identities are never granted access.
    raise HTTPException(403, "management access only")


def web_router() -> APIRouter:
    router = APIRouter()

    @router.get("/", include_in_schema=False)
    async def demo():
        return FileResponse(PAGES / "index.html", headers=PAGE_HEADERS)

    @router.get("/dashboard", include_in_schema=False, dependencies=[Depends(require_management)])
    async def dashboard():
        return FileResponse(PAGES / "dashboard.html", headers=PAGE_HEADERS)

    @router.get("/dashboard/data", tags=["Management"], dependencies=[Depends(require_management)])
    async def dashboard_data(request: Request, response: Response):
        response.headers["Cache-Control"] = "no-store"
        r = request.app.state.redis
        result = {
            "updated_ms": int(time.time() * 1000),
            "mode": request.app.state.settings.waf_mode,
            "integration": "not_connected",
            "dependencies": {"redis": "unavailable", "mock_llm": "unavailable"},
            "usage": None, "decisions": None, "bans": None,
            "telemetry_note": "WAF telemetry awaits verified schema-v2 output.",
            "limits": {"decisions": 20, "ban_keys_scanned": 200},
            "controls": {"buckets": request.app.state.waf_config.enable_buckets,
                         "honeypot": request.app.state.waf_config.enable_honeypot,
                         "ml_loaded": request.app.state.runtime.scorer is not None},
            "validation": "application_checks_only; joint_attack_and_kernel_checks_pending",
            "outage_usage": request.app.state.runtime.outage_usage,
        }
        try:
            await r.ping()
            result["dependencies"]["redis"] = "ok"
            raw = await r.hgetall("p20:app:usage:total")
            usage = {
                field: float(raw.get(field, 0)) if field == "cost_usd" else int(raw.get(field, 0))
                for field in ("requests", "tokens_in", "tokens_out", "cost_usd")
            }
            if any(not math.isfinite(value) or value < 0 for value in usage.values()):
                raise ValueError("invalid usage counters")
            result["usage"] = usage
            # Read only B-owned application output. Never connect to A's signal/map state.
            rows = await r.xrevrange("p20:stream:waf_decisions", count=20)
            if rows and all(row.get("schema_version") == "2" for _, row in rows):
                fields = ("ts_ms", "ip", "route", "decision", "reason", "anomaly_score")
                result["decisions"] = [{k: row.get(k, "") for k in fields} for _, row in rows]
                result["telemetry_note"] = "Showing application decisions; attack/kernel validation remains pending."
            bans, keys = [], []
            async for key in r.scan_iter(match="p20:ban:*", count=50):
                keys.append(key)
                if len(keys) > 200:
                    break
            pipe = r.pipeline(transaction=False)
            for key in keys[:200]:
                pipe.get(key)
                pipe.ttl(key)
            values = await pipe.execute()
            for raw_ban, ttl in zip(values[::2], values[1::2]):
                try:
                    ban = json.loads(raw_ban or "{}")
                    if isinstance(ban, dict) and ban.get("source") == "waf" and ttl > 0:
                        bans.append({"ip": str(ban.get("ip", "")), "reason": str(ban.get("reason", "")), "ttl_s": ttl})
                except (ValueError, TypeError):
                    continue
            result["bans"] = bans
            result["bans_truncated"] = len(keys) > 200
        except (RedisError, ValueError, TypeError):
            result["telemetry_note"] = "Redis telemetry could not be read completely; refresh after recovery."
        try:
            health = await request.app.state.llm.get("/health")
            if health.status_code == 200 and health.json().get("backend") == "synthetic":
                result["dependencies"]["mock_llm"] = "ok"
        except (httpx.HTTPError, ValueError, AttributeError):
            pass
        return result

    @router.get("/dashboard/evidence", tags=["Management"], dependencies=[Depends(require_management)])
    async def evidence(request: Request, response: Response):
        response.headers["Cache-Control"] = "no-store"
        state = request.app.state.runtime
        return {
            "run_id": state.config.run_id,
            "kind": "process_local_bounded_evidence_not_final_benchmark",
            "timings": list(state.timings), "outage_events": list(state.outage_events),
            "outage_usage": state.outage_usage,
            "dropped_events": state.dropped_events, "dropped_timings": state.dropped_timings,
            "cache_evictions": state.cache_evictions,
            "note": "Outage Redis commits may be uncertain; do not automatically merge or double-add these totals.",
        }

    return router
