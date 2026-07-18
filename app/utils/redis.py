from time import time as current_timestamp
from time import time_ns

import redis.asyncio as redis
from redis.exceptions import WatchError

from app.config import get_settings

settings = get_settings()

redis_client: redis.Redis | None = None


async def get_redis() -> redis.Redis:
    global redis_client
    if redis_client is None:
        redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    return redis_client


async def close_redis():
    global redis_client
    if redis_client:
        await redis_client.close()
        redis_client = None


# ==================== Token Blacklist ====================

BLACKLIST_PREFIX = "token_blacklist:"


async def blacklist_token(jti: str, expires_in_seconds: int):
    """Add a token JTI to the blacklist with auto-expiry."""
    r = await get_redis()
    await r.setex(f"{BLACKLIST_PREFIX}{jti}", expires_in_seconds, "1")


async def is_token_blacklisted(jti: str) -> bool:
    """Check if a token JTI is blacklisted."""
    r = await get_redis()
    return await r.exists(f"{BLACKLIST_PREFIX}{jti}") > 0


# ==================== OAuth Auth Code ====================

AUTH_CODE_PREFIX = "auth_code:"


async def store_auth_code(code: str, payload: dict, ttl: int):
    """Store a one-time auth code → JSON payload with auto-expiry."""
    import json

    r = await get_redis()
    await r.setex(f"{AUTH_CODE_PREFIX}{code}", ttl, json.dumps(payload))


async def consume_auth_code(code: str) -> dict | None:
    """Atomically read and delete an auth code. Returns payload or None."""
    import json

    r = await get_redis()
    raw = await r.getdel(f"{AUTH_CODE_PREFIX}{code}")
    if raw is None:
        return None
    return json.loads(raw)


# ==================== Passwordless Email Login ====================

EMAIL_FLOW_PREFIX = "email_flow:"
EMAIL_FLOW_RECOVERY_PREFIX = "email_flow_recovery:"
EMAIL_BROWSER_FLOWS_PREFIX = "email_browser_flows:"
EMAIL_OTP_PREFIX = "email_otp:"
EMAIL_COOLDOWN_PREFIX = "email_cooldown:"
EMAIL_RATE_EMAIL_PREFIX = "email_rate_email:"
EMAIL_RATE_IP_PREFIX = "email_rate_ip:"
EMAIL_RATE_FLOW_PREFIX = "email_rate_flow:"
EMAIL_RATE_SEND_GLOBAL_KEY = "email_rate_send_global"
EMAIL_RATE_AUTHORIZE_IP_PREFIX = "email_rate_authorize_ip:"
EMAIL_RATE_AUTHORIZE_CLIENT_PREFIX = "email_rate_authorize_client:"
EMAIL_RATE_AUTHORIZE_GLOBAL_KEY = "email_rate_authorize_global"


def _remaining_ttl(ttl: int, fallback: int) -> int:
    """将 Redis TTL 转为可直接用于 Retry-After 的正整数。"""
    return max(ttl, 1) if ttl >= 0 else fallback


async def _acquire_fixed_window_slot(
    r: redis.Redis,
    counters: tuple[tuple[str, int], ...],
    *,
    window_seconds: int,
    cooldown: tuple[str, int] | None = None,
) -> tuple[bool, int]:
    """原子检查并提交一组固定窗口计数，可选附加冷却键。

    WATCH 保证所有维度基于同一快照作出决定；只有全部维度均允许时才在
    一个 MULTI 中写入 cooldown 和计数。拒绝请求不会污染其他维度，已有
    计数使用 KEEPTTL，因此窗口不会因后续请求滑动。
    """
    counter_keys = [key for key, _limit in counters]
    watched_keys = [*counter_keys, *([cooldown[0]] if cooldown else [])]
    while True:
        pipe = r.pipeline()
        try:
            await pipe.watch(*watched_keys)
            raw_counts = await pipe.mget(counter_keys)
            counter_ttls = [int(await pipe.ttl(key)) for key in counter_keys]
            cooldown_exists = bool(await pipe.exists(cooldown[0])) if cooldown else False
            cooldown_ttl = int(await pipe.ttl(cooldown[0])) if cooldown_exists and cooldown else -2

            # WATCH 只会在 EXEC 时报告过期导致的键变化；拒绝路径不会执行 EXEC，
            # 因此读值后恰好过期的键必须主动重取，不能误报完整 fallback 窗口。
            if (cooldown_exists and cooldown_ttl == -2) or any(
                value is not None and ttl == -2 for value, ttl in zip(raw_counts, counter_ttls, strict=True)
            ):
                continue

            retry_after = []
            if cooldown_exists and cooldown:
                retry_after.append(_remaining_ttl(cooldown_ttl, cooldown[1]))
            counts = [int(value) if value is not None else 0 for value in raw_counts]
            for count, ttl, (_key, limit) in zip(counts, counter_ttls, counters, strict=True):
                if count >= limit:
                    retry_after.append(_remaining_ttl(ttl, window_seconds))
            if retry_after:
                await pipe.unwatch()
                return False, max(retry_after)

            pipe.multi()
            if cooldown:
                pipe.set(cooldown[0], "1", ex=cooldown[1])
            for count, raw_value, (key, _limit) in zip(counts, raw_counts, counters, strict=True):
                if raw_value is not None:
                    pipe.set(key, count + 1, keepttl=True)
                else:
                    pipe.set(key, count + 1, ex=window_seconds)
            await pipe.execute()
            return True, 0
        except WatchError:
            continue
        finally:
            await pipe.reset()


async def acquire_email_authorize_slot(
    client_digest: str,
    ip_digest: str,
    *,
    window_seconds: int,
    client_limit: int,
    ip_limit: int,
    global_limit: int,
) -> tuple[bool, int]:
    """创建邮箱授权 flow 前执行 IP、client 与全局三层固定窗口门禁。"""
    r = await get_redis()
    return await _acquire_fixed_window_slot(
        r,
        (
            (f"{EMAIL_RATE_AUTHORIZE_IP_PREFIX}{ip_digest}", ip_limit),
            (f"{EMAIL_RATE_AUTHORIZE_CLIENT_PREFIX}{client_digest}", client_limit),
            (EMAIL_RATE_AUTHORIZE_GLOBAL_KEY, global_limit),
        ),
        window_seconds=window_seconds,
    )


async def store_email_flow(flow_id: str, payload: dict, ttl: int, recovery_ttl: int):
    import json

    r = await get_redis()
    await r.setex(f"{EMAIL_FLOW_PREFIX}{flow_id}", ttl, json.dumps(payload))
    recovery = {
        key: payload[key]
        for key in ("client_id", "redirect_uri", "app_state", "nonce_mac", "csrf_mac")
        if key in payload
    }
    await r.setex(f"{EMAIL_FLOW_RECOVERY_PREFIX}{flow_id}", recovery_ttl, json.dumps(recovery))


async def get_email_flow(flow_id: str) -> dict | None:
    import json

    r = await get_redis()
    raw = await r.get(f"{EMAIL_FLOW_PREFIX}{flow_id}")
    return json.loads(raw) if raw is not None else None


async def get_email_flow_recovery(flow_id: str) -> dict | None:
    import json

    r = await get_redis()
    raw = await r.get(f"{EMAIL_FLOW_RECOVERY_PREFIX}{flow_id}")
    return json.loads(raw) if raw is not None else None


async def delete_email_flow(flow_id: str):
    r = await get_redis()
    await r.delete(f"{EMAIL_FLOW_PREFIX}{flow_id}")


async def register_email_flow_for_browser(
    browser_digest: str,
    flow_id: str,
    *,
    max_flows: int,
    ttl: int,
):
    """登记同一浏览器的授权流，并删除超出上限的最旧流。"""
    r = await get_redis()
    index_key = f"{EMAIL_BROWSER_FLOWS_PREFIX}{browser_digest}"
    await r.zadd(index_key, {flow_id: time_ns()})
    await r.expire(index_key, ttl)
    count = await r.zcard(index_key)
    overflow = count - max_flows
    if overflow <= 0:
        return
    stale = await r.zrange(index_key, 0, overflow - 1)
    if not stale:
        return
    pipe = r.pipeline(transaction=True)
    for stale_flow_id in stale:
        pipe.delete(
            f"{EMAIL_FLOW_PREFIX}{stale_flow_id}",
            f"{EMAIL_FLOW_RECOVERY_PREFIX}{stale_flow_id}",
            f"{EMAIL_OTP_PREFIX}{stale_flow_id}",
        )
    pipe.zrem(index_key, *stale)
    await pipe.execute()


async def stage_email_otp(flow_id: str, payload: dict, ttl: int):
    """在发送前暂存待发送验证码，同时保留上一个已确认送达的验证码。"""
    import json

    r = await get_redis()
    key = f"{EMAIL_OTP_PREFIX}{flow_id}"
    while True:
        pipe = r.pipeline()
        try:
            await pipe.watch(key)
            raw = await pipe.get(key)
            current = json.loads(raw) if raw is not None else {}
            active = current.get("active")
            if active and float(active.get("expires_at", 0)) <= current_timestamp():
                active = None
            record = {
                "active": active,
                "pending": payload,
                "attempts": 0,
            }
            pipe.multi()
            pipe.set(key, json.dumps(record), ex=ttl)
            await pipe.execute()
            return
        except WatchError:
            continue
        finally:
            await pipe.reset()


async def promote_email_otp(flow_id: str, expected_pending_mac: str):
    """发送明确成功后，将 pending 提升为唯一 active，旧验证码立即失效。"""
    import hmac
    import json

    r = await get_redis()
    key = f"{EMAIL_OTP_PREFIX}{flow_id}"
    while True:
        pipe = r.pipeline()
        try:
            await pipe.watch(key)
            raw = await pipe.get(key)
            if raw is None:
                return
            record = json.loads(raw)
            pending = record.get("pending")
            if not pending or not hmac.compare_digest(str(pending.get("code_mac", "")), expected_pending_mac):
                return
            record = {"active": pending, "pending": None, "attempts": 0}
            pipe.multi()
            pipe.set(key, json.dumps(record), keepttl=True)
            await pipe.execute()
            return
        except WatchError:
            continue
        finally:
            await pipe.reset()


async def delete_email_otp(flow_id: str):
    r = await get_redis()
    await r.delete(f"{EMAIL_OTP_PREFIX}{flow_id}")


async def consume_email_otp(flow_id: str, expected_mac: str, max_attempts: int) -> dict | None:
    """原子校验并消费验证码；错误尝试也在同一 WATCH 事务中递增。"""
    import hmac
    import json

    r = await get_redis()
    key = f"{EMAIL_OTP_PREFIX}{flow_id}"
    while True:
        pipe = r.pipeline()
        try:
            await pipe.watch(key)
            raw = await pipe.get(key)
            if raw is None:
                return None
            record = json.loads(raw)
            attempts = int(record.get("attempts", 0))
            matched = None
            for candidate in (record.get("active"), record.get("pending")):
                if (
                    candidate
                    and float(candidate.get("expires_at", 0)) > current_timestamp()
                    and hmac.compare_digest(str(candidate.get("code_mac", "")), expected_mac)
                ):
                    matched = candidate
                    break
            pipe.multi()
            if matched is not None:
                pipe.delete(key)
                await pipe.execute()
                return matched
            attempts += 1
            if attempts >= max_attempts:
                pipe.delete(key)
            else:
                record["attempts"] = attempts
                pipe.set(key, json.dumps(record), keepttl=True)
            await pipe.execute()
            return None
        except WatchError:
            continue
        finally:
            await pipe.reset()


async def acquire_email_send_slot(
    email_digest: str,
    ip_digest: str,
    flow_id: str,
    *,
    cooldown_seconds: int,
    window_seconds: int,
    email_limit: int,
    ip_limit: int,
    flow_limit: int,
    global_limit: int,
) -> tuple[bool, int]:
    """对匿名邮箱摘要和可信客户端 IP 摘要执行冷却及窗口限流。"""
    r = await get_redis()
    cooldown_key = f"{EMAIL_COOLDOWN_PREFIX}{email_digest}"
    return await _acquire_fixed_window_slot(
        r,
        (
            (f"{EMAIL_RATE_EMAIL_PREFIX}{email_digest}", email_limit),
            (f"{EMAIL_RATE_IP_PREFIX}{ip_digest}", ip_limit),
            (f"{EMAIL_RATE_FLOW_PREFIX}{flow_id}", flow_limit),
            (EMAIL_RATE_SEND_GLOBAL_KEY, global_limit),
        ),
        window_seconds=window_seconds,
        cooldown=(cooldown_key, cooldown_seconds),
    )


# ==================== SSO IdP Session ====================

SESSION_PREFIX = "sso_session:"


async def create_session(sid: str, payload: dict, ttl: int):
    """Store an IdP session → JSON payload with a sliding TTL."""
    import json

    r = await get_redis()
    await r.setex(f"{SESSION_PREFIX}{sid}", ttl, json.dumps(payload))


async def get_session(sid: str) -> dict | None:
    """Read a session payload without consuming it. Returns None if absent/expired."""
    import json

    r = await get_redis()
    raw = await r.get(f"{SESSION_PREFIX}{sid}")
    if raw is None:
        return None
    return json.loads(raw)


async def touch_session(sid: str, ttl: int):
    """Slide the session's TTL forward without reading the payload."""
    r = await get_redis()
    await r.expire(f"{SESSION_PREFIX}{sid}", ttl)


async def delete_session(sid: str):
    """Delete a session (logout / absolute-lifetime expiry)."""
    r = await get_redis()
    await r.delete(f"{SESSION_PREFIX}{sid}")
