import redis.asyncio as redis

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
