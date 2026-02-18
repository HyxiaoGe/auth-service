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
