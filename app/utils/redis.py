import logging

import redis.asyncio as redis

from app.config import get_settings

logger = logging.getLogger(__name__)

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


# ==================== User-wide access-token revocation (Single Logout) ====================

USER_REVOKED_PREFIX = "revoked_user:"


async def revoke_user_access_tokens(user_id: str, at_epoch: float, ttl: int):
    """Mark every access token this user holds with ``iat`` < ``at_epoch`` as revoked.

    Access tokens are stateless JWTs that resource servers validate offline, so destroying
    the IdP session and revoking refresh tokens does not stop an already-issued access token
    until it expires -- the window where a logged-out app keeps accepting the token. This
    per-user marker lets every resource server reject those in-flight tokens on the next
    request. TTL = access-token lifetime: once it elapses no pre-logout token can still be
    unexpired, so the key self-cleans.
    """
    r = await get_redis()
    await r.setex(f"{USER_REVOKED_PREFIX}{user_id}", ttl, str(float(at_epoch)))


async def get_user_revoked_at(user_id: str) -> float | None:
    """Epoch seconds before which this user's access tokens are revoked, or None."""
    r = await get_redis()
    raw = await r.get(f"{USER_REVOKED_PREFIX}{user_id}")
    return float(raw) if raw is not None else None


async def is_user_access_revoked(user_id: str, token_iat: float | int | None) -> bool:
    """True iff a revocation marker exists and the token was issued before it (iat < marker).

    The marker is a float wall-clock instant (``time.time()``) while a JWT ``iat`` is integer
    epoch seconds, so strict ``<`` deliberately over-revokes: EVERY token minted before the
    logout instant is rejected (the security guarantee), and the only false-revoke would be a
    re-login completing within the same wall-clock second -- impossible across an OAuth
    re-auth. (Storing the marker as an int instead would let a same-second *pre*-logout token
    survive, a real hole; see ``test_fractional_marker_revokes_everything_up_to_the_logout_second``.)

    Runs on every authenticated request, so it FAILS OPEN: if the shared Redis is unreachable
    we log and treat the token as not-revoked rather than 500 the whole auth hot path. The
    revocation lag then degrades to the token's own <=15-min expiry until Redis recovers.
    """
    if token_iat is None:
        return False
    try:
        revoked_at = await get_user_revoked_at(user_id)
    except Exception:
        logger.warning("revocation check unavailable (Redis); failing open", exc_info=True)
        return False
    if revoked_at is None:
        return False
    return float(token_iat) < revoked_at


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
