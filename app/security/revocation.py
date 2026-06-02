"""Per-user access-token revocation marker (Single Logout for stateless access tokens).

Access tokens are stateless JWTs that resource servers validate offline, so destroying the
IdP session and revoking refresh tokens does NOT stop an already-issued access token until it
expires -- the window where a logged-out app keeps accepting the token. ``/auth/logout`` writes
a per-user "revoked before T" marker into the shared Redis; every resource server checks it
right after verifying the JWT signature and rejects any token whose ``iat`` predates T.

This lives in the ``security`` layer (not ``utils``) on purpose: the check runs inside
``get_current_user`` and the architecture contract forbids ``security`` importing ``utils``, so
revocation owns its own Redis client built from ``config`` (the same ``redis_url`` everything
else uses -- a separate connection pool to the same shared instance).
"""

import logging

import redis.asyncio as redis

from app.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

redis_client: redis.Redis | None = None

USER_REVOKED_PREFIX = "revoked_user:"


async def get_redis() -> redis.Redis:
    global redis_client
    if redis_client is None:
        redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    return redis_client


async def revoke_user_access_tokens(user_id: str, at_epoch: float, ttl: int):
    """Mark every access token this user holds with ``iat`` < ``at_epoch`` as revoked.

    TTL = access-token lifetime: once it elapses no pre-logout token can still be unexpired,
    so the key self-cleans. Stored as a float so the over-revoke comparison below is correct.
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
