"""Per-user access-token revocation marker (Single Logout for stateless access tokens).

Access tokens are stateless 15-min JWTs that resource servers validate offline, so
destroying the IdP session + revoking refresh tokens does NOT stop an already-issued
access token until it expires -- that is the window where a logged-out app (e.g. audio)
keeps accepting the token. ``revoke_user_access_tokens`` writes a per-user "revoked
before T" marker in the shared Redis; every resource server checks it (``is_user_access_
revoked``) right after verifying the JWT signature, and rejects any token whose ``iat`` is
earlier than T. The marker's TTL = access-token lifetime, after which no pre-logout token
can still be unexpired, so it self-cleans.
"""

from app.utils import redis as redis_util


async def test_no_marker_means_not_revoked():
    assert await redis_util.is_user_access_revoked("u1", 1000) is False


async def test_token_issued_before_marker_is_revoked():
    await redis_util.revoke_user_access_tokens("u1", at_epoch=2000.0, ttl=900)
    assert await redis_util.is_user_access_revoked("u1", 1999) is True


async def test_token_issued_at_or_after_marker_is_valid():
    # Strict `<`: a token minted at/after the logout instant (e.g. a fresh re-login) survives.
    await redis_util.revoke_user_access_tokens("u1", at_epoch=2000.0, ttl=900)
    assert await redis_util.is_user_access_revoked("u1", 2000) is False
    assert await redis_util.is_user_access_revoked("u1", 2001) is False


async def test_marker_is_scoped_per_user():
    await redis_util.revoke_user_access_tokens("u1", at_epoch=2000.0, ttl=900)
    assert await redis_util.is_user_access_revoked("u2", 1000) is False  # other user untouched


async def test_missing_iat_is_not_revoked():
    await redis_util.revoke_user_access_tokens("u1", at_epoch=2000.0, ttl=900)
    assert await redis_util.is_user_access_revoked("u1", None) is False


async def test_get_user_revoked_at_roundtrips_the_timestamp():
    assert await redis_util.get_user_revoked_at("u1") is None
    await redis_util.revoke_user_access_tokens("u1", at_epoch=1717000000.5, ttl=900)
    assert await redis_util.get_user_revoked_at("u1") == 1717000000.5


async def test_marker_has_ttl_so_it_self_cleans():
    await redis_util.revoke_user_access_tokens("u1", at_epoch=2000.0, ttl=900)
    r = await redis_util.get_redis()
    ttl = await r.ttl(f"{redis_util.USER_REVOKED_PREFIX}u1")
    assert 0 < ttl <= 900


async def test_fractional_marker_revokes_everything_up_to_the_logout_second():
    """Production markers are fractional (``time.time()``); JWT ``iat`` is integer seconds.

    The marker MUST stay a float so the over-revoke bias is correct: a logout at 2000.5
    has to revoke a token minted at 2000.2 (iat truncates to 2000), and it does. Storing
    the marker as ``int(2000.5)==2000`` would let that pre-logout token survive (``2000 <
    2000`` is False) -- a real revocation hole. The only "cost" is that a *re-login* landing
    in the same wall-clock second is also revoked, which cannot happen: re-auth takes several
    OAuth round-trips, so a fresh token always lands in a later second (iat >= 2001 -> kept).
    """
    await redis_util.revoke_user_access_tokens("u1", at_epoch=2000.5, ttl=900)
    assert await redis_util.is_user_access_revoked("u1", 2000) is True  # minted before logout -> revoked
    assert await redis_util.is_user_access_revoked("u1", 2001) is False  # next second (re-login) -> kept


async def test_is_user_access_revoked_fails_open_on_redis_error(monkeypatch):
    """Availability: the check runs on EVERY authenticated request across all apps. A Redis
    blip must not 500 the whole auth hot path -- fail open (treat as not-revoked) and log."""

    async def boom(_user_id):
        raise ConnectionError("redis down")

    monkeypatch.setattr(redis_util, "get_user_revoked_at", boom)
    assert await redis_util.is_user_access_revoked("u1", 1000) is False
