"""get_current_user rejects access tokens revoked by a Single Logout.

After the JWT signature/type check, get_current_user consults the per-user revocation
marker (shared Redis). A still-unexpired access token whose ``iat`` predates the user's
logout must be rejected with 401 -- this is what makes "logout once = logout everywhere"
bite on the NEXT request, even though the JWT itself is still cryptographically valid.
decode_token is stubbed so the test targets the revocation gate, not JWT crypto.
"""

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.security import deps
from app.security import revocation as redis_util


def _creds() -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials="any.jwt.value")


def _stub_decode(monkeypatch, *, sub: str, iat: int):
    monkeypatch.setattr(
        deps,
        "decode_token",
        lambda _tok, verify_type=None: {"sub": sub, "iat": iat, "email": "a@b.c", "type": "access"},
    )


async def test_rejects_token_issued_before_logout(monkeypatch):
    _stub_decode(monkeypatch, sub="u1", iat=1000)
    await redis_util.revoke_user_access_tokens("u1", at_epoch=2000.0, ttl=900)

    with pytest.raises(HTTPException) as ei:
        await deps.get_current_user(credentials=_creds())
    assert ei.value.status_code == 401


async def test_accepts_token_issued_after_logout(monkeypatch):
    # A fresh re-login mints a token with iat > the revocation instant -> still valid.
    _stub_decode(monkeypatch, sub="u1", iat=3000)
    await redis_util.revoke_user_access_tokens("u1", at_epoch=2000.0, ttl=900)

    user = await deps.get_current_user(credentials=_creds())
    assert user.sub == "u1"


async def test_accepts_when_no_revocation_marker(monkeypatch):
    _stub_decode(monkeypatch, sub="u2", iat=1000)

    user = await deps.get_current_user(credentials=_creds())
    assert user.sub == "u2"


async def test_redis_outage_does_not_break_the_auth_hot_path(monkeypatch):
    """The revocation check is now a Redis GET on EVERY authenticated request. A Redis
    outage must NOT cascade to a 500 across every app -- the request proceeds (fail-open),
    trading a bounded (<=15-min) revocation lag for availability."""
    _stub_decode(monkeypatch, sub="u1", iat=1000)

    async def boom(_user_id):
        raise ConnectionError("redis down")

    monkeypatch.setattr(redis_util, "get_user_revoked_at", boom)

    user = await deps.get_current_user(credentials=_creds())  # must not raise 500
    assert user.sub == "u1"
