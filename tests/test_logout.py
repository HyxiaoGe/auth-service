"""Single Logout (SLO): POST /auth/logout.

Deletes the IdP session, clears the cookie, and -- crucially -- revokes ALL of
the user's refresh tokens (without that, a leaked refresh token keeps minting
access tokens and the "logout" is meaningless). Optional post_logout_redirect_uri
is honored only if it belongs to a registered application.
"""

import uuid

from fastapi import Request, Response
from fastapi.responses import RedirectResponse

from app.routers import auth
from app.schemas import LogoutRequest
from app.utils import redis as redis_util


def _req_with_session(sid):
    headers = [(b"cookie", f"sso_session={sid}".encode())] if sid else []
    return Request({"type": "http", "headers": headers})


async def test_logout_deletes_session_revokes_tokens_and_clears_cookie(monkeypatch):
    uid = uuid.uuid4()
    await redis_util.create_session("s1", {"user_id": str(uid), "auth_time": 111}, ttl=100)

    revoked = {}

    async def fake_revoke(user_id, db):
        revoked["uid"] = user_id

    monkeypatch.setattr(auth.auth_service, "_revoke_all_user_tokens", fake_revoke)

    resp = Response()
    await auth.logout(request=_req_with_session("s1"), response=resp, payload=None, db=None)

    assert await redis_util.get_session("s1") is None  # session destroyed
    assert revoked["uid"] == uid  # refresh tokens revoked for the session's user
    assert "Max-Age=0" in resp.headers["set-cookie"]  # cookie cleared


async def test_logout_without_session_is_noop_but_clears_cookie(monkeypatch):
    calls = {"n": 0}

    async def fake_revoke(user_id, db):
        calls["n"] += 1

    monkeypatch.setattr(auth.auth_service, "_revoke_all_user_tokens", fake_revoke)

    resp = Response()
    await auth.logout(request=_req_with_session(None), response=resp, payload=None, db=None)

    assert calls["n"] == 0  # nothing to revoke
    assert "Max-Age=0" in resp.headers["set-cookie"]


async def test_logout_redirects_to_validated_post_logout_uri(monkeypatch):
    await redis_util.create_session("s2", {"user_id": str(uuid.uuid4())}, ttl=100)

    async def fake_revoke(user_id, db):
        return None

    async def fake_registered(uri, db):
        return True

    monkeypatch.setattr(auth.auth_service, "_revoke_all_user_tokens", fake_revoke)
    monkeypatch.setattr(auth, "_is_registered_redirect", fake_registered)

    resp = Response()
    result = await auth.logout(
        request=_req_with_session("s2"),
        response=resp,
        payload=LogoutRequest(post_logout_redirect_uri="https://app.example/loggedout"),
        db=None,
    )

    assert isinstance(result, RedirectResponse)
    assert result.status_code == 302
    assert result.headers["location"] == "https://app.example/loggedout"
    assert "Max-Age=0" in result.headers["set-cookie"]  # cookie cleared on the redirect too


async def test_logout_ignores_unregistered_post_logout_uri(monkeypatch):
    await redis_util.create_session("s3", {"user_id": str(uuid.uuid4())}, ttl=100)

    async def fake_revoke(user_id, db):
        return None

    async def fake_registered(uri, db):
        return False  # open-redirect guard

    monkeypatch.setattr(auth.auth_service, "_revoke_all_user_tokens", fake_revoke)
    monkeypatch.setattr(auth, "_is_registered_redirect", fake_registered)

    resp = Response()
    result = await auth.logout(
        request=_req_with_session("s3"),
        response=resp,
        payload=LogoutRequest(post_logout_redirect_uri="https://evil.example/x"),
        db=None,
    )

    assert not isinstance(result, RedirectResponse)  # refused -> plain response
    assert "Max-Age=0" in resp.headers["set-cookie"]
