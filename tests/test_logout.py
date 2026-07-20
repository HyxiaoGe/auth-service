"""Single Logout (SLO): POST /auth/logout.

Deletes the IdP session, clears the cookie, and -- crucially -- revokes ALL of the
user's refresh tokens (without that, a leaked refresh token keeps minting access tokens
and the "logout" is meaningless). An optional post_logout_redirect_uri may arrive as a
JSON body OR as an urlencoded form field -- the latter so a top-level
``<form method=POST>`` can deliver it cross-site while the SameSite=Lax session cookie
rides the navigation. It is honored only if it is a registered redirect_uri, scoped to
the calling app when client_id is supplied.
"""

import json
import uuid
from urllib.parse import urlencode

from fastapi import Request, Response
from fastapi.responses import RedirectResponse

from app.routers import auth
from app.security import revocation
from app.utils import redis as redis_util

SID_ONE = "browser-session-sid-0001"
SID_EMAIL = "browser-session-sid-email"
SID_FIVE = "browser-session-sid-0005"
SID_SIX = "browser-session-sid-0006"
SID_SEVEN = "browser-session-sid-0007"
SID_TWO = "browser-session-sid-0002"
SID_THREE = "browser-session-sid-0003"
SID_FOUR = "browser-session-sid-0004"


def _request(sid=None, body=b"", content_type=None):
    headers = []
    if sid:
        headers.append((b"cookie", f"sso_session={sid}".encode()))
    if content_type:
        headers.append((b"content-type", content_type.encode()))
    scope = {"type": "http", "method": "POST", "headers": headers}

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive=receive)


def _form(**fields):
    return urlencode(fields).encode(), "application/x-www-form-urlencoded"


def _json_body(**fields):
    return json.dumps(fields).encode(), "application/json"


async def test_logout_deletes_session_revokes_sid_tokens_and_clears_cookie(monkeypatch):
    uid = uuid.uuid4()
    await redis_util.create_session(
        SID_ONE, {"session_id": SID_ONE, "user_id": str(uid), "auth_time": 111}, ttl=100
    )

    revoked = {}

    async def fake_revoke(sid, db):
        revoked["sid"] = sid

    monkeypatch.setattr(auth.auth_service, "revoke_session_refresh_tokens", fake_revoke)

    body, content_type = _json_body(session_sid=SID_ONE)
    resp = Response()
    await auth.logout(
        request=_request(sid=SID_ONE, body=body, content_type=content_type),
        response=resp,
        db=None,
    )

    assert await redis_util.get_session(SID_ONE) is None  # session destroyed
    assert revoked["sid"] == SID_ONE
    assert await revocation.is_sid_revoked(SID_ONE) is True
    assert "Max-Age=0" in resp.headers["set-cookie"]  # cookie cleared


async def test_email_otp_sso_session_uses_sid_scoped_logout_path(monkeypatch):
    uid = uuid.uuid4()
    await redis_util.create_session(
        SID_EMAIL,
        {"session_id": SID_EMAIL, "user_id": str(uid), "auth_time": 111, "amr": ["email_otp"]},
        ttl=100,
    )
    revoked = {}

    async def fake_revoke(sid, db):
        revoked["sid"] = sid

    monkeypatch.setattr(auth.auth_service, "revoke_session_refresh_tokens", fake_revoke)
    body, content_type = _json_body(session_sid=SID_EMAIL)
    response = Response()
    await auth.logout(
        request=_request(sid=SID_EMAIL, body=body, content_type=content_type),
        response=response,
        db=None,
    )

    assert await redis_util.get_session(SID_EMAIL) is None
    assert revoked["sid"] == SID_EMAIL
    assert "Max-Age=0" in response.headers["set-cookie"]


async def test_logout_writes_sid_marker_without_revoking_whole_user(monkeypatch):
    uid = uuid.uuid4()
    await redis_util.create_session(SID_FIVE, {"session_id": SID_FIVE, "user_id": str(uid)}, ttl=100)

    async def fake_revoke(sid, db):
        return None

    monkeypatch.setattr(auth.auth_service, "revoke_session_refresh_tokens", fake_revoke)

    body, content_type = _json_body(session_sid=SID_FIVE)
    resp = Response()
    await auth.logout(
        request=_request(sid=SID_FIVE, body=body, content_type=content_type),
        response=resp,
        db=None,
    )

    assert await revocation.get_user_revoked_at(str(uid)) is None
    assert await revocation.is_sid_revoked(SID_FIVE) is True

    # TTL = access-token lifetime (+slack) so the marker self-cleans once no pre-logout
    # token can still be unexpired. Pin it here so a wrong TTL in logout() can't slip through.
    r = await revocation.get_redis()
    ttl = await r.ttl(f"{revocation.SID_REVOKED_PREFIX}{SID_FIVE}")
    expected = auth.settings.sid_revocation_ttl_seconds
    assert expected - 5 < ttl <= expected


async def test_logout_rejects_stale_app_target_without_touching_current_cookie(monkeypatch):
    uid = uuid.uuid4()
    await redis_util.create_session(SID_SIX, {"session_id": SID_SIX, "user_id": str(uid)}, ttl=100)

    async def fake_revoke(sid, db):
        return None

    monkeypatch.setattr(auth.auth_service, "revoke_session_refresh_tokens", fake_revoke)

    body, content_type = _json_body(session_sid="different-session-sid-123")
    resp = Response()
    result = await auth.logout(
        request=_request(sid=SID_SIX, body=body, content_type=content_type),
        response=resp,
        db=None,
    )

    assert result.status_code == 409
    assert await redis_util.get_session(SID_SIX) is not None
    assert "set-cookie" not in resp.headers


async def test_logout_all_keeps_explicit_account_wide_generation_path(monkeypatch):
    uid = uuid.uuid4()
    await redis_util.create_session(SID_SEVEN, {"session_id": SID_SEVEN, "user_id": str(uid)}, ttl=100)
    called = {}

    async def fake_logout_user(user_id, db):
        called["uid"] = user_id

    monkeypatch.setattr(auth.auth_service, "logout_user", fake_logout_user)
    response = Response()

    result = await auth.logout_all_devices(
        request=_request(sid=SID_SEVEN),
        response=response,
        current_user=auth.CurrentUser(sub=str(uid), email="u@example.com"),
        db=None,
    )

    assert result.message == "Logged out on all devices"
    assert called["uid"] == uid
    assert await revocation.get_user_revoked_at(str(uid)) is not None
    assert await redis_util.get_session(SID_SEVEN) is None
    assert "Max-Age=0" in response.headers["set-cookie"]


async def test_legacy_logout_without_target_is_server_side_noop(monkeypatch):
    calls = {"n": 0}

    async def fake_revoke(sid, db):
        calls["n"] += 1

    async def fake_registered(uri, db, client_id=None):
        return True

    monkeypatch.setattr(auth.auth_service, "revoke_session_refresh_tokens", fake_revoke)
    monkeypatch.setattr(auth, "_is_registered_redirect", fake_registered)

    resp = Response()
    await auth.logout(request=_request(sid=None), response=resp, db=None)

    assert calls["n"] == 0  # nothing to revoke
    assert "set-cookie" not in resp.headers


async def test_legacy_logout_with_current_cookie_never_guesses_or_revokes_current_account(monkeypatch):
    await redis_util.create_session(
        SID_SIX,
        {"session_id": SID_SIX, "user_id": str(uuid.uuid4())},
        ttl=100,
    )
    calls = {"n": 0}

    async def fake_revoke(sid, db):
        calls["n"] += 1

    async def fake_registered(uri, db, client_id=None):
        return True

    monkeypatch.setattr(auth.auth_service, "revoke_session_refresh_tokens", fake_revoke)
    monkeypatch.setattr(auth, "_is_registered_redirect", fake_registered)
    body, content_type = _form(post_logout_redirect_uri="https://app.example/auth/callback")
    response = Response()

    result = await auth.logout(
        request=_request(sid=SID_SIX, body=body, content_type=content_type),
        response=response,
        db=None,
    )

    assert isinstance(result, RedirectResponse)
    assert calls["n"] == 0
    assert await redis_util.get_session(SID_SIX) is not None
    assert await revocation.is_sid_revoked(SID_SIX) is False
    assert "set-cookie" not in result.headers


async def test_logout_form_post_redirects_to_registered_uri(monkeypatch):
    """The SLO case: a top-level urlencoded form POST must 302 back to a registered uri."""
    await redis_util.create_session(
        SID_TWO, {"session_id": SID_TWO, "user_id": str(uuid.uuid4())}, ttl=100
    )

    async def fake_revoke(sid, db):
        return None

    async def fake_registered(uri, db, client_id=None):
        return True

    monkeypatch.setattr(auth.auth_service, "revoke_session_refresh_tokens", fake_revoke)
    monkeypatch.setattr(auth, "_is_registered_redirect", fake_registered)

    body, ct = _form(
        post_logout_redirect_uri="https://app.example/auth/callback",
        client_id="appA",
        session_sid=SID_TWO,
    )
    resp = Response()
    result = await auth.logout_session(
        request=_request(sid=SID_TWO, body=body, content_type=ct), response=resp, db=None
    )

    assert isinstance(result, RedirectResponse)
    assert result.status_code == 302
    assert result.headers["location"] == "https://app.example/auth/callback"
    assert "Max-Age=0" in result.headers["set-cookie"]  # cookie cleared on the redirect too


async def test_logout_json_body_still_redirects_to_registered_uri(monkeypatch):
    """Back-compat: a programmatic JSON body keeps working."""
    await redis_util.create_session(
        SID_THREE, {"session_id": SID_THREE, "user_id": str(uuid.uuid4())}, ttl=100
    )

    async def fake_revoke(sid, db):
        return None

    async def fake_registered(uri, db, client_id=None):
        return True

    monkeypatch.setattr(auth.auth_service, "revoke_session_refresh_tokens", fake_revoke)
    monkeypatch.setattr(auth, "_is_registered_redirect", fake_registered)

    body, ct = _json_body(
        post_logout_redirect_uri="https://app.example/auth/callback",
        session_sid=SID_THREE,
    )
    resp = Response()
    result = await auth.logout(request=_request(sid=SID_THREE, body=body, content_type=ct), response=resp, db=None)

    assert isinstance(result, RedirectResponse)
    assert result.headers["location"] == "https://app.example/auth/callback"


async def test_logout_ignores_unregistered_post_logout_uri(monkeypatch):
    await redis_util.create_session(
        SID_FOUR, {"session_id": SID_FOUR, "user_id": str(uuid.uuid4())}, ttl=100
    )

    async def fake_revoke(sid, db):
        return None

    async def fake_registered(uri, db, client_id=None):
        return False  # open-redirect guard

    monkeypatch.setattr(auth.auth_service, "revoke_session_refresh_tokens", fake_revoke)
    monkeypatch.setattr(auth, "_is_registered_redirect", fake_registered)

    body, ct = _form(post_logout_redirect_uri="https://evil.example/x", session_sid=SID_FOUR)
    resp = Response()
    result = await auth.logout(request=_request(sid=SID_FOUR, body=body, content_type=ct), response=resp, db=None)

    assert not isinstance(result, RedirectResponse)  # refused -> plain response
    assert "Max-Age=0" in resp.headers["set-cookie"]


async def test_registered_redirect_scopes_to_client_id_when_present(monkeypatch):
    """When client_id is supplied, the uri must be registered for THAT app, not any app."""
    seen = {}

    async def fake_resolve(client_id, redirect_uri, db):
        seen["args"] = (client_id, redirect_uri)
        return object() if client_id == "appA" else None

    monkeypatch.setattr(auth, "_resolve_authorize_app", fake_resolve)

    uri = "https://app.example/auth/callback"
    assert await auth._is_registered_redirect(uri, db=None, client_id="appA") is True
    assert await auth._is_registered_redirect(uri, db=None, client_id="appB") is False
    assert seen["args"] == ("appB", uri)  # delegated to the per-app resolver


async def test_registered_redirect_falls_back_to_any_app_without_client_id():
    """Without client_id, membership is checked across all active apps (back-compat)."""

    class _App:
        def __init__(self, uris):
            self.redirect_uris = uris

    class _Result:
        def __init__(self, apps):
            self._apps = apps

        def scalars(self):
            return iter(self._apps)

    class _DB:
        def __init__(self, apps):
            self._apps = apps

        async def execute(self, _stmt):
            return _Result(self._apps)

    uri = "https://app.example/auth/callback"
    assert await auth._is_registered_redirect(uri, db=_DB([_App([uri])])) is True
    assert await auth._is_registered_redirect(uri, db=_DB([_App(["https://other/cb"])])) is False
