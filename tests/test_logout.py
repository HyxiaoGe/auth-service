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
from app.utils import redis as redis_util


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


async def test_logout_deletes_session_revokes_tokens_and_clears_cookie(monkeypatch):
    uid = uuid.uuid4()
    await redis_util.create_session("s1", {"user_id": str(uid), "auth_time": 111}, ttl=100)

    revoked = {}

    async def fake_revoke(user_id, db):
        revoked["uid"] = user_id

    monkeypatch.setattr(auth.auth_service, "_revoke_all_user_tokens", fake_revoke)

    resp = Response()
    await auth.logout(request=_request(sid="s1"), response=resp, db=None)

    assert await redis_util.get_session("s1") is None  # session destroyed
    assert revoked["uid"] == uid  # refresh tokens revoked for the session's user
    assert "Max-Age=0" in resp.headers["set-cookie"]  # cookie cleared


async def test_logout_without_session_is_noop_but_clears_cookie(monkeypatch):
    calls = {"n": 0}

    async def fake_revoke(user_id, db):
        calls["n"] += 1

    monkeypatch.setattr(auth.auth_service, "_revoke_all_user_tokens", fake_revoke)

    resp = Response()
    await auth.logout(request=_request(sid=None), response=resp, db=None)

    assert calls["n"] == 0  # nothing to revoke
    assert "Max-Age=0" in resp.headers["set-cookie"]


async def test_logout_form_post_redirects_to_registered_uri(monkeypatch):
    """The SLO case: a top-level urlencoded form POST must 302 back to a registered uri."""
    await redis_util.create_session("s2", {"user_id": str(uuid.uuid4())}, ttl=100)

    async def fake_revoke(user_id, db):
        return None

    async def fake_registered(uri, db, client_id=None):
        return True

    monkeypatch.setattr(auth.auth_service, "_revoke_all_user_tokens", fake_revoke)
    monkeypatch.setattr(auth, "_is_registered_redirect", fake_registered)

    body, ct = _form(post_logout_redirect_uri="https://app.example/auth/callback", client_id="appA")
    resp = Response()
    result = await auth.logout(request=_request(sid="s2", body=body, content_type=ct), response=resp, db=None)

    assert isinstance(result, RedirectResponse)
    assert result.status_code == 302
    assert result.headers["location"] == "https://app.example/auth/callback"
    assert "Max-Age=0" in result.headers["set-cookie"]  # cookie cleared on the redirect too


async def test_logout_json_body_still_redirects_to_registered_uri(monkeypatch):
    """Back-compat: a programmatic JSON body keeps working."""
    await redis_util.create_session("s3", {"user_id": str(uuid.uuid4())}, ttl=100)

    async def fake_revoke(user_id, db):
        return None

    async def fake_registered(uri, db, client_id=None):
        return True

    monkeypatch.setattr(auth.auth_service, "_revoke_all_user_tokens", fake_revoke)
    monkeypatch.setattr(auth, "_is_registered_redirect", fake_registered)

    body, ct = _json_body(post_logout_redirect_uri="https://app.example/auth/callback")
    resp = Response()
    result = await auth.logout(request=_request(sid="s3", body=body, content_type=ct), response=resp, db=None)

    assert isinstance(result, RedirectResponse)
    assert result.headers["location"] == "https://app.example/auth/callback"


async def test_logout_ignores_unregistered_post_logout_uri(monkeypatch):
    await redis_util.create_session("s4", {"user_id": str(uuid.uuid4())}, ttl=100)

    async def fake_revoke(user_id, db):
        return None

    async def fake_registered(uri, db, client_id=None):
        return False  # open-redirect guard

    monkeypatch.setattr(auth.auth_service, "_revoke_all_user_tokens", fake_revoke)
    monkeypatch.setattr(auth, "_is_registered_redirect", fake_registered)

    body, ct = _form(post_logout_redirect_uri="https://evil.example/x")
    resp = Response()
    result = await auth.logout(request=_request(sid="s4", body=body, content_type=ct), response=resp, db=None)

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
