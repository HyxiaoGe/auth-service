"""P1 integration: OAuth callbacks establish an IdP session (Set-Cookie + Redis).

Additive behavior — the existing redirect to {redirect_uri}?code=... is unchanged;
the callback now also mints a session. Collaborators (social login, code exchange,
redirect-uri validation, state) are stubbed; the auth-code + session storage stay
real against fakeredis.
"""

import uuid

from fastapi.responses import RedirectResponse
from starlette.requests import Request

from app.routers import oauth
from app.utils import redis as redis_util


def _req() -> Request:
    return Request({"type": "http", "headers": [], "client": ("10.0.0.9", 0)})


class _FakeUser:
    def __init__(self, uid):
        self.id = uid
        self.is_active = True


def _stub_oauth(monkeypatch, exchange_name, uid):
    async def fake_state(_state):
        return {"client_id": "c1", "redirect_uri": "https://app.example/cb"}

    async def fake_validate(_client_id, _redirect_uri, _db):
        return None

    async def fake_exchange(_code):
        return {"provider_id": "p1", "email": "a@b.com", "name": "A", "avatar_url": None}

    async def fake_social_login(**_kwargs):
        return _FakeUser(uid)

    monkeypatch.setattr(oauth.oauth_service, "verify_and_consume_state", fake_state)
    monkeypatch.setattr(oauth, "_validate_redirect_uri", fake_validate)
    monkeypatch.setattr(oauth.oauth_service, exchange_name, fake_exchange)
    monkeypatch.setattr(oauth.auth_service, "social_login", fake_social_login)


async def test_google_callback_sets_session_cookie_without_changing_redirect(monkeypatch):
    uid = uuid.uuid4()
    _stub_oauth(monkeypatch, "exchange_google_code", uid)

    resp = await oauth.google_callback(request=_req(), code="x", state="s", db=None)

    assert isinstance(resp, RedirectResponse)
    assert resp.status_code == 302
    # existing behavior preserved
    assert resp.headers["location"].startswith("https://app.example/cb?code=")
    # new behavior: session cookie present...
    assert "set-cookie" in resp.headers
    set_cookie = resp.headers["set-cookie"]
    assert "sso_session=" in set_cookie
    assert "HttpOnly" in set_cookie
    # ...and a Redis session keyed to the (stringified) user id exists
    sid = set_cookie.split("sso_session=", 1)[1].split(";", 1)[0]
    payload = await redis_util.get_session(sid)
    assert payload["user_id"] == str(uid)


async def test_github_callback_sets_session_cookie_with_github_amr(monkeypatch):
    uid = uuid.uuid4()
    _stub_oauth(monkeypatch, "exchange_github_code", uid)

    resp = await oauth.github_callback(request=_req(), code="x", state="s", db=None)

    assert resp.status_code == 302
    assert resp.headers["location"].startswith("https://app.example/cb?code=")
    assert "set-cookie" in resp.headers
    sid = resp.headers["set-cookie"].split("sso_session=", 1)[1].split(";", 1)[0]
    payload = await redis_util.get_session(sid)
    assert payload["user_id"] == str(uid)
    assert payload["amr"] == ["github"]
