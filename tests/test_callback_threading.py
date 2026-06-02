"""Social callbacks resume the /authorize context.

When the oauth_state was created by /authorize it carries app_state + code_challenge.
The callback must (a) echo app_state back to the app as ?state=, and (b) bind the
code_challenge into the minted auth code so /token enforces PKCE. The legacy direct flow
stores neither, so the callback must still produce a bare ?code= redirect (zero-breakage).
"""

import uuid
from urllib.parse import parse_qs, urlparse

from starlette.requests import Request

from app.routers import oauth
from app.services import oauth_service
from app.utils.redis import consume_auth_code

CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
CB = "https://app.example/cb"


def _req() -> Request:
    return Request({"type": "http", "headers": [], "client": ("10.0.0.9", 0)})


class _FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()


def _stub_social(monkeypatch):
    async def fake_validate(client_id, redirect_uri, db):
        return None

    async def fake_exchange(code):
        return {"provider_id": "g1", "email": "a@b.c", "name": "A", "avatar_url": None}

    user = _FakeUser()

    async def fake_social_login(**kwargs):
        return user

    monkeypatch.setattr(oauth, "_validate_redirect_uri", fake_validate)
    monkeypatch.setattr(oauth.oauth_service, "exchange_google_code", fake_exchange)
    monkeypatch.setattr(oauth.auth_service, "social_login", fake_social_login)
    return user


async def test_callback_from_authorize_echoes_state_and_binds_challenge(monkeypatch):
    user = _stub_social(monkeypatch)
    state = await oauth_service.create_oauth_state(
        "appA",
        CB,
        app_state="APPSTATE",
        code_challenge=CHALLENGE,
        code_challenge_method="S256",
        provider="google",
        response_type="code",
    )

    resp = await oauth.google_callback(request=_req(), code="x", state=state, db=None)

    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["state"] == ["APPSTATE"]  # app's CSRF state echoed back
    assert "set-cookie" in resp.headers  # IdP session established (P1)
    data = await consume_auth_code(q["code"][0])
    assert data["code_challenge"] == CHALLENGE  # PKCE bound -> /token will enforce
    assert data["user_id"] == str(user.id)


async def test_legacy_callback_has_no_state_and_no_challenge(monkeypatch):
    _stub_social(monkeypatch)
    # legacy direct flow: oauth_state carries only client_id + redirect_uri
    state = await oauth_service.create_oauth_state("appA", CB)

    resp = await oauth.google_callback(request=_req(), code="x", state=state, db=None)

    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert "state" not in q  # nothing to echo
    data = await consume_auth_code(q["code"][0])
    assert "code_challenge" not in data  # legacy code -> /token skips PKCE
