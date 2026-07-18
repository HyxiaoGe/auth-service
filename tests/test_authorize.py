"""GET /auth/authorize -- the SSO front door -- plus its oauth_error() helper.

Covers the OAuth/OIDC error-shape contract and the silent/interactive/prompt=none
branches of /authorize. DB-backed app validation is monkeypatched (like the logout
tests) so these stay pure unit tests over the routing logic.
"""

import json
import time
import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse

from app.routers import auth
from app.utils.redis import consume_auth_code, create_session

# RFC 7636 Appendix B vector (challenge corresponds to this verifier).
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
CB = "https://app.example/cb"


def _request(cookie_sid=None):
    headers = [(b"cookie", f"sso_session={cookie_sid}".encode())] if cookie_sid else []
    return Request({"type": "http", "headers": headers})


def _loc_query(resp):
    return parse_qs(urlparse(resp.headers["location"]).query)


# ==================== oauth_error() ====================


def test_oauth_error_without_redirect_returns_400_json():
    resp = auth.oauth_error("invalid_client", "unknown client")
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 400
    body = json.loads(bytes(resp.body))
    assert body["error"] == "invalid_client"
    assert body["error_description"] == "unknown client"


def test_oauth_error_with_redirect_returns_302_with_error_and_state():
    resp = auth.oauth_error("login_required", "no session", redirect_uri="https://app.example/cb", state="S1")
    assert isinstance(resp, RedirectResponse)
    assert resp.status_code == 302
    parsed = urlparse(resp.headers["location"])
    assert parsed.path == "/cb"
    q = parse_qs(parsed.query)
    assert q["error"] == ["login_required"]
    assert q["state"] == ["S1"]
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["referrer-policy"] == "no-referrer"


def test_oauth_error_preserves_business_query_and_replaces_reserved_values():
    resp = auth.oauth_error(
        "login_required",
        "no session",
        redirect_uri="https://app.example/cb?tenant=one&code=old&state=old&error=old",
        state="fresh",
    )

    q = _loc_query(resp)
    assert q["tenant"] == ["one"]
    assert q["error"] == ["login_required"]
    assert q["state"] == ["fresh"]
    assert "code" not in q


def test_oauth_error_redirect_omits_state_when_absent():
    resp = auth.oauth_error("server_error", "boom", redirect_uri="https://app.example/cb")
    q = _loc_query(resp)
    assert "state" not in q


# ==================== GET /authorize ====================


@pytest.fixture
def valid_app(monkeypatch):
    """Make client_id/redirect_uri validation pass without touching the DB."""

    async def fake_resolve(client_id, redirect_uri, db):
        return object()  # truthy "app"

    monkeypatch.setattr(auth, "_resolve_authorize_app", fake_resolve)


async def _authorize(request, **kw):
    base = dict(
        client_id="appA",
        redirect_uri=CB,
        response_type="code",
        state="S",
        code_challenge=CHALLENGE,
        code_challenge_method="S256",
        db=None,
    )
    base.update(kw)
    return await auth.authorize(request=request, **base)


async def _live_session(sid, user_id):
    await create_session(sid, {"user_id": user_id, "auth_time": int(time.time()), "amr": ["google"]}, ttl=100)


async def test_authorize_rejects_non_code_response_type(valid_app):
    resp = await _authorize(_request(), response_type="token")
    assert isinstance(resp, JSONResponse) and resp.status_code == 400  # 400 JSON, NOT a redirect
    assert json.loads(bytes(resp.body))["error"] == "unsupported_response_type"


async def test_authorize_rejects_unknown_client(monkeypatch):
    async def fake_resolve(client_id, redirect_uri, db):
        return None

    monkeypatch.setattr(auth, "_resolve_authorize_app", fake_resolve)
    resp = await _authorize(_request(), client_id="bad")
    assert isinstance(resp, JSONResponse) and resp.status_code == 400  # never redirect to unvalidated uri
    assert json.loads(bytes(resp.body))["error"] == "invalid_client"


async def test_authorize_requires_pkce_challenge(valid_app):
    resp = await _authorize(_request(), code_challenge=None, code_challenge_method=None)
    assert isinstance(resp, RedirectResponse) and resp.status_code == 302  # redirect_uri is valid now
    q = _loc_query(resp)
    assert q["error"] == ["invalid_request"]
    assert q["state"] == ["S"]


async def test_authorize_rejects_plain_pkce(valid_app):
    resp = await _authorize(_request(), code_challenge_method="plain")
    q = _loc_query(resp)
    assert q["error"] == ["invalid_request"]


async def test_authorize_silent_when_session_valid(valid_app):
    uid = str(uuid.uuid4())
    await _live_session("sess1", uid)
    resp = await _authorize(_request("sess1"), state="S2")
    assert isinstance(resp, RedirectResponse) and resp.status_code == 302
    q = _loc_query(resp)
    assert "error" not in q
    assert q["state"] == ["S2"]
    # silent SSO: a code is issued with no social round-trip, bound to the PKCE challenge
    data = await consume_auth_code(q["code"][0])
    assert data["user_id"] == uid
    assert data["app_client_id"] == "appA"
    assert data["code_challenge"] == CHALLENGE


async def test_authorize_silent_preserves_business_query_and_replaces_reserved_values(valid_app):
    uid = str(uuid.uuid4())
    await _live_session("sess-query", uid)
    resp = await _authorize(
        _request("sess-query"),
        redirect_uri="https://app.example/cb?tenant=one&code=old&state=old&error=old",
        state="fresh",
    )

    q = _loc_query(resp)
    assert q["tenant"] == ["one"]
    assert q["state"] == ["fresh"]
    assert len(q["code"]) == 1 and q["code"] != ["old"]
    assert "error" not in q
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["referrer-policy"] == "no-referrer"


async def test_authorize_prompt_none_without_session(valid_app):
    resp = await _authorize(_request(), state="S3", prompt="none")
    q = _loc_query(resp)
    assert q["error"] == ["login_required"]  # silent failure, no UI
    assert q["state"] == ["S3"]


async def test_authorize_prompt_login_forces_social_despite_session(valid_app):
    await _live_session("sess2", str(uuid.uuid4()))
    resp = await _authorize(_request("sess2"), prompt="login", provider="google")
    assert isinstance(resp, RedirectResponse)
    assert "accounts.google.com" in resp.headers["location"]  # re-auth, not silent


async def test_authorize_interactive_with_provider_goes_to_social(valid_app):
    resp = await _authorize(_request(), provider="github")
    assert isinstance(resp, RedirectResponse)
    assert "github.com" in resp.headers["location"]


async def test_authorize_email_is_rejected_without_html_or_flow(valid_app, fake_redis):
    response = await _authorize(_request(), provider="email", state="EMAIL_STATE")

    assert isinstance(response, RedirectResponse)
    assert response.status_code == 302
    assert response.media_type is None
    assert "set-cookie" not in response.headers
    query = _loc_query(response)
    assert query["error"] == ["invalid_request"]
    assert query["error_description"] == ["provider must be google or github"]
    assert query["state"] == ["EMAIL_STATE"]
    assert [key async for key in fake_redis.scan_iter("email_flow:*")] == []


async def test_authorize_interactive_without_provider_returns_error(valid_app):
    resp = await _authorize(_request(), state="S6")  # no session, no provider
    q = _loc_query(resp)
    assert q["error"] == ["invalid_request"]
    assert q["state"] == ["S6"]
