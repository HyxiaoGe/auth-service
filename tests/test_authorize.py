"""GET /auth/authorize -- the SSO front door -- plus its oauth_error() helper.

Covers the OAuth/OIDC error-shape contract and the silent/interactive/prompt=none
branches of /authorize. DB-backed app validation is monkeypatched (like the logout
tests) so these stay pure unit tests over the routing logic.
"""

import json
import re
import time
import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse

from app.config import Settings
from app.routers import auth
from app.services import email_sender
from app.utils.redis import consume_auth_code, create_session, get_email_flow

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


async def test_authorize_email_returns_hosted_page_after_all_oauth_validation(valid_app, monkeypatch):
    config = Settings(
        auth_base_url="https://auth.example.com",
        email_login_enabled=True,
        email_code_pepper="test-only-pepper-with-32-characters",
        smtp_host="smtp.example.com",
        smtp_from_email="login@example.com",
        smtp_smoke_recipient="smtp-smoke@example.com",
        trusted_proxy_cidrs="172.25.0.10/32",
    )
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(email_sender, "_smtp_verified", True)

    resp = await _authorize(_request(), provider="email", state="EMAIL_STATE")

    assert resp.status_code == 200
    assert resp.media_type == "text/html"
    assert resp.headers["cache-control"] == "no-store"
    assert "__Host-email_browser=" in resp.headers["set-cookie"]
    assert "Max-Age=3600" in resp.headers["set-cookie"]
    assert "SameSite=lax" in resp.headers["set-cookie"]
    body = bytes(resp.body).decode()
    assert 'action="/auth/email/send"' in body
    assert 'name="csrf_token"' in body
    assert CB not in body
    flow_id = re.search(r'name="flow_id" value="([^"]+)"', body).group(1)
    stored = await get_email_flow(flow_id)
    assert stored["client_id"] == "appA"
    assert stored["redirect_uri"] == CB
    assert stored["app_state"] == "EMAIL_STATE"
    assert stored["code_challenge"] == CHALLENGE


async def test_authorize_email_disabled_fails_closed_without_creating_flow(valid_app, monkeypatch, fake_redis):
    monkeypatch.setattr(auth, "settings", Settings(email_login_enabled=False))

    resp = await _authorize(_request(), provider="email")

    assert resp.status_code == 503
    assert resp.media_type == "text/html"
    assert [key async for key in fake_redis.scan_iter("email_flow:*")] == []


async def test_authorize_email_smtp_unverified_fails_closed_without_creating_flow(
    valid_app,
    monkeypatch,
    fake_redis,
):
    config = Settings(
        auth_base_url="https://auth.example.com",
        email_login_enabled=True,
        email_code_pepper="test-only-pepper-with-32-characters",
        smtp_host="smtp.example.com",
        smtp_from_email="login@example.com",
        smtp_smoke_recipient="smtp-smoke@example.com",
        trusted_proxy_cidrs="172.25.0.10/32",
    )
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(email_sender, "_smtp_verified", False)

    response = await _authorize(_request(), provider="email")

    assert response.status_code == 503
    assert [key async for key in fake_redis.scan_iter("email_flow:*")] == []


async def test_authorize_email_rate_limit_rejects_before_creating_another_flow(
    valid_app,
    monkeypatch,
    fake_redis,
):
    config = Settings(
        auth_base_url="https://auth.example.com",
        email_login_enabled=True,
        email_code_pepper="test-only-pepper-with-32-characters",
        smtp_host="smtp.example.com",
        smtp_from_email="login@example.com",
        smtp_smoke_recipient="smtp-smoke@example.com",
        trusted_proxy_cidrs="172.25.0.10/32",
        email_authorize_rate_limit_per_client=1,
    )
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(email_sender, "_smtp_verified", True)

    first = await _authorize(_request(), provider="email")
    second = await _authorize(_request(), provider="email")

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"] == str(config.email_rate_limit_window_seconds)
    assert len([key async for key in fake_redis.scan_iter("email_flow:*")]) == 1


async def test_authorize_interactive_without_provider_returns_error(valid_app):
    resp = await _authorize(_request(), state="S6")  # no session, no provider
    q = _loc_query(resp)
    assert q["error"] == ["invalid_request"]
    assert q["state"] == ["S6"]
