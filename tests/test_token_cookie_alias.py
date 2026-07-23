"""受信 loopback auth alias 的中央 Cookie 复制安全边界。"""

import time
import uuid

import pytest
from fastapi import HTTPException, Request, Response
from httpx import ASGITransport, AsyncClient

from app.config import Settings
from app.database import get_db
from app.main import app
from app.routers import oauth
from app.schemas import OAuthTokenExchangeRequest, TokenResponse
from app.services import session_service
from app.utils import redis as redis_util

CLIENT_ID = "appA"
REDIRECT_URI = "http://localhost:3000/auth/callback"
ORIGIN = "http://localhost:3000"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def _request(*, origin: str | None = ORIGIN, server=("localhost", 8100)) -> Request:
    headers: list[tuple[bytes, bytes]] = [(b"host", f"{server[0]}:{server[1]}".encode())]
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "http",
            "server": server,
            "path": "/auth/oauth/token",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 12345),
        }
    )


def _public_request(*, origin: str = "https://app.other.test") -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "server": ("auth.example.com", 443),
            "path": "/auth/oauth/token",
            "query_string": b"",
            "headers": [
                (b"host", b"auth.example.com"),
                (b"origin", origin.encode()),
            ],
            "client": ("203.0.113.10", 12345),
        }
    )


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _DB:
    def __init__(self, user):
        self.user = user

    async def execute(self, _statement):
        return _Result(self.user)


class _User:
    def __init__(self):
        self.id = uuid.uuid4()
        self.email = "user@example.com"
        self.is_active = True
        self.is_superuser = False
        self.auth_generation = 2


def _settings() -> Settings:
    return Settings(
        app_env="development",
        auth_base_url="https://auth.example.com",
        auth_browser_aliases="http://localhost:8100",
        cors_origins=ORIGIN,
    )


async def _store_bound_code(user: _User, *, code: str, cookie_sid: str = "secret-cookie-sid"):
    await redis_util.create_session(
        cookie_sid,
        {
            "session_id": "public-session-id-1234",
            "user_id": str(user.id),
            "auth_generation": user.auth_generation,
            "auth_time": int(time.time()),
            "version": "stable-session-version",
        },
        ttl=100,
    )
    await redis_util.store_auth_code(
        code,
        {
            "user_id": str(user.id),
            "app_client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "provider": "google",
            "auth_generation": user.auth_generation,
            "code_challenge": CHALLENGE,
            "sid": "public-session-id-1234",
            "cookie_sid": cookie_sid,
            "session_version": "stable-session-version",
        },
        ttl=100,
    )


async def test_trusted_alias_sets_bound_cookie_only_after_successful_token_issue(monkeypatch):
    user = _User()
    await _store_bound_code(user, code="alias-success")
    response = Response()
    order: list[str] = []

    async def fake_registered(*_args, **_kwargs):
        return True

    async def fake_issue(*_args, **_kwargs):
        order.append("issue")
        return TokenResponse(access_token="access", refresh_token="refresh", expires_in=900)

    async def fake_log(*_args, **_kwargs):
        order.append("log")

    original_set_cookie = session_service.set_session_cookie

    def tracked_set_cookie(target_response, cookie_sid):
        order.append("cookie")
        original_set_cookie(target_response, cookie_sid)

    monkeypatch.setattr(oauth, "settings", _settings())
    monkeypatch.setattr(session_service, "settings", _settings())
    monkeypatch.setattr(oauth, "_redirect_uri_registered", fake_registered)
    monkeypatch.setattr(oauth.auth_service, "_issue_tokens", fake_issue)
    monkeypatch.setattr(oauth.auth_service, "_log_login", fake_log)
    monkeypatch.setattr(session_service, "set_session_cookie", tracked_set_cookie)

    tokens = await oauth.exchange_code_for_tokens(
        OAuthTokenExchangeRequest(
            code="alias-success",
            client_id=CLIENT_ID,
            code_verifier=VERIFIER,
        ),
        _request(),
        db=_DB(user),
        response=response,
    )

    assert tokens.access_token == "access"
    assert order == ["issue", "log", "cookie"]
    assert "sso_session=secret-cookie-sid" in response.headers["set-cookie"]
    assert "secret-cookie-sid" not in tokens.model_dump_json()


async def test_fastapi_injects_token_response_and_emits_bound_cookie(monkeypatch):
    user = _User()
    await _store_bound_code(user, code="route-response-injection")

    async def fake_registered(*_args, **_kwargs):
        return True

    async def fake_issue(*_args, **_kwargs):
        return TokenResponse(access_token="access", refresh_token="refresh", expires_in=900)

    async def fake_log(*_args, **_kwargs):
        return None

    async def override_db():
        yield _DB(user)

    monkeypatch.setattr(oauth, "settings", _settings())
    monkeypatch.setattr(session_service, "settings", _settings())
    monkeypatch.setattr(oauth, "_redirect_uri_registered", fake_registered)
    monkeypatch.setattr(oauth.auth_service, "_issue_tokens", fake_issue)
    monkeypatch.setattr(oauth.auth_service, "_log_login", fake_log)
    app.dependency_overrides[get_db] = override_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://localhost:8100",
        ) as client:
            response = await client.post(
                "/auth/oauth/token",
                headers={"Origin": ORIGIN},
                json={
                    "code": "route-response-injection",
                    "client_id": CLIENT_ID,
                    "code_verifier": VERIFIER,
                },
            )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    assert "sso_session=secret-cookie-sid" in response.headers["set-cookie"]


@pytest.mark.parametrize(
    ("browser_request", "detail"),
    [
        (_request(origin=None), "origin"),
        (_request(origin="http://127.0.0.1:3000"), "origin"),
    ],
)
async def test_bound_cookie_code_rejects_untrusted_browser_context_before_signing(
    monkeypatch,
    browser_request,
    detail,
):
    user = _User()
    await _store_bound_code(user, code=f"reject-{detail}")
    issued = False

    async def fake_registered(*_args, **_kwargs):
        return True

    async def fake_issue(*_args, **_kwargs):
        nonlocal issued
        issued = True
        return TokenResponse(access_token="access", refresh_token="refresh", expires_in=900)

    monkeypatch.setattr(oauth, "settings", _settings())
    monkeypatch.setattr(session_service, "settings", _settings())
    monkeypatch.setattr(oauth, "_redirect_uri_registered", fake_registered)
    monkeypatch.setattr(oauth.auth_service, "_issue_tokens", fake_issue)

    with pytest.raises(HTTPException, match=detail):
        await oauth.exchange_code_for_tokens(
            OAuthTokenExchangeRequest(
                code=f"reject-{detail}",
                client_id=CLIENT_ID,
                code_verifier=VERIFIER,
            ),
            browser_request,
            db=_DB(user),
            response=Response(),
        )

    assert issued is False


async def test_bound_cookie_code_rejects_redis_session_version_mismatch_before_signing(monkeypatch):
    user = _User()
    await _store_bound_code(user, code="version-mismatch")
    session = await redis_util.get_session("secret-cookie-sid")
    session["version"] = "replaced-version"
    await redis_util.create_session("secret-cookie-sid", session, ttl=100)
    issued = False

    async def fake_registered(*_args, **_kwargs):
        return True

    async def fake_issue(*_args, **_kwargs):
        nonlocal issued
        issued = True
        return TokenResponse(access_token="access", refresh_token="refresh", expires_in=900)

    monkeypatch.setattr(oauth, "settings", _settings())
    monkeypatch.setattr(session_service, "settings", _settings())
    monkeypatch.setattr(oauth, "_redirect_uri_registered", fake_registered)
    monkeypatch.setattr(oauth.auth_service, "_issue_tokens", fake_issue)

    with pytest.raises(HTTPException, match="session binding"):
        await oauth.exchange_code_for_tokens(
            OAuthTokenExchangeRequest(
                code="version-mismatch",
                client_id=CLIENT_ID,
                code_verifier=VERIFIER,
            ),
            _request(),
            db=_DB(user),
            response=Response(),
        )

    assert issued is False


async def test_public_canonical_auth_keeps_cross_site_pkce_exchange_compatible(monkeypatch):
    user = _User()
    redirect_uri = "https://app.other.test/auth/callback"
    await _store_bound_code(user, code="public-cross-site")
    code_data = await redis_util.consume_auth_code("public-cross-site")
    code_data["redirect_uri"] = redirect_uri
    await redis_util.store_auth_code("public-cross-site", code_data, ttl=100)
    response = Response()

    async def fake_registered(*_args, **_kwargs):
        return True

    async def fake_issue(*_args, **_kwargs):
        return TokenResponse(access_token="access", refresh_token="refresh", expires_in=900)

    async def fake_log(*_args, **_kwargs):
        return None

    public_settings = Settings(
        app_env="development",
        auth_base_url="https://auth.example.com",
        auth_browser_aliases="http://localhost:8100",
        cors_origins="https://app.other.test",
    )
    monkeypatch.setattr(oauth, "settings", public_settings)
    monkeypatch.setattr(session_service, "settings", public_settings)
    monkeypatch.setattr(oauth, "_redirect_uri_registered", fake_registered)
    monkeypatch.setattr(oauth.auth_service, "_issue_tokens", fake_issue)
    monkeypatch.setattr(oauth.auth_service, "_log_login", fake_log)

    tokens = await oauth.exchange_code_for_tokens(
        OAuthTokenExchangeRequest(
            code="public-cross-site",
            client_id=CLIENT_ID,
            code_verifier=VERIFIER,
        ),
        _public_request(),
        db=_DB(user),
        response=response,
    )

    assert tokens.access_token == "access"
    assert "set-cookie" not in response.headers


async def test_legacy_code_remains_compatible_and_never_sets_cookie(monkeypatch):
    user = _User()
    await redis_util.store_auth_code(
        "legacy-code",
        {
            "user_id": str(user.id),
            "app_client_id": CLIENT_ID,
            "provider": "google",
            "auth_generation": user.auth_generation,
        },
        ttl=100,
    )
    response = Response()

    async def fake_issue(*_args, **_kwargs):
        return TokenResponse(access_token="access", refresh_token="refresh", expires_in=900)

    async def fake_log(*_args, **_kwargs):
        return None

    monkeypatch.setattr(oauth.auth_service, "_issue_tokens", fake_issue)
    monkeypatch.setattr(oauth.auth_service, "_log_login", fake_log)

    tokens = await oauth.exchange_code_for_tokens(
        OAuthTokenExchangeRequest(code="legacy-code", client_id=CLIENT_ID),
        _request(origin=None),
        db=_DB(user),
        response=response,
    )

    assert tokens.access_token == "access"
    assert "set-cookie" not in response.headers
