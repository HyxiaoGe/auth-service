"""账密端点的公网关闭与受控内部兼容测试。"""

import httpx
import pytest
from fastapi import FastAPI

from app.config import Settings
from app.database import get_db
from app.main import app, include_password_auth_router
from app.routers import password_auth

INTERNAL_TOKEN = "internal-perf-token-that-is-at-least-32-characters"
INTERNAL_EMAIL_PREFIX = "fusion-perf+"
INTERNAL_EMAIL_DOMAIN = "seanfield.org"


def _internal_app() -> FastAPI:
    internal_app = FastAPI()
    include_password_auth_router(
        internal_app,
        Settings(
            password_auth_enabled=True,
            password_auth_internal_token=INTERNAL_TOKEN,
            password_auth_email_prefix=INTERNAL_EMAIL_PREFIX,
            password_auth_email_domain=INTERNAL_EMAIL_DOMAIN,
        ),
    )

    async def fake_db():
        yield object()

    internal_app.dependency_overrides[get_db] = fake_db
    return internal_app


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/auth/register", "/auth/login"])
async def test_password_auth_routes_are_absent_by_default(path):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(path, json={"email": "user@example.com", "password": "secret123"})

    assert response.status_code == 404


def test_password_auth_routes_are_absent_from_default_openapi():
    paths = app.openapi()["paths"]

    assert "/auth/register" not in paths
    assert "/auth/login" not in paths


def test_internal_password_auth_routes_stay_out_of_openapi():
    paths = _internal_app().openapi()["paths"]

    assert "/auth/register" not in paths
    assert "/auth/login" not in paths


def test_internal_password_auth_router_rejects_short_token():
    with pytest.raises(ValueError, match="at least 32 characters"):
        password_auth.create_router("short", INTERNAL_EMAIL_PREFIX, INTERNAL_EMAIL_DOMAIN)


@pytest.mark.parametrize(
    "internal_token",
    [
        f" {'x' * 32}",
        f"{'x' * 32} ",
        f"\t{'x' * 32}",
        f"{'x' * 32}\n",
    ],
)
def test_internal_password_auth_router_rejects_token_with_outer_whitespace(internal_token):
    with pytest.raises(ValueError, match="must not contain leading or trailing whitespace"):
        password_auth.create_router(internal_token, INTERNAL_EMAIL_PREFIX, INTERNAL_EMAIL_DOMAIN)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/auth/register", "/auth/login"])
@pytest.mark.parametrize("internal_token", [None, "wrong-token"])
@pytest.mark.parametrize(
    "payload",
    [
        {"email": "user@example.com", "password": "secret123"},
        {},
    ],
)
async def test_internal_password_auth_rejects_missing_or_wrong_token(path, internal_token, payload, monkeypatch):
    async def unexpected_call(*_args, **_kwargs):
        raise AssertionError("内部令牌校验失败时不应进入账密处理器")

    monkeypatch.setattr(password_auth.auth_service, "register_user", unexpected_call)
    monkeypatch.setattr(password_auth.auth_service, "login_user", unexpected_call)
    headers = {password_auth.INTERNAL_AUTH_HEADER: internal_token} if internal_token else {}
    transport = httpx.ASGITransport(app=_internal_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            path,
            headers=headers,
            json=payload,
        )

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/auth/register", "/auth/login"])
@pytest.mark.parametrize("internal_token", [None, "wrong-token"])
@pytest.mark.parametrize(
    ("content", "content_type"),
    [
        (b'{"email":', "application/json"),
        (b"not-json", "text/plain"),
        (b"", "application/json"),
        (b"x" * (16 * 1024 + 1), "application/json"),
    ],
    ids=["malformed-json", "wrong-content-type", "empty-body", "oversized-body"],
)
async def test_internal_password_auth_checks_token_before_reading_or_validating_body(
    path,
    internal_token,
    content,
    content_type,
    monkeypatch,
):
    async def unexpected_call(*_args, **_kwargs):
        raise AssertionError("内部令牌校验失败时不应解析请求体或调用账密服务")

    monkeypatch.setattr(password_auth.auth_service, "register_user", unexpected_call)
    monkeypatch.setattr(password_auth.auth_service, "login_user", unexpected_call)
    headers = {"content-type": content_type}
    if internal_token:
        headers[password_auth.INTERNAL_AUTH_HEADER] = internal_token
    transport = httpx.ASGITransport(app=_internal_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(path, headers=headers, content=content)

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/auth/register", "/auth/login"])
async def test_internal_password_auth_does_not_consume_body_before_token_check(path):
    async def unread_body():
        raise AssertionError("内部令牌校验前不得消费请求体")
        yield b""  # pragma: no cover - 将函数保持为异步生成器

    transport = httpx.ASGITransport(app=_internal_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(path, headers={"content-type": "application/json"}, content=unread_body())

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/auth/register", "/auth/login"])
@pytest.mark.parametrize(
    ("content", "content_type", "expected_status"),
    [
        (b'{"email":', "application/json", 422),
        (b"not-json", "text/plain", 422),
        (b"", "application/json", 422),
        (b"{}", "application/json", 422),
        (b"x" * (16 * 1024 + 1), "application/json", 413),
    ],
    ids=["malformed-json", "wrong-content-type", "empty-body", "invalid-schema", "oversized-body"],
)
async def test_internal_password_auth_validates_body_only_after_correct_token(
    path,
    content,
    content_type,
    expected_status,
    monkeypatch,
):
    async def unexpected_call(*_args, **_kwargs):
        raise AssertionError("无效请求体不应调用账密服务")

    monkeypatch.setattr(password_auth.auth_service, "register_user", unexpected_call)
    monkeypatch.setattr(password_auth.auth_service, "login_user", unexpected_call)
    transport = httpx.ASGITransport(app=_internal_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            path,
            headers={
                password_auth.INTERNAL_AUTH_HEADER: INTERNAL_TOKEN,
                "content-type": content_type,
            },
            content=content,
        )

    assert response.status_code == expected_status


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/auth/register", "/auth/login"])
async def test_internal_password_auth_limits_chunked_body_without_content_length(path, monkeypatch):
    async def unexpected_call(*_args, **_kwargs):
        raise AssertionError("超大请求体不应调用账密服务")

    async def oversized_chunks():
        yield b"x" * (8 * 1024)
        yield b"x" * (8 * 1024 + 1)

    monkeypatch.setattr(password_auth.auth_service, "register_user", unexpected_call)
    monkeypatch.setattr(password_auth.auth_service, "login_user", unexpected_call)
    transport = httpx.ASGITransport(app=_internal_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            path,
            headers={
                password_auth.INTERNAL_AUTH_HEADER: INTERNAL_TOKEN,
                "content-type": "application/json",
            },
            content=oversized_chunks(),
        )

    assert response.status_code == 413


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/auth/register", "/auth/login"])
@pytest.mark.parametrize(
    "email",
    [
        "victim@seanfield.org",
        "fusion-perf+case@evil.example",
        "fusion-perf+case@sub.seanfield.org",
    ],
)
async def test_internal_password_auth_rejects_email_outside_configured_scope(path, email, monkeypatch):
    async def unexpected_call(*_args, **_kwargs):
        raise AssertionError("邮箱超出内部范围时不应进入账密处理器")

    monkeypatch.setattr(password_auth.auth_service, "register_user", unexpected_call)
    monkeypatch.setattr(password_auth.auth_service, "login_user", unexpected_call)
    transport = httpx.ASGITransport(app=_internal_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            path,
            headers={password_auth.INTERNAL_AUTH_HEADER: INTERNAL_TOKEN},
            json={"email": email, "password": "secret123"},
        )

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/auth/register", "/auth/login"])
async def test_internal_password_auth_accepts_correct_token(path, monkeypatch):
    calls = []

    async def fake_register_user(payload, db):
        calls.append(("register", payload.email, db))

    async def fake_login_user(payload, request, db):
        calls.append(("login", payload.email, db))
        return {
            "access_token": "access",
            "refresh_token": "refresh",
            "expires_in": 900,
        }

    monkeypatch.setattr(password_auth.auth_service, "register_user", fake_register_user)
    monkeypatch.setattr(password_auth.auth_service, "login_user", fake_login_user)
    transport = httpx.ASGITransport(app=_internal_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            path,
            headers={password_auth.INTERNAL_AUTH_HEADER: INTERNAL_TOKEN},
            json={"email": "fusion-perf+case@seanfield.org", "password": "secret123"},
        )

    assert response.status_code == (201 if path.endswith("register") else 200)
    assert response.json()["access_token"] == "access"
    assert calls[-1][0] == "login"


@pytest.mark.asyncio
async def test_internal_password_auth_keeps_legacy_header_compatibility(monkeypatch):
    async def fake_login_user(payload, request, db):
        return {
            "access_token": "access",
            "refresh_token": "refresh",
            "expires_in": 900,
        }

    monkeypatch.setattr(password_auth.auth_service, "login_user", fake_login_user)
    transport = httpx.ASGITransport(app=_internal_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/auth/login",
            headers={password_auth.LEGACY_INTERNAL_AUTH_HEADER: INTERNAL_TOKEN},
            json={"email": "fusion-perf+case@seanfield.org", "password": "secret123"},
        )

    assert response.status_code == 200
