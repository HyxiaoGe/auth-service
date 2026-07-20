"""Headless 邮箱验证码登录的 JSON 协议与安全边界。"""

import json
import re
import uuid
from unittest.mock import AsyncMock

from fastapi import Request
from httpx import ASGITransport, AsyncClient

from app.config import Settings
from app.main import app
from app.routers import auth
from app.schemas import EmailHeadlessSendRequest, EmailHeadlessStartRequest, EmailHeadlessVerifyRequest
from app.services import email_login_service, email_sender
from app.services.email_sender import DisabledEmailSender, EmailDeliveryError
from app.utils.redis import consume_auth_code, delete_email_flow, get_email_flow, get_session

CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
APP_STATE = "app_state_0123456789abcdefghijklmnopqrstuv"
CALLBACK = "https://app.example.com/auth/callback"
ORIGIN = "https://app.example.com"


class _User:
    def __init__(self, email: str = "user@example.com"):
        self.id = uuid.uuid4()
        self.email = email
        self.is_active = True
        self.is_superuser = False


class _Scalars:
    def __init__(self, values):
        self.values = values

    def all(self):
        return list(self.values)


class _Result:
    def __init__(self, values):
        self.values = values

    def scalars(self):
        return _Scalars(self.values)


class _DB:
    def __init__(self, users=()):
        self.users = list(users)

    async def execute(self, _query):
        return _Result(self.users)


class _Sender:
    available = True

    def __init__(self, *, fail: bool = False):
        self.fail = fail
        self.sent = []

    async def send_login_code(
        self, recipient: str, code: str, ttl_seconds: int, delivery_id: str | None = None
    ):
        self.sent.append((recipient, code, ttl_seconds))
        if self.fail:
            raise EmailDeliveryError("delivery failed")


def _settings(**overrides) -> Settings:
    values = {
        "auth_base_url": "https://auth.example.com",
        "cors_origins": f"{ORIGIN},http://localhost:3000,app://-",
        "email_login_enabled": True,
        "email_headless_login_enabled": True,
        "email_code_pepper": "test-only-pepper-with-32-characters",
        "smtp_host": "smtp.example.com",
        "smtp_from_email": "login@example.com",
        "smtp_smoke_recipient": "smtp-smoke@example.com",
        "trusted_proxy_cidrs": "172.25.0.10/32",
        "email_code_max_attempts": 3,
    }
    values.update(overrides)
    return Settings(**values)


def _request(
    *,
    origin: str | None = ORIGIN,
    cookie_name: str | None = None,
    cookie_value: str | None = None,
    csrf_token: str | None = None,
    ip: str = "203.0.113.8",
) -> Request:
    headers = []
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    if cookie_name and cookie_value:
        headers.append((b"cookie", f"{cookie_name}={cookie_value}".encode()))
    if csrf_token is not None:
        headers.append((b"x-csrf-token", csrf_token.encode()))
    return Request({"type": "http", "method": "POST", "headers": headers, "client": (ip, 1234)})


def _json(response) -> dict:
    return json.loads(bytes(response.body))


def _start_payload(**overrides) -> EmailHeadlessStartRequest:
    values = {
        "client_id": "appA",
        "redirect_uri": CALLBACK,
        "response_type": "code",
        "state": APP_STATE,
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    }
    values.update(overrides)
    return EmailHeadlessStartRequest(**values)


async def test_hosted_email_form_routes_are_removed():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        send_response = await client.post(
            "/auth/email/send",
            data={"flow_id": "f" * 32, "csrf_token": "c" * 32, "email": "user@example.com"},
        )
        verify_response = await client.post(
            "/auth/email/verify",
            data={"flow_id": "f" * 32, "csrf_token": "c" * 32, "code": "123456"},
        )

    assert send_response.status_code == 404
    assert verify_response.status_code == 404


async def _active_app(*_args):
    return object()


async def _start_flow(config: Settings, *, state: str = APP_STATE):
    return await email_login_service.create_email_flow(
        client_id="appA",
        redirect_uri=CALLBACK,
        app_state=state,
        code_challenge=CHALLENGE,
        config=config,
    )


async def test_headless_start_creates_bound_flow_and_secure_cookie(monkeypatch):
    config = _settings()
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(auth, "_resolve_authorize_app", _active_app)
    monkeypatch.setattr(email_sender, "_smtp_verified", True)

    response = await auth.start_email_headless(_request(), _start_payload(), db=_DB())

    assert response.status_code == 201
    body = _json(response)
    assert body["flow_id"]
    assert body["csrf_token"]
    assert body["expires_in"] == config.email_flow_ttl_seconds
    assert body["code_length"] == 6
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["vary"] == "Origin"
    cookie = response.headers["set-cookie"]
    assert "__Host-email_browser=" in cookie
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie
    stored = await get_email_flow(body["flow_id"])
    assert stored["client_id"] == "appA"
    assert stored["redirect_uri"] == CALLBACK
    assert stored["app_state"] == APP_STATE
    assert stored["code_challenge"] == CHALLENGE


async def test_headless_start_rejects_missing_mismatched_or_non_cors_origin_before_side_effect(
    monkeypatch,
    fake_redis,
):
    config = _settings()
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(auth, "_resolve_authorize_app", _active_app)
    monkeypatch.setattr(email_sender, "_smtp_verified", True)

    for request in (
        _request(origin=None),
        _request(origin="null"),
        _request(origin="https://evil.example"),
    ):
        response = await auth.start_email_headless(request, _start_payload(), db=_DB())
        assert response.status_code == 403
        assert _json(response)["error"] == "origin_not_allowed"

    monkeypatch.setattr(auth, "settings", _settings(cors_origins="https://other.example"))
    response = await auth.start_email_headless(_request(), _start_payload(), db=_DB())
    assert response.status_code == 403
    assert [key async for key in fake_redis.scan_iter("email_flow:*")] == []


async def test_headless_start_rejects_packaged_electron_origin(monkeypatch):
    config = _settings()
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(auth, "_resolve_authorize_app", _active_app)
    monkeypatch.setattr(email_sender, "_smtp_verified", True)

    response = await auth.start_email_headless(
        _request(origin="app://-"),
        _start_payload(redirect_uri="app://-/auth/callback"),
        db=_DB(),
    )

    assert response.status_code == 403
    assert _json(response)["error"] == "origin_not_allowed"


async def test_headless_start_rejects_cross_site_origin_even_when_redirect_and_cors_match(
    monkeypatch,
    fake_redis,
):
    config = _settings(
        auth_base_url="https://auth.example.com",
        cors_origins="https://app.other.com",
    )
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(auth, "_resolve_authorize_app", _active_app)
    monkeypatch.setattr(email_sender, "_smtp_verified", True)

    response = await auth.start_email_headless(
        _request(origin="https://app.other.com"),
        _start_payload(redirect_uri="https://app.other.com/auth/callback"),
        db=_DB(),
    )

    assert response.status_code == 403
    assert _json(response)["error"] == "origin_not_allowed"
    assert [key async for key in fake_redis.scan_iter("email_flow:*")] == []


async def test_headless_start_allows_localhost_http_same_site(monkeypatch):
    config = _settings(
        auth_base_url="http://localhost:8100",
        cors_origins="http://localhost:3000",
        trusted_proxy_cidrs="",
    )
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(auth, "_resolve_authorize_app", _active_app)
    monkeypatch.setattr(email_sender, "_smtp_verified", True)

    response = await auth.start_email_headless(
        _request(origin="http://localhost:3000"),
        _start_payload(redirect_uri="http://localhost:3000/auth/callback"),
        db=_DB(),
    )

    assert response.status_code == 201


async def test_headless_cors_preflight_allows_configured_web_origin_and_rejects_other_origins():
    transport = ASGITransport(app=app)
    headers = {
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,x-csrf-token",
    }
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        allowed = await client.options("/auth/email/headless/send", headers=headers)
        rejected = await client.options(
            "/auth/email/headless/send",
            headers={**headers, "Origin": "https://evil.example"},
        )

    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert allowed.headers["access-control-allow-credentials"] == "true"
    assert "x-csrf-token" in allowed.headers["access-control-allow-headers"].lower()
    assert rejected.status_code == 400
    assert "access-control-allow-origin" not in rejected.headers


async def test_headless_start_validates_oauth_contract_and_readiness_without_creating_flow(
    monkeypatch,
    fake_redis,
):
    config = _settings()
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(auth, "_resolve_authorize_app", _active_app)
    monkeypatch.setattr(email_sender, "_smtp_verified", True)

    bad_response_type = await auth.start_email_headless(
        _request(),
        _start_payload(response_type="token"),
        db=_DB(),
    )
    bad_pkce = await auth.start_email_headless(
        _request(),
        _start_payload(code_challenge_method="plain"),
        db=_DB(),
    )

    async def unknown_app(*_args):
        return None

    monkeypatch.setattr(auth, "_resolve_authorize_app", unknown_app)
    unknown_client = await auth.start_email_headless(_request(), _start_payload(), db=_DB())

    assert bad_response_type.status_code == 400
    assert _json(bad_response_type)["error"] == "unsupported_response_type"
    assert bad_pkce.status_code == 400
    assert _json(bad_pkce)["error"] == "invalid_request"
    assert unknown_client.status_code == 400
    assert _json(unknown_client)["error"] == "invalid_client"
    assert [key async for key in fake_redis.scan_iter("email_flow:*")] == []


async def test_headless_start_rejects_malformed_pkce_and_state_before_side_effect(monkeypatch, fake_redis):
    config = _settings(
        auth_base_url="http://localhost:8100",
        cors_origins="http://localhost:3000",
        trusted_proxy_cidrs="",
    )
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(email_sender, "_smtp_verified", True)
    resolve_app = AsyncMock(return_value=object())
    monkeypatch.setattr(auth, "_resolve_authorize_app", resolve_app)
    valid = {
        "client_id": "appA",
        "redirect_uri": "http://localhost:3000/auth/callback",
        "response_type": "code",
        "state": APP_STATE,
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    }
    invalid_fields = [
        {"code_challenge": "short"},
        {"code_challenge": "!" * 43},
        {"state": "a" * 31},
        {"state": "a" * 31 + "!"},
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for overrides in invalid_fields:
            response = await client.post(
                "/auth/email/headless/start",
                headers={"Origin": "http://localhost:3000"},
                json={**valid, **overrides},
            )
            assert response.status_code == 400
            assert response.json()["error"] == "invalid_request"

    resolve_app.assert_not_awaited()
    assert [key async for key in fake_redis.scan_iter("email_flow:*")] == []
    assert [key async for key in fake_redis.scan_iter("email_rate_*")] == []


async def test_headless_send_returns_generic_accepted_response_and_delivers_in_background(monkeypatch):
    config = _settings()
    started = await _start_flow(config)
    user = _User()
    sender = _Sender()
    monkeypatch.setattr(auth, "settings", config)

    response = await auth.send_email_headless(
        _request(
            cookie_name=started.cookie_name,
            cookie_value=started.cookie_value,
            csrf_token=started.csrf_token,
        ),
        EmailHeadlessSendRequest(flow_id=started.flow_id, email=user.email),
        db=_DB([user]),
        sender=sender,
    )

    assert response.status_code == 202
    assert _json(response) == {
        "accepted": True,
        "next": "verify",
        "expires_in": config.email_code_ttl_seconds,
        "resend_after": config.email_code_resend_seconds,
        "masked_destination": "u***@example.com",
    }
    assert sender.sent == []
    assert response.background is not None
    await response.background()
    assert sender.sent and sender.sent[0][0] == user.email


async def test_headless_send_does_not_reveal_unknown_account(monkeypatch, fake_redis):
    config = _settings(email_code_resend_seconds=1)
    known = await _start_flow(config)
    unknown = await _start_flow(config)
    user = _User()
    monkeypatch.setattr(auth, "settings", config)

    known_response = await auth.send_email_headless(
        _request(cookie_name=known.cookie_name, cookie_value=known.cookie_value, csrf_token=known.csrf_token),
        EmailHeadlessSendRequest(flow_id=known.flow_id, email=user.email),
        db=_DB([user]),
        sender=_Sender(),
    )
    rate_keys = [key async for key in fake_redis.scan_iter("email_rate_*")]
    cooldown_keys = [key async for key in fake_redis.scan_iter("email_cooldown:*")]
    await fake_redis.delete(*rate_keys, *cooldown_keys)
    unknown_response = await auth.send_email_headless(
        _request(
            cookie_name=unknown.cookie_name,
            cookie_value=unknown.cookie_value,
            csrf_token=unknown.csrf_token,
        ),
        EmailHeadlessSendRequest(flow_id=unknown.flow_id, email=user.email),
        db=_DB(),
        sender=_Sender(),
    )

    assert known_response.status_code == unknown_response.status_code == 202
    assert _json(known_response) == _json(unknown_response)


async def test_headless_send_rejects_bad_binding_without_creating_otp(monkeypatch, fake_redis):
    config = _settings()
    started = await _start_flow(config)
    monkeypatch.setattr(auth, "settings", config)

    response = await auth.send_email_headless(
        _request(
            cookie_name=started.cookie_name,
            cookie_value=started.cookie_value,
            csrf_token="x" * 43,
        ),
        EmailHeadlessSendRequest(flow_id=started.flow_id, email="user@example.com"),
        db=_DB([_User()]),
        sender=_Sender(),
    )

    assert response.status_code == 403
    assert _json(response)["error"] == "invalid_interaction"
    assert [key async for key in fake_redis.scan_iter("email_otp:*")] == []


async def test_headless_send_returns_structured_rate_limit_and_unavailable(monkeypatch, fake_redis):
    config = _settings(email_rate_limit_per_flow=1, email_code_resend_seconds=60)
    started = await _start_flow(config)
    monkeypatch.setattr(auth, "settings", config)
    request = _request(
        cookie_name=started.cookie_name,
        cookie_value=started.cookie_value,
        csrf_token=started.csrf_token,
    )
    payload = EmailHeadlessSendRequest(flow_id=started.flow_id, email="missing@example.com")

    first = await auth.send_email_headless(request, payload, db=_DB(), sender=_Sender())
    limited = await auth.send_email_headless(request, payload, db=_DB(), sender=_Sender())
    unavailable = await auth.send_email_headless(request, payload, db=_DB(), sender=DisabledEmailSender())

    assert first.status_code == 202
    assert limited.status_code == 429
    assert _json(limited)["error"] == "rate_limited"
    assert _json(limited)["error_description"] == "too many verification code requests"
    assert int(limited.headers["retry-after"]) == _json(limited)["retry_after"]
    assert await get_email_flow(started.flow_id) is not None
    assert await fake_redis.get(f"email_rate_flow:{started.flow_id}") == "1"
    assert await fake_redis.get(f"email_rate_send_request_flow:{started.flow_id}") == "3"
    assert unavailable.status_code == 503
    assert _json(unavailable)["error"] == "delivery_unavailable"


async def test_headless_send_limits_missing_flow_before_redis_lookup_without_flow_bucket(monkeypatch, fake_redis):
    config = _settings(email_send_request_rate_limit_per_ip=1, email_send_request_rate_limit_global=100)
    monkeypatch.setattr(auth, "settings", config)
    request = _request(csrf_token="x" * 43, ip="203.0.113.8")
    payload = EmailHeadlessSendRequest(flow_id="missing-flow-id-00000000", email="user@example.com")

    first = await auth.send_email_headless(request, payload, db=_DB(), sender=_Sender())
    limited = await auth.send_email_headless(request, payload, db=_DB(), sender=_Sender())

    assert first.status_code == 403
    assert limited.status_code == 429
    assert _json(limited)["error"] == "rate_limited"
    assert _json(limited)["error_description"] == "too many email send requests"
    assert int(limited.headers["retry-after"]) == _json(limited)["retry_after"]
    request_keys = [key async for key in fake_redis.scan_iter("email_rate_send_request*")]
    assert len(request_keys) == 2
    assert sorted([await fake_redis.get(key) for key in request_keys]) == ["1", "1"]
    assert [key async for key in fake_redis.scan_iter("email_rate_send_request_flow:*")] == []


async def test_headless_send_limits_live_flow_before_feature_db_or_otp(monkeypatch, fake_redis):
    config = _settings(
        email_rate_limit_per_flow=1,
        email_send_request_rate_limit_per_flow=1,
    )
    started = await _start_flow(config)
    monkeypatch.setattr(auth, "settings", config)
    request = _request(
        cookie_name=started.cookie_name,
        cookie_value=started.cookie_value,
        csrf_token=started.csrf_token,
    )
    payload = EmailHeadlessSendRequest(flow_id=started.flow_id, email="user@example.com")

    unavailable = await auth.send_email_headless(
        request,
        payload,
        db=_DB([_User()]),
        sender=DisabledEmailSender(),
    )
    limited = await auth.send_email_headless(
        request,
        payload,
        db=_DB([_User()]),
        sender=_Sender(),
    )

    assert unavailable.status_code == 503
    assert limited.status_code == 429
    assert _json(limited)["error_description"] == "too many email send requests"
    assert await fake_redis.get(f"email_rate_send_request_flow:{started.flow_id}") == "1"
    assert await fake_redis.exists(f"email_otp:{started.flow_id}") == 0


async def test_headless_verify_returns_only_authorization_code_and_starts_sso_session(monkeypatch):
    config = _settings()
    started = await _start_flow(config)
    user = _User()
    sender = _Sender()
    db = _DB([user])
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="203.0.113.8",
        db=db,
        sender=sender,
        config=config,
    )
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(auth.session_service, "settings", config)
    monkeypatch.setattr(auth, "_resolve_authorize_app", _active_app)

    response = await auth.verify_email_headless(
        _request(
            cookie_name=started.cookie_name,
            cookie_value=started.cookie_value,
            csrf_token=started.csrf_token,
        ),
        EmailHeadlessVerifyRequest(flow_id=started.flow_id, code=sender.sent[0][1]),
        db=db,
    )

    assert response.status_code == 200
    body = _json(response)
    assert set(body) == {"code", "state", "expires_in"}
    assert body["state"] == APP_STATE
    assert "access_token" not in body and "refresh_token" not in body
    code_data = await consume_auth_code(body["code"])
    assert code_data == {
        "user_id": str(user.id),
        "app_client_id": "appA",
        "redirect_uri": CALLBACK,
        "provider": "email_otp",
        "auth_generation": 0,
        "code_challenge": CHALLENGE,
        "sid": code_data["sid"],
    }
    assert code_data["sid"]
    session_cookie = next(value for value in response.headers.getlist("set-cookie") if "sso_session=" in value)
    sid = re.search(r"(?:__Host-)?sso_session=([^;]+)", session_cookie).group(1)
    session = await get_session(sid)
    assert session["user_id"] == str(user.id)
    assert session["amr"] == ["email_otp"]
    assert session["session_id"] == code_data["sid"]
    assert session["session_id"] != sid  # HttpOnly cookie lookup key 永不进入 token/code


async def test_headless_verify_limits_missing_flow_by_client_ip_before_flow_or_otp_lookup(monkeypatch, fake_redis):
    config = _settings(email_verify_rate_limit_per_ip=1, email_verify_rate_limit_global=100)
    monkeypatch.setattr(auth, "settings", config)
    request = _request(csrf_token="x" * 43, ip="203.0.113.8")
    payload = EmailHeadlessVerifyRequest(flow_id="missing-flow-id-00000000", code="123456")

    first = await auth.verify_email_headless(request, payload, db=_DB())
    limited = await auth.verify_email_headless(request, payload, db=_DB())

    assert first.status_code == 403
    assert limited.status_code == 429
    assert _json(limited)["error"] == "rate_limited"
    assert _json(limited)["error_description"] == "too many verification attempts"
    assert int(limited.headers["retry-after"]) == _json(limited)["retry_after"]
    request_keys = [key async for key in fake_redis.scan_iter("email_rate_verify_request*")]
    assert len(request_keys) == 2
    assert sorted([await fake_redis.get(key) for key in request_keys]) == ["1", "1"]
    assert [key async for key in fake_redis.scan_iter("email_rate_verify_flow:*")] == []


async def test_headless_verify_global_rejection_does_not_increment_new_ip_bucket(monkeypatch, fake_redis):
    config = _settings(email_verify_rate_limit_per_ip=100, email_verify_rate_limit_global=1)
    monkeypatch.setattr(auth, "settings", config)
    payload = EmailHeadlessVerifyRequest(flow_id="missing-flow-id-00000000", code="123456")

    first = await auth.verify_email_headless(
        _request(csrf_token="x" * 43, ip="203.0.113.8"),
        payload,
        db=_DB(),
    )
    limited = await auth.verify_email_headless(
        _request(csrf_token="x" * 43, ip="203.0.113.9"),
        payload,
        db=_DB(),
    )

    assert first.status_code == 403
    assert limited.status_code == 429
    ip_keys = [key async for key in fake_redis.scan_iter("email_rate_verify_request_ip:*")]
    assert len(ip_keys) == 1
    assert await fake_redis.get("email_rate_verify_request_global") == "1"


async def test_headless_verify_limits_bound_flow_before_application_lookup_without_send(monkeypatch, fake_redis):
    config = _settings(
        email_code_max_attempts=1,
        email_rate_limit_per_flow=1,
        email_verify_rate_limit_per_flow=1,
    )
    started = await _start_flow(config)
    resolve_app = AsyncMock(return_value=object())
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(auth, "_resolve_authorize_app", resolve_app)
    request = _request(
        cookie_name=started.cookie_name,
        cookie_value=started.cookie_value,
        csrf_token=started.csrf_token,
    )
    payload = EmailHeadlessVerifyRequest(flow_id=started.flow_id, code="123456")

    no_otp = await auth.verify_email_headless(request, payload, db=_DB())
    limited = await auth.verify_email_headless(request, payload, db=_DB())

    assert no_otp.status_code == 400
    assert _json(no_otp)["error"] == "invalid_code"
    assert limited.status_code == 429
    assert _json(limited)["error"] == "rate_limited"
    assert _json(limited)["error_description"] == "too many verification attempts"
    assert resolve_app.await_count == 1
    assert await fake_redis.get(f"email_rate_verify_flow:{started.flow_id}") == "1"


async def test_headless_verify_keeps_otp_attempt_lockout_and_generic_failure(monkeypatch, fake_redis):
    config = _settings(
        email_code_max_attempts=2,
        email_verify_rate_limit_per_ip=100,
        email_verify_rate_limit_per_flow=100,
        email_verify_rate_limit_global=100,
    )
    started = await _start_flow(config)
    user = _User()
    sender = _Sender()
    db = _DB([user])
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="203.0.113.8",
        db=db,
        sender=sender,
        config=config,
    )
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(auth, "_resolve_authorize_app", _active_app)
    request = _request(
        cookie_name=started.cookie_name,
        cookie_value=started.cookie_value,
        csrf_token=started.csrf_token,
    )
    wrong_code = "000000" if sender.sent[0][1] != "000000" else "999999"

    first_wrong = await auth.verify_email_headless(
        request,
        EmailHeadlessVerifyRequest(flow_id=started.flow_id, code=wrong_code),
        db=db,
    )
    second_wrong = await auth.verify_email_headless(
        request,
        EmailHeadlessVerifyRequest(flow_id=started.flow_id, code=wrong_code),
        db=db,
    )
    correct_after_lockout = await auth.verify_email_headless(
        request,
        EmailHeadlessVerifyRequest(flow_id=started.flow_id, code=sender.sent[0][1]),
        db=db,
    )

    assert [first_wrong.status_code, second_wrong.status_code, correct_after_lockout.status_code] == [400, 400, 400]
    assert {_json(response)["error"] for response in (first_wrong, second_wrong, correct_after_lockout)} == {
        "invalid_code"
    }
    assert await fake_redis.exists(f"email_otp:{started.flow_id}") == 0


async def test_headless_verify_accepts_correct_code_at_configured_flow_limit(monkeypatch):
    config = _settings(
        email_code_max_attempts=2,
        email_rate_limit_per_flow=1,
        email_verify_rate_limit_per_ip=100,
        email_verify_rate_limit_per_flow=2,
        email_verify_rate_limit_global=100,
    )
    started = await _start_flow(config)
    user = _User()
    sender = _Sender()
    db = _DB([user])
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="203.0.113.8",
        db=db,
        sender=sender,
        config=config,
    )
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(auth.session_service, "settings", config)
    monkeypatch.setattr(auth, "_resolve_authorize_app", _active_app)
    request = _request(
        cookie_name=started.cookie_name,
        cookie_value=started.cookie_value,
        csrf_token=started.csrf_token,
    )
    wrong_code = "000000" if sender.sent[0][1] != "000000" else "999999"

    wrong = await auth.verify_email_headless(
        request,
        EmailHeadlessVerifyRequest(flow_id=started.flow_id, code=wrong_code),
        db=db,
    )
    success = await auth.verify_email_headless(
        request,
        EmailHeadlessVerifyRequest(flow_id=started.flow_id, code=sender.sent[0][1]),
        db=db,
    )

    assert wrong.status_code == 400
    assert success.status_code == 200
    assert set(_json(success)) == {"code", "state", "expires_in"}


async def test_headless_verify_bad_origin_or_csrf_does_not_consume_code(monkeypatch):
    config = _settings()
    started = await _start_flow(config)
    user = _User()
    sender = _Sender()
    db = _DB([user])
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="203.0.113.8",
        db=db,
        sender=sender,
        config=config,
    )
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(auth.session_service, "settings", config)
    monkeypatch.setattr(auth, "_resolve_authorize_app", _active_app)
    payload = EmailHeadlessVerifyRequest(flow_id=started.flow_id, code=sender.sent[0][1])

    wrong_origin = await auth.verify_email_headless(
        _request(
            origin="https://evil.example",
            cookie_name=started.cookie_name,
            cookie_value=started.cookie_value,
            csrf_token=started.csrf_token,
        ),
        payload,
        db=db,
    )
    wrong_csrf = await auth.verify_email_headless(
        _request(
            cookie_name=started.cookie_name,
            cookie_value=started.cookie_value,
            csrf_token="x" * 43,
        ),
        payload,
        db=db,
    )
    success = await auth.verify_email_headless(
        _request(
            cookie_name=started.cookie_name,
            cookie_value=started.cookie_value,
            csrf_token=started.csrf_token,
        ),
        payload,
        db=db,
    )

    assert wrong_origin.status_code == 403
    assert wrong_csrf.status_code == 403
    assert success.status_code == 200


async def test_headless_verify_expired_bound_flow_returns_recoverable_login_required(monkeypatch):
    config = _settings()
    started = await _start_flow(config, state="RECOVER_STATE")
    await delete_email_flow(started.flow_id)
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(auth, "_resolve_authorize_app", _active_app)

    response = await auth.verify_email_headless(
        _request(
            cookie_name=started.cookie_name,
            cookie_value=started.cookie_value,
            csrf_token=started.csrf_token,
        ),
        EmailHeadlessVerifyRequest(flow_id=started.flow_id, code="123456"),
        db=_DB(),
    )

    assert response.status_code == 410
    assert _json(response) == {
        "error": "interaction_expired",
        "error_description": "email login flow expired, please sign in again",
        "state": "RECOVER_STATE",
    }


async def test_headless_send_limits_recovery_before_application_without_consuming_verify_flow(monkeypatch, fake_redis):
    config = _settings(
        email_rate_limit_per_flow=1,
        email_send_request_rate_limit_per_ip=100,
        email_send_request_rate_limit_per_flow=1,
        email_send_request_rate_limit_global=100,
    )
    started = await _start_flow(config, state="RECOVER_STATE")
    await delete_email_flow(started.flow_id)
    resolve_app = AsyncMock(return_value=object())
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(auth, "_resolve_authorize_app", resolve_app)
    request = _request(
        cookie_name=started.cookie_name,
        cookie_value=started.cookie_value,
        csrf_token=started.csrf_token,
    )
    payload = EmailHeadlessSendRequest(flow_id=started.flow_id, email="user@example.com")

    expired = await auth.send_email_headless(request, payload, db=_DB(), sender=_Sender())
    limited = await auth.send_email_headless(request, payload, db=_DB(), sender=_Sender())

    assert expired.status_code == 410
    assert limited.status_code == 429
    assert _json(limited)["error_description"] == "too many email send requests"
    assert int(limited.headers["retry-after"]) == _json(limited)["retry_after"]
    assert resolve_app.await_count == 1
    assert await fake_redis.get(f"email_rate_send_request_flow:{started.flow_id}") == "1"
    assert [key async for key in fake_redis.scan_iter("email_rate_verify_flow:*")] == []
    request_keys = [key async for key in fake_redis.scan_iter("email_rate_send_request*")]
    request_values = [await fake_redis.get(key) for key in request_keys if not key.startswith("email_rate_send_request_flow:")]
    assert sorted(request_values) == ["2", "2"]


async def test_headless_verify_limits_bound_recovery_before_application_lookup(monkeypatch, fake_redis):
    config = _settings(
        email_code_max_attempts=1,
        email_rate_limit_per_flow=1,
        email_verify_rate_limit_per_ip=100,
        email_verify_rate_limit_per_flow=1,
        email_verify_rate_limit_global=100,
    )
    started = await _start_flow(config, state="RECOVER_STATE")
    await delete_email_flow(started.flow_id)
    resolve_app = AsyncMock(return_value=object())
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(auth, "_resolve_authorize_app", resolve_app)
    request = _request(
        cookie_name=started.cookie_name,
        cookie_value=started.cookie_value,
        csrf_token=started.csrf_token,
        ip="203.0.113.8",
    )
    payload = EmailHeadlessVerifyRequest(flow_id=started.flow_id, code="123456")

    expired = await auth.verify_email_headless(request, payload, db=_DB())
    limited = await auth.verify_email_headless(request, payload, db=_DB())

    assert expired.status_code == 410
    assert limited.status_code == 429
    assert _json(limited)["error"] == "rate_limited"
    assert _json(limited)["error_description"] == "too many verification attempts"
    assert int(limited.headers["retry-after"]) == _json(limited)["retry_after"]
    assert resolve_app.await_count == 1
    assert await fake_redis.get(f"email_rate_verify_flow:{started.flow_id}") == "1"
    request_keys = [key async for key in fake_redis.scan_iter("email_rate_verify_request*")]
    assert sorted([await fake_redis.get(key) for key in request_keys]) == ["2", "2"]


async def test_headless_verify_revalidates_application_before_consuming_otp(monkeypatch):
    config = _settings()
    started = await _start_flow(config)
    user = _User()
    sender = _Sender()
    db = _DB([user])
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="203.0.113.8",
        db=db,
        sender=sender,
        config=config,
    )
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(auth.session_service, "settings", config)

    async def inactive_app(*_args):
        return None

    monkeypatch.setattr(auth, "_resolve_authorize_app", inactive_app)
    request = _request(
        cookie_name=started.cookie_name,
        cookie_value=started.cookie_value,
        csrf_token=started.csrf_token,
    )
    payload = EmailHeadlessVerifyRequest(flow_id=started.flow_id, code=sender.sent[0][1])
    rejected = await auth.verify_email_headless(request, payload, db=db)

    monkeypatch.setattr(auth, "_resolve_authorize_app", _active_app)
    success = await auth.verify_email_headless(request, payload, db=db)

    assert rejected.status_code == 400
    assert _json(rejected)["error"] == "invalid_client"
    assert success.status_code == 200
