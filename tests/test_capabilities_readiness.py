import asyncio
from unittest.mock import AsyncMock
from urllib.parse import urlencode

import pytest
from httpx import ASGITransport, AsyncClient

import app.main as main_module
from app.config import Settings
from app.main import app
from app.routers import auth
from app.services import email_sender
from app.services.email_sender import EmailDeliveryError

LOCAL_CALLBACK = "http://localhost:3000/auth/callback"


def _capabilities_path(*, client_id: str | None = None, redirect_uri: str | None = None) -> str:
    query = {key: value for key, value in {"client_id": client_id, "redirect_uri": redirect_uri}.items() if value}
    return f"/auth/capabilities?{urlencode(query)}" if query else "/auth/capabilities"


@pytest.fixture(autouse=True)
def reset_smtp_verification(monkeypatch):
    monkeypatch.setattr(email_sender, "_smtp_verified", False, raising=False)
    monkeypatch.setattr(email_sender, "_smtp_failure_generation", 0, raising=False)


async def _get(
    path: str,
    *,
    client_address: tuple[str, int] = ("127.0.0.1", 1234),
    headers: dict[str, str] | None = None,
    base_url: str = "http://test",
):
    transport = ASGITransport(app=app, client=client_address)
    async with AsyncClient(transport=transport, base_url=base_url) as client:
        return await client.get(path, headers=headers)


async def test_auth_capabilities_reports_email_login_false_when_disabled(monkeypatch):
    monkeypatch.setattr(auth, "settings", Settings(email_login_enabled=False))

    response = await _get("/auth/capabilities", headers={"Origin": "http://localhost:3000"})

    assert response.status_code == 200
    assert response.json() == {"email_login": False, "email_headless_login": False}
    assert response.headers["cache-control"] == "no-store"
    assert "Origin" in response.headers["vary"]


async def test_auth_capabilities_allows_packaged_electron_origin():
    response = await _get("/auth/capabilities", headers={"Origin": "app://-"})

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "app://-"
    assert response.headers["access-control-allow-credentials"] == "true"


async def test_auth_capabilities_reports_email_login_false_when_config_incomplete(monkeypatch):
    monkeypatch.setattr(
        auth,
        "settings",
        Settings(
            auth_base_url="http://localhost:8100",
            email_login_enabled=True,
            email_code_pepper="x" * 32,
            smtp_smoke_recipient="smtp-smoke@example.com",
        ),
    )

    response = await _get("/auth/capabilities", headers={"Origin": "http://localhost:3000"})

    assert response.status_code == 200
    assert response.json() == {"email_login": False, "email_headless_login": False}


async def test_auth_capabilities_keeps_hosted_email_login_disabled_when_delivery_is_ready(monkeypatch):
    monkeypatch.setattr(
        auth,
        "settings",
        Settings(
            auth_base_url="http://localhost:8100",
            email_login_enabled=True,
            email_code_pepper="x" * 32,
            smtp_host="smtp.example.com",
            smtp_from_email="login@example.com",
            smtp_smoke_recipient="smtp-smoke@example.com",
        ),
    )
    monkeypatch.setattr(email_sender, "_smtp_verified", True, raising=False)

    response = await _get("/auth/capabilities")

    assert response.status_code == 200
    assert response.json() == {"email_login": False, "email_headless_login": False}


async def test_auth_capabilities_reports_headless_only_when_its_switch_and_email_readiness_are_true(monkeypatch):
    monkeypatch.setattr(
        auth,
        "settings",
        Settings(
            auth_base_url="http://localhost:8100",
            email_login_enabled=True,
            email_headless_login_enabled=True,
            email_code_pepper="x" * 32,
            smtp_host="smtp.example.com",
            smtp_from_email="login@example.com",
            smtp_smoke_recipient="smtp-smoke@example.com",
        ),
    )
    monkeypatch.setattr(email_sender, "_smtp_verified", True, raising=False)
    resolve_app = AsyncMock(return_value=object())
    monkeypatch.setattr(auth, "_resolve_authorize_app", resolve_app)

    response = await _get(
        _capabilities_path(client_id="fusion", redirect_uri=LOCAL_CALLBACK),
        headers={"Origin": "http://localhost:3000"},
        base_url="http://localhost:8100",
    )

    assert response.status_code == 200
    assert response.json() == {"email_login": False, "email_headless_login": True}
    resolve_app.assert_awaited_once()


@pytest.mark.parametrize(
    "path",
    [
        "/auth/capabilities",
        _capabilities_path(client_id="fusion"),
        _capabilities_path(redirect_uri=LOCAL_CALLBACK),
    ],
)
async def test_auth_capabilities_requires_both_client_parameters_for_headless(monkeypatch, path):
    monkeypatch.setattr(
        auth,
        "settings",
        Settings(
            auth_base_url="http://localhost:8100",
            email_login_enabled=True,
            email_headless_login_enabled=True,
            email_code_pepper="x" * 32,
            smtp_host="smtp.example.com",
            smtp_from_email="login@example.com",
            smtp_smoke_recipient="smtp-smoke@example.com",
        ),
    )
    monkeypatch.setattr(email_sender, "_smtp_verified", True, raising=False)
    resolve_app = AsyncMock(return_value=object())
    monkeypatch.setattr(auth, "_resolve_authorize_app", resolve_app)

    response = await _get(path, headers={"Origin": "http://localhost:3000"})

    assert response.status_code == 200
    assert response.json() == {"email_login": False, "email_headless_login": False}
    resolve_app.assert_not_awaited()


async def test_auth_capabilities_requires_active_app_and_exact_redirect(monkeypatch):
    monkeypatch.setattr(
        auth,
        "settings",
        Settings(
            auth_base_url="http://localhost:8100",
            email_login_enabled=True,
            email_headless_login_enabled=True,
            email_code_pepper="x" * 32,
            smtp_host="smtp.example.com",
            smtp_from_email="login@example.com",
            smtp_smoke_recipient="smtp-smoke@example.com",
        ),
    )
    monkeypatch.setattr(email_sender, "_smtp_verified", True, raising=False)
    resolve_app = AsyncMock(return_value=None)
    monkeypatch.setattr(auth, "_resolve_authorize_app", resolve_app)

    response = await _get(
        _capabilities_path(client_id="fusion", redirect_uri=LOCAL_CALLBACK),
        headers={"Origin": "http://localhost:3000"},
        base_url="http://localhost:8100",
    )

    assert response.status_code == 200
    assert response.json() == {"email_login": False, "email_headless_login": False}
    resolve_app.assert_awaited_once()


async def test_auth_capabilities_rejects_cross_site_even_when_origin_redirect_and_cors_match(monkeypatch):
    monkeypatch.setattr(
        auth,
        "settings",
        Settings(
            auth_base_url="https://auth.example.com",
            cors_origins="https://app.other.com",
            email_login_enabled=True,
            email_headless_login_enabled=True,
            email_code_pepper="x" * 32,
            smtp_host="smtp.example.com",
            smtp_from_email="login@example.com",
            smtp_smoke_recipient="smtp-smoke@example.com",
            trusted_proxy_cidrs="127.0.0.1/32",
        ),
    )
    monkeypatch.setattr(email_sender, "_smtp_verified", True, raising=False)
    resolve_app = AsyncMock(return_value=object())
    monkeypatch.setattr(auth, "_resolve_authorize_app", resolve_app)
    redirect_uri = "https://app.other.com/auth/callback"

    response = await _get(
        _capabilities_path(client_id="fusion", redirect_uri=redirect_uri),
        headers={"Origin": "https://app.other.com"},
        base_url="https://auth.example.com",
    )

    assert response.status_code == 200
    assert response.json() == {"email_login": False, "email_headless_login": False}
    resolve_app.assert_not_awaited()


async def test_auth_capabilities_allows_same_site_sibling_subdomain(monkeypatch):
    monkeypatch.setattr(
        auth,
        "settings",
        Settings(
            auth_base_url="https://authmail.seanfield.org",
            cors_origins="https://dev.seanfield.org",
            email_login_enabled=True,
            email_headless_login_enabled=True,
            email_code_pepper="x" * 32,
            smtp_host="smtp.example.com",
            smtp_from_email="login@seanfield.org",
            smtp_smoke_recipient="smtp-smoke@seanfield.org",
            trusted_proxy_cidrs="127.0.0.1/32",
        ),
    )
    monkeypatch.setattr(email_sender, "_smtp_verified", True, raising=False)
    resolve_app = AsyncMock(return_value=object())
    monkeypatch.setattr(auth, "_resolve_authorize_app", resolve_app)
    redirect_uri = "https://dev.seanfield.org/auth/callback"

    response = await _get(
        _capabilities_path(client_id="fusion", redirect_uri=redirect_uri),
        headers={"Origin": "https://dev.seanfield.org"},
        base_url="https://authmail.seanfield.org",
    )

    assert response.status_code == 200
    assert response.json() == {"email_login": False, "email_headless_login": True}
    resolve_app.assert_awaited_once()


@pytest.mark.parametrize("origin", ["app://-", "null", None])
async def test_auth_capabilities_keeps_headless_off_for_non_web_origin(monkeypatch, origin):
    monkeypatch.setattr(
        auth,
        "settings",
        Settings(
            auth_base_url="http://localhost:8100",
            email_login_enabled=True,
            email_headless_login_enabled=True,
            email_code_pepper="x" * 32,
            smtp_host="smtp.example.com",
            smtp_from_email="login@example.com",
            smtp_smoke_recipient="smtp-smoke@example.com",
        ),
    )
    monkeypatch.setattr(email_sender, "_smtp_verified", True, raising=False)
    resolve_app = AsyncMock(return_value=object())
    monkeypatch.setattr(auth, "_resolve_authorize_app", resolve_app)

    headers = {"Origin": origin} if origin is not None else None
    response = await _get(
        _capabilities_path(client_id="fusion", redirect_uri=LOCAL_CALLBACK),
        headers=headers,
        base_url="http://localhost:8100",
    )

    assert response.status_code == 200
    assert response.json() == {"email_login": False, "email_headless_login": False}
    resolve_app.assert_not_awaited()


async def test_email_delivery_health_disabled_is_green_without_verifying_smtp(monkeypatch):
    config = Settings(email_login_enabled=False)
    preflight = AsyncMock()
    monkeypatch.setattr(main_module, "settings", config)
    monkeypatch.setattr(email_sender.SMTPEmailSender, "preflight", preflight)

    response = await _get("/health/email-delivery")

    assert response.status_code == 200
    assert response.json()["status"] == "disabled"
    assert email_sender.is_smtp_verified() is False
    preflight.assert_not_awaited()


async def test_email_delivery_health_enabled_but_incomplete_is_503(monkeypatch):
    config = Settings(
        auth_base_url="http://localhost:8100",
        email_login_enabled=True,
        email_code_pepper="x" * 32,
        smtp_smoke_recipient="smtp-smoke@example.com",
    )
    preflight = AsyncMock()
    monkeypatch.setattr(main_module, "settings", config)
    monkeypatch.setattr(email_sender.SMTPEmailSender, "preflight", preflight)

    response = await _get("/health/email-delivery")

    assert response.status_code == 503
    assert response.json()["status"] == "misconfigured"
    assert email_sender.is_smtp_verified() is False
    preflight.assert_not_awaited()


async def test_email_delivery_success_keeps_hosted_off_and_headless_requires_context(monkeypatch):
    config = Settings(
        auth_base_url="http://localhost:8100",
        email_login_enabled=True,
        email_code_pepper="x" * 32,
        smtp_host="smtp.example.com",
        smtp_from_email="login@example.com",
        smtp_smoke_recipient="smtp-smoke@example.com",
    )
    preflight = AsyncMock()

    async def report_monitor_success(_timeout_seconds):
        assert email_sender.confirm_smtp_verification(email_sender.smtp_failure_generation()) is True
        return True

    wait_for_verification = AsyncMock(side_effect=report_monitor_success)
    monkeypatch.setattr(main_module, "settings", config)
    monkeypatch.setattr(auth, "settings", config)
    monkeypatch.setattr(email_sender, "wait_for_smtp_verification", wait_for_verification)
    monkeypatch.setattr(email_sender.SMTPEmailSender, "preflight", preflight)

    before = await _get("/auth/capabilities")
    health = await _get("/health/email-delivery")
    after = await _get("/auth/capabilities")

    assert before.json() == {"email_login": False, "email_headless_login": False}
    assert health.status_code == 200
    assert health.json()["status"] == "ready"
    assert after.json() == {"email_login": False, "email_headless_login": False}
    assert email_sender.is_smtp_verified() is True
    expected_wait = (
        config.smtp_timeout_seconds * main_module.EMAIL_DELIVERY_VERIFICATION_SMTP_PHASES
        + main_module.EMAIL_DELIVERY_VERIFICATION_GRACE_SECONDS
    )
    wait_for_verification.assert_awaited_once_with(expected_wait)
    preflight.assert_not_awaited()


async def test_email_delivery_health_timeout_is_fail_closed_without_running_preflight(monkeypatch):
    config = Settings(
        auth_base_url="http://localhost:8100",
        email_login_enabled=True,
        email_code_pepper="x" * 32,
        smtp_host="smtp.example.com",
        smtp_from_email="login@example.com",
        smtp_smoke_recipient="smtp-smoke@example.com",
    )
    monkeypatch.setattr(main_module, "settings", config)
    monkeypatch.setattr(auth, "settings", config)
    wait_for_verification = AsyncMock(return_value=False)
    preflight = AsyncMock(side_effect=EmailDeliveryError("must not be called"))
    monkeypatch.setattr(email_sender, "wait_for_smtp_verification", wait_for_verification)
    monkeypatch.setattr(email_sender.SMTPEmailSender, "preflight", preflight)

    health = await _get("/health/email-delivery")
    capability = await _get("/auth/capabilities")

    assert health.status_code == 503
    assert health.json()["status"] == "not_ready"
    assert capability.json() == {"email_login": False, "email_headless_login": False}
    assert email_sender.is_smtp_verified() is False
    expected_wait = (
        config.smtp_timeout_seconds * main_module.EMAIL_DELIVERY_VERIFICATION_SMTP_PHASES
        + main_module.EMAIL_DELIVERY_VERIFICATION_GRACE_SECONDS
    )
    assert expected_wait > config.smtp_timeout_seconds * main_module.EMAIL_DELIVERY_VERIFICATION_SMTP_PHASES
    wait_for_verification.assert_awaited_once_with(expected_wait)
    preflight.assert_not_awaited()


async def test_lifespan_starts_acceptance_preflight_monitor_when_email_login_is_ready(monkeypatch):
    config = Settings(
        auth_base_url="http://localhost:8100",
        email_login_enabled=True,
        email_code_pepper="x" * 32,
        smtp_host="smtp.example.com",
        smtp_from_email="login@example.com",
        smtp_smoke_recipient="smtp-smoke@example.com",
    )
    monitor = AsyncMock()
    close = AsyncMock()
    monkeypatch.setattr(main_module, "settings", config)
    monkeypatch.setattr(email_sender, "monitor_smtp_verification", monitor)
    monkeypatch.setattr(main_module, "close_redis", close)

    async with main_module.lifespan(app):
        await asyncio.sleep(0)

    monitor.assert_awaited_once_with(config)
    close.assert_awaited_once_with()


@pytest.mark.parametrize("path", ["/health/ready", "/health/email-delivery"])
async def test_internal_health_endpoints_reject_non_loopback_clients(path, monkeypatch):
    database_check = AsyncMock()
    redis_check = AsyncMock()
    preflight = AsyncMock()
    monkeypatch.setattr(main_module, "_check_database", database_check)
    monkeypatch.setattr(main_module, "_check_redis", redis_check)
    monkeypatch.setattr(email_sender.SMTPEmailSender, "preflight", preflight)

    response = await _get(path, client_address=("203.0.113.8", 4321))

    assert response.status_code == 403
    database_check.assert_not_awaited()
    redis_check.assert_not_awaited()
    preflight.assert_not_awaited()


async def test_readiness_returns_ready_after_database_and_redis_checks(monkeypatch):
    database_check = AsyncMock()
    redis_check = AsyncMock()
    monkeypatch.setattr(main_module, "_check_database", database_check)
    monkeypatch.setattr(main_module, "_check_redis", redis_check)

    response = await _get("/health/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    database_check.assert_awaited_once_with()
    redis_check.assert_awaited_once_with()


async def test_readiness_returns_503_when_database_is_unavailable(monkeypatch):
    monkeypatch.setattr(main_module, "_check_database", AsyncMock(side_effect=RuntimeError("db down")))
    redis_check = AsyncMock()
    monkeypatch.setattr(main_module, "_check_redis", redis_check)

    response = await _get("/health/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    redis_check.assert_awaited_once_with()


async def test_readiness_returns_503_when_redis_is_unavailable(monkeypatch):
    monkeypatch.setattr(main_module, "_check_database", AsyncMock())
    monkeypatch.setattr(main_module, "_check_redis", AsyncMock(side_effect=RuntimeError("redis down")))

    response = await _get("/health/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"


async def test_readiness_cancels_hanging_sibling_when_one_dependency_fails(monkeypatch):
    redis_started = asyncio.Event()
    redis_cancelled = asyncio.Event()
    blocker = asyncio.Event()

    async def failing_database_check():
        await redis_started.wait()
        raise RuntimeError("db down")

    async def hanging_redis_check():
        redis_started.set()
        try:
            await blocker.wait()
        except asyncio.CancelledError:
            redis_cancelled.set()
            raise

    monkeypatch.setattr(main_module, "_check_database", failing_database_check)
    monkeypatch.setattr(main_module, "_check_redis", hanging_redis_check)

    response = await _get("/health/ready")

    assert response.status_code == 503
    assert redis_cancelled.is_set()


async def test_readiness_bounds_parallel_dependency_checks_with_total_timeout(monkeypatch):
    blocker = asyncio.Event()

    async def blocked_database_check():
        await blocker.wait()

    redis_check = AsyncMock()
    monkeypatch.setattr(main_module, "_check_database", blocked_database_check)
    monkeypatch.setattr(main_module, "_check_redis", redis_check)
    monkeypatch.setattr(main_module, "READINESS_TIMEOUT_SECONDS", 0.01)

    response = await _get("/health/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    redis_check.assert_awaited_once_with()
