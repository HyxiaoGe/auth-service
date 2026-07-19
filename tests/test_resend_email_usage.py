"""Resend 发送选择、用量快照与管理员只读接口契约。"""

import asyncio
import json
from contextlib import suppress
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

import app.main as main_module
from app.config import Settings
from app.main import app
from app.security.deps import CurrentUser, get_current_superuser, get_current_user
from app.services import email_sender, email_usage
from app.services.email_sender import (
    DisabledEmailSender,
    EmailDeliveryError,
    ResendEmailSender,
    SMTPEmailSender,
)


def _settings(**overrides) -> Settings:
    values = {
        "auth_base_url": "http://localhost:8100",
        "email_login_enabled": True,
        "email_code_pepper": "x" * 32,
        "smtp_from_email": "login@example.com",
        "smtp_from_name": "Fusion",
        "smtp_smoke_recipient": "delivered+auth-service@resend.dev",
        "resend_api_key": "re_test_secret",
        "resend_monthly_quota": 3000,
        "resend_daily_quota": 100,
    }
    values.update(overrides)
    return Settings(**values)


class _FakeResendClient:
    def __init__(self, responses, calls, **kwargs):
        self.responses = responses
        self.calls = calls
        self.calls.append(("client", kwargs))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def post(self, url, **kwargs):
        self.calls.append(("post", url, kwargs))
        return self.responses.pop(0)


def _response(status_code=200, *, headers=None, payload=None) -> httpx.Response:
    return httpx.Response(
        status_code,
        headers=headers,
        json=payload or {"id": "email-id"},
        request=httpx.Request("POST", "https://api.resend.com/emails"),
    )


def test_resend_is_selected_only_for_an_explicit_api_key(monkeypatch):
    resend = _settings()
    monkeypatch.setattr(email_sender, "get_settings", lambda: resend)
    assert resend.email_login_ready is True

    monkeypatch.setattr(email_sender, "_smtp_verified", False)
    assert isinstance(email_sender.get_email_sender(), DisabledEmailSender)

    monkeypatch.setattr(email_sender, "_smtp_verified", True)
    assert isinstance(email_sender.get_email_sender(), ResendEmailSender)

    smtp = _settings(
        resend_api_key="",
        smtp_host="smtp.example.com",
    )
    monkeypatch.setattr(email_sender, "get_settings", lambda: smtp)
    assert smtp.email_login_ready is True
    assert isinstance(email_sender.get_email_sender(), SMTPEmailSender)


def test_resend_paid_plan_has_no_daily_quota_but_requires_positive_monthly_quota():
    paid = _settings(resend_daily_quota="paid")
    assert paid.resend_daily_quota == "paid"

    with pytest.raises(ValueError, match="resend_monthly_quota"):
        _settings(resend_monthly_quota=0)
    with pytest.raises(ValueError, match="resend_daily_quota"):
        _settings(resend_daily_quota=0)


def test_usage_period_end_stays_inside_the_displayed_month():
    key, period_start, period_end = email_usage._period(datetime(2026, 7, 19, tzinfo=UTC))

    assert key == "2026-07"
    assert period_start == "2026-07-01T00:00:00+00:00"
    assert period_end == "2026-07-31T23:59:59.999999+00:00"


async def test_resend_login_and_preflight_capture_sanitized_latest_usage(monkeypatch, fake_redis):
    calls = []
    responses = [
        _response(
            headers={
                "x-resend-monthly-quota": "12",
                "x-resend-daily-quota": "3",
                "ratelimit-limit": "5",
                "ratelimit-remaining": "4",
                "ratelimit-reset": "1",
            }
        ),
        _response(
            headers={
                "x-resend-monthly-quota": "13",
                "x-resend-daily-quota": "4",
                "ratelimit-limit": "5",
                "ratelimit-remaining": "3",
                "ratelimit-reset": "1",
            }
        ),
    ]
    monkeypatch.setattr(
        email_sender.httpx,
        "AsyncClient",
        lambda **kwargs: _FakeResendClient(responses, calls, **kwargs),
    )
    config = _settings()
    sender = ResendEmailSender(config)

    await sender.send_login_code("person@example.com", "123456", 300)
    await sender.preflight()

    posts = [call for call in calls if call[0] == "post"]
    assert len(posts) == 2
    assert posts[0][1] == "https://api.resend.com/emails"
    assert posts[0][2]["headers"]["Authorization"] == "Bearer re_test_secret"
    assert posts[0][2]["headers"]["User-Agent"] == "auth-service/1.0"
    assert posts[0][2]["headers"]["Idempotency-Key"].startswith("auth-service-login-otp-")
    assert "person@example.com" not in posts[0][2]["headers"]["Idempotency-Key"]
    assert "123456" not in posts[0][2]["headers"]["Idempotency-Key"]
    assert posts[0][2]["json"]["to"] == ["person@example.com"]
    assert posts[0][2]["json"]["tags"] == [{"name": "message_type", "value": "login_otp"}]
    assert "123456" in posts[0][2]["json"]["text"]
    assert posts[1][2]["json"]["to"] == ["delivered+auth-service@resend.dev"]
    assert posts[1][2]["json"]["tags"] == [{"name": "message_type", "value": "preflight"}]
    assert posts[1][2]["headers"]["Idempotency-Key"].startswith("auth-service-preflight-")
    assert "部署预检" in posts[1][2]["json"]["subject"]
    assert "123456" not in posts[1][2]["json"]["text"]

    keys = [key async for key in fake_redis.scan_iter("email_usage:resend:*")]
    assert len(keys) == 1
    raw = await fake_redis.get(keys[0])
    snapshot = json.loads(raw)
    assert snapshot["used_emails"] == 13
    assert snapshot["daily_used_emails"] == 4
    assert snapshot["rate_limit"] == 5
    assert snapshot["rate_limit_remaining"] == 3
    assert snapshot["rate_limit_reset_seconds"] == 1
    assert "re_test_secret" not in raw
    assert "person@example.com" not in raw
    assert "123456" not in raw

    usage = await email_usage.get_email_usage(config)
    assert usage == {
        "provider": "resend",
        "configured": True,
        "available": True,
        "used_emails": 13,
        "monthly_quota": 3000,
        "remaining_emails": 2987,
        "usage_ratio": pytest.approx(13 / 3000),
        "daily_used_emails": 4,
        "daily_quota": 100,
        "period_start": snapshot["period_start"],
        "period_end": snapshot["period_end"],
        "synced_at": snapshot["synced_at"],
        "source": "resend_response_headers",
    }


async def test_existing_acceptance_monitor_uses_resend_sender_abstraction(monkeypatch):
    preflight = AsyncMock()
    monkeypatch.setattr(ResendEmailSender, "preflight", preflight)
    email_sender.invalidate_smtp_verification()
    task = asyncio.create_task(
        email_sender.monitor_smtp_verification(_settings(), retry_seconds=0, max_retry_seconds=0)
    )
    try:
        for _ in range(100):
            if preflight.await_count:
                break
            await asyncio.sleep(0)
        assert preflight.await_count == 1
        assert email_sender.is_smtp_verified() is True
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


async def test_email_delivery_health_preserves_smtp_value_and_reports_resend_provider(monkeypatch):
    monkeypatch.setattr(main_module, "settings", _settings())
    monkeypatch.setattr(email_sender, "_smtp_verified", True)
    monkeypatch.setattr(email_sender, "wait_for_smtp_verification", AsyncMock(return_value=True))

    transport = ASGITransport(app=app, client=("127.0.0.1", 1234))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health/email-delivery")

    assert response.status_code == 200
    assert response.json()["verification"] == "resend_api_accepted_only"


async def test_resend_error_is_generic_and_does_not_persist_provider_response(monkeypatch, fake_redis):
    calls = []
    responses = [_response(403, payload={"message": "provider-sensitive-detail"})]
    monkeypatch.setattr(
        email_sender.httpx,
        "AsyncClient",
        lambda **kwargs: _FakeResendClient(responses, calls, **kwargs),
    )

    with pytest.raises(EmailDeliveryError) as exc:
        await ResendEmailSender(_settings()).send_login_code("person@example.com", "123456", 300)

    assert str(exc.value) == "Resend delivery failed"
    assert "provider-sensitive-detail" not in repr(exc.value)
    assert "re_test_secret" not in repr(exc.value)
    assert [key async for key in fake_redis.scan_iter("email_usage:resend:*")] == []


@pytest.mark.parametrize("status_code", [400, 422, 429])
async def test_resend_request_failures_do_not_revoke_global_delivery_readiness(
    monkeypatch,
    tmp_path,
    status_code,
):
    calls = []
    responses = [_response(), _response(status_code)]
    monkeypatch.setattr(
        email_sender.httpx,
        "AsyncClient",
        lambda **kwargs: _FakeResendClient(responses, calls, **kwargs),
    )
    config = _settings(
        resend_preflight_cache_path=str(tmp_path / "resend-preflight.json"),
        resend_preflight_cache_ttl_seconds=3600,
    )
    sender = ResendEmailSender(config)
    await sender.preflight()
    monkeypatch.setattr(email_sender, "_smtp_verified", True)

    with pytest.raises(EmailDeliveryError):
        await sender.send_login_code("person@example.com", "123456", 300)

    assert email_sender.is_smtp_verified() is True
    assert sender._preflight_cache_valid() is True


@pytest.mark.parametrize("status_code", [401, 403, 500])
async def test_resend_global_failures_revoke_delivery_readiness(
    monkeypatch,
    tmp_path,
    status_code,
):
    calls = []
    responses = [_response(), _response(status_code)]
    monkeypatch.setattr(
        email_sender.httpx,
        "AsyncClient",
        lambda **kwargs: _FakeResendClient(responses, calls, **kwargs),
    )
    config = _settings(
        resend_preflight_cache_path=str(tmp_path / "resend-preflight.json"),
        resend_preflight_cache_ttl_seconds=3600,
    )
    sender = ResendEmailSender(config)
    await sender.preflight()
    monkeypatch.setattr(email_sender, "_smtp_verified", True)

    with pytest.raises(EmailDeliveryError):
        await sender.send_login_code("person@example.com", "123456", 300)

    assert email_sender.is_smtp_verified() is False
    assert sender._preflight_cache_valid() is False


async def test_resend_retries_reuse_stable_idempotency_keys(monkeypatch):
    calls = []
    responses = [_response(500), _response(), _response(500), _response()]
    monkeypatch.setattr(
        email_sender.httpx,
        "AsyncClient",
        lambda **kwargs: _FakeResendClient(responses, calls, **kwargs),
    )
    config = _settings()

    with pytest.raises(EmailDeliveryError):
        await ResendEmailSender(config).send_login_code(
            "person@example.com", "123456", 300, delivery_id="flow-a"
        )
    await ResendEmailSender(config).send_login_code(
        "person@example.com", "123456", 300, delivery_id="flow-a"
    )

    preflight_sender = ResendEmailSender(config)
    with pytest.raises(EmailDeliveryError):
        await preflight_sender.preflight()
    await preflight_sender.preflight()

    posts = [call for call in calls if call[0] == "post"]
    login_keys = [call[2]["headers"]["Idempotency-Key"] for call in posts[:2]]
    preflight_keys = [call[2]["headers"]["Idempotency-Key"] for call in posts[2:]]
    assert login_keys[0] == login_keys[1]
    assert preflight_keys[0] == preflight_keys[1]
    assert login_keys[0] != preflight_keys[0]


async def test_development_preflight_cache_skips_hot_reload_requests(monkeypatch, tmp_path):
    calls = []
    responses = [_response()]
    monkeypatch.setattr(
        email_sender.httpx,
        "AsyncClient",
        lambda **kwargs: _FakeResendClient(responses, calls, **kwargs),
    )
    cache_path = tmp_path / "resend-preflight.json"
    config = _settings(
        resend_preflight_cache_path=str(cache_path),
        resend_preflight_cache_ttl_seconds=3600,
    )

    await ResendEmailSender(config).preflight()
    await ResendEmailSender(config).preflight()

    posts = [call for call in calls if call[0] == "post"]
    assert len(posts) == 1
    cache = cache_path.read_text()
    assert "re_test_secret" not in cache
    assert "login@example.com" not in cache
    assert "delivered+auth-service@resend.dev" not in cache


async def test_resend_delivery_failure_invalidates_development_preflight_cache(monkeypatch, tmp_path):
    calls = []
    responses = [_response(), _response(500), _response()]
    monkeypatch.setattr(
        email_sender.httpx,
        "AsyncClient",
        lambda **kwargs: _FakeResendClient(responses, calls, **kwargs),
    )
    config = _settings(
        resend_preflight_cache_path=str(tmp_path / "resend-preflight.json"),
        resend_preflight_cache_ttl_seconds=3600,
    )

    await ResendEmailSender(config).preflight()
    cached_sender = ResendEmailSender(config)
    await cached_sender.preflight()
    with pytest.raises(EmailDeliveryError):
        await cached_sender.send_login_code("person@example.com", "123456", 300)
    await ResendEmailSender(config).preflight()

    posts = [call for call in calls if call[0] == "post"]
    assert len(posts) == 3


async def test_missing_monthly_header_does_not_overwrite_last_valid_snapshot(monkeypatch, fake_redis):
    calls = []
    responses = [
        _response(headers={"x-resend-monthly-quota": "20", "ratelimit-remaining": "4"}),
        _response(headers={"x-resend-monthly-quota": "invalid", "ratelimit-remaining": "3"}),
    ]
    monkeypatch.setattr(
        email_sender.httpx,
        "AsyncClient",
        lambda **kwargs: _FakeResendClient(responses, calls, **kwargs),
    )
    sender = ResendEmailSender(_settings())

    await sender.preflight()
    keys = [key async for key in fake_redis.scan_iter("email_usage:resend:*")]
    first = json.loads(await fake_redis.get(keys[0]))
    await sender.preflight()
    second = json.loads(await fake_redis.get(keys[0]))

    assert second["used_emails"] == 20
    assert second["synced_at"] == first["synced_at"]
    assert second["rate_limit_remaining"] == 4


async def test_concurrent_usage_snapshots_cannot_overwrite_a_higher_monthly_value(fake_redis):
    observed_at = "Sat, 18 Jul 2026 10:00:00 GMT"
    await asyncio.gather(
        *(
            email_usage.record_resend_usage(
                {
                    "date": observed_at,
                    "x-resend-monthly-quota": str(used),
                    "x-resend-daily-quota": str(used),
                }
            )
            for used in range(20, 0, -1)
        )
    )

    snapshot = json.loads(await fake_redis.get("email_usage:resend:2026-07"))
    assert snapshot["used_emails"] == 20
    assert snapshot["daily_used_emails"] == 20


async def test_provider_response_date_keeps_month_end_snapshots_in_the_correct_bucket(fake_redis):
    await email_usage.record_resend_usage(
        {
            "date": "Tue, 30 Jun 2026 23:59:59 GMT",
            "x-resend-monthly-quota": "2999",
        }
    )
    await email_usage.record_resend_usage(
        {
            "date": "Wed, 01 Jul 2026 00:00:00 GMT",
            "x-resend-monthly-quota": "1",
        }
    )

    june = json.loads(await fake_redis.get("email_usage:resend:2026-06"))
    july = json.loads(await fake_redis.get("email_usage:resend:2026-07"))
    assert june["used_emails"] == 2999
    assert july["used_emails"] == 1


async def test_unsynced_resend_usage_is_configured_but_unavailable():
    usage = await email_usage.get_email_usage(_settings(resend_daily_quota="paid"))

    assert usage["provider"] == "resend"
    assert usage["configured"] is True
    assert usage["available"] is False
    assert usage["used_emails"] is None
    assert usage["monthly_quota"] == 3000
    assert usage["remaining_emails"] is None
    assert usage["usage_ratio"] is None
    assert usage["daily_used_emails"] is None
    assert usage["daily_quota"] is None
    assert usage["period_start"] is not None
    assert usage["period_end"] is not None
    assert usage["synced_at"] is None
    assert usage["source"] == "not_synced"


async def test_smtp_configuration_does_not_make_resend_usage_card_configured():
    usage = await email_usage.get_email_usage(
        _settings(resend_api_key="", smtp_host="smtp.example.com")
    )

    assert usage["provider"] == "resend"
    assert usage["configured"] is False
    assert usage["available"] is False
    assert usage["source"] == "not_configured"


async def _admin_get():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get("/admin/email-usage")


async def test_email_usage_endpoint_requires_admin_scope():
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        sub="user-id",
        email="user@example.com",
        scopes=["user"],
    )
    try:
        response = await _admin_get()
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    assert response.json() == {"detail": "Admin access required"}


async def test_email_usage_endpoint_returns_read_only_snapshot_for_admin(monkeypatch):
    expected = {
        "provider": "resend",
        "configured": True,
        "available": False,
        "used_emails": None,
        "monthly_quota": 3000,
        "remaining_emails": None,
        "usage_ratio": None,
        "daily_used_emails": None,
        "daily_quota": 100,
        "period_start": "2026-07-01T00:00:00+00:00",
        "period_end": "2026-07-31T23:59:59.999999+00:00",
        "synced_at": None,
        "source": "not_synced",
    }

    async def fake_usage(_config):
        return expected

    monkeypatch.setattr(email_usage, "get_email_usage", fake_usage)
    app.dependency_overrides[get_current_superuser] = lambda: CurrentUser(
        sub="admin-id",
        email="admin@example.com",
        scopes=["admin"],
    )
    try:
        response = await _admin_get()
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() == expected
    assert response.headers["cache-control"] == "private, no-store"
