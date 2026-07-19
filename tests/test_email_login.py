"""集中式邮箱验证码登录的安全与协议契约。"""

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import Request
from pydantic import ValidationError

from app.config import Settings
from app.routers import auth, oauth
from app.schemas import EmailHeadlessSendRequest, OAuthTokenExchangeRequest, TokenResponse
from app.services import auth_service, email_login_service, email_sender, oauth_service
from app.services.email_sender import DisabledEmailSender, EmailDeliveryError, SMTPEmailSender
from app.utils import redis as redis_util
from app.utils.redis import get_email_flow

CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CALLBACK = "https://app.example/cb"


class _User:
    def __init__(self, email="Stored.User@Example.com", *, active=True, superuser=False):
        self.id = uuid.uuid4()
        self.email = email
        self.is_active = active
        self.is_superuser = superuser


class _Scalars:
    def __init__(self, users):
        self._users = users

    def all(self):
        return list(self._users)


class _Result:
    def __init__(self, users):
        self._users = users

    def scalars(self):
        return _Scalars(self._users)

    def scalar_one_or_none(self):
        return self._users[0] if len(self._users) == 1 else None


class _DB:
    def __init__(self, users=()):
        self.users = list(users)

    async def execute(self, _query):
        return _Result(self.users)


class _FakeSender:
    available = True

    def __init__(self, *, fail=False):
        self.fail = fail
        self.sent = []

    async def send_login_code(self, recipient, code, ttl_seconds, delivery_id=None):
        self.sent.append((recipient, code, ttl_seconds))
        if self.fail:
            raise EmailDeliveryError("provider unavailable")


def _settings(**overrides):
    values = {
        "auth_base_url": "https://auth.example.com",
        "email_login_enabled": True,
        "email_code_pepper": "test-only-pepper-with-32-characters",
        "smtp_host": "smtp.example.com",
        "smtp_from_email": "login@example.com",
        "smtp_smoke_recipient": "smtp-smoke@example.com",
        "email_code_ttl_seconds": 300,
        "email_flow_ttl_seconds": 600,
        "email_code_resend_seconds": 60,
        "email_code_max_attempts": 3,
        "email_rate_limit_per_email": 5,
        "email_rate_limit_per_ip": 20,
        "email_rate_limit_per_flow": 3,
        "email_send_rate_limit_global": 1000,
        "email_authorize_rate_limit_per_ip": 60,
        "email_authorize_rate_limit_per_client": 120,
        "email_authorize_rate_limit_global": 2000,
        "email_rate_limit_window_seconds": 3600,
        "email_flow_max_per_browser": 5,
        "trusted_proxy_cidrs": "172.25.0.10/32",
    }
    values.update(overrides)
    return Settings(**values)


def _request(cookie_name=None, cookie_value=None, ip="10.0.0.8", origin="https://auth.example.com"):
    headers = [(b"origin", origin.encode())] if origin is not None else []
    if cookie_name and cookie_value:
        headers.append((b"cookie", f"{cookie_name}={cookie_value}".encode()))
    return Request({"type": "http", "headers": headers, "client": (ip, 1234)})


async def _flow(config=None, redirect_uri=CALLBACK, browser_cookie=None, **overrides):
    config = config or _settings(**overrides)
    started = await email_login_service.create_email_flow(
        client_id="appA",
        redirect_uri=redirect_uri,
        app_state="STATE",
        code_challenge=CHALLENGE,
        browser_cookie=browser_cookie,
        config=config,
    )
    return config, started


def test_normalize_email_strips_and_uses_database_lower_rule():
    assert email_login_service.normalize_email("  Stored.User@EXAMPLE.COM  ") == "stored.user@example.com"


def test_normalize_email_converts_unicode_domain_to_ascii_idna():
    assert email_login_service.normalize_email("User@bücher.example") == "user@xn--bcher-kva.example"


@pytest.mark.parametrize("email", ["Straße@example.com", "İ@example.com", "user name@example.com"])
def test_normalize_email_rejects_local_parts_that_cannot_match_postgres_ascii_rule(email):
    with pytest.raises(ValueError, match="invalid canonical email"):
        email_login_service.normalize_email(email)


def test_email_request_schema_rejects_non_ascii_local_part_before_service_call():
    with pytest.raises(ValidationError):
        EmailHeadlessSendRequest(flow_id="x" * 16, email="Straße@example.com")


def test_smtp_starttls_uses_system_default_certificate_context(monkeypatch):
    context = object()
    calls = {}

    class FakeSMTP:
        def __init__(self, host, port, **kwargs):
            calls["connect"] = (host, port, kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def starttls(self, **kwargs):
            calls["starttls"] = kwargs

        def login(self, *_args):
            return None

        def send_message(self, _message):
            calls["sent"] = True

    monkeypatch.setattr(email_sender.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(email_sender.smtplib, "SMTP", FakeSMTP)
    SMTPEmailSender(_settings())._send_sync("user@example.com", "123456", 300)

    assert calls["starttls"] == {"context": context}
    assert calls["sent"] is True


def test_smtp_ssl_uses_system_default_certificate_context(monkeypatch):
    context = object()
    calls = {}

    class FakeSMTPSSL:
        def __init__(self, host, port, **kwargs):
            calls["connect"] = (host, port, kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def send_message(self, _message):
            calls["sent"] = True

    monkeypatch.setattr(email_sender.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(email_sender.smtplib, "SMTP_SSL", FakeSMTPSSL)
    SMTPEmailSender(_settings(smtp_starttls=False, smtp_use_ssl=True))._send_sync(
        "user@example.com", "123456", 300
    )

    assert calls["connect"][2]["context"] is context
    assert calls["sent"] is True


async def test_email_auth_code_exchange_keeps_stable_user_uuid_and_login_method(monkeypatch):
    user = _User("user@example.com")
    code = await oauth_service.mint_auth_code(
        user_id=str(user.id),
        client_id="appA",
        redirect_uri=CALLBACK,
        provider="email_otp",
        code_challenge=CHALLENGE,
    )
    captured = {}

    async def fake_issue_tokens(token_user, client_id, _db):
        captured["issued"] = (token_user.id, client_id)
        return TokenResponse(access_token="access", refresh_token="refresh", expires_in=900)

    async def fake_log_login(_db, user_id, client_id, method, _request, success=True, reason=None):
        captured["logged"] = (user_id, client_id, method, success, reason)

    monkeypatch.setattr(oauth.auth_service, "_issue_tokens", fake_issue_tokens)
    monkeypatch.setattr(oauth.auth_service, "_log_login", fake_log_login)
    tokens = await oauth.exchange_code_for_tokens(
        payload=OAuthTokenExchangeRequest(code=code, client_id="appA", code_verifier=VERIFIER),
        request=_request(),
        db=_DB([user]),
    )

    assert tokens.access_token == "access"
    assert captured["issued"] == (user.id, "appA")
    assert captured["logged"][:3] == (user.id, "appA", "email_otp")


@pytest.mark.parametrize(("superuser", "expected_scopes"), [(False, ["user"]), (True, ["admin"])])
async def test_email_login_token_uses_existing_user_scope_and_uuid(monkeypatch, superuser, expected_scopes):
    user = _User("user@example.com", superuser=superuser)
    captured = {}

    def fake_access_token(**kwargs):
        captured["access"] = kwargs
        return "access"

    def fake_refresh_token(**kwargs):
        captured["refresh"] = kwargs
        return "refresh", "hash", datetime.now(UTC) + timedelta(days=1)

    class TokenDB:
        def add(self, value):
            captured["stored"] = value

        async def commit(self):
            captured["committed"] = True

    monkeypatch.setattr(auth_service, "create_access_token", fake_access_token)
    monkeypatch.setattr(auth_service, "create_refresh_token", fake_refresh_token)
    tokens = await auth_service._issue_tokens(user, "appA", TokenDB())

    assert tokens.access_token == "access"
    assert captured["access"]["user_id"] == str(user.id)
    assert captured["access"]["scopes"] == expected_scopes
    assert captured["refresh"]["user_id"] == str(user.id)
    assert captured["stored"].user_id == user.id
    assert captured["committed"] is True


async def test_flow_cookie_nonce_is_required_and_oauth_context_stays_server_side():
    config, started = await _flow()

    stored = await get_email_flow(started.flow_id)
    assert stored["client_id"] == "appA"
    assert stored["redirect_uri"] == CALLBACK
    assert stored["app_state"] == "STATE"
    assert stored["code_challenge"] == CHALLENGE
    assert "nonce" not in stored
    assert await email_login_service.get_bound_email_flow(started.flow_id, "wrong", config=config) is None
    assert (
        await email_login_service.get_bound_email_flow(started.flow_id, started.cookie_value, config=config)
        == stored
    )


async def test_stable_browser_cookie_allows_two_tabs_and_rejects_other_browser():
    config, first = await _flow()
    _, second = await _flow(config, browser_cookie=first.cookie_value)

    assert first.cookie_name == second.cookie_name == "__Host-email_browser"
    assert first.cookie_value == second.cookie_value
    assert await email_login_service.get_bound_email_flow(first.flow_id, first.cookie_value, config=config)
    assert await email_login_service.get_bound_email_flow(second.flow_id, second.cookie_value, config=config)
    assert await email_login_service.get_bound_email_flow(first.flow_id, "x" * 43, config=config) is None


async def test_browser_flow_limit_evicts_oldest_flow_and_recovery():
    config, first = await _flow(email_flow_max_per_browser=2)
    _, second = await _flow(config, browser_cookie=first.cookie_value)
    _, third = await _flow(config, browser_cookie=first.cookie_value)

    assert await get_email_flow(first.flow_id) is None
    assert await email_login_service.get_bound_email_flow_recovery(
        first.flow_id,
        first.cookie_value,
        first.csrf_token,
        config=config,
    ) is None
    assert await get_email_flow(second.flow_id) is not None
    assert await get_email_flow(third.flow_id) is not None


async def test_existing_active_user_gets_hmac_stored_code_without_plaintext_or_email(fake_redis):
    config, started = await _flow()
    user = _User()
    sender = _FakeSender()

    result = await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email="  STORED.user@example.COM ",
        client_ip="10.0.0.8",
        db=_DB([user]),
        sender=sender,
        config=config,
    )

    assert result.accepted is True
    assert sender.sent and sender.sent[0][0] == user.email
    sent_code = sender.sent[0][1]
    raw_values = [await fake_redis.get(key) async for key in fake_redis.scan_iter("email_otp:*")]
    serialized = " ".join(value or "" for value in raw_values)
    assert sent_code not in serialized
    assert user.email not in serialized
    assert "stored.user@example.com" not in serialized
    assert "code_mac" in serialized


async def test_unknown_email_is_delivered_but_inactive_email_is_not():
    config, unknown_flow = await _flow()
    sender = _FakeSender()
    unknown = await email_login_service.request_login_code(
        flow_id=unknown_flow.flow_id,
        flow_cookie=unknown_flow.cookie_value,
        email="missing@example.com",
        client_ip="10.0.0.8",
        db=_DB(),
        sender=sender,
        config=config,
    )

    _, inactive_flow = await _flow(config)
    inactive = await email_login_service.request_login_code(
        flow_id=inactive_flow.flow_id,
        flow_cookie=inactive_flow.cookie_value,
        email="disabled@example.com",
        client_ip="10.0.0.9",
        db=_DB([_User("disabled@example.com", active=False)]),
        sender=sender,
        config=config,
    )

    assert unknown == inactive
    assert unknown.accepted is True
    assert len(sender.sent) == 1
    assert sender.sent[0][0] == "missing@example.com"


async def test_delivery_failure_keeps_uncertain_code_verifiable_with_generic_response():
    config, started = await _flow()
    user = _User("user@example.com")
    sender = _FakeSender(fail=True)

    result = await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email="user@example.com",
        client_ip="10.0.0.8",
        db=_DB([user]),
        sender=sender,
        config=config,
    )

    assert result.accepted is True
    verified = await email_login_service.verify_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        code=sender.sent[0][1],
        db=_DB([user]),
        config=config,
    )
    assert verified is not None and verified.user.id == user.id


async def test_failed_resend_keeps_previous_delivered_code_valid(fake_redis):
    config, started = await _flow()
    user = _User("user@example.com")
    db = _DB([user])
    first_sender = _FakeSender()
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="10.0.0.8",
        db=db,
        sender=first_sender,
        config=config,
    )
    old_code = first_sender.sent[0][1]
    cooldown_keys = [key async for key in fake_redis.scan_iter("email_cooldown:*")]
    await fake_redis.delete(*cooldown_keys)

    failed_sender = _FakeSender(fail=True)
    result = await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="10.0.0.8",
        db=db,
        sender=failed_sender,
        defer_delivery=True,
        config=config,
    )

    assert result.accepted is True
    assert failed_sender.sent == []
    await email_login_service.complete_login_code_delivery(result.delivery, failed_sender)
    verified = await email_login_service.verify_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        code=old_code,
        db=db,
        config=config,
    )
    assert verified is not None and verified.user.id == user.id


async def test_failed_resend_keeps_uncertain_new_code_valid(fake_redis):
    config, started = await _flow()
    user = _User("user@example.com")
    db = _DB([user])
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="10.0.0.8",
        db=db,
        sender=_FakeSender(),
        config=config,
    )
    cooldown_keys = [key async for key in fake_redis.scan_iter("email_cooldown:*")]
    await fake_redis.delete(*cooldown_keys)
    failed_sender = _FakeSender(fail=True)
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="10.0.0.8",
        db=db,
        sender=failed_sender,
        config=config,
    )

    verified = await email_login_service.verify_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        code=failed_sender.sent[0][1],
        db=db,
        config=config,
    )
    assert verified is not None and verified.user.id == user.id


async def test_successful_resend_invalidates_old_code(fake_redis):
    config, started = await _flow()
    user = _User("user@example.com")
    db = _DB([user])
    first_sender = _FakeSender()
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="10.0.0.8",
        db=db,
        sender=first_sender,
        config=config,
    )
    cooldown_keys = [key async for key in fake_redis.scan_iter("email_cooldown:*")]
    await fake_redis.delete(*cooldown_keys)
    second_sender = _FakeSender()
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="10.0.0.8",
        db=db,
        sender=second_sender,
        config=config,
    )

    assert await email_login_service.verify_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        code=first_sender.sent[0][1],
        db=db,
        config=config,
    ) is None
    verified = await email_login_service.verify_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        code=second_sender.sent[0][1],
        db=db,
        config=config,
    )
    assert verified is not None and verified.user.id == user.id


async def test_staging_new_code_does_not_extend_expired_active_code(monkeypatch, fake_redis):
    clock = {"now": 1_000.0}
    monkeypatch.setattr(email_login_service, "current_timestamp", lambda: clock["now"])
    monkeypatch.setattr(redis_util, "current_timestamp", lambda: clock["now"])
    config, started = await _flow(email_code_ttl_seconds=10)
    user = _User("user@example.com")
    db = _DB([user])
    first_sender = _FakeSender()
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="10.0.0.8",
        db=db,
        sender=first_sender,
        config=config,
    )
    clock["now"] = 1_011.0
    cooldown_keys = [key async for key in fake_redis.scan_iter("email_cooldown:*")]
    await fake_redis.delete(*cooldown_keys)
    deferred = await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="10.0.0.8",
        db=db,
        sender=_FakeSender(),
        defer_delivery=True,
        config=config,
    )

    raw = await fake_redis.get(f"email_otp:{started.flow_id}")
    record = json.loads(raw)
    assert record["active"] is None
    assert record["pending"]["expires_at"] == 1_021.0
    assert await email_login_service.verify_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        code=first_sender.sent[0][1],
        db=db,
        config=config,
    ) is None
    assert deferred.delivery is not None


async def test_resend_cooldown_and_rate_limit_are_enforced_for_every_email():
    config, started = await _flow(email_rate_limit_per_email=1, email_code_resend_seconds=60)
    sender = _FakeSender()
    first = await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email="missing@example.com",
        client_ip="10.0.0.8",
        db=_DB(),
        sender=sender,
        config=config,
    )
    second = await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email="missing@example.com",
        client_ip="10.0.0.8",
        db=_DB(),
        sender=sender,
        config=config,
    )

    assert first.accepted is True
    assert second.accepted is False
    assert second.retry_after > 0


async def test_first_rate_counters_are_created_with_ttl(fake_redis):
    config, started = await _flow()
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email="missing@example.com",
        client_ip="10.0.0.8",
        db=_DB(),
        sender=_FakeSender(),
        config=config,
    )

    keys = [key async for key in fake_redis.scan_iter("email_rate_*")]
    assert len(keys) == 4
    ttls = [await fake_redis.ttl(key) for key in keys]
    assert all(ttl > 0 for ttl in ttls)


async def test_concurrent_first_rate_increments_all_keep_fixed_window_ttl(fake_redis):
    from app.utils.redis import acquire_email_send_slot

    await asyncio.gather(
        *[
            acquire_email_send_slot(
                f"mail-{index}",
                "shared-ip",
                f"flow-{index}",
                cooldown_seconds=60,
                window_seconds=3600,
                email_limit=100,
                ip_limit=100,
                flow_limit=100,
                global_limit=100,
            )
            for index in range(20)
        ]
    )

    assert await fake_redis.get("email_rate_ip:shared-ip") == "20"
    assert 0 < await fake_redis.ttl("email_rate_ip:shared-ip") <= 3600


@pytest.mark.parametrize("blocked_dimension", ["ip", "flow", "global"])
async def test_send_rejection_does_not_poison_target_email_or_other_rate_buckets(
    blocked_dimension,
    fake_redis,
):
    from app.utils.redis import acquire_email_send_slot

    limits = {
        "email_limit": 100,
        "ip_limit": 1 if blocked_dimension == "ip" else 100,
        "flow_limit": 1 if blocked_dimension == "flow" else 100,
        "global_limit": 1 if blocked_dimension == "global" else 100,
    }
    assert (
        await acquire_email_send_slot(
            "prime-email",
            "shared-ip" if blocked_dimension == "ip" else "prime-ip",
            "shared-flow" if blocked_dimension == "flow" else "prime-flow",
            cooldown_seconds=60,
            window_seconds=3600,
            **limits,
        )
    )[0]
    before = {
        key: await fake_redis.get(key)
        async for key in fake_redis.scan_iter("email_rate_*")
    }

    allowed, _ = await acquire_email_send_slot(
        "victim-email",
        "shared-ip" if blocked_dimension == "ip" else "victim-ip",
        "shared-flow" if blocked_dimension == "flow" else "victim-flow",
        cooldown_seconds=60,
        window_seconds=3600,
        **limits,
    )

    assert allowed is False
    assert await fake_redis.exists("email_cooldown:victim-email") == 0
    assert await fake_redis.exists("email_rate_email:victim-email") == 0
    assert {
        key: await fake_redis.get(key)
        async for key in fake_redis.scan_iter("email_rate_*")
    } == before


@pytest.mark.parametrize(
    ("shared_dimension", "client_digest", "ip_digest"),
    [
        ("ip", "victim-client", "shared-ip"),
        ("client", "shared-client", "victim-ip"),
        ("global", "victim-client", "victim-ip"),
    ],
)
async def test_authorize_rejection_does_not_partially_increment_other_buckets(
    shared_dimension,
    client_digest,
    ip_digest,
    fake_redis,
):
    from app.utils.redis import acquire_email_authorize_slot

    limits = {
        "ip_limit": 1 if shared_dimension == "ip" else 100,
        "client_limit": 1 if shared_dimension == "client" else 100,
        "global_limit": 1 if shared_dimension == "global" else 100,
    }
    assert (
        await acquire_email_authorize_slot(
            "shared-client" if shared_dimension == "client" else "prime-client",
            "shared-ip" if shared_dimension == "ip" else "prime-ip",
            window_seconds=3600,
            **limits,
        )
    )[0]
    before = {
        key: await fake_redis.get(key)
        async for key in fake_redis.scan_iter("email_rate_authorize*")
    }

    allowed, _ = await acquire_email_authorize_slot(
        client_digest,
        ip_digest,
        window_seconds=3600,
        **limits,
    )

    assert allowed is False
    assert {
        key: await fake_redis.get(key)
        async for key in fake_redis.scan_iter("email_rate_authorize*")
    } == before


@pytest.mark.parametrize("limited_dimension", ["ip", "flow", "global"])
async def test_concurrent_send_rate_limit_is_a_strict_bound(limited_dimension, fake_redis):
    from app.utils.redis import acquire_email_send_slot

    limit = 5
    results = await asyncio.gather(
        *[
            acquire_email_send_slot(
                f"mail-{index}",
                "shared-ip" if limited_dimension == "ip" else f"ip-{index}",
                "shared-flow" if limited_dimension == "flow" else f"flow-{index}",
                cooldown_seconds=60,
                window_seconds=3600,
                email_limit=100,
                ip_limit=limit if limited_dimension == "ip" else 100,
                flow_limit=limit if limited_dimension == "flow" else 100,
                global_limit=limit if limited_dimension == "global" else 100,
            )
            for index in range(20)
        ]
    )

    assert sum(allowed for allowed, _ in results) == limit
    key = {
        "ip": "email_rate_ip:shared-ip",
        "flow": "email_rate_flow:shared-flow",
        "global": "email_rate_send_global",
    }[limited_dimension]
    assert await fake_redis.get(key) == str(limit)
    assert 0 < await fake_redis.ttl(key) <= 3600


async def test_concurrent_same_email_acquires_only_one_cooldown_slot(fake_redis):
    from app.utils.redis import acquire_email_send_slot

    results = await asyncio.gather(
        *[
            acquire_email_send_slot(
                "shared-email",
                f"ip-{index}",
                f"flow-{index}",
                cooldown_seconds=60,
                window_seconds=3600,
                email_limit=100,
                ip_limit=100,
                flow_limit=100,
                global_limit=100,
            )
            for index in range(20)
        ]
    )

    assert sum(allowed for allowed, _ in results) == 1
    assert await fake_redis.get("email_rate_email:shared-email") == "1"
    assert 0 < await fake_redis.ttl("email_rate_email:shared-email") <= 3600
    assert 0 < await fake_redis.ttl("email_cooldown:shared-email") <= 60


@pytest.mark.parametrize("limited_dimension", ["ip", "client", "global"])
async def test_concurrent_authorize_rate_limit_is_a_strict_bound(limited_dimension, fake_redis):
    from app.utils.redis import acquire_email_authorize_slot

    limit = 5
    results = await asyncio.gather(
        *[
            acquire_email_authorize_slot(
                "shared-client" if limited_dimension == "client" else f"client-{index}",
                "shared-ip" if limited_dimension == "ip" else f"ip-{index}",
                window_seconds=3600,
                client_limit=limit if limited_dimension == "client" else 100,
                ip_limit=limit if limited_dimension == "ip" else 100,
                global_limit=limit if limited_dimension == "global" else 100,
            )
            for index in range(20)
        ]
    )

    assert sum(allowed for allowed, _ in results) == limit
    key = {
        "ip": "email_rate_authorize_ip:shared-ip",
        "client": "email_rate_authorize_client:shared-client",
        "global": "email_rate_authorize_global",
    }[limited_dimension]
    assert await fake_redis.get(key) == str(limit)
    assert 0 < await fake_redis.ttl(key) <= 3600


@pytest.mark.parametrize("limited_dimension", ["ip", "global"])
async def test_concurrent_verify_request_rate_limit_is_a_strict_bound(limited_dimension, fake_redis):
    from app.utils.redis import acquire_email_verify_request_slot

    limit = 5
    results = await asyncio.gather(
        *[
            acquire_email_verify_request_slot(
                "shared-ip" if limited_dimension == "ip" else f"ip-{index}",
                window_seconds=3600,
                ip_limit=limit if limited_dimension == "ip" else 100,
                global_limit=limit if limited_dimension == "global" else 100,
            )
            for index in range(20)
        ]
    )

    assert sum(allowed for allowed, _ in results) == limit
    key = {
        "ip": "email_rate_verify_request_ip:shared-ip",
        "global": "email_rate_verify_request_global",
    }[limited_dimension]
    assert await fake_redis.get(key) == str(limit)
    assert 0 < await fake_redis.ttl(key) <= 3600


@pytest.mark.parametrize("limited_dimension", ["ip", "global"])
async def test_concurrent_send_request_rate_limit_is_a_strict_bound(limited_dimension, fake_redis):
    from app.utils.redis import acquire_email_send_request_slot

    limit = 5
    results = await asyncio.gather(
        *[
            acquire_email_send_request_slot(
                "shared-ip" if limited_dimension == "ip" else f"ip-{index}",
                window_seconds=3600,
                ip_limit=limit if limited_dimension == "ip" else 100,
                global_limit=limit if limited_dimension == "global" else 100,
            )
            for index in range(20)
        ]
    )

    assert sum(allowed for allowed, _ in results) == limit
    key = {
        "ip": "email_rate_send_request_ip:shared-ip",
        "global": "email_rate_send_request_global",
    }[limited_dimension]
    assert await fake_redis.get(key) == str(limit)
    assert 0 < await fake_redis.ttl(key) <= 3600


async def test_concurrent_send_request_flow_rate_limit_is_a_strict_bound(fake_redis):
    from app.utils.redis import acquire_email_send_request_flow_slot

    results = await asyncio.gather(
        *[
            acquire_email_send_request_flow_slot(
                "shared-flow",
                window_seconds=3600,
                flow_limit=5,
            )
            for _ in range(20)
        ]
    )

    assert sum(allowed for allowed, _ in results) == 5
    assert await fake_redis.get("email_rate_send_request_flow:shared-flow") == "5"


async def test_send_request_rejection_does_not_increment_other_bucket_and_returns_ttl(fake_redis):
    from app.utils.redis import acquire_email_send_request_slot

    assert (
        await acquire_email_send_request_slot(
            "prime-ip",
            window_seconds=3600,
            ip_limit=100,
            global_limit=1,
        )
    )[0]
    await fake_redis.expire("email_rate_send_request_global", 7)
    before = {
        key: await fake_redis.get(key)
        async for key in fake_redis.scan_iter("email_rate_send_request*")
    }

    allowed, retry_after = await acquire_email_send_request_slot(
        "victim-ip",
        window_seconds=3600,
        ip_limit=100,
        global_limit=1,
    )

    assert allowed is False
    assert 1 <= retry_after <= 7
    assert {
        key: await fake_redis.get(key)
        async for key in fake_redis.scan_iter("email_rate_send_request*")
    } == before


async def test_concurrent_verify_flow_rate_limit_is_a_strict_bound(fake_redis):
    from app.utils.redis import acquire_email_verify_flow_slot

    results = await asyncio.gather(
        *[
            acquire_email_verify_flow_slot(
                "shared-flow",
                window_seconds=3600,
                flow_limit=5,
            )
            for _ in range(20)
        ]
    )

    assert sum(allowed for allowed, _ in results) == 5
    assert await fake_redis.get("email_rate_verify_flow:shared-flow") == "5"
    assert 0 < await fake_redis.ttl("email_rate_verify_flow:shared-flow") <= 3600


async def test_verify_request_rejection_does_not_increment_other_bucket(fake_redis):
    from app.utils.redis import acquire_email_verify_request_slot

    assert (
        await acquire_email_verify_request_slot(
            "prime-ip",
            window_seconds=3600,
            ip_limit=100,
            global_limit=1,
        )
    )[0]
    before = {
        key: await fake_redis.get(key)
        async for key in fake_redis.scan_iter("email_rate_verify_request*")
    }

    allowed, retry_after = await acquire_email_verify_request_slot(
        "victim-ip",
        window_seconds=3600,
        ip_limit=100,
        global_limit=1,
    )

    assert allowed is False
    assert retry_after > 0
    assert {
        key: await fake_redis.get(key)
        async for key in fake_redis.scan_iter("email_rate_verify_request*")
    } == before


async def test_verify_rate_limits_use_fixed_window_and_actual_retry_after(fake_redis):
    from app.utils.redis import acquire_email_verify_request_slot

    assert (
        await acquire_email_verify_request_slot(
            "shared-ip",
            window_seconds=3600,
            ip_limit=1,
            global_limit=100,
        )
    )[0]
    await fake_redis.expire("email_rate_verify_request_ip:shared-ip", 7)

    allowed, retry_after = await acquire_email_verify_request_slot(
        "shared-ip",
        window_seconds=3600,
        ip_limit=1,
        global_limit=100,
    )

    assert allowed is False
    assert 1 <= retry_after <= 7
    assert await fake_redis.get("email_rate_verify_request_global") == "1"


async def test_verify_ip_and_flow_rate_buckets_are_isolated(fake_redis):
    from app.utils.redis import acquire_email_verify_flow_slot, acquire_email_verify_request_slot

    assert (
        await acquire_email_verify_request_slot(
            "ip-one",
            window_seconds=3600,
            ip_limit=1,
            global_limit=100,
        )
    )[0]
    assert not (
        await acquire_email_verify_request_slot(
            "ip-one",
            window_seconds=3600,
            ip_limit=1,
            global_limit=100,
        )
    )[0]
    assert (
        await acquire_email_verify_request_slot(
            "ip-two",
            window_seconds=3600,
            ip_limit=1,
            global_limit=100,
        )
    )[0]

    assert (
        await acquire_email_verify_flow_slot(
            "flow-one",
            window_seconds=3600,
            flow_limit=1,
        )
    )[0]
    assert not (
        await acquire_email_verify_flow_slot(
            "flow-one",
            window_seconds=3600,
            flow_limit=1,
        )
    )[0]
    assert (
        await acquire_email_verify_flow_slot(
            "flow-two",
            window_seconds=3600,
            flow_limit=1,
        )
    )[0]


async def test_existing_fixed_window_ttl_does_not_slide_on_accept(fake_redis):
    from app.utils.redis import acquire_email_send_slot

    assert (
        await acquire_email_send_slot(
            "mail-1",
            "shared-ip",
            "shared-flow",
            cooldown_seconds=60,
            window_seconds=3600,
            email_limit=100,
            ip_limit=100,
            flow_limit=100,
            global_limit=100,
        )
    )[0]
    existing_keys = ["email_rate_ip:shared-ip", "email_rate_flow:shared-flow", "email_rate_send_global"]
    for key in existing_keys:
        await fake_redis.expire(key, 7)

    assert (
        await acquire_email_send_slot(
            "mail-2",
            "shared-ip",
            "shared-flow",
            cooldown_seconds=60,
            window_seconds=3600,
            email_limit=100,
            ip_limit=100,
            flow_limit=100,
            global_limit=100,
        )
    )[0]
    ttls = [await fake_redis.ttl(key) for key in existing_keys]
    assert all(0 < ttl <= 7 for ttl in ttls)


async def test_subsecond_existing_window_uses_keepttl_instead_of_restarting_full_window(fake_redis):
    from app.utils.redis import acquire_email_send_slot

    assert (
        await acquire_email_send_slot(
            "mail-1",
            "shared-ip",
            "shared-flow",
            cooldown_seconds=60,
            window_seconds=3600,
            email_limit=100,
            ip_limit=100,
            flow_limit=100,
            global_limit=100,
        )
    )[0]
    existing_keys = ["email_rate_ip:shared-ip", "email_rate_flow:shared-flow", "email_rate_send_global"]
    for key in existing_keys:
        await fake_redis.pexpire(key, 500)

    assert (
        await acquire_email_send_slot(
            "mail-2",
            "shared-ip",
            "shared-flow",
            cooldown_seconds=60,
            window_seconds=3600,
            email_limit=100,
            ip_limit=100,
            flow_limit=100,
            global_limit=100,
        )
    )[0]
    pttls = [await fake_redis.pttl(key) for key in existing_keys]
    assert all(0 < pttl <= 500 for pttl in pttls)


async def test_send_retry_after_uses_actual_remaining_blocking_ttl(fake_redis):
    from app.utils.redis import acquire_email_send_slot

    assert (
        await acquire_email_send_slot(
            "mail-1",
            "shared-ip",
            "flow-1",
            cooldown_seconds=60,
            window_seconds=3600,
            email_limit=100,
            ip_limit=1,
            flow_limit=100,
            global_limit=100,
        )
    )[0]
    await fake_redis.expire("email_rate_ip:shared-ip", 7)

    allowed, retry_after = await acquire_email_send_slot(
        "mail-2",
        "shared-ip",
        "flow-2",
        cooldown_seconds=60,
        window_seconds=3600,
        email_limit=100,
        ip_limit=1,
        flow_limit=100,
        global_limit=100,
    )

    assert allowed is False
    assert 1 <= retry_after <= 7


async def test_authorize_retry_after_uses_actual_remaining_blocking_ttl(fake_redis):
    from app.utils.redis import acquire_email_authorize_slot

    assert (
        await acquire_email_authorize_slot(
            "shared-client",
            "ip-1",
            window_seconds=3600,
            client_limit=1,
            ip_limit=100,
            global_limit=100,
        )
    )[0]
    await fake_redis.expire("email_rate_authorize_client:shared-client", 9)

    allowed, retry_after = await acquire_email_authorize_slot(
        "shared-client",
        "ip-2",
        window_seconds=3600,
        client_limit=1,
        ip_limit=100,
        global_limit=100,
    )

    assert allowed is False
    assert 1 <= retry_after <= 9


async def test_expired_counter_between_value_and_ttl_read_retries_snapshot(monkeypatch, fake_redis):
    from app.utils.redis import acquire_email_authorize_slot

    blocking_key = "email_rate_authorize_client:shared-client"
    await fake_redis.set(blocking_key, "1", ex=3600)
    original_pipeline = fake_redis.pipeline
    raced = False

    def racing_pipeline(*args, **kwargs):
        nonlocal raced
        pipe = original_pipeline(*args, **kwargs)
        if not raced:
            original_mget = pipe.mget

            async def mget_then_expire(keys):
                nonlocal raced
                values = await original_mget(keys)
                raced = True
                await fake_redis.delete(blocking_key)
                return values

            monkeypatch.setattr(pipe, "mget", mget_then_expire)
        return pipe

    monkeypatch.setattr(fake_redis, "pipeline", racing_pipeline)
    allowed, retry_after = await acquire_email_authorize_slot(
        "shared-client",
        "new-ip",
        window_seconds=3600,
        client_limit=1,
        ip_limit=100,
        global_limit=100,
    )

    assert raced is True
    assert (allowed, retry_after) == (True, 0)


async def test_authorize_flow_gate_enforces_ip_client_and_global_limits(fake_redis):
    async def clear_authorize_rates():
        keys = [key async for key in fake_redis.scan_iter("email_rate_authorize*")]
        if keys:
            await fake_redis.delete(*keys)

    client_config = _settings(email_authorize_rate_limit_per_client=1)
    assert (await email_login_service.acquire_email_flow_creation_slot("appA", "203.0.113.1", config=client_config))[0]
    assert not (
        await email_login_service.acquire_email_flow_creation_slot("appA", "203.0.113.2", config=client_config)
    )[0]

    await clear_authorize_rates()
    ip_config = _settings(email_authorize_rate_limit_per_ip=1)
    assert (await email_login_service.acquire_email_flow_creation_slot("appA", "203.0.113.1", config=ip_config))[0]
    assert not (
        await email_login_service.acquire_email_flow_creation_slot("appB", "203.0.113.1", config=ip_config)
    )[0]
    assert await fake_redis.get("email_rate_authorize_global") == "1"
    assert not (
        await email_login_service.acquire_email_flow_creation_slot("appC", "203.0.113.1", config=ip_config)
    )[0]
    assert await fake_redis.get("email_rate_authorize_global") == "1"

    await clear_authorize_rates()
    global_config = _settings(email_authorize_rate_limit_global=1)
    assert (await email_login_service.acquire_email_flow_creation_slot("appA", "203.0.113.1", config=global_config))[0]
    assert not (
        await email_login_service.acquire_email_flow_creation_slot("appB", "203.0.113.2", config=global_config)
    )[0]


async def test_send_global_limit_is_a_hard_bound_when_ip_identity_changes():
    config, first = await _flow(email_send_rate_limit_global=1)
    first_result = await email_login_service.request_login_code(
        flow_id=first.flow_id,
        flow_cookie=first.cookie_value,
        email="first-missing@example.com",
        client_ip="203.0.113.1",
        db=_DB(),
        sender=_FakeSender(),
        config=config,
    )
    _, second = await _flow(config, browser_cookie=first.cookie_value)
    second_result = await email_login_service.request_login_code(
        flow_id=second.flow_id,
        flow_cookie=second.cookie_value,
        email="second-missing@example.com",
        client_ip="203.0.113.2",
        db=_DB(),
        sender=_FakeSender(),
        config=config,
    )

    assert first_result.accepted is True
    assert second_result.accepted is False


async def test_send_ip_limit_rejections_do_not_consume_global_capacity(fake_redis):
    config, first = await _flow(email_rate_limit_per_ip=1)
    assert (
        await email_login_service.request_login_code(
            flow_id=first.flow_id,
            flow_cookie=first.cookie_value,
            email="first-missing@example.com",
            client_ip="203.0.113.1",
            db=_DB(),
            sender=_FakeSender(),
            config=config,
        )
    ).accepted
    for index in range(2):
        _, blocked_flow = await _flow(config, browser_cookie=first.cookie_value)
        blocked = await email_login_service.request_login_code(
            flow_id=blocked_flow.flow_id,
            flow_cookie=blocked_flow.cookie_value,
            email=f"blocked-{index}@example.com",
            client_ip="203.0.113.1",
            db=_DB(),
            sender=_FakeSender(),
            config=config,
        )
        assert blocked.accepted is False

    assert await fake_redis.get("email_rate_send_global") == "1"


async def test_one_flow_cannot_rotate_across_many_email_addresses(fake_redis):
    config, started = await _flow(email_rate_limit_per_flow=1)
    first = await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email="first@example.com",
        client_ip="10.0.0.8",
        db=_DB(),
        sender=_FakeSender(),
        config=config,
    )
    second = await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email="second@example.com",
        client_ip="10.0.0.8",
        db=_DB(),
        sender=_FakeSender(),
        config=config,
    )

    assert first.accepted is True
    assert second.accepted is False
    flow_keys = [key async for key in fake_redis.scan_iter("email_rate_flow:*")]
    assert len(flow_keys) == 1


async def test_code_has_max_attempts_and_is_single_use():
    config, started = await _flow()
    user = _User("user@example.com")
    sender = _FakeSender()
    db = _DB([user])
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="10.0.0.8",
        db=db,
        sender=sender,
        config=config,
    )
    code = sender.sent[0][1]

    assert await email_login_service.verify_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        code="000000" if code != "000000" else "999999",
        db=db,
        config=config,
    ) is None
    verified = await email_login_service.verify_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        code=code,
        db=db,
        config=config,
    )
    assert verified is not None and verified.user.id == user.id
    assert await email_login_service.verify_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        code=code,
        db=db,
        config=config,
    ) is None


async def test_concurrent_verification_consumes_code_once():
    config, started = await _flow()
    user = _User("user@example.com")
    sender = _FakeSender()
    db = _DB([user])
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="10.0.0.8",
        db=db,
        sender=sender,
        config=config,
    )

    results = await asyncio.gather(
        *[
            email_login_service.verify_login_code(
                flow_id=started.flow_id,
                flow_cookie=started.cookie_value,
                code=sender.sent[0][1],
                db=db,
                config=config,
            )
            for _ in range(2)
        ]
    )
    assert sum(result is not None for result in results) == 1


async def test_three_wrong_attempts_lock_the_code():
    config, started = await _flow()
    user = _User("user@example.com")
    sender = _FakeSender()
    db = _DB([user])
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=user.email,
        client_ip="10.0.0.8",
        db=db,
        sender=sender,
        config=config,
    )
    code = sender.sent[0][1]
    wrong = "000000" if code != "000000" else "999999"

    for _ in range(3):
        assert await email_login_service.verify_login_code(
            flow_id=started.flow_id,
            flow_cookie=started.cookie_value,
            code=wrong,
            db=db,
            config=config,
        ) is None
    assert await email_login_service.verify_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        code=code,
        db=db,
        config=config,
    ) is None


async def test_disabled_sender_is_fail_closed_before_user_lookup():
    config, started = await _flow()
    result = await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email="user@example.com",
        client_ip="10.0.0.8",
        db=_DB([_User("user@example.com")]),
        sender=DisabledEmailSender(),
        config=config,
    )
    assert result.accepted is False
    assert result.unavailable is True


async def test_email_flow_logs_neither_email_nor_code(caplog):
    config, started = await _flow()
    sender = _FakeSender()
    email = "private.person@example.com"
    await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=email,
        client_ip="10.0.0.8",
        db=_DB([_User(email)]),
        sender=sender,
        config=config,
    )

    assert email not in caplog.text
    assert sender.sent[0][1] not in caplog.text


async def test_email_flow_logs_do_not_distinguish_account_existence_or_delivery_failure(caplog):
    caplog.set_level("INFO", logger="app.services.email_login_service")
    config = _settings()

    async def request_messages(*, email: str, db: _DB, sender: _FakeSender) -> list[str]:
        _, started = await _flow(config)
        caplog.clear()
        await email_login_service.request_login_code(
            flow_id=started.flow_id,
            flow_cookie=started.cookie_value,
            email=email,
            client_ip="10.0.0.8",
            db=db,
            sender=sender,
            config=config,
        )
        return [record.getMessage() for record in caplog.records]

    existing = await request_messages(
        email="existing@example.com",
        db=_DB([_User("existing@example.com")]),
        sender=_FakeSender(),
    )
    unknown = await request_messages(
        email="unknown@example.com",
        db=_DB(),
        sender=_FakeSender(),
    )
    failed = await request_messages(
        email="failed@example.com",
        db=_DB([_User("failed@example.com")]),
        sender=_FakeSender(fail=True),
    )

    assert existing == unknown == failed == ["email_login.code_request_processed"]
    assert "account=" not in caplog.text
    assert "flow=" not in caplog.text


def test_client_ip_ignores_forged_forwarding_headers_from_untrusted_peer(monkeypatch):
    config = _settings(trusted_proxy_cidrs="", email_login_enabled=False)
    monkeypatch.setattr(auth, "settings", config)
    request = Request(
        {
            "type": "http",
            "client": ("10.0.0.8", 1234),
            "headers": [(b"x-forwarded-for", b"203.0.113.9"), (b"cf-connecting-ip", b"198.51.100.7")],
        }
    )
    assert auth._email_client_ip(request) == "10.0.0.8"


def test_client_ip_uses_forwarded_header_only_from_explicit_trusted_proxy(monkeypatch):
    config = _settings(trusted_proxy_cidrs="172.25.0.0/16")
    monkeypatch.setattr(auth, "settings", config)
    request = Request(
        {
            "type": "http",
            "client": ("172.25.0.12", 1234),
            "headers": [(b"x-forwarded-for", b"203.0.113.9, 172.25.0.2")],
        }
    )
    assert auth._email_client_ip(request) == "203.0.113.9"


def test_client_ip_ignores_forged_leftmost_xff_and_cf_header(monkeypatch):
    config = _settings(trusted_proxy_cidrs="172.25.0.10/32,172.25.0.1/32")
    monkeypatch.setattr(auth, "settings", config)
    request = Request(
        {
            "type": "http",
            "client": ("172.25.0.10", 1234),
            "headers": [
                (b"x-forwarded-for", b"198.51.100.66, 203.0.113.9, 172.25.0.1"),
                (b"cf-connecting-ip", b"198.51.100.77"),
            ],
        }
    )
    assert auth._email_client_ip(request) == "203.0.113.9"


def test_client_ip_skips_multiple_explicitly_trusted_hops_from_right(monkeypatch):
    config = _settings(trusted_proxy_cidrs="172.25.0.10/32,172.25.0.1/32,192.168.64.1/32")
    monkeypatch.setattr(auth, "settings", config)
    request = Request(
        {
            "type": "http",
            "client": ("172.25.0.10", 1234),
            "headers": [(b"x-forwarded-for", b"203.0.113.9, 192.168.64.1, 172.25.0.1")],
        }
    )
    assert auth._email_client_ip(request) == "203.0.113.9"


def test_client_ip_direct_connection_uses_peer(monkeypatch):
    monkeypatch.setattr(auth, "settings", _settings(trusted_proxy_cidrs="172.25.0.0/16"))
    assert auth._email_client_ip(_request(ip="192.0.2.10")) == "192.0.2.10"
