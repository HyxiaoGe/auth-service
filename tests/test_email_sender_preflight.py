import asyncio
from contextlib import suppress
from unittest.mock import AsyncMock

import pytest

from app.config import Settings
from app.services import email_sender
from app.services.email_sender import DisabledEmailSender, EmailDeliveryError, SMTPEmailSender


def _settings(**overrides):
    values = {
        "auth_base_url": "http://localhost:8100",
        "email_login_enabled": True,
        "email_code_pepper": "x" * 32,
        "smtp_host": "smtp.example.com",
        "smtp_from_email": "login@example.com",
        "smtp_smoke_recipient": "smtp-smoke@example.com",
        "smtp_username": "mailer",
        "smtp_password": "secret",
    }
    values.update(overrides)
    return Settings(**values)


def test_get_email_sender_fails_closed_until_smtp_is_verified(monkeypatch):
    config = _settings()
    monkeypatch.setattr(email_sender, "get_settings", lambda: config)
    monkeypatch.setattr(email_sender, "_smtp_verified", False)

    assert isinstance(email_sender.get_email_sender(), DisabledEmailSender)

    monkeypatch.setattr(email_sender, "_smtp_verified", True)
    assert isinstance(email_sender.get_email_sender(), SMTPEmailSender)


async def test_smtp_preflight_submits_marked_message_to_dedicated_recipient(monkeypatch):
    context = object()
    calls = []

    class FakeSMTP:
        def __init__(self, host, port, **kwargs):
            calls.append(("connect", host, port, kwargs))

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def starttls(self, **kwargs):
            calls.append(("starttls", kwargs))

        def login(self, username, password):
            calls.append(("login", username, password))

        def send_message(self, message):
            calls.append(("send", message))

    monkeypatch.setattr(email_sender.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(email_sender.smtplib, "SMTP", FakeSMTP)

    await SMTPEmailSender(_settings()).preflight()

    assert [call[0] for call in calls] == ["connect", "starttls", "login", "send"]
    assert calls[0] == ("connect", "smtp.example.com", 587, {"timeout": 10.0})
    assert calls[1] == ("starttls", {"context": context})
    assert calls[2] == ("login", "mailer", "secret")
    message = calls[3][1]
    assert message["To"] == "smtp-smoke@example.com"
    assert "部署预检" in message["Subject"]
    assert "123456" not in message.get_content()


async def test_smtp_preflight_wraps_message_submission_failure(monkeypatch):
    class FakeSMTP:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def starttls(self, **_kwargs):
            return None

        def login(self, *_args):
            return None

        def noop(self):
            return 250, b"ok"

        def send_message(self, _message):
            raise OSError("recipient rejected")

    monkeypatch.setattr(email_sender.smtplib, "SMTP", FakeSMTP)

    with pytest.raises(EmailDeliveryError, match="SMTP preflight failed"):
        await SMTPEmailSender(_settings()).preflight()


async def _wait_for_probe_count(probe: AsyncMock, expected: int) -> None:
    for _ in range(100):
        if probe.await_count >= expected:
            return
        await asyncio.sleep(0)
    raise AssertionError(f"SMTP probe did not reach {expected} calls")


async def test_smtp_monitor_retries_startup_failure_and_recovers(monkeypatch):
    probe = AsyncMock(side_effect=[EmailDeliveryError("temporary outage"), None])
    monkeypatch.setattr(email_sender.SMTPEmailSender, "preflight", probe)
    email_sender.invalidate_smtp_verification()

    task = asyncio.create_task(
        email_sender.monitor_smtp_verification(_settings(), retry_seconds=0, max_retry_seconds=0)
    )
    try:
        await _wait_for_probe_count(probe, 2)
        assert email_sender.is_smtp_verified() is True
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


async def test_smtp_monitor_half_open_probe_recovers_after_runtime_failure(monkeypatch):
    probe = AsyncMock()
    monkeypatch.setattr(email_sender.SMTPEmailSender, "preflight", probe)
    email_sender.invalidate_smtp_verification()

    task = asyncio.create_task(
        email_sender.monitor_smtp_verification(_settings(), retry_seconds=0, max_retry_seconds=0)
    )
    try:
        await _wait_for_probe_count(probe, 1)
        assert email_sender.is_smtp_verified() is True

        email_sender.invalidate_smtp_verification()
        await _wait_for_probe_count(probe, 2)
        assert email_sender.is_smtp_verified() is True
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


async def test_smtp_monitor_does_not_publish_stale_success_over_newer_failure(monkeypatch):
    first_started = asyncio.Event()
    release_first = asyncio.Event()
    second_started = asyncio.Event()
    never_release_second = asyncio.Event()
    calls = 0

    async def preflight(_sender):
        nonlocal calls
        calls += 1
        if calls == 1:
            first_started.set()
            await release_first.wait()
            return
        second_started.set()
        await never_release_second.wait()

    monkeypatch.setattr(email_sender.SMTPEmailSender, "preflight", preflight)
    email_sender.invalidate_smtp_verification()
    task = asyncio.create_task(
        email_sender.monitor_smtp_verification(_settings(), retry_seconds=0, max_retry_seconds=0)
    )
    try:
        await first_started.wait()
        email_sender.invalidate_smtp_verification()
        release_first.set()
        await second_started.wait()

        assert email_sender.is_smtp_verified() is False
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


async def test_real_login_delivery_failure_revokes_smtp_verification(monkeypatch):
    class FakeSMTP:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def starttls(self, **_kwargs):
            return None

        def login(self, *_args):
            return None

        def send_message(self, _message):
            raise OSError("delivery failed")

    monkeypatch.setattr(email_sender.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(email_sender, "_smtp_verified", True)

    with pytest.raises(EmailDeliveryError, match="SMTP delivery failed"):
        await SMTPEmailSender(_settings()).send_login_code("user@example.com", "123456", 300)

    assert email_sender.is_smtp_verified() is False


async def test_recipient_refused_does_not_revoke_global_smtp_verification(monkeypatch):
    class FakeSMTP:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def starttls(self, **_kwargs):
            return None

        def login(self, *_args):
            return None

        def send_message(self, _message):
            raise email_sender.smtplib.SMTPRecipientsRefused(
                {"user@example.com": (550, b"mailbox unavailable")}
            )

    monkeypatch.setattr(email_sender.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(email_sender, "_smtp_verified", True)

    with pytest.raises(EmailDeliveryError, match="SMTP delivery failed"):
        await SMTPEmailSender(_settings()).send_login_code("user@example.com", "123456", 300)

    assert email_sender.is_smtp_verified() is True
