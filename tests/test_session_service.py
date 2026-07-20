"""IdP session service: cookie writing, sid reading, resolve + start_session.

Covers the security-critical behaviors: fresh sid on every login (anti
session-fixation), absolute-lifetime cap, and the dev/prod cookie attribute
matrix (HttpOnly always, Secure + __Host- in prod).
"""

import time

from fastapi import Request, Response

from app.config import Settings
from app.services import session_service
from app.utils import redis as redis_util


def _make_request(cookies: dict) -> Request:
    headers = []
    if cookies:
        cookie = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers.append((b"cookie", cookie.encode()))
    return Request({"type": "http", "headers": headers})


# ---- cookie writing ----


def test_set_session_cookie_dev_attributes():
    resp = Response()
    session_service.set_session_cookie(resp, "abc123")
    header = resp.headers["set-cookie"]
    assert "sso_session=abc123" in header
    assert "HttpOnly" in header
    assert "Path=/" in header
    assert "samesite=lax" in header.lower()
    assert "Max-Age=604800" in header
    assert "Secure" not in header  # dev runs over http://localhost


def test_set_session_cookie_prod_is_secure_and_host_prefixed(monkeypatch):
    monkeypatch.setattr(session_service, "settings", Settings(app_env="production"))
    resp = Response()
    session_service.set_session_cookie(resp, "abc123")
    header = resp.headers["set-cookie"]
    assert "__Host-sso_session=abc123" in header
    assert "Secure" in header
    assert "Domain" not in header  # __Host- forbids a Domain attribute


def test_https_dev_upgrades_existing_cookie_in_place_without_renaming(monkeypatch):
    monkeypatch.setattr(
        session_service,
        "settings",
        Settings(app_env="development", auth_base_url="https://auth.example.com"),
    )
    response = Response()

    session_service.set_session_cookie(response, "upgraded")

    header = response.headers["set-cookie"]
    assert "sso_session=upgraded" in header
    assert "__Host-sso_session" not in header
    assert "Secure" in header
    assert session_service.read_sid(_make_request({"sso_session": "existing"})) == "existing"


def test_clear_session_cookie_expires_it():
    resp = Response()
    session_service.clear_session_cookie(resp)
    header = resp.headers["set-cookie"]
    assert "sso_session=" in header
    assert "Max-Age=0" in header


# ---- reading sid ----


def test_read_sid_present():
    assert session_service.read_sid(_make_request({"sso_session": "xyz"})) == "xyz"


def test_read_sid_absent():
    assert session_service.read_sid(_make_request({})) is None


# ---- resolve_session ----


async def test_resolve_session_no_cookie_returns_none():
    assert await session_service.resolve_session(_make_request({})) == (None, None)


async def test_resolve_session_unknown_sid_returns_none():
    assert await session_service.resolve_session(_make_request({"sso_session": "ghost"})) == (None, None)


async def test_resolve_session_valid_returns_sid_and_payload():
    now = int(time.time())
    await redis_util.create_session(
        "good",
        {"session_id": "public-session-good", "user_id": "u1", "auth_time": now, "amr": ["google"]},
        ttl=100,
    )
    sid, payload = await session_service.resolve_session(_make_request({"sso_session": "good"}))
    assert sid == "good"
    assert payload["user_id"] == "u1"


async def test_resolve_session_over_absolute_max_is_purged():
    old = int(time.time()) - (Settings().session_absolute_max_seconds + 10)
    await redis_util.create_session("stale", {"user_id": "u1", "auth_time": old}, ttl=100)
    assert await session_service.resolve_session(_make_request({"sso_session": "stale"})) == (None, None)
    assert await redis_util.get_session("stale") is None  # actively deleted


# ---- start_session ----


async def test_start_session_sets_cookie_and_persists_fresh_session():
    resp = Response()
    sid = await session_service.start_session(resp, "user-1", ["google"])
    assert sid
    assert f"sso_session={sid}" in resp.headers["set-cookie"]
    payload = await redis_util.get_session(sid)
    assert payload["user_id"] == "user-1"
    assert payload["amr"] == ["google"]
    assert "auth_time" in payload
    assert payload["version"]
    assert payload["session_id"]
    assert payload["session_id"] != sid


async def test_start_session_mints_new_sid_each_time():
    # Anti session-fixation: a fresh sid every login, never reusing inbound cookies.
    sid1 = await session_service.start_session(Response(), "user-1", ["google"])
    sid2 = await session_service.start_session(Response(), "user-1", ["google"])
    assert sid1 != sid2


async def test_start_session_supersedes_previous_sid():
    old_sid = await session_service.start_session(Response(), "user-1", ["google"])
    old_session_id = (await redis_util.get_session(old_sid))["session_id"]
    new_sid = await session_service.start_session(
        Response(),
        "user-2",
        ["email_otp"],
        previous_sid=old_sid,
    )

    assert new_sid != old_sid
    assert await redis_util.get_session(old_sid) is None
    # token 会话族必须等继任 token 已签发后再撤销，session 层只替换中央 cookie。
    assert await session_service.is_sid_revoked(old_session_id) is False
