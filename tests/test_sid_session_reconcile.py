"""浏览器 SSO 会话 sid 与无跳转账户对账协议回归测试。"""

import json
import time
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request, Response

from app.routers import auth, oauth
from app.schemas import OAuthTokenExchangeRequest, SessionReconcileRequest, TokenResponse
from app.security import revocation
from app.services import auth_service
from app.utils import redis as redis_util

CLIENT_ID = "appA"
REDIRECT_URI = "https://app.example/callback"
ORIGIN = "https://app.example"
STATE = "state_abcdefghijklmnopqrstuvwxyz012345"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"


def _request(*, sid: str | None = None, origin: str | None = ORIGIN, bearer: str | None = "access") -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if sid:
        headers.append((b"cookie", f"sso_session={sid}".encode()))
    if origin:
        headers.append((b"origin", origin.encode()))
    if bearer:
        headers.append((b"authorization", f"Bearer {bearer}".encode()))
    return Request({"type": "http", "method": "POST", "headers": headers, "client": ("127.0.0.1", 0)})


def _payload() -> SessionReconcileRequest:
    return SessionReconcileRequest(
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        state=STATE,
        code_challenge=CHALLENGE,
        code_challenge_method="S256",
    )


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return list(self.value)


class _DB:
    def __init__(self, users: dict[str, object] | None = None):
        self.users = users or {}
        self.committed = False

    async def execute(self, statement):
        entity = statement.column_descriptions[0]["entity"]
        if entity is auth.User:
            values = list(self.users.values())
            return _Result(values.pop(0) if values else None)
        if entity is auth_service.RefreshToken:
            return _Result([])
        raise AssertionError(f"unexpected entity: {entity}")

    async def commit(self):
        self.committed = True


def _user(user_id: str, generation: int = 0):
    return SimpleNamespace(
        id=uuid.UUID(user_id),
        email=f"{user_id[:8]}@example.com",
        is_active=True,
        is_superuser=False,
        auth_generation=generation,
    )


async def _allow_app(monkeypatch, *, allow_origin: bool = True):
    async def allowed(_client_id, _redirect_uri, _db):
        return object()

    monkeypatch.setattr(auth, "_resolve_authorize_app", allowed)
    monkeypatch.setattr(auth, "_headless_origin_matches", lambda *_args, **_kwargs: allow_origin)


def _decode_as(monkeypatch, *, sub: str, sid: str | None):
    payload = {
        "sub": sub,
        "aud": CLIENT_ID,
        "type": "access",
        "auth_generation": 0,
        "iat": int(time.time()),
    }
    if sid is not None:
        payload["sid"] = sid
    monkeypatch.setattr(auth, "decode_token", lambda *_args, **_kwargs: payload)


async def test_reconcile_rejects_missing_origin_before_reading_cookie(monkeypatch):
    await _allow_app(monkeypatch, allow_origin=False)
    _decode_as(monkeypatch, sub=str(uuid.uuid4()), sid="old-session-sid-123456")

    response = await auth.reconcile_session(_request(origin=None), _payload(), db=None)

    assert response.status_code == 403
    assert json.loads(bytes(response.body))["error"] == "origin_not_allowed"


async def test_reconcile_returns_no_session_without_exposing_identity(monkeypatch):
    await _allow_app(monkeypatch)
    _decode_as(monkeypatch, sub=str(uuid.uuid4()), sid="old-session-sid-123456")

    response = await auth.reconcile_session(_request(sid=None), _payload(), db=None)

    assert response.status_code == 200
    assert json.loads(bytes(response.body)) == {"status": "no_session"}


async def test_reconcile_rejects_non_url_safe_signed_sid(monkeypatch):
    await _allow_app(monkeypatch)
    _decode_as(monkeypatch, sub=str(uuid.uuid4()), sid="invalid session sid")

    response = await auth.reconcile_session(_request(sid=None), _payload(), db=None)

    assert response.status_code == 401
    assert json.loads(bytes(response.body))["error"] == "invalid_token"


async def test_reconcile_returns_match_only_for_same_user_and_sid(monkeypatch):
    await _allow_app(monkeypatch)
    user_id = str(uuid.uuid4())
    _decode_as(monkeypatch, sub=user_id, sid="same-session-sid-1234")
    await redis_util.create_session(
        "same-session-sid-1234",
        {
            "session_id": "same-session-sid-1234",
            "user_id": user_id,
            "auth_generation": 0,
            "auth_time": int(time.time()),
            "version": "version-a",
        },
        ttl=100,
    )

    response = await auth.reconcile_session(
        _request(sid="same-session-sid-1234"),
        _payload(),
        db=_DB({user_id: _user(user_id)}),
    )

    assert json.loads(bytes(response.body)) == {"status": "match"}


async def test_reconcile_mismatch_revokes_source_sid_and_mints_bound_code(monkeypatch):
    await _allow_app(monkeypatch)
    source_id = str(uuid.uuid4())
    target_id = str(uuid.uuid4())
    _decode_as(monkeypatch, sub=source_id, sid="source-session-sid-1234")
    await redis_util.create_session(
        "target-cookie-secret-1234",
        {
            "session_id": "target-session-sid-1234",
            "user_id": target_id,
            "auth_generation": 0,
            "auth_time": int(time.time()),
            "version": "version-b",
        },
        ttl=100,
    )

    response = await auth.reconcile_session(
        _request(sid="target-cookie-secret-1234"),
        _payload(),
        db=_DB({target_id: _user(target_id)}),
    )

    body = json.loads(bytes(response.body))
    assert body["status"] == "switch_required"
    assert body["state"] == STATE
    assert "user_id" not in body
    code_data = await redis_util.consume_auth_code(body["code"])
    assert code_data["flow"] == "reconcile"
    assert code_data["user_id"] == target_id
    assert code_data["sid"] == "target-session-sid-1234"
    assert code_data["source_sid"] == "source-session-sid-1234"
    assert code_data["session_version"] == "version-b"
    assert code_data["origin"] == ORIGIN
    assert code_data["state"] == STATE
    assert await revocation.is_sid_revoked("source-session-sid-1234") is False


async def test_reconcile_legacy_token_requires_switch_even_for_same_user(monkeypatch):
    await _allow_app(monkeypatch)
    user_id = str(uuid.uuid4())
    _decode_as(monkeypatch, sub=user_id, sid=None)
    await redis_util.create_session(
        "target-cookie",
        {
            "session_id": "target-session-id-1234",
            "user_id": user_id,
            "auth_generation": 0,
            "auth_time": int(time.time()),
            "version": "version-c",
        },
        ttl=100,
    )

    response = await auth.reconcile_session(
        _request(sid="target-cookie"),
        _payload(),
        db=_DB({user_id: _user(user_id)}),
    )

    assert json.loads(bytes(response.body))["status"] == "switch_required"


async def test_resume_rejects_missing_origin_before_reading_cookie(monkeypatch):
    await _allow_app(monkeypatch, allow_origin=False)

    async def must_not_resolve_session(_request):
        raise AssertionError("Origin 校验失败时不得读取中央会话")

    monkeypatch.setattr(auth.session_service, "resolve_session", must_not_resolve_session)

    response = await auth.resume_session(_request(origin=None, bearer=None), _payload(), db=None)

    assert response.status_code == 403
    assert json.loads(bytes(response.body))["error"] == "origin_not_allowed"


async def test_resume_rejects_unregistered_redirect_before_reading_cookie(monkeypatch):
    monkeypatch.setattr(auth, "_headless_origin_matches", lambda *_args, **_kwargs: True)

    async def unknown_app(_client_id, _redirect_uri, _db):
        return None

    async def must_not_resolve_session(_request):
        raise AssertionError("应用校验失败时不得读取中央会话")

    monkeypatch.setattr(auth, "_resolve_authorize_app", unknown_app)
    monkeypatch.setattr(auth.session_service, "resolve_session", must_not_resolve_session)

    response = await auth.resume_session(_request(bearer=None), _payload(), db=None)

    assert response.status_code == 400
    assert json.loads(bytes(response.body))["error"] == "invalid_client"


async def test_resume_returns_no_session_without_exposing_identity(monkeypatch):
    await _allow_app(monkeypatch)

    response = await auth.resume_session(_request(sid=None, bearer=None), _payload(), db=None)

    assert response.status_code == 200
    assert json.loads(bytes(response.body)) == {"status": "no_session"}


async def test_resume_mints_dedicated_code_bound_to_current_session(monkeypatch):
    await _allow_app(monkeypatch)
    user_id = str(uuid.uuid4())
    await redis_util.create_session(
        "resume-cookie-secret-1234",
        {
            "session_id": "resume-session-sid-1234",
            "user_id": user_id,
            "auth_generation": 2,
            "auth_time": int(time.time()),
            "version": "resume-version-a",
        },
        ttl=100,
    )

    response = await auth.resume_session(
        _request(sid="resume-cookie-secret-1234", bearer=None),
        _payload(),
        db=_DB({user_id: _user(user_id, generation=2)}),
    )

    body = json.loads(bytes(response.body))
    assert body == {"status": "resume_required", "code": body["code"], "state": STATE}
    assert "user_id" not in body
    code_data = await redis_util.consume_auth_code(body["code"])
    assert code_data == {
        "flow": "resume",
        "user_id": user_id,
        "app_client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "provider": "sso_resume",
        "auth_generation": 2,
        "code_challenge": CHALLENGE,
        "sid": "resume-session-sid-1234",
        "session_version": "resume-version-a",
        "origin": ORIGIN,
        "state": STATE,
    }
    assert await redis_util.consume_auth_code(body["code"]) is None


@pytest.mark.parametrize(
    ("payload_redirect", "payload_state", "request_origin", "session_overrides", "detail"),
    [
        ("https://other.example/callback", STATE, ORIGIN, {}, "binding mismatch"),
        (REDIRECT_URI, "other_state_abcdefghijklmnopqrstuvwxyz", ORIGIN, {}, "binding mismatch"),
        (REDIRECT_URI, STATE, "https://other.example", {}, "origin mismatch"),
        (REDIRECT_URI, STATE, ORIGIN, {"session_id": "other-session-sid-1234"}, "session changed"),
        (REDIRECT_URI, STATE, ORIGIN, {"version": "other-version"}, "session changed"),
        (REDIRECT_URI, STATE, ORIGIN, {"user_id": "00000000-0000-0000-0000-000000000001"}, "session changed"),
        (REDIRECT_URI, STATE, ORIGIN, {"auth_generation": 3}, "session changed"),
    ],
)
async def test_resume_code_exchange_rejects_changed_binding(
    monkeypatch,
    payload_redirect,
    payload_state,
    request_origin,
    session_overrides,
    detail,
):
    user_id = str(uuid.uuid4())
    session = {
        "session_id": "resume-public-session-id",
        "user_id": user_id,
        "auth_generation": 2,
        "auth_time": int(time.time()),
        "version": "resume-stable-version",
    }
    session.update(session_overrides)
    await redis_util.create_session("resume-cookie-secret", session, ttl=100)
    await redis_util.store_auth_code(
        "resume-bound-code",
        {
            "flow": "resume",
            "user_id": user_id,
            "app_client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "provider": "sso_resume",
            "auth_generation": 2,
            "code_challenge": CHALLENGE,
            "sid": "resume-public-session-id",
            "session_version": "resume-stable-version",
            "origin": ORIGIN,
            "state": STATE,
        },
        ttl=100,
    )

    async def fake_registered(_client_id, _redirect_uri, _db):
        return None

    monkeypatch.setattr(oauth, "_validate_redirect_uri", fake_registered)

    with pytest.raises(HTTPException) as error:
        await oauth.exchange_code_for_tokens(
            OAuthTokenExchangeRequest(
                code="resume-bound-code",
                client_id=CLIENT_ID,
                redirect_uri=payload_redirect,
                state=payload_state,
                code_verifier=VERIFIER,
            ),
            _request(sid="resume-cookie-secret", origin=request_origin, bearer=None),
            response=Response(),
            db=None,
        )

    assert error.value.status_code == 400
    assert detail in error.value.detail


async def test_resume_code_exchange_issues_tokens_for_bound_session(monkeypatch):
    user_id = str(uuid.uuid4())
    user = _user(user_id, generation=2)
    await redis_util.create_session(
        "resume-cookie-secret",
        {
            "session_id": "resume-public-session-id",
            "user_id": user_id,
            "auth_generation": 2,
            "auth_time": int(time.time()),
            "version": "resume-stable-version",
        },
        ttl=100,
    )
    await redis_util.store_auth_code(
        "resume-ok",
        {
            "flow": "resume",
            "user_id": user_id,
            "app_client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "provider": "sso_resume",
            "auth_generation": 2,
            "code_challenge": CHALLENGE,
            "sid": "resume-public-session-id",
            "session_version": "resume-stable-version",
            "origin": ORIGIN,
            "state": STATE,
        },
        ttl=100,
    )
    captured = {}

    async def fake_registered(_client_id, _redirect_uri, _db):
        return None

    async def fake_issue(_user, _client_id, _db, *, sid=None):
        captured["sid"] = sid
        return TokenResponse(access_token="a", refresh_token="r", expires_in=900)

    async def fake_log(*_args, **_kwargs):
        return None

    monkeypatch.setattr(oauth, "_validate_redirect_uri", fake_registered)
    monkeypatch.setattr(oauth.auth_service, "_issue_tokens", fake_issue)
    monkeypatch.setattr(oauth.auth_service, "_log_login", fake_log)

    tokens = await oauth.exchange_code_for_tokens(
        OAuthTokenExchangeRequest(
            code="resume-ok",
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            state=STATE,
            code_verifier=VERIFIER,
        ),
        _request(sid="resume-cookie-secret", bearer=None),
        response=Response(),
        db=_DB({user_id: user}),
    )

    assert tokens.access_token == "a"
    assert captured["sid"] == "resume-public-session-id"


async def test_reconcile_code_exchange_rejects_cookie_session_change(monkeypatch):
    user_id = str(uuid.uuid4())
    await redis_util.create_session(
        "new-cookie-sid",
        {
            "session_id": "new-public-session-id",
            "user_id": user_id,
            "auth_generation": 0,
            "auth_time": int(time.time()),
            "version": "new-version",
        },
        ttl=100,
    )
    await redis_util.store_auth_code(
        "reconcile-code",
        {
            "flow": "reconcile",
            "user_id": user_id,
            "app_client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "provider": "sso_reconcile",
            "auth_generation": 0,
            "code_challenge": CHALLENGE,
            "sid": "expected-cookie-sid",
            "session_version": "expected-version",
            "origin": ORIGIN,
            "state": STATE,
        },
        ttl=100,
    )

    async def fake_registered(_client_id, _redirect_uri, _db):
        return None

    monkeypatch.setattr(oauth, "_validate_redirect_uri", fake_registered)

    with pytest.raises(HTTPException) as error:
        await oauth.exchange_code_for_tokens(
            OAuthTokenExchangeRequest(
                code="reconcile-code",
                client_id=CLIENT_ID,
                redirect_uri=REDIRECT_URI,
                state=STATE,
                code_verifier=VERIFIER,
            ),
            _request(sid="new-cookie-sid"),
            response=Response(),
            db=None,
        )

    assert error.value.status_code == 400
    assert "session changed" in error.value.detail


async def test_reconcile_code_exchange_issues_tokens_for_bound_sid(monkeypatch):
    user_id = str(uuid.uuid4())
    user = _user(user_id)
    await redis_util.create_session(
        "target-cookie-secret",
        {
            "session_id": "target-public-session-id",
            "user_id": user_id,
            "auth_generation": 0,
            "auth_time": int(time.time()),
            "version": "stable-version",
        },
        ttl=100,
    )
    await redis_util.store_auth_code(
        "reconcile-ok",
        {
            "flow": "reconcile",
            "user_id": user_id,
            "app_client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "provider": "sso_reconcile",
            "auth_generation": 0,
            "code_challenge": CHALLENGE,
            "sid": "target-public-session-id",
            "source_sid": "source-public-session-id",
            "session_version": "stable-version",
            "origin": ORIGIN,
            "state": STATE,
        },
        ttl=100,
    )
    captured = {}

    async def fake_registered(_client_id, _redirect_uri, _db):
        return None

    async def fake_issue(_user, _client_id, _db, *, sid=None):
        captured["sid"] = sid
        return TokenResponse(access_token="a", refresh_token="r", expires_in=900)

    async def fake_log(*_args, **_kwargs):
        return None

    async def fake_revoke_source(sid, _db):
        captured["revoked_source_sid"] = sid

    monkeypatch.setattr(oauth, "_validate_redirect_uri", fake_registered)
    monkeypatch.setattr(oauth.auth_service, "_issue_tokens", fake_issue)
    monkeypatch.setattr(oauth.auth_service, "_log_login", fake_log)
    monkeypatch.setattr(oauth.auth_service, "revoke_session_refresh_tokens", fake_revoke_source)

    tokens = await oauth.exchange_code_for_tokens(
        OAuthTokenExchangeRequest(
            code="reconcile-ok",
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            state=STATE,
            code_verifier=VERIFIER,
        ),
        _request(sid="target-cookie-secret"),
        response=Response(),
        db=_DB({user_id: user}),
    )

    assert tokens.access_token == "a"
    assert captured["sid"] == "target-public-session-id"
    assert captured["revoked_source_sid"] == "source-public-session-id"
    assert await revocation.is_sid_revoked("source-public-session-id") is True


async def test_normal_auth_code_for_superseded_sid_cannot_issue_tokens(monkeypatch):
    user_id = str(uuid.uuid4())
    await redis_util.store_auth_code(
        "stale-session-code",
        {
            "user_id": user_id,
            "app_client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "provider": "google",
            "auth_generation": 0,
            "sid": "superseded-session-sid-1234",
        },
        ttl=100,
    )
    await revocation.revoke_sid("superseded-session-sid-1234", ttl=100)

    with pytest.raises(HTTPException) as error:
        await oauth.exchange_code_for_tokens(
            OAuthTokenExchangeRequest(code="stale-session-code", client_id=CLIENT_ID),
            _request(sid=None),
            response=Response(),
            db=None,
        )

    assert error.value.status_code == 400


async def test_refresh_rejects_revoked_sid_before_issuing_successor(monkeypatch):
    user_id = uuid.uuid4()
    monkeypatch.setattr(
        auth_service,
        "decode_token",
        lambda *_args, **_kwargs: {
            "sub": str(user_id),
            "type": "refresh",
            "auth_generation": 0,
            "sid": "revoked-session",
        },
    )
    await revocation.revoke_sid("revoked-session", ttl=100)

    with pytest.raises(HTTPException) as error:
        await auth_service.refresh_access_token("refresh", db=None)

    assert error.value.status_code == 401


def test_sid_migration_adds_nullable_binding_for_legacy_rows():
    migration = (
        __import__("pathlib").Path(__file__).parents[1]
        / "alembic"
        / "versions"
        / "d9e0f1a2b3c4_add_refresh_token_sid.py"
    ).read_text()

    assert 'sa.Column("sid", sa.String(length=128), nullable=True)' in migration
    assert 'op.create_index("ix_refresh_tokens_sid", "refresh_tokens", ["sid"])' in migration
