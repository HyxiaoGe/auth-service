"""认证代际（auth_generation）的注销竞态回归测试。

这些测试用可控的假数据库模拟 PostgreSQL ``SELECT ... FOR UPDATE``：refresh 与
logout 都必须先拿用户行锁，才能继续触碰 refresh token。这样无论哪个请求先拿锁，
logout 返回后都不会留下可继续兑换或刷新的旧代际凭证。
"""

import asyncio
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request, Response

from app.models import RefreshToken, User
from app.routers import oauth
from app.schemas import OAuthTokenExchangeRequest, TokenResponse
from app.services import auth_service
from app.utils.redis import store_auth_code


def test_generation_migration_invalidates_all_legacy_credentials_once():
    source = (
        Path(__file__).parents[1]
        / "alembic"
        / "versions"
        / "c8d9e0f1a2b3_add_auth_generation.py"
    ).read_text()

    assert 'op.execute("UPDATE users SET auth_generation = 1")' in source
    assert 'sa.Column("auth_generation", sa.Integer(), nullable=False, server_default=sa.text("0"))' in source


def _request() -> Request:
    return Request({"type": "http", "headers": [], "client": ("127.0.0.1", 12345)})


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return list(self.value)


class _TokenExchangeDB:
    def __init__(self, user):
        self.user = user
        self.statements = []

    async def execute(self, statement):
        self.statements.append(statement)
        return _Result(self.user)


@pytest.mark.parametrize("provider", ["email_otp", "google", "github", "sso"])
async def test_logout_invalidates_unredeemed_auth_code_for_every_login_flow(provider, monkeypatch):
    """登出后，四种入口在登出前签发的 auth code 都必须统一失效。"""
    user = SimpleNamespace(
        id=uuid.uuid4(),
        email="user@example.com",
        is_active=True,
        is_superuser=False,
        auth_generation=1,
    )
    await store_auth_code(
        f"stale-{provider}",
        {
            "user_id": str(user.id),
            "app_client_id": "appA",
            "redirect_uri": "https://app.example/callback",
            "provider": provider,
            "auth_generation": 0,
        },
        ttl=100,
    )
    issued = False

    async def fake_issue(*_args, **_kwargs):
        nonlocal issued
        issued = True
        return TokenResponse(access_token="a", refresh_token="r", expires_in=900)

    monkeypatch.setattr(oauth.auth_service, "_issue_tokens", fake_issue)
    db = _TokenExchangeDB(user)

    with pytest.raises(HTTPException) as exc:
        await oauth.exchange_code_for_tokens(
            payload=OAuthTokenExchangeRequest(code=f"stale-{provider}", client_id="appA"),
            request=_request(),
            response=Response(),
            db=db,
        )

    assert exc.value.status_code == 400
    assert issued is False
    assert db.statements[0].column_descriptions[0]["entity"] is User
    assert db.statements[0]._for_update_arg is not None


async def test_legacy_auth_code_without_generation_fails_closed():
    await store_auth_code(
        "legacy-no-generation",
        {
            "user_id": str(uuid.uuid4()),
            "app_client_id": "appA",
            "redirect_uri": "https://app.example/callback",
            "provider": "google",
        },
        ttl=100,
    )

    with pytest.raises(HTTPException) as exc:
        await oauth.exchange_code_for_tokens(
            payload=OAuthTokenExchangeRequest(code="legacy-no-generation", client_id="appA"),
            request=_request(),
            response=Response(),
            db=_TokenExchangeDB(None),
        )

    assert exc.value.status_code == 400


class _SharedRows:
    def __init__(self):
        uid = uuid.uuid4()
        self.user = SimpleNamespace(
            id=uid,
            email="user@example.com",
            is_active=True,
            is_superuser=False,
            auth_generation=0,
        )
        self.old_token = SimpleNamespace(
            user_id=uid,
            token_hash="old-hash",
            app_client_id="appA",
            auth_generation=0,
            is_revoked=False,
            revoked_at=None,
            rotated_at=None,
            grace_consumed=False,
            sid="browser-session-sid-generation",
        )
        self.tokens = [self.old_token]
        self.user_lock = asyncio.Lock()
        self.events = {"refresh": asyncio.Event(), "logout": asyncio.Event()}
        self.release = {"refresh": asyncio.Event(), "logout": asyncio.Event()}


class _ConcurrentDB:
    """用共享 asyncio.Lock 模拟两个事务争抢同一 PostgreSQL 用户行锁。"""

    def __init__(self, rows: _SharedRows, role: str, *, pause_after_user_lock: bool = False):
        self.rows = rows
        self.role = role
        self.pause_after_user_lock = pause_after_user_lock
        self.has_user_lock = False
        self.order = []

    async def execute(self, statement):
        entity = statement.column_descriptions[0]["entity"]
        if entity is User:
            assert statement._for_update_arg is not None
            await self.rows.user_lock.acquire()
            self.has_user_lock = True
            self.order.append("user")
            self.rows.events[self.role].set()
            if self.pause_after_user_lock:
                await self.rows.release[self.role].wait()
            return _Result(self.rows.user)

        assert entity is RefreshToken
        assert self.has_user_lock, "必须先锁用户行，再触碰 refresh_tokens"
        assert statement._for_update_arg is not None
        self.order.append("refresh")
        where = str(statement.whereclause)
        if "token_hash" in where:
            return _Result(self.rows.old_token)
        active = [token for token in self.rows.tokens if not token.is_revoked]
        return _Result(active)

    def add(self, token):
        self.rows.tokens.append(token)

    async def commit(self):
        if self.has_user_lock:
            self.has_user_lock = False
            self.rows.user_lock.release()


async def _fake_issue_tokens(user, app_client_id, db, *, sid=None):
    successor = SimpleNamespace(
        user_id=user.id,
        token_hash="successor-hash",
        app_client_id=app_client_id,
        auth_generation=user.auth_generation,
        is_revoked=False,
        revoked_at=None,
        rotated_at=None,
        grace_consumed=False,
        sid=sid,
    )
    db.add(successor)
    await db.commit()
    return TokenResponse(access_token="access", refresh_token="refresh", expires_in=900)


async def test_refresh_wins_user_lock_then_logout_revokes_its_successor(monkeypatch):
    """refresh 先提交时，logout 随后必须看见并撤销刚签发的 successor。"""
    rows = _SharedRows()
    refresh_db = _ConcurrentDB(rows, "refresh", pause_after_user_lock=True)
    logout_db = _ConcurrentDB(rows, "logout")
    monkeypatch.setattr(
        auth_service,
        "decode_token",
        lambda *_args, **_kwargs: {
            "sub": str(rows.user.id),
            "auth_generation": 0,
            "type": "refresh",
            "sid": "browser-session-sid-generation",
        },
    )
    monkeypatch.setattr(auth_service, "hash_token", lambda _token: "old-hash")
    monkeypatch.setattr(auth_service, "_issue_tokens", _fake_issue_tokens)

    refresh_task = asyncio.create_task(auth_service.refresh_access_token("old", refresh_db))
    await rows.events["refresh"].wait()
    logout_task = asyncio.create_task(auth_service.logout_user(rows.user.id, logout_db))
    await asyncio.sleep(0)
    assert rows.events["logout"].is_set() is False

    rows.release["refresh"].set()
    await refresh_task
    await logout_task

    successor = next(token for token in rows.tokens if token.token_hash == "successor-hash")
    assert successor.is_revoked is True
    assert rows.user.auth_generation == 1
    assert refresh_db.order == ["user", "refresh"]
    assert logout_db.order == ["user", "refresh"]


async def test_logout_wins_user_lock_then_refresh_rejects_old_generation(monkeypatch):
    """logout 先提交时，等待中的 refresh 必须因 generation 失配而拒绝签发。"""
    rows = _SharedRows()
    logout_db = _ConcurrentDB(rows, "logout", pause_after_user_lock=True)
    refresh_db = _ConcurrentDB(rows, "refresh")
    monkeypatch.setattr(
        auth_service,
        "decode_token",
        lambda *_args, **_kwargs: {
            "sub": str(rows.user.id),
            "auth_generation": 0,
            "type": "refresh",
            "sid": "browser-session-sid-generation",
        },
    )
    monkeypatch.setattr(auth_service, "hash_token", lambda _token: "old-hash")
    monkeypatch.setattr(auth_service, "_issue_tokens", _fake_issue_tokens)

    logout_task = asyncio.create_task(auth_service.logout_user(rows.user.id, logout_db))
    await rows.events["logout"].wait()
    refresh_task = asyncio.create_task(auth_service.refresh_access_token("old", refresh_db))
    await asyncio.sleep(0)
    assert rows.events["refresh"].is_set() is False

    rows.release["logout"].set()
    await logout_task
    with pytest.raises(HTTPException) as exc:
        await refresh_task

    assert exc.value.status_code == 401
    assert rows.user.auth_generation == 1
    assert all(token.token_hash != "successor-hash" for token in rows.tokens)
    assert logout_db.order == ["user", "refresh"]
    assert refresh_db.order == ["user"]


async def test_legacy_sidless_refresh_requires_login_upgrade(monkeypatch):
    """迁移前无 sid 的 refresh 必须拒绝，不能形成绕过 session 撤销的永久分支。"""
    rows = _SharedRows()
    db = _ConcurrentDB(rows, "refresh")
    monkeypatch.setattr(
        auth_service,
        "decode_token",
        lambda *_args, **_kwargs: {"sub": str(rows.user.id), "type": "refresh"},
    )
    monkeypatch.setattr(auth_service, "hash_token", lambda _token: "old-hash")
    monkeypatch.setattr(auth_service, "_issue_tokens", _fake_issue_tokens)

    with pytest.raises(HTTPException) as exc:
        await auth_service.refresh_access_token("legacy", db)

    assert exc.value.status_code == 401
    assert db.order == []
