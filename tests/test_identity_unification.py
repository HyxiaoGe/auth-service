"""邮箱 OTP 与社交登录共享身份的注册、归一化和竞态契约。"""

import asyncio
import json
import uuid
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.exc import IntegrityError

from app.config import Settings
from app.models import SocialAccount, User
from app.routers import oauth
from app.services import auth_service, email_login_service, oauth_service
from app.services.email_sender import EmailSender


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

    def scalar_one_or_none(self):
        return self.values[0] if len(self.values) == 1 else None


class _IdentityStore:
    def __init__(self):
        self.users: list[User] = []
        self.social_accounts: list[SocialAccount] = []
        self.lock = asyncio.Lock()
        self.commit_barrier: asyncio.Barrier | None = None

    def seed_user(self, email: str, *, active: bool = True) -> User:
        user = User(
            id=uuid.uuid4(),
            email=email,
            name=email.split("@", 1)[0],
            avatar_url=None,
            password_hash=None,
            is_active=active,
            is_superuser=False,
        )
        self.users.append(user)
        return user

    def seed_social(self, user: User, provider: str, provider_id: str) -> SocialAccount:
        social = SocialAccount(
            id=uuid.uuid4(),
            user_id=user.id,
            provider=provider,
            provider_id=provider_id,
            provider_email=user.email,
            provider_name=user.name,
            provider_avatar=None,
        )
        social.user = user
        self.social_accounts.append(social)
        return social


class _IdentitySession:
    """只实现身份服务所需的 AsyncSession 子集，并模拟唯一约束竞态。"""

    def __init__(self, store: _IdentityStore):
        self.store = store
        self.pending: list[object] = []

    async def execute(self, statement):
        entity = statement.column_descriptions[0].get("entity")
        params = statement.compile().params
        sql = str(statement)
        if entity is User:
            if "users.id" in sql and "WHERE users.id" in sql:
                expected = next(value for key, value in params.items() if key.startswith("id_"))
                values = [user for user in self.store.users if str(user.id) == str(expected)]
            else:
                expected = next(
                    value for key, value in params.items() if key.startswith(("lower_", "btrim_"))
                )
                values = [
                    user
                    for user in self.store.users
                    if email_login_service.normalize_email(user.email) == expected
                ]
            if "users.is_active IS true" in sql:
                values = [user for user in values if user.is_active]
            return _Result(values)

        if entity is SocialAccount:
            provider = next(value for key, value in params.items() if key.startswith("provider_"))
            if any(key.startswith("provider_id_") for key in params):
                provider_id = next(value for key, value in params.items() if key.startswith("provider_id_"))
                values = [
                    social
                    for social in self.store.social_accounts
                    if social.provider == provider and social.provider_id == provider_id
                ]
            else:
                user_id = next(value for key, value in params.items() if key.startswith("user_id_"))
                values = [
                    social
                    for social in self.store.social_accounts
                    if social.provider == provider and str(social.user_id) == str(user_id)
                ]
            return _Result(values)
        raise AssertionError(f"未支持的查询: {statement}")

    def add(self, value):
        self.pending.append(value)

    async def commit(self):
        barrier = self.store.commit_barrier
        if barrier is not None:
            await barrier.wait()
            self.store.commit_barrier = None
        async with self.store.lock:
            for value in self.pending:
                if isinstance(value, User):
                    normalized = email_login_service.normalize_email(value.email)
                    if any(
                        email_login_service.normalize_email(existing.email) == normalized
                        for existing in self.store.users
                    ):
                        raise IntegrityError("uq_users_normalized_email", {}, Exception("duplicate"))
                elif isinstance(value, SocialAccount):
                    if any(
                        existing.provider == value.provider and existing.provider_id == value.provider_id
                        for existing in self.store.social_accounts
                    ):
                        raise IntegrityError("uq_social_accounts_provider_identity", {}, Exception("duplicate"))
                    if any(
                        existing.user_id == value.user_id and existing.provider == value.provider
                        for existing in self.store.social_accounts
                    ):
                        raise IntegrityError("uq_social_accounts_user_provider", {}, Exception("duplicate"))

            for value in self.pending:
                if isinstance(value, User):
                    value.id = value.id or uuid.uuid4()
                    self.store.users.append(value)
                elif isinstance(value, SocialAccount):
                    value.id = value.id or uuid.uuid4()
                    value.user = next(user for user in self.store.users if user.id == value.user_id)
                    self.store.social_accounts.append(value)
            self.pending.clear()

    async def rollback(self):
        self.pending.clear()

    async def refresh(self, _value):
        return None


class _Sender(EmailSender):
    available = True

    def __init__(self):
        self.sent: list[tuple[str, str, int]] = []

    async def send_login_code(
        self, recipient: str, code: str, ttl_seconds: int, delivery_id: str | None = None
    ) -> None:
        self.sent.append((recipient, code, ttl_seconds))


def _settings() -> Settings:
    return Settings(
        auth_base_url="https://auth.example.com",
        email_login_enabled=True,
        email_code_pepper="test-only-pepper-with-32-characters",
        smtp_host="smtp.example.com",
        smtp_from_email="login@example.com",
        smtp_smoke_recipient="smoke@example.com",
        trusted_proxy_cidrs="172.25.0.10/32",
        email_code_resend_seconds=1,
    )


async def _flow(config: Settings):
    return await email_login_service.create_email_flow(
        client_id="appA",
        redirect_uri="https://app.example/callback",
        app_state="STATE",
        code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        config=config,
    )


async def _request_code(store: _IdentityStore, email: str):
    config = _settings()
    started = await _flow(config)
    sender = _Sender()
    result = await email_login_service.request_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        email=email,
        client_ip="203.0.113.8",
        db=_IdentitySession(store),
        sender=sender,
        config=config,
    )
    return config, started, sender, result


async def test_unknown_email_is_delivered_without_creating_user_until_correct_otp(fake_redis):
    store = _IdentityStore()
    config, started, sender, result = await _request_code(store, "  New.User@Example.COM ")

    assert result.accepted is True
    assert store.users == []
    assert sender.sent[0][0] == "new.user@example.com"
    otp_record = json.loads(await fake_redis.get(f"email_otp:{started.flow_id}"))
    assert otp_record["active"]["normalized_email"] == "new.user@example.com"
    assert sender.sent[0][1] not in json.dumps(otp_record)

    verified = await email_login_service.verify_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        code=sender.sent[0][1],
        db=_IdentitySession(store),
        config=config,
    )

    assert verified is not None
    assert verified.user.email == "new.user@example.com"
    assert verified.user.password_hash is None
    assert verified.user.is_active is True
    assert len(store.users) == 1


async def test_existing_active_email_otp_reuses_same_user_id():
    store = _IdentityStore()
    existing = store.seed_user("Stored.User@Example.com")
    config, started, sender, _result = await _request_code(store, "stored.user@EXAMPLE.COM")

    verified = await email_login_service.verify_login_code(
        flow_id=started.flow_id,
        flow_cookie=started.cookie_value,
        code=sender.sent[0][1],
        db=_IdentitySession(store),
        config=config,
    )

    assert verified is not None and verified.user.id == existing.id
    assert len(store.users) == 1


async def test_disabled_email_is_not_delivered_and_never_creates_replacement(fake_redis):
    store = _IdentityStore()
    disabled = store.seed_user("disabled@example.com", active=False)
    _config, started, sender, result = await _request_code(store, "DISABLED@example.com")

    assert result.accepted is True
    assert sender.sent == []
    otp_record = json.loads(await fake_redis.get(f"email_otp:{started.flow_id}"))
    assert "normalized_email" not in otp_record["active"]
    assert store.users == [disabled]


async def test_otp_and_google_concurrent_first_creation_resolve_to_one_user():
    store = _IdentityStore()
    config, started, sender, _result = await _request_code(store, "same@example.com")
    store.commit_barrier = asyncio.Barrier(2)

    verified, social_user = await asyncio.gather(
        email_login_service.verify_login_code(
            flow_id=started.flow_id,
            flow_cookie=started.cookie_value,
            code=sender.sent[0][1],
            db=_IdentitySession(store),
            config=config,
        ),
        auth_service.social_login(
            provider="google",
            provider_id="google-1",
            email="SAME@EXAMPLE.COM",
            email_verified=True,
            name="Same",
            avatar_url=None,
            db=_IdentitySession(store),
        ),
    )

    assert verified is not None
    assert verified.user.id == social_user.id
    assert len(store.users) == 1
    assert len(store.social_accounts) == 1


async def test_google_unbound_identity_requires_verified_email_but_bound_identity_is_authoritative():
    store = _IdentityStore()
    with pytest.raises(HTTPException) as unverified:
        await auth_service.social_login(
            provider="google",
            provider_id="new-google",
            email="user@example.com",
            email_verified=False,
            name="User",
            avatar_url=None,
            db=_IdentitySession(store),
        )
    assert unverified.value.status_code == 400

    active = store.seed_user("bound@example.com")
    store.seed_social(active, "google", "bound-google")
    bound = await auth_service.social_login(
        provider="google",
        provider_id="bound-google",
        email="",
        email_verified=False,
        name=None,
        avatar_url=None,
        db=_IdentitySession(store),
    )
    assert bound.id == active.id

    active.is_active = False
    with pytest.raises(HTTPException) as disabled:
        await auth_service.social_login(
            provider="google",
            provider_id="bound-google",
            email="",
            email_verified=False,
            name=None,
            avatar_url=None,
            db=_IdentitySession(store),
        )
    assert disabled.value.status_code == 403


async def test_github_unbound_identity_without_trusted_email_is_rejected():
    with pytest.raises(HTTPException) as unverified:
        await auth_service.social_login(
            provider="github",
            provider_id="new-github",
            email=None,
            email_verified=False,
            name="User",
            avatar_url=None,
            db=_IdentitySession(_IdentityStore()),
        )
    assert unverified.value.status_code == 400


async def test_email_case_is_unified_but_different_emails_are_not_merged():
    store = _IdentityStore()
    first = await auth_service.social_login(
        provider="google",
        provider_id="google-a",
        email="Mixed@Example.COM",
        email_verified=True,
        name="A",
        avatar_url=None,
        db=_IdentitySession(store),
    )
    same = await auth_service.social_login(
        provider="github",
        provider_id="github-a",
        email="mixed@example.com",
        email_verified=True,
        name="A",
        avatar_url=None,
        db=_IdentitySession(store),
    )
    other = await auth_service.social_login(
        provider="google",
        provider_id="google-b",
        email="other@example.com",
        email_verified=True,
        name="B",
        avatar_url=None,
        db=_IdentitySession(store),
    )

    assert first.id == same.id
    assert other.id != first.id
    assert len(store.users) == 2


async def test_concurrent_social_identity_link_is_idempotent():
    store = _IdentityStore()
    first, second = await asyncio.gather(
        *[
            auth_service.social_login(
                provider="github",
                provider_id="github-race",
                email="race@example.com",
                email_verified=True,
                name="Race",
                avatar_url=None,
                db=_IdentitySession(store),
            )
            for _ in range(2)
        ]
    )

    assert first.id == second.id
    assert len(store.users) == 1
    assert len(store.social_accounts) == 1


async def test_concurrent_same_provider_identity_with_different_emails_leaves_no_orphan_user():
    store = _IdentityStore()
    store.commit_barrier = asyncio.Barrier(2)
    first, second = await asyncio.gather(
        auth_service.social_login(
            provider="google",
            provider_id="same-google-id",
            email="winner-a@example.com",
            email_verified=True,
            name="A",
            avatar_url=None,
            db=_IdentitySession(store),
        ),
        auth_service.social_login(
            provider="google",
            provider_id="same-google-id",
            email="loser-b@example.com",
            email_verified=True,
            name="B",
            avatar_url=None,
            db=_IdentitySession(store),
        ),
    )

    assert first.id == second.id
    assert len(store.users) == 1
    assert len(store.social_accounts) == 1
    assert store.social_accounts[0].user_id == store.users[0].id


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class _OAuthClient:
    redirect_uri = "https://auth.example/callback"

    def __init__(self, responses):
        self.responses = responses
        self.requested: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def fetch_token(self, *_args, **_kwargs):
        return None

    async def get(self, url, **_kwargs):
        self.requested.append(url)
        response = self.responses[url]
        if isinstance(response, BaseException):
            raise response
        if hasattr(response, "raise_for_status"):
            return response
        return _Response(response)


async def test_google_exchange_propagates_verified_email(monkeypatch):
    url = "https://www.googleapis.com/oauth2/v2/userinfo"
    client = _OAuthClient(
        {
            url: {
                "id": "g1",
                "email": "User@Example.com",
                "verified_email": True,
                "name": "User",
            }
        }
    )
    monkeypatch.setattr(oauth_service, "create_google_client", lambda: client)

    info = await oauth_service.exchange_google_code("code")

    assert info["email_verified"] is True


@pytest.mark.parametrize("verified_email", [False, "false", 1, None])
async def test_google_exchange_only_accepts_literal_true_verified_email(monkeypatch, verified_email):
    url = "https://www.googleapis.com/oauth2/v2/userinfo"
    client = _OAuthClient(
        {
            url: {
                "id": "g1",
                "email": "user@example.com",
                "verified_email": verified_email,
                "name": "User",
            }
        }
    )
    monkeypatch.setattr(oauth_service, "create_google_client", lambda: client)

    info = await oauth_service.exchange_google_code("code")

    assert info["email_verified"] is False


async def test_github_always_uses_primary_verified_non_noreply_email(monkeypatch):
    user_url = "https://api.github.com/user"
    emails_url = "https://api.github.com/user/emails"
    client = _OAuthClient(
        {
            user_url: {
                "id": 1,
                "email": "untrusted-public@example.com",
                "login": "octocat",
                "avatar_url": None,
            },
            emails_url: [
                {"email": "secondary@example.com", "primary": False, "verified": True},
                {"email": "Primary@Example.com", "primary": True, "verified": True},
            ],
        }
    )
    monkeypatch.setattr(oauth_service, "create_github_client", lambda: client)

    info = await oauth_service.exchange_github_code("code")

    assert client.requested == [user_url, emails_url]
    assert info["email"] == "primary@example.com"
    assert info["email_verified"] is True


@pytest.mark.parametrize(
    "emails",
    [
        [{"email": "12345+user@users.noreply.github.com", "primary": True, "verified": True}],
        [{"email": "user@example.com", "primary": True, "verified": False}],
        [{"email": "user@example.com", "primary": False, "verified": True}],
        [],
    ],
)
async def test_github_marks_noreply_or_missing_trusted_email_as_unverified(monkeypatch, emails):
    client = _OAuthClient(
        {
            "https://api.github.com/user": {"id": 1, "email": "public@example.com", "login": "octocat"},
            "https://api.github.com/user/emails": emails,
        }
    )
    monkeypatch.setattr(oauth_service, "create_github_client", lambda: client)

    info = await oauth_service.exchange_github_code("code")

    assert info["email"] is None
    assert info["email_verified"] is False


def _failed_github_response(status_code: int, detail: str) -> httpx.Response:
    return httpx.Response(
        status_code,
        json={"detail": detail},
        request=httpx.Request("GET", "https://api.github.com/user/emails"),
    )


@pytest.mark.parametrize(
    "emails_response",
    [
        _failed_github_response(403, "secret-403-response"),
        _failed_github_response(503, "secret-500-response"),
        httpx.ReadTimeout("secret-timeout-detail"),
        {"unexpected": "object"},
        [None, 1, "bad", {"primary": True, "verified": True, "email": ["bad"]}],
    ],
)
async def test_github_email_endpoint_failures_degrade_after_stable_provider_id(
    monkeypatch,
    caplog,
    emails_response,
):
    client = _OAuthClient(
        {
            "https://api.github.com/user": {"id": 42, "login": "octocat"},
            "https://api.github.com/user/emails": emails_response,
        }
    )
    monkeypatch.setattr(oauth_service, "create_github_client", lambda: client)

    info = await oauth_service.exchange_github_code("code")

    assert info["provider_id"] == "42"
    assert info["email"] is None
    assert info["email_verified"] is False
    assert "secret-" not in caplog.text


async def test_github_degraded_email_still_allows_bound_identity_but_rejects_unbound(monkeypatch):
    client = _OAuthClient(
        {
            "https://api.github.com/user": {"id": 42, "login": "octocat"},
            "https://api.github.com/user/emails": httpx.ReadTimeout("provider detail"),
        }
    )
    monkeypatch.setattr(oauth_service, "create_github_client", lambda: client)
    info = await oauth_service.exchange_github_code("code")

    store = _IdentityStore()
    bound_user = store.seed_user("bound@example.com")
    store.seed_social(bound_user, "github", info["provider_id"])
    resolved = await auth_service.social_login(provider="github", db=_IdentitySession(store), **info)
    assert resolved.id == bound_user.id

    with pytest.raises(HTTPException) as exc:
        await auth_service.social_login(
            provider="github",
            db=_IdentitySession(_IdentityStore()),
            **info,
        )
    assert exc.value.status_code == 400
    assert exc.value.detail == "Provider email is not verified"


@pytest.mark.parametrize("email", ["Straße@example.com", "user name@example.com"])
async def test_unbound_oauth_rejects_noncanonical_email_with_generic_4xx(email):
    with pytest.raises(HTTPException) as exc:
        await auth_service.social_login(
            provider="github",
            provider_id="new-provider",
            email=email,
            email_verified=True,
            name=None,
            avatar_url=None,
            db=_IdentitySession(_IdentityStore()),
        )
    assert exc.value.status_code == 400
    assert exc.value.detail == "Provider email is not verified"


@pytest.mark.parametrize(
    ("callback", "exchange_name", "provider"),
    [
        (oauth.google_callback, "exchange_google_code", "google"),
        (oauth.github_callback, "exchange_github_code", "github"),
    ],
)
async def test_oauth_callback_delegates_missing_email_for_bound_provider_identity(
    monkeypatch,
    callback,
    exchange_name,
    provider,
):
    captured = {}

    async def fake_state(_state):
        return {"client_id": "appA", "redirect_uri": "https://app.example/callback"}

    async def fake_validate(_client_id, _redirect_uri, _db):
        return None

    async def fake_exchange(_code):
        return {
            "provider_id": f"{provider}-bound",
            "email": None,
            "email_verified": False,
            "name": None,
            "avatar_url": None,
        }

    async def fake_social_login(**kwargs):
        captured.update(kwargs)
        return type("BoundUser", (), {"id": uuid.uuid4()})()

    async def fake_redirect(_user, _state_data, provider, request=None, db=None):
        captured["redirect_provider"] = provider
        return RedirectResponse("https://app.example/callback?code=ok")

    monkeypatch.setattr(oauth.oauth_service, "verify_and_consume_state", fake_state)
    monkeypatch.setattr(oauth, "_validate_redirect_uri", fake_validate)
    monkeypatch.setattr(oauth.oauth_service, exchange_name, fake_exchange)
    monkeypatch.setattr(oauth.auth_service, "social_login", fake_social_login)
    monkeypatch.setattr(oauth, "_social_redirect", fake_redirect)

    response = await callback(request=None, code="code", state="state", db=None)

    assert response.status_code == 307
    assert captured["email"] is None
    assert captured["email_verified"] is False
    assert captured["provider_id"] == f"{provider}-bound"
    assert captured["redirect_provider"] == provider


def test_database_models_and_migration_define_identity_uniqueness():
    user_indexes = {index.name: index for index in User.__table__.indexes}
    assert user_indexes["uq_users_normalized_email"].unique is True
    user_constraints = {constraint.name for constraint in User.__table__.constraints}
    assert "ck_users_email_ascii" in user_constraints

    social_constraints = {constraint.name for constraint in SocialAccount.__table__.constraints}
    assert "uq_social_accounts_provider_identity" in social_constraints
    assert "uq_social_accounts_user_provider" in social_constraints

    migration = Path(__file__).parents[1] / "alembic/versions/b7c8d9e0f1a2_unify_passwordless_identity.py"
    source = migration.read_text()
    assert "lower(btrim(email))" in source
    assert "octet_length(email) = char_length(email)" in source
    assert "ck_users_email_ascii" in source
    assert "uq_social_accounts_provider_identity" in source
    assert "uq_social_accounts_user_provider" in source
