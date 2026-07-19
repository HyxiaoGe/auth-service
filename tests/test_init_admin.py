"""管理员初始化脚本的安全边界测试。"""

from types import SimpleNamespace

import pytest

from scripts import init_admin


class _ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        if isinstance(self.value, list):
            return self.value
        return [] if self.value is None else [self.value]


class _FakeSession:
    def __init__(self, results):
        self.results = iter(results)
        self.added = []
        self.committed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def execute(self, statement):
        return _ScalarResult(next(self.results))

    def add(self, model):
        self.added.append(model)

    async def commit(self):
        self.committed = True


def test_build_config_requires_explicit_admin_email_but_not_password():
    with pytest.raises(ValueError, match="管理员邮箱"):
        init_admin.build_config([], {})

    config = init_admin.build_config(["--admin-email", "admin@example.com"], {})
    assert config.admin_password is None


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--admin-email", "not-an-email", "--admin-password", "StrongPass!123"], "邮箱格式"),
        (["--admin-email", "admin@example.com", "--admin-password", "short"], "至少 12"),
        (["--admin-email", "admin@example.com", "--admin-password", "alllowercase123!"], "大写字母"),
    ],
)
def test_build_config_rejects_invalid_email_and_weak_password(arguments, message):
    with pytest.raises(ValueError, match=message):
        init_admin.build_config(arguments, {})


def test_build_config_supports_environment_and_cli_override():
    config = init_admin.build_config(
        ["--admin-email", "cli@example.com", "--skip-sample-app"],
        {
            "AUTH_ADMIN_EMAIL": "env@example.com",
            "AUTH_ADMIN_PASSWORD": "Environment!123",
        },
    )

    assert config.admin_email == "cli@example.com"
    assert config.admin_password == "Environment!123"
    assert config.skip_sample_app is True
    assert config.admin_password not in repr(config)


def test_build_config_normalizes_unicode_domain_to_ascii():
    config = init_admin.build_config(["--admin-email", "user@例子.公司"], {})

    assert config.admin_email == "user@xn--fsqu00a.xn--55qx5d"


def test_main_rejects_weak_password_without_echoing_it(capsys):
    password = "weak-password"

    exit_code = init_admin.main(
        ["--admin-email", "admin@example.com", "--admin-password", password],
        {},
    )

    output = capsys.readouterr()
    assert exit_code == 2
    assert password not in output.out
    assert password not in output.err


@pytest.mark.asyncio
async def test_init_creates_admin_and_generic_sample_app_without_leaking_password(monkeypatch, capsys):
    password = "UniqueAdmin!123"
    session = _FakeSession([None, None])
    hashed_passwords = []
    monkeypatch.setattr(init_admin, "async_session", lambda: session)
    monkeypatch.setattr(
        init_admin,
        "hash_password",
        lambda value: hashed_passwords.append(value) or "secure-password-hash",
    )

    config = init_admin.InitConfig(
        admin_email="admin@example.com",
        admin_password=password,
        admin_name="Auth Service Admin",
        skip_sample_app=False,
        sample_app_name="Example Application",
        sample_app_redirect_uri="http://localhost:3000/auth/callback",
    )
    await init_admin.init(config)

    output = capsys.readouterr()
    admin, application = session.added
    assert admin.email == "admin@example.com"
    assert admin.is_superuser is True
    assert admin.password_hash == "secure-password-hash"
    assert application.name == "Example Application"
    assert application.redirect_uris == ["http://localhost:3000/auth/callback"]
    assert hashed_passwords == [password]
    assert session.committed is True
    assert password not in output.out
    assert password not in output.err


@pytest.mark.asyncio
async def test_init_creates_passwordless_admin_without_hashing_placeholder(monkeypatch):
    session = _FakeSession([None])
    monkeypatch.setattr(init_admin, "async_session", lambda: session)
    monkeypatch.setattr(
        init_admin,
        "hash_password",
        lambda value: pytest.fail("未提供密码时不应生成密码哈希"),
    )

    config = init_admin.InitConfig(
        admin_email="admin@example.com",
        admin_password=None,
        admin_name="Auth Service Admin",
        skip_sample_app=True,
        sample_app_name="Example Application",
        sample_app_redirect_uri="http://localhost:3000/auth/callback",
    )
    await init_admin.init(config)

    assert len(session.added) == 1
    assert session.added[0].password_hash is None


@pytest.mark.asyncio
async def test_init_can_skip_sample_application(monkeypatch):
    session = _FakeSession([None])
    monkeypatch.setattr(init_admin, "async_session", lambda: session)
    monkeypatch.setattr(init_admin, "hash_password", lambda value: "secure-password-hash")

    config = init_admin.InitConfig(
        admin_email="admin@example.com",
        admin_password="UniqueAdmin!123",
        admin_name="Auth Service Admin",
        skip_sample_app=True,
        sample_app_name="Example Application",
        sample_app_redirect_uri="http://localhost:3000/auth/callback",
    )
    await init_admin.init(config)

    assert len(session.added) == 1
    assert session.committed is True


@pytest.mark.asyncio
async def test_init_is_idempotent_when_admin_and_sample_app_already_exist(monkeypatch):
    existing_admin = SimpleNamespace(email="admin@example.com", is_superuser=True)
    existing_application = SimpleNamespace(client_id="app_existing")
    session = _FakeSession([existing_admin, existing_application])
    monkeypatch.setattr(init_admin, "async_session", lambda: session)
    monkeypatch.setattr(
        init_admin,
        "hash_password",
        lambda value: pytest.fail("已存在的管理员不应重新计算密码哈希"),
    )

    config = init_admin.InitConfig(
        admin_email="admin@example.com",
        admin_password=None,
        admin_name="Auth Service Admin",
        skip_sample_app=False,
        sample_app_name="Example Application",
        sample_app_redirect_uri="http://localhost:3000/auth/callback",
    )
    await init_admin.init(config)

    assert session.added == []
    assert session.committed is True


@pytest.mark.asyncio
async def test_init_refuses_to_overwrite_existing_admin_password(monkeypatch):
    existing_admin = SimpleNamespace(email="admin@example.com", is_superuser=True)
    session = _FakeSession([existing_admin])
    monkeypatch.setattr(init_admin, "async_session", lambda: session)

    config = init_admin.InitConfig(
        admin_email="admin@example.com",
        admin_password="UniqueAdmin!123",
        admin_name="Auth Service Admin",
        skip_sample_app=True,
        sample_app_name="Example Application",
        sample_app_redirect_uri="http://localhost:3000/auth/callback",
    )

    with pytest.raises(ValueError, match="拒绝覆盖其密码"):
        await init_admin.init(config)

    assert session.added == []
    assert session.committed is False


@pytest.mark.asyncio
async def test_init_rejects_ambiguous_duplicate_sample_application_names(monkeypatch):
    first = SimpleNamespace(client_id="app_first")
    second = SimpleNamespace(client_id="app_second")
    session = _FakeSession([None, [first, second]])
    monkeypatch.setattr(init_admin, "async_session", lambda: session)

    config = init_admin.InitConfig(
        admin_email="admin@example.com",
        admin_password=None,
        admin_name="Auth Service Admin",
        skip_sample_app=False,
        sample_app_name="Example Application",
        sample_app_redirect_uri="http://localhost:3000/auth/callback",
    )

    with pytest.raises(ValueError, match="存在多个同名应用"):
        await init_admin.init(config)

    assert session.committed is False


@pytest.mark.asyncio
async def test_init_promotes_existing_identity_to_superuser(monkeypatch):
    existing_admin = SimpleNamespace(email="admin@example.com", is_superuser=False)
    session = _FakeSession([existing_admin])
    monkeypatch.setattr(init_admin, "async_session", lambda: session)

    config = init_admin.InitConfig(
        admin_email="admin@example.com",
        admin_password=None,
        admin_name="Auth Service Admin",
        skip_sample_app=True,
        sample_app_name="Example Application",
        sample_app_redirect_uri="http://localhost:3000/auth/callback",
    )
    await init_admin.init(config)

    assert existing_admin.is_superuser is True
    assert session.committed is True
