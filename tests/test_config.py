"""Session Cookie、邮箱登录安全前置与限流配置测试。"""

import pytest
from pydantic import ValidationError

from app.config import Settings


def test_password_auth_is_disabled_by_default():
    settings = Settings()

    assert settings.password_auth_enabled is False
    assert settings.password_auth_internal_token == ""
    assert settings.password_auth_email_prefix == ""
    assert settings.password_auth_email_domain == ""


def test_trusted_jwks_path_and_issuer_must_be_configured_together():
    with pytest.raises(ValidationError, match="jwt_trusted"):
        Settings(jwt_trusted_jwks_path="/tmp/dev-jwks.json")
    with pytest.raises(ValidationError, match="jwt_trusted"):
        Settings(jwt_trusted_issuer="https://auth.dev.example")

    settings = Settings(
        jwt_trusted_jwks_path="/tmp/dev-jwks.json",
        jwt_trusted_issuer="https://auth.dev.example",
    )
    assert settings.jwt_trusted_issuer == "https://auth.dev.example"

    with pytest.raises(ValidationError, match="only allowed in development"):
        Settings(
            app_env="production",
            jwt_trusted_jwks_path="/tmp/dev-jwks.json",
            jwt_trusted_issuer="https://auth.dev.example",
        )


def test_resend_preflight_cache_is_development_only_and_trimmed():
    settings = Settings(
        resend_preflight_cache_path="/tmp/resend-preflight.json",
        resend_preflight_cache_ttl_seconds=3600,
    )
    assert settings.resend_preflight_cache_path == "/tmp/resend-preflight.json"

    with pytest.raises(ValidationError, match="resend_preflight_cache_path"):
        Settings(resend_preflight_cache_path=" /tmp/resend-preflight.json")
    with pytest.raises(ValidationError, match="only allowed in development"):
        Settings(
            app_env="production",
            resend_preflight_cache_path="/tmp/resend-preflight.json",
        )


@pytest.mark.parametrize("internal_token", ["", "short"])
def test_enabled_password_auth_requires_long_internal_token(internal_token):
    with pytest.raises(ValidationError, match="password_auth_internal_token"):
        Settings(
            password_auth_enabled=True,
            password_auth_internal_token=internal_token,
        )


@pytest.mark.parametrize("internal_token", [f" {'x' * 32}", f"{'x' * 32} "])
def test_enabled_password_auth_rejects_internal_token_with_outer_whitespace(internal_token):
    with pytest.raises(ValidationError, match="password_auth_internal_token"):
        Settings(
            password_auth_enabled=True,
            password_auth_internal_token=internal_token,
            password_auth_email_prefix="fusion-perf+",
            password_auth_email_domain="seanfield.org",
        )


@pytest.mark.parametrize(
    ("email_prefix", "email_domain"),
    [
        ("", "seanfield.org"),
        ("fusion-perf+", ""),
    ],
)
def test_enabled_password_auth_requires_email_scope(email_prefix, email_domain):
    with pytest.raises(ValidationError, match="password_auth_email"):
        Settings(
            password_auth_enabled=True,
            password_auth_internal_token="x" * 32,
            password_auth_email_prefix=email_prefix,
            password_auth_email_domain=email_domain,
        )


def test_enabled_password_auth_accepts_long_internal_token():
    settings = Settings(
        password_auth_enabled=True,
        password_auth_internal_token="x" * 32,
        password_auth_email_prefix="fusion-perf+",
        password_auth_email_domain="seanfield.org",
    )

    assert settings.password_auth_enabled is True


def test_dev_session_cookie_is_lax_host_only_not_secure():
    s = Settings(app_env="development")
    assert s.session_cookie_name == "sso_session"
    assert s.session_cookie_secure is False
    assert s.session_cookie_samesite == "lax"
    assert s.session_cookie_domain is None


def test_prod_session_cookie_is_host_prefixed_and_secure():
    s = Settings(app_env="production")
    # __Host- prefix mandates Secure + Path=/ + no Domain — only valid over HTTPS.
    assert s.session_cookie_name == "__Host-sso_session"
    assert s.session_cookie_secure is True


def test_https_auth_base_url_keeps_dev_cookie_name_but_forces_secure():
    s = Settings(app_env="development", auth_base_url="https://auth.example.com")

    assert s.session_cookie_name == "sso_session"
    assert s.session_cookie_secure is True


def test_https_with_explicit_cookie_domain_cannot_use_host_prefix():
    s = Settings(
        app_env="development",
        auth_base_url="https://auth.example.com",
        session_cookie_domain=".example.com",
    )

    assert s.session_cookie_name == "sso_session"
    assert s.session_cookie_secure is True


def test_email_login_is_disabled_until_all_security_and_smtp_config_is_present():
    assert Settings().email_login_ready is False
    assert Settings().email_headless_login_ready is False
    assert (
        Settings(
            email_login_enabled=True,
            email_code_pepper="x" * 32,
            smtp_host="smtp.example.com",
            smtp_from_email="login@example.com",
            smtp_smoke_recipient="smtp-smoke@example.com",
        ).email_login_ready
        is True
    )


def test_headless_email_login_has_an_independent_default_off_switch():
    ready = Settings(
        auth_base_url="http://localhost:8100",
        email_login_enabled=True,
        email_code_pepper="x" * 32,
        smtp_host="smtp.example.com",
        smtp_from_email="login@example.com",
        smtp_smoke_recipient="smtp-smoke@example.com",
    )
    enabled = ready.model_copy(update={"email_headless_login_enabled": True})

    assert ready.email_login_ready is True
    assert ready.email_headless_login_ready is False
    assert enabled.email_headless_login_ready is True


def test_email_login_public_https_requires_explicit_trusted_proxy_cidrs():
    with pytest.raises(ValidationError, match="trusted_proxy_cidrs"):
        Settings(
            auth_base_url="https://auth.example.com",
            email_login_enabled=True,
            email_code_pepper="x" * 32,
            smtp_host="smtp.example.com",
            smtp_from_email="login@example.com",
            smtp_smoke_recipient="smtp-smoke@example.com",
        )


def test_email_login_local_http_allows_empty_trusted_proxy_cidrs():
    settings = Settings(
        auth_base_url="http://localhost:8100",
        email_login_enabled=True,
        email_code_pepper="x" * 32,
        smtp_host="smtp.example.com",
        smtp_from_email="login@example.com",
        smtp_smoke_recipient="smtp-smoke@example.com",
    )

    assert settings.trusted_proxy_networks == ()
    assert settings.email_login_ready is True


def test_enabled_email_login_requires_smoke_recipient():
    with pytest.raises(ValidationError, match="smtp_smoke_recipient"):
        Settings(
            auth_base_url="http://localhost:8100",
            email_login_enabled=True,
            email_code_pepper="x" * 32,
            smtp_host="smtp.example.com",
            smtp_from_email="login@example.com",
        )


def test_email_authorize_limits_default_to_high_water_circuit_breakers():
    settings = Settings()

    assert settings.email_authorize_rate_limit_per_client == 2000
    assert settings.email_authorize_rate_limit_global == 10000


def test_email_verify_limits_have_separate_request_and_flow_defaults():
    settings = Settings()

    assert settings.email_verify_rate_limit_per_ip == 120
    assert settings.email_verify_rate_limit_per_flow == 15
    assert settings.email_verify_rate_limit_global == 10000


def test_email_send_request_limits_have_separate_defaults():
    settings = Settings()

    assert settings.email_send_request_rate_limit_per_ip == 120
    assert settings.email_send_request_rate_limit_per_flow == 15
    assert settings.email_send_request_rate_limit_global == 10000


def test_email_send_request_flow_limit_covers_actual_send_quota():
    with pytest.raises(
        ValidationError,
        match="email_send_request_rate_limit_per_flow must be >=",
    ):
        Settings(
            email_rate_limit_per_flow=4,
            email_send_request_rate_limit_per_flow=3,
        )


def test_email_verify_flow_limit_covers_every_allowed_code_attempt():
    with pytest.raises(
        ValidationError,
        match="email_verify_rate_limit_per_flow must be >=",
    ):
        Settings(
            email_code_max_attempts=5,
            email_rate_limit_per_flow=3,
            email_verify_rate_limit_per_flow=14,
        )

    settings = Settings(
        email_code_max_attempts=5,
        email_rate_limit_per_flow=3,
        email_verify_rate_limit_per_flow=15,
    )
    assert settings.email_verify_rate_limit_per_flow == 15


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("email_code_ttl_seconds", 0),
        ("email_flow_ttl_seconds", -1),
        ("email_flow_recovery_ttl_seconds", 0),
        ("email_code_resend_seconds", 0),
        ("email_code_max_attempts", 0),
        ("email_rate_limit_per_email", 0),
        ("email_rate_limit_per_ip", 0),
        ("email_rate_limit_per_flow", 0),
        ("email_send_rate_limit_global", 0),
        ("email_authorize_rate_limit_per_ip", 0),
        ("email_authorize_rate_limit_per_client", 0),
        ("email_authorize_rate_limit_global", 0),
        ("email_send_request_rate_limit_per_ip", 0),
        ("email_send_request_rate_limit_per_flow", 0),
        ("email_send_request_rate_limit_global", 0),
        ("email_verify_rate_limit_per_ip", 0),
        ("email_verify_rate_limit_per_flow", 0),
        ("email_verify_rate_limit_global", 0),
        ("email_flow_max_per_browser", 0),
        ("email_rate_limit_window_seconds", 0),
        ("smtp_port", 0),
        ("smtp_port", 65536),
        ("smtp_timeout_seconds", 0),
    ],
)
def test_email_security_and_smtp_numeric_settings_must_be_positive(field, value):
    with pytest.raises(ValidationError):
        Settings(**{field: value})


def test_session_ttls_have_sane_defaults():
    s = Settings(app_env="development")
    assert s.session_ttl_seconds == 604800  # 7-day sliding window
    assert s.session_absolute_max_seconds == 2592000  # 30-day hard cap
    # Absolute cap must be >= sliding TTL, else the sliding window is meaningless.
    assert s.session_absolute_max_seconds >= s.session_ttl_seconds


def test_enabled_email_login_requires_long_pepper():
    with pytest.raises(ValidationError, match="at least 32 characters"):
        Settings(email_login_enabled=True, email_code_pepper="short")


def test_email_code_cannot_outlive_its_authorization_flow():
    with pytest.raises(ValidationError, match="email_code_ttl_seconds"):
        Settings(email_code_ttl_seconds=601, email_flow_ttl_seconds=600)


def test_plaintext_smtp_is_allowed_only_for_explicit_local_development():
    local = Settings(
        auth_base_url="http://localhost:8100",
        email_login_enabled=True,
        email_code_pepper="x" * 32,
        smtp_host="smtp.local",
        smtp_from_email="login@example.com",
        smtp_smoke_recipient="smtp-smoke@example.com",
        smtp_starttls=False,
        smtp_allow_plaintext_development=True,
    )
    assert local.email_login_ready is True

    with pytest.raises(ValidationError, match="plaintext SMTP"):
        Settings(
            auth_base_url="https://auth.example.com",
            email_login_enabled=True,
            email_code_pepper="x" * 32,
            smtp_host="smtp.local",
            smtp_from_email="login@example.com",
            smtp_smoke_recipient="smtp-smoke@example.com",
            smtp_starttls=False,
            smtp_allow_plaintext_development=True,
        )
