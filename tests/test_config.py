"""Session-cookie configuration: dev vs prod gating.

Cookie name and Secure flag are DERIVED from app_env so production can never be
misconfigured into an insecure cookie. TTL/SameSite/Domain are plain settings.
"""

from app.config import Settings


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


def test_session_ttls_have_sane_defaults():
    s = Settings(app_env="development")
    assert s.session_ttl_seconds == 604800  # 7-day sliding window
    assert s.session_absolute_max_seconds == 2592000  # 30-day hard cap
    # Absolute cap must be >= sliding TTL, else the sliding window is meaningless.
    assert s.session_absolute_max_seconds >= s.session_ttl_seconds
