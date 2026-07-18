import pytest
from fastapi import HTTPException

from app.routers import auth, oauth
from app.schemas import AppCreateRequest
from app.services import auth_service
from app.utils.redirect_uri import oauth_redirect_origin, oauth_redirect_uri_allowed


class _UnexpectedDB:
    async def execute(self, _query):
        raise AssertionError("不安全回调必须在数据库查询前被拒绝")


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "https://fusion.seanfield.org/auth/callback",
        "https://app.example/auth/callback?tenant=one",
        "http://localhost:3000/auth/callback",
        "http://127.2.3.4:3000/auth/callback",
        "http://[::1]:3000/auth/callback",
        "app://-/auth/callback",
    ],
)
def test_oauth_redirect_policy_allows_secure_and_loopback_callbacks(redirect_uri):
    assert oauth_redirect_uri_allowed(redirect_uri) is True


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "http://app.example/auth/callback",
        "http://192.168.1.10:3004/auth/callback",
        "javascript://attacker.example/steal",
        "https://user:pass@app.example/auth/callback",
        "https://app.example/auth/callback#fragment",
        "/relative/callback",
    ],
)
def test_oauth_redirect_policy_rejects_insecure_callbacks(redirect_uri):
    assert oauth_redirect_uri_allowed(redirect_uri) is False
    assert oauth_redirect_origin(redirect_uri) is None


def test_oauth_redirect_origin_never_contains_path_query_or_fragment():
    assert oauth_redirect_origin("https://app.example:8443/cb?state=secret") == "https://app.example:8443"


async def test_application_registration_rejects_insecure_redirect_uri():
    payload = AppCreateRequest(name="unsafe", redirect_uris=["http://app.example/auth/callback"])

    with pytest.raises(HTTPException, match="redirect_uri must use HTTPS, app://-, or loopback HTTP"):
        await auth_service.create_application(payload, _UnexpectedDB())


def test_application_registration_accepts_current_supported_redirects():
    payload = AppCreateRequest(
        name="safe",
        redirect_uris=["https://app.example/auth/callback", "http://localhost:3000/auth/callback", "app://-/auth/callback"],
    )

    assert len(payload.redirect_uris) == 3


async def test_authorize_boundary_rejects_registered_non_loopback_http_before_database_lookup():
    assert await auth._resolve_authorize_app("appA", "http://app.example/auth/callback", _UnexpectedDB()) is None


async def test_legacy_oauth_boundary_rejects_non_loopback_http_before_database_lookup():
    with pytest.raises(HTTPException, match="Insecure redirect_uri"):
        await oauth._validate_redirect_uri("appA", "http://app.example/auth/callback", _UnexpectedDB())
