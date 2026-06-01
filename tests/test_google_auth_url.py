"""get_google_auth_url(state, prompt=None): prompt is caller-driven, not hardcoded.

Today the function pins prompt="consent", which force-shows Google's consent screen on
every login and defeats even Google's own SSO. For cross-app silent SSO the default must
send NO prompt (let Google use its session), while /authorize can still pass prompt=login
to force re-auth.
"""

from urllib.parse import parse_qs, urlparse

from app.services import oauth_service


def _query(url: str) -> dict:
    return parse_qs(urlparse(url).query)


def test_default_sends_no_prompt():
    q = _query(oauth_service.get_google_auth_url("state123"))
    assert "prompt" not in q  # silent: let Google use its own session


def test_default_does_not_request_offline_access():
    # We mint our own refresh tokens; we never use Google's, so don't ask for offline.
    q = _query(oauth_service.get_google_auth_url("state123"))
    assert "access_type" not in q


def test_prompt_login_is_passed_through():
    q = _query(oauth_service.get_google_auth_url("state123", prompt="login"))
    assert q.get("prompt") == ["login"]


def test_prompt_select_account_is_passed_through():
    q = _query(oauth_service.get_google_auth_url("state123", prompt="select_account"))
    assert q.get("prompt") == ["select_account"]


def test_state_is_preserved():
    q = _query(oauth_service.get_google_auth_url("state123"))
    assert q.get("state") == ["state123"]
