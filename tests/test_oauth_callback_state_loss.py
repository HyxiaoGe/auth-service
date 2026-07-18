"""State-loss hardening: a missing/expired oauth_state must not dead-end the user.

When the Redis state is gone at callback time (expired, or consumed by a duplicate
callback during a slow IdP round-trip) the payload that held client_id/redirect_uri is
gone too -- so there is no app to safely redirect back to. Instead of the raw JSON 400
that previously left the user stranded on a "looks-broken" page, the callback renders a
branded HTML page and emits a structured ``oauth_state.missing`` log (with the real client
IP) so the next occurrence is diagnosable from the app logs.
"""

import logging

from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.requests import Request

from app.routers import oauth


def _req(xff: str | None = None) -> Request:
    """Minimal Starlette Request; ``xff`` populates X-Forwarded-For (real client hop)."""
    headers = [(b"x-forwarded-for", xff.encode())] if xff else []
    return Request({"type": "http", "headers": headers, "client": ("10.0.0.9", 0)})


async def test_google_callback_expired_state_renders_branded_page_and_logs(monkeypatch, caplog):
    async def fake_state(_state):
        raise ValueError("Invalid or expired OAuth state")

    monkeypatch.setattr(oauth.oauth_service, "verify_and_consume_state", fake_state)

    with caplog.at_level(logging.WARNING):
        resp = await oauth.google_callback(
            request=_req(xff="203.0.113.7, 10.0.0.1"), code="abc", state="deadbeefstate0", db=None
        )

    # graceful: a branded HTML 400, NOT a raised HTTPException / raw JSON dead-end
    assert isinstance(resp, HTMLResponse)
    assert resp.status_code == 400
    assert "text/html" in resp.headers["content-type"]
    assert "重新登录" in resp.body.decode()
    # instrumentation: missing-state logged with provider + real client IP (first XFF hop)
    assert "oauth_state.missing" in caplog.text
    assert "provider=google" in caplog.text
    assert "203.0.113.7" in caplog.text


async def test_github_callback_expired_state_renders_branded_page_and_logs(monkeypatch, caplog):
    async def fake_state(_state):
        raise ValueError("Invalid or expired OAuth state")

    monkeypatch.setattr(oauth.oauth_service, "verify_and_consume_state", fake_state)

    with caplog.at_level(logging.WARNING):
        resp = await oauth.github_callback(request=_req(xff="198.51.100.4"), code="abc", state="ghstate00000", db=None)

    assert isinstance(resp, HTMLResponse)
    assert resp.status_code == 400
    assert "重新登录" in resp.body.decode()
    assert "oauth_state.missing" in caplog.text
    assert "provider=github" in caplog.text
    assert "198.51.100.4" in caplog.text


async def test_google_callback_absent_state_renders_branded_page_and_logs(caplog):
    # No state query param at all -> same graceful page, logged as reason=absent.
    with caplog.at_level(logging.WARNING):
        resp = await oauth.google_callback(request=_req(), code="abc", state=None, db=None)

    assert isinstance(resp, HTMLResponse)
    assert resp.status_code == 400
    assert "oauth_state.missing" in caplog.text
    assert "reason=absent" in caplog.text


# ---- Recovery: a lost main state whose durable routing copy survives bounces back ----


async def test_google_callback_recovers_lost_state_and_bounces_back(monkeypatch, caplog):
    """Main state gone (expired/duplicate) BUT the durable recovery copy still knows the app.

    Root-cause fix: the user must land back IN the app (error=login_required, so the SDK can
    retry) instead of dead-ending on the foreign-domain branded page. No code is exchanged
    and no token is minted on this path, so it carries no replay/CSRF risk.
    """

    async def fake_state(_state):
        raise ValueError("Invalid or expired OAuth state")

    async def fake_recover(_state):
        return {
            "client_id": "c1",
            "redirect_uri": "https://app.example/cb?tenant=one&code=old&state=old",
        }

    async def fake_registered(_client_id, _redirect_uri, _db):
        return True

    monkeypatch.setattr(oauth.oauth_service, "verify_and_consume_state", fake_state)
    monkeypatch.setattr(oauth.oauth_service, "recover_state_routing", fake_recover)
    monkeypatch.setattr(oauth, "_redirect_uri_registered", fake_registered)

    with caplog.at_level(logging.INFO):
        resp = await oauth.google_callback(
            request=_req(xff="203.0.113.7"), code="abc", state="lostbutrecoverable", db=None
        )

    # bounced back to the app, NOT a branded dead-end
    assert isinstance(resp, RedirectResponse)
    assert resp.status_code == 302
    loc = resp.headers["location"]
    assert loc.startswith("https://app.example/cb?")
    assert "error=login_required" in loc
    assert "tenant=one" in loc
    assert "code=old" not in loc
    assert "state=old" not in loc
    assert resp.headers["cache-control"] == "no-store"
    # distinct instrumentation: recovered, not missing
    assert "oauth_state.recovered" in caplog.text
    assert "provider=google" in caplog.text


async def test_recovered_state_with_unregistered_uri_falls_back_to_branded_page(monkeypatch, caplog):
    """Defense in depth: even a recovered redirect_uri must be a registered one, else we
    refuse to redirect (open-redirect guard) and fall back to the branded page."""

    async def fake_state(_state):
        raise ValueError("Invalid or expired OAuth state")

    async def fake_recover(_state):
        return {"client_id": "c1", "redirect_uri": "https://evil.example/cb"}

    async def fake_registered(_client_id, _redirect_uri, _db):
        return False

    monkeypatch.setattr(oauth.oauth_service, "verify_and_consume_state", fake_state)
    monkeypatch.setattr(oauth.oauth_service, "recover_state_routing", fake_recover)
    monkeypatch.setattr(oauth, "_redirect_uri_registered", fake_registered)

    with caplog.at_level(logging.WARNING):
        resp = await oauth.google_callback(request=_req(), code="abc", state="recovbadURI", db=None)

    assert isinstance(resp, HTMLResponse)
    assert resp.status_code == 400
    assert "oauth_state.missing" in caplog.text
