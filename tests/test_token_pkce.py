"""Conditional PKCE on POST /auth/oauth/token.

Zero-breakage rule: PKCE is enforced ONLY when the auth code was minted with a
code_challenge (i.e. came through /authorize). Legacy codes from the existing direct
/oauth/{provider} flow carry no challenge, so /token must keep working without a
code_verifier -- otherwise every current app breaks.
"""

import uuid

import pytest
from fastapi import HTTPException

from app.routers import oauth
from app.schemas import OAuthTokenExchangeRequest
from app.utils.redis import store_auth_code

# RFC 7636 Appendix B vector.
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


# ---- endpoint reject paths (these raise at the PKCE gate, before any DB access) ----


async def test_token_rejects_wrong_verifier_when_code_has_challenge():
    await store_auth_code(
        "c-wrong",
        {"user_id": str(uuid.uuid4()), "app_client_id": "appA", "code_challenge": CHALLENGE},
        ttl=100,
    )
    payload = OAuthTokenExchangeRequest(code="c-wrong", client_id="appA", code_verifier="bogus")
    with pytest.raises(HTTPException) as exc:
        await oauth.exchange_code_for_tokens(payload=payload, request=None, db=None)
    assert exc.value.status_code == 400
    assert "invalid_grant" in exc.value.detail


async def test_token_rejects_missing_verifier_when_code_has_challenge():
    await store_auth_code(
        "c-missing",
        {"user_id": str(uuid.uuid4()), "app_client_id": "appA", "code_challenge": CHALLENGE},
        ttl=100,
    )
    payload = OAuthTokenExchangeRequest(code="c-missing", client_id="appA")  # no code_verifier
    with pytest.raises(HTTPException) as exc:
        await oauth.exchange_code_for_tokens(payload=payload, request=None, db=None)
    assert exc.value.status_code == 400
    assert "invalid_grant" in exc.value.detail


# ---- the PKCE gate as a unit (pure: no DB) ----


def test_enforce_pkce_passes_legacy_code_without_challenge():
    # Legacy direct-flow code: no challenge stored -> no verifier needed (zero-breakage).
    oauth._enforce_pkce({"user_id": "u"}, None)  # must not raise


def test_enforce_pkce_passes_correct_verifier():
    oauth._enforce_pkce({"code_challenge": CHALLENGE}, VERIFIER)  # must not raise


def test_enforce_pkce_rejects_missing_verifier():
    with pytest.raises(HTTPException) as exc:
        oauth._enforce_pkce({"code_challenge": CHALLENGE}, None)
    assert exc.value.status_code == 400
    assert "invalid_grant" in exc.value.detail


def test_enforce_pkce_rejects_wrong_verifier():
    with pytest.raises(HTTPException) as exc:
        oauth._enforce_pkce({"code_challenge": CHALLENGE}, "nope")
    assert exc.value.status_code == 400
