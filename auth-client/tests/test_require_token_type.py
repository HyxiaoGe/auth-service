"""Tests for JWTValidator.require_token_type — opt-in token-type enforcement.

These mint RS256 tokens with a locally-generated RSA keypair and inject a matching
fake JWKS (kid 'auth-key-1', mirroring Auth Service) straight into the validator's
JWKS cache, so no network / running Auth Service is needed.

Context: a consumer API must reject tokens whose `type` claim is not
"access" (e.g. refresh tokens presented on protected routes). The stock validator
did not enforce this. The check is opt-in via `require_token_type` and defaults to
None (no check) so existing consumers (audio-web) are unaffected.
"""

import asyncio
import json
import time

import jwt
import pytest
from auth_service_client import AuthenticatedUser, JWTValidator
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

KID = "auth-key-1"


@pytest.fixture(scope="module")
def keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks(keypair):
    jwk = json.loads(RSAAlgorithm.to_jwk(keypair.public_key()))
    jwk.update({"kid": KID, "alg": "RS256", "use": "sig"})
    return {"keys": [jwk]}


def _mint(keypair, **claims):
    now = int(time.time())
    payload = {"sub": "u1", "iat": now, "exp": now + 3600, **claims}
    return jwt.encode(payload, keypair, algorithm="RS256", headers={"kid": KID})


def _validator(jwks, **kwargs):
    v = JWTValidator(jwks_url="http://fake/.well-known/jwks.json", **kwargs)
    # Inject JWKS straight into the cache so no HTTP / Auth Service is hit.
    v._jwks_cache = jwks
    v._cache_time = time.time()
    return v


def test_verify_returns_authenticated_user_for_valid_token(keypair, jwks):
    # Baseline characterization: harness + existing decode path work end-to-end.
    token = _mint(keypair, type="access", email="a@b.c", scopes=["admin"])
    user = _validator(jwks).verify(token)
    assert isinstance(user, AuthenticatedUser)
    assert user.sub == "u1"
    assert user.email == "a@b.c"
    assert user.scopes == ["admin"]


def test_require_token_type_accepts_matching_type(keypair, jwks):
    token = _mint(keypair, type="access")
    user = _validator(jwks, require_token_type="access").verify(token)
    assert user.sub == "u1"


def test_require_token_type_rejects_mismatched_type(keypair, jwks):
    token = _mint(keypair, type="refresh")
    with pytest.raises(jwt.InvalidTokenError):
        _validator(jwks, require_token_type="access").verify(token)


def test_require_token_type_rejects_missing_type_claim(keypair, jwks):
    token = _mint(keypair)  # no 'type' claim at all
    with pytest.raises(jwt.InvalidTokenError):
        _validator(jwks, require_token_type="access").verify(token)


def test_require_token_type_none_is_noop_for_any_type(keypair, jwks):
    # Default (what audio-web uses): no type check — a refresh-type token still decodes.
    token = _mint(keypair, type="refresh")
    user = _validator(jwks).verify(token)  # require_token_type defaults to None
    assert user.sub == "u1"


def test_require_token_type_async_rejects_mismatched_type(keypair, jwks):
    token = _mint(keypair, type="refresh")
    with pytest.raises(jwt.InvalidTokenError):
        asyncio.run(_validator(jwks, require_token_type="access").verify_async(token))


def test_require_token_type_async_accepts_matching_type(keypair, jwks):
    token = _mint(keypair, type="access")
    user = asyncio.run(_validator(jwks, require_token_type="access").verify_async(token))
    assert user.sub == "u1"
