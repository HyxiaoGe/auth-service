"""JWT 时钟偏差容错的安全边界测试。"""

import asyncio
import json
from datetime import datetime

import jwt
import pytest
from auth_service_client import JWTValidator
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

KID = "auth-key-1"
NOW = 2_000_000_000


class _FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime.fromtimestamp(NOW, tz=tz)


@pytest.fixture(autouse=True)
def frozen_jwt_clock(monkeypatch):
    monkeypatch.setattr(jwt.api_jwt, "datetime", _FrozenDateTime)


@pytest.fixture(scope="module")
def keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks(keypair):
    jwk = json.loads(RSAAlgorithm.to_jwk(keypair.public_key()))
    jwk.update({"kid": KID, "alg": "RS256", "use": "sig"})
    return {"keys": [jwk]}


def _mint(keypair, **claims):
    payload = {"sub": "u1", "iat": NOW, "exp": NOW + 60, **claims}
    return jwt.encode(payload, keypair, algorithm="RS256", headers={"kid": KID})


def _validator(jwks, **kwargs):
    validator = JWTValidator(
        jwks_url="http://fake/.well-known/jwks.json",
        **kwargs,
    )
    validator._jwks_cache = jwks
    validator._cache_time = NOW
    return validator


def _verify(validator, token, method):
    result = getattr(validator, method)(token)
    return asyncio.run(result) if method == "verify_async" else result


def test_default_rejects_token_issued_one_second_in_the_future(keypair, jwks):
    token = _mint(keypair, iat=NOW + 1)

    with pytest.raises(jwt.ImmatureSignatureError, match="iat"):
        _validator(jwks).verify(token)


@pytest.mark.parametrize("method", ["verify", "verify_async"])
def test_configured_leeway_accepts_one_second_clock_skew(keypair, jwks, method):
    token = _mint(keypair, iat=NOW + 1)
    validator = _validator(jwks, leeway_seconds=2)

    user = _verify(validator, token, method)

    assert user.sub == "u1"


@pytest.mark.parametrize("method", ["verify", "verify_async"])
@pytest.mark.parametrize(
    ("claims", "error_type", "error_claim"),
    [
        ({"iat": NOW + 3}, jwt.ImmatureSignatureError, "iat"),
        ({"nbf": NOW + 3}, jwt.ImmatureSignatureError, "nbf"),
        ({"exp": NOW - 3}, jwt.ExpiredSignatureError, "expired"),
    ],
)
def test_leeway_does_not_accept_claims_beyond_the_configured_window(
    keypair,
    jwks,
    method,
    claims,
    error_type,
    error_claim,
):
    token = _mint(keypair, **claims)

    with pytest.raises(error_type, match=error_claim):
        _verify(_validator(jwks, leeway_seconds=2), token, method)


@pytest.mark.parametrize("method", ["verify", "verify_async"])
@pytest.mark.parametrize(
    "claims",
    [
        {"iat": NOW + 2},
        {"nbf": NOW + 2},
        {"exp": NOW - 1},
    ],
)
def test_leeway_accepts_claims_inside_the_configured_window(keypair, jwks, method, claims):
    token = _mint(keypair, **claims)

    user = _verify(_validator(jwks, leeway_seconds=2), token, method)

    assert user.sub == "u1"


@pytest.mark.parametrize("method", ["verify", "verify_async"])
def test_expiration_at_the_exact_leeway_boundary_remains_rejected(keypair, jwks, method):
    token = _mint(keypair, exp=NOW - 2)

    with pytest.raises(jwt.ExpiredSignatureError):
        _verify(_validator(jwks, leeway_seconds=2), token, method)


@pytest.mark.parametrize(
    "value",
    [-1, float("nan"), float("inf"), float("-inf"), 10**1000, True],
)
def test_invalid_leeway_is_rejected_at_construction(value):
    with pytest.raises(ValueError, match="leeway_seconds"):
        JWTValidator(jwks_url="http://fake/.well-known/jwks.json", leeway_seconds=value)


def test_default_leeway_is_zero_for_backward_compatibility():
    validator = JWTValidator(jwks_url="http://fake/.well-known/jwks.json")

    assert validator.leeway_seconds == 0.0
