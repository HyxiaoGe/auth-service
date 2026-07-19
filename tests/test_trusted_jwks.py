"""本地 headless auth 只信任显式配置的外部 issuer/JWKS。"""

import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app.config import Settings
from app.security import jwt_handler


def _key_pair(tmp_path, name: str) -> tuple[str, str, object]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = tmp_path / f"{name}-private.pem"
    public_path = tmp_path / f"{name}-public.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return str(private_path), str(public_path), private_key


def _token(
    private_key,
    issuer: str,
    *,
    token_type: str = "access",
    kid: str | None = "auth-key-1",
    expires_in: timedelta = timedelta(minutes=5),
) -> str:
    now = datetime.now(UTC)
    headers = {"kid": kid} if kid is not None else {}
    return jwt.encode(
        {
            "sub": "admin-id",
            "email": "admin@example.com",
            "iss": issuer,
            "iat": now,
            "exp": now + expires_in,
            "jti": "token-id",
            "type": token_type,
            "scopes": ["admin"],
        },
        private_key,
        algorithm="RS256",
        headers=headers,
    )


def _settings(tmp_path, *, trusted_issuer: str = "https://auth.dev.example"):
    local_private, local_public, local_key = _key_pair(tmp_path, "local")
    _, _, trusted_key = _key_pair(tmp_path, "trusted")
    trusted_jwks = tmp_path / "trusted-jwks.json"
    jwk = json.loads(RSAAlgorithm.to_jwk(trusted_key.public_key()))
    jwk.update({"kid": "auth-key-1", "use": "sig", "alg": "RS256"})
    trusted_jwks.write_text(json.dumps({"keys": [jwk]}))
    settings = Settings(
        auth_base_url="http://localhost:8101",
        jwt_private_key_path=local_private,
        jwt_public_key_path=local_public,
        jwt_trusted_jwks_path=str(trusted_jwks),
        jwt_trusted_issuer=trusted_issuer,
    )
    return settings, local_key, trusted_key


def test_decode_token_preserves_primary_issuer_and_accepts_explicit_trusted_jwks(
    monkeypatch, tmp_path
):
    settings, local_key, trusted_key = _settings(tmp_path)
    monkeypatch.setattr(jwt_handler, "settings", settings)

    local_payload = jwt_handler.decode_token(
        _token(local_key, settings.auth_base_url), verify_type="access"
    )
    trusted_payload = jwt_handler.decode_token(
        _token(trusted_key, settings.jwt_trusted_issuer), verify_type="access"
    )

    assert local_payload["sub"] == "admin-id"
    assert trusted_payload["scopes"] == ["admin"]


def test_trusted_jwks_does_not_accept_an_unconfigured_issuer(monkeypatch, tmp_path):
    settings, _, trusted_key = _settings(tmp_path)
    monkeypatch.setattr(jwt_handler, "settings", settings)

    with pytest.raises(jwt.InvalidIssuerError):
        jwt_handler.decode_token(
            _token(trusted_key, "https://attacker.example"),
            verify_type="access",
        )


def test_trusted_jwks_still_enforces_access_token_type(monkeypatch, tmp_path):
    settings, _, trusted_key = _settings(tmp_path)
    monkeypatch.setattr(jwt_handler, "settings", settings)

    with pytest.raises(jwt.InvalidTokenError, match="Expected token type"):
        jwt_handler.decode_token(
            _token(trusted_key, settings.jwt_trusted_issuer, token_type="refresh"),
            verify_type="access",
        )


def test_trusted_jwks_never_extends_refresh_token_trust(monkeypatch, tmp_path):
    settings, _, trusted_key = _settings(tmp_path)
    monkeypatch.setattr(jwt_handler, "settings", settings)

    with pytest.raises(jwt.InvalidSignatureError):
        jwt_handler.decode_token(
            _token(
                trusted_key,
                settings.jwt_trusted_issuer,
                token_type="refresh",
            ),
            verify_type="refresh",
        )


@pytest.mark.parametrize("kid", [None, "unknown-key"])
def test_trusted_jwks_rejects_missing_or_unknown_kid(monkeypatch, tmp_path, kid):
    settings, _, trusted_key = _settings(tmp_path)
    monkeypatch.setattr(jwt_handler, "settings", settings)

    with pytest.raises(jwt.InvalidTokenError):
        jwt_handler.decode_token(
            _token(trusted_key, settings.jwt_trusted_issuer, kid=kid),
            verify_type="access",
        )


def test_trusted_jwks_rejects_expired_tokens(monkeypatch, tmp_path):
    settings, _, trusted_key = _settings(tmp_path)
    monkeypatch.setattr(jwt_handler, "settings", settings)

    with pytest.raises(jwt.ExpiredSignatureError):
        jwt_handler.decode_token(
            _token(
                trusted_key,
                settings.jwt_trusted_issuer,
                expires_in=timedelta(seconds=-1),
            ),
            verify_type="access",
        )


def test_trusted_jwks_does_not_enable_other_algorithms(monkeypatch, tmp_path):
    settings, _, _ = _settings(tmp_path)
    monkeypatch.setattr(jwt_handler, "settings", settings)
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "admin-id",
            "iss": settings.jwt_trusted_issuer,
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "type": "access",
        },
        "not-an-rsa-key",
        algorithm="HS256",
        headers={"kid": "auth-key-1"},
    )

    with pytest.raises(jwt.InvalidAlgorithmError):
        jwt_handler.decode_token(token, verify_type="access")
