import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import get_settings

settings = get_settings()


def _load_key(path: str) -> str:
    return Path(path).read_text()


def _get_private_key():
    return _load_key(settings.jwt_private_key_path)


def _get_public_key():
    return _load_key(settings.jwt_public_key_path)


def _decode_with_key(token: str, key, issuer: str) -> dict:
    return jwt.decode(
        token,
        key,
        algorithms=[settings.jwt_algorithm],
        issuer=issuer,
        options={"verify_aud": False},
    )


def _trusted_jwks_key(token: str):
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise jwt.InvalidTokenError("trusted token is missing kid")
        jwks = json.loads(Path(settings.jwt_trusted_jwks_path).read_text())
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        if not isinstance(keys, list):
            raise jwt.InvalidTokenError("trusted JWKS has an invalid shape")
        matches = [
            key
            for key in keys
            if isinstance(key, dict)
            and key.get("kid") == kid
            and key.get("kty") == "RSA"
            and key.get("use", "sig") == "sig"
            and key.get("alg", settings.jwt_algorithm) == settings.jwt_algorithm
        ]
        if len(matches) != 1:
            raise jwt.InvalidTokenError("trusted JWKS key is missing or ambiguous")
        return jwt.PyJWK.from_dict(matches[0], algorithm=settings.jwt_algorithm).key
    except jwt.InvalidTokenError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise jwt.InvalidTokenError("trusted JWKS is unavailable") from exc


def create_access_token(
    user_id: str,
    email: str,
    app_client_id: str | None = None,
    scopes: list[str] | None = None,
    auth_generation: int = 0,
) -> str:
    """Create a short-lived access token."""
    now = datetime.now(UTC)
    payload = {
        "sub": user_id,
        "email": email,
        "iss": settings.auth_base_url,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
        "jti": str(uuid.uuid4()),
        "type": "access",
        "auth_generation": auth_generation,
    }
    if app_client_id:
        payload["aud"] = app_client_id
    if scopes:
        payload["scopes"] = scopes

    return jwt.encode(payload, _get_private_key(), algorithm=settings.jwt_algorithm, headers={"kid": "auth-key-1"})


def create_refresh_token(
    user_id: str,
    app_client_id: str | None = None,
    auth_generation: int = 0,
) -> tuple[str, str, datetime]:
    """
    Create a long-lived refresh token.
    Returns: (token_string, token_hash, expires_at)
    """
    now = datetime.now(UTC)
    expires_at = now + timedelta(days=settings.refresh_token_expire_days)

    payload = {
        "sub": user_id,
        "iss": settings.auth_base_url,
        "iat": now,
        "exp": expires_at,
        "jti": str(uuid.uuid4()),
        "type": "refresh",
        "auth_generation": auth_generation,
    }
    if app_client_id:
        payload["aud"] = app_client_id

    token = jwt.encode(payload, _get_private_key(), algorithm=settings.jwt_algorithm, headers={"kid": "auth-key-1"})
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token, token_hash, expires_at


def decode_token(token: str, verify_type: str | None = None) -> dict:
    """
    Decode and verify a JWT token.
    Raises jwt.exceptions on failure.
    """
    try:
        payload = _decode_with_key(token, _get_public_key(), settings.auth_base_url)
    except jwt.InvalidSignatureError:
        # 外部 issuer 只可扩展 access-token 验证；refresh token 必须始终由
        # 本服务自己的密钥与 issuer 签发，避免跨环境旋转 token 链。
        if (
            verify_type != "access"
            or not settings.jwt_trusted_jwks_path
            or not settings.jwt_trusted_issuer
        ):
            raise
        payload = _decode_with_key(
            token,
            _trusted_jwks_key(token),
            settings.jwt_trusted_issuer,
        )
    if verify_type and payload.get("type") != verify_type:
        raise jwt.InvalidTokenError(f"Expected token type '{verify_type}', got '{payload.get('type')}'")
    return payload


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def get_jwks() -> dict:
    """
    Generate JWKS (JSON Web Key Set) from the public key.
    Business services use this endpoint to verify JWTs without sharing secrets.
    """
    public_key_pem = _get_public_key()
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    public_key = load_pem_public_key(public_key_pem.encode())
    numbers = public_key.public_numbers()

    # Convert to base64url encoding
    import base64

    def _b64url(num: int, length: int) -> str:
        data = num.to_bytes(length, byteorder="big")
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    e = _b64url(numbers.e, 3)
    n = _b64url(numbers.n, (numbers.n.bit_length() + 7) // 8)

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "auth-key-1",
                "n": n,
                "e": e,
            }
        ]
    }


def generate_rsa_keys(private_path: str = "keys/private.pem", public_path: str = "keys/public.pem"):
    """Generate RSA key pair and save to files."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    Path(private_path).parent.mkdir(parents=True, exist_ok=True)

    Path(private_path).write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    Path(public_path).write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(f"RSA keys generated: {private_path}, {public_path}")
