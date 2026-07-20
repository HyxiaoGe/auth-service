"""自托管初始化的密钥安全与幂等测试。"""

import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.security.jwt_handler import generate_rsa_keys
from scripts.bootstrap import ensure_jwt_keys


def test_ensure_jwt_keys_generates_then_reuses_same_pair(tmp_path):
    private_path = tmp_path / "keys" / "private.pem"
    public_path = tmp_path / "keys" / "public.pem"

    assert ensure_jwt_keys(str(private_path), str(public_path)) == "generated"
    private_fingerprint = private_path.read_bytes()
    public_fingerprint = public_path.read_bytes()

    assert ensure_jwt_keys(str(private_path), str(public_path)) == "reused"
    assert private_path.read_bytes() == private_fingerprint
    assert public_path.read_bytes() == public_fingerprint
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600


@pytest.mark.parametrize("existing_name", ["private.pem", "public.pem"])
def test_ensure_jwt_keys_rejects_partial_pair_without_overwrite(tmp_path, existing_name):
    existing_path = tmp_path / existing_name
    existing_path.write_bytes(b"keep-me")

    with pytest.raises(RuntimeError, match="incomplete"):
        ensure_jwt_keys(
            str(tmp_path / "private.pem"),
            str(tmp_path / "public.pem"),
        )

    assert existing_path.read_bytes() == b"keep-me"


def test_ensure_jwt_keys_rejects_mismatched_pair(tmp_path):
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    generate_rsa_keys(
        str(first_dir / "private.pem"),
        str(first_dir / "public.pem"),
    )
    generate_rsa_keys(
        str(second_dir / "private.pem"),
        str(second_dir / "public.pem"),
    )

    with pytest.raises(RuntimeError, match="do not match"):
        ensure_jwt_keys(
            str(first_dir / "private.pem"),
            str(second_dir / "public.pem"),
        )


@pytest.mark.parametrize("corrupt_name", ["private.pem", "public.pem"])
def test_ensure_jwt_keys_rejects_invalid_key_file(tmp_path, corrupt_name):
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    generate_rsa_keys(str(private_path), str(public_path))
    (tmp_path / corrupt_name).write_bytes(b"not-a-key")

    with pytest.raises(RuntimeError, match="unreadable or invalid"):
        ensure_jwt_keys(str(private_path), str(public_path))


def test_ensure_jwt_keys_rejects_broad_private_permissions(tmp_path):
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    generate_rsa_keys(str(private_path), str(public_path))
    private_path.chmod(0o640)

    with pytest.raises(RuntimeError, match="permissions are too broad"):
        ensure_jwt_keys(str(private_path), str(public_path))


def test_ensure_jwt_keys_rejects_weak_rsa_pair(tmp_path):
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    with pytest.raises(RuntimeError, match="at least 2048 bits"):
        ensure_jwt_keys(str(private_path), str(public_path))


def test_default_compose_uses_versioned_image_and_bootstrap_gate():
    compose = (Path(__file__).parents[1] / "compose.yaml").read_text()

    assert "ghcr.io/hyxiaoge/auth-service:v1.1.0" in compose
    assert 'profiles: ["bundled"]' in compose
    assert "python\", \"-m\", \"scripts.bootstrap" in compose
    assert "condition: service_completed_successfully" in compose
    assert "auth_keys:/app/keys:ro" in compose
    assert "build:" not in compose
