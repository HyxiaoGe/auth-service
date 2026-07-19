"""JWT 密钥生成的防覆盖与文件权限测试。"""

import stat

import pytest

from app.security.jwt_handler import generate_rsa_keys


def test_generate_rsa_keys_creates_private_key_with_restricted_permissions(tmp_path):
    private_path = tmp_path / "nested" / "private.pem"
    public_path = tmp_path / "nested" / "public.pem"

    generate_rsa_keys(str(private_path), str(public_path))

    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(public_path.stat().st_mode) == 0o644
    assert b"PRIVATE KEY" in private_path.read_bytes()
    assert b"PUBLIC KEY" in public_path.read_bytes()


@pytest.mark.parametrize("existing_name", ["private.pem", "public.pem"])
def test_generate_rsa_keys_refuses_to_overwrite_either_existing_key(tmp_path, existing_name):
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    existing_path = tmp_path / existing_name
    existing_path.write_bytes(b"keep-existing-key")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        generate_rsa_keys(str(private_path), str(public_path))

    assert existing_path.read_bytes() == b"keep-existing-key"
    assert not ({private_path, public_path} - {existing_path}).pop().exists()
