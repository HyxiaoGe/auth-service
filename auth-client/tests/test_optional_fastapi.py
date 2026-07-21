"""FastAPI extra 不得破坏基础 JWT 校验器的裸装导入。"""

import os
import subprocess
import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def test_fastapi_helpers_remain_importable_with_extra_installed():
    from auth_service_client import require_auth, require_scopes

    assert callable(require_auth)
    assert callable(require_scopes)


def test_base_import_works_without_fastapi_and_helpers_explain_extra():
    code = r'''
import importlib.abc
import sys

class BlockFastAPI(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname == "fastapi" or fullname.startswith("fastapi."):
            raise ModuleNotFoundError("No module named 'fastapi'", name="fastapi")
        return None

sys.meta_path.insert(0, BlockFastAPI())

import auth_service_client

assert auth_service_client.JWTValidator.__name__ == "JWTValidator"
assert auth_service_client.AuthenticatedUser.__name__ == "AuthenticatedUser"
try:
    auth_service_client.require_auth
except ModuleNotFoundError as error:
    assert "auth-client[fastapi]" in str(error)
else:
    raise AssertionError("FastAPI helper must require the optional extra")
'''
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PACKAGE_ROOT)
    completed = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
