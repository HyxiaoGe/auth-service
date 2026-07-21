"""PyPI 发布元数据与类型声明的回归测试。"""

import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 仅 Python 3.10
    import tomli as tomllib

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PACKAGE_ROOT.parent


def _project_metadata() -> dict:
    return tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def test_release_version_is_consistent():
    metadata = _project_metadata()
    init_source = (PACKAGE_ROOT / "auth_service_client" / "__init__.py").read_text(encoding="utf-8")
    version_match = re.search(r'^__version__ = "([^"]+)"$', init_source, flags=re.MULTILINE)

    assert metadata["version"] == "0.3.0"
    assert re.fullmatch(r"\d+\.\d+\.\d+", metadata["version"])
    assert version_match is not None
    assert version_match.group(1) == metadata["version"]


def test_pypi_metadata_exposes_supported_runtime_and_project_links():
    metadata = _project_metadata()

    assert metadata["license"] == "Apache-2.0"
    assert metadata["license-files"] == ["LICENSE"]
    assert metadata["readme"] == {"file": "README.md", "content-type": "text/markdown"}
    assert {"Homepage", "Documentation", "Source", "Issues"} <= metadata["urls"].keys()
    assert {
        "Development Status :: 4 - Beta",
        "Framework :: FastAPI",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Typing :: Typed",
    } <= set(metadata["classifiers"])


def test_distribution_carries_license_and_typed_marker():
    assert (PACKAGE_ROOT / "LICENSE").read_bytes() == (REPOSITORY_ROOT / "LICENSE").read_bytes()
    assert not (PACKAGE_ROOT / "auth").exists()
    assert (PACKAGE_ROOT / "auth_service_client" / "py.typed").is_file()
    package_data = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"][
        "setuptools"
    ]["package-data"]
    assert "py.typed" in package_data["auth_service_client"]
    package_find = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"][
        "setuptools"
    ]["packages"]["find"]
    assert package_find["include"] == ["auth_service_client*"]


def test_public_python_examples_use_unique_import_name():
    example_paths = [
        REPOSITORY_ROOT / "README.md",
        REPOSITORY_ROOT / "docs" / "ONBOARDING.md",
        REPOSITORY_ROOT / "docs" / "AUTH_CONTRACT.md",
        REPOSITORY_ROOT / "examples" / "backend_fastapi_integration.py",
        PACKAGE_ROOT / "README.md",
    ]

    for path in example_paths:
        source = path.read_text(encoding="utf-8")
        assert "from auth import" not in source, path
        assert "from auth_service_client import" in source, path
