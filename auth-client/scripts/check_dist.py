#!/usr/bin/env python3
"""校验 auth-client 的 wheel/sdist 内容与核心元数据。"""

from __future__ import annotations

import argparse
import email.policy
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 仅 Python 3.10
    import tomli as tomllib

EXPECTED_NAME = "seanfield-auth-client"
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = tomllib.loads(
    (PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8")
)["project"]["version"]
RUNTIME_FILES = {
    "auth_service_client/__init__.py",
    "auth_service_client/dependencies.py",
    "auth_service_client/validator.py",
    "auth_service_client/py.typed",
}


def _fail(message: str) -> None:
    raise SystemExit(message)


def _is_cache_residue(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return (
        any(part in {"__pycache__", ".pytest_cache", ".ruff_cache"} for part in parts)
        or path.endswith((".pyc", ".pyo"))
    )


def _single(dist_dir: Path, pattern: str, label: str) -> Path:
    matches = sorted(dist_dir.glob(pattern))
    if len(matches) != 1:
        _fail(f"expected exactly one {label}, found {[path.name for path in matches]}")
    return matches[0]


def _validate_wheel(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        members = {name for name in archive.namelist() if not name.endswith("/")}
        residue = sorted(name for name in members if _is_cache_residue(name))
        if residue:
            _fail(f"wheel contains build residue: {residue}")
        legacy_metadata = sorted(
            name for name in members if any(part.endswith(".egg-info") for part in PurePosixPath(name).parts)
        )
        if legacy_metadata:
            _fail(f"wheel contains legacy egg-info metadata: {legacy_metadata}")

        missing_runtime = sorted(RUNTIME_FILES - members)
        if missing_runtime:
            _fail(f"wheel is missing runtime files: {missing_runtime}")
        legacy_auth = sorted(name for name in members if name.startswith("auth/"))
        if legacy_auth:
            _fail(f"wheel must not contain the conflicting auth package: {legacy_auth}")

        metadata_files = [name for name in members if name.endswith(".dist-info/METADATA")]
        license_files = [name for name in members if name.endswith(".dist-info/licenses/LICENSE")]
        top_level_files = [name for name in members if name.endswith(".dist-info/top_level.txt")]
        if len(metadata_files) != 1 or len(license_files) != 1 or len(top_level_files) != 1:
            _fail("wheel must contain exactly one METADATA, top_level.txt and Apache-2.0 LICENSE")
        if archive.read(top_level_files[0]).decode().splitlines() != ["auth_service_client"]:
            _fail("wheel top_level.txt must contain only auth_service_client")

        dist_info = metadata_files[0].removesuffix("METADATA")
        unexpected = sorted(
            name
            for name in members
            if not name.startswith("auth_service_client/") and not name.startswith(dist_info)
        )
        if unexpected:
            _fail(f"wheel contains unrelated files: {unexpected}")

        metadata = BytesParser(policy=email.policy.default).parsebytes(archive.read(metadata_files[0]))
        if metadata["Name"] != EXPECTED_NAME or metadata["Version"] != EXPECTED_VERSION:
            _fail(f"unexpected wheel identity: {metadata['Name']} {metadata['Version']}")
        if metadata["License-Expression"] != "Apache-2.0":
            _fail(f"unexpected license expression: {metadata['License-Expression']}")
        if metadata["Requires-Python"] != ">=3.10":
            _fail(f"unexpected Requires-Python: {metadata['Requires-Python']}")


def _validate_sdist(sdist: Path) -> None:
    with tarfile.open(sdist, mode="r:gz") as archive:
        members = {member.name for member in archive.getmembers() if member.isfile()}

    roots = {PurePosixPath(name).parts[0] for name in members}
    if len(roots) != 1:
        _fail(f"sdist must have one archive root, found {sorted(roots)}")
    root = roots.pop()
    relative = {name.removeprefix(f"{root}/") for name in members}

    residue = sorted(name for name in relative if _is_cache_residue(name))
    if residue:
        _fail(f"sdist contains build residue: {residue}")

    expected_egg_info = {
        "seanfield_auth_client.egg-info/PKG-INFO",
        "seanfield_auth_client.egg-info/SOURCES.txt",
        "seanfield_auth_client.egg-info/dependency_links.txt",
        "seanfield_auth_client.egg-info/requires.txt",
        "seanfield_auth_client.egg-info/top_level.txt",
    }
    actual_egg_info = {
        name
        for name in relative
        if PurePosixPath(name).parts[0].endswith(".egg-info")
    }
    if actual_egg_info != expected_egg_info:
        _fail(
            "sdist egg-info must contain only freshly generated standard metadata: "
            f"{sorted(actual_egg_info)}"
        )

    required = {"LICENSE", "README.md", "pyproject.toml", *RUNTIME_FILES}
    missing = sorted(required - relative)
    if missing:
        _fail(f"sdist is missing source files: {missing}")

    forbidden_roots = {
        ".github",
        "app",
        "auth",
        "tests",
        "alembic",
        "docs",
        "examples",
        "keys",
    }
    unrelated = sorted(name for name in relative if PurePosixPath(name).parts[0] in forbidden_roots)
    if unrelated:
        _fail(f"sdist contains unrelated repository files: {unrelated}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist_dir", type=Path)
    args = parser.parse_args()
    if not args.dist_dir.is_dir():
        _fail(f"distribution directory does not exist: {args.dist_dir}")

    wheel = _single(args.dist_dir, "*.whl", "wheel")
    sdist = _single(args.dist_dir, "*.tar.gz", "sdist")
    _validate_wheel(wheel)
    _validate_sdist(sdist)
    print(f"validated {wheel.name} and {sdist.name}")


if __name__ == "__main__":
    main()
