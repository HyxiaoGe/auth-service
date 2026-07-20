#!/usr/bin/env python3
"""安全初始化 JWT 密钥、持久化依赖与数据库迁移。"""

import asyncio
import os
import stat
import sys
import time
from pathlib import Path

from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command
from app.config import get_settings
from app.security.jwt_handler import generate_rsa_keys

DEFAULT_TIMEOUT_SECONDS = 120.0
RETRY_INTERVAL_SECONDS = 2.0
DATABASE_PLACEHOLDER = "replace-with-a-64-character-random-hex-value"


def _validate_existing_key_pair(private_path: Path, public_path: Path) -> None:
    """确认已有密钥完整、匹配，并且私钥未向组或其他用户开放。"""
    private_mode = stat.S_IMODE(private_path.stat().st_mode)
    if private_mode & 0o077:
        raise RuntimeError(
            f"JWT private key permissions are too broad: {oct(private_mode)}; expected 0o600"
        )

    try:
        private_key = serialization.load_pem_private_key(
            private_path.read_bytes(),
            password=None,
        )
        public_key = serialization.load_pem_public_key(public_path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError("JWT key files are unreadable or invalid") from exc

    if not isinstance(private_key, rsa.RSAPrivateKey) or not isinstance(
        public_key, rsa.RSAPublicKey
    ):
        raise RuntimeError("JWT key files must contain an RSA key pair")
    if private_key.key_size < 2048:
        raise RuntimeError("JWT RSA key size must be at least 2048 bits")
    if private_key.public_key().public_numbers() != public_key.public_numbers():
        raise RuntimeError("JWT private and public keys do not match")


def ensure_jwt_keys(private_path: str, public_path: str) -> str:
    """首次启动时生成密钥；后续启动只验证，不覆盖或静默修复。"""
    private_file = Path(private_path)
    public_file = Path(public_path)
    private_exists = private_file.exists()
    public_exists = public_file.exists()

    if private_exists != public_exists:
        raise RuntimeError(
            "JWT key state is incomplete; restore both key files from the same backup"
        )
    if not private_exists:
        generate_rsa_keys(private_path, public_path)
        return "generated"

    _validate_existing_key_pair(private_file, public_file)
    return "reused"


async def _wait_for_database(database_url: str, deadline: float) -> None:
    engine = create_async_engine(database_url, pool_pre_ping=True)
    try:
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                async with engine.connect() as connection:
                    await connection.execute(text("SELECT 1"))
                return
            except Exception as exc:  # pragma: no cover - 由容器集成测试覆盖
                last_error = exc
                await asyncio.sleep(RETRY_INTERVAL_SECONDS)
        raise RuntimeError("database did not become ready before bootstrap timeout") from last_error
    finally:
        await engine.dispose()


async def _wait_for_redis(redis_url: str, deadline: float) -> None:
    client = Redis.from_url(redis_url)
    try:
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                if await client.ping():
                    return
            except Exception as exc:  # pragma: no cover - 由容器集成测试覆盖
                last_error = exc
            await asyncio.sleep(RETRY_INTERVAL_SECONDS)
        raise RuntimeError("Redis did not become ready before bootstrap timeout") from last_error
    finally:
        await client.aclose()


async def wait_for_dependencies(database_url: str, redis_url: str, timeout: float) -> None:
    """在同一超时窗口内并行等待外部或 Compose 内置依赖。"""
    deadline = time.monotonic() + timeout
    async with asyncio.TaskGroup() as group:
        group.create_task(_wait_for_database(database_url, deadline))
        group.create_task(_wait_for_redis(redis_url, deadline))


def run_migrations() -> None:
    command.upgrade(Config("alembic.ini"), "head")


def main() -> None:
    settings = get_settings()
    if DATABASE_PLACEHOLDER in settings.database_url or DATABASE_PLACEHOLDER in settings.database_url_sync:
        raise RuntimeError("replace the POSTGRES_PASSWORD placeholder before starting")

    key_status = ensure_jwt_keys(
        settings.jwt_private_key_path,
        settings.jwt_public_key_path,
    )
    timeout = float(os.getenv("AUTH_BOOTSTRAP_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS))
    if timeout <= 0:
        raise RuntimeError("AUTH_BOOTSTRAP_TIMEOUT_SECONDS must be positive")

    print(f"JWT keys: {key_status}", flush=True)
    print("Waiting for PostgreSQL and Redis...", flush=True)
    asyncio.run(wait_for_dependencies(settings.database_url, settings.redis_url, timeout))
    print("Applying database migrations...", flush=True)
    run_migrations()
    print("Bootstrap completed successfully.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Bootstrap failed: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1) from exc
