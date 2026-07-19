#!/usr/bin/env python3
"""安全地初始化管理员用户，并可选注册一个示例应用。"""

import argparse
import asyncio
import os
import secrets
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import func, select

from app.config import get_settings
from app.database import async_session
from app.models import Application, User
from app.security.password import hash_password
from app.utils.email import normalize_email

settings = get_settings()

ADMIN_EMAIL_ENV = "AUTH_ADMIN_EMAIL"
ADMIN_PASSWORD_ENV = "AUTH_ADMIN_PASSWORD"
ADMIN_NAME_ENV = "AUTH_ADMIN_NAME"
SKIP_SAMPLE_APP_ENV = "AUTH_SKIP_SAMPLE_APP"
SAMPLE_APP_NAME_ENV = "AUTH_SAMPLE_APP_NAME"
SAMPLE_APP_REDIRECT_URI_ENV = "AUTH_SAMPLE_APP_REDIRECT_URI"

DEFAULT_ADMIN_NAME = "Auth Service Admin"
DEFAULT_SAMPLE_APP_NAME = "Example Application"
DEFAULT_SAMPLE_APP_REDIRECT_URI = "http://localhost:3000/auth/callback"


@dataclass(frozen=True)
class InitConfig:
    admin_email: str
    admin_name: str
    skip_sample_app: bool
    sample_app_name: str
    sample_app_redirect_uri: str
    admin_password: str | None = field(default=None, repr=False)


def _parse_boolean(value: str | None, *, variable_name: str) -> bool:
    if value is None:
        return False
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    raise ValueError(f"环境变量 {variable_name} 必须是 true/false、1/0、yes/no 或 on/off")


def _validate_email(value: str | None) -> str:
    if not value or not value.strip():
        raise ValueError(f"必须通过 --admin-email 或环境变量 {ADMIN_EMAIL_ENV} 提供管理员邮箱")
    try:
        return normalize_email(value)
    except ValueError:
        raise ValueError("管理员邮箱格式无效") from None


def _validate_password(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) < 12:
        raise ValueError("管理员密码至少 12 个字符")
    if len(value) > 128:
        raise ValueError("管理员密码不能超过 128 个字符")
    requirements = (
        (any(char.islower() for char in value), "小写字母"),
        (any(char.isupper() for char in value), "大写字母"),
        (any(char.isdigit() for char in value), "数字"),
        (any(not char.isalnum() for char in value), "特殊字符"),
    )
    missing = [label for satisfied, label in requirements if not satisfied]
    if missing:
        raise ValueError(f"管理员密码必须包含{'、'.join(missing)}")
    return value


def _validate_name(value: str, *, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name}不能为空")
    if len(normalized) > 100:
        raise ValueError(f"{field_name}不能超过 100 个字符")
    return normalized


def _validate_redirect_uri(value: str) -> str:
    normalized = value.strip()
    parsed = urlsplit(normalized)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("示例应用回调地址必须是无凭据、无片段的 HTTP(S) 绝对地址")
    return normalized


def build_config(arguments: Sequence[str], environ: Mapping[str, str]) -> InitConfig:
    """按“CLI 优先于环境变量”的顺序构建并校验初始化配置。"""

    parser = argparse.ArgumentParser(description="初始化 auth-service 管理员和可选示例应用")
    parser.add_argument("--admin-email", default=environ.get(ADMIN_EMAIL_ENV), help=f"管理员邮箱（或 {ADMIN_EMAIL_ENV}）")
    parser.add_argument(
        "--admin-password",
        default=environ.get(ADMIN_PASSWORD_ENV),
        help=f"管理员密码（或 {ADMIN_PASSWORD_ENV}；推荐使用环境变量，避免出现在进程列表中）",
    )
    parser.add_argument("--admin-name", default=environ.get(ADMIN_NAME_ENV, DEFAULT_ADMIN_NAME), help="管理员显示名称")
    parser.add_argument(
        "--skip-sample-app",
        action="store_true",
        default=_parse_boolean(environ.get(SKIP_SAMPLE_APP_ENV), variable_name=SKIP_SAMPLE_APP_ENV),
        help=f"跳过示例应用注册（或设置 {SKIP_SAMPLE_APP_ENV}=true）",
    )
    parser.add_argument(
        "--sample-app-name",
        default=environ.get(SAMPLE_APP_NAME_ENV, DEFAULT_SAMPLE_APP_NAME),
        help="示例应用名称",
    )
    parser.add_argument(
        "--sample-app-redirect-uri",
        default=environ.get(SAMPLE_APP_REDIRECT_URI_ENV, DEFAULT_SAMPLE_APP_REDIRECT_URI),
        help="示例应用回调地址",
    )
    parsed = parser.parse_args(arguments)

    return InitConfig(
        admin_email=_validate_email(parsed.admin_email),
        admin_password=_validate_password(parsed.admin_password),
        admin_name=_validate_name(parsed.admin_name, field_name="管理员名称"),
        skip_sample_app=parsed.skip_sample_app,
        sample_app_name=_validate_name(parsed.sample_app_name, field_name="示例应用名称"),
        sample_app_redirect_uri=_validate_redirect_uri(parsed.sample_app_redirect_uri),
    )


async def init(config: InitConfig):
    """根据显式配置幂等创建管理员和可选示例应用。"""

    async with async_session() as db:
        result = await db.execute(
            select(User).where(func.lower(func.btrim(User.email)) == config.admin_email)
        )
        admin = result.scalar_one_or_none()

        if admin is not None and config.admin_password is not None:
            raise ValueError(
                "管理员已存在，初始化脚本拒绝覆盖其密码；请省略密码或使用专门的密码轮换流程"
            )

        if not admin:
            admin = User(
                email=config.admin_email,
                name=config.admin_name,
                password_hash=(hash_password(config.admin_password) if config.admin_password else None),
                is_superuser=True,
            )
            db.add(admin)
            print(f"✅ 管理员已创建：{config.admin_email}")
        elif not admin.is_superuser:
            admin.is_superuser = True
            print(f"✅ 现有身份已提升为管理员：{config.admin_email}")
        else:
            print(f"ℹ️  管理员已存在：{config.admin_email}")

        if not config.skip_sample_app:
            result = await db.execute(
                select(Application).where(Application.name == config.sample_app_name).limit(2)
            )
            applications = list(result.scalars())
            if len(applications) > 1:
                raise ValueError(
                    f"存在多个同名应用“{config.sample_app_name}”，请改用唯一名称或先人工整理"
                )
            application = applications[0] if applications else None

            if not application:
                client_id = f"app_{secrets.token_hex(16)}"
                client_secret = secrets.token_urlsafe(48)
                application = Application(
                    name=config.sample_app_name,
                    description="Example client application",
                    client_id=client_id,
                    client_secret=client_secret,
                    redirect_uris=[config.sample_app_redirect_uri],
                )
                db.add(application)
                print(f"✅ 示例应用“{config.sample_app_name}”已注册：")
                print(f"   client_id:     {client_id}")
                print(f"   client_secret: {client_secret}")
                print("   ⚠️  请立即保存 client_secret，后续不会再次显示。")
            else:
                print(f"ℹ️  示例应用“{config.sample_app_name}”已存在（client_id: {application.client_id}）")
        else:
            print("ℹ️  已按配置跳过示例应用注册")

        await db.commit()

    print()
    print("🚀 初始化完成！")
    print(f"   API 文档：http://localhost:{settings.app_port}/docs")


def main(arguments: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    args = sys.argv[1:] if arguments is None else arguments
    env = os.environ if environ is None else environ
    try:
        config = build_config(args, env)
        asyncio.run(init(config))
    except ValueError as exc:
        print(f"❌ 初始化配置无效：{exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
