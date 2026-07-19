"""OTP 与 OAuth 共用的邮箱身份解析和竞态安全建号。"""

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User
from app.utils.email import normalize_email, normalized_email_expression


class InactiveIdentityError(Exception):
    """规范化邮箱已经属于禁用用户。"""


async def find_user_by_email(email: str, db: AsyncSession) -> User | None:
    """按统一规范化规则查找用户；唯一约束异常时安全失败。"""
    normalized = normalize_email(email)
    result = await db.execute(
        select(User).where(normalized_email_expression(User.email) == normalized).limit(2)
    )
    users = list(result.scalars().all())
    if len(users) > 1:
        raise RuntimeError("normalized email is not unique")
    return users[0] if users else None


async def find_active_user_by_id(user_id: str, db: AsyncSession) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id, User.is_active.is_(True)).limit(2))
    users = list(result.scalars().all())
    return users[0] if len(users) == 1 and users[0].is_active else None


async def get_or_create_active_user(
    email: str,
    *,
    name: str | None,
    avatar_url: str | None,
    db: AsyncSession,
) -> User:
    """复用规范化邮箱用户，或创建无密码用户；唯一冲突时读取竞态胜者。"""
    normalized = normalize_email(email)
    existing = await find_user_by_email(normalized, db)
    if existing is not None:
        if not existing.is_active:
            raise InactiveIdentityError
        return existing

    user = User(
        email=normalized,
        name=name or normalized.split("@", 1)[0],
        avatar_url=avatar_url,
        password_hash=None,
        is_active=True,
        is_superuser=False,
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        winner = await find_user_by_email(normalized, db)
        if winner is None:
            raise
        if not winner.is_active:
            raise InactiveIdentityError from None
        return winner

    await db.refresh(user)
    return user
