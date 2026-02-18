import secrets
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.models import Application, LoginLog, RefreshToken, SocialAccount, User
from app.schemas import (
    AppCreateRequest,
    AppCreateResponse,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
)
from app.security.jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_token,
)
from app.security.password import hash_password, verify_password

settings = get_settings()


# ==================== Registration ====================


async def register_user(payload: RegisterRequest, db: AsyncSession) -> User:
    """Register a new user with email and password."""
    # Check existing
    result = await db.execute(select(User).where(User.email == payload.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user = User(
        email=payload.email,
        name=payload.name or payload.email.split("@")[0],
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


# ==================== Login ====================


async def login_user(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession,
) -> TokenResponse:
    """Authenticate with email/password and issue tokens."""
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not user.password_hash or not verify_password(payload.password, user.password_hash):
        # Log failed attempt
        await _log_login(db, None, payload.client_id, "password", request, success=False, reason="Invalid credentials")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    tokens = await _issue_tokens(user, payload.client_id, db)
    await _log_login(db, user.id, payload.client_id, "password", request, success=True)
    return tokens


# ==================== Social Login ====================


async def social_login(
    provider: str,
    provider_id: str,
    email: str,
    name: str | None,
    avatar_url: str | None,
    client_id: str | None,
    request: Request,
    db: AsyncSession,
) -> TokenResponse:
    """Handle social OAuth login - find or create user, link social account."""
    # 1. Check if social account already linked
    result = await db.execute(
        select(SocialAccount)
        .options(selectinload(SocialAccount.user))
        .where(SocialAccount.provider == provider, SocialAccount.provider_id == provider_id)
    )
    social = result.scalar_one_or_none()

    if social:
        user = social.user
    else:
        # 2. Check if user exists by email
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

        if not user:
            # 3. Create new user
            user = User(email=email, name=name, avatar_url=avatar_url)
            db.add(user)
            await db.flush()

        # 4. Link social account
        social = SocialAccount(
            user_id=user.id,
            provider=provider,
            provider_id=provider_id,
            provider_email=email,
            provider_name=name,
            provider_avatar=avatar_url,
        )
        db.add(social)

    await db.commit()
    await db.refresh(user)

    tokens = await _issue_tokens(user, client_id, db)
    await _log_login(db, user.id, client_id, provider, request, success=True)
    return tokens


# ==================== Token Operations ====================


async def refresh_access_token(refresh_token_str: str, db: AsyncSession) -> TokenResponse:
    """Use a refresh token to get a new access token (with rotation)."""
    # Decode
    try:
        payload = decode_token(refresh_token_str, verify_type="refresh")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # Check DB
    token_hash = hash_token(refresh_token_str)
    result = await db.execute(
        select(RefreshToken)
        .options(selectinload(RefreshToken.user))
        .where(RefreshToken.token_hash == token_hash)
    )
    stored = result.scalar_one_or_none()

    if not stored or stored.is_revoked:
        # Potential token reuse attack - revoke all tokens for this user
        if stored:
            await _revoke_all_user_tokens(stored.user_id, db)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked or invalid")

    user = stored.user
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    # Rotate: revoke old, issue new
    stored.is_revoked = True
    stored.revoked_at = datetime.now(timezone.utc)

    tokens = await _issue_tokens(user, stored.app_client_id, db)
    return tokens


async def revoke_refresh_token(refresh_token_str: str, db: AsyncSession):
    """Revoke a specific refresh token."""
    token_hash = hash_token(refresh_token_str)
    result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    stored = result.scalar_one_or_none()

    if stored and not stored.is_revoked:
        stored.is_revoked = True
        stored.revoked_at = datetime.now(timezone.utc)
        await db.commit()


# ==================== Application Management ====================


async def create_application(payload: AppCreateRequest, db: AsyncSession) -> AppCreateResponse:
    """Register a new client application."""
    client_id = f"app_{secrets.token_hex(16)}"
    client_secret = secrets.token_urlsafe(48)

    app = Application(
        name=payload.name,
        description=payload.description,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uris=payload.redirect_uris,
    )
    db.add(app)
    await db.commit()
    await db.refresh(app)

    return AppCreateResponse(
        id=app.id,
        name=app.name,
        description=app.description,
        client_id=app.client_id,
        client_secret=client_secret,  # only shown once
        redirect_uris=app.redirect_uris,
        is_active=app.is_active,
        created_at=app.created_at,
    )


async def list_applications(db: AsyncSession) -> list[Application]:
    result = await db.execute(select(Application).order_by(Application.created_at.desc()))
    return list(result.scalars().all())


# ==================== Login Logs ====================


async def get_login_logs(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 50,
    user_id: str | None = None,
    app_id: str | None = None,
) -> tuple[list[LoginLog], int]:
    query = select(LoginLog).order_by(LoginLog.logged_at.desc())
    count_query = select(LoginLog)

    if user_id:
        query = query.where(LoginLog.user_id == user_id)
        count_query = count_query.where(LoginLog.user_id == user_id)
    if app_id:
        query = query.where(LoginLog.app_id == app_id)
        count_query = count_query.where(LoginLog.app_id == app_id)

    # Pagination
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    logs = list(result.scalars().all())

    from sqlalchemy import func

    count_result = await db.execute(select(func.count()).select_from(count_query.subquery()))
    total = count_result.scalar() or 0

    return logs, total


# ==================== Internal Helpers ====================


async def _issue_tokens(user: User, app_client_id: str | None, db: AsyncSession) -> TokenResponse:
    """Issue a pair of access + refresh tokens for a user."""
    scopes = ["admin"] if user.is_superuser else ["user"]

    access_token = create_access_token(
        user_id=str(user.id),
        email=user.email,
        app_client_id=app_client_id,
        scopes=scopes,
    )
    refresh_token_str, token_hash, expires_at = create_refresh_token(
        user_id=str(user.id),
        app_client_id=app_client_id,
    )

    # Store refresh token in DB
    stored_token = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        app_client_id=app_client_id,
        expires_at=expires_at,
    )
    db.add(stored_token)
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token_str,
        expires_in=settings.access_token_expire_minutes * 60,
    )


async def _log_login(
    db: AsyncSession,
    user_id: uuid.UUID | None,
    app_client_id: str | None,
    method: str,
    request: Request,
    success: bool = True,
    reason: str | None = None,
):
    """Record a login event."""
    # Resolve app_id from client_id
    app_id = None
    if app_client_id:
        result = await db.execute(select(Application.id).where(Application.client_id == app_client_id))
        app_id = result.scalar_one_or_none()

    if user_id:
        log = LoginLog(
            user_id=user_id,
            app_id=app_id,
            login_method=method,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent", "")[:500],
            success=success,
            failure_reason=reason,
        )
        db.add(log)
        await db.commit()


async def _revoke_all_user_tokens(user_id: uuid.UUID, db: AsyncSession):
    """Revoke all refresh tokens for a user (security measure)."""
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.user_id == user_id, RefreshToken.is_revoked == False)
    )
    for token in result.scalars():
        token.is_revoked = True
        token.revoked_at = datetime.now(timezone.utc)
    await db.commit()
