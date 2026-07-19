import logging
import secrets
import uuid
from datetime import UTC, datetime

from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
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
from app.security.revocation import get_user_revoked_at
from app.services.identity_service import find_user_by_email
from app.utils.email import normalize_email
from app.utils.redirect_uri import oauth_redirect_uri_allowed

settings = get_settings()

logger = logging.getLogger(__name__)


# ==================== Registration ====================


async def register_user(payload: RegisterRequest, db: AsyncSession) -> User:
    """Register a new user with email and password."""
    normalized = normalize_email(str(payload.email))
    # Check existing
    if await find_user_by_email(normalized, db):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user = User(
        email=normalized,
        name=payload.name or normalized.split("@")[0],
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
    user = await find_user_by_email(normalize_email(str(payload.email)), db)

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
    email: str | None,
    name: str | None,
    avatar_url: str | None,
    db: AsyncSession,
    email_verified: bool = False,
) -> User:
    """优先信任已绑定 provider_id；首次绑定只接受已验证邮箱并处理唯一约束竞态。"""
    social = await _find_social_identity(provider, provider_id, db)
    if social is not None:
        if not social.user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")
        return social.user

    if not email or not email_verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Provider email is not verified")

    try:
        normalized = normalize_email(email)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provider email is not verified",
        ) from None
    last_error: IntegrityError | None = None
    for attempt in range(2):
        user = await find_user_by_email(normalized, db)
        is_new_user = user is None
        if user is not None and not user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")
        if user is None:
            user = User(
                id=uuid.uuid4(),
                email=normalized,
                name=name or normalized.split("@", 1)[0],
                avatar_url=avatar_url,
                password_hash=None,
                is_active=True,
                is_superuser=False,
            )

        user_id = user.id
        linked = await _find_user_provider_identity(user_id, provider, db)
        if linked is not None:
            if linked.provider_id == provider_id:
                return user
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A different provider account is already linked",
            )

        social = SocialAccount(
            user_id=user_id,
            provider=provider,
            provider_id=provider_id,
            provider_email=normalized,
            provider_name=name,
            provider_avatar=avatar_url,
        )
        if is_new_user:
            db.add(user)
        db.add(social)
        try:
            await db.commit()
        except IntegrityError as error:
            last_error = error
            await db.rollback()
            winner = await _find_social_identity(provider, provider_id, db)
            if winner is not None:
                if not winner.user.is_active:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Account is disabled",
                    ) from error
                return winner.user
            if attempt == 0:
                continue
            break

        await db.refresh(user)
        return user

    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Social account link conflict",
    ) from last_error


async def _find_social_identity(provider: str, provider_id: str, db: AsyncSession) -> SocialAccount | None:
    result = await db.execute(
        select(SocialAccount)
        .options(selectinload(SocialAccount.user))
        .where(SocialAccount.provider == provider, SocialAccount.provider_id == provider_id)
    )
    return result.scalar_one_or_none()


async def _find_user_provider_identity(
    user_id: uuid.UUID,
    provider: str,
    db: AsyncSession,
) -> SocialAccount | None:
    result = await db.execute(
        select(SocialAccount).where(SocialAccount.user_id == user_id, SocialAccount.provider == provider)
    )
    return result.scalar_one_or_none()


# ==================== Token Operations ====================


async def refresh_access_token(refresh_token_str: str, db: AsyncSession) -> TokenResponse:
    """Use a refresh token to get a new access token (with rotation)."""
    # Decode
    try:
        decode_token(refresh_token_str, verify_type="refresh")
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from err

    # Check DB. FOR UPDATE locks the row so a concurrent replay of the same token serializes
    # behind us -- the grace window below can then be consumed at most once (selectinload runs
    # a separate, unlocked query for the user, so no "FOR UPDATE on outer join" problem).
    token_hash = hash_token(refresh_token_str)
    result = await db.execute(
        select(RefreshToken)
        .options(selectinload(RefreshToken.user))
        .where(RefreshToken.token_hash == token_hash)
        .with_for_update()
    )
    stored = result.scalar_one_or_none()

    # Unknown/forged token (hash not in DB): hard 401, no grace, no revoke-all.
    if not stored:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked or invalid")

    if stored.is_revoked:
        # Rotation grace (RFC 9700 §4.14.2 MAY): when a rotation RESPONSE is lost over a flaky
        # tunnel the client still holds the old token and replays it -- a network retry, not a
        # reuse attack. Re-issue the successor ONCE for such a token, but only if it was killed
        # by a normal rotation, inside the narrow grace window, not already consumed, the account
        # is active, and no later SLO logout has invalidated the chain. Everything else
        # (super-window, already-consumed, /logout-revoked, real theft) is treated as reuse and
        # revokes the user's tokens -- but ONLY for the offending app (stored.app_client_id).
        # Other first-party apps hold independent rotation lineages; nuking them too turns one
        # app's lost-rotation replay into a cross-app spurious logout (observed live: an audio
        # replay collaterally revoked the same user's valid fusion token). A deliberate
        # account-wide logout still sweeps every app via the /logout path (app_client_id=None).
        if _within_rotation_grace(stored) and not await _logout_after_rotation(stored):
            stored.grace_consumed = True  # single-use gate (atomic under the row lock above)
            return await _issue_tokens(stored.user, stored.app_client_id, db)
        await _revoke_all_user_tokens(stored.user_id, db, app_client_id=stored.app_client_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked or invalid")

    user = stored.user
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    # Rotate: revoke old (tagged rotated_at so a lost-response replay can be graced), issue new
    now = datetime.now(UTC)
    stored.is_revoked = True
    stored.revoked_at = now
    stored.rotated_at = now

    tokens = await _issue_tokens(user, stored.app_client_id, db)
    return tokens


def _within_rotation_grace(stored: RefreshToken) -> bool:
    """True iff this revoked token looks like a lost-response retry eligible for a one-time
    re-issue: revoked by a normal rotation (``rotated_at`` set), inside the grace window, not yet
    consumed, and the account still active. Everything else is treated as reuse. ``grace`` <= 0
    disables the window entirely (rollback switch)."""
    if stored.rotated_at is None or stored.grace_consumed or not stored.user.is_active:
        return False
    if settings.refresh_reuse_grace_seconds <= 0:
        return False
    age = (datetime.now(UTC) - stored.rotated_at).total_seconds()
    return 0 <= age <= settings.refresh_reuse_grace_seconds


async def _logout_after_rotation(stored: RefreshToken) -> bool:
    """True iff an SLO logout marker exists at/after this token's rotation instant, meaning a
    fresh successor would silently bypass that logout. Fails open (no logout) on Redis trouble,
    matching the resource-server denylist philosophy -- the narrow grace window bounds exposure."""
    if stored.rotated_at is None:
        return False
    try:
        marker = await get_user_revoked_at(str(stored.user_id))
    except Exception:
        logger.warning("rotation-grace logout-marker check unavailable (Redis); failing open", exc_info=True)
        return False
    return marker is not None and marker >= stored.rotated_at.timestamp()


async def revoke_refresh_token(refresh_token_str: str, db: AsyncSession):
    """Revoke a specific refresh token."""
    token_hash = hash_token(refresh_token_str)
    result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    stored = result.scalar_one_or_none()

    if stored and not stored.is_revoked:
        stored.is_revoked = True
        stored.revoked_at = datetime.now(UTC)
        await db.commit()


# ==================== Application Management ====================


async def create_application(payload: AppCreateRequest, db: AsyncSession) -> AppCreateResponse:
    """Register a new client application."""
    if any(not oauth_redirect_uri_allowed(uri) for uri in payload.redirect_uris):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="redirect_uri must use HTTPS, app://-, or loopback HTTP",
        )
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


async def _revoke_all_user_tokens(user_id: uuid.UUID, db: AsyncSession, app_client_id: str | None = None):
    """Revoke a user's active refresh tokens (security measure).

    ``app_client_id`` scopes the blast radius. A reuse-detected token only compromises the
    rotation lineage of the app it was issued for; other first-party apps hold independent
    lineages and must NOT be collateral-revoked, or a lost-rotation replay in one app silently
    logs the user out of every other app (the cross-app spurious logout). Reuse detection passes
    the offending token's ``app_client_id`` to scope revocation to that app. ``None`` keeps the
    original account-wide sweep for deliberate "logout everywhere" / account-disable flows.
    """
    conditions = [RefreshToken.user_id == user_id, RefreshToken.is_revoked.is_(False)]
    if app_client_id is not None:
        conditions.append(RefreshToken.app_client_id == app_client_id)
    result = await db.execute(select(RefreshToken).where(*conditions))
    for token in result.scalars():
        token.is_revoked = True
        token.revoked_at = datetime.now(UTC)
    await db.commit()
