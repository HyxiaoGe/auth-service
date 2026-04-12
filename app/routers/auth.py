from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import User, UserPreference
from app.schemas import (
    LoginRequest,
    MessageResponse,
    ProfileUpdateRequest,
    RefreshRequest,
    RegisterRequest,
    RevokeRequest,
    TokenResponse,
    UserInfo,
    UserPreferencesResponse,
)
from app.security.deps import CurrentUser, get_current_user
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(
    payload: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Register a new user with email and password."""
    await auth_service.register_user(payload, db)
    # Auto-login after registration
    login_payload = LoginRequest(email=payload.email, password=payload.password)
    return await auth_service.login_user(login_payload, request, db)


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Login with email and password. Optionally pass client_id to identify the app."""
    return await auth_service.login_user(payload, request, db)


@router.post("/token/refresh", response_model=TokenResponse)
async def refresh_token(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """Exchange a refresh token for a new token pair (rotation enabled)."""
    return await auth_service.refresh_access_token(payload.refresh_token, db)


@router.post("/token/revoke", response_model=MessageResponse)
async def revoke_token(
    payload: RevokeRequest,
    db: AsyncSession = Depends(get_db),
):
    """Revoke a refresh token (logout)."""
    await auth_service.revoke_refresh_token(payload.refresh_token, db)
    return MessageResponse(message="Token revoked successfully")


def _build_preferences(pref: UserPreference | None) -> UserPreferencesResponse:
    if pref is None:
        return UserPreferencesResponse()
    return UserPreferencesResponse(
        locale=pref.locale,
        timezone=pref.timezone,
        theme=pref.theme,
    )


@router.get("/userinfo", response_model=UserInfo)
async def get_userinfo(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current user info from the access token."""
    from sqlalchemy.orm import selectinload

    result = await db.execute(select(User).options(selectinload(User.preferences)).where(User.id == user.sub))
    db_user = result.scalar_one_or_none()
    if not db_user:
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return UserInfo(
        id=db_user.id,
        email=db_user.email,
        name=db_user.name,
        avatar_url=db_user.avatar_url,
        is_superuser=db_user.is_superuser,
        is_active=db_user.is_active,
        created_at=db_user.created_at,
        preferences=_build_preferences(db_user.preferences),
    )


@router.patch("/profile", response_model=UserInfo)
async def update_profile(
    payload: ProfileUpdateRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update current user's profile and preferences."""
    from sqlalchemy.orm import selectinload

    result = await db.execute(select(User).options(selectinload(User.preferences)).where(User.id == user.sub))
    db_user = result.scalar_one_or_none()
    if not db_user:
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Update profile fields
    if payload.name is not None:
        db_user.name = payload.name
    if payload.avatar_url is not None:
        db_user.avatar_url = payload.avatar_url

    # Update preferences
    has_pref_update = any(v is not None for v in [payload.locale, payload.timezone, payload.theme])
    if has_pref_update:
        pref = db_user.preferences
        if pref is None:
            pref = UserPreference(user_id=db_user.id)
            db.add(pref)
            db_user.preferences = pref
        if payload.locale is not None:
            pref.locale = payload.locale
        if payload.timezone is not None:
            pref.timezone = payload.timezone
        if payload.theme is not None:
            pref.theme = payload.theme

    await db.commit()
    await db.refresh(db_user)
    # Re-load preferences after commit
    result = await db.execute(select(User).options(selectinload(User.preferences)).where(User.id == db_user.id))
    db_user = result.scalar_one_or_none()

    return UserInfo(
        id=db_user.id,
        email=db_user.email,
        name=db_user.name,
        avatar_url=db_user.avatar_url,
        is_superuser=db_user.is_superuser,
        is_active=db_user.is_active,
        created_at=db_user.created_at,
        preferences=_build_preferences(db_user.preferences),
    )
