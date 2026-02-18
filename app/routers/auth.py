from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas import (
    LoginRequest,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    RevokeRequest,
    TokenResponse,
    UserInfo,
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
    user = await auth_service.register_user(payload, db)
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


@router.get("/userinfo", response_model=UserInfo)
async def get_userinfo(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current user info from the access token."""
    from sqlalchemy import select
    from app.models import User

    result = await db.execute(select(User).where(User.id == user.sub))
    db_user = result.scalar_one_or_none()
    if not db_user:
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return db_user
