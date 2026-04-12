from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas import AppCreateRequest, AppCreateResponse, AppResponse, LoginLogResponse
from app.security.deps import CurrentUser, get_current_superuser
from app.services import auth_service

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.post("/apps", response_model=AppCreateResponse, status_code=201)
async def create_app(
    payload: AppCreateRequest,
    _: CurrentUser = Depends(get_current_superuser),
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new client application.
    Returns client_id and client_secret (secret is only shown once).
    """
    return await auth_service.create_application(payload, db)


@router.get("/apps", response_model=list[AppResponse])
async def list_apps(
    _: CurrentUser = Depends(get_current_superuser),
    db: AsyncSession = Depends(get_db),
):
    """List all registered applications."""
    return await auth_service.list_applications(db)


@router.get("/login-logs", response_model=list[LoginLogResponse])
async def get_login_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user_id: str | None = Query(None),
    app_id: str | None = Query(None),
    _: CurrentUser = Depends(get_current_superuser),
    db: AsyncSession = Depends(get_db),
):
    """View login audit logs. Filterable by user_id and app_id."""
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models import LoginLog

    query = (
        select(LoginLog)
        .options(selectinload(LoginLog.user), selectinload(LoginLog.application))
        .order_by(LoginLog.logged_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )

    if user_id:
        query = query.where(LoginLog.user_id == user_id)
    if app_id:
        query = query.where(LoginLog.app_id == app_id)

    result = await db.execute(query)
    logs = result.scalars().all()

    return [
        LoginLogResponse(
            id=log.id,
            user_email=log.user.email if log.user else None,
            app_name=log.application.name if log.application else None,
            login_method=log.login_method,
            ip_address=log.ip_address,
            user_agent=log.user_agent,
            success=log.success,
            failure_reason=log.failure_reason,
            logged_at=log.logged_at,
        )
        for log in logs
    ]
