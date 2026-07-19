"""受控内部账密兼容端点。

该路由默认不会注册到 FastAPI 应用；即使显式启用也不会进入 OpenAPI，且每次请求都必须
通过专用内部令牌校验。账密 schema、服务与哈希实现继续保留，供现有内部任务兼容与回滚。
"""

import json
from secrets import compare_digest

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas import LoginRequest, RegisterRequest, TokenResponse
from app.services import auth_service

INTERNAL_AUTH_HEADER = "X-Fusion-Internal-Auth"
MAX_PASSWORD_AUTH_BODY_BYTES = 16 * 1024


def _not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


async def _read_limited_body(request: Request) -> bytes:
    """在复制请求体到应用内存前限制内部账密请求大小。"""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared_size = int(content_length)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Content-Length") from None
        if declared_size > MAX_PASSWORD_AUTH_BODY_BYTES:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Request body too large")

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_PASSWORD_AUTH_BODY_BYTES:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Request body too large")
        body.extend(chunk)
    return bytes(body)


async def _parse_json_body[RequestModel: BaseModel](request: Request, model: type[RequestModel]) -> RequestModel:
    """在内部鉴权通过后，按 FastAPI 常规语义解析并校验 JSON 请求体。"""
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
    if media_type != "application/json" and not media_type.endswith("+json"):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="JSON body required")

    body = await _read_limited_body(request)
    if not body:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Request body required")
    try:
        data = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid JSON body") from None

    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc


def create_router(internal_token: str, email_prefix: str, email_domain: str) -> APIRouter:
    """创建绑定指定内部令牌、且不出现在 OpenAPI 中的账密路由。"""
    if internal_token != internal_token.strip():
        raise ValueError("internal_token must not contain leading or trailing whitespace")
    if len(internal_token) < 32:
        raise ValueError("internal_token must contain at least 32 characters")
    email_prefix = email_prefix.strip()
    email_domain = email_domain.strip().casefold()
    if not email_prefix or not email_domain or "@" in email_prefix or "@" in email_domain:
        raise ValueError("email_prefix and email_domain must define a valid restricted scope")
    expected_token = internal_token.encode("utf-8")

    async def require_internal_auth(request: Request) -> None:
        provided_token = request.headers.get(INTERNAL_AUTH_HEADER, "").encode("utf-8")
        if not compare_digest(provided_token, expected_token):
            raise _not_found()

    def require_scoped_email(email: str) -> None:
        local_part, separator, domain = email.rpartition("@")
        if not separator or not local_part.startswith(email_prefix) or domain.casefold() != email_domain:
            raise _not_found()

    router = APIRouter(
        prefix="/auth",
        tags=["Authentication"],
        include_in_schema=False,
        dependencies=[Depends(require_internal_auth)],
    )

    @router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
    async def register(
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        """供受控内部任务注册账号并自动登录。"""
        payload = await _parse_json_body(request, RegisterRequest)
        require_scoped_email(str(payload.email))
        await auth_service.register_user(payload, db)
        login_payload = LoginRequest(email=payload.email, password=payload.password)
        return await auth_service.login_user(login_payload, request, db)

    @router.post("/login", response_model=TokenResponse)
    async def login(
        request: Request,
        db: AsyncSession = Depends(get_db),
    ):
        """供受控内部任务使用邮箱密码换取令牌。"""
        payload = await _parse_json_body(request, LoginRequest)
        require_scoped_email(str(payload.email))
        return await auth_service.login_user(payload, request, db)

    return router
