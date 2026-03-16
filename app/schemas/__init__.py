import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr


# ==================== Auth ====================

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    client_id: str | None = None  # which app is the user logging into


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class RefreshRequest(BaseModel):
    refresh_token: str


class RevokeRequest(BaseModel):
    refresh_token: str


class OAuthCallbackParams(BaseModel):
    code: str
    state: str | None = None


class OAuthTokenExchangeRequest(BaseModel):
    code: str
    client_id: str


# ==================== User ====================

class UserPreferencesResponse(BaseModel):
    locale: str = "zh"
    timezone: str = "Asia/Shanghai"
    theme: str = "system"


class UserInfo(BaseModel):
    id: uuid.UUID
    email: str
    name: str | None
    avatar_url: str | None
    is_superuser: bool = False
    is_active: bool
    created_at: datetime
    preferences: UserPreferencesResponse = UserPreferencesResponse()

    model_config = {"from_attributes": True}


class UserInfoWithProviders(UserInfo):
    providers: list[str] = []  # ["google", "github"]


class ProfileUpdateRequest(BaseModel):
    name: str | None = None
    avatar_url: str | None = None
    locale: str | None = None
    timezone: str | None = None
    theme: str | None = None


# ==================== Application ====================

class AppCreateRequest(BaseModel):
    name: str
    description: str | None = None
    redirect_uris: list[str] = []


class AppResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    client_id: str
    redirect_uris: list[str]
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class AppCreateResponse(AppResponse):
    client_secret: str  # only shown once at creation


# ==================== Login Log ====================

class LoginLogResponse(BaseModel):
    id: uuid.UUID
    user_email: str | None = None
    app_name: str | None = None
    login_method: str
    ip_address: str | None
    user_agent: str | None
    success: bool
    failure_reason: str | None
    logged_at: datetime


# ==================== Common ====================

class MessageResponse(BaseModel):
    message: str


class PaginatedResponse(BaseModel):
    items: list
    total: int
    page: int
    page_size: int
