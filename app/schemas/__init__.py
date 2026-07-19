import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator


class _AsciiLocalEmailModel(BaseModel):
    """身份请求不允许需要 SMTPUTF8 的本地部分进入业务层。"""

    @field_validator("email", check_fields=False)
    @classmethod
    def require_ascii_local_part(cls, value: EmailStr) -> EmailStr:
        local_part = str(value).rpartition("@")[0]
        if not local_part.isascii():
            raise ValueError("email must use an ASCII local part") from None
        return value

# ==================== Auth ====================


class RegisterRequest(_AsciiLocalEmailModel):
    email: EmailStr
    password: str
    name: str | None = None


class LoginRequest(_AsciiLocalEmailModel):
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


class LogoutRequest(BaseModel):
    # Both optional: logout is driven by the session cookie. A post_logout_redirect_uri
    # is honored only when it belongs to a registered application.
    post_logout_redirect_uri: str | None = None
    client_id: str | None = None


class OAuthCallbackParams(BaseModel):
    code: str
    state: str | None = None


class OAuthTokenExchangeRequest(BaseModel):
    code: str
    client_id: str
    # PKCE (RFC 7636): required only when the auth code was minted with a code_challenge
    # (i.e. came through /authorize). Legacy direct-flow codes omit it.
    code_verifier: str | None = None


class EmailHeadlessStartRequest(BaseModel):
    client_id: str = Field(min_length=1, max_length=255)
    redirect_uri: str = Field(min_length=1, max_length=2048)
    response_type: str = Field(min_length=1, max_length=32)
    state: str = Field(max_length=2048)
    code_challenge: str = Field(max_length=256)
    code_challenge_method: str = Field(min_length=1, max_length=16)


class EmailHeadlessSendRequest(_AsciiLocalEmailModel):
    flow_id: str = Field(min_length=16, max_length=128)
    email: EmailStr


class EmailHeadlessVerifyRequest(BaseModel):
    flow_id: str = Field(min_length=16, max_length=128)
    code: str = Field(pattern=r"^[0-9]{6}$")


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
