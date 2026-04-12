import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str | None] = mapped_column(String(100))
    avatar_url: Mapped[str | None] = mapped_column(String(500))
    password_hash: Mapped[str | None] = mapped_column(String(255))  # nullable for social-only users
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    social_accounts: Mapped[list["SocialAccount"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    login_logs: Mapped[list["LoginLog"]] = relationship(back_populates="user")
    preferences: Mapped["UserPreference | None"] = relationship(
        back_populates="user", cascade="all, delete-orphan", uselist=False
    )


class Application(Base):
    """Registered client applications that use this auth service."""

    __tablename__ = "applications"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100))  # e.g. "MovieMate", "Prism"
    description: Mapped[str | None] = mapped_column(Text)
    client_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    client_secret: Mapped[str] = mapped_column(String(128))
    redirect_uris: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    login_logs: Mapped[list["LoginLog"]] = relationship(back_populates="application")


class SocialAccount(Base):
    """Third-party OAuth accounts linked to users."""

    __tablename__ = "social_accounts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(20))  # google / github
    provider_id: Mapped[str] = mapped_column(String(255))  # ID from the provider
    provider_email: Mapped[str | None] = mapped_column(String(255))
    provider_name: Mapped[str | None] = mapped_column(String(100))
    provider_avatar: Mapped[str | None] = mapped_column(String(500))
    access_token: Mapped[str | None] = mapped_column(Text)  # encrypted provider token (optional)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    user: Mapped["User"] = relationship(back_populates="social_accounts")

    # Unique constraint: one provider account per user, one provider_id per provider
    __table_args__ = (
        # A user can only link one account per provider
        # A provider account can only be linked to one user
        {"comment": "unique(provider, provider_id) enforced via unique index"},
    )


class RefreshToken(Base):
    """Stored refresh tokens for revocation support."""

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # SHA256 of the token
    app_client_id: Mapped[str | None] = mapped_column(String(64))  # which app issued this
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Relationships
    user: Mapped["User"] = relationship(back_populates="refresh_tokens")


class LoginLog(Base):
    """Audit log of all login events across all applications."""

    __tablename__ = "login_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    app_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("applications.id"), index=True)
    login_method: Mapped[str] = mapped_column(String(20))  # password / google / github
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(500))
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    failure_reason: Mapped[str | None] = mapped_column(String(255))
    logged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    user: Mapped["User"] = relationship(back_populates="login_logs")
    application: Mapped["Application | None"] = relationship(back_populates="login_logs")


class UserPreference(Base):
    """User preferences shared across all applications."""

    __tablename__ = "user_preferences"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True)
    locale: Mapped[str] = mapped_column(String(10), default="zh", server_default="zh")
    timezone: Mapped[str] = mapped_column(String(50), default="Asia/Shanghai", server_default="Asia/Shanghai")
    theme: Mapped[str] = mapped_column(String(20), default="system", server_default="system")
    extra: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    user: Mapped["User"] = relationship(back_populates="preferences")
