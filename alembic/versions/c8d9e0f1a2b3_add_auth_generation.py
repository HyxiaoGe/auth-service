"""为用户与刷新令牌增加认证代际

Revision ID: c8d9e0f1a2b3
Revises: b7c8d9e0f1a2
Create Date: 2026-07-19 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c8d9e0f1a2b3"
down_revision: str | None = "b7c8d9e0f1a2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 新用户仍从 0 开始；但存量用户必须一次性提升到 1，使迁移前所有缺失
    # generation 的 refresh JWT、DB token 行和 SSO session（均按 0 解释）立即失配。
    # 部署流程会在运行本迁移前停止旧 auth 实例，避免迁移期间继续签发旧凭据。
    op.add_column(
        "users",
        sa.Column("auth_generation", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.add_column(
        "refresh_tokens",
        sa.Column("auth_generation", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.execute("UPDATE users SET auth_generation = 1")


def downgrade() -> None:
    op.drop_column("refresh_tokens", "auth_generation")
    op.drop_column("users", "auth_generation")
