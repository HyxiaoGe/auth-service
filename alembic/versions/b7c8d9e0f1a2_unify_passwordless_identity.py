"""统一无密码邮箱与社交身份唯一性

Revision ID: b7c8d9e0f1a2
Revises: f1a2b3c4d5e6
Create Date: 2026-07-19 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b7c8d9e0f1a2"
down_revision: str | None = "f1a2b3c4d5e6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 现有环境已确认没有规范化邮箱或社交身份重复；约束在升级时再次强制校验。
    op.create_index(
        "uq_users_normalized_email",
        "users",
        [sa.text("lower(btrim(email))")],
        unique=True,
    )
    op.create_unique_constraint(
        "uq_social_accounts_provider_identity",
        "social_accounts",
        ["provider", "provider_id"],
    )
    op.create_unique_constraint(
        "uq_social_accounts_user_provider",
        "social_accounts",
        ["user_id", "provider"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_social_accounts_user_provider", "social_accounts", type_="unique")
    op.drop_constraint("uq_social_accounts_provider_identity", "social_accounts", type_="unique")
    op.drop_index("uq_users_normalized_email", table_name="users")
