"""add refresh token sid

Revision ID: d9e0f1a2b3c4
Revises: c8d9e0f1a2b3
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d9e0f1a2b3c4"
down_revision: str | None = "c8d9e0f1a2b3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 仅为无锁迁移保持 nullable；运行时拒绝 sid=NULL 的旧 refresh，避免其形成
    # 不受 session 撤销约束的永久轮转分支。用户通过下一次登录/reconcile 升级。
    op.add_column("refresh_tokens", sa.Column("sid", sa.String(length=128), nullable=True))
    op.create_index("ix_refresh_tokens_sid", "refresh_tokens", ["sid"])


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_sid", table_name="refresh_tokens")
    op.drop_column("refresh_tokens", "sid")
