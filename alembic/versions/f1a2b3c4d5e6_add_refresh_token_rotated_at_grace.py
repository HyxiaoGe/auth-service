"""add refresh_tokens.rotated_at and grace_consumed (rotation grace window)

Revision ID: f1a2b3c4d5e6
Revises: a1b2c3d4e5f6
Create Date: 2026-06-05 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f1a2b3c4d5e6"
down_revision: str | None = "a1b2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Both nullable / defaulted, no backfill: existing rows get rotated_at=NULL (never graced,
    # which is the safe default) and grace_consumed=false.
    op.add_column("refresh_tokens", sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "refresh_tokens",
        sa.Column("grace_consumed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )


def downgrade() -> None:
    op.drop_column("refresh_tokens", "grace_consumed")
    op.drop_column("refresh_tokens", "rotated_at")
