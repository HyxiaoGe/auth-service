"""add user_preferences table

Revision ID: a1b2c3d4e5f6
Revises: c542006e6b13
Create Date: 2026-03-16 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "c542006e6b13"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_preferences",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", sa.dialects.postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("locale", sa.String(10), nullable=False, server_default="zh"),
        sa.Column("timezone", sa.String(50), nullable=False, server_default="Asia/Shanghai"),
        sa.Column("theme", sa.String(20), nullable=False, server_default="system"),
        sa.Column("extra", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_user_preferences_user_id", "user_preferences", ["user_id"])

    # Set seanfield767@gmail.com as superuser
    op.execute(
        "UPDATE users SET is_superuser = true WHERE email = 'seanfield767@gmail.com'"
    )


def downgrade() -> None:
    op.execute(
        "UPDATE users SET is_superuser = false WHERE email = 'seanfield767@gmail.com'"
    )
    op.drop_index("ix_user_preferences_user_id", table_name="user_preferences")
    op.drop_table("user_preferences")
