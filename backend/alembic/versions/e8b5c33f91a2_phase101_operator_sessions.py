"""phase101_operator_sessions

Revision ID: e8b5c33f91a2
Revises: c712d86a51e0
Create Date: 2026-10-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "e8b5c33f91a2"
down_revision: Union[str, None] = "c712d86a51e0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "operator_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_digest"),
    )
    op.create_index("ix_operator_sessions_expires_at", "operator_sessions", ["expires_at"], unique=False)
    op.create_index("ix_operator_sessions_revoked_at", "operator_sessions", ["revoked_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_operator_sessions_revoked_at", table_name="operator_sessions")
    op.drop_index("ix_operator_sessions_expires_at", table_name="operator_sessions")
    op.drop_table("operator_sessions")
