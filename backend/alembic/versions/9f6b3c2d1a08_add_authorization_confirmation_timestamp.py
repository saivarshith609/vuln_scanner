"""add authorization confirmation timestamp

Revision ID: 9f6b3c2d1a08
Revises: a72e6b91c4d2
Create Date: 2026-10-29
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "9f6b3c2d1a08"
down_revision: Union[str, None] = "a72e6b91c4d2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("authorization_confirmed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "authorization_confirmed_at")
