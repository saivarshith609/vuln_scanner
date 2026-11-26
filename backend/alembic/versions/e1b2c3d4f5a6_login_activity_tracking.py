"""login activity tracking

Revision ID: e1b2c3d4f5a6
Revises: d4a6f28c91b3
Create Date: 2026-11-27
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "e1b2c3d4f5a6"
down_revision: Union[str, None] = "d4a6f28c91b3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "login_activities",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("attempted_identifier", sa.String(length=320), nullable=True),
        sa.Column("browser_name", sa.String(length=64), nullable=False),
        sa.Column("browser_version", sa.String(length=32), nullable=True),
        sa.Column("operating_system", sa.String(length=64), nullable=False),
        sa.Column("os_version", sa.String(length=32), nullable=True),
        sa.Column("device_type", sa.String(length=24), nullable=False),
        sa.Column("login_status", sa.String(length=16), nullable=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("login_status IN ('success', 'failed')", name="ck_login_activities_status"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_login_activities_attempted_at", "login_activities", ["attempted_at"])
    op.create_index("ix_login_activities_user_id", "login_activities", ["user_id"])
    op.create_index("ix_login_activities_browser_name", "login_activities", ["browser_name"])
    op.create_index("ix_login_activities_login_status", "login_activities", ["login_status"])
    op.create_index("ix_login_activities_attempted_identifier", "login_activities", ["attempted_identifier"])


def downgrade() -> None:
    op.drop_index("ix_login_activities_attempted_identifier", table_name="login_activities")
    op.drop_index("ix_login_activities_login_status", table_name="login_activities")
    op.drop_index("ix_login_activities_browser_name", table_name="login_activities")
    op.drop_index("ix_login_activities_user_id", table_name="login_activities")
    op.drop_index("ix_login_activities_attempted_at", table_name="login_activities")
    op.drop_table("login_activities")
