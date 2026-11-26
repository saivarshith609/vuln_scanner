"""users and resource ownership

Revision ID: f3a91c2d7e10
Revises: e8b5c33f91a2
Create Date: 2026-10-28
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "f3a91c2d7e10"
down_revision: Union[str, None] = "e8b5c33f91a2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("role", sa.String(length=20), server_default="user", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("role IN ('user', 'admin')", name="ck_users_role"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.add_column("operator_sessions", sa.Column("user_id", sa.Uuid(), nullable=True))
    op.add_column("operator_sessions", sa.Column("csrf_digest", sa.String(length=64), nullable=True))
    op.create_foreign_key("fk_operator_sessions_user_id", "operator_sessions", "users", ["user_id"], ["id"], ondelete="CASCADE")
    op.create_index("ix_operator_sessions_user_id", "operator_sessions", ["user_id"], unique=False)

    for table in ("assets", "scans", "reports", "authorized_targets"):
        op.add_column(table, sa.Column("owner_user_id", sa.Uuid(), nullable=True))
        op.create_foreign_key(
            f"fk_{table}_owner_user_id", table, "users", ["owner_user_id"], ["id"], ondelete="SET NULL",
        )
        op.create_index(f"ix_{table}_owner_user_id", table, ["owner_user_id"], unique=False)

    op.drop_constraint("authorized_targets_target_key", "authorized_targets", type_="unique")
    op.create_index(
        "uq_authorized_targets_owner_target",
        "authorized_targets",
        ["owner_user_id", "target"],
        unique=True,
        postgresql_nulls_not_distinct=True,
    )


def downgrade() -> None:
    op.drop_index("uq_authorized_targets_owner_target", table_name="authorized_targets")
    op.create_unique_constraint("authorized_targets_target_key", "authorized_targets", ["target"])
    for table in ("authorized_targets", "reports", "scans", "assets"):
        op.drop_index(f"ix_{table}_owner_user_id", table_name=table)
        op.drop_constraint(f"fk_{table}_owner_user_id", table, type_="foreignkey")
        op.drop_column(table, "owner_user_id")
    op.drop_index("ix_operator_sessions_user_id", table_name="operator_sessions")
    op.drop_constraint("fk_operator_sessions_user_id", "operator_sessions", type_="foreignkey")
    op.drop_column("operator_sessions", "csrf_digest")
    op.drop_column("operator_sessions", "user_id")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_table("users")
