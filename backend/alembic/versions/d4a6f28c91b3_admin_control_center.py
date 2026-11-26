"""admin control center, audit logs, and account lifecycle fields

Revision ID: d4a6f28c91b3
Revises: 9f6b3c2d1a08
Create Date: 2026-10-29
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "d4a6f28c91b3"
down_revision: Union[str, None] = "9f6b3c2d1a08"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("password_change_required", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("users", sa.Column("version", sa.Integer(), nullable=False, server_default="1"))
    op.add_column("users", sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
    op.create_check_constraint("ck_users_version", "users", "version >= 1")

    op.add_column("reports", sa.Column("scan_id", sa.Uuid(), nullable=True))
    op.create_foreign_key("fk_reports_scan_id_scans", "reports", "scans", ["scan_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("outcome", sa.String(length=20), nullable=False),
        sa.Column("resource_type", sa.String(length=50), nullable=True),
        sa.Column("resource_id", sa.String(length=100), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("ix_audit_logs_actor_user_id", "audit_logs", ["actor_user_id"])
    op.create_index("ix_audit_logs_event_type", "audit_logs", ["event_type"])
    op.create_index("ix_audit_logs_resource", "audit_logs", ["resource_type", "resource_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_resource", table_name="audit_logs")
    op.drop_index("ix_audit_logs_event_type", table_name="audit_logs")
    op.drop_index("ix_audit_logs_actor_user_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("ix_reports_scan_id", table_name="reports")
    op.drop_constraint("fk_reports_scan_id_scans", "reports", type_="foreignkey")
    op.drop_column("reports", "scan_id")
    op.drop_constraint("ck_users_version", "users", type_="check")
    op.drop_column("users", "last_login_at")
    op.drop_column("users", "version")
    op.drop_column("users", "password_change_required")
