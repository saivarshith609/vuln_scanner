"""network discovery inventory metadata

Revision ID: a72e6b91c4d2
Revises: f3a91c2d7e10
Create Date: 2026-10-28
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "a72e6b91c4d2"
down_revision: Union[str, None] = "f3a91c2d7e10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("operation", sa.String(length=20), server_default="scan", nullable=False))
    op.add_column("scans", sa.Column("target_kind", sa.String(length=20), server_default="host", nullable=False))
    op.add_column("scans", sa.Column("range_start", sa.String(length=45), nullable=True))
    op.add_column("scans", sa.Column("range_end", sa.String(length=45), nullable=True))
    op.add_column("scans", sa.Column("authorization_mode", sa.String(length=20), server_default="allow_list", nullable=False))
    op.add_column("scans", sa.Column("authorization_confirmed", sa.Boolean(), server_default=sa.false(), nullable=False))
    op.add_column("scans", sa.Column("partial_results", sa.Boolean(), server_default=sa.false(), nullable=False))
    op.create_check_constraint("ck_scans_operation", "scans", "operation IN ('scan', 'discovery')")
    op.create_check_constraint("ck_scans_target_kind", "scans", "target_kind IN ('host', 'cidr', 'range')")
    op.create_check_constraint(
        "ck_scans_authorization_mode", "scans",
        "authorization_mode IN ('allow_list', 'on_demand')",
    )
    op.create_index("ix_scans_operation", "scans", ["operation"], unique=False)
    op.add_column("scan_results", sa.Column("mac_address", sa.String(length=32), nullable=True))
    op.add_column("scan_results", sa.Column("vendor", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_results", "vendor")
    op.drop_column("scan_results", "mac_address")
    op.drop_index("ix_scans_operation", table_name="scans")
    op.drop_constraint("ck_scans_authorization_mode", "scans", type_="check")
    op.drop_constraint("ck_scans_target_kind", "scans", type_="check")
    op.drop_constraint("ck_scans_operation", "scans", type_="check")
    op.drop_column("scans", "partial_results")
    op.drop_column("scans", "authorization_confirmed")
    op.drop_column("scans", "authorization_mode")
    op.drop_column("scans", "range_end")
    op.drop_column("scans", "range_start")
    op.drop_column("scans", "target_kind")
    op.drop_column("scans", "operation")
