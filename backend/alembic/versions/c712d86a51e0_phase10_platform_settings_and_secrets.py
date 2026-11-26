"""phase10_platform_settings_and_secrets

Revision ID: c712d86a51e0
Revises: a50026cb99e7
Create Date: 2026-10-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "c712d86a51e0"
down_revision: Union[str, None] = "a50026cb99e7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "platform_settings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("max_concurrent_scans", sa.Integer(), nullable=False),
        sa.Column("scanner_rate_limit_per_minute", sa.Integer(), nullable=False),
        sa.Column("session_timeout_minutes", sa.Integer(), nullable=False),
        sa.Column("accent_color", sa.String(length=7), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "integration_credentials",
        sa.Column("provider", sa.String(length=20), nullable=False),
        sa.Column("encrypted_secret", sa.LargeBinary(), nullable=False),
        sa.Column("masked_hint", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("provider"),
    )
    op.create_table(
        "platform_api_keys",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("key_hash", sa.LargeBinary(), nullable=False),
        sa.Column("hash_salt", sa.LargeBinary(), nullable=False),
        sa.Column("masked_hint", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("platform_api_keys")
    op.drop_table("integration_credentials")
    op.drop_table("platform_settings")
