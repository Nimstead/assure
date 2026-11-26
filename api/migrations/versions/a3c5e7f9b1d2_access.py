"""who can get in and what they hold on each Linux host (DECISIONS 165)

Revision ID: a3c5e7f9b1d2
Revises: d4f6a8c0e2b1
Create Date: 2026-11-26 21:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a3c5e7f9b1d2'
down_revision: str | Sequence[str] | None = 'd4f6a8c0e2b1'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'asset_access',
        sa.Column('asset_id', sa.String(length=32), sa.ForeignKey('asset.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('org_id', sa.String(length=32), sa.ForeignKey('org.id'), nullable=False),
        sa.Column('read_at', sa.DateTime(), nullable=False),
        sa.Column('state', sa.String(length=10), nullable=False),
        sa.Column('problem', sa.String(length=300), nullable=True),
        sa.Column('data_at', sa.DateTime(), nullable=True),
        sa.Column('data', sa.JSON(), nullable=False),
    )
    op.create_index('ix_asset_access_org_id', 'asset_access', ['org_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_asset_access_org_id', table_name='asset_access')
    op.drop_table('asset_access')
