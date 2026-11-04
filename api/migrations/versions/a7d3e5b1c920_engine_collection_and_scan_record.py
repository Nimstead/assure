"""engine: the agent's collection document and stored scan records

Revision ID: a7d3e5b1c920
Revises: c3e8f1a92d45
Create Date: 2026-11-03 02:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a7d3e5b1c920'
down_revision: str | Sequence[str] | None = 'c3e8f1a92d45'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('asset', sa.Column('collection', sa.JSON(), nullable=True))
    op.create_table(
        'scan_record',
        sa.Column('id', sa.String(length=32), nullable=False),
        sa.Column('org_id', sa.String(length=32), nullable=False),
        sa.Column('asset_id', sa.String(length=32), nullable=False),
        sa.Column('created', sa.DateTime(), nullable=False),
        sa.Column('engine_version', sa.String(length=20), nullable=False),
        sa.Column('content_version', sa.String(length=40), nullable=False),
        sa.Column('inventory_sha256', sa.String(length=64), nullable=False),
        sa.Column('verdicts_sha256', sa.String(length=64), nullable=False),
        sa.Column('inventory', sa.JSON(), nullable=False),
        sa.Column('report', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['asset.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['org_id'], ['org.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_scan_record_asset_id'), 'scan_record', ['asset_id'], unique=False)
    op.create_index(op.f('ix_scan_record_org_id'), 'scan_record', ['org_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_scan_record_org_id'), table_name='scan_record')
    op.drop_index(op.f('ix_scan_record_asset_id'), table_name='scan_record')
    op.drop_table('scan_record')
    op.drop_column('asset', 'collection')
