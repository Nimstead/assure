"""what runs on each host, and each finding's runtime state (DECISIONS 161)

Revision ID: b7d1e3f5a9c2
Revises: e8b2d4f6a1c3
Create Date: 2026-11-25 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b7d1e3f5a9c2'
down_revision: str | Sequence[str] | None = 'e8b2d4f6a1c3'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'asset_runtime',
        sa.Column('asset_id', sa.String(length=32), sa.ForeignKey('asset.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('org_id', sa.String(length=32), sa.ForeignKey('org.id'), nullable=False),
        sa.Column('read_at', sa.DateTime(), nullable=False),
        sa.Column('state', sa.String(length=10), nullable=False),
        sa.Column('problem', sa.String(length=300), nullable=True),
        sa.Column('since', sa.DateTime(), nullable=True),
        sa.Column('last_complete', sa.DateTime(), nullable=True),
        sa.Column('programs', sa.JSON(), nullable=False),
        sa.Column('native', sa.JSON(), nullable=False),
        sa.Column('seen', sa.JSON(), nullable=False),
        sa.Column('replaced', sa.JSON(), nullable=False),
        sa.Column('replaced_count', sa.Integer(), nullable=False),
    )
    op.create_index('ix_asset_runtime_org_id', 'asset_runtime', ['org_id'])
    with op.batch_alter_table('finding') as b:
        b.add_column(sa.Column('runtime', sa.String(length=12), nullable=True))
    op.create_index('ix_finding_runtime', 'finding', ['org_id', 'runtime'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_finding_runtime', table_name='finding')
    with op.batch_alter_table('finding') as b:
        b.drop_column('runtime')
    op.drop_index('ix_asset_runtime_org_id', table_name='asset_runtime')
    op.drop_table('asset_runtime')
