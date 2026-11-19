"""the containers each host runs, and the image asset each one runs (DECISIONS 139)

Revision ID: c9e1a3f5b7d2
Revises: b7d2e4f6a813
Create Date: 2026-11-19 09:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c9e1a3f5b7d2'
down_revision: str | Sequence[str] | None = 'b7d2e4f6a813'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'container',
        sa.Column('asset_id', sa.String(length=32), nullable=False),
        sa.Column('container_id', sa.String(length=64), nullable=False),
        sa.Column('image_asset_id', sa.String(length=32), nullable=False),
        sa.Column('org_id', sa.String(length=32), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('runtime', sa.String(length=20), nullable=False),
        sa.Column('ref', sa.String(length=255), nullable=False),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['asset.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['image_asset_id'], ['asset.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['org_id'], ['org.id']),
        sa.PrimaryKeyConstraint('asset_id', 'container_id'),
    )
    op.create_index(op.f('ix_container_image_asset_id'), 'container', ['image_asset_id'], unique=False)
    op.create_index(op.f('ix_container_org_id'), 'container', ['org_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_container_org_id'), table_name='container')
    op.drop_index(op.f('ix_container_image_asset_id'), table_name='container')
    op.drop_table('container')
