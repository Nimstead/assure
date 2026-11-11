"""each agent's neighbour table, and its own addresses (DECISIONS 128)

Revision ID: b7d2e4f6a813
Revises: a1c3e5f7b902
Create Date: 2026-11-11 23:30:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b7d2e4f6a813'
down_revision: str | Sequence[str] | None = 'a1c3e5f7b902'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'neighbour',
        sa.Column('asset_id', sa.String(length=32), nullable=False),
        sa.Column('ip', sa.String(length=45), nullable=False),
        sa.Column('mac', sa.String(length=17), nullable=False),
        sa.Column('org_id', sa.String(length=32), nullable=False),
        sa.Column('interface', sa.String(length=64), nullable=False),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['asset.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['org_id'], ['org.id']),
        sa.PrimaryKeyConstraint('asset_id', 'ip', 'mac'),
    )
    op.create_index(op.f('ix_neighbour_org_id'), 'neighbour', ['org_id'], unique=False)
    op.add_column('asset', sa.Column('own_addresses', sa.JSON(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('asset', 'own_addresses')
    op.drop_index(op.f('ix_neighbour_org_id'), table_name='neighbour')
    op.drop_table('neighbour')
