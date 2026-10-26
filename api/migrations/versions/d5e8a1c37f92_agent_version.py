"""agent version reported with each inventory

Revision ID: d5e8a1c37f92
Revises: b3d9f2a61c40
Create Date: 2026-10-26 21:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'd5e8a1c37f92'
down_revision: str | Sequence[str] | None = 'b3d9f2a61c40'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('asset', sa.Column('agent_version', sa.String(length=50), server_default='', nullable=False))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('asset', 'agent_version')
