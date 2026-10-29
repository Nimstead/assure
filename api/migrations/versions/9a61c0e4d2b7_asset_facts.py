"""agent-reported host facts (Windows round 1)

Revision ID: 9a61c0e4d2b7
Revises: b41c7d9e2a58
Create Date: 2026-10-29 02:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '9a61c0e4d2b7'
down_revision: str | Sequence[str] | None = 'b41c7d9e2a58'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('asset', sa.Column('facts', sa.JSON(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('asset', 'facts')
