"""external targets: ownership verification time on assets

Revision ID: b3d9f2a61c40
Revises: a7c4e1f09b23
Create Date: 2026-10-26 16:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b3d9f2a61c40'
down_revision: str | Sequence[str] | None = 'a7c4e1f09b23'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('asset', sa.Column('verified_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('asset', 'verified_at')
