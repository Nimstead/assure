"""an admin-chosen directory source per asset (DECISIONS 102)

Revision ID: e5c2a9d7f413
Revises: d4f1b8a3c6e2
Create Date: 2026-11-04 08:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'e5c2a9d7f413'
down_revision: str | Sequence[str] | None = 'd4f1b8a3c6e2'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('asset', sa.Column('directory_source', sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('asset', 'directory_source')
