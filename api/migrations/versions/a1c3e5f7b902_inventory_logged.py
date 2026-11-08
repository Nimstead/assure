"""the last inventory written to the ledger, so an unchanged one is written once a day (DECISIONS 121)

Revision ID: a1c3e5f7b902
Revises: e5c2a9d7f413
Create Date: 2026-11-08 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a1c3e5f7b902'
down_revision: str | Sequence[str] | None = 'e5c2a9d7f413'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('asset', sa.Column('inventory_logged_sha256', sa.String(length=64), nullable=True))
    op.add_column('asset', sa.Column('inventory_logged_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('asset', 'inventory_logged_at')
    op.drop_column('asset', 'inventory_logged_sha256')
