"""a binary's source package version, where it differs from its own (DECISIONS 84)

Revision ID: d4f1b8a3c6e2
Revises: a7d3e5b1c920
Create Date: 2026-11-03 04:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'd4f1b8a3c6e2'
down_revision: str | Sequence[str] | None = 'a7d3e5b1c920'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('installed_package', sa.Column('source_version', sa.String(length=255), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('installed_package', 'source_version')
