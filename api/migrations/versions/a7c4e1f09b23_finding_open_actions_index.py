"""finding index for the home-page summary (open findings grouped into actions)

Revision ID: a7c4e1f09b23
Revises: cb6d07e32b0a
Create Date: 2026-10-26 14:40:00.000000

"""
from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a7c4e1f09b23'
down_revision: str | Sequence[str] | None = 'cb6d07e32b0a'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_index('ix_finding_open_actions', 'finding', ['org_id', 'status', 'ecosystem', 'package'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_finding_open_actions', table_name='finding')
