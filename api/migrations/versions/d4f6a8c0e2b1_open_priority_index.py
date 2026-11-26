"""the home page counts open findings by priority from an index alone

Revision ID: d4f6a8c0e2b1
Revises: b7d1e3f5a9c2
Create Date: 2026-11-26 09:30:00.000000

"""
from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'd4f6a8c0e2b1'
down_revision: str | Sequence[str] | None = 'b7d1e3f5a9c2'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index('ix_finding_open_priority', 'finding', ['org_id', 'status', 'priority'])


def downgrade() -> None:
    op.drop_index('ix_finding_open_priority', table_name='finding')
