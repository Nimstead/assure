"""agent self-update state (auto_update, last update error), org-wide update pause, not-reporting alert marker

Revision ID: a3c8e5f20b17
Revises: e7a2c94b1d05
Create Date: 2026-10-28 18:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a3c8e5f20b17'
down_revision: str | Sequence[str] | None = 'e7a2c94b1d05'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('asset') as b:
        b.add_column(sa.Column('auto_update', sa.Boolean(), nullable=True))
        b.add_column(sa.Column('agent_update_error', sa.String(length=500), nullable=True))
        b.add_column(sa.Column('silent_alerted_at', sa.DateTime(), nullable=True))
    with op.batch_alter_table('org') as b:
        b.add_column(sa.Column('agent_updates_paused', sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('org') as b:
        b.drop_column('agent_updates_paused')
    with op.batch_alter_table('asset') as b:
        b.drop_column('silent_alerted_at')
        b.drop_column('agent_update_error')
        b.drop_column('auto_update')
