"""asset and enrolment token owners, and the weekly summary switch (DECISIONS 145, 147)

Revision ID: d4f6a8c0e2b4
Revises: c9e1a3f5b7d2
Create Date: 2026-11-20 13:30:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'd4f6a8c0e2b4'
down_revision: str | Sequence[str] | None = 'c9e1a3f5b7d2'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('asset', sa.Column('owner', sa.String(length=100), nullable=True))
    op.add_column('enroll_token', sa.Column('owner', sa.String(length=100), nullable=True))
    op.add_column('org', sa.Column('weekly_summary', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column('org', sa.Column('weekly_summary_sent', sa.String(length=10), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('org', 'weekly_summary_sent')
    op.drop_column('org', 'weekly_summary')
    op.drop_column('enroll_token', 'owner')
    op.drop_column('asset', 'owner')
