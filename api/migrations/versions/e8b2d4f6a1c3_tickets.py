"""ticket settings and tickets (DECISIONS 150)

Revision ID: e8b2d4f6a1c3
Revises: d4f6a8c0e2b4
Create Date: 2026-11-21 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'e8b2d4f6a1c3'
down_revision: str | Sequence[str] | None = 'd4f6a8c0e2b4'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'ticket_settings',
        sa.Column('org_id', sa.String(length=32), sa.ForeignKey('org.id'), primary_key=True),
        sa.Column('kind', sa.String(length=10), nullable=False),
        sa.Column('site', sa.String(length=500), nullable=False),
        sa.Column('user', sa.String(length=320), nullable=False),
        sa.Column('token', sa.String(length=2000), nullable=True),
        sa.Column('default_project', sa.String(length=255), nullable=False),
        sa.Column('routes', sa.JSON(), nullable=False),
        sa.Column('min_priority', sa.String(length=20), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('sync_started', sa.DateTime(), nullable=True),
        sa.Column('last_sync', sa.JSON(), nullable=True),
    )
    op.create_table(
        'ticket',
        sa.Column('id', sa.String(length=32), primary_key=True),
        sa.Column('org_id', sa.String(length=32), sa.ForeignKey('org.id'), nullable=False),
        sa.Column('fingerprint', sa.String(length=12), nullable=False),
        sa.Column('owner', sa.String(length=100), nullable=True),
        sa.Column('action', sa.JSON(), nullable=False),
        sa.Column('project', sa.String(length=255), nullable=False),
        sa.Column('key', sa.String(length=100), nullable=True),
        sa.Column('state', sa.String(length=10), nullable=False),
        sa.Column('title', sa.String(length=300), nullable=False),
        sa.Column('body_sha', sa.String(length=64), nullable=False),
        sa.Column('machines', sa.JSON(), nullable=False),
        sa.Column('opened_at', sa.DateTime(), nullable=False),
        sa.Column('closed_at', sa.DateTime(), nullable=True),
        sa.Column('checked_at', sa.DateTime(), nullable=True),
        sa.Column('error', sa.String(length=500), nullable=True),
        sa.UniqueConstraint('org_id', 'fingerprint'),
    )
    op.create_index('ix_ticket_org_id', 'ticket', ['org_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_ticket_org_id', table_name='ticket')
    op.drop_table('ticket')
    op.drop_table('ticket_settings')
