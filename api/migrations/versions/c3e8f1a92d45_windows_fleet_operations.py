"""maintenance windows, restart deadline, Active Directory computers (Windows round 1, plan T40-T43)

Revision ID: c3e8f1a92d45
Revises: 9a61c0e4d2b7
Create Date: 2026-10-29 03:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c3e8f1a92d45'
down_revision: str | Sequence[str] | None = '9a61c0e4d2b7'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('org', sa.Column('maintenance_window', sa.JSON(), nullable=True))
    op.add_column('org', sa.Column('reboot_deadline_hours', sa.Integer(), server_default='24', nullable=False))
    op.add_column('asset', sa.Column('maintenance_window', sa.JSON(), nullable=True))
    op.create_table(
        'directory_computer',
        sa.Column('org_id', sa.String(length=32), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('os', sa.String(length=255), nullable=False),
        sa.Column('os_version', sa.String(length=100), nullable=False),
        sa.Column('last_logon', sa.DateTime(), nullable=True),
        sa.Column('seen_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['org.id']),
        sa.PrimaryKeyConstraint('org_id', 'domain', 'name'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('directory_computer')
    op.drop_column('asset', 'maintenance_window')
    op.drop_column('org', 'reboot_deadline_hours')
    op.drop_column('org', 'maintenance_window')
