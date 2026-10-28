"""webhook URL sealed at rest (wider column); alert email recipients confirm before they get mail; sign-ups by email link

Revision ID: e7a2c94b1d05
Revises: d5e8a1c37f92
Create Date: 2026-10-28 09:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'e7a2c94b1d05'
down_revision: str | Sequence[str] | None = 'd5e8a1c37f92'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # Existing plaintext URLs are sealed by the next feeds run (notify.seal_legacy), which has the server key.
    with op.batch_alter_table('org') as b:
        b.alter_column('notify_webhook_url', type_=sa.String(length=2000), existing_type=sa.String(length=500), existing_nullable=True)
        b.add_column(sa.Column('notify_emails_confirmed', sa.JSON(), nullable=False, server_default='[]'))  # existing recipients must confirm
    op.create_table('pending_signup',
                    sa.Column('token_hash', sa.String(length=64), nullable=False),
                    sa.Column('email', sa.String(length=320), nullable=False),
                    sa.Column('org_name', sa.String(length=200), nullable=False),
                    sa.Column('password_hash', sa.String(length=200), nullable=False),
                    sa.Column('expires', sa.DateTime(), nullable=False),
                    sa.PrimaryKeyConstraint('token_hash'))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('pending_signup')
    with op.batch_alter_table('org') as b:
        b.drop_column('notify_emails_confirmed')
        b.alter_column('notify_webhook_url', type_=sa.String(length=500), existing_type=sa.String(length=2000), existing_nullable=True)
