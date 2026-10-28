"""security round 4: sign-up links never hold a password; MFA, API tokens, session idle timeout, enrolling token, per-org SLAs

Revision ID: b41c7d9e2a58
Revises: a3c8e5f20b17
Create Date: 2026-10-28 18:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b41c7d9e2a58'
down_revision: str | Sequence[str] | None = 'a3c8e5f20b17'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # Pending sign-ups held the requester's password (account pre-hijack): drop them; the address owner signs up again.
    op.execute("DELETE FROM pending_signup")
    with op.batch_alter_table('pending_signup') as b:
        b.drop_column('password_hash')
        b.add_column(sa.Column('purpose', sa.String(length=10), nullable=False, server_default='signup'))
        b.add_column(sa.Column('org_id', sa.String(length=32), nullable=True))
        b.create_index('ix_pending_signup_email', ['email'])
    with op.batch_alter_table('user') as b:
        b.add_column(sa.Column('totp_secret', sa.String(length=500), nullable=True))
        b.add_column(sa.Column('totp_last_step', sa.Integer(), nullable=False, server_default='0'))
        b.add_column(sa.Column('recovery_codes', sa.JSON(), nullable=False, server_default='[]'))
    with op.batch_alter_table('web_session') as b:
        b.add_column(sa.Column('last_used', sa.DateTime(), nullable=False, server_default=sa.func.now()))
    with op.batch_alter_table('asset') as b:
        b.add_column(sa.Column('enrolled_by', sa.String(length=12), nullable=True))
    with op.batch_alter_table('org') as b:
        b.add_column(sa.Column('sla_days', sa.JSON(), nullable=False, server_default='{}'))
    op.create_table('api_token',
                    sa.Column('token_hash', sa.String(length=64), nullable=False),
                    sa.Column('org_id', sa.String(length=32), nullable=False),
                    sa.Column('user_id', sa.String(length=32), nullable=False),
                    sa.Column('name', sa.String(length=100), nullable=False),
                    sa.Column('created', sa.DateTime(), nullable=False),
                    sa.Column('expires', sa.DateTime(), nullable=True),
                    sa.Column('last_used', sa.DateTime(), nullable=True),
                    sa.ForeignKeyConstraint(['org_id'], ['org.id']),
                    sa.ForeignKeyConstraint(['user_id'], ['user.id']),
                    sa.PrimaryKeyConstraint('token_hash'))
    op.create_index('ix_api_token_org_id', 'api_token', ['org_id'])
    op.create_index('ix_api_token_user_id', 'api_token', ['user_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_api_token_user_id', 'api_token')
    op.drop_index('ix_api_token_org_id', 'api_token')
    op.drop_table('api_token')
    with op.batch_alter_table('org') as b:
        b.drop_column('sla_days')
    with op.batch_alter_table('asset') as b:
        b.drop_column('enrolled_by')
    with op.batch_alter_table('web_session') as b:
        b.drop_column('last_used')
    with op.batch_alter_table('user') as b:
        b.drop_column('recovery_codes')
        b.drop_column('totp_last_step')
        b.drop_column('totp_secret')
    op.execute("DELETE FROM pending_signup")
    with op.batch_alter_table('pending_signup') as b:
        b.drop_index('ix_pending_signup_email')
        b.drop_column('org_id')
        b.drop_column('purpose')
        b.add_column(sa.Column('password_hash', sa.String(length=200), nullable=False))
