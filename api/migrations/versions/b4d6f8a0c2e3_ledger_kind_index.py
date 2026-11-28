"""ledger lookups by kind and subject: every inventory asks which assets sent an SBOM, which read the org's whole ledger

Revision ID: b4d6f8a0c2e3
Revises: a3c5e7f9b1d2
Create Date: 2026-11-28 04:00:00.000000

"""
from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b4d6f8a0c2e3'
down_revision: str | Sequence[str] | None = 'a3c5e7f9b1d2'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_index('ix_ledger_org_kind_subject', 'ledger_entry', ['org_id', 'kind', 'subject'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_ledger_org_kind_subject', table_name='ledger_entry')
