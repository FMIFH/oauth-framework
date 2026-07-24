"""add_deactivated_at_to_signing_keys

Revision ID: 8515712e5250
Revises: 73d71c913c37
Create Date: 2026-07-19 12:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "8515712e5250"
down_revision: Union[str, Sequence[str], None] = "73d71c913c37"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("signing_keys", sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("signing_keys", "deactivated_at")
