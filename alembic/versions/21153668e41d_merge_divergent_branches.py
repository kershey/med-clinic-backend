"""Merge divergent branches

Revision ID: 21153668e41d
Revises: a01031a50d97, fix_migration_state, reset_alembic_version
Create Date: 2025-06-07 19:05:23.123452

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '21153668e41d'
down_revision: Union[str, None] = ('a01031a50d97', 'fix_migration_state', 'reset_alembic_version')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass 