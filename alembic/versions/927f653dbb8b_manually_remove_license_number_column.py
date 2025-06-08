"""Manually remove license_number column

Revision ID: 927f653dbb8b
Revises: 21153668e41d
Create Date: 2025-06-07 19:05:37.214029

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '927f653dbb8b'
down_revision: Union[str, None] = '21153668e41d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_column('doctors', 'license_number')


def downgrade() -> None:
    """Downgrade schema."""
    op.add_column('doctors', sa.Column('license_number', sa.String(), nullable=True)) 