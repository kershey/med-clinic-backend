"""add_admin_level_to_users_table

Revision ID: 2fdf25c8d879
Revises: 4cd1b0f2622c
Create Date: 2025-06-14 16:34:51.092947

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2fdf25c8d879'
down_revision: Union[str, None] = '04da95b9d05a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('users', sa.Column('admin_level', sa.Integer(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('users', 'admin_level') 