"""Dummy migration for missing revision 04da95b9d05a

Revision ID: 04da95b9d05a
Revises: 4cd1b0f2622c
Create Date: 2024-01-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '04da95b9d05a'
down_revision: Union[str, None] = '4cd1b0f2622c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The operations for this missing revision are assumed to be
    # already applied to the database.
    pass


def downgrade() -> None:
    # Similarly, the downgrade operations are unknown or not applicable.
    pass
