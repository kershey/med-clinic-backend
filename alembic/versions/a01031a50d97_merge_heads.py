"""merge heads

Revision ID: a01031a50d97
Revises: e05cf3a6fa52, e70c137a1bbf
Create Date: 2025-06-07 02:19:08.295968

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a01031a50d97'
down_revision: Union[str, None] = ('e05cf3a6fa52', 'e70c137a1bbf')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass 