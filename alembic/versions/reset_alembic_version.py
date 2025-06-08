"""Reset alembic version

Revision ID: reset_alembic_version
Revises: 
Create Date: 2024-03-21 11:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'reset_alembic_version'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Drop and recreate alembic_version table
    op.drop_table('alembic_version')
    op.create_table(
        'alembic_version',
        sa.Column('version_num', sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint('version_num')
    )
    # Set version to our merge revision
    op.execute("INSERT INTO alembic_version (version_num) VALUES ('a01031a50d97')")

def downgrade() -> None:
    # This is a one-way migration
    pass 