"""Fix migration state

Revision ID: fix_migration_state
Revises: 
Create Date: 2024-03-21 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'fix_migration_state'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Drop alembic_version table if it exists
    op.execute("DROP TABLE IF EXISTS alembic_version")
    
    # Create alembic_version table
    op.create_table(
        'alembic_version',
        sa.Column('version_num', sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint('version_num')
    )
    
    # Insert the merge revision
    op.execute("INSERT INTO alembic_version (version_num) VALUES ('a01031a50d97')")

def downgrade() -> None:
    # This is a one-way migration
    pass 