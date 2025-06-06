"""remove_doctor_availability_columns

Revision ID: e05cf3a6fa52
Revises: 281f0032545c
Create Date: 2024-03-21 11:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'e05cf3a6fa52'
down_revision: Union[str, None] = '281f0032545c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Drop doctor availability columns
    op.drop_column('users', 'doctor_status')
    op.drop_column('users', 'doctor_availability_notes')
    op.drop_column('users', 'doctor_availability_updated_at')
    op.drop_column('users', 'doctor_availability_updated_by')
    
    # Drop the enum type
    op.execute('DROP TYPE doctorstatus')

def downgrade() -> None:
    # Recreate the enum type
    doctor_status_enum = postgresql.ENUM('AVAILABLE', 'UNAVAILABLE', 'ON_LEAVE', 'ON_CALL', name='doctorstatus')
    doctor_status_enum.create(op.get_bind())
    
    # Recreate the columns
    op.add_column('users', sa.Column('doctor_status', doctor_status_enum, nullable=True))
    op.add_column('users', sa.Column('doctor_availability_notes', sa.String(), nullable=True))
    op.add_column('users', sa.Column('doctor_availability_updated_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('users', sa.Column('doctor_availability_updated_by', sa.Integer(), nullable=True)) 