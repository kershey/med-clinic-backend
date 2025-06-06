"""add_doctor_status_columns

Revision ID: 281f0032545c
Revises: 2715ac7b3fd6
Create Date: 2024-03-21 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '281f0032545c'
down_revision: Union[str, None] = '2715ac7b3fd6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Create enum type for doctor status
doctor_status_enum = postgresql.ENUM('AVAILABLE', 'UNAVAILABLE', 'ON_LEAVE', 'ON_CALL', name='doctorstatus')

def upgrade() -> None:
    # Create enum type
    doctor_status_enum.create(op.get_bind())
    
    # Add doctor status columns
    op.add_column('users', sa.Column('doctor_status', doctor_status_enum, nullable=True))
    op.add_column('users', sa.Column('doctor_specialization', sa.String(), nullable=True))
    op.add_column('users', sa.Column('doctor_bio', sa.String(), nullable=True))
    op.add_column('users', sa.Column('doctor_availability_notes', sa.String(), nullable=True))
    op.add_column('users', sa.Column('doctor_availability_updated_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('users', sa.Column('doctor_availability_updated_by', sa.Integer(), nullable=True))

def downgrade() -> None:
    # Remove doctor status columns
    op.drop_column('users', 'doctor_availability_updated_by')
    op.drop_column('users', 'doctor_availability_updated_at')
    op.drop_column('users', 'doctor_availability_notes')
    op.drop_column('users', 'doctor_bio')
    op.drop_column('users', 'doctor_specialization')
    op.drop_column('users', 'doctor_status')
    
    # Drop enum type
    doctor_status_enum.drop(op.get_bind()) 