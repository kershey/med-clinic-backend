"""Add doctor model and relationships

Revision ID: e70c137a1bbf
Revises: 7d6de07f5793
Create Date: 2024-03-21 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'e70c137a1bbf'
down_revision: Union[str, None] = '7d6de07f5793'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create doctor_status enum type if it doesn't exist
    doctor_status = postgresql.ENUM('AVAILABLE', 'UNAVAILABLE', 'ON_LEAVE', 'ON_CALL',
                                  name='doctorstatus', create_type=False)
    doctor_status.create(op.get_bind(), checkfirst=True)

    # Create doctors table
    op.create_table(
        'doctors',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('specialization', sa.String(), nullable=False),
        sa.Column('license_number', sa.String(), nullable=True),
        sa.Column('clinic_address', sa.String(), nullable=True),
        sa.Column('fee', sa.Numeric(precision=10, scale=2), nullable=True),
        sa.Column('bio', sa.String(), nullable=True),
        sa.Column('availability_status', postgresql.ENUM('AVAILABLE', 'UNAVAILABLE', 'ON_LEAVE', 'ON_CALL',
                                                       name='doctorstatus', create_type=False), nullable=True),
        sa.Column('is_approved', sa.Boolean(), nullable=True),
        sa.Column('schedule', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id')
    )
    op.create_index(op.f('ix_doctors_id'), 'doctors', ['id'], unique=False)


def downgrade() -> None:
    # Drop doctors table
    op.drop_index(op.f('ix_doctors_id'), table_name='doctors')
    op.drop_table('doctors')

    # Drop doctor_status enum type
    doctor_status = postgresql.ENUM(name='doctorstatus')
    doctor_status.drop(op.get_bind(), checkfirst=True) 