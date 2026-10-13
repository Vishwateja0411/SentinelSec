"""001_initial_targets

Revision ID: 001_initial_targets
Revises: 
Create Date: 2026-10-11 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '001_initial_targets'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'targets',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('target', sa.String(length=2048), nullable=False),
        sa.Column('type', sa.Enum('ip', 'url', name='targettype'), nullable=False),
        sa.Column('authorization_attestation', sa.Boolean(), nullable=False),
        sa.Column('attestation_timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_targets_id'), 'targets', ['id'], unique=False)
    op.create_index(op.f('ix_targets_target'), 'targets', ['target'], unique=False)
    op.create_index(op.f('ix_targets_created_at'), 'targets', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_targets_created_at'), table_name='targets')
    op.drop_index(op.f('ix_targets_target'), table_name='targets')
    op.drop_index(op.f('ix_targets_id'), table_name='targets')
    op.drop_table('targets')
    # Drop enum type in postgres if applicable
    targettype_enum = sa.Enum('ip', 'url', name='targettype')
    targettype_enum.drop(op.get_bind(), checkfirst=True)
