"""Persist authorized scope entries and audit history."""
from alembic import op
import sqlalchemy as sa

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('assessments', sa.Column('scope_revision', sa.Integer(), nullable=False, server_default='0'))
    op.create_table(
        'scope_entries',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('assessment_id', sa.Uuid(), sa.ForeignKey('assessments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('normalized_value', sa.String(1024), nullable=False),
        sa.Column('kind', sa.String(16), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint('assessment_id', 'normalized_value', name='uq_scope_entry_value'),
        sa.CheckConstraint("kind IN ('IP address', 'Subnet', 'Hostname', 'Web URL')", name='ck_scope_entry_kind'),
    )
    op.create_table(
        'scope_events',
        sa.Column('assessment_id', sa.Uuid(), sa.ForeignKey('assessments.id'), primary_key=True),
        sa.Column('revision', sa.Integer(), primary_key=True),
        sa.Column('entry_id', sa.Uuid(), nullable=False),
        sa.Column('actor_id', sa.Uuid(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('action', sa.String(16), nullable=False),
        sa.Column('before', sa.JSON()),
        sa.Column('after', sa.JSON()),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("action IN ('added', 'edited', 'removed')", name='ck_scope_event_action'),
    )


def downgrade():
    op.drop_table('scope_events')
    op.drop_table('scope_entries')
    op.drop_column('assessments', 'scope_revision')
