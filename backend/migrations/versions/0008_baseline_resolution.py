"""Add system-managed baseline planning records."""
from alembic import op
import sqlalchemy as sa

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'baseline_tool_states',
        sa.Column('tool', sa.String(32), primary_key=True),
        sa.Column('state', sa.String(16), nullable=False),
        sa.Column('capabilities', sa.JSON(), nullable=False),
        sa.Column('revision', sa.Integer(), nullable=False),
        sa.CheckConstraint("state IN ('enabled', 'disabled', 'unavailable', 'unknown')", name='ck_baseline_tool_state'),
        sa.CheckConstraint('revision > 0', name='ck_baseline_tool_revision'),
    )
    op.create_table(
        'baseline_evaluations',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('assessment_id', sa.Uuid(), nullable=False),
        sa.Column('target_id', sa.Uuid(), nullable=False),
        sa.Column('profile_key', sa.String(80), nullable=False),
        sa.Column('fingerprint', sa.String(64), nullable=False),
        sa.Column('decision', sa.JSON(), nullable=False),
        sa.Column('trigger', sa.String(32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    for key in ('assessment_id', 'target_id'):
        op.create_index(f'ix_baseline_evaluations_{key}', 'baseline_evaluations', [key])
    op.create_table(
        'baseline_assignments',
        sa.Column('target_id', sa.Uuid(), sa.ForeignKey('assessment_targets.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('profile_key', sa.String(80), primary_key=True),
        sa.Column('evaluation_id', sa.Uuid(), sa.ForeignKey('baseline_evaluations.id'), nullable=False, unique=True),
    )


def downgrade():
    op.drop_table('baseline_assignments')
    op.drop_table('baseline_evaluations')
    op.drop_table('baseline_tool_states')
