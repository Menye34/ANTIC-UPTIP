"""Store explicitly registered assessment targets."""
from alembic import op
import sqlalchemy as sa

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'assessment_targets',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('assessment_id', sa.Uuid(), sa.ForeignKey('assessments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('original_value', sa.String(1024), nullable=False),
        sa.Column('normalized_value', sa.String(1024), nullable=False),
        sa.Column('kind', sa.String(16), nullable=False),
        sa.Column('scope_status', sa.String(24), nullable=False),
        sa.Column('classification_reason', sa.String(80), nullable=False),
        sa.Column('scope_revision', sa.Integer(), nullable=False),
        sa.Column('revision', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint('assessment_id', 'normalized_value', name='uq_assessment_target_value'),
        sa.CheckConstraint("kind IN ('IP address', 'Subnet', 'Hostname', 'Web URL')", name='ck_target_kind'),
        sa.CheckConstraint("scope_status IN ('in_scope', 'out_of_scope', 'requires_revalidation')", name='ck_target_scope'),
        sa.CheckConstraint('scope_revision >= 0 AND revision > 0', name='ck_target_revisions'),
    )


def downgrade():
    op.drop_table('assessment_targets')
