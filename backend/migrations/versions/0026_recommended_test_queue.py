"""Independent durable queue for accepted recommended tests."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSON

revision = '0026'
down_revision = '0025'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('recommended_test_jobs',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('assessment_id', UUID(as_uuid=True), sa.ForeignKey('assessments.id'), nullable=False),
        sa.Column('target_id', UUID(as_uuid=True), sa.ForeignKey('assessment_targets.id'), nullable=False),
        sa.Column('actor_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('recommendation_id', sa.String(64), nullable=False),
        sa.Column('tool', sa.String(40), nullable=False),
        sa.Column('profile_id', sa.String(80), nullable=False),
        sa.Column('profile_version', sa.Integer(), nullable=False),
        sa.Column('scope_revision', sa.Integer(), nullable=False),
        sa.Column('execution_plan', JSON(), nullable=False),
        sa.Column('status', sa.String(32), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('failure_reason', sa.String(120), nullable=True),
        sa.Column('stdout', sa.LargeBinary(), nullable=True),
        sa.Column('stderr', sa.LargeBinary(), nullable=True),
        sa.Column('output_digest', sa.String(64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('assessment_id', 'recommendation_id', name='uq_recommended_job_recommendation'),
        sa.CheckConstraint("status IN ('Queued','Running','Completed','Failed','Stopped','Blocked','Cancelled')", name='ck_recommended_job_status'),
        )
    op.create_index('ix_recommended_job_queue', 'recommended_test_jobs', ['status', 'created_at'])
    # Runtime grants are deployed separately with least-privilege role review.


def downgrade():
    op.drop_index('ix_recommended_job_queue', table_name='recommended_test_jobs')
    op.drop_table('recommended_test_jobs')
