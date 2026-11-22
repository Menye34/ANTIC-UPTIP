"""Persist normalized recommended-test observations without baseline attempt IDs."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = '0028'
down_revision = '0027'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('recommended_processing_outcomes',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('job_id', UUID(as_uuid=True), nullable=False),
        sa.Column('assessment_id', UUID(as_uuid=True), nullable=False),
        sa.Column('target_id', UUID(as_uuid=True), nullable=False),
        sa.Column('processor', sa.String(80), nullable=False),
        sa.Column('processor_version', sa.String(40), nullable=False),
        sa.Column('output_digest', sa.String(64), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('error_code', sa.String(80)),
        sa.Column('observation_count', sa.Integer(), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['job_id','assessment_id','target_id'],
            ['recommended_test_jobs.id','recommended_test_jobs.assessment_id','recommended_test_jobs.target_id'],
            name='fk_recommended_processing_job'),
        sa.UniqueConstraint('id','job_id','assessment_id','target_id',name='uq_recommended_processing_binding'),
        sa.UniqueConstraint('job_id','processor','processor_version','output_digest',name='uq_recommended_processing_source'),
        sa.CheckConstraint("status IN ('Succeeded','Failed')",name='ck_recommended_processing_status'),
        sa.CheckConstraint("output_digest ~ '^[0-9a-f]{64}$'",name='ck_recommended_processing_digest'),
        sa.CheckConstraint('observation_count >= 0',name='ck_recommended_processing_count'))
    op.create_index('ix_recommended_processing_assessment','recommended_processing_outcomes',['assessment_id','job_id'])
    op.create_table('recommended_observations',
        sa.Column('id',UUID(as_uuid=True),primary_key=True),
        sa.Column('processing_id',UUID(as_uuid=True),nullable=False),
        sa.Column('job_id',UUID(as_uuid=True),nullable=False),
        sa.Column('assessment_id',UUID(as_uuid=True),nullable=False),
        sa.Column('target_id',UUID(as_uuid=True),nullable=False),
        sa.Column('observation_type',sa.String(80),nullable=False),
        sa.Column('data',JSONB(),nullable=False),
        sa.Column('deduplication_key',sa.String(64),nullable=False),
        sa.Column('collected_at',sa.DateTime(timezone=True),nullable=False),
        sa.Column('processed_at',sa.DateTime(timezone=True),nullable=False),
        sa.Column('is_partial',sa.Boolean(),nullable=False),
        sa.ForeignKeyConstraint(['processing_id','job_id','assessment_id','target_id'],
            ['recommended_processing_outcomes.id','recommended_processing_outcomes.job_id',
             'recommended_processing_outcomes.assessment_id','recommended_processing_outcomes.target_id'],
            name='fk_recommended_observation_processing'),
        sa.UniqueConstraint('job_id','deduplication_key',name='uq_recommended_observation_key'),
        sa.CheckConstraint("deduplication_key ~ '^[0-9a-f]{64}$'",name='ck_recommended_observation_key'),
        sa.CheckConstraint("jsonb_typeof(data)='object' AND octet_length(data::text)<=16384",name='ck_recommended_observation_data'))
    op.create_index('ix_recommended_observation_assessment','recommended_observations',['assessment_id','target_id'])
    # Least-privilege runtime access; processing records are append-only.
    op.execute("""
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'uptip_runtime') THEN
        GRANT SELECT, INSERT ON recommended_processing_outcomes TO uptip_runtime;
        GRANT SELECT, INSERT ON recommended_observations TO uptip_runtime;
      END IF;
    END $$;
    """)


def downgrade():
    op.drop_index('ix_recommended_observation_assessment',table_name='recommended_observations')
    op.drop_table('recommended_observations')
    op.drop_index('ix_recommended_processing_assessment',table_name='recommended_processing_outcomes')
    op.drop_table('recommended_processing_outcomes')
