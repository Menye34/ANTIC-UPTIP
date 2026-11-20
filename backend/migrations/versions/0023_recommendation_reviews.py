"""Add analyst review history; no executable profiles or approvals."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID
revision = '0023'
down_revision = '0022'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('recommendation_review_events',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('assessment_id', UUID(as_uuid=True), sa.ForeignKey('assessments.id'), nullable=False),
        sa.Column('recommendation_id', sa.String(64), nullable=False),
        sa.Column('actor_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('context_digest', sa.String(64), nullable=False),
        sa.Column('revision', sa.Integer(), nullable=False),
        sa.UniqueConstraint('assessment_id','recommendation_id','revision',name='uq_recommendation_review_revision'),
        sa.CheckConstraint('revision>0',name='ck_recommendation_review_revision'),
        sa.Column('snapshot', sa.JSON(), nullable=False),
        sa.Column('outcome', sa.String(16), nullable=False),
        sa.Column('decided_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("json_typeof(snapshot)='object' AND (snapshot->>'id') IS NOT DISTINCT FROM recommendation_id", name='ck_recommendation_review_snapshot'),
        sa.CheckConstraint("outcome IN ('Accepted','Rejected')", name='ck_recommendation_review_outcome'),
        sa.CheckConstraint("recommendation_id ~ '^[0-9a-f]{64}$' AND context_digest=recommendation_id", name='ck_recommendation_review_context'))
    op.create_index('ix_recommendation_review_latest', 'recommendation_review_events', ['assessment_id','recommendation_id','revision'])
    op.execute('''
CREATE FUNCTION validate_recommendation_review() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE lifecycle text;
BEGIN
 SELECT status INTO lifecycle FROM public.assessments WHERE id=NEW.assessment_id FOR SHARE;
 IF lifecycle IS DISTINCT FROM 'Testing' OR EXISTS (
   SELECT 1 FROM public.testing_completion_events WHERE assessment_id=NEW.assessment_id)
 THEN RAISE EXCEPTION 'Review requires active Testing'; END IF;
 IF NOT EXISTS (SELECT 1 FROM public.security_observations o
   JOIN public.scanner_evidence e ON e.id=o.evidence_id
   WHERE o.id::text=NEW.snapshot->>'source_observation_id'
   AND o.evidence_id::text=NEW.snapshot->>'source_evidence_id'
   AND o.target_id::text=NEW.snapshot->>'target_id'
   AND o.assessment_id=NEW.assessment_id AND e.assessment_id=NEW.assessment_id)
 THEN RAISE EXCEPTION 'Review provenance mismatch'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION validate_recommendation_review() FROM PUBLIC;
CREATE TRIGGER validate_recommendation_review BEFORE INSERT ON recommendation_review_events
FOR EACH ROW EXECUTE FUNCTION validate_recommendation_review();
CREATE TRIGGER immutable_recommendation_review BEFORE UPDATE OR DELETE ON recommendation_review_events
FOR EACH ROW EXECUTE FUNCTION reject_execution_history_change();
CREATE TRIGGER no_recommendation_review_truncate BEFORE TRUNCATE ON recommendation_review_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_execution_history_change();
GRANT SELECT, INSERT ON recommendation_review_events TO uptip_runtime;
''')

def downgrade():
    op.execute('''LOCK TABLE assessments, recommendation_review_events IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM recommendation_review_events)
 THEN RAISE EXCEPTION 'Cannot downgrade with recommendation review history'; END IF;
END $$;''')
    op.drop_table('recommendation_review_events')
    op.execute('DROP FUNCTION validate_recommendation_review()')
