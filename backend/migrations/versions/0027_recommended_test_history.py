"""Protect recommended-job consent, terminal output and append-only events.

Legacy jobs retain unknown provenance (NULL); never invent or enable old consent.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSON

revision = '0027'
down_revision = '0026'
branch_labels = depends_on = None


def upgrade():
    op.add_column('recommended_test_jobs', sa.Column('authorization_snapshot', JSON(), nullable=True))
    op.add_column('recommended_test_jobs', sa.Column('termination_verified', sa.Boolean(), nullable=True))
    op.add_column('recommended_test_jobs', sa.Column('output_partial', sa.Boolean(), nullable=True))
    op.add_column('recommended_test_jobs', sa.Column('process_reference', sa.String(160), nullable=True))
    op.create_unique_constraint('uq_recommended_job_binding', 'recommended_test_jobs', ['id', 'assessment_id', 'target_id'])
    op.create_foreign_key('fk_recommended_target_assessment', 'recommended_test_jobs', 'assessment_targets',
                          ['target_id', 'assessment_id'], ['id', 'assessment_id'])
    op.create_table('recommended_test_events',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('job_id', UUID(as_uuid=True), nullable=False),
        sa.Column('assessment_id', UUID(as_uuid=True), nullable=False),
        sa.Column('target_id', UUID(as_uuid=True), nullable=False),
        sa.Column('event_type', sa.String(40), nullable=False),
        sa.Column('reason_code', sa.String(120), nullable=False),
        sa.Column('occurred_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['job_id', 'assessment_id', 'target_id'],
            ['recommended_test_jobs.id', 'recommended_test_jobs.assessment_id', 'recommended_test_jobs.target_id'], name='fk_recommended_event_job'))
    op.create_index('ix_recommended_event_job', 'recommended_test_events', ['job_id', 'occurred_at', 'id'])
    op.execute('''
CREATE FUNCTION public.protect_recommended_job() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE creator uuid; lifecycle text;
BEGIN
 IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'Recommended test history is immutable'; END IF;
 SELECT creator_id INTO creator FROM public.assessments WHERE id=NEW.assessment_id;
 PERFORM id FROM public.users WHERE id=creator FOR SHARE;
 SELECT status INTO lifecycle FROM public.assessments WHERE id=NEW.assessment_id FOR UPDATE;
 IF TG_OP='INSERT' THEN
  IF lifecycle IS DISTINCT FROM 'Testing' OR NEW.actor_id IS DISTINCT FROM creator OR NEW.status <> 'Queued'
  THEN RAISE EXCEPTION 'Recommended test requires Testing creator consent'; END IF;
 ELSE
  IF ROW(NEW.id,NEW.assessment_id,NEW.target_id,NEW.actor_id,NEW.recommendation_id,NEW.tool,
    NEW.profile_id,NEW.profile_version,NEW.scope_revision,NEW.execution_plan::text,NEW.authorization_snapshot::text,NEW.created_at)
  IS DISTINCT FROM ROW(OLD.id,OLD.assessment_id,OLD.target_id,OLD.actor_id,OLD.recommendation_id,OLD.tool,
    OLD.profile_id,OLD.profile_version,OLD.scope_revision,OLD.execution_plan::text,OLD.authorization_snapshot::text,OLD.created_at)
  OR OLD.status NOT IN ('Queued','Running')
  THEN RAISE EXCEPTION 'Recommended test history is immutable'; END IF;
  IF OLD.process_reference IS NOT NULL AND NEW.process_reference IS DISTINCT FROM OLD.process_reference
  THEN RAISE EXCEPTION 'Recommended process identity is immutable'; END IF;
  IF NEW.status='Completed' AND (NEW.termination_verified IS DISTINCT FROM TRUE OR NEW.output_partial IS DISTINCT FROM FALSE OR NEW.output_digest IS NULL)
  THEN RAISE EXCEPTION 'Recommended completion requires verified output and termination'; END IF;
 END IF;
 IF coalesce(octet_length(NEW.stdout),0)+coalesce(octet_length(NEW.stderr),0)>5242880
 THEN RAISE EXCEPTION 'Recommended output exceeds limit'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.protect_recommended_job() FROM PUBLIC;
CREATE TRIGGER protect_recommended_job BEFORE INSERT OR UPDATE OR DELETE ON public.recommended_test_jobs
FOR EACH ROW EXECUTE FUNCTION public.protect_recommended_job();
CREATE TRIGGER no_truncate_recommended_jobs BEFORE TRUNCATE ON public.recommended_test_jobs
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_execution_history_change();
CREATE TRIGGER immutable_recommended_events BEFORE UPDATE OR DELETE ON public.recommended_test_events
FOR EACH ROW EXECUTE FUNCTION public.reject_execution_history_change();
CREATE TRIGGER no_truncate_recommended_events BEFORE TRUNCATE ON public.recommended_test_events
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_execution_history_change();
GRANT SELECT,INSERT ON public.recommended_test_jobs,public.recommended_test_events TO uptip_runtime;
CREATE FUNCTION public.lock_recommended_assessment_jobs(aid uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM id FROM public.recommended_test_jobs WHERE assessment_id=aid ORDER BY id FOR UPDATE;
END $$;
REVOKE ALL ON FUNCTION public.lock_recommended_assessment_jobs(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.lock_recommended_assessment_jobs(uuid) TO uptip_runtime;
CREATE FUNCTION public.lock_recommended_job_sources(jid uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE aid uuid; actor uuid; target uuid;
BEGIN
 SELECT assessment_id,actor_id,target_id INTO aid,actor,target FROM public.recommended_test_jobs WHERE id=jid;
 IF NOT FOUND THEN RAISE EXCEPTION 'Recommended job unavailable'; END IF;
 PERFORM id FROM public.users WHERE id=actor FOR SHARE;
 PERFORM id FROM public.assessments WHERE id=aid FOR UPDATE;
 PERFORM public.lock_assessment_start_sources();
 PERFORM id FROM public.assessment_targets WHERE id=target AND assessment_id=aid FOR SHARE;
 PERFORM id FROM public.recommended_test_jobs WHERE id=jid FOR UPDATE;
END $$;
REVOKE ALL ON FUNCTION public.lock_recommended_job_sources(uuid) FROM PUBLIC;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='uptip_worker') THEN
 GRANT EXECUTE ON FUNCTION public.lock_recommended_job_sources(uuid) TO uptip_worker;
 GRANT SELECT ON public.testing_recommendation_decisions,public.recommendation_review_events,public.assessment_assignments TO uptip_worker;
 GRANT SELECT ON public.recommended_test_jobs,public.recommended_test_events TO uptip_worker;
 GRANT INSERT ON public.recommended_test_events TO uptip_worker;
 GRANT UPDATE(status,started_at,finished_at,exit_code,failure_reason,stdout,stderr,output_digest,
  termination_verified,output_partial,process_reference,updated_at) ON public.recommended_test_jobs TO uptip_worker;
END IF; END $$;
''')


def downgrade():
    op.execute('''LOCK TABLE public.recommended_test_jobs, public.recommended_test_events IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM public.recommended_test_jobs) OR EXISTS(SELECT 1 FROM public.recommended_test_events)
THEN RAISE EXCEPTION 'Cannot erase recommended test history'; END IF; END $$;''')
    op.drop_table('recommended_test_events')
    op.execute('DROP FUNCTION public.lock_recommended_assessment_jobs(uuid); DROP FUNCTION public.lock_recommended_job_sources(uuid)')
    op.execute('DROP TRIGGER protect_recommended_job ON public.recommended_test_jobs; DROP TRIGGER no_truncate_recommended_jobs ON public.recommended_test_jobs; DROP FUNCTION public.protect_recommended_job()')
    op.drop_constraint('fk_recommended_target_assessment', 'recommended_test_jobs', type_='foreignkey')
    op.drop_constraint('uq_recommended_job_binding', 'recommended_test_jobs', type_='unique')
    for name in ('authorization_snapshot', 'termination_verified', 'output_partial', 'process_reference'): op.drop_column('recommended_test_jobs', name)
