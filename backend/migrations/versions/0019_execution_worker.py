"""Narrow worker lock capability and immutable recorded process identity.

No worker role creation, worker grants, scanner checks or existing data changes. Operators
grant the capability to a separate least-privilege worker role after review.
"""
from alembic import op

revision = '0019'
down_revision = '0018'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
GRANT SELECT ON public.execution_attempts, public.scanner_evidence,
 public.result_processing_outcomes, public.security_observations, public.execution_events TO uptip_runtime;
CREATE FUNCTION public.lock_execution_dispatch_sources(request_uuid uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE assessment_uuid uuid; actor_uuid uuid;
BEGIN
 SELECT q.assessment_id,a.creator_id INTO assessment_uuid,actor_uuid
 FROM public.baseline_execution_requests q JOIN public.assessments a ON a.id=q.assessment_id
 WHERE q.id=request_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'Execution request unavailable'; END IF;
 PERFORM 1 FROM public.users WHERE id=actor_uuid FOR SHARE;
 PERFORM 1 FROM public.assessments WHERE id=assessment_uuid FOR UPDATE;
 PERFORM public.lock_assessment_start_sources();
 PERFORM 1 FROM public.baseline_execution_requests WHERE id=request_uuid FOR UPDATE;
END; $$;
REVOKE ALL ON FUNCTION public.lock_execution_dispatch_sources(uuid) FROM PUBLIC;
CREATE FUNCTION public.protect_execution_process_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF OLD.process_reference IS NOT NULL AND NEW.process_reference IS DISTINCT FROM OLD.process_reference
 THEN RAISE EXCEPTION 'Recorded process identity is immutable'; END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER protect_execution_process_identity BEFORE UPDATE ON public.execution_attempts
FOR EACH ROW EXECUTE FUNCTION public.protect_execution_process_identity();
""")


def downgrade():
    op.execute('LOCK TABLE public.execution_attempts IN ACCESS EXCLUSIVE MODE')
    op.execute("""DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM public.execution_attempts WHERE process_reference IS NOT NULL)
 THEN RAISE EXCEPTION 'Cannot remove process identity protection with recorded history'; END IF;
 END; $$""")
    op.execute('DROP TRIGGER protect_execution_process_identity ON public.execution_attempts')
    op.execute('DROP FUNCTION public.protect_execution_process_identity()')
    op.execute('DROP FUNCTION public.lock_execution_dispatch_sources(uuid)')
    op.execute('REVOKE SELECT ON public.execution_attempts, public.scanner_evidence, public.result_processing_outcomes, public.security_observations, public.execution_events FROM uptip_runtime')
