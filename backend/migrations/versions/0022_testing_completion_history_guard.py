"""Protect Testing Completion history without changing runtime grants or 0021.

This revision must remain installed while completion/decision history exists.
The database owner remains trusted for DDL; runtime must never own these tables.
"""
from alembic import op

revision = '0022'
down_revision = '0021'
branch_labels = None
depends_on = None


def upgrade():
    # Reuse the established append-only trigger from execution persistence.
    op.execute('''
CREATE TRIGGER immutable_testing_completion
BEFORE UPDATE OR DELETE ON public.testing_completion_events
FOR EACH ROW EXECUTE FUNCTION public.reject_execution_history_change();
CREATE TRIGGER no_testing_completion_truncate
BEFORE TRUNCATE ON public.testing_completion_events
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_execution_history_change();
CREATE TRIGGER no_testing_decision_delete
BEFORE DELETE ON public.testing_recommendation_decisions
FOR EACH ROW EXECUTE FUNCTION public.reject_execution_history_change();
CREATE TRIGGER no_testing_decision_truncate
BEFORE TRUNCATE ON public.testing_recommendation_decisions
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_execution_history_change();

CREATE FUNCTION public.protect_completed_testing_state() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.status IN ('Draft','Ready','Testing') AND
    (OLD.status='Finding Review' OR EXISTS (
        SELECT 1 FROM public.testing_completion_events WHERE assessment_id=OLD.id))
 THEN RAISE EXCEPTION 'Completed testing cannot be reopened'; END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER protect_completed_testing_state
BEFORE UPDATE OF status ON public.assessments
FOR EACH ROW EXECUTE FUNCTION public.protect_completed_testing_state();

-- Like the existing dispatch lock helper, this narrow trigger uses owner
-- authority only for a fixed parent-state read/lock, not for arbitrary SQL.
CREATE FUNCTION public.protect_testing_decision_history() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE current_state text;
BEGIN
 IF ROW(NEW.assessment_id,NEW.recommendation_id) IS DISTINCT FROM
    ROW(OLD.assessment_id,OLD.recommendation_id)
 THEN RAISE EXCEPTION 'Testing decision identity is immutable'; END IF;
 -- Coordinate with completion's assessment lock; never update a completed
 -- decision using a state read before a concurrent completion committed.
 SELECT status INTO current_state FROM public.assessments
 WHERE id=OLD.assessment_id FOR SHARE;
 IF current_state='Finding Review' OR EXISTS (
     SELECT 1 FROM public.testing_completion_events WHERE assessment_id=OLD.assessment_id)
 THEN RAISE EXCEPTION 'Completed testing decisions are immutable'; END IF;
 RETURN NEW;
END; $$;
REVOKE ALL ON FUNCTION public.protect_testing_decision_history() FROM PUBLIC;
CREATE TRIGGER protect_testing_decision_history
BEFORE UPDATE ON public.testing_recommendation_decisions
FOR EACH ROW EXECUTE FUNCTION public.protect_testing_decision_history();
''')


def downgrade():
    # Locks precede checks and every DDL change, closing the check/drop race.
    # Parent first, consistent with the application completion transaction.
    op.execute('''
LOCK TABLE public.assessments, public.testing_completion_events,
 public.testing_recommendation_decisions IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM public.testing_completion_events)
 OR EXISTS (SELECT 1 FROM public.testing_recommendation_decisions)
 OR EXISTS (SELECT 1 FROM public.assessments WHERE status='Finding Review')
 THEN RAISE EXCEPTION 'Cannot downgrade with Testing Completion history or Finding Review assessments';
 END IF;
END; $$;
DROP TRIGGER protect_testing_decision_history ON public.testing_recommendation_decisions;
DROP FUNCTION public.protect_testing_decision_history();
DROP TRIGGER protect_completed_testing_state ON public.assessments;
DROP FUNCTION public.protect_completed_testing_state();
DROP TRIGGER no_testing_decision_truncate ON public.testing_recommendation_decisions;
DROP TRIGGER no_testing_decision_delete ON public.testing_recommendation_decisions;
DROP TRIGGER no_testing_completion_truncate ON public.testing_completion_events;
DROP TRIGGER immutable_testing_completion ON public.testing_completion_events;
''')
