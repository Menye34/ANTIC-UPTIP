"""Fail-closed consumer for the independent recommended-test queue.

A job is never dispatched merely because it is queued.  This consumer only
claims work after the release policy permits execution and a network boundary
is installed; until then it leaves queued jobs untouched.
"""
from sqlalchemy import select
from .recommended_test_queue import RecommendedTestJob
from .nikto_profile import authority, validate_plan, PROFILE_ID, VERSION


def pending_ids(db, limit=100):
    """List jobs independently of assessment-start scheduling."""
    return db.scalars(select(RecommendedTestJob.id)
        .where(RecommendedTestJob.status == 'Queued')
        .order_by(RecommendedTestJob.created_at, RecommendedTestJob.id)
        .limit(limit)).all()


def dispatch_readiness(job, *, boundary_enforced=False):
    """Verify the immutable profile and mandatory network isolation.

    A false result must not change the job status to Running or launch a tool.
    """
    if (job.status != 'Queued' or job.tool != 'Nikto'
            or job.profile_id != PROFILE_ID or job.profile_version != VERSION
            or not validate_plan(job.execution_plan)):
        return False
    policy = authority()
    return policy['execution_enabled'] is True and boundary_enforced is True


def fresh_scope_check(db, job):
    """Recheck the stored exact endpoint against current assessment scope.

    This is a prerequisite for any future dispatcher, not an execution grant.
    The assessment row is locked first so scope updates cannot race this check.
    """
    from .models import Assessment, AssessmentTarget
    from .target_scope import classify, scope_entries

    assessment = db.scalar(select(Assessment).where(
        Assessment.id == job.assessment_id).with_for_update())
    if assessment is None or assessment.status != 'Testing':
        return False
    target = db.scalar(select(AssessmentTarget).where(
        AssessmentTarget.id == job.target_id,
        AssessmentTarget.assessment_id == assessment.id).with_for_update())
    if (target is None or target.kind != 'IP address'
            or target.scope_status != 'in_scope'
            or target.scope_revision != assessment.scope_revision
            or job.scope_revision != assessment.scope_revision
            or not validate_plan(job.execution_plan)
            or target.normalized_value != job.execution_plan['target']):
        return False
    try:
        return classify(target.normalized_value, target.kind,
                        scope_entries(db, assessment.id))[0] == 'in_scope'
    except (ValueError, TypeError):
        return False
