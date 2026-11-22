"""Fail-closed consumer for the independent recommended-test queue.

A job is never dispatched merely because it is queued.  This consumer only
claims work after the release policy permits execution and a network boundary
is installed; until then it leaves queued jobs untouched.
"""
from sqlalchemy import select
from .recommended_test_queue import RecommendedTestJob
from .nikto_profile import dispatch_enabled, validate_plan, PROFILE_ID


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
    if (not isinstance(job.execution_plan, dict) or job.status != 'Queued' or job.tool != 'Nikto'
            or job.profile_id != PROFILE_ID or job.profile_version != job.execution_plan.get('profile_version')
            or not validate_plan(job.execution_plan)):
        return False
    return dispatch_enabled(job.execution_plan) and boundary_enforced is True


def fresh_scope_check(db, job):
    """Recheck the stored exact endpoint against current assessment scope.

    This is a prerequisite for any future dispatcher, not an execution grant.
    The assessment row is locked first so scope updates cannot race this check.
    """
    from .recommended_test_authorization import revalidate
    return revalidate(db, job)
