"""Single-attempt recommended execution under a real child network boundary."""
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import logging
from sqlalchemy import select, text
from .models import ExecutionAttempt
from .recommended_test_queue import RecommendedTestJob, RecommendedTestEvent
from .recommended_test_consumer import dispatch_readiness, fresh_scope_check
from .recommended_test_results import mark_running, record_outcome
from .nmap_adapter import AdapterUnavailable

logger = logging.getLogger(__name__)


def event(db, job, kind, reason):
    db.add(RecommendedTestEvent(job_id=job.id, assessment_id=job.assessment_id,
        target_id=job.target_id, event_type=kind, reason_code=reason, occurred_at=datetime.now(timezone.utc)))
    db.flush()


def locked(db, job_id):
    ids = db.execute(select(RecommendedTestJob.actor_id, RecommendedTestJob.assessment_id)
                     .where(RecommendedTestJob.id == job_id)).one_or_none()
    if ids is None: return None
    db.execute(text('SELECT public.lock_recommended_job_sources(:id)'), {'id': job_id})
    return db.scalar(select(RecommendedTestJob).where(RecommendedTestJob.id == job_id)
        .with_for_update().execution_options(populate_existing=True))


class RecommendedTestRunner:
    def __init__(self, factory, adapter, *, boundary, stopping=lambda: False):
        self.factory, self.adapter, self.boundary, self.stopping = factory, adapter, boundary, stopping

    def run(self, job_id):
        if self.stopping() or self.boundary is None: return False
        with self.factory() as db:
            job = db.get(RecommendedTestJob, job_id)
            if job is None or job.status != 'Queued':
                return False
            if not dispatch_readiness(job, boundary_enforced=True):
                # A valid queued job may simply be awaiting release.
                # Invalidate only jobs whose previously accepted policy
                # is no longer current.
                from .nikto_profile import validate_plan, dispatch_enabled
                if validate_plan(job.execution_plan) and not dispatch_enabled(job.execution_plan):
                    with self.factory.begin() as locked_db:
                        current = locked(locked_db, job_id)
                        if (current is not None and current.status == 'Queued'
                                and validate_plan(current.execution_plan)
                                and not dispatch_enabled(current.execution_plan)):
                            current.status = 'Blocked'
                            current.failure_reason = 'recommended_authorization_unverified'
                            event(locked_db, current, 'dispatch_blocked', current.failure_reason)
                return False
            plan = dict(job.execution_plan)
        claimed = False
        launched = False
        try:
            # The context establishes namespaces and firewall before any scanner.
            # The adapter independently requires and enters these pinned namespaces.
            with self.boundary.restrict(plan['target'], plan['port']):
                with self.factory.begin() as db:
                    db.execute(text('SELECT pg_advisory_xact_lock(873248902)'))
                    if db.scalar(select(ExecutionAttempt.id).where(ExecutionAttempt.status.in_(('Claimed','Running','RecoveryRequired'))).limit(1)):
                        return False
                    if db.scalar(select(RecommendedTestJob.id).where(RecommendedTestJob.status == 'Running').limit(1)):
                        return False
                    job = locked(db, job_id)
                    if job is None or job.status != 'Queued' or self.stopping():
                        return False
                    if (not dispatch_readiness(job, boundary_enforced=self.boundary.enforced)
                            or job.execution_plan != plan or not fresh_scope_check(db, job)):
                        job.status = 'Blocked'
                        job.failure_reason = 'recommended_authorization_unverified'
                        event(db, job, 'dispatch_blocked', job.failure_reason)
                        return False
                    mark_running(job)
                    event(db, job, 'execution_claimed', 'recommended_dispatch_verified')
                claimed = True

                launch_db = None

                def checked(db):
                    job = locked(db, job_id)
                    if (self.stopping() or not self.boundary.enforced or not job or job.status != 'Running'
                            or job.execution_plan != plan or not fresh_scope_check(db, job)):
                        raise AdapterUnavailable('recommended_prelaunch_authorization_lost')
                    return job

                @contextmanager
                def guard():
                    nonlocal launch_db
                    with self.factory.begin() as db:
                        launch_db = db
                        try:
                            checked(db)
                            # Keep parent/input locks through Popen and identity recording.
                            yield
                        finally:
                            launch_db = None

                def safe():
                    try:
                        if launch_db is not None:
                            checked(launch_db)
                        else:
                            with self.factory.begin() as db: checked(db)
                        return True
                    except Exception:
                        return False

                def started(identity):
                    nonlocal launched
                    launched = True
                    if launch_db is None: raise AdapterUnavailable('recommended_launch_guard_required')
                    job = checked(launch_db)
                    job.process_reference = identity
                    event(launch_db, job, 'scanner_started', 'recommended_dispatch_verified')

                if not safe(): raise AdapterUnavailable('recommended_prelaunch_authorization_lost')
                outcome = self.adapter.run(plan, safe=safe, launched=started, launch_guard=guard)
                if not safe(): outcome = replace(outcome, partial=True, reason='final_safety_unverified')
            with self.factory.begin() as db:
                job = locked(db, job_id)
                if job is None or job.status != 'Running': return False
                record_outcome(job, outcome)
                event(db, job, 'execution_finished' if outcome.terminated else 'recovery_required',
                      job.failure_reason or 'scanner_output_recorded')
            # Independent post-commit processing cannot roll back a completed scan.
            # A failed parser leaves the original output available for investigation.
            try:
                from .recommended_normalization import process_job
                with self.factory.begin() as db:
                    process_job(db, job_id)
            except Exception:
                logger.exception('recommended_result_normalization_failed job_id=%s', job_id)
            return True
        except Exception as exc:
            if claimed:
                with self.factory.begin() as db:
                    job = locked(db, job_id)
                    if job and job.status == 'Running':
                        # Unknown postlaunch outcomes block both queues after restart.
                        job.failure_reason = 'launch_or_termination_unverified' if launched else 'executor_unavailable_or_boundary_lost'
                        if not launched: job.status = 'Blocked'
                        event(db, job, 'recovery_required' if launched else 'dispatch_blocked', job.failure_reason)
            elif isinstance(exc, AdapterUnavailable):
                with self.factory.begin() as db:
                    job = locked(db, job_id)
                    if job and job.status == 'Queued':
                        job.status = 'Blocked'
                        job.failure_reason = 'network_boundary_unavailable'
                        event(db, job, 'dispatch_blocked', job.failure_reason)
            return False
