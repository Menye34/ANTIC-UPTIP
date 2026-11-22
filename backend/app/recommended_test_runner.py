"""Single-attempt, fail-closed recommended test runner.

The caller must supply an independently enforced endpoint network boundary.
This module never grants scope or starts an uncontained scanner.
"""
from contextlib import contextmanager
from sqlalchemy import select

from .recommended_test_queue import RecommendedTestJob
from .recommended_test_consumer import dispatch_readiness, fresh_scope_check
from .recommended_test_results import mark_running, record_outcome


class RecommendedTestRunner:
    def __init__(self, factory, adapter, *, boundary, stopping=lambda: False):
        self.factory = factory
        self.adapter = adapter
        self.boundary = boundary
        self.stopping = stopping

    def run(self, job_id):
        """Claim once; a crash after claim must never silently relaunch a scan."""
        if self.stopping() or self.boundary is None:
            return False
        with self.factory.begin() as db:
            job = db.scalar(select(RecommendedTestJob).where(
                RecommendedTestJob.id == job_id).with_for_update())
            if (job is None or not dispatch_readiness(job, boundary_enforced=self.boundary.enforced)
                    or not fresh_scope_check(db, job)):
                return False
            plan = dict(job.execution_plan)
            mark_running(job)
        # No automatic retry: a crash after the claim leaves Running for manual
        # reconciliation, rather than risking duplicate security scans.
        def safe():
            if self.stopping():
                return False
            try:
                with self.factory.begin() as db:
                    job = db.scalar(select(RecommendedTestJob).where(
                        RecommendedTestJob.id == job_id).with_for_update())
                    return (job is not None and job.status == 'Running'
                            and job.execution_plan == plan and fresh_scope_check(db, job)
                            and self.boundary.enforced)
            except Exception:
                return False

        try:
            with self.boundary.restrict(plan['target'], plan['port']):
                if not safe():
                    raise RuntimeError('recommended_scope_or_boundary_lost')
                outcome = self.adapter.run(plan, safe=safe, launched=lambda _: None)
        except Exception:
            with self.factory.begin() as db:
                job = db.scalar(select(RecommendedTestJob).where(
                    RecommendedTestJob.id == job_id).with_for_update())
                if job is not None and job.status == 'Running':
                    job.status = 'Failed'
                    job.failure_reason = 'executor_unavailable_or_boundary_lost'
            return False
        with self.factory.begin() as db:
            job = db.scalar(select(RecommendedTestJob).where(
                RecommendedTestJob.id == job_id).with_for_update())
            if job is None or job.status != 'Running':
                return False
            record_outcome(job, outcome)
        return True
