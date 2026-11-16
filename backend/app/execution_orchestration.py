"""Durable, single-process worker orchestration. No lease-based relaunch."""
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import select, text

from .dispatch_verification import DispatchDenied, verify
from .execution_results import evidence, process
from .nmap_adapter import AdapterUnavailable
from .models import Assessment, BaselineExecutionRequest, ExecutionAttempt, ExecutionEvent


def now():
    return datetime.now(timezone.utc)


def event(db, request, attempt, kind, reason, details=None):
    db.add(ExecutionEvent(request_id=request.id, assessment_id=request.assessment_id,
        target_id=request.target_id, attempt_id=attempt.id if attempt else None,
        operation_id=uuid4(), event_type=kind, reason_code=reason,
        system_origin='execution-worker-v1', details=details or {}, occurred_at=now()))
    db.flush()


def locked(db, request_id):
    # Read identifiers only, then lock in the same order as Start: actor,
    # assessment, global sources, request, attempt, processing. Refresh all data.
    ids = db.execute(select(BaselineExecutionRequest.assessment_id, Assessment.creator_id)
        .join(Assessment, Assessment.id == BaselineExecutionRequest.assessment_id)
        .where(BaselineExecutionRequest.id == request_id)).one_or_none()
    if ids is None:
        raise DispatchDenied('execution_not_found')
    db.execute(text('SELECT public.lock_execution_dispatch_sources(:request_id)'), {'request_id': request_id})
    db.scalar(select(Assessment).where(Assessment.id == ids.assessment_id)
              .execution_options(populate_existing=True))
    return db.scalar(select(BaselineExecutionRequest).where(BaselineExecutionRequest.id == request_id)
        .execution_options(populate_existing=True))


def recover_expired(factory):
    # Read IDs without holding out-of-order attempt locks.
    with factory() as db:
        ids = db.scalars(select(ExecutionAttempt.id).where(
            ExecutionAttempt.status.in_(('Claimed', 'Running')),
            ExecutionAttempt.lease_expires_at <= now())).all()
    count = 0
    for attempt_id in ids:
        with factory.begin() as db:
            prior = db.get(ExecutionAttempt, attempt_id)
            request = locked(db, prior.request_id)
            a = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.id == attempt_id)
                .with_for_update().execution_options(populate_existing=True))
            if a.status in ('Claimed', 'Running') and a.lease_expires_at <= now():
                a.status = 'RecoveryRequired'
                a.reason_code = a.recovery_reason = 'lease_expired_process_state_unverified'
                event(db, request, a, 'recovery_required', a.reason_code)
                count += 1
    return count


def claim(factory, request_id, worker_id, timeout):
    if not 1 <= timeout <= 600 or not worker_id or len(worker_id) > 160:
        raise ValueError('Invalid worker claim limits')
    with factory.begin() as db:
        db.execute(text('SELECT pg_advisory_xact_lock(873248902)'))
        request = locked(db, request_id)
        if request.status != 'Queued':
            return None
        if db.scalar(select(ExecutionAttempt.id).where(
                ExecutionAttempt.status.in_(('Claimed', 'Running', 'RecoveryRequired'))).limit(1)):
            return None
        if db.scalar(select(ExecutionAttempt.id).where(ExecutionAttempt.request_id == request.id).limit(1)):
            # Includes expired/uncertain claims: never automatically retry.
            return None
        try:
            decision = verify(db, request)
        except (DispatchDenied, ValueError, KeyError, TypeError) as exc:
            request.status = 'Blocked'
            code = str(exc) if isinstance(exc, DispatchDenied) else 'invalid_dispatch_input'
            event(db, request, None, 'dispatch_blocked', code)
            return None
        timestamp = now()
        a = ExecutionAttempt(id=uuid4(), request_id=request.id, assessment_id=request.assessment_id,
            target_id=request.target_id, attempt_number=1, claim_id=uuid4(), worker_id=worker_id,
            claimed_at=timestamp, heartbeat_at=timestamp, lease_expires_at=timestamp+timedelta(seconds=30),
            status='Claimed', tool=request.tool, profile_id=request.profile_id,
            profile_version=request.profile_version, parameters=decision['plan'],
            parameter_digest=decision['plan']['parameter_digest'], timeout_seconds=timeout)
        db.add(a)
        db.flush()
        event(db, request, a, 'execution_claimed', 'dispatch_checks_verified',
              {'dispatch_policy': {key: decision['dispatch_policy'][key] for key in ('id', 'version', 'digest')},
               'start_snapshot_digest': decision['start_snapshot_digest']})
        return a.id, a.claim_id, decision['plan']


class ExecutionRunner:
    def __init__(self, factory, adapter, store, worker_id, stopped=lambda: False):
        self.factory, self.adapter, self.store, self.worker_id = factory, adapter, store, worker_id
        self.stopped = stopped
        self._launch_db = None

    def run(self, request_id):
        with self.factory() as db:
            if db.scalar(select(ExecutionAttempt.id).where(
                    ExecutionAttempt.status.in_(('Claimed', 'Running', 'RecoveryRequired'))).limit(1)):
                return False
        # Availability and exact executable/version are verified before claiming.
        self.adapter.verify()
        claimed = claim(self.factory, request_id, self.worker_id, self.adapter.config.timeout)
        if claimed is None:
            return False
        attempt_id, claim_id, plan = claimed

        def checked(db):
            request = locked(db, request_id)
            attempt = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.id == attempt_id)
                .with_for_update().execution_options(populate_existing=True))
            verify(db, request, attempt=attempt, worker_id=self.worker_id, claim_id=claim_id)
            if self.stopped():
                raise DispatchDenied('worker_shutdown')
            attempt.heartbeat_at = now()
            attempt.lease_expires_at = now()+timedelta(seconds=30)
            return request, attempt

        @contextmanager
        def guard():
            with self.factory.begin() as db:
                self._launch_db = db
                try:
                    request, attempt = checked(db)
                    # Commit the launch intent and identity together. A worker
                    # crash at any point remains active and requires recovery.
                    attempt.status = 'Running'
                    attempt.started_at = now()
                    attempt.reason_code = 'launch_intent'
                    request.status = 'Running'
                    yield
                finally:
                    self._launch_db = None

        def safe():
            try:
                if self._launch_db is not None:
                    checked(self._launch_db)
                else:
                    with self.factory.begin() as db:
                        checked(db)
                return True
            except Exception:
                return False

        def launched(identity):
            db = self._launch_db
            request = db.get(BaselineExecutionRequest, request_id)
            attempt = db.get(ExecutionAttempt, attempt_id)
            attempt.process_reference = identity
            event(db, request, attempt, 'scanner_started', 'dispatch_verified',
                  {'process_reference': identity, 'executable_sha256': self.adapter.config.sha256,
                   'executable_version': self.adapter.config.version})

        try:
            outcome = self.adapter.run(plan, safe=safe, launched=launched, launch_guard=guard)
        except AdapterUnavailable:
            # The adapter raises this only before Popen. Once a process exists,
            # it returns its bounded output and verified termination outcome.
            with self.factory.begin() as db:
                request = locked(db, request_id)
                a = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.id == attempt_id).with_for_update())
                if a.status == 'Claimed':
                    a.status = 'Blocked'
                    a.finished_at = now()
                    a.reason_code = 'prelaunch_executor_unavailable'
                    request.status = 'Blocked'
                    event(db, request, a, 'dispatch_blocked', a.reason_code)
            return False
        except BaseException:
            # Unknown launch or transaction outcome is never considered proof of
            # termination. No automatic retries, even after a worker restart.
            with self.factory.begin() as db:
                request = locked(db, request_id)
                a = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.id == attempt_id).with_for_update())
                if a.status in ('Claimed', 'Running'):
                    a.status = 'RecoveryRequired'
                    a.reason_code = a.recovery_reason = 'launch_or_persistence_outcome_uncertain'
                    event(db, request, a, 'recovery_required', a.reason_code)
            raise
        with self.factory.begin() as db:
            request = locked(db, request_id)
            a = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.id == attempt_id).with_for_update())
            if a.worker_id != self.worker_id or a.claim_id != claim_id:
                raise DispatchDenied('worker_ownership_lost')
            try:
                verify(db, request, attempt=a, worker_id=self.worker_id, claim_id=claim_id)
            except (DispatchDenied, ValueError, KeyError, TypeError):
                outcome = replace(outcome, partial=True, reason='final_safety_unverified')
            # Preserve bytes even if runtime authorization was lost. Evidence
            # must not become a claim that the operation was still authorized.
            source = evidence(db, a, outcome.stdout, 'nmap-xml', outcome.partial, self.store)
            evidence(db, a, outcome.stderr, 'stderr-text', outcome.partial, self.store)
            event(db, request, a, 'evidence_persisted', outcome.reason, {'evidence_id': str(source.id)})
            if not outcome.terminated or a.status in ('Claimed', 'RecoveryRequired'):
                if a.status != 'RecoveryRequired':
                    a.status = 'RecoveryRequired'
                    a.reason_code = a.recovery_reason = 'termination_unverified'
                    event(db, request, a, 'recovery_required', a.reason_code)
                return False
            a.terminated_at = a.finished_at = now()
            a.termination_outcome = 'process_reaped'
            a.exit_code = outcome.exit_code
            a.reason_code = outcome.reason
            stopped = outcome.reason in ('runtime_safety_lost', 'final_safety_unverified')
            a.status = ('Succeeded' if not outcome.partial and outcome.exit_code == 0
                        else 'Stopped' if stopped else 'Failed')
            db.flush()
            # Scanner success is distinct from processing success.
            result = process(db, a, source, outcome.stdout)
            if request.status not in ('Cancelled', 'Stopped', 'Blocked'):
                request.status = ('Completed' if a.status == 'Succeeded' and result.status == 'Succeeded'
                                  else 'Stopped' if stopped else 'Failed')
            event(db, request, a, 'execution_finished', request.status.lower(),
                  {'scanner_outcome': a.status, 'processing_outcome': result.status})
        return True
