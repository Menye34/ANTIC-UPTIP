"""Read-only Testing views backed by persisted execution requests."""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .assessment_routes import accessible, analyst
from .database import get_db
from .models import (Assessment, AssessmentStartAuthorization, BaselineExecutionRequest, User,
                     ExecutionAttempt, ScannerEvidence, ResultProcessingOutcome, SecurityObservation, ExecutionEvent)

router = APIRouter(prefix='/api/v1/assessments/{assessment_id}/testing')


def assessment_for(db, assessment_id, user):
    assessment = db.scalar(select(Assessment).where(Assessment.id == assessment_id, accessible(user)))
    if assessment is None:
        raise HTTPException(404)
    return assessment


def execution_view(request):
    snapshot = request.authorized_activity
    return {
        'id': request.id, 'target_id': request.target_id, 'profile_id': request.profile_id,
        'profile_version': request.profile_version, 'test_name': request.activity, 'tool': request.tool,
        'target': snapshot['target_value'], 'status': request.status,
        'authorization_id': request.authorization_id, 'created_at': request.created_at,
        'updated_at': request.updated_at, 'execution_authorized': False,
    }


@router.get('')
def testing_overview(assessment_id: UUID, user: User = Depends(analyst), db: Session = Depends(get_db)):
    # One SQL statement observes one PostgreSQL snapshot, including authorization
    # and every execution row. A concurrent Start cannot split this response.
    discoveries = select(func.json_agg(func.json_build_object(
        'id', SecurityObservation.id, 'execution_id', SecurityObservation.request_id,
        'target_id', SecurityObservation.target_id, 'type', SecurityObservation.observation_type,
        'data', SecurityObservation.data, 'partial', SecurityObservation.is_partial)))\
        .where(SecurityObservation.assessment_id == Assessment.id).correlate(Assessment).scalar_subquery()
    rows = db.execute(
        select(Assessment, AssessmentStartAuthorization, BaselineExecutionRequest, discoveries)
        .outerjoin(AssessmentStartAuthorization,
                   AssessmentStartAuthorization.assessment_id == Assessment.id)
        .outerjoin(BaselineExecutionRequest, BaselineExecutionRequest.assessment_id == Assessment.id)
        .where(Assessment.id == assessment_id, accessible(user))
        .order_by(BaselineExecutionRequest.created_at, BaselineExecutionRequest.id)
        .execution_options(populate_existing=True)
    ).all()
    if not rows:
        raise HTTPException(404)
    assessment, authorization, _, observations = rows[0]
    requests = [row[2] for row in rows if row[2] is not None]
    counts = {state: sum(item.status == state for item in requests) for state in
              ('Queued', 'Running', 'Completed', 'Failed', 'Stopped', 'Blocked', 'Cancelled')}
    snapshot = authorization.snapshot if authorization else {}
    return {
        'assessment_id': assessment_id, 'lifecycle_status': assessment.status,
        'counts': {'total': len(requests), 'in_progress': counts['Running'],
                   'completed': counts['Completed'], 'failed': counts['Failed'],
                   'queued': counts['Queued'], 'stopped': counts['Stopped'],
                   'blocked': counts['Blocked'], 'cancelled': counts['Cancelled']},
        'executions': [execution_view(item) for item in requests],
        'authorization_scope': {
            'authorization_id': authorization.id if authorization else None,
            'scope_revision': snapshot.get('scope_revision'), 'scope_digest': snapshot.get('scope_digest'),
            'mode': snapshot.get('mode'), 'policy': snapshot.get('policy'),
            'excluded_activities': snapshot.get('excluded_activities', []),
            'excluded_targets': snapshot.get('excluded_targets', []),
        },
        'discovered_so_far': observations or [],
        'recent_activity': [
            {'event': 'execution_queued', 'execution_id': item.id, 'occurred_at': item.created_at}
            for item in reversed(requests[-20:])
        ],
    }


@router.get('/executions')
def list_executions(assessment_id: UUID, user: User = Depends(analyst), db: Session = Depends(get_db)):
    assessment_for(db, assessment_id, user)
    return [execution_view(item) for item in db.scalars(select(BaselineExecutionRequest)
            .where(BaselineExecutionRequest.assessment_id == assessment_id)
            .order_by(BaselineExecutionRequest.created_at, BaselineExecutionRequest.id))]


@router.get('/executions/{execution_id}')
def execution_details(assessment_id: UUID, execution_id: UUID,
                      user: User = Depends(analyst), db: Session = Depends(get_db)):
    assessment_for(db, assessment_id, user)
    request = db.scalar(select(BaselineExecutionRequest).where(
        BaselineExecutionRequest.id == execution_id, BaselineExecutionRequest.assessment_id == assessment_id,
    ))
    if request is None:
        raise HTTPException(404)
    attempts = db.scalars(select(ExecutionAttempt).where(
        ExecutionAttempt.request_id == execution_id, ExecutionAttempt.assessment_id == assessment_id)
        .order_by(ExecutionAttempt.attempt_number)).all()
    evidence = db.scalars(select(ScannerEvidence).where(
        ScannerEvidence.request_id == execution_id, ScannerEvidence.assessment_id == assessment_id)
        .order_by(ScannerEvidence.collected_at)).all()
    processing = db.scalars(select(ResultProcessingOutcome).where(
        ResultProcessingOutcome.request_id == execution_id, ResultProcessingOutcome.assessment_id == assessment_id)
        .order_by(ResultProcessingOutcome.created_at)).all()
    observations = db.scalars(select(SecurityObservation).where(
        SecurityObservation.request_id == execution_id, SecurityObservation.assessment_id == assessment_id)).all()
    events = db.scalars(select(ExecutionEvent).where(
        ExecutionEvent.request_id == execution_id, ExecutionEvent.assessment_id == assessment_id)
        .order_by(ExecutionEvent.occurred_at, ExecutionEvent.id)).all()
    # No stdout/stderr, storage paths, worker process identity or secrets.
    return {**execution_view(request), 'authorized_activity': request.authorized_activity,
            'dispatch_status': 'requires_fresh_authorization',
            'attempts': [{'id': a.id, 'attempt_number': a.attempt_number, 'status': a.status,
                'claimed_at': a.claimed_at, 'started_at': a.started_at, 'finished_at': a.finished_at,
                'exit_code': a.exit_code, 'reason_code': a.reason_code,
                'termination_outcome': a.termination_outcome, 'recovery_reason': a.recovery_reason} for a in attempts],
            'evidence': [{'id': e.id, 'attempt_id': e.attempt_id, 'format': e.format,
                'sha256': e.content_hash, 'size_bytes': e.size_bytes, 'partial': e.is_partial,
                'collected_at': e.collected_at} for e in evidence],
            'processing': [{'id': p.id, 'evidence_id': p.evidence_id, 'status': p.status,
                'processor': p.processor, 'version': p.processor_version, 'error_code': p.error_code,
                'observation_count': p.observation_count, 'partial': p.is_partial} for p in processing],
            'observations': [{'id': o.id, 'type': o.observation_type, 'data': o.data,
                              'partial': o.is_partial, 'evidence_id': o.evidence_id} for o in observations],
            'events': [{'id': e.id, 'event': e.event_type, 'reason_code': e.reason_code,
                        'occurred_at': e.occurred_at, 'attempt_id': e.attempt_id} for e in events]}
