"""Read-only Testing views backed by persisted execution requests."""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select, and_
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import aggregate_order_by

from .assessment_routes import accessible, analyst
from .database import get_db
from .models import (ScopeEntry, Assessment, AssessmentStartAuthorization, BaselineExecutionRequest, User,
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
    # Keep the event timeline in the same PostgreSQL statement/snapshot as the
    # assessment, authorization, requests, and observations. Never expose event
    # details, process identities, or worker internals in this overview.
    recent_events = (select(
        ExecutionEvent.request_id.label('execution_id'),
        ExecutionEvent.event_type.label('event'),
        ExecutionEvent.occurred_at.label('occurred_at'),
        ExecutionEvent.id.label('event_id'),
    ).where(ExecutionEvent.assessment_id == Assessment.id)
     .order_by(ExecutionEvent.occurred_at.desc(), ExecutionEvent.id.desc())
     .limit(20).correlate(Assessment).lateral('recent_execution_events'))
    activity = (select(func.json_agg(func.json_build_object(
        'event', recent_events.c.event,
        'execution_id', recent_events.c.execution_id,
        'occurred_at', recent_events.c.occurred_at,
    ))).select_from(recent_events).scalar_subquery())
    boundaries = select(func.json_agg(func.json_build_object('value', ScopeEntry.normalized_value,
        'kind', ScopeEntry.kind))).where(ScopeEntry.assessment_id == Assessment.id).correlate(Assessment).scalar_subquery()
    actor = select(User.username).where(User.id == AssessmentStartAuthorization.actor_id).correlate(AssessmentStartAuthorization).scalar_subquery()
    trusted = (select(func.json_agg(func.json_build_object('target_id', SecurityObservation.target_id,
        'type', SecurityObservation.observation_type, 'data', SecurityObservation.data)))
        .select_from(SecurityObservation)
        .join(ResultProcessingOutcome, and_(ResultProcessingOutcome.id == SecurityObservation.processing_id,
            ResultProcessingOutcome.evidence_id == SecurityObservation.evidence_id,
            ResultProcessingOutcome.attempt_id == SecurityObservation.attempt_id,
            ResultProcessingOutcome.request_id == SecurityObservation.request_id,
            ResultProcessingOutcome.target_id == SecurityObservation.target_id,
            ResultProcessingOutcome.assessment_id == SecurityObservation.assessment_id))
        .join(ScannerEvidence, and_(ScannerEvidence.id == SecurityObservation.evidence_id,
            ScannerEvidence.attempt_id == SecurityObservation.attempt_id,
            ScannerEvidence.request_id == SecurityObservation.request_id,
            ScannerEvidence.target_id == SecurityObservation.target_id,
            ScannerEvidence.assessment_id == SecurityObservation.assessment_id))
        .join(ExecutionAttempt, and_(ExecutionAttempt.id == SecurityObservation.attempt_id,
            ExecutionAttempt.request_id == SecurityObservation.request_id,
            ExecutionAttempt.target_id == SecurityObservation.target_id,
            ExecutionAttempt.assessment_id == SecurityObservation.assessment_id))
        .join(BaselineExecutionRequest, and_(BaselineExecutionRequest.id == SecurityObservation.request_id,
            BaselineExecutionRequest.target_id == SecurityObservation.target_id,
            BaselineExecutionRequest.assessment_id == SecurityObservation.assessment_id))
        .where(SecurityObservation.assessment_id == Assessment.id,
            SecurityObservation.is_partial.is_(False), ScannerEvidence.is_partial.is_(False),
            ResultProcessingOutcome.is_partial.is_(False), ResultProcessingOutcome.status == 'Succeeded',
            BaselineExecutionRequest.status == 'Completed', ExecutionAttempt.status == 'Succeeded').correlate(Assessment).scalar_subquery())
    service_processed = (select(ResultProcessingOutcome.id)
        .join(ScannerEvidence, and_(ScannerEvidence.id == ResultProcessingOutcome.evidence_id,
            ScannerEvidence.attempt_id == ResultProcessingOutcome.attempt_id,
            ScannerEvidence.request_id == ResultProcessingOutcome.request_id,
            ScannerEvidence.target_id == ResultProcessingOutcome.target_id,
            ScannerEvidence.assessment_id == ResultProcessingOutcome.assessment_id))
        .join(ExecutionAttempt, and_(ExecutionAttempt.id == ResultProcessingOutcome.attempt_id,
            ExecutionAttempt.request_id == ResultProcessingOutcome.request_id,
            ExecutionAttempt.target_id == ResultProcessingOutcome.target_id,
            ExecutionAttempt.assessment_id == ResultProcessingOutcome.assessment_id))
        .join(BaselineExecutionRequest,
        and_(BaselineExecutionRequest.id == ResultProcessingOutcome.request_id,
             BaselineExecutionRequest.assessment_id == ResultProcessingOutcome.assessment_id,
             BaselineExecutionRequest.target_id == ResultProcessingOutcome.target_id)).where(
        ResultProcessingOutcome.assessment_id == Assessment.id, ResultProcessingOutcome.status == 'Succeeded',
        ResultProcessingOutcome.is_partial.is_(False), BaselineExecutionRequest.status == 'Completed',
        BaselineExecutionRequest.profile_id == 'service-discovery', ScannerEvidence.is_partial.is_(False),
        ExecutionAttempt.status == 'Succeeded').correlate(Assessment).exists())
    from .recommended_testing_reads import overview_jobs, overview_events, execution_view as recommended_view
    rows = db.execute(
        select(Assessment, AssessmentStartAuthorization, BaselineExecutionRequest, discoveries, activity,
               boundaries, actor, trusted, service_processed, overview_jobs(), overview_events())
        .outerjoin(AssessmentStartAuthorization,
                   AssessmentStartAuthorization.assessment_id == Assessment.id)
        .outerjoin(BaselineExecutionRequest, BaselineExecutionRequest.assessment_id == Assessment.id)
        .where(Assessment.id == assessment_id, accessible(user))
        .order_by(BaselineExecutionRequest.created_at, BaselineExecutionRequest.id)
        .execution_options(populate_existing=True)
    ).all()
    if not rows:
        raise HTTPException(404)
    assessment, authorization, _, observations, event_activity, boundary_rows, actor_name, verified, processed, recommended, recommended_events = rows[0]
    event_activity = (event_activity or []) + (recommended_events or [])
    requests = [row[2] for row in rows if row[2] is not None]
    executions = [execution_view(item) for item in requests] + [recommended_view(item) for item in recommended or []]
    counts = {state: sum(item['status'] == state for item in executions) for state in
              ('Queued', 'Running', 'Completed', 'Failed', 'Stopped', 'Blocked', 'Cancelled')}
    snapshot = authorization.snapshot if authorization else {}
    from .baseline_catalog import fingerprint
    boundary_rows = sorted(boundary_rows or [], key=lambda b: (b['value'], b['kind']))
    scope_current = bool(authorization and assessment.scope_revision == snapshot.get('scope_revision')
        and fingerprint(sorted([[b['value'], b['kind']] for b in boundary_rows])) == snapshot.get('scope_digest'))
    from .testing_read_summary import discovery_totals
    return {
        'assessment_id': assessment_id, 'lifecycle_status': assessment.status,
        # Permission to request preparation, not proof of dispatch eligibility.
        'can_schedule_service_discovery': bool(assessment.status == 'Testing'
            and assessment.creator_id == user.id and authorization is not None),
        'counts': {'total': len(executions), 'in_progress': counts['Running'],
                   'completed': counts['Completed'], 'failed': counts['Failed'],
                   'queued': counts['Queued'], 'stopped': counts['Stopped'],
                   'blocked': counts['Blocked'], 'cancelled': counts['Cancelled']},
        'executions': sorted(executions, key=lambda item: (str(item['created_at']),str(item['id']))),
        'authorization_scope': {
            'authorization_id': authorization.id if authorization else None,
            'boundaries': boundary_rows if scope_current else None,
            'scope_current': scope_current,
            'authorized_by': {'id': str(authorization.actor_id), 'username': actor_name,
                              'confirmed_at': authorization.confirmed_at.isoformat()} if authorization and actor_name else None,
            'scope_revision': snapshot.get('scope_revision'), 'scope_digest': snapshot.get('scope_digest'),
            'mode': snapshot.get('mode'), 'policy': snapshot.get('policy'),
            'excluded_activities': snapshot.get('excluded_activities', []),
            'excluded_targets': snapshot.get('excluded_targets', []),
        },
        'discovered_so_far': observations or [],
        'discovery_totals': discovery_totals(verified or [], bool(processed)),
        'recent_activity': sorted(
            (event_activity or []) + [
                {'event': 'execution_queued', 'execution_id': item.id,
                 'occurred_at': item.created_at.isoformat()}
                for item in requests if item.status == 'Queued'
            ],
            key=lambda entry: (str(entry['occurred_at']), str(entry['execution_id'])),
            reverse=True,
        )[:20],
    }


@router.get('/executions')
def list_executions(assessment_id: UUID, user: User = Depends(analyst), db: Session = Depends(get_db)):
    return testing_overview(assessment_id, user, db)['executions']


@router.get('/executions/{execution_id}')
def execution_details(assessment_id: UUID, execution_id: UUID,
                      user: User = Depends(analyst), db: Session = Depends(get_db)):
    def collection(model, fields):
        values = [value for key, field in fields.items() for value in (key, getattr(model, field))]
        ordering = {'execution_attempts': [model.attempt_number] if model is ExecutionAttempt else [],
                    'scanner_evidence': [model.collected_at, model.id] if model is ScannerEvidence else [],
                    'result_processing_outcomes': [model.created_at, model.id] if model is ResultProcessingOutcome else [],
                    'security_observations': [model.id],
                    'execution_events': [model.occurred_at, model.id] if model is ExecutionEvent else []}[model.__tablename__]
        return select(func.json_agg(aggregate_order_by(func.json_build_object(*values), *ordering))).where(
            model.request_id == BaselineExecutionRequest.id,
            model.assessment_id == BaselineExecutionRequest.assessment_id,
            model.target_id == BaselineExecutionRequest.target_id).correlate(BaselineExecutionRequest).scalar_subquery()
    attempts = collection(ExecutionAttempt, {k: k for k in ('id','attempt_number','status','claimed_at',
        'started_at','finished_at','exit_code','reason_code','termination_outcome','recovery_reason')})
    evidence = collection(ScannerEvidence, {'id':'id','attempt_id':'attempt_id','format':'format',
        'sha256':'content_hash','size_bytes':'size_bytes','partial':'is_partial','collected_at':'collected_at'})
    processing = collection(ResultProcessingOutcome, {'id':'id','evidence_id':'evidence_id','status':'status',
        'processor':'processor','version':'processor_version','error_code':'error_code',
        'observation_count':'observation_count','partial':'is_partial'})
    observations = collection(SecurityObservation, {'id':'id','type':'observation_type','data':'data',
        'partial':'is_partial','evidence_id':'evidence_id'})
    events = collection(ExecutionEvent, {'id':'id','event':'event_type','reason_code':'reason_code',
        'occurred_at':'occurred_at','attempt_id':'attempt_id'})
    row = db.execute(select(BaselineExecutionRequest, attempts, evidence, processing, observations, events)
        .join(Assessment, Assessment.id == BaselineExecutionRequest.assessment_id)
        .where(Assessment.id == assessment_id, accessible(user), BaselineExecutionRequest.id == execution_id)
        .execution_options(populate_existing=True)).one_or_none()
    if row is None:
        from .recommended_testing_reads import details
        return details(db, assessment_id, execution_id, user)
    request, attempts, evidence, processing, observations, events = row
    from .testing_read_summary import dispatch_history
    return {**execution_view(request), 'authorized_activity': request.authorized_activity,
        **dispatch_history(events or []),
        'attempts': sorted(attempts or [], key=lambda a: a['attempt_number']),
        'evidence': sorted(evidence or [], key=lambda e: (e['collected_at'], e['id'])),
        'processing': processing or [],
        'observations': sorted(observations or [], key=lambda o: o['id']),
        'events': sorted(events or [], key=lambda e: (e['occurred_at'], e['id']))}


@router.get('/executions/{execution_id}/evidence/{evidence_id}')
def original_evidence(assessment_id: UUID, execution_id: UUID, evidence_id: UUID,
                      user: User = Depends(analyst), db: Session = Depends(get_db)):
    source = db.scalar(select(ScannerEvidence)
        .join(BaselineExecutionRequest, and_(BaselineExecutionRequest.id == ScannerEvidence.request_id,
            BaselineExecutionRequest.assessment_id == ScannerEvidence.assessment_id,
            BaselineExecutionRequest.target_id == ScannerEvidence.target_id,
            BaselineExecutionRequest.tool == ScannerEvidence.tool))
        .join(ExecutionAttempt, and_(ExecutionAttempt.id == ScannerEvidence.attempt_id,
            ExecutionAttempt.request_id == ScannerEvidence.request_id,
            ExecutionAttempt.assessment_id == ScannerEvidence.assessment_id,
            ExecutionAttempt.target_id == ScannerEvidence.target_id))
        .join(Assessment, Assessment.id == ScannerEvidence.assessment_id)
        .where(Assessment.id == assessment_id, accessible(user), ScannerEvidence.id == evidence_id,
               BaselineExecutionRequest.id == execution_id))
    if source is None:
        from .recommended_testing_reads import original
        return original(db, assessment_id, execution_id, evidence_id, user)
    from .config import get_settings
    from .evidence_reading import EvidenceUnavailable, read_original
    try:
        content = read_original(source, get_settings().evidence_read_directory)
    except EvidenceUnavailable:
        raise HTTPException(503, detail={'code': 'original_evidence_unavailable'}) from None
    return {'assessment_id': assessment_id, 'execution_id': execution_id, 'evidence_id': evidence_id,
            'sha256': source.content_hash, 'size_bytes': source.size_bytes, 'format': source.format,
            'partial': source.is_partial, 'content': content}


# Recommendations — read-only endpoints.

@router.get('/recommendations')
def list_recommendations(
    assessment_id: UUID,
    user: User = Depends(analyst),
    db: Session = Depends(get_db),
):
    from .testing_completion_service import recommendation_state
    return recommendation_state(db, assessment_id, user)


@router.get('/recommendations/{recommendation_id}/eligibility')
def recommendation_eligibility(
    assessment_id: UUID,
    recommendation_id: str,
    user: User = Depends(analyst),
    db: Session = Depends(get_db),
):
    from .recommendation_eligibility import evaluate_recommendation

    assessment_for(db, assessment_id, user)

    from .testing_completion_service import trusted_recommendation_observations
    observations = trusted_recommendation_observations(db, assessment_id)

    result = evaluate_recommendation(recommendation_id, observations)

    if result['reason_code'] == 'invalid_recommendation_id':
        raise HTTPException(422, detail='Invalid recommendation identifier')

    if result['reason_code'] == 'recommendation_not_current':
        raise HTTPException(404, detail='Recommendation unavailable')

    return {'assessment_id': assessment_id, **result}


@router.get('/recommendations/{recommendation_id}/authorization-review')
def recommendation_authorization_review(
    assessment_id: UUID,
    recommendation_id: str,
    user: User = Depends(analyst),
    db: Session = Depends(get_db),
):
    from .recommendation_authorization_review import review_authorization

    assessment = assessment_for(db, assessment_id, user)
    result = review_authorization(db, assessment, recommendation_id)

    if result['reason_code'] == 'invalid_recommendation_id':
        raise HTTPException(422, detail='Invalid recommendation identifier')

    if result['reason_code'] == 'recommendation_not_current':
        raise HTTPException(404, detail='Recommendation unavailable')

    return {'assessment_id': assessment_id, **result}


def recommended_receipt(job, replay=False):
    return {'id': job.id, 'assessment_id': job.assessment_id, 'recommendation_id': job.recommendation_id,
            'status': job.status, 'tool': job.tool, 'already_requested': replay,
            'execution_authorized': False}


@router.get('/recommendations/{recommendation_id}/start-readiness')
def recommended_start_readiness(assessment_id: UUID, recommendation_id: str,
    user: User = Depends(analyst), db: Session = Depends(get_db)):
    from .recommended_test_authorization import preparation, StartUnavailable
    from .nikto_profile import dispatch_enabled
    from .baseline_catalog import fingerprint
    assessment_for(db, assessment_id, user)
    db.scalar(select(Assessment).where(Assessment.id == assessment_id).with_for_update(read=True))
    result = {'assessment_id': assessment_id, 'recommendation_id': recommendation_id,
              'ready': False, 'reason_code': 'execution_integration_pending',
              'snapshot_digest': None, 'configured_profile': None, 'endpoint': None}
    try:
        facts = preparation(db, assessment_id, user.id, recommendation_id, lock=False)
    except StartUnavailable as exc:
        result['reason_code'] = str(exc)
        return result
    result.update(snapshot_digest=fingerprint(facts), configured_profile='Web Server Security Checks',
                  endpoint=facts['plan']['endpoint_preview'])
    from .recommended_test_queue import RecommendedTestJob
    existing = db.scalar(select(RecommendedTestJob).where(RecommendedTestJob.assessment_id == assessment_id,
        RecommendedTestJob.recommendation_id == recommendation_id))
    if existing is not None:
        result['reason_code'] = 'recommended_already_requested' if existing.execution_plan == facts['plan'] else 'recommended_existing_policy_stale'
    elif dispatch_enabled(facts['plan']):
        result.update(ready=True, reason_code='ready')
    return result


from pydantic import BaseModel, ConfigDict, Field


class RecommendedStartBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    snapshot_digest: str = Field(pattern=r'^[0-9a-f]{64}$')


@router.post('/recommendations/{recommendation_id}/start', status_code=202)
def start_recommended_test(assessment_id: UUID, recommendation_id: str, body: RecommendedStartBody,
    request: Request, user: User = Depends(analyst), db: Session = Depends(get_db)):
    from .testing_completion_routes import csrf_guard
    from .recommended_test_authorization import preparation, consent, StartUnavailable
    from .recommended_test_queue import RecommendedTestJob
    from .recommended_test_runner import event
    from .nikto_profile import dispatch_enabled, PROFILE_ID
    from .baseline_catalog import fingerprint
    csrf_guard(request, user, db)
    assessment_for(db, assessment_id, user)
    try:
        facts = preparation(db, assessment_id, user.id, recommendation_id)
    except StartUnavailable as exc:
        raise HTTPException(403 if str(exc) == 'recommended_creator_required' else 409,
                            detail={'code': str(exc)}) from None
    if not dispatch_enabled(facts['plan']):
        raise HTTPException(503, detail={'code': 'execution_integration_pending'})
    if fingerprint(facts) != body.snapshot_digest:
        raise HTTPException(409, detail={'code': 'recommended_review_stale'})
    existing = db.scalar(select(RecommendedTestJob).where(RecommendedTestJob.assessment_id == assessment_id,
                                                       RecommendedTestJob.recommendation_id == recommendation_id))
    if existing is not None:
        if existing.execution_plan != facts['plan']:
            raise HTTPException(409, detail={'code': 'recommended_existing_policy_stale'})
        return recommended_receipt(existing, True)
    job = RecommendedTestJob(assessment_id=assessment_id, target_id=UUID(facts['target_id']), actor_id=user.id,
        recommendation_id=recommendation_id, tool='Nikto', profile_id=PROFILE_ID, profile_version=facts['plan']['profile_version'],
        scope_revision=facts['scope_revision'], execution_plan=facts['plan'], authorization_snapshot=consent(facts), status='Queued')
    db.add(job); db.flush()
    event(db, job, 'execution_queued', 'explicit_recommended_start')
    receipt = recommended_receipt(job)
    db.commit()
    return receipt


@router.get('/recommendations/{recommendation_id}/start-receipt')
def recommended_start_receipt(assessment_id: UUID, recommendation_id: str,
    user: User = Depends(analyst), db: Session = Depends(get_db)):
    from .recommended_test_queue import RecommendedTestJob
    job = db.scalar(select(RecommendedTestJob).join(Assessment, Assessment.id == RecommendedTestJob.assessment_id)
        .where(Assessment.id == assessment_id, accessible(user), RecommendedTestJob.recommendation_id == recommendation_id))
    if job is None: raise HTTPException(404)
    return recommended_receipt(job, True)
