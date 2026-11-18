"""Testing Completion: fail-closed readiness, explicit decisions and atomic lifecycle transition."""
from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .assessment_routes import accessible, analyst
from .config import get_settings
from .database import get_db
from .models import (
    Assessment, AuthSession, BaselineExecutionRequest, ExecutionAttempt,
    ResultProcessingOutcome, SecurityObservation, TestingCompletionEvent,
    TestingRecommendationDecision, User,
)
from .recommendation_planner import plan_recommendations
from .routes import trusted_origin
from .security import can_activate, digest, session_csrf

router = APIRouter(prefix='/api/v1/assessments/{assessment_id}/testing/completion')


def assessment_row(db, assessment_id, user, *, lock=False):
    query = select(Assessment).where(Assessment.id == assessment_id, accessible(user))
    if lock:
        query = query.with_for_update()
    assessment = db.scalar(query.execution_options(populate_existing=True))
    if assessment is None:
        raise HTTPException(404)
    return assessment


def csrf_guard(request, user, db):
    settings = get_settings()
    token = request.cookies.get(settings.cookie_name)
    if not token or not trusted_origin(request):
        raise HTTPException(403)
    expected = session_csrf(settings, token).encode()
    if not hmac.compare_digest(request.headers.get('x-csrf-token', '').encode(), expected):
        raise HTTPException(403)
    actor = db.scalar(select(User).where(User.id == user.id).with_for_update(read=True))
    session = db.scalar(select(AuthSession).where(AuthSession.token_hash == digest(token))
                        .with_for_update(read=True))
    if (actor is None or session is None or session.user_id != user.id
            or session.expires_at <= datetime.now(timezone.utc) or not can_activate(actor)):
        raise HTTPException(401)
    if actor.role != 'Security Analyst':
        raise HTTPException(403)


def readiness(db, assessment, *, lock=False):
    executions = select(BaselineExecutionRequest).where(
        BaselineExecutionRequest.assessment_id == assessment.id).order_by(BaselineExecutionRequest.id)
    if lock:
        executions = executions.with_for_update()
    rows = db.scalars(executions).all()
    statuses = {name: sum(item.status == name for item in rows) for name in
                ('Queued', 'Running', 'Completed', 'Failed', 'Stopped', 'Blocked', 'Cancelled')}
    processing = db.scalars(select(ResultProcessingOutcome).where(
        ResultProcessingOutcome.assessment_id == assessment.id)).all()
    processing_errors = sum(item.status in ('Failed', 'Interrupted') for item in processing)
    processing_pending = sum(item.status in ('Pending', 'Processing') for item in processing)
    successful = {item.request_id for item in processing if item.status == 'Succeeded'}
    missing_processing = sum(item.status == 'Completed' and item.id not in successful for item in rows)
    attempts = db.scalars(select(ExecutionAttempt).where(
        ExecutionAttempt.assessment_id == assessment.id)).all()
    active_attempts = sum(item.status in ('Claimed', 'Running', 'RecoveryRequired') for item in attempts)
    observations = db.scalars(select(SecurityObservation).where(
        SecurityObservation.assessment_id == assessment.id).order_by(
            SecurityObservation.collected_at, SecurityObservation.id)).all()
    recommendations = plan_recommendations(observations)
    decisions = {item.recommendation_id: item.decision for item in db.scalars(
        select(TestingRecommendationDecision).where(
            TestingRecommendationDecision.assessment_id == assessment.id)).all()}
    pending = [item['id'] for item in recommendations if decisions.get(item['id']) != 'Reviewed']
    blockers = []
    if not rows:
        blockers.append('no_tests')
    if statuses['Queued'] or statuses['Running'] or active_attempts:
        blockers.append('active_tests')
    if any(statuses[name] for name in ('Failed', 'Stopped', 'Blocked', 'Cancelled')):
        blockers.append('unsuccessful_tests')
    if processing_errors or processing_pending or missing_processing:
        blockers.append('processing_not_clear')
    if pending:
        blockers.append('pending_recommendations')
    if assessment.status not in ('Testing', 'Finding Review'):
        blockers.append('incorrect_lifecycle')
    snapshot = {
        'total': len(rows), 'counts': statuses, 'active_attempts': active_attempts,
        'processing_errors': processing_errors, 'processing_pending': processing_pending,
        'missing_processing': missing_processing, 'recommendation_count': len(recommendations),
        'pending_recommendation_ids': pending,
        'reviewed_recommendations': sum(decisions.get(item['id']) == 'Reviewed' for item in recommendations),
        'deferred_recommendations': sum(decisions.get(item['id']) == 'Deferred' for item in recommendations),
        'candidate_findings': None,
        'blockers': blockers,
    }
    serialized = json.dumps(snapshot, sort_keys=True, separators=(',', ':'))
    fingerprint = hashlib.sha256(serialized.encode()).hexdigest()
    event = db.get(TestingCompletionEvent, assessment.id)
    return {
        'assessment_id': str(assessment.id), 'lifecycle_status': assessment.status,
        'ready': not blockers and assessment.status == 'Testing',
        'snapshot_digest': fingerprint,
        'summary': snapshot,
        'recommendations': [{'id': item['id'], 'title': item['title'],
                             'decision': decisions.get(item['id'])} for item in recommendations],
        'completion': ({
            'completed_at': event.completed_at, 'actor_id': str(event.actor_id),
            'snapshot': event.snapshot,
        } if event else None),
    }


@router.get('')
def completion_review(assessment_id: UUID, user: User = Depends(analyst),
                      db: Session = Depends(get_db)):
    assessment = assessment_row(db, assessment_id, user)
    return readiness(db, assessment)


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    recommendation_id: str = Field(pattern=r'^[0-9a-f]{64}$')
    decision: Literal['Reviewed', 'Deferred']


@router.post('/decisions')
def decide(assessment_id: UUID, body: DecisionBody, request: Request,
           user: User = Depends(analyst), db: Session = Depends(get_db)):
    csrf_guard(request, user, db)
    assessment = assessment_row(db, assessment_id, user, lock=True)
    if assessment.status != 'Testing':
        raise HTTPException(409)
    review = readiness(db, assessment, lock=True)
    if body.recommendation_id not in {item['id'] for item in review['recommendations']}:
        raise HTTPException(409)
    record = db.get(TestingRecommendationDecision, (assessment_id, body.recommendation_id))
    if record is None:
        record = TestingRecommendationDecision(
            assessment_id=assessment_id, recommendation_id=body.recommendation_id,
            actor_id=user.id, decision=body.decision, decided_at=datetime.now(timezone.utc))
        db.add(record)
    elif record.decision != body.decision:
        record.decision = body.decision
        record.actor_id = user.id
        record.decided_at = datetime.now(timezone.utc)
    db.commit()
    return {'assessment_id': str(assessment_id), 'recommendation_id': body.recommendation_id,
            'decision': body.decision}


class CompleteBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    snapshot_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    confirmed: Literal[True]


@router.post('')
def complete(assessment_id: UUID, body: CompleteBody, request: Request,
             user: User = Depends(analyst), db: Session = Depends(get_db)):
    csrf_guard(request, user, db)
    assessment = assessment_row(db, assessment_id, user, lock=True)
    if assessment.creator_id != user.id:
        raise HTTPException(403)
    if assessment.status != 'Testing':
        raise HTTPException(409)
    review = readiness(db, assessment, lock=True)
    if not review['ready'] or not hmac.compare_digest(review['snapshot_digest'], body.snapshot_digest):
        raise HTTPException(409)
    event = TestingCompletionEvent(
        assessment_id=assessment_id, actor_id=user.id, completed_at=datetime.now(timezone.utc),
        snapshot=review['summary'],
    )
    db.add(event)
    assessment.status = 'Finding Review'
    db.commit()
    return readiness(db, assessment)
