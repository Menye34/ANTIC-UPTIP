"""Testing Completion: fail-closed readiness, explicit decisions and atomic lifecycle transition."""
from datetime import datetime, timezone
import hmac
import json
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from .assessment_routes import accessible, analyst
from .config import get_settings
from .database import get_db
from .models import (
    Assessment, AuthSession, TestingCompletionEvent,
    TestingRecommendationDecision, RecommendationReviewEvent, User,
)
from .testing_completion_service import review_state, receipt_snapshot
from .testing_completion_schemas import CompletionReview, DecisionResponse
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


@router.get('', response_model=CompletionReview)
def completion_review(assessment_id: UUID, user: User = Depends(analyst),
                      db: Session = Depends(get_db)):
    return review_state(db, assessment_id, user)[0]


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    recommendation_id: str = Field(pattern=r'^[0-9a-f]{64}$')
    decision: Literal['Reviewed', 'Deferred']
    review_outcome: Literal['Accepted', 'Rejected'] | None = None


@router.post('/decisions', response_model=DecisionResponse)
def decide(assessment_id: UUID, body: DecisionBody, request: Request,
           user: User = Depends(analyst), db: Session = Depends(get_db)):
    if body.review_outcome is not None and body.decision != 'Reviewed':
        raise HTTPException(422)
    csrf_guard(request, user, db)
    assessment = assessment_row(db, assessment_id, user, lock=True)
    if assessment.status != 'Testing':
        raise HTTPException(409)
    review, state = review_state(db, assessment_id, user, lock=True)
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
    if body.review_outcome is not None:
        from .testing_completion_service import recommendation_state
        current = recommendation_state(db, assessment_id, user)
        item = next((item for item in current['recommendations'] if item['id'] == body.recommendation_id), None)
        if item is None or item.get('context_digest') != body.recommendation_id:
            raise HTTPException(409)
        if item.get('review_outcome') != body.review_outcome:
            revision = (db.scalar(select(func.max(RecommendationReviewEvent.revision)).where(
                RecommendationReviewEvent.assessment_id == assessment_id,
                RecommendationReviewEvent.recommendation_id == body.recommendation_id)) or 0) + 1
            db.add(RecommendationReviewEvent(assessment_id=assessment_id, revision=revision,
                recommendation_id=body.recommendation_id, context_digest=body.recommendation_id,
                actor_id=user.id, outcome=body.review_outcome,
                snapshot=json.loads(json.dumps(item, default=str))))
    db.commit()
    return {'assessment_id': str(assessment_id), 'recommendation_id': body.recommendation_id,
            'decision': body.decision}


class CompleteBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    snapshot_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    confirmed: Literal[True]


@router.post('', response_model=CompletionReview)
def complete(assessment_id: UUID, body: CompleteBody, request: Request,
             user: User = Depends(analyst), db: Session = Depends(get_db)):
    csrf_guard(request, user, db)
    assessment = assessment_row(db, assessment_id, user, lock=True)
    if assessment.creator_id != user.id:
        raise HTTPException(403)
    if assessment.status != 'Testing':
        raise HTTPException(409)
    review, state = review_state(db, assessment_id, user, lock=True)
    if not review['ready'] or not hmac.compare_digest(review['snapshot_digest'], body.snapshot_digest):
        raise HTTPException(409)
    event = TestingCompletionEvent(
        assessment_id=assessment_id, actor_id=user.id, completed_at=datetime.now(timezone.utc),
        snapshot=receipt_snapshot(review, state),
    )
    db.add(event)
    # Finalize supported consolidated findings in the same locked transaction.
    # Discovery facts alone produce no vulnerability findings.
    from .findings_processing import consolidate
    consolidate(db, assessment_id)
    assessment.status = 'Finding Review'
    db.flush()
    result, _ = review_state(db, assessment_id, user)
    if result['lifecycle_status'] != 'Finding Review' or result['completion'] is None:
        raise HTTPException(503, detail='Completion receipt could not be verified.')
    db.commit()
    return result
