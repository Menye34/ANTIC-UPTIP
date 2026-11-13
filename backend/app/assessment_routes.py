from datetime import date, datetime, timezone
import hmac
import logging
import re
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, aliased

from .assessment_readiness import evaluate_readiness
from .assessment_start import signing_key, snapshot_for, start_review, verify_review_token
from .baseline_catalog import fingerprint
from .baseline_scheduling import queue_baselines, queued_requests
from .config import get_settings
from .database import get_db
from .models import Assessment, AssessmentAssignment, AssessmentCreationEvent, AssessmentStartAuthorization, AssessmentStartEvent, AssessmentTarget, AuthSession, ScopeEntry, User, assessment_reference_sequence
from .routes import require_role, trusted_origin
from .security import can_activate, digest, session_csrf

router = APIRouter(prefix='/api/v1/assessments')
analyst = require_role('Security Analyst')


class CreateAssessment(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    start_date: date | None = None
    end_date: date | None = None

    @field_validator('start_date', 'end_date', mode='before')
    @classmethod
    def iso_date(cls, value):
        if value is not None and (not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value)):
            raise ValueError('Use a valid ISO calendar date.')
        return value


class AssessmentSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    reference: str
    name: str
    status: str
    end_date: date | None
    updated_at: datetime


class AssessmentOverview(AssessmentSummary):
    description: str | None
    start_date: date | None
    lead_analyst: str
    created_by: str
    created_at: datetime
    scope_entry_count: int = 0
    target_count: int = 0


def accessible(user: User):
    assigned = select(AssessmentAssignment.assessment_id).where(AssessmentAssignment.analyst_id == user.id)
    return (Assessment.creator_id == user.id) | Assessment.id.in_(assigned)


def overview(assessment, lead, actor, occurred_at, scope_entry_count=0, target_count=0):
    return AssessmentOverview(**AssessmentSummary.model_validate(assessment).model_dump(),
        description=assessment.description, start_date=assessment.start_date,
        lead_analyst=lead, created_by=actor, created_at=occurred_at, scope_entry_count=scope_entry_count, target_count=target_count)


@router.post('', status_code=201, response_model=AssessmentOverview)
def create(body: CreateAssessment, request: Request, response: Response,
           idempotency_key: UUID = Header(alias='Idempotency-Key'),
           user: User = Depends(analyst), db: Session = Depends(get_db)):
    settings = get_settings()
    supplied = request.headers.get('x-csrf-token', '').encode()
    expected = session_csrf(settings, request.cookies[settings.cookie_name]).encode()
    if not trusted_origin(request) or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=403)
    if body.start_date and body.end_date and body.end_date < body.start_date:
        raise HTTPException(status_code=422)
    fingerprint = digest(body.model_dump_json())
    try:
        # Hold the creator lock until the draft and its event commit together.
        db.execute(select(User.id).where(User.id == user.id).with_for_update()).scalar_one()
        previous = db.scalar(select(Assessment).where(
            Assessment.creator_id == user.id, Assessment.idempotency_key == idempotency_key))
        if previous:
            if previous.request_fingerprint != fingerprint:
                raise HTTPException(status_code=409)
            result = get_assessment(previous.id, user, db)
            db.commit()
            response.status_code = 200
            return result

        identifier = uuid4()
        number = db.scalar(select(assessment_reference_sequence.next_value()))
        reference = f'ASM-{datetime.now(timezone.utc).year}-{number:03d}'
        assessment = Assessment(id=identifier, reference=reference, name=body.name,
            idempotency_key=idempotency_key, request_fingerprint=fingerprint,
            description=body.description or None, start_date=body.start_date, end_date=body.end_date,
            status='Draft', creator_id=user.id, lead_analyst_id=user.id)
        event = AssessmentCreationEvent(assessment_id=identifier, actor_id=user.id)
        db.add(assessment)
        db.flush()
        db.add(event)
        db.flush()
        result = overview(assessment, user.username, user.username, event.occurred_at)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise
    return result


@router.get('', response_model=list[AssessmentSummary])
def list_assessments(user: User = Depends(analyst), db: Session = Depends(get_db)):
    return db.scalars(select(Assessment).where(accessible(user))
                      .order_by(Assessment.updated_at.desc(), Assessment.id)).all()


@router.get('/{assessment_id}', response_model=AssessmentOverview)
def get_assessment(assessment_id: UUID, user: User = Depends(analyst), db: Session = Depends(get_db)):
    lead = aliased(User)
    actor = aliased(User)
    count = select(func.count()).select_from(ScopeEntry).where(ScopeEntry.assessment_id == Assessment.id).scalar_subquery()
    targets = select(func.count()).select_from(AssessmentTarget).where(
        AssessmentTarget.assessment_id == Assessment.id).scalar_subquery()
    row = db.execute(select(Assessment, lead.username, actor.username, AssessmentCreationEvent.occurred_at, count, targets)
        .join(lead, Assessment.lead_analyst_id == lead.id)
        .join(AssessmentCreationEvent, AssessmentCreationEvent.assessment_id == Assessment.id)
        .join(actor, AssessmentCreationEvent.actor_id == actor.id)
        .where(Assessment.id == assessment_id, accessible(user))).one_or_none()
    if row is None:
        raise HTTPException(status_code=404)
    return overview(*row)


@router.get('/{assessment_id}/readiness')
def get_readiness(assessment_id: UUID, request: Request, response: Response,
                  user: User = Depends(analyst), db: Session = Depends(get_db)):
    # Scope, target and baseline writers serialize on this same assessment row.
    assessment = db.scalar(select(Assessment).where(
        Assessment.id == assessment_id, accessible(user)).with_for_update(read=True))
    if assessment is None:
        raise HTTPException(status_code=404)
    response.headers['Cache-Control'] = 'no-store'
    readiness = evaluate_readiness(db, assessment)
    settings = get_settings()
    review = start_review(snapshot_for(readiness), signing_key(settings), user.id,
                          request.cookies.get(settings.cookie_name), creator=assessment.creator_id == user.id)
    eligible = {(item['target_id'], item['profile_id']) for item in review['eligible_activities']}
    for target in readiness['targets']:
        for activity in target['baseline_activities']:
            pair = (str(target['target_id']), activity['profile_id'])
            activity['start_review_eligible'] = review['confirmation_possible'] and pair in eligible
        target['start_review_eligible'] = any(item['start_review_eligible'] for item in target['baseline_activities'])
    logging.getLogger('uptip.assessment').info(
        'start_review actor=%s assessment=%s confirmable=%s', user.id, assessment_id, review['confirmation_possible'],
    )
    blockers = []
    if assessment.creator_id != user.id:
        blockers.append({'code': 'start_creator_required', 'message': 'Only the assessment creator can confirm Start.'})
    if not signing_key(settings):
        blockers.append({'code': 'start_signing_unavailable', 'message': 'Secure Start confirmation is unavailable.'})
    return {**readiness, 'reasons': readiness['reasons'] + blockers,
            'start_review_eligible': review['confirmation_possible'], 'start_review': review}

class StartConfirmation(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    review_token: str = Field(min_length=1, max_length=4096)
    mode: Literal['full', 'partial']
    confirmed: Literal[True]

    @field_validator('confirmed', mode='before')
    @classmethod
    def explicit_confirmation(cls, value):
        if value is not True:
            raise ValueError('Explicit Start confirmation is required.')
        return value


def start_conflict(code, actor_id=None, assessment_id=None):
    logging.getLogger('uptip.assessment').info(
        'start_rejected actor=%s assessment=%s code=%s', actor_id, assessment_id, code,
    )
    return JSONResponse(status_code=409, content={'detail': {'code': code}},
                        headers={'Cache-Control': 'no-store'})


def start_receipt(record, requests):
    return {
        'authorization_id': record.id, 'assessment_id': record.assessment_id,
        'lifecycle_status': 'Testing' if requests else 'Ready', 'mode': record.mode, 'confirmed_at': record.confirmed_at.astimezone(timezone.utc),
        'snapshot_digest': record.snapshot_digest, 'execution_authorized': False,
        'queued_execution_count': len(requests), 'queued_execution_ids': [item.id for item in requests],
        'testing_url': f'/api/v1/assessments/{record.assessment_id}/testing',
        'excluded_activities': record.snapshot['excluded_activities'],
        'excluded_targets': record.snapshot['excluded_targets'],
        'authorized_activity_count': len(record.snapshot['eligible_activities']),
        'authorized_target_count': len({item['target_id'] for item in record.snapshot['eligible_activities']}),
        'excluded_activity_count': len(record.snapshot['excluded_activities']),
        'excluded_target_count': len(record.snapshot['excluded_targets']),
    }


@router.post('/{assessment_id}/start', status_code=201)
def confirm_start(assessment_id: UUID, body: StartConfirmation, request: Request, response: Response,
                  idempotency_key: UUID = Header(alias='Idempotency-Key'),
                  user: User = Depends(analyst), db: Session = Depends(get_db)):
    settings = get_settings()
    session_token = request.cookies[settings.cookie_name]
    supplied = request.headers.get('x-csrf-token', '').encode()
    if not trusted_origin(request) or not hmac.compare_digest(supplied, session_csrf(settings, session_token).encode()):
        raise HTTPException(403)
    response.headers['Cache-Control'] = 'no-store'
    # Authentication writers lock the user first. Hold the user and session
    # stable through confirmation, including when a request waited on a lock.
    actor = db.scalar(select(User).where(User.id == user.id).with_for_update(read=True)
                      .execution_options(populate_existing=True))
    session = db.scalar(select(AuthSession).where(AuthSession.token_hash == digest(session_token))
                        .with_for_update(read=True).execution_options(populate_existing=True))
    if (actor is None or session is None or session.user_id != user.id
            or session.expires_at <= datetime.now(timezone.utc) or not can_activate(actor)):
        raise HTTPException(401)
    if actor.role != 'Security Analyst':
        raise HTTPException(403)
    assessment = db.scalar(select(Assessment).where(Assessment.id == assessment_id, accessible(user))
                           .with_for_update().execution_options(populate_existing=True))
    if assessment is None:
        raise HTTPException(404)
    if assessment.creator_id != user.id:
        raise HTTPException(403)

    request_fingerprint = fingerprint({'confirmation': body.model_dump(), 'session': digest(session_token)})
    previous = db.scalar(select(AssessmentStartAuthorization)
                         .where(AssessmentStartAuthorization.assessment_id == assessment_id))
    if previous is not None and previous.idempotency_key == idempotency_key:
        if previous.actor_id != user.id or not hmac.compare_digest(previous.request_fingerprint, request_fingerprint):
            return start_conflict('start_idempotency_conflict', user.id, assessment_id)
        receipt = start_receipt(previous, queued_requests(db, previous.id))
        db.commit()
        response.status_code = 200
        return receipt
    if assessment.status != 'Draft' or previous is not None:
        return start_conflict('start_lifecycle_conflict', user.id, assessment_id)

    key = signing_key(settings)
    if not key:
        return start_conflict('start_signing_unavailable', user.id, assessment_id)
    claims = verify_review_token(body.review_token, key, session_token, assessment_id, user.id, body.mode)
    if claims is None:
        return start_conflict('start_review_invalid', user.id, assessment_id)
    expiry = datetime.fromisoformat(claims['expires_at'])
    if expiry <= datetime.now(timezone.utc):
        return start_conflict('start_review_expired', user.id, assessment_id)

    # Covers existing rows and first-time tool insertion. The maintenance
    # command commits its tool write before it takes any assessment locks.
    # Keep governed authorization records stable until Start confirmation commits.
    # SHARE locks conflict with concurrent INSERT operations that could revoke
    # or replace the authorization state during readiness verification.
    db.execute(text('SELECT public.lock_assessment_start_sources()'))
    snapshot = snapshot_for(evaluate_readiness(db, assessment))
    snapshot_digest = fingerprint(snapshot)

    # Reject confirmations based on an outdated assessment snapshot.
    if not hmac.compare_digest(snapshot_digest, claims['digest']):
        return start_conflict('start_review_stale', user.id, assessment_id)

    if not snapshot['mode']:
        return start_conflict('start_no_eligible_activities', user.id, assessment_id)

    if snapshot['mode'] != body.mode:
        return start_conflict('start_review_stale', user.id, assessment_id)
    now = datetime.now(timezone.utc)
    if expiry <= now:
        return start_conflict('start_review_expired', user.id, assessment_id)
    if session.expires_at <= now:
        raise HTTPException(401)

    record = AssessmentStartAuthorization(
        id=uuid4(), assessment_id=assessment_id, actor_id=user.id, idempotency_key=idempotency_key,
        request_fingerprint=request_fingerprint, mode=body.mode, snapshot_version=snapshot['schema_version'],
        snapshot_digest=snapshot_digest, snapshot=snapshot, confirmed_at=now,
    )
    try:
        db.add(record)
        db.flush()
        db.add(AssessmentStartEvent(authorization_id=record.id, occurred_at=now,
                                    from_status='Draft', to_status='Testing'))
        requests = queue_baselines(db, record)
        assessment.status = 'Testing'
        receipt = start_receipt(record, requests)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise
    logging.getLogger('uptip.assessment').info(
        'start_accepted actor=%s assessment=%s authorization=%s queued=%s',
        user.id, assessment_id, record.id, len(requests),
    )
    return receipt
