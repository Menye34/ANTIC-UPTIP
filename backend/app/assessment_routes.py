from datetime import date, datetime, timezone
import hmac
import re
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, aliased

from .config import get_settings
from .database import get_db
from .models import Assessment, AssessmentAssignment, AssessmentCreationEvent, AssessmentTarget, ScopeEntry, User, assessment_reference_sequence
from .routes import require_role, trusted_origin
from .security import digest, session_csrf

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
