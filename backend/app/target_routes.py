from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .assessment_routes import analyst
from .database import get_db
from .models import AssessmentTarget, User
from .scope_routes import Removal, Revision, can_edit, parent, problem
from .scope_validation import normalize
from .target_scope import classify, scope_entries

router = APIRouter(prefix='/api/v1/assessments/{assessment_id}/targets')


class TargetInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    value: str = Field(max_length=1024)


class TargetEdit(TargetInput, Revision):
    pass


class TargetView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    assessment_id: UUID
    original_value: str
    normalized_value: str
    kind: str
    scope_status: str
    classification_reason: str
    scope_revision: int
    revision: int
    eligibility: str = 'blocked'
    created_at: datetime
    updated_at: datetime


def listing(assessment, user, db):
    entries = db.scalars(select(AssessmentTarget).where(AssessmentTarget.assessment_id == assessment.id)
                         .order_by(AssessmentTarget.created_at, AssessmentTarget.id))
    targets = []
    for entry in entries:
        view = TargetView.model_validate(entry)
        if view.scope_revision != assessment.scope_revision:
            view.scope_status = 'requires_revalidation'
            view.classification_reason = 'Authorized scope changed since classification.'
        if view.scope_status == 'in_scope':
            view.eligibility = 'pending'
        targets.append(view)
    return {'targets': targets, 'can_edit': can_edit(assessment, user), 'status': assessment.status,
            'counts': {'total': len(targets), 'eligible': 0,
                       'blocked': sum(target.eligibility == 'blocked' for target in targets)}}


@router.get('')
def list_targets(assessment_id: UUID, user: User = Depends(analyst), db: Session = Depends(get_db)):
    return listing(parent(assessment_id, user, db), user, db)


def find_target(db, assessment_id, target_id):
    target = db.scalar(select(AssessmentTarget).where(
        AssessmentTarget.assessment_id == assessment_id, AssessmentTarget.id == target_id))
    if target is None:
        raise HTTPException(404)
    return target


def save_target(assessment, user, db, value, target=None):
    try:
        normalized, kind = normalize(value)
    except ValueError:
        return problem(422, 'invalid_entry')
    duplicate = select(AssessmentTarget.id).where(
        AssessmentTarget.assessment_id == assessment.id, AssessmentTarget.normalized_value == normalized)
    if target is not None:
        duplicate = duplicate.where(AssessmentTarget.id != target.id)
    if db.scalar(duplicate) is not None:
        return problem(409, 'duplicate_entry')
    status, reason = classify(normalized, kind, scope_entries(db, assessment.id))
    if target is None:
        target = AssessmentTarget(assessment_id=assessment.id)
        db.add(target)
    elif target.original_value != value:
        target.revision += 1
    target.original_value = value
    target.normalized_value = normalized
    target.kind = kind
    target.scope_status, target.classification_reason = status, reason
    target.scope_revision = assessment.scope_revision
    return finish(assessment, user, db)


def finish(assessment, user, db):
    db.flush()
    result = listing(assessment, user, db)
    db.commit()
    return result


@router.post('', status_code=201)
def add_target(assessment_id: UUID, body: TargetInput, request: Request,
               user: User = Depends(analyst), db: Session = Depends(get_db)):
    return save_target(parent(assessment_id, user, db, request), user, db, body.value)


@router.patch('/{target_id}')
def edit_target(assessment_id: UUID, target_id: UUID, body: TargetEdit, request: Request,
                user: User = Depends(analyst), db: Session = Depends(get_db)):
    assessment = parent(assessment_id, user, db, request)
    target = find_target(db, assessment_id, target_id)
    if target.revision != body.revision:
        return problem(409, 'stale_revision')
    return save_target(assessment, user, db, body.value, target)


@router.delete('/{target_id}')
def remove_target(assessment_id: UUID, target_id: UUID, body: Removal, request: Request,
                  user: User = Depends(analyst), db: Session = Depends(get_db)):
    assessment = parent(assessment_id, user, db, request)
    target = find_target(db, assessment_id, target_id)
    if target.revision != body.revision:
        return problem(409, 'stale_revision')
    if not body.confirmed:
        return problem(422, 'confirmation_required')
    db.delete(target)
    return finish(assessment, user, db)
