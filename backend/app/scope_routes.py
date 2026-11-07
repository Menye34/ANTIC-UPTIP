import hmac
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .assessment_routes import accessible, analyst
from .config import get_settings
from .database import get_db
from .models import Assessment, ScopeEntry, ScopeEvent, User
from .routes import trusted_origin
from .scope_validation import normalize
from .security import session_csrf

router = APIRouter(prefix='/api/v1/assessments/{assessment_id}/scope')


class Revision(BaseModel):
    model_config = ConfigDict(extra='forbid')
    revision: int = Field(ge=0, strict=True)


class EntryInput(Revision):
    value: str = Field(max_length=1024)


class Removal(Revision):
    confirmed: bool = Field(strict=True)


def parent(assessment_id, user, db, request=None):
    query = select(Assessment).where(Assessment.id == assessment_id, accessible(user))
    if request is not None:
        settings = get_settings()
        expected = session_csrf(settings, request.cookies[settings.cookie_name])
        if not trusted_origin(request) or not hmac.compare_digest(
            request.headers.get('x-csrf-token', '').encode(), expected.encode()
        ):
            raise HTTPException(403)
    assessment = db.scalar(query.with_for_update(read=request is None))
    if assessment is None:
        raise HTTPException(404)
    if request is not None and not can_edit(assessment, user):
        raise HTTPException(403)
    return assessment


def can_edit(assessment, user):
    return assessment.status == 'Draft' and assessment.creator_id == user.id


def snapshot(entry):
    return {'value': entry.normalized_value, 'kind': entry.kind}


def listing(assessment, user, db):
    entries = db.scalars(select(ScopeEntry).where(ScopeEntry.assessment_id == assessment.id)
                         .order_by(ScopeEntry.created_at, ScopeEntry.id))
    return {'revision': assessment.scope_revision, 'status': assessment.status, 'can_edit': can_edit(assessment, user),
            'entries': [{'id': entry.id, **snapshot(entry)} for entry in entries]}


def problem(status, code):
    return JSONResponse(status_code=status, content={'code': code})


@router.get('')
def list_scope(assessment_id: UUID, user: User = Depends(analyst), db: Session = Depends(get_db)):
    # Keep the revision and entry list consistent with writes serialized on the parent row.
    return listing(parent(assessment_id, user, db), user, db)


def mutate(assessment_id, scope_id, body, request, user, db, action):
    assessment = parent(assessment_id, user, db, request)
    if body.revision != assessment.scope_revision:
        return problem(409, 'stale_revision')
    entry = None
    before = None
    after = None
    if scope_id is not None:
        entry = db.scalar(select(ScopeEntry).where(ScopeEntry.assessment_id == assessment_id, ScopeEntry.id == scope_id))
        if entry is None:
            raise HTTPException(404)
        before = snapshot(entry)
    if action == 'removed':
        if not body.confirmed:
            return problem(422, 'confirmation_required')
        db.delete(entry)
    else:
        try:
            value, kind = normalize(body.value)
        except ValueError:
            return problem(422, 'invalid_entry')
        if before == {'value': value, 'kind': kind}:
            # Normalization can turn an edit into a no-op. Keep the current configuration revision.
            return {**listing(assessment, user, db), 'changed': before, 'affected_target_count': 0}
        duplicate = select(ScopeEntry.id).where(
            ScopeEntry.assessment_id == assessment_id, ScopeEntry.normalized_value == value)
        if scope_id is not None:
            duplicate = duplicate.where(ScopeEntry.id != scope_id)
        if db.scalar(duplicate) is not None:
            return problem(409, 'duplicate_entry')
        if entry is None:
            entry = ScopeEntry(id=uuid4(), assessment_id=assessment_id)
            db.add(entry)
        entry.normalized_value = value
        entry.kind = kind
        after = snapshot(entry)
    assessment.scope_revision += 1
    db.add(ScopeEvent(assessment_id=assessment_id, revision=assessment.scope_revision, entry_id=entry.id,
                      actor_id=user.id, action=action, before=before, after=after))
    try:
        db.flush()
        result = listing(assessment, user, db)
        result['changed'] = after or before
        # Target registration arrives in Phase C2. Invalidate its future decisions by revision.
        result['affected_target_count'] = 0
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise
    return result


@router.post('', status_code=201)
def add(assessment_id: UUID, body: EntryInput, request: Request,
        user: User = Depends(analyst), db: Session = Depends(get_db)):
    return mutate(assessment_id, None, body, request, user, db, 'added')


@router.patch('/{scope_id}')
def edit(assessment_id: UUID, scope_id: UUID, body: EntryInput, request: Request,
         user: User = Depends(analyst), db: Session = Depends(get_db)):
    return mutate(assessment_id, scope_id, body, request, user, db, 'edited')


@router.delete('/{scope_id}')
def remove(assessment_id: UUID, scope_id: UUID, body: Removal, request: Request,
           user: User = Depends(analyst), db: Session = Depends(get_db)):
    return mutate(assessment_id, scope_id, body, request, user, db, 'removed')
