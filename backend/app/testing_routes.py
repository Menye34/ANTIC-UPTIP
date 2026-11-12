"""Read-only Testing views backed by persisted execution requests."""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .assessment_routes import accessible, analyst
from .database import get_db
from .models import Assessment, AssessmentStartAuthorization, BaselineExecutionRequest, User

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
    rows = db.execute(
        select(Assessment, AssessmentStartAuthorization, BaselineExecutionRequest)
        .outerjoin(AssessmentStartAuthorization,
                   AssessmentStartAuthorization.assessment_id == Assessment.id)
        .outerjoin(BaselineExecutionRequest, BaselineExecutionRequest.assessment_id == Assessment.id)
        .where(Assessment.id == assessment_id, accessible(user))
        .order_by(BaselineExecutionRequest.created_at, BaselineExecutionRequest.id)
        .execution_options(populate_existing=True)
    ).all()
    if not rows:
        raise HTTPException(404)
    assessment, authorization, _ = rows[0]
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
        'discovered_so_far': [],  # Scheduling creates no observations.
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
    return {**execution_view(request), 'authorized_activity': request.authorized_activity,
            'dispatch_status': 'requires_fresh_authorization'}
