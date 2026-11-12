"""Durable baseline scheduling. Dispatch requires a separate authorization gate."""
from copy import deepcopy
from uuid import UUID, uuid4

from sqlalchemy import select

from .models import AssessmentTarget, BaselineExecutionRequest


def queue_baselines(db, authorization):
    """Caller owns the assessment lock and commits authorization and requests together."""
    activities = authorization.snapshot['eligible_activities']
    if not activities:
        raise ValueError('Cannot schedule an empty Start authorization.')
    target_ids = set(db.scalars(select(AssessmentTarget.id).where(
        AssessmentTarget.assessment_id == authorization.assessment_id,
    )))
    requests = []
    for activity in activities:
        target_id = UUID(activity['target_id'])
        if (target_id not in target_ids or activity.get('status') != 'resolved'
                or activity.get('policy', {}).get('disposition') != 'preauthorized'
                or not activity.get('safety_evidence')
                or not activity.get('evaluation_fingerprint')
                or not activity.get('profile_digest')):
            raise ValueError('Start authorization contains an invalid scheduling activity.')
        evidence = activity['safety_evidence']
        if not evidence.get('parameter_digest') or not evidence.get('reference'):
            raise ValueError('Scheduling requires an immutable approved parameter reference.')
        request = BaselineExecutionRequest(
            id=uuid4(), assessment_id=authorization.assessment_id, authorization_id=authorization.id,
            target_id=target_id, profile_id=activity['profile_id'], profile_version=activity['version'],
            tool=activity['tool'], activity=activity['activity'], status='Queued',
            authorized_activity={**deepcopy(activity), 'target_value': next(
                item['value'] for item in authorization.snapshot['targets']
                if item['target_id'] == activity['target_id']
            )},
        )
        db.add(request)
        requests.append(request)
    db.flush()
    return requests


def queued_requests(db, authorization_id):
    return db.scalars(select(BaselineExecutionRequest)
                      .where(BaselineExecutionRequest.authorization_id == authorization_id)
                      .order_by(BaselineExecutionRequest.target_id, BaselineExecutionRequest.profile_id)).all()
