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
    for activity in sorted(activities, key=lambda a: (a['profile_id'] == 'service-discovery', a['target_id'], a['profile_id'])):
        if activity['profile_id'] == 'service-discovery':
            requests.append(queue_scoped_service(db, authorization, activity, requests))
            continue
        target_id = UUID(activity['target_id'])
        if authorization.snapshot.get('purpose') == 'schedule_only':
            from .scheduling_policy import validate_preparation
            prep = activity.get('scheduling_preparation')
            if (not validate_preparation(prep) or target_id not in target_ids
                    or prep['assessment_id'] != str(authorization.assessment_id)
                    or prep['target_id'] != str(target_id)
                    or prep['evaluation_fingerprint'] != activity.get('evaluation_fingerprint')
                    or prep['evaluation_id'] != activity.get('evaluation_id')
                    or activity.get('status') != 'resolved'
                    or activity.get('profile_id') != 'network-discovery'
                    or activity.get('tool') != 'Nmap' or activity.get('activity') != 'Network Discovery'
                    or activity.get('version') != 2):
                raise ValueError('Invalid server-derived scheduling preparation.')
        else:
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


def queue_scoped_service(db, authorization, activity, requests):
    """Reuse existing consent/dispatch pipeline within the atomic Start transaction."""
    from datetime import timedelta, timezone
    from .models import ServiceDiscoveryConsent
    from .baseline_catalog import fingerprint
    from .service_start_preparation import validate, ports_for
    from .service_discovery import preparation
    prep = activity.get('scheduling_preparation')
    if (not validate(prep) or activity.get('status') != 'resolved'
            or activity.get('tool') != 'Nmap' or activity.get('activity') != 'Service Discovery'
            or activity.get('version') != 1 or activity.get('profile_digest') != prep['profile_digest']
            or prep['assessment_id'] != str(authorization.assessment_id)
            or prep['target_id'] != activity['target_id']
            or prep['evaluation_id'] != activity['evaluation_id']
            or prep['evaluation_fingerprint'] != activity['evaluation_fingerprint']):
        raise ValueError('Invalid scoped service preparation')
    host = next((r for r in requests if str(r.target_id) == activity['target_id']
                 and r.profile_id == 'network-discovery'), None)
    if host is None or host.authorized_activity['scheduling_preparation'] != prep['host_preparation']:
        raise ValueError('Authorized host preparation required')
    ports = ports_for(db, authorization.assessment_id, prep['target_value'], prep['scheduling_policy']['version'])
    if ports != prep['authorized_tcp_ports']:
        raise ValueError('Authorized ports changed')
    db.flush()
    current = preparation(db, host, ports)
    if current['plan'] != prep['plan']:
        raise ValueError('Reviewed service plan changed')
    now = authorization.confirmed_at.astimezone(timezone.utc)
    expiry = now + timedelta(hours=1)
    snapshot = {'schema_version': 1, 'actor_id': str(authorization.actor_id), 'confirmed': True,
                'expires_at': expiry.isoformat(), 'preparation': current,
                'source': 'assessment_start', 'reviewed_preparation': prep}
    digest = fingerprint(snapshot)
    row = BaselineExecutionRequest(id=uuid4(), assessment_id=authorization.assessment_id,
        authorization_id=authorization.id, target_id=host.target_id,
        profile_id='service-discovery', profile_version=1, tool='Nmap', activity='Service Discovery',
        status='Queued', authorized_activity={'target_value': prep['target_value'],
            'service_consent_digest': digest, 'scheduling_preparation': {
                'plan': current['plan'], 'parameter_digest': current['plan']['parameter_digest']}})
    db.add(row)
    db.flush()
    # One Start may cover several targets; use each immutable request identity
    # for consent uniqueness rather than reusing the Start idempotency key.
    db.add(ServiceDiscoveryConsent(request_id=row.id, assessment_id=authorization.assessment_id,
        target_id=host.target_id, actor_id=authorization.actor_id, idempotency_key=row.id,
        snapshot=snapshot, digest=digest, created_at=now, expires_at=expiry))
    # The existing AssessmentStartEvent audits this transaction. The immutable
    # consent binds its authorization, actor, timestamp and reviewed policy.
    # ExecutionEvent is worker-owned history: the web app must not impersonate
    # a worker or require INSERT privileges on that table to schedule work.
    db.flush()
    return row
