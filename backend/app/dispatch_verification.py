"""Independent positive dispatch checks for v2; no process or database writes."""
from datetime import datetime, timezone
from sqlalchemy import select

from .baseline_catalog import fingerprint
from .baseline_resolution import evaluate
from .dispatch_policy import PROFILE, authority, validate_plan
from .models import (Assessment, AssessmentTarget, AssessmentStartAuthorization,
                     BaselineAssignment, BaselineEvaluation, BaselineToolState, User)
from .target_scope import classify, scope_entries


class DispatchDenied(ValueError):
    pass


def verify(db, request, *, attempt=None, worker_id=None, claim_id=None):
    """Caller coordinates actor, assessment, global-source and request locks.

    Scheduling snapshots are verified as consent only. Dispatch authority is the
    separate pinned release policy and fresh execution checks returned here.
    """
    def require(condition, code):
        if not condition:
            raise DispatchDenied(code)

    require(request.tool == 'Nmap' and request.profile_id == PROFILE.key
            and request.activity == PROFILE.activity, 'unsupported_dispatch_profile')
    require(request.profile_version == 2, 'v1_output_contract_not_dispatchable'
            if request.profile_version == 1 else 'unsupported_profile_version')
    require(request.status in ('Queued', 'Running'), 'execution_not_active')
    assessment = db.get(Assessment, request.assessment_id)
    require(assessment is not None and assessment.status == 'Testing', 'assessment_not_testing')
    actor = db.execute(select(User.id, User.status, User.role, User.password_change_required)
                       .where(User.id == assessment.creator_id)).one_or_none()
    require(actor is not None and actor.status == 'active' and actor.role == 'Security Analyst'
            and not actor.password_change_required, 'creator_permission_revoked')
    auth = db.get(AssessmentStartAuthorization, request.authorization_id)
    require(auth is not None and auth.actor_id == actor.id and auth.assessment_id == assessment.id,
            'start_authorization_invalid')
    snapshot = auth.snapshot
    require(isinstance(snapshot, dict) and fingerprint(snapshot) == auth.snapshot_digest
            and snapshot.get('schema_version') == auth.snapshot_version
            and snapshot.get('purpose') == 'schedule_only'
            and snapshot.get('assessment_id') == str(assessment.id)
            and snapshot.get('lifecycle_status') == 'Draft'
            and snapshot.get('mode') == auth.mode, 'start_snapshot_invalid')
    target = db.get(AssessmentTarget, request.target_id)
    require(target is not None and target.assessment_id == assessment.id
            and target.kind == 'IP address', 'target_unavailable')
    boundaries = scope_entries(db, assessment.id)
    scope_digest = fingerprint(sorted(map(list, boundaries)))
    require(target.scope_revision == assessment.scope_revision
            and target.scope_status == 'in_scope'
            and classify(target.normalized_value, target.kind, boundaries)[0] == 'in_scope'
            and snapshot.get('scope_revision') == assessment.scope_revision
            and snapshot.get('scope_digest') == scope_digest, 'scope_changed')
    targets = [t for t in snapshot.get('targets', []) if t.get('target_id') == str(target.id)]
    require(len(targets) == 1 and targets[0].get('value') == target.normalized_value
            and targets[0].get('revision') == target.revision
            and targets[0].get('scope_status') == 'in_scope', 'target_snapshot_changed')
    activities = [a for a in snapshot.get('eligible_activities', [])
                  if a.get('target_id') == str(target.id) and a.get('profile_id') == PROFILE.key]
    require(len(activities) == 1, 'activity_snapshot_invalid')
    activity = activities[0]
    require(request.authorized_activity == {**activity, 'target_value': target.normalized_value}
            and activity.get('version') == 2 and activity.get('status') == 'resolved'
            and activity.get('policy', {}).get('disposition') == 'preauthorized'
            and not activity.get('policy_dependencies'), 'activity_binding_invalid')
    prep = activity.get('scheduling_preparation')
    from .scheduling_policy import validate_preparation
    require(validate_preparation(prep), 'scheduling_preparation_invalid')
    require(snapshot.get('policy') == prep['scheduling_policy']
            and snapshot.get('mode') in ('full', 'partial')
            and not any(item.get('target_id') == str(target.id)
                        for item in snapshot.get('excluded_targets', []))
            and not any(item.get('target_id') == str(target.id) and item.get('profile_id') == PROFILE.key
                        for item in snapshot.get('excluded_activities', []))
            and (snapshot['mode'] != 'full' or not (snapshot.get('excluded_targets') or snapshot.get('excluded_activities'))),
            'start_exclusion_or_policy_conflict')
    require(prep['assessment_id'] == str(assessment.id) and prep['target_id'] == str(target.id)
            and prep['scope_revision'] == assessment.scope_revision
            and prep['target_revision'] == target.revision and prep['scope_digest'] == scope_digest
            and prep['target_value'] == target.normalized_value and not prep['dependencies']
            and validate_plan(prep['plan']), 'restricted_plan_invalid')
    assignment = db.get(BaselineAssignment, (target.id, PROFILE.key))
    require(assignment is not None, 'baseline_missing')
    evaluation = db.get(BaselineEvaluation, assignment.evaluation_id)
    tool = db.get(BaselineToolState, 'Nmap')
    require(tool is not None and tool.state == 'enabled' and PROFILE.capability in tool.capabilities,
            'tool_unavailable')
    require(evaluation is not None and str(evaluation.id) == str(activity.get('evaluation_id'))
            and str(evaluation.id) == prep['evaluation_id']
            and evaluation.fingerprint == fingerprint(evaluation.decision)
            and evaluation.fingerprint == activity.get('evaluation_fingerprint')
            and evaluation.fingerprint == prep['evaluation_fingerprint']
            and evaluation.fingerprint == fingerprint(evaluate(target, assessment.scope_revision, PROFILE, tool))
            and tool.revision == prep['tool_revision'], 'baseline_or_tool_stale')
    if attempt is not None:
        now = datetime.now(timezone.utc)
        require(attempt.request_id == request.id and attempt.worker_id == worker_id
                and attempt.claim_id == claim_id and attempt.status in ('Claimed', 'Running')
                and attempt.lease_expires_at > now and attempt.cancellation_requested_at is None
                and attempt.parameters == prep['plan']
                and attempt.parameter_digest == prep['parameter_digest'], 'worker_ownership_invalid')
    return {'dispatch_policy': authority(), 'start_authorization_id': str(auth.id),
            'start_snapshot_digest': auth.snapshot_digest, 'plan': prep['plan'],
            'scope_revision': assessment.scope_revision, 'target_revision': target.revision,
            'tool_revision': tool.revision, 'evaluation_id': str(evaluation.id),
            'scheduling_policy_digest': prep['scheduling_policy']['digest'],
            'evaluation_fingerprint': evaluation.fingerprint,
            'execution_authorized': True}
