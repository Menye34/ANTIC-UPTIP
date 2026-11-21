"""Opt-in consent and revalidation using the shared execution framework."""
from datetime import datetime, timezone
from sqlalchemy import select
from .baseline_catalog import fingerprint
from .models import (BaselineExecutionRequest, BaselineToolState,
                     ServiceDiscoveryConsent, ServiceDiscoveryRevocation)
from .nmap_service_profile import CAPABILITY, PROFILE_ID, authority, plan, validate_plan


def preparation(db, host_request, ports):
    from .dispatch_verification import DispatchDenied
    from .nmap_dispatch_authorization import verify_start_snapshot_integrity, verify_current_scope_target
    from .models import (Assessment, AssessmentStartAuthorization, AssessmentTarget, User,
                         BaselineAssignment, BaselineEvaluation)
    from .baseline_resolution import evaluate
    from .dispatch_policy import PROFILE
    def require(condition, code):
        if not condition:
            raise DispatchDenied(code)
    assessment = db.get(Assessment, host_request.assessment_id)
    require(assessment is not None and assessment.status == 'Testing', 'assessment_not_testing')
    actor = db.execute(select(User.id, User.status, User.role, User.password_change_required)
                       .where(User.id == assessment.creator_id)).one_or_none()
    require(actor is not None and actor.status == 'active' and actor.role == 'Security Analyst'
            and not actor.password_change_required, 'creator_permission_revoked')
    auth = db.get(AssessmentStartAuthorization, host_request.authorization_id)
    require(auth is not None and auth.actor_id == actor.id, 'start_authorization_invalid')
    snapshot = auth.snapshot
    require(verify_start_snapshot_integrity(auth, host_request, snapshot).reason_code ==
            'start_snapshot_integrity_verified' and snapshot.get('purpose') == 'schedule_only',
            'start_snapshot_invalid')
    require(verify_current_scope_target(db, assessment, host_request, snapshot).reason_code ==
            'current_scope_target_binding_verified_dispatch_pending', 'scope_or_target_changed')
    target = db.get(AssessmentTarget, host_request.target_id)
    require(target.kind == 'IP address' and host_request.profile_id == 'network-discovery'
            and host_request.profile_version == 2 and host_request.tool == 'Nmap'
            and host_request.activity == 'Network Discovery', 'authorized_host_target_required')
    matches = [a for a in snapshot.get('eligible_activities', [])
               if a.get('target_id') == str(target.id) and a.get('profile_id') == 'network-discovery']
    require(len(matches) == 1 and host_request.authorized_activity ==
            {**matches[0], 'target_value': target.normalized_value}, 'host_consent_binding_invalid')
    require(not any(a.get('target_id') == str(target.id) for a in snapshot.get('excluded_targets', [])),
            'target_excluded_at_start')
    tool = db.get(BaselineToolState, 'Nmap')
    require(tool is not None and tool.state == 'enabled'
            and CAPABILITY in tool.capabilities and PROFILE.capability in tool.capabilities,
            'service_tool_capability_unavailable')
    assignment = db.get(BaselineAssignment, (target.id, PROFILE.key))
    evaluation = db.get(BaselineEvaluation, assignment.evaluation_id) if assignment else None
    decision = evaluate(target, assessment.scope_revision, PROFILE, tool)
    require(evaluation is not None and decision['status'] == 'resolved'
            and evaluation.fingerprint == fingerprint(evaluation.decision)
            and evaluation.fingerprint == fingerprint(decision), 'current_baseline_required')
    # Fresh service consent binds CURRENT facts, rather than reinterpreting or
    # rewriting the old host Start consent's tool/evaluation revisions.
    lineage = {'start_snapshot_digest': auth.snapshot_digest,
               'scope_revision': assessment.scope_revision, 'target_revision': target.revision,
               'tool_revision': tool.revision, 'evaluation_id': str(evaluation.id),
               'evaluation_fingerprint': evaluation.fingerprint}
    return {'schema_version': 1, 'purpose': 'explicit_service_discovery',
            'assessment_id': str(host_request.assessment_id),
            'target_id': str(host_request.target_id),
            'host_request_id': str(host_request.id),
            'start_authorization_id': str(host_request.authorization_id),
            'start_snapshot_digest': lineage['start_snapshot_digest'],
            'scope_revision': lineage['scope_revision'],
            'target_revision': lineage['target_revision'], 'tool_revision': lineage['tool_revision'],
            'evaluation_id': lineage['evaluation_id'],
            'evaluation_fingerprint': lineage['evaluation_fingerprint'],
            'policy': authority(), 'plan': plan(host_request.authorized_activity['target_value'], ports)}


def verify_service(db, request, *, attempt=None, worker_id=None, claim_id=None):
    from .dispatch_verification import DispatchDenied
    def require(condition, code):
        if not condition:
            raise DispatchDenied(code)
    require(request.profile_id == PROFILE_ID and request.profile_version == 1
            and request.tool == 'Nmap' and request.activity == 'Service Discovery'
            and request.status in ('Queued', 'Running'), 'unsupported_service_request')
    consent = db.get(ServiceDiscoveryConsent, request.id)
    now = datetime.now(timezone.utc)
    require(consent is not None and consent.assessment_id == request.assessment_id
            and consent.target_id == request.target_id and consent.created_at <= now < consent.expires_at
            and db.get(ServiceDiscoveryRevocation, request.id) is None, 'service_consent_missing_expired_or_revoked')
    saved = consent.snapshot
    require(fingerprint(saved) == consent.digest and saved.get('schema_version') == 1
            and saved.get('confirmed') is True and saved.get('actor_id') == str(consent.actor_id)
            and saved.get('expires_at') == consent.expires_at.astimezone(timezone.utc).isoformat(),
            'service_consent_integrity_invalid')
    prep = saved.get('preparation', {})
    from uuid import UUID
    host = db.get(BaselineExecutionRequest, UUID(prep['host_request_id']))
    require(host is not None and host.assessment_id == request.assessment_id
            and host.target_id == request.target_id and host.authorization_id == request.authorization_id,
            'service_lineage_invalid')
    from .models import Assessment
    assessment = db.get(Assessment, request.assessment_id)
    require(assessment is not None and assessment.creator_id == consent.actor_id, 'service_actor_invalid')
    if saved.get('source') == 'assessment_start':
        from .service_start_preparation import validate, ports_for, SUPPORTED_VERSIONS
        from .models import AssessmentStartAuthorization
        reviewed = saved.get('reviewed_preparation')
        auth = db.get(AssessmentStartAuthorization, request.authorization_id)
        matches = [a for a in auth.snapshot.get('eligible_activities', [])
                   if a.get('target_id') == str(request.target_id)
                   and a.get('profile_id') == 'service-discovery'] if auth else []
        require(isinstance(reviewed, dict) and isinstance(reviewed.get('scheduling_policy'), dict),
                'start_service_reviewed_preparation_invalid')
        version = reviewed['scheduling_policy'].get('version')
        require(type(version) is int and version in SUPPORTED_VERSIONS,
                'service_scheduling_policy_version_unsupported')
        require(validate(reviewed), 'start_service_reviewed_preparation_invalid')
        require(len(matches) == 1, 'start_service_activity_match_invalid')
        require(matches[0].get('scheduling_preparation') == reviewed,
                'start_service_authorization_binding_invalid')
        require(reviewed['plan'] == prep['plan'], 'start_service_plan_binding_invalid')
        require(ports_for(db, request.assessment_id, prep['plan']['target'], version) == prep['plan']['ports'],
                'start_service_scope_ports_changed')
        if host.status in ('Queued', 'Running'):
            from .dispatch_verification import DispatchDeferred
            raise DispatchDeferred('host_discovery_dependency_pending')
        require(host.status == 'Completed', 'host_discovery_dependency_unsatisfied')
    current = preparation(db, host, prep['plan']['ports'])
    require(current == prep and validate_plan(prep['plan']), 'service_preparation_stale')
    expected = {'target_value': prep['plan']['target'], 'service_consent_digest': consent.digest,
                'scheduling_preparation': {'plan': prep['plan'], 'parameter_digest': prep['plan']['parameter_digest']}}
    require(request.authorized_activity == expected, 'service_activity_binding_invalid')
    if attempt is not None:
        require(attempt.request_id == request.id and attempt.worker_id == worker_id
                and attempt.claim_id == claim_id and attempt.status in ('Claimed', 'Running')
                and attempt.lease_expires_at > now and attempt.cancellation_requested_at is None
                and attempt.parameters == prep['plan']
                and attempt.parameter_digest == prep['plan']['parameter_digest'], 'worker_ownership_invalid')
    return {'dispatch_policy': authority(), 'start_authorization_id': str(request.authorization_id),
            'start_snapshot_digest': prep['start_snapshot_digest'], 'plan': prep['plan'],
            'scope_revision': prep['scope_revision'], 'target_revision': prep['target_revision'],
            'tool_revision': prep['tool_revision'], 'evaluation_id': prep['evaluation_id'],
            'evaluation_fingerprint': prep['evaluation_fingerprint'],
            'scheduling_policy_digest': prep['policy']['digest'], 'execution_authorized': True}
