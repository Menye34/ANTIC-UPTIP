"""Read-only assessment readiness diagnostics for the Start authorization workflow."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from sqlalchemy import select

from .baseline_catalog import fingerprint
from .baseline_resolution import baseline_view, current_assignments, tool_states
from .authorization_provider import load_trusted_policy
from .system_safety_verifier import verify_nmap_discovery
from .execution_policy import ActivityContext, decision, evaluate_activity
from .models import AssessmentTarget
from .target_scope import classify, scope_entries


@dataclass(frozen=True)
class PrerequisiteCompletion:
    target_id: str
    profile_id: str
    evaluation_id: str
    evaluation_fingerprint: str
    policy_digest: str
    reference: str
    successful: bool
    completed_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class StartEvidence:
    reference: str
    expires_at: datetime
    parameter_digest: str
    risk: str
    verified_prerequisites: frozenset[str]
    requested_units: int
    clear_stop_conditions: frozenset[str]
    mandatory_activities: frozenset[tuple[str, str]]
    prerequisite_completions: tuple[PrerequisiteCompletion, ...] = ()


def trusted_start_evidence(db, assessment_id, target_id, evaluation_id,
                           evaluation_fingerprint, policy_digest, approval_reference):
    """Retrieve persisted evidence bound to the exact approved assessment state."""
    from .start_evidence_provider import load_trusted_start_evidence

    return load_trusted_start_evidence(
        db, assessment_id, target_id, evaluation_id,
        evaluation_fingerprint, policy_digest, approval_reference,
    )


def reason(code, message):
    return {'code': code, 'message': message}


def evaluate_readiness(db, assessment):
    """Evaluate persisted state while the caller holds the assessment read lock."""
    boundaries = scope_entries(db, assessment.id)
    states = tool_states(db)
    assignments = current_assignments(db, assessment.id)
    targets = db.scalars(select(AssessmentTarget).where(AssessmentTarget.assessment_id == assessment.id)
                         .order_by(AssessmentTarget.created_at, AssessmentTarget.id)).all()
    now = datetime.now(timezone.utc)
    reasons = []
    if assessment.status != 'Draft':
        reasons.append(reason('lifecycle_not_draft', 'Only Draft assessments can proceed toward Start authorization.'))
    if not boundaries:
        reasons.append(reason('no_authorized_scope', 'The assessment has no authorized scope.'))
    if not targets:
        reasons.append(reason('no_targets', 'The assessment has no targets.'))

    policy = load_trusted_policy(db)
    policy_reason = reason(policy.code, policy.message)
    authorization_reason = reason('authorization_checks_unavailable', 'Execution dispatch authorization is unavailable.')
    if policy.status not in ('approved', 'configured'):
        reasons.append(policy_reason)
    reasons.append(authorization_reason)
    results = []
    for target in targets:
        target_reasons = []
        try:
            actual_scope, _ = classify(target.normalized_value, target.kind, boundaries)
        except ValueError:
            actual_scope = 'requires_revalidation'
        if (target.scope_revision != assessment.scope_revision
                or target.scope_status == 'requires_revalidation'
                or actual_scope == 'requires_revalidation'
                or (actual_scope == 'in_scope' and target.scope_status != actual_scope)):
            scope_status = 'requires_revalidation'
            target_reasons.append(reason('target_scope_requires_revalidation', 'Target scope classification must be revalidated.'))
        elif actual_scope != 'in_scope':
            scope_status = 'out_of_scope'
            target_reasons.append(reason('target_out_of_scope', 'The target is outside the current authorized scope.'))
        else:
            scope_status = 'in_scope'

        activities, summary = baseline_view(target, assessment.scope_revision, states, assignments.get(target.id, {}))
        if scope_status != 'in_scope':
            for activity in activities:
                activity.update(status='blocked' if scope_status == 'out_of_scope' else 'requires_revalidation',
                                reason_code=target_reasons[0]['code'], reason=target_reasons[0]['message'])
            if activities:
                summary = activities[0]['status']
        target_assignments = assignments.get(target.id, {})
        for activity in activities:
            _, evaluation = target_assignments.get(activity['profile_id'], (None, None))
            if activity['status'] == 'resolved' and (
                    evaluation is None or fingerprint(evaluation.decision) != evaluation.fingerprint):
                activity.update(status='requires_revalidation', reason_code='baseline_evidence_invalid',
                                reason='Stored baseline evidence must be revalidated.')
        if summary == 'resolved' and not any(activity['status'] == 'resolved' for activity in activities):
            summary = 'requires_revalidation'
        if not activities:
            target_reasons.append(reason('no_compatible_baseline', 'No baseline profile is compatible with this target.'))
        elif not any(activity['status'] == 'resolved' for activity in activities):
            target_reasons.append(reason('no_current_resolved_baseline', 'The target has no current resolved baseline.'))
        for activity in activities:
            _, evaluation = target_assignments.get(activity['profile_id'], (None, None))
            evidence = None
            if activity['status'] != 'resolved':
                activity_policy = decision(activity['reason_code'], activity['reason'])
            else:
                profile = evaluation.decision.get('profile', {})
                if policy.status == 'approved':
                    evidence = trusted_start_evidence(
                        db, assessment.id, target.id, evaluation.id,
                        evaluation.fingerprint, policy.definition.digest,
                        policy.approval.reference,
                    )
                    if evidence and (not evidence.reference or evidence.expires_at.tzinfo is None
                                     or evidence.expires_at <= now):
                        evidence = None
                activity_policy = evaluate_activity(policy, ActivityContext(
                    activity=activity['activity'], tool=activity['tool'],
                    capability=profile.get('capability', ''), target_kind=target.kind,
                    profile_id=activity['profile_id'], profile_version=activity['version'],
                    in_scope=scope_status == 'in_scope', baseline_current=True,
                    tool_capable=profile.get('capability') in evaluation.decision.get('tool_capabilities', []),
                    parameter_digest=evidence.parameter_digest if evidence else None,
                    risk=evidence.risk if evidence else None,
                    verified_prerequisites=evidence.verified_prerequisites if evidence else frozenset(),
                    requested_units=evidence.requested_units if evidence else None,
                    clear_stop_conditions=evidence.clear_stop_conditions if evidence else frozenset(),
                ))
            profile = evaluation.decision.get('profile', {}) if evaluation else {}
            activity['system_safety_verification'] = None
            if (
                policy.status == 'configured'
                and activity['status'] == 'resolved'
                and activity['tool'] == 'Nmap'
                and activity['profile_id'] == 'network-discovery'
            ):
                verification = verify_nmap_discovery(
                    in_scope=scope_status == 'in_scope',
                    baseline_current=True,
                    tool_capable=(
                        profile.get('capability')
                        in evaluation.decision.get('tool_capabilities', [])
                    ),
                    target_kind=target.kind,
                    profile_id=activity['profile_id'],
                    profile_version=activity['version'],
                )
                activity['system_safety_verification'] = {
                    'passed': verification.passed,
                    'checks': list(verification.checks),
                    'pending': list(verification.pending),
                }
            activity['profile_digest'] = profile.get('digest')
            activity['required_capability'] = profile.get('capability')
            activity['safety_evidence'] = None
            if evidence:
                details = {
                    'reference': evidence.reference, 'expires_at': evidence.expires_at.isoformat(),
                    'parameter_digest': evidence.parameter_digest, 'risk': evidence.risk,
                    'verified_prerequisites': sorted(evidence.verified_prerequisites),
                    'requested_units': evidence.requested_units,
                    'clear_stop_conditions': sorted(evidence.clear_stop_conditions),
                    'mandatory_activities': sorted([list(pair) for pair in evidence.mandatory_activities]),
                }
            rule = next((rule for rule in policy.definition.rules
                         if rule.rule_id == activity_policy['rule_id']), None) if policy.definition else None
            activity['policy_dependencies'] = sorted(
                [dep.model_dump() for dep in rule.activity_dependencies],
                key=lambda dep: dep['profile_id'],
            ) if rule else []
            activity['policy_eligible'] = activity_policy['disposition'] == 'preauthorized'
            if evidence:
                completions = []
                for completion in evidence.prerequisite_completions:
                    item = asdict(completion)
                    for field in ('completed_at', 'expires_at'):
                        item[field] = item[field].isoformat()
                    completions.append(item)
                details['prerequisite_completions'] = sorted(completions, key=fingerprint)
                activity['safety_evidence'] = {**details, 'fingerprint': fingerprint(details)}
            activity['policy'] = activity_policy
            activity['start_review_eligible'] = (
                assessment.status == 'Draft' and activity_policy['disposition'] == 'preauthorized'
            )
            activity['execution_authorized'] = False
            activity['evaluation_id'] = evaluation.id if evaluation else None
            activity['evaluation_fingerprint'] = evaluation.fingerprint if evaluation else None
        if assessment.status != 'Draft':
            target_reasons.append(reasons[0])
        target_eligible = (
            assessment.status == 'Draft'
            and scope_status == 'in_scope'
            and any(activity['start_review_eligible'] for activity in activities)
        )
        results.append({
            'target_id': target.id, 'value': target.normalized_value, 'kind': target.kind,
            'scope_status': scope_status, 'target_revision': target.revision,
            'state': 'eligible' if target_eligible else 'blocked',
            'eligible': target_eligible,
            'start_review_eligible': target_eligible,
            'execution_authorized': False,
            'baseline_summary': summary, 'baseline_activities': activities,
            'reasons': (
                target_reasons
                + ([policy_reason] if policy.status not in ('approved', 'configured') else [])
                + ([] if target_eligible else [authorization_reason])
            ),
        })

    return {
        'assessment_id': assessment.id, 'lifecycle_status': assessment.status,
        'scope_revision': assessment.scope_revision, 'scope_digest': fingerprint(sorted(map(list, boundaries))),
        'state': (
            'eligible' if results and all(t['eligible'] for t in results)
            else 'partial' if any(t['eligible'] for t in results)
            else 'blocked'
        ),
        'reasons': reasons,
        'counts': {
            'total': len(results),
            'eligible': sum(1 for t in results if t['eligible']),
            'blocked_or_excluded': sum(1 for t in results if not t['eligible']),
        },
        'policy': policy.public_view(),
        'policy_approval': {
            'reference': policy.approval.reference,
            'expires_at': policy.approval.expires_at.isoformat() if policy.approval.expires_at else None,
        } if policy.approval else None,
        'start_review_eligible': any(target['start_review_eligible'] for target in results),
        'execution_authorized': False,
        'authorization_checks': 'unavailable', 'targets': results,
    }
