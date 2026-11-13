"""Version 1 permits queued preparation only, never scanner execution.

Application-release policy, deliberately independent of execution approvals.
Only one canonical IPv4 address and the reviewed -sn profile are supported.
"""
from dataclasses import asdict
from .baseline_catalog import Profile, fingerprint
from .nmap_execution_binding import build_nmap_discovery_plan, ExecutionBindingError

POLICY_ID = 'uptip-baseline-scheduling'
POLICY_VERSION = 1
PREPARATION_VERSION = 1
# Independent release-owned definitions: do not derive trust from mutable input.
_PROFILE = Profile('network-discovery', 1, 'Nmap', 'Network Discovery',
    'Prepare network discovery for an explicitly authorized IPv4 target.',
    'ipv4-discovery', ('IP address', 'Subnet'),
    'Only the authorized IPv4 address or contained subnet.')
_PARAMETER_DEFINITION = {
    'profile_id': 'network-discovery', 'profile_version': 1, 'tool': 'Nmap',
    'activity': 'Network Discovery', 'capability': 'ipv4-discovery',
    'target_kind': 'IP address', 'arguments': ['-sn'], 'risk': 'low',
    'max_units': 1, 'allow_port_scanning': False, 'allow_scripts': False,
    'allow_target_expansion': False,
}
REQUIRED_CHECKS = ('scope_current', 'baseline_current', 'tool_capable', 'restricted_plan')


def definition():
    return {'id': POLICY_ID, 'version': POLICY_VERSION, 'purpose': 'schedule_only',
            'profile': _PROFILE.snapshot(), 'parameters': dict(_PARAMETER_DEFINITION),
            'target_kind': 'IP address', 'max_units_per_activity': 1,
            'prerequisites': list(REQUIRED_CHECKS), 'dependencies': []}


def public_policy():
    value = definition()
    return {'id': POLICY_ID, 'version': POLICY_VERSION, 'digest': fingerprint(value),
            'status': 'system_managed', 'purpose': 'schedule_only'}


def blocked(code, message):
    return {'disposition': 'blocked', 'rule_id': None, 'reason_code': code, 'reason': message}


def prepare(assessment, target, activity, evaluation, tool, scope_status, scope_digest):
    """Derive reproducible preparation facts from current server-owned inputs."""
    if assessment.status != 'Draft':
        return None, blocked('lifecycle_not_draft', 'Only Draft assessments can be started.')
    if scope_status != 'in_scope' or target.scope_revision != assessment.scope_revision:
        return None, blocked('target_scope_invalid', 'Current authorized target scope is required.')
    if target.kind != 'IP address' or activity['profile_id'] != 'network-discovery':
        return None, blocked('scheduling_profile_unsupported', 'This target or baseline is not supported for scheduling.')
    if activity['status'] != 'resolved' or evaluation is None:
        return None, blocked(activity['reason_code'], activity['reason'])
    if fingerprint(evaluation.decision) != evaluation.fingerprint:
        return None, blocked('baseline_evidence_invalid', 'Baseline evaluation must be revalidated.')
    profile = evaluation.decision.get('profile')
    if fingerprint(profile) != fingerprint(_PROFILE.snapshot()):
        return None, blocked('scheduling_profile_changed', 'Baseline profile differs from the reviewed scheduling profile.')
    if (tool is None or tool.state != 'enabled' or 'ipv4-discovery' not in tool.capabilities):
        return None, blocked('scheduling_tool_unavailable', 'A trusted enabled IPv4 discovery capability is required.')
    try:
        plan = build_nmap_discovery_plan(target=target.normalized_value,
                    approved_parameter_digest=fingerprint(_PARAMETER_DEFINITION))
    except ExecutionBindingError:
        return None, blocked('scheduling_parameters_invalid', 'Prepared parameters do not match the restricted scheduling profile.')
    checks = {'scope_current', 'baseline_current', 'tool_capable', 'restricted_plan'}
    if set(REQUIRED_CHECKS) != checks:
        return None, blocked('scheduling_prerequisites_unsatisfied', 'Scheduling prerequisites are unsupported or unsatisfied.')
    policy = public_policy()
    facts = {
        'schema_version': PREPARATION_VERSION, 'purpose': 'schedule_only',
        'assessment_id': str(assessment.id), 'target_id': str(target.id),
        'scope_revision': assessment.scope_revision, 'scope_digest': scope_digest,
        'target_revision': target.revision, 'target_value': target.normalized_value,
        'target_kind': target.kind, 'evaluation_id': str(evaluation.id),
        'evaluation_fingerprint': evaluation.fingerprint,
        'tool_revision': tool.revision, 'required_capability': 'ipv4-discovery',
        'scheduling_policy': policy, 'profile_digest': profile['digest'],
        'parameter_digest': plan.parameter_digest, 'plan': asdict(plan),
        'verified_checks': sorted(checks), 'units': 1, 'dependencies': [],
    }
    facts['plan']['arguments'] = list(plan.arguments)
    return {**facts, 'fingerprint': fingerprint(facts)}, {
        'disposition': 'preauthorized', 'rule_id': 'schedule-ipv4-discovery-v1',
        'reason_code': 'scheduling_plan_verified',
        'reason': 'Restricted baseline plan verified for queued scheduling only.',
    }


def validate_preparation(facts):
    """Validate persisted scheduling facts again before constructing a queue."""
    if not isinstance(facts, dict):
        return False
    try:
        content = {key: value for key, value in facts.items() if key != 'fingerprint'}
        plan = build_nmap_discovery_plan(target=facts['target_value'],
                    approved_parameter_digest=fingerprint(_PARAMETER_DEFINITION))
        expected_plan = {**asdict(plan), 'arguments': list(plan.arguments)}
        return (facts['fingerprint'] == fingerprint(content)
                and facts['schema_version'] == PREPARATION_VERSION
                and facts['purpose'] == 'schedule_only' and facts['target_kind'] == 'IP address'
                and facts['scheduling_policy'] == public_policy()
                and facts['plan'] == expected_plan and facts['parameter_digest'] == plan.parameter_digest
                and facts['profile_digest'] == _PROFILE.snapshot()['digest']
                and type(facts['units']) is int and facts['units'] == 1
                and facts['required_capability'] == 'ipv4-discovery'
                and type(facts['tool_revision']) is int and facts['tool_revision'] > 0
                and facts['dependencies'] == [] and facts['verified_checks'] == sorted(REQUIRED_CHECKS)
                and set(REQUIRED_CHECKS) == {'scope_current','baseline_current','tool_capable','restricted_plan'})
    except (KeyError, TypeError, ValueError):
        return False
