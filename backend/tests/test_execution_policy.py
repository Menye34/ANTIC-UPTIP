from dataclasses import replace

import pytest

from app.execution_policy import ActivityContext, evaluate_activity, select_policy

# Synthetic policy examples. No operational policy is installed by these tests.
RULE = {
    'rule_id': 'test-rule', 'activity': 'Fixture activity', 'tool': 'Fixture tool',
    'capability': 'fixture-capability', 'target_kind': 'IP address',
    'profile_id': 'fixture-profile', 'profile_version': 1, 'disposition': 'preauthorized',
    'parameter_digest': 'a' * 64, 'risk': 'low', 'prerequisites': ('fixture-ready',),
    'max_units': 2, 'stop_conditions': ('fixture-stop',),
}
CONTEXT = ActivityContext(
    activity=RULE['activity'], tool=RULE['tool'], capability=RULE['capability'],
    target_kind=RULE['target_kind'], profile_id=RULE['profile_id'], profile_version=1,
    in_scope=True, baseline_current=True, tool_capable=True,
    parameter_digest=RULE['parameter_digest'], risk='low',
    verified_prerequisites=frozenset({'fixture-ready'}), requested_units=1,
    clear_stop_conditions=frozenset({'fixture-stop'}),
)


def policy(*rules, **approval_overrides):
    from app.execution_policy import PolicyDefinition

    definition = PolicyDefinition(policy_id='test-policy', version=1, rules=rules)
    approval = {'policy_id': definition.policy_id, 'version': definition.version,
                'digest': definition.digest, 'provenance': 'Test fixture only'}
    return select_policy(definition, {**approval, **approval_overrides})


def test_per_activity_dispositions_and_denial_precedence():
    secondary = {**RULE, 'rule_id': 'analyst-rule', 'activity': 'Second activity',
                 'risk': 'high', 'disposition': 'requires_analyst_decision'}
    denied = {**RULE, 'rule_id': 'deny-rule', 'activity': 'Denied activity', 'disposition': 'blocked'}
    selected = policy(RULE, secondary, denied)
    assert evaluate_activity(selected, CONTEXT)['disposition'] == 'preauthorized'
    assert evaluate_activity(selected, replace(CONTEXT, activity='Second activity', risk='high'))[
        'disposition'] == 'requires_analyst_decision'
    assert evaluate_activity(selected, replace(CONTEXT, activity='Denied activity'))['disposition'] == 'blocked'
    conflict = policy(RULE, {**denied, 'activity': RULE['activity']})
    assert evaluate_activity(conflict, CONTEXT)['rule_id'] == 'deny-rule'
    ambiguous = policy(RULE, {**RULE, 'rule_id': 'other-rule'})
    assert evaluate_activity(ambiguous, CONTEXT)['reason_code'] == 'policy_rule_ambiguous'


@pytest.mark.parametrize('changes,code', [
    ({'in_scope': False}, 'activity_safety_gate_failed'),
    ({'baseline_current': False}, 'activity_safety_gate_failed'),
    ({'tool_capable': False}, 'activity_safety_gate_failed'),
    ({'profile_version': 2}, 'policy_rule_missing'),
    ({'capability': 'unknown'}, 'policy_rule_missing'),
    ({'parameter_digest': None}, 'activity_parameters_unverified'),
    ({'risk': None}, 'activity_risk_unverified'),
    ({'verified_prerequisites': frozenset()}, 'activity_prerequisites_unverified'),
    ({'requested_units': 3}, 'activity_limit_unverified'),
    ({'clear_stop_conditions': frozenset()}, 'activity_stop_conditions_unverified'),
])
def test_policy_fails_closed_for_missing_or_stale_activity_inputs(changes, code):
    result = evaluate_activity(policy(RULE), replace(CONTEXT, **changes))
    assert result['reason_code'] == code
    assert result['disposition'] == 'blocked'


def test_policy_approval_is_bound_to_identity_version_and_digest():
    definition = {'policy_id': 'test-policy', 'version': 1, 'rules': (RULE,)}
    assert select_policy(None, None).status == 'unavailable'
    assert select_policy(definition, None).status == 'unapproved'
    assert select_policy({**definition, 'rules': ({**RULE, 'risk': 'high'},)}, None).status == 'invalid'
    assert policy(RULE, provenance=' ').status == 'invalid'
    assert policy(RULE, version=2).status == 'stale'
    assert policy(RULE, policy_id='wrong').status == 'stale'
    assert policy(RULE, digest='b' * 64).status == 'stale'
