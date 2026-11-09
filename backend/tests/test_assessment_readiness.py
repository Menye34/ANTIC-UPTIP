from dataclasses import replace
from uuid import UUID

import pytest
from sqlalchemy import event

from app import baseline_catalog
from app.baseline_maintenance import record_tool_state
from app.models import AssessmentTarget
from test_assessments import API, add_analyst, sign_in


@pytest.fixture
def draft(client, db):
    owner = add_analyst(db, 'readiness-owner')
    headers = sign_in(client, owner.username)
    response = client.post(API, headers=headers, json={'name': 'Readiness assessment'})
    assert response.status_code == 201
    return f"{API}/{response.json()['id']}", headers


def test_empty_and_unauthorized_readiness(client, db, draft):
    path, _ = draft
    response = client.get(path + '/readiness')
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    data = response.json()
    assert data['assessment_id'] == path.rsplit('/', 1)[1]
    assert data['lifecycle_status'] == 'Draft'
    assert data['state'] == 'blocked'
    assert data['counts'] == {'total': 0, 'eligible': 0, 'blocked_or_excluded': 0}
    assert 'no_targets' in {reason['code'] for reason in data['reasons']}
    client.cookies.clear()
    assert client.get(path + '/readiness').status_code == 401
    other = add_analyst(db, 'readiness-outsider')
    sign_in(client, other.username)
    assert client.get(path + '/readiness').status_code == 404


def test_resolved_baselines_do_not_bypass_missing_policy(client, db, engine, draft, monkeypatch):
    path, headers = draft
    network, web = baseline_catalog.PROFILES
    second = replace(network, key='test-second-network-profile')
    monkeypatch.setattr(baseline_catalog, 'PROFILES', (network, web, second))
    record_tool_state(db, 'Nmap', 'enabled', ['ipv4-discovery'])
    db.commit()
    assert client.post(path + '/scope', headers=headers,
                       json={'revision': 0, 'value': '192.0.2.0/24'}).status_code == 201
    for value in ('192.0.2.1', '198.51.100.1'):
        assert client.post(path + '/targets', headers=headers, json={'value': value}).status_code == 201

    def assert_no_writes(conn, cursor, statement, *args):
        assert statement.lstrip().upper().startswith('SELECT'), statement

    event.listen(engine, 'before_cursor_execute', assert_no_writes)
    try:
        response = client.get(path + '/readiness')
        assert response.status_code == 200
        data = response.json()
        assert client.get(path + '/readiness').json() == data
    finally:
        event.remove(engine, 'before_cursor_execute', assert_no_writes)

    assert data['counts'] == {'total': 2, 'eligible': 0, 'blocked_or_excluded': 2}
    assert data['policy']['status'] == 'unavailable'
    assert data['policy']['version'] is None and data['policy']['provenance'] is None
    assert data['authorization_checks'] == 'unavailable'
    by_value = {target['value']: target for target in data['targets']}
    inside = by_value['192.0.2.1']
    assert not inside['eligible']
    assert [a['status'] for a in inside['baseline_activities']] == ['resolved', 'resolved']
    assert 'execution_policy_missing' in {r['code'] for r in inside['reasons']}
    outside = by_value['198.51.100.1']
    assert outside['scope_status'] == 'out_of_scope'
    assert all(a['status'] == 'blocked' for a in outside['baseline_activities'])


@pytest.mark.parametrize('tool_state,code', [
    ('disabled', 'tool_disabled'),
    ('unavailable', 'tool_unavailable'),
    ('unknown', 'tool_unknown'),
])
def test_baseline_unavailable_and_scope_revalidation(client, db, draft, tool_state, code):
    path, headers = draft
    record_tool_state(db, 'Nmap', tool_state, [])
    db.commit()
    assert client.post(path + '/scope', headers=headers,
                       json={'revision': 0, 'value': '192.0.2.0/24'}).status_code == 201
    response = client.post(path + '/targets', headers=headers, json={'value': '192.0.2.1'})
    assert response.status_code == 201
    target_id = UUID(response.json()['targets'][0]['id'])
    result = client.get(path + '/readiness').json()['targets'][0]
    assert result['baseline_summary'] == 'unavailable'
    assert result['baseline_activities'][0]['reason_code'] == code
    db.get(AssessmentTarget, target_id).scope_revision = 0
    db.commit()
    result = client.get(path + '/readiness').json()['targets'][0]
    assert result['scope_status'] == 'requires_revalidation'
    assert result['baseline_summary'] == 'requires_revalidation'


def test_target_without_compatible_baseline(client, draft):
    path, headers = draft
    assert client.post(path + '/scope', headers=headers,
                       json={'revision': 0, 'value': 'example.test'}).status_code == 201
    assert client.post(path + '/targets', headers=headers, json={'value': 'example.test'}).status_code == 201
    result = client.get(path + '/readiness').json()['targets'][0]
    assert result['baseline_summary'] == 'no_compatible_baseline'
    assert result['baseline_activities'] == []
    assert not result['eligible']


def test_tool_revision_invalidates_resolved_baseline_until_reconciliation(client, db, draft):
    from app.baseline_resolution import reconcile
    from app.models import Assessment

    path, headers = draft
    record_tool_state(db, 'Nmap', 'enabled', ['ipv4-discovery'])
    db.commit()
    assert client.post(path + '/scope', headers=headers,
                       json={'revision': 0, 'value': '192.0.2.0/24'}).status_code == 201
    assert client.post(path + '/targets', headers=headers, json={'value': '192.0.2.1'}).status_code == 201

    def activity():
        data = client.get(path + '/readiness').json()
        assert data['execution_authorized'] is False
        assert data['start_review_eligible'] is False
        return data['targets'][0]['baseline_activities'][0]

    assert activity()['status'] == 'resolved'
    record_tool_state(db, 'Nmap', 'disabled', [])
    db.commit()
    assert activity()['status'] == 'requires_revalidation'
    assert activity()['policy']['disposition'] == 'blocked'
    assessment_id = UUID(path.rsplit('/', 1)[1])
    from sqlalchemy import select
    assessment = db.scalar(select(Assessment).where(Assessment.id == assessment_id).with_for_update())
    reconcile(db, assessment, 'tool_state_changed')
    db.commit()
    assert activity()['status'] == 'unavailable'
    assert activity()['reason_code'] == 'tool_disabled'


def test_scope_override_recalculates_missing_resolved_baseline_reason(client, db, draft):
    from sqlalchemy import delete
    from app.models import ScopeEntry

    path, headers = draft
    record_tool_state(db, 'Nmap', 'enabled', ['ipv4-discovery'])
    db.commit()
    assert client.post(path + '/scope', headers=headers,
                       json={'revision': 0, 'value': '192.0.2.0/24'}).status_code == 201
    assert client.post(path + '/targets', headers=headers, json={'value': '192.0.2.1'}).status_code == 201
    db.execute(delete(ScopeEntry).where(ScopeEntry.assessment_id == UUID(path.rsplit('/', 1)[1])))
    db.commit()
    result = client.get(path + '/readiness').json()['targets'][0]
    assert result['baseline_activities'][0]['status'] == 'blocked'
    assert 'no_current_resolved_baseline' in {reason['code'] for reason in result['reasons']}


def test_approved_policy_cannot_bypass_missing_safety_evidence(client, db, engine, draft, monkeypatch):
    import socket
    import subprocess

    from app import assessment_readiness
    from app.execution_policy import PolicyDefinition, PolicyRule, select_policy

    path, headers = draft
    profile = baseline_catalog.PROFILES[0]
    definition = PolicyDefinition(policy_id='test-readiness-policy', version=1, rules=(
        PolicyRule(
            rule_id='test-network-rule', activity=profile.activity, tool=profile.tool,
            capability=profile.capability, target_kind='IP address', profile_id=profile.key,
            profile_version=profile.version, disposition='preauthorized',
            parameter_digest='a' * 64, risk='low', prerequisites=('test-prerequisite',),
            max_units=1, stop_conditions=('test-stop-condition',),
        ),
    ))
    approval = {'policy_id': definition.policy_id, 'version': definition.version,
                'digest': definition.digest, 'provenance': 'Synthetic readiness test only'}
    monkeypatch.setattr(assessment_readiness, 'effective_policy',
                        lambda: select_policy(definition, approval))

    record_tool_state(db, profile.tool, 'enabled', [profile.capability])
    db.commit()
    assert client.post(path + '/scope', headers=headers,
                       json={'revision': 0, 'value': '192.0.2.0/24'}).status_code == 201
    assert client.post(path + '/targets', headers=headers, json={'value': '192.0.2.1'}).status_code == 201

    def assert_read_only(conn, cursor, statement, *args):
        assert statement.lstrip().upper().startswith('SELECT'), statement

    def forbid_external_call(*args, **kwargs):
        pytest.fail('Readiness attempted an external call')

    event.listen(engine, 'before_cursor_execute', assert_read_only)
    try:
        with monkeypatch.context() as guard:
            guard.setattr(socket, 'getaddrinfo', forbid_external_call)
            guard.setattr(socket.socket, 'connect', forbid_external_call)
            guard.setattr(subprocess, 'Popen', forbid_external_call)
            response = client.get(path + '/readiness')
            assert response.status_code == 200
            assert response.headers['Cache-Control'] == 'no-store'
            data = response.json()
            assert client.get(path + '/readiness').json() == data
    finally:
        event.remove(engine, 'before_cursor_execute', assert_read_only)

    assert data['policy'] == {
        'status': 'approved', 'id': definition.policy_id, 'version': definition.version,
        'digest': definition.digest, 'provenance': approval['provenance'],
        'reason': {'code': 'execution_policy_approved',
                   'message': 'Execution policy matches the active approval.'},
    }
    target, = data['targets']
    activity, = target['baseline_activities']
    assert data['lifecycle_status'] == 'Draft'
    assert data['counts']['eligible'] == 0
    assert activity['status'] == 'resolved'
    assert activity['policy']['disposition'] == 'blocked'
    assert activity['policy']['rule_id'] == 'test-network-rule'
    assert activity['policy']['reason_code'] == 'activity_parameters_unverified'
    for result in (data, target, activity):
        assert result['start_review_eligible'] is False
        assert result['execution_authorized'] is False
