"""Unit contract for conservative normalization and finding identity."""
from types import SimpleNamespace
from uuid import uuid4

from app.findings_processing import normalize


def record(kind='security_issue', partial=False, data=None):
    assessment, target = uuid4(), uuid4()
    observation = SimpleNamespace(assessment_id=assessment, target_id=target,
        observation_type=kind, is_partial=partial, data=data or {})
    evidence = SimpleNamespace(is_partial=False)
    request = SimpleNamespace(authorized_activity={'target_value': 'https://example.test'})
    return observation, evidence, request


def issue(**changes):
    data = dict(issue_key='csp-header-missing', title='Content Security Policy Header Not Set',
        severity='Medium', affected_target='https://example.test',
        description='Missing header', impact='Content injection',
        security_control='CSP', observed_condition='Header absent',
        detected_issue='CSP missing', remediation='Configure CSP')
    data.update(changes)
    return data


def test_discovery_facts_never_become_vulnerabilities():
    for kind in ('host_discovery', 'service_discovery'):
        assert normalize(*record(kind=kind, data=issue())) is None


def test_partial_and_untrusted_inputs_are_rejected():
    observation, evidence, request = record(data=issue())
    observation.is_partial = True
    assert normalize(observation, evidence, request) is None
    observation.is_partial = False
    evidence.is_partial = True
    assert normalize(observation, evidence, request) is None
    evidence.is_partial = False
    for invalid in (issue(severity='Unknown'), issue(severity='Critical-ish'),
                    issue(affected_target='https://other.test'), issue(issue_key=''),
                    issue(description='')):
        observation.data = invalid
        assert normalize(observation, evidence, request) is None


def test_supported_issue_normalizes_and_is_stable():
    observation, evidence, request = record(data=issue())
    first = normalize(observation, evidence, request)
    second = normalize(observation, evidence, request)
    assert first == second
    assert first[1]['severity'] == 'Medium'
    assert len(first[0]) == 64


def test_distinct_issues_get_distinct_identities():
    observation, evidence, request = record(data=issue())
    original = normalize(observation, evidence, request)[0]
    observation.data = issue(issue_key='other-issue')
    assert normalize(observation, evidence, request)[0] != original
