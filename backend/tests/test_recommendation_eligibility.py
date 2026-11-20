"""Recommendation eligibility must not imply permission to run a scanner."""
from types import SimpleNamespace
from uuid import uuid4

from app.recommendation_eligibility import evaluate_recommendation
from app.recommendation_planner import plan_recommendations


def observed(status='up', partial=False):
    return SimpleNamespace(
        id=uuid4(), target_id=uuid4(), evidence_id=uuid4(),
        observation_type='service_discovery', is_partial=partial,
        data={'state': 'open' if status=='up' else 'closed', 'address': '192.0.2.10', 'port':443, 'transport':'tcp','service':'https'},
    )


def test_known_recommendation_remains_non_executable():
    source = observed()
    recommendation_id = plan_recommendations([source])[0]['id']
    result = evaluate_recommendation(recommendation_id, [source])
    assert result['reason_code'] == 'tool_integration_pending'
    assert result['eligible'] is False
    assert result['authorization_available'] is False
    assert result['execution_available'] is False
    assert result['available_profiles'] == []
    assert result['source_observation_id'] == source.id
    assert result['source_evidence_id'] == source.evidence_id


def test_stale_recommendation_is_rejected():
    source = observed()
    recommendation_id = plan_recommendations([source])[0]['id']
    assert evaluate_recommendation(recommendation_id, [])['reason_code'] == 'recommendation_not_current'
    source.is_partial = True
    assert evaluate_recommendation(recommendation_id, [source])['eligible'] is False


def test_invalid_or_untrusted_identifier_is_rejected():
    for value in ('', 'not-an-id', None, 123, 'x' * 100):
        result = evaluate_recommendation(value, [observed()])
        assert result['eligible'] is False
        assert result['reason_code'] == 'invalid_recommendation_id'


def test_down_host_cannot_be_eligible():
    assert evaluate_recommendation('a' * 64, [observed(status='down')])['eligible'] is False
