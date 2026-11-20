"""Planner regression tests: suggestions are not executable authorizations."""
from types import SimpleNamespace
from uuid import uuid4

from app.recommendation_planner import plan_recommendations


def observation(kind='service_discovery', status='up', partial=False, address='192.0.2.10',
                target_id=None):
    return SimpleNamespace(
        id=uuid4(), target_id=target_id or uuid4(), evidence_id=uuid4(),
        observation_type=kind, is_partial=partial,
        data={'status': status, 'address': address, 'state': 'open' if status=='up' else 'closed', 'port':443, 'transport':'tcp', 'service':'https'},
    )


def test_no_observations_yields_no_recommendations():
    assert plan_recommendations([]) == []


def test_confirmed_service_produces_evidence_linked_pending_test():
    source = observation()
    item, = plan_recommendations([source])
    assert item['source_observation_id'] == source.id
    assert item['source_evidence_id'] == source.evidence_id
    assert item['target_id'] == source.target_id
    assert item['target'] == '192.0.2.10'
    assert item['execution_available'] is False
    assert item['suggested_test'] == 'HTTP Server Assessment'
    assert item['port'] == 443
    assert item['service'] == 'https'
    assert item['id'] == plan_recommendations([source])[0]['id']


def test_deduplicates_same_target_and_address():
    target_id = uuid4()
    assert len(plan_recommendations([
        observation(target_id=target_id),
        observation(target_id=target_id),
    ])) == 1


def test_does_not_infer_from_partial_down_or_unrecognized_observations():
    assert plan_recommendations([
        observation(partial=True),
        observation(status='down'),
        observation(kind='host_discovery'),
        observation(address=''),
    ]) == []
