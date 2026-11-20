"""Fail-closed recommendation authorization review tests."""
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import patch

from app.recommendation_authorization_review import review_authorization


def fixture(status='Testing', scope_status='in_scope'):
    assessment = SimpleNamespace(id=uuid4(), status=status, scope_revision=3)
    target = SimpleNamespace(id=uuid4(), assessment_id=assessment.id,
        normalized_value='192.0.2.10', kind='IP address', scope_revision=3,
        scope_status=scope_status, revision=2)
    observation = SimpleNamespace(id=uuid4(), target_id=target.id, evidence_id=uuid4(),
        observation_type='service_discovery', is_partial=False,
        data={'state':'open', 'address':'192.0.2.10', 'port':443,'transport':'tcp','service':'https'})
    from app.recommendation_planner import plan_recommendations
    recommendation_id = plan_recommendations([observation])[0]['id']
    db = SimpleNamespace()
    db.scalars = lambda query: SimpleNamespace(all=lambda: [observation])
    db.scalar = lambda query: target
    return db, assessment, recommendation_id


def test_review_remains_non_authorizing_even_when_scope_matches():
    db, assessment, recommendation_id = fixture()
    with patch('app.recommendation_authorization_review.scope_entries',
               return_value=[('192.0.2.10', 'IP address')]):
        result = review_authorization(db, assessment, recommendation_id)
    assert result['reason_code'] == 'tool_integration_pending'
    assert result['eligible'] is False
    assert result['authorization_available'] is False
    assert result['execution_available'] is False
    assert len(result['review_fingerprint']) == 64


def test_review_denies_stale_scope():
    db, assessment, recommendation_id = fixture(scope_status='requires_revalidation')
    result = review_authorization(db, assessment, recommendation_id)
    assert result['reason_code'] == 'target_scope_stale'
    assert result['eligible'] is False


def test_review_denies_non_testing_assessment():
    db, assessment, recommendation_id = fixture(status='Draft')
    result = review_authorization(db, assessment, recommendation_id)
    assert result['reason_code'] == 'assessment_not_testing'
