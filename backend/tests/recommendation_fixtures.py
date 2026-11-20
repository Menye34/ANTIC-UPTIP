"""Contract mocks only: never scan results, tool registrations or database facts."""
from types import SimpleNamespace
from app.recommendation_planner import plan_recommendations


def synthetic_recommendations(observations):
    """Isolate completion/decision contracts from the production planner rules.

    The real Nmap producer remains host-discovery-only and its DB guard rejects
    services. These mocked planner inputs do not assert that it found HTTPS.
    Pure planner tests separately test typed service/web-application facts.
    """
    synthetic = [SimpleNamespace(id=o.id,target_id=o.target_id,evidence_id=o.evidence_id,
        is_partial=o.is_partial,observation_type='service_discovery',
        data={'address':o.data.get('address'),'port':443,'transport':'tcp','state':'open','service':'https'})
        for o in observations]
    return plan_recommendations(synthetic)


def mock_recommendations(monkeypatch):
    monkeypatch.setattr('app.testing_completion_service.plan_recommendations',synthetic_recommendations)
    monkeypatch.setattr('app.recommendation_eligibility.plan_recommendations',synthetic_recommendations)
