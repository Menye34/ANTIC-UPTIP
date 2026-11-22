"""Fail-closed eligibility evaluation for future recommendation-driven tests.

This module cannot authorize, queue, or dispatch an execution.
"""
import re
from .recommendation_planner import plan_recommendations


def evaluate_recommendation(recommendation_id, observations):
    """Recompute recommendation identity from persisted observations, not client input."""
    if not isinstance(recommendation_id, str) or not re.fullmatch(r'[0-9a-f]{64}', recommendation_id):
        return {'eligible': False, 'reason_code': 'invalid_recommendation_id',
                'authorization_available': False, 'execution_available': False}
    matches = [item for item in plan_recommendations(observations)
               if item['id'] == recommendation_id]
    if len(matches) != 1:
        return {'eligible': False, 'reason_code': 'recommendation_not_current',
                'authorization_available': False, 'execution_available': False}
    item = matches[0]
    # GET never grants scanner permission. Approved Nikto still requires the
    # separate creator-confirmed Start Test contract; alternatives remain absent.
    from .nikto_profile import integration_available
    reason = ('explicit_start_required' if item.get('suggested_tool') == 'Nikto' and integration_available()
              else item['execution_unavailability_reason'])
    return {'eligible': False, 'reason_code': reason,
            'recommendation_id': item['id'],
            'source_observation_id': item['source_observation_id'],
            'source_evidence_id': item['source_evidence_id'],
            'target_id': item['target_id'],
            'authorization_available': False, 'execution_available': False,
            'available_profiles': []}
