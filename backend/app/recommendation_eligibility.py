"""Fail-closed eligibility evaluation for future recommendation-driven tests.

This module cannot authorize, queue, or dispatch an execution.
"""
from .recommendation_planner import plan_recommendations


def evaluate_recommendation(recommendation_id, observations):
    """Recompute recommendation identity from persisted observations, not client input."""
    if not isinstance(recommendation_id, str) or len(recommendation_id) != 64:
        return {'eligible': False, 'reason_code': 'invalid_recommendation_id',
                'authorization_available': False, 'execution_available': False}
    matches = [item for item in plan_recommendations(observations)
               if item['id'] == recommendation_id]
    if len(matches) != 1:
        return {'eligible': False, 'reason_code': 'recommendation_not_current',
                'authorization_available': False, 'execution_available': False}
    item = matches[0]
    # No independently authorized follow-up profile has been implemented.
    return {'eligible': False, 'reason_code': 'followup_profile_not_supported',
            'recommendation_id': item['id'],
            'source_observation_id': item['source_observation_id'],
            'source_evidence_id': item['source_evidence_id'],
            'target_id': item['target_id'],
            'authorization_available': False, 'execution_available': False,
            'available_profiles': []}
