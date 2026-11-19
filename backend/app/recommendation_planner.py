"""Deterministic, read-only suggestions from persisted security observations.

No recommendation grants permission to dispatch a scanner.
"""
from hashlib import sha256


def plan_recommendations(observations):
    """Return conservative analyst review suggestions; never infer ports or services."""
    result = []
    seen = set()
    for observation in observations:
        if observation.observation_type != 'host_discovery' or observation.is_partial:
            continue
        data = observation.data
        if not isinstance(data, dict) or data.get('status') != 'up':
            continue
        address = data.get('address')
        if not isinstance(address, str) or not address or len(address) > 255:
            continue
        identity = (str(observation.target_id), address)
        if identity in seen:
            continue
        seen.add(identity)
        stable_id = sha256(f'host-review-v1:{identity[0]}:{identity[1]}'.encode()).hexdigest()
        result.append({
            'id': stable_id,
            'kind': 'review_host_discovery',
            'title': 'Review responding host',
            'target_id': observation.target_id,
            'target': address,
            'service': None,
            'port': None,
            'reason': 'A completed discovery observation recorded this host as responding.',
            'source_observation_id': observation.id,
            'source_evidence_id': observation.evidence_id,
            'execution_available': False,
            'execution_status': 'not_supported',
            'suggested_test': None,
            'suggested_tool': None,
        })
    return result
