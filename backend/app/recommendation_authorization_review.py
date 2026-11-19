"""Read-only, fail-closed recommendation authorization preflight.

This does not issue approvals or create execution requests.
"""
from sqlalchemy import select

from .baseline_catalog import fingerprint
from .models import AssessmentTarget, SecurityObservation
from .recommendation_eligibility import evaluate_recommendation
from .target_scope import classify, scope_entries


def review_authorization(db, assessment, recommendation_id):
    observations = db.scalars(select(SecurityObservation).where(
        SecurityObservation.assessment_id == assessment.id,
    ).order_by(SecurityObservation.collected_at, SecurityObservation.id)).all()
    result = evaluate_recommendation(recommendation_id, observations)
    if result['reason_code'] in ('invalid_recommendation_id', 'recommendation_not_current'):
        return result

    target = db.scalar(select(AssessmentTarget).where(
        AssessmentTarget.id == result['target_id'],
        AssessmentTarget.assessment_id == assessment.id,
    ))
    if assessment.status != 'Testing':
        reason = 'assessment_not_testing'
    elif target is None:
        reason = 'target_unavailable'
    elif (target.scope_revision != assessment.scope_revision
          or target.scope_status != 'in_scope'
          or target.kind != 'IP address'):
        reason = 'target_scope_stale'
    elif target.normalized_value != next(
        (item.data.get('address') for item in observations
         if item.id == result['source_observation_id'] and isinstance(item.data, dict)), None
    ):
        reason = 'observation_target_mismatch'
    elif classify(target.normalized_value, target.kind, scope_entries(db, assessment.id))[0] != 'in_scope':
        reason = 'target_out_of_scope'
    else:
        reason = 'followup_profile_not_supported'

    # Fingerprint is informational, not an authorization token.
    context = {
        'assessment_id': str(assessment.id),
        'recommendation_id': recommendation_id,
        'target_id': str(result['target_id']),
        'source_observation_id': str(result['source_observation_id']),
        'source_evidence_id': str(result['source_evidence_id']),
        'scope_revision': assessment.scope_revision,
        'target_revision': target.revision if target is not None else None,
    }
    return {**result, 'eligible': False, 'authorization_available': False,
            'execution_available': False, 'reason_code': reason,
            'review_fingerprint': fingerprint(context)}
