"""Server-derived recommendation consent; no scanner or automatic approval."""
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from sqlalchemy.orm import load_only
from .baseline_catalog import fingerprint
from .models import Assessment, AssessmentTarget, User, RecommendationReviewEvent
from .nikto_profile import plan, activation
from .target_scope import classify, scope_entries


class StartUnavailable(ValueError):
    pass


def preparation(db, assessment_id, actor_id, recommendation_id, *, lock=True):
    def coordinated(query, *, read=False):
        return query.with_for_update(read=read) if lock else query
    # Actor -> assessment -> target -> job is the common writer lock order.
    actor = db.scalar(coordinated(select(User).options(load_only(User.id, User.status, User.role, User.password_change_required)).where(User.id == actor_id), read=True)
                      .execution_options(populate_existing=True))
    from .security import can_activate
    if actor is None or actor.role != 'Security Analyst' or not can_activate(actor):
        raise StartUnavailable('recommended_actor_unavailable')
    assessment = db.scalar(coordinated(select(Assessment).where(Assessment.id == assessment_id))
                           .execution_options(populate_existing=True))
    if assessment is None or assessment.creator_id != actor_id:
        raise StartUnavailable('recommended_creator_required')
    if assessment.status != 'Testing': raise StartUnavailable('assessment_not_testing')
    from .testing_completion_service import recommendation_state
    item = next((r for r in recommendation_state(db, assessment_id, actor)['recommendations']
                 if r['id'] == recommendation_id), None)
    if not item or item['decision'] != 'Reviewed' or item.get('review_outcome') != 'Accepted':
        raise StartUnavailable('recommendation_not_accepted')
    if item.get('suggested_tool') != 'Nikto' or item.get('proposed_test', {}).get('id') != 'http-server-assessment':
        raise StartUnavailable('recommended_profile_unsupported')
    target = db.scalar(coordinated(select(AssessmentTarget).where(AssessmentTarget.id == item['target_id'],
        AssessmentTarget.assessment_id == assessment_id), read=True).execution_options(populate_existing=True))
    boundaries = scope_entries(db, assessment_id)
    if (target is None or target.kind != 'IP address' or target.scope_status != 'in_scope'
            or target.scope_revision != assessment.scope_revision or target.normalized_value != item['target']
            or classify(target.normalized_value, target.kind, boundaries)[0] != 'in_scope'):
        raise StartUnavailable('recommended_scope_invalid')
    from .scope_ports import authorized_ports
    ports = authorized_ports(db, assessment_id, target.normalized_value)
    if ports and item['port'] not in ports: raise StartUnavailable('recommended_port_out_of_scope')
    from .models import BaselineToolState
    tool = db.scalar(coordinated(select(BaselineToolState).where(BaselineToolState.tool == 'Nikto'), read=True)
                     .execution_options(populate_existing=True))
    if tool is None or tool.state != 'enabled' or 'http-server-assessment' not in tool.capabilities:
        raise StartUnavailable('nikto_tool_unavailable')
    from .nikto_network_boundary import rules
    try:
        selected = activation()
        candidate = plan(item['target'], item['port'], item['service'], version=selected['policy']['version'])
        rules(candidate['target'], candidate['port'])
    except ValueError as exc:
        code = str(exc) if str(exc) in ('nikto_policy_activation_invalid','nikto_profile_integrity_invalid','nikto_policy_version_unsupported') else 'recommended_endpoint_unsupported'
        raise StartUnavailable(code) from None
    review = db.scalar(select(RecommendationReviewEvent).where(
        RecommendationReviewEvent.assessment_id == assessment_id,
        RecommendationReviewEvent.recommendation_id == recommendation_id)
        .order_by(RecommendationReviewEvent.revision.desc()).limit(1))
    if review is None or review.outcome != 'Accepted' or review.context_digest != recommendation_id:
        raise StartUnavailable('recommended_acceptance_unverified')
    facts = {'schema_version': 1, 'assessment_id': str(assessment_id), 'actor_id': str(actor_id),
             'target_id': str(target.id), 'target_revision': target.revision,
             'scope_revision': assessment.scope_revision, 'scope_digest': fingerprint(sorted(map(list, boundaries))),
             'recommendation_id': recommendation_id, 'review_id': str(review.id), 'review_revision': review.revision,
             'tool_revision': tool.revision,
             'observation_id': str(item['source_observation_id']), 'evidence_id': str(item['source_evidence_id']),
             'plan': candidate}
    if selected['policy']['version'] == 2:
        facts['dispatch_activation'] = {'policy_id': selected['policy']['id'], 'version': 2,
            'digest': selected['policy']['digest']}
    return facts


def consent(facts):
    now = datetime.now(timezone.utc)
    return {**facts, 'confirmed_at': now.isoformat(), 'expires_at': (now + timedelta(hours=1)).isoformat()}


def revalidate(db, job):
    saved = job.authorization_snapshot
    if not isinstance(saved, dict): return False
    try:
        confirmed = datetime.fromisoformat(saved['confirmed_at'])
        expiry = datetime.fromisoformat(saved['expires_at'])
        if not confirmed.tzinfo or not expiry.tzinfo or not confirmed <= datetime.now(timezone.utc) < expiry <= confirmed + timedelta(hours=1):
            return False
        # The worker's narrow lock helper already coordinates these sources.
        facts = preparation(db, job.assessment_id, job.actor_id, job.recommendation_id, lock=False)
        return (facts == {k: v for k, v in saved.items() if k not in ('confirmed_at','expires_at')}
                and job.execution_plan == facts['plan'] and str(job.target_id) == facts['target_id']
                and job.scope_revision == facts['scope_revision'])
    except (ValueError, TypeError, KeyError):
        return False
