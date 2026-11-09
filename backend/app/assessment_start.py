"""Build and authenticate a review of the exact work an analyst can confirm."""
from datetime import datetime, timedelta, timezone
from hmac import compare_digest
import json

from .baseline_catalog import fingerprint
from .security import client_key

SNAPSHOT_VERSION = 2
TOKEN_LIFETIME = timedelta(minutes=10)


def dependency_failure(item, candidates, policy_digest, now):
    evidence = item['safety_evidence']
    references = evidence['mandatory_activities']
    declared = {dep['profile_id']: dep['semantics'] for dep in item['policy_dependencies']}
    if sorted(profile for _, profile in references) != sorted(declared):
        return 'mandatory_activity_unavailable'
    completions = evidence['prerequisite_completions']
    expected = {tuple(ref) for ref in references if declared[ref[1]] == 'completed'}
    if len(completions) != len(expected) or {
        (proof['target_id'], proof['profile_id']) for proof in completions
    } != expected:
        return 'prerequisite_completion_unverified'
    for proof in completions:
        prerequisite = candidates.get((proof['target_id'], proof['profile_id']))
        completed = datetime.fromisoformat(proof['completed_at'])
        expiry = datetime.fromisoformat(proof['expires_at'])
        if (prerequisite is None or not proof['reference'].strip() or proof['successful'] is not True
                or proof['evaluation_id'] != prerequisite['evaluation_id']
                or proof['evaluation_fingerprint'] != prerequisite['evaluation_fingerprint']
                or proof['policy_digest'] != policy_digest or completed.utcoffset() is None
                or expiry.utcoffset() is None or not completed <= now < expiry):
            return 'prerequisite_completion_unverified'
    return None


def snapshot_for(readiness):
    targets = []
    pending = {}
    excluded_targets = []
    excluded_activities = []
    for target in sorted(readiness['targets'], key=lambda item: str(item['target_id'])):
        target_id = str(target['target_id'])
        targets.append({
            'target_id': target_id, 'value': target['value'], 'kind': target['kind'],
            'revision': target['target_revision'], 'scope_status': target['scope_status'],
        })
        if not target['baseline_activities']:
            excluded_targets.append({'target_id': target_id, 'reasons': target['reasons']})
        for activity in target['baseline_activities']:
            pair = (target_id, activity['profile_id'])
            item = {**activity, 'target_id': target_id}
            if item['evaluation_id']:
                item['evaluation_id'] = str(item['evaluation_id'])
            if item['start_review_eligible'] and item['safety_evidence']:
                pending[pair] = item
            else:
                code = ('lifecycle_not_draft' if readiness['lifecycle_status'] != 'Draft'
                        else item['policy']['reason_code'])
                excluded_activities.append({**item, 'exclusion_code': code})

    # Validate completion independently of graph membership. Graph traversal
    # then rejects missing, excluded, and cyclic dependencies of either kind.
    now = datetime.now(timezone.utc)
    for pair, item in list(pending.items()):
        code = dependency_failure(item, pending, readiness['policy']['digest'], now)
        if code:
            excluded_activities.append({**pending.pop(pair), 'start_review_eligible': False,
                                        'exclusion_code': code})

    # A cycle or a missing/blocked dependency never enters the eligible set.
    eligible = {}
    while pending:
        independent = [
            pair for pair, item in pending.items()
            if all(tuple(dep) in eligible for dep in item['safety_evidence']['mandatory_activities'])
        ]
        if not independent:
            break
        for pair in independent:
            eligible[pair] = pending.pop(pair)
    excluded_activities.extend(
        {**item, 'start_review_eligible': False, 'exclusion_code': 'mandatory_activity_unavailable'} for item in pending.values()
    )
    excluded_ids = {item['target_id'] for item in excluded_targets}
    eligible_ids = {pair[0] for pair in eligible}
    for target in targets:
        target_id = target['target_id']
        if target_id not in eligible_ids and target_id not in excluded_ids:
            excluded_targets.append({'target_id': target_id, 'reasons': [
                {'code': 'no_eligible_activity', 'message': 'No reviewed activity can be authorized for this target.'}
            ]})
    mode = None
    approval = readiness['policy_approval'] or {}
    if eligible and approval.get('reference'):
        mode = 'partial' if excluded_targets or excluded_activities else 'full'
    policy = readiness['policy']
    return {
        'schema_version': SNAPSHOT_VERSION,
        'assessment_id': str(readiness['assessment_id']),
        'lifecycle_status': readiness['lifecycle_status'],
        'scope_revision': readiness['scope_revision'],
        'scope_digest': readiness['scope_digest'],
        'targets': targets,
        'eligible_activities': [eligible[pair] for pair in sorted(eligible)],
        'excluded_activities': sorted(excluded_activities, key=lambda item: (item['target_id'], item['profile_id'])),
        'excluded_targets': sorted(excluded_targets, key=lambda item: item['target_id']),
        'policy': {**policy, 'approval_reference': approval.get('reference'),
                   'approval_expires_at': approval.get('expires_at')},
        'mode': mode,
    }


def signing_key(settings):
    key = settings.start_review_key
    if key is not None and len(key.get_secret_value().strip()) >= 32:
        return key.get_secret_value()
    return None


def signature(key, session_token, payload):
    session_key = client_key(key, 'assessment-start-session-v1:' + session_token)
    return client_key(session_key, 'assessment-start-review-v1:' + payload)


def start_review(snapshot, key, actor_id, session_token, *, creator):
    now = datetime.now(timezone.utc)
    digest = fingerprint(snapshot)
    possible = bool(creator and key and session_token and snapshot['mode'])
    expiry = None
    token = None
    if possible:
        expiry = min(
            now + TOKEN_LIFETIME,
            *(datetime.fromisoformat(item['safety_evidence']['expires_at']) for item in snapshot['eligible_activities']),
        )
        for item in snapshot['eligible_activities']:
            for proof in item['safety_evidence']['prerequisite_completions']:
                expiry = min(expiry, datetime.fromisoformat(proof['expires_at']))
        approval_expiry = snapshot['policy']['approval_expires_at']
        if approval_expiry:
            expiry = min(expiry, datetime.fromisoformat(approval_expiry))
        if expiry <= now:
            possible = False
            expiry = None
        else:
            payload = json.dumps({
                'assessment_id': snapshot['assessment_id'], 'actor_id': str(actor_id),
                'digest': digest, 'mode': snapshot['mode'], 'expires_at': expiry.isoformat(),
            }, sort_keys=True, separators=(',', ':'))
            token = payload.encode().hex() + '.' + signature(key, session_token, payload)
    return {
        **snapshot, 'confirmation_possible': possible, 'snapshot_digest': digest,
        'expires_at': expiry, 'review_token': token,
    }


def verify_review_token(token, key, session_token, assessment_id, actor_id, mode):
    if not key:
        return None
    try:
        encoded, supplied = token.split('.', 1)
        payload = bytes.fromhex(encoded).decode()
        if encoded != payload.encode().hex() or not compare_digest(signature(key, session_token, payload), supplied):
            return None
        claims = json.loads(payload)
        if (claims['assessment_id'] != str(assessment_id) or claims['actor_id'] != str(actor_id)
                or claims['mode'] != mode):
            return None
        return claims
    except (ValueError, KeyError, TypeError):
        return None
