from uuid import uuid4

from sqlalchemy import select

from . import baseline_catalog
from .baseline_catalog import fingerprint
from .models import AssessmentTarget, BaselineAssignment, BaselineEvaluation, BaselineToolState


def tool_states(db):
    return {row.tool: row for row in db.scalars(select(BaselineToolState))}


def compatible_profiles(target):
    return sorted((profile for profile in baseline_catalog.PROFILES if target.kind in profile.kinds),
                  key=lambda profile: profile.key)


def evaluate(target, scope_revision, profile, tool):
    if target.scope_revision != scope_revision or target.scope_status == 'requires_revalidation':
        status, code, reason = 'requires_revalidation', 'scope_stale', 'Target scope must be revalidated.'
    elif target.scope_status != 'in_scope':
        status, code, reason = 'blocked', 'outside_scope', 'Target is outside the authorized scope.'
    elif tool is None or tool.state != 'enabled':
        state = tool.state if tool else 'unknown'
        status, code, reason = 'unavailable', f'tool_{state}', {
            'unknown': 'Tool availability has not been verified.',
            'disabled': 'Tool is disabled.',
            'unavailable': 'Tool is unavailable.',
        }[state]
    elif profile.capability not in tool.capabilities:
        status, code, reason = 'unavailable', 'capability_missing', 'Required tool capability is unavailable.'
    else:
        status, code, reason = 'resolved', 'prepared', 'Baseline prepared for review.'
    return {
        'profile': profile.snapshot(), 'target_value': target.normalized_value,
        'target_kind': target.kind, 'target_scope_status': target.scope_status,
        'target_revision': target.revision, 'scope_revision': scope_revision,
        'classified_scope_revision': target.scope_revision,
        'tool_revision': tool.revision if tool else None,
        'tool_state': tool.state if tool else 'unknown',
        'tool_capabilities': sorted(tool.capabilities) if tool else [],
        'status': status, 'reason_code': code, 'reason': reason,
    }


def current_assignments(db, assessment_id):
    rows = db.execute(select(BaselineAssignment, BaselineEvaluation)
                      .join(BaselineEvaluation, BaselineAssignment.evaluation_id == BaselineEvaluation.id)
                      .where(BaselineEvaluation.assessment_id == assessment_id))
    result = {}
    for assignment, evaluation in rows:
        result.setdefault(assignment.target_id, {})[assignment.profile_key] = (assignment, evaluation)
    return result


def reconcile(db, assessment, trigger, targets=None):
    """Caller holds the assessment write lock and owns the transaction."""
    if targets is None:
        targets = db.scalars(select(AssessmentTarget).where(AssessmentTarget.assessment_id == assessment.id))
    states = tool_states(db)
    current = current_assignments(db, assessment.id)
    for target in targets:
        previous = current.get(target.id, {})
        for profile in compatible_profiles(target):
            decision = evaluate(target, assessment.scope_revision, profile, states.get(profile.tool))
            digest = fingerprint(decision)
            assignment, evaluation = previous.pop(profile.key, (None, None))
            if evaluation is not None and evaluation.fingerprint == digest:
                continue
            event = BaselineEvaluation(id=uuid4(), assessment_id=assessment.id, target_id=target.id,
                                       profile_key=profile.key, fingerprint=digest, decision=decision, trigger=trigger)
            db.add(event)
            db.flush()
            if assignment is None:
                db.add(BaselineAssignment(target_id=target.id, profile_key=profile.key, evaluation_id=event.id))
            else:
                assignment.evaluation_id = event.id
        for assignment, _ in previous.values():
            db.delete(assignment)


def baseline_view(target, scope_revision, states, current):
    assignments = []
    for profile in compatible_profiles(target):
        expected = evaluate(target, scope_revision, profile, states.get(profile.tool))
        _, recorded = current.get(profile.key, (None, None))
        if recorded is None:
            status, code, reason = 'pending', 'evaluation_pending', 'Baseline evaluation is pending.'
        elif recorded.fingerprint != fingerprint(expected):
            status, code, reason = 'requires_revalidation', 'inputs_changed', 'Baseline inputs changed. Revalidation is required.'
        else:
            status, code, reason = expected['status'], expected['reason_code'], expected['reason']
        assignments.append({'profile_id': profile.key, 'version': profile.version, 'tool': profile.tool,
                            'activity': profile.activity, 'status': status, 'reason_code': code, 'reason': reason,
                            'target_revision': target.revision, 'scope_revision': scope_revision,
                            'tool_revision': expected['tool_revision']})
    statuses = {item['status'] for item in assignments}
    summary = next((status for status in ('resolved', 'requires_revalidation', 'pending', 'unavailable', 'blocked')
                    if status in statuses), 'no_compatible_baseline')
    return assignments, summary
