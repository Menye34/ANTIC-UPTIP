"""Assessment-scoped completion reads and calculations; no execution authority."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from types import SimpleNamespace

from fastapi import HTTPException
from sqlalchemy import and_, func, select
from pydantic import ValidationError

from .assessment_routes import accessible
from .models import (Assessment, BaselineExecutionRequest, ExecutionAttempt,
                     ResultProcessingOutcome, SecurityObservation,
                     TestingRecommendationDecision, TestingCompletionEvent, ScannerEvidence, RecommendationReviewEvent)
from .recommendation_planner import plan_recommendations, carry_deferred_legacy
from .security import can_activate

VERSION = 2
STATES = ('Queued', 'Running', 'Completed', 'Failed', 'Stopped', 'Blocked', 'Cancelled')
ACTIVE = ('Claimed', 'Running', 'RecoveryRequired')


@dataclass(frozen=True)
class CompletionState:
    assessment_id: str
    name: str
    lifecycle: str
    creator_id: str
    scope_revision: int
    executions: list
    attempts: list
    processing: list
    observations: list
    decisions: list
    receipt: dict | None
    review_events: list = field(default_factory=list)


def aggregate(model, fields):
    values = [value for key in fields for value in (key, getattr(model, key))]
    return select(func.json_agg(func.json_build_object(*values))).where(
        model.assessment_id == Assessment.id).correlate(Assessment).scalar_subquery()


def load_state(db, assessment_id, user):
    """One statement/MVCC snapshot, including access, lifecycle and receipt."""
    query = select(
        Assessment.id, Assessment.name, Assessment.status, Assessment.creator_id, Assessment.scope_revision,
        aggregate(BaselineExecutionRequest, ('id', 'target_id', 'authorization_id', 'profile_id', 'profile_version',
                                            'status')).label('executions'),
        aggregate(ExecutionAttempt, ('id', 'request_id', 'attempt_number', 'status', 'parameter_digest',
                                     'started_at', 'finished_at', 'terminated_at', 'termination_outcome',
                                     'exit_code', 'reason_code')).label('attempts'),
        aggregate(ResultProcessingOutcome, ('id', 'request_id', 'evidence_id', 'status', 'processor',
                                            'processor_version', 'run_number', 'is_partial',
                                            'finished_at', 'observation_count', 'error_code')).label('processing'),
        aggregate(SecurityObservation, ('id', 'target_id', 'request_id', 'evidence_id', 'processing_id',
                                        'observation_type', 'data', 'is_partial', 'collected_at',
                                        'processed_at')).label('observations'),
        aggregate(TestingRecommendationDecision, ('recommendation_id', 'actor_id', 'decision',
                                                   'decided_at')).label('decisions'),
        aggregate(RecommendationReviewEvent, ('id','recommendation_id','actor_id','outcome','revision','decided_at')).label('review_events'),
        select(func.json_build_object('actor_id', TestingCompletionEvent.actor_id,
                                      'completed_at', TestingCompletionEvent.completed_at,
                                      'snapshot', TestingCompletionEvent.snapshot))
        .where(TestingCompletionEvent.assessment_id == Assessment.id).correlate(Assessment)
        .scalar_subquery().label('receipt'),
    ).where(Assessment.id == assessment_id, accessible(user))
    from .recommended_test_queue import RecommendedTestJob
    query = query.add_columns(aggregate(RecommendedTestJob, ('id','target_id','profile_id','profile_version','status')).label('recommended'))
    row = db.execute(query).mappings().one_or_none()
    if row is None:
        raise HTTPException(404)
    return CompletionState(str(row['id']), row['name'], row['status'], str(row['creator_id']),
                           row['scope_revision'], (row['executions'] or []) + (row['recommended'] or []), row['attempts'] or [],
                           row['processing'] or [], row['observations'] or [], row['decisions'] or [], row['receipt'], row['review_events'] or [])


def lock_inputs(db, assessment_id):
    """Caller already holds actor/session and exclusive assessment locks.

    Existing worker writers use that parent lock. Do not lock decisions after
    the parent: their update trigger already coordinates through the parent.
    """
    from .recommended_test_queue import RecommendedTestJob
    for model in (BaselineExecutionRequest, RecommendedTestJob, ExecutionAttempt, ResultProcessingOutcome, SecurityObservation):
        if model is RecommendedTestJob:
            from sqlalchemy import text
            db.execute(text('SELECT public.lock_recommended_assessment_jobs(:id)'), {'id': assessment_id})
            continue
        db.execute(select(model.id).where(model.assessment_id == assessment_id)
                   .order_by(model.id).with_for_update()).all()


def decision_statistics(suggestions, decisions):
    """Only current generated IDs participate; review never grants execution rights."""
    by_id = {item['recommendation_id']: item['decision'] for item in decisions}
    items = [{**item, 'decision': by_id.get(item['id'])} for item in suggestions]
    reviewed = sum(item['decision'] == 'Reviewed' for item in items)
    deferred = sum(item['decision'] == 'Deferred' for item in items)
    pending = [item['id'] for item in items if item['decision'] != 'Reviewed']
    counts = {'total': len(items), 'pending_review': len(items) - reviewed - deferred,
              'reviewed': reviewed, 'deferred': deferred, 'pending_completion': len(pending)}
    return items, pending, counts


def recommendation_statistics(observations, decisions):
    ordered = sorted(observations, key=lambda item: (utc(item['collected_at']), item['id']))
    objects = [SimpleNamespace(**item) for item in ordered]
    suggestions = carry_deferred_legacy(objects, decisions, plan_recommendations(objects))
    items, pending, counts = decision_statistics(suggestions, decisions)
    return [{key: item[key] for key in ('id', 'title', 'decision')} for item in items], pending, counts


def recommendation_state(db, assessment_id, user):
    """Access, observations, decisions and validated provenance in one MVCC read."""
    sources = (select(func.json_agg(func.json_build_object(
        'observation_id', SecurityObservation.id, 'execution_id', BaselineExecutionRequest.id, 'test_name', BaselineExecutionRequest.activity,
        'tool', BaselineExecutionRequest.tool, 'status', BaselineExecutionRequest.status)))
        .select_from(SecurityObservation).join(ScannerEvidence, and_(
            ScannerEvidence.id == SecurityObservation.evidence_id,
            ScannerEvidence.request_id == SecurityObservation.request_id,
            ScannerEvidence.attempt_id == SecurityObservation.attempt_id,
            ScannerEvidence.target_id == SecurityObservation.target_id,
            ScannerEvidence.assessment_id == Assessment.id)).join(BaselineExecutionRequest, and_(
            BaselineExecutionRequest.id == SecurityObservation.request_id,
            BaselineExecutionRequest.assessment_id == Assessment.id,
            BaselineExecutionRequest.target_id == SecurityObservation.target_id))
        .join(ResultProcessingOutcome, and_(ResultProcessingOutcome.id == SecurityObservation.processing_id,
            ResultProcessingOutcome.evidence_id == SecurityObservation.evidence_id,
            ResultProcessingOutcome.assessment_id == Assessment.id))
        .where(SecurityObservation.assessment_id == Assessment.id,
               BaselineExecutionRequest.status == 'Completed', ResultProcessingOutcome.status == 'Succeeded',
               ResultProcessingOutcome.is_partial.is_(False), ScannerEvidence.is_partial.is_(False))
        .correlate(Assessment).scalar_subquery())
    row = db.execute(select(
        Assessment.id,
        aggregate(SecurityObservation, ('id', 'target_id', 'evidence_id', 'observation_type',
                                        'data', 'is_partial', 'collected_at')).label('observations'),
        aggregate(TestingRecommendationDecision, ('recommendation_id', 'decision')).label('decisions'),
        sources.label('sources'),
        aggregate(RecommendationReviewEvent, ('id','recommendation_id','outcome','decided_at','revision')).label('review_events'),
    ).where(Assessment.id == assessment_id, accessible(user))).mappings().one_or_none()
    if row is None:
        raise HTTPException(404)
    source_by_id = {item['observation_id']: item for item in row['sources'] or []}
    observations = sorted([item for item in row['observations'] or [] if item['id'] in source_by_id], key=lambda item: (utc(item['collected_at']), item['id']))
    objects = [SimpleNamespace(**item) for item in observations]
    suggestions = carry_deferred_legacy(objects, row['decisions'] or [], plan_recommendations(objects))
    items, _, counts = decision_statistics(suggestions, row['decisions'] or [])
    # PostgreSQL JSON consistently represents UUIDs as strings on both sides.
    source_by_id = {item['observation_id']: item for item in row['sources'] or []}
    outcomes = {event['recommendation_id']: event['outcome'] for event in sorted(
        row['review_events'] or [], key=lambda event: event['revision'])}
    from .nikto_profile import integration_available
    nikto_integrated = integration_available()
    for item in items:
        if nikto_integrated and item.get('suggested_tool') == 'Nikto':
            item['execution_status'] = 'requires_start_review'
            item['tool_integration_status'] = 'integrated'
            item['execution_unavailability_reason'] = 'explicit_start_required'
            item['explanation'] = [*item['explanation'][:2], 'Nikto is integrated. Execution requires current Start Test readiness and explicit analyst confirmation.']
            item['reason'] = '\n\n'.join(item['explanation'])
        item['review_outcome'] = outcomes.get(item['id'])
        source = source_by_id.get(item['source_observation_id'])
        item['source_test'] = ({key: source[key] for key in ('test_name', 'tool', 'status', 'execution_id')}
                               if source is not None else None)
    from .testing_completion_schemas import DecisionCounts
    DecisionCounts.model_validate(counts)
    return {'assessment_id': str(row['id']), 'count': len(items), 'recommendations': items,
            'decision_counts': counts, 'execution_authorized': False, 'planner_version': 2,
            'no_recommendation_reason': 'insufficient_supported_evidence' if not items else None}


def calculate_summary(state):
    statuses = {name: sum(item['status'] == name for item in state.executions) for name in STATES}
    active = [item for item in state.attempts if item['status'] in ACTIVE]
    active_ids = {item['id'] for item in state.executions if item['status'] in ('Queued', 'Running')}
    active_ids.update(item['request_id'] for item in active)
    recovery_ids = {item['request_id'] for item in state.attempts if item['status'] == 'RecoveryRequired'}
    # Deliberately unchanged: every historical failed/interrupted run remains
    # blocking. Task 2 neither defines nor implements a recovery policy.
    errors = sum(item['status'] in ('Failed', 'Interrupted') for item in state.processing)
    pending_processing = sum(item['status'] in ('Pending', 'Processing') for item in state.processing)
    successful = {item['request_id'] for item in state.processing if item['status'] == 'Succeeded'}
    missing = sum(item['status'] == 'Completed' and item['id'] not in successful for item in state.executions)
    completed_ids = {item['id'] for item in state.executions if item['status'] == 'Completed'}
    valid_processing = {item['id']: item for item in state.processing
                        if item['status'] == 'Succeeded' and not item.get('is_partial', False)}
    trusted = [item for item in state.observations if item.get('request_id') in completed_ids
               and item.get('processing_id') in valid_processing
               and item.get('evidence_id') == valid_processing[item['processing_id']].get('evidence_id')]
    recommendations, pending, decisions = recommendation_statistics(trusted, state.decisions)
    blockers, details = [], []
    def block(code, message, count=None, action=None):
        blockers.append(code)
        details.append({'code': code, 'message': message, 'count': count, 'action': action})
    if not state.executions:
        block('no_tests', 'No tests have been scheduled.', 0, 'view_tests')
    if state.lifecycle == 'Finding Review' and state.receipt is None:
        block('missing_completion_receipt', 'The completion receipt could not be verified.')
    if active_ids:
        block('active_tests', 'Active, queued or uncertain execution requests remain.', len(active_ids), 'view_tests')
    unsuccessful = sum(statuses[name] for name in ('Failed', 'Stopped', 'Blocked', 'Cancelled'))
    if unsuccessful:
        block('unsuccessful_tests', 'Unsuccessful execution requests require attention.', unsuccessful, 'view_tests')
    if errors or pending_processing or missing:
        block('processing_not_clear', 'Processing failures, pending work or missing results require attention.',
              errors + pending_processing + missing, 'view_tests')
    if pending:
        block('pending_recommendations', 'Recommendation decisions remain pending; deferred items still require review.',
              len(pending), 'review_recommendations')
    if state.lifecycle not in ('Testing', 'Finding Review'):
        block('incorrect_lifecycle', 'The assessment is not in the Testing phase.')
    summary = {'total': len(state.executions), 'counts': statuses, 'active_attempts': len(active),
               'active_execution_requests': len(active_ids), 'recovery_required_requests': len(recovery_ids),
               'processing_errors': errors, 'processing_pending': pending_processing, 'missing_processing': missing,
               'recommendation_count': len(recommendations), 'pending_recommendation_ids': pending,
               'reviewed_recommendations': decisions['reviewed'], 'deferred_recommendations': decisions['deferred'],
               'decision_counts': decisions, 'candidate_findings': None, 'blockers': blockers}
    return summary, recommendations, details


def utc(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('Timezone-aware timestamp required')
    return value.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def canonical_digest(payload):
    return sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                             allow_nan=False).encode('utf-8')).hexdigest()


def snapshot_inputs(state):
    groups = {}
    for name, sort_key, timestamps in (
        ('executions', 'id', ()),
        ('attempts', 'id', ('started_at', 'finished_at', 'terminated_at')),
        ('processing', 'id', ('finished_at',)),
        ('observations', 'id', ('collected_at', 'processed_at')),
        ('decisions', 'recommendation_id', ('decided_at',)),
    ):
        values = []
        for record in getattr(state, name):
            item = dict(record)
            for key in timestamps:
                if key in item and item[key] is not None:
                    item[key] = utc(item[key])
            # Preserve binding to observation content without storing raw output.
            if name == 'observations':
                item['data_digest'] = canonical_digest(item.pop('data'))
            values.append(item)
        groups[name] = sorted(values, key=lambda item: item[sort_key])
    if state.review_events:
        groups['review_events'] = sorted([{**event, 'decided_at': utc(event['decided_at'])}
            for event in state.review_events], key=lambda event: event['id'])
    return {'schema_version': VERSION, 'assessment_id': state.assessment_id,
            'lifecycle_status': state.lifecycle, 'creator_id': state.creator_id,
            'scope_revision': state.scope_revision, **groups}


def build_review(state, user):
    summary, recommendations, details = calculate_summary(state)
    inputs = snapshot_inputs(state)
    fingerprint = canonical_digest({'inputs': inputs, 'summary': summary})
    receipt = None
    if state.receipt is not None:
        stored = state.receipt['snapshot']
        metadata = stored.get('_completion_contract') if isinstance(stored, dict) else None
        receipt = {**state.receipt, 'completed_at': utc(state.receipt['completed_at']),
                   'snapshot_schema_version': metadata['schema_version'] if metadata is not None else 1,
                   'snapshot_digest': metadata['snapshot_digest'] if metadata is not None else None}
    result = {'assessment_id': state.assessment_id, 'assessment_name': state.name,
              'lifecycle_status': state.lifecycle, 'ready': not summary['blockers'] and state.lifecycle == 'Testing',
              'can_complete': user.role == 'Security Analyst' and can_activate(user)
                              and str(user.id) == state.creator_id and state.lifecycle == 'Testing',
              'snapshot_schema_version': VERSION, 'snapshot_digest': fingerprint,
              'summary': summary, 'blocker_details': details, 'recommendations': recommendations,
              'completion': receipt}
    from .testing_completion_schemas import CompletionReview
    return CompletionReview.model_validate(result).model_dump(mode='json')


def review_state(db, assessment_id, user, *, lock=False):
    if lock:
        lock_inputs(db, assessment_id)
    state = load_state(db, assessment_id, user)
    try:
        return build_review(state, user), state
    except (ValidationError, ValueError, KeyError, TypeError):
        raise HTTPException(503, detail='Completion state could not be verified.') from None


def receipt_snapshot(review, state):
    """Legacy summary keys stay intact; extra metadata uses the existing JSON column."""
    return {**review['summary'], '_completion_contract': {
        'schema_version': VERSION, 'snapshot_digest': review['snapshot_digest'],
        'inputs': snapshot_inputs(state),
    }}


def trusted_recommendation_observations(db, assessment_id):
    return db.scalars(select(SecurityObservation)
        .join(ScannerEvidence, ScannerEvidence.id == SecurityObservation.evidence_id)
        .join(ResultProcessingOutcome, ResultProcessingOutcome.id == SecurityObservation.processing_id)
        .join(BaselineExecutionRequest, BaselineExecutionRequest.id == SecurityObservation.request_id)
        .where(SecurityObservation.assessment_id == assessment_id,
               ScannerEvidence.assessment_id == assessment_id,
               ResultProcessingOutcome.assessment_id == assessment_id,
               BaselineExecutionRequest.assessment_id == assessment_id,
               BaselineExecutionRequest.status == 'Completed', ResultProcessingOutcome.status == 'Succeeded',
               ResultProcessingOutcome.is_partial.is_(False), ScannerEvidence.is_partial.is_(False))
        .order_by(SecurityObservation.collected_at, SecurityObservation.id)).all()
