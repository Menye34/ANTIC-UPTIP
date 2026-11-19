"""Task 2 contracts: coherent persisted reads and unchanged completion gates."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import event, func, select
from sqlalchemy.exc import SQLAlchemyError

from app.models import (Assessment, AssessmentAssignment, BaselineExecutionRequest, ExecutionAttempt,
                        ResultProcessingOutcome, SecurityObservation,
                        TestingCompletionEvent as CompletionEvent,
                        TestingRecommendationDecision as Decision)
from app.testing_completion_service import (CompletionState, build_review,
                                            receipt_snapshot)
from app.testing_completion_schemas import CompletionReview
from test_scheduling_start import prepared, get_review, confirm  # noqa: F401
from test_execution_orchestration import FakeAdapter, BorrowedFactory
from app.execution_orchestration import ExecutionRunner, claim
from app.execution_results import EvidenceStore


def synthetic(**changes):
    # Pure calculation fixtures do not represent persisted scanner evidence.
    actor = SimpleNamespace(id=uuid4(), role='Security Analyst', status='active',
                            password_change_required=False, locked_until=None)
    state = CompletionState(str(uuid4()), 'Contract assessment', 'Testing', str(actor.id), 1,
                            [], [], [], [], [], None)
    return replace(state, **changes), actor


def test_empty_and_lifecycle_contracts():
    state, actor = synthetic()
    review = build_review(state, actor)
    assert review['can_complete'] and not review['ready']
    assert review['summary']['blockers'] == ['no_tests']
    for status in ('Draft', 'Ready'):
        response = build_review(replace(state, lifecycle=status), actor)
        assert not response['can_complete'] and not response['ready']
        assert response['summary']['blockers'] == ['no_tests', 'incorrect_lifecycle']


@pytest.mark.parametrize('attempt_status', ['Claimed', 'Running', 'RecoveryRequired'])
def test_request_and_attempt_counts_are_independent(attempt_status):
    state, actor = synthetic(executions=[{'id': 'r', 'status': 'Running'}],
                             attempts=[{'id': 'a', 'request_id': 'r', 'status': attempt_status}])
    response = build_review(state, actor)
    summary = response['summary']
    assert summary['total'] == summary['active_execution_requests'] == summary['active_attempts'] == 1
    assert summary['counts']['Running'] == 1
    assert summary['recovery_required_requests'] == (attempt_status == 'RecoveryRequired')
    assert response['blocker_details'][0]['count'] == 1


@pytest.mark.parametrize('status', ['Failed', 'Interrupted', 'Pending', 'Processing'])
def test_all_historical_processing_runs_still_block(status):
    state, actor = synthetic(executions=[{'id': 'r', 'status': 'Completed'}], processing=[
        {'id': 'old', 'request_id': 'r', 'status': status},
        {'id': 'new', 'request_id': 'r', 'status': 'Succeeded'}])
    result = build_review(state, actor)
    assert not result['ready'] and result['summary']['blockers'] == ['processing_not_clear']
    assert result['summary']['missing_processing'] == 0


@pytest.mark.parametrize('difference', ['same_evidence', 'evidence', 'attempt', 'request', 'processor', 'version'])
@pytest.mark.parametrize('failure', ['Failed', 'Interrupted'])
def test_processing_success_does_not_supersede_provenance(difference, failure):
    # Characterization only: synthetic histories are not permission to create
    # otherwise invalid persisted records or to bypass processing triggers.
    old = dict(id='old', request_id='r', attempt_id='a', evidence_id='e',
               processor='nmap-host-discovery', processor_version='2', run_number=1,
               status=failure, is_partial=False, error_code='synthetic_failure')
    new = {**old, 'id': 'new', 'status': 'Succeeded', 'run_number': 2, 'error_code': None}
    field = {'evidence': 'evidence_id', 'attempt': 'attempt_id', 'request': 'request_id',
             'processor': 'processor', 'version': 'processor_version'}.get(difference)
    if field:
        new[field] = 'different'
    if difference in ('attempt', 'request'):
        new['evidence_id'] = 'different-evidence'
    if difference == 'request':
        new['attempt_id'] = 'different-attempt'
    executions = [{'id': 'r', 'status': 'Completed'}]
    if difference == 'request':
        executions.append({'id': 'different', 'status': 'Completed'})
    state, actor = synthetic(executions=executions, processing=[old, new])
    review = build_review(state, actor)
    assert not review['ready']
    assert review['summary']['blockers'] == ['processing_not_clear']
    assert review['summary']['processing_errors'] == 1
    assert review['summary']['missing_processing'] == (difference == 'request')
    # Neither ordering nor a newer run number constitutes approved recovery.
    assert build_review(replace(state, processing=[new, old]), actor)['snapshot_digest'] == review['snapshot_digest']


def test_processing_success_cannot_clear_uncertain_execution():
    state, actor = synthetic(executions=[{'id': 'r', 'status': 'Completed'}],
        attempts=[{'id': 'a', 'request_id': 'r', 'status': 'RecoveryRequired'}],
        processing=[{'id': 'p', 'request_id': 'r', 'status': 'Succeeded'}])
    review = build_review(state, actor)
    assert not review['ready']
    assert review['summary']['blockers'] == ['active_tests']
    assert review['summary']['recovery_required_requests'] == 1
    assert review['summary']['active_execution_requests'] == 1


@pytest.mark.parametrize('status', ['Failed', 'Stopped', 'Cancelled', 'Blocked'])
def test_unsuccessful_requests_block(status):
    state, actor = synthetic(executions=[{'id': 'r', 'status': status}])
    assert build_review(state, actor)['summary']['blockers'] == ['unsuccessful_tests']


def test_missing_processing_and_missing_receipt_fail_closed():
    state, actor = synthetic(executions=[{'id': 'r', 'status': 'Completed'}])
    result = build_review(replace(state, lifecycle='Finding Review'), actor)
    assert not result['ready'] and not result['can_complete']
    assert result['summary']['blockers'] == ['missing_completion_receipt', 'processing_not_clear']


def test_digest_uses_stable_identities_order_and_utc():
    stamp = datetime.now(timezone.utc)
    rows = [{'id': 'a', 'request_id': 'r', 'status': 'Succeeded', 'finished_at': stamp.isoformat()},
            {'id': 'b', 'request_id': 'r', 'status': 'Succeeded', 'finished_at': None}]
    state, actor = synthetic(executions=[{'id': 'r', 'status': 'Completed'}], processing=rows)
    first = build_review(state, actor)
    equivalent = [{**rows[0], 'finished_at': stamp.astimezone(timezone(timedelta(hours=1))).isoformat()}, rows[1]]
    assert build_review(replace(state, processing=equivalent[::-1]), actor)['snapshot_digest'] == first['snapshot_digest']
    different = [{**rows[0], 'id': 'replacement'}, rows[1]]
    changed = build_review(replace(state, processing=different), actor)
    assert changed['summary'] == first['summary']
    assert changed['snapshot_digest'] != first['snapshot_digest']
    assert build_review(replace(state, scope_revision=2), actor)['snapshot_digest'] != first['snapshot_digest']


def test_new_and_legacy_receipt_validation():
    state, actor = synthetic(executions=[{'id': 'r', 'status': 'Completed'}],
                             processing=[{'id': 'p', 'request_id': 'r', 'status': 'Succeeded'}])
    review = build_review(state, actor)
    assert review['ready']
    snapshot = receipt_snapshot(review, state)
    receipt = {'actor_id': str(actor.id), 'completed_at': datetime.now(timezone.utc), 'snapshot': snapshot}
    result = build_review(replace(state, lifecycle='Finding Review', receipt=receipt), actor)
    assert result['completion']['snapshot_digest'] == review['snapshot_digest']
    assert not result['ready'] and not result['can_complete']
    corrupt = {**snapshot, 'total': 2}
    with pytest.raises(ValidationError):
        build_review(replace(state, lifecycle='Finding Review', receipt={**receipt, 'snapshot': corrupt}), actor)
    legacy = {'synthetic_legacy': True}
    result = build_review(replace(state, lifecycle='Finding Review', receipt={**receipt, 'snapshot': legacy}), actor)
    assert result['completion']['snapshot'] == legacy
    assert result['completion']['snapshot_schema_version'] == 1
    assert result['completion']['snapshot_digest'] is None


@pytest.mark.parametrize('alter', [
    lambda r: r.update(unexpected='field'),
    lambda r: r.update(ready=True),
    lambda r: r['summary'].update(total=True),
    lambda r: r['summary'].update(total=1),
    lambda r: r['summary']['decision_counts'].update(pending_completion=1),
    lambda r: r['blocker_details'].clear(),
])
def test_invalid_response_contract_is_rejected(alter):
    state, actor = synthetic()
    result = build_review(state, actor)
    alter(result)
    with pytest.raises(ValidationError):
        CompletionReview.model_validate(result)


@pytest.fixture
def completed_work(client, db, prepared, tmp_path):
    path, headers, owner = prepared
    started = confirm(client, path, headers, get_review(client, path)['start_review'])
    assert started.status_code == 201
    request_id = UUID(started.json()['queued_execution_ids'][0])
    tmp_path.chmod(0o700)
    adapter = FakeAdapter()
    assert ExecutionRunner(BorrowedFactory(db), adapter, EvidenceStore(tmp_path), 'contract-fixture').run(request_id)
    assert adapter.calls == 1
    return path, headers, owner, request_id


def reviewed(client, path, headers):
    response = client.get(path + '/testing/completion')
    assert response.status_code == 200, response.text
    for item in response.json()['recommendations']:
        result = client.post(path + '/testing/completion/decisions', headers=headers,
                             json={'recommendation_id': item['id'], 'decision': 'Reviewed'})
        assert result.status_code == 200
    result = client.get(path + '/testing/completion')
    assert result.status_code == 200, result.text
    return result.json()


def test_persisted_decision_statistics_and_receipt(client, db, completed_work):
    path, headers, owner, _ = completed_work
    first = client.get(path + '/testing/completion').json()
    assert first['summary']['decision_counts'] == {
        'total': 1, 'pending_review': 1, 'reviewed': 0, 'deferred': 0, 'pending_completion': 1}
    rid = first['recommendations'][0]['id']
    assert client.post(path + '/testing/completion/decisions', headers=headers,
                       json={'recommendation_id': rid, 'decision': 'Deferred'}).status_code == 200
    deferred = client.get(path + '/testing/completion').json()
    assert deferred['summary']['decision_counts'] == {
        'total': 1, 'pending_review': 0, 'reviewed': 0, 'deferred': 1, 'pending_completion': 1}
    assert not deferred['ready']
    ready = reviewed(client, path, headers)
    assert ready['ready'] and ready['can_complete']
    response = client.post(path + '/testing/completion', headers=headers,
                           json={'confirmed': True, 'snapshot_digest': ready['snapshot_digest']})
    assert response.status_code == 200, response.text
    done = response.json()
    assert done['lifecycle_status'] == 'Finding Review'
    assert not done['ready'] and not done['can_complete']
    assert done['completion']['snapshot_digest'] == ready['snapshot_digest']
    identifier = UUID(path.rsplit('/', 1)[1])
    assert db.get(Assessment, identifier).status == 'Finding Review'
    persisted = db.get(CompletionEvent, identifier)
    assert done['completion']['snapshot'] == persisted.snapshot
    assert done['completion']['actor_id'] == str(owner.id)
    assert client.get(path + '/testing/completion').json() == done
    assert client.post(path + '/testing/completion', headers=headers,
                       json={'confirmed': True, 'snapshot_digest': ready['snapshot_digest']}).status_code == 409
    assert db.scalar(select(func.count()).select_from(CompletionEvent)) == 1


def test_access_capability_and_creator_enforcement(client, db, completed_work):
    from test_assessments import add_analyst, sign_in
    path, headers, owner, _ = completed_work
    ready = reviewed(client, path, headers)
    identifier = UUID(path.rsplit('/', 1)[1])
    other = add_analyst(db, 'completion-assigned')
    other_headers = sign_in(client, other.username)
    assert client.get(path + '/testing/completion').status_code == 404
    db.add(AssessmentAssignment(assessment_id=identifier, analyst_id=other.id))
    db.commit()
    result = client.get(path + '/testing/completion').json()
    assert result['ready'] and not result['can_complete']
    assert result['snapshot_digest'] == ready['snapshot_digest']
    assert client.post(path + '/testing/completion', headers=other_headers,
                       json={'confirmed': True, 'snapshot_digest': ready['snapshot_digest']}).status_code == 403
    sign_in(client, owner.username)
    client.cookies.clear()
    assert client.get(path + '/testing/completion').status_code == 401


@pytest.mark.parametrize('change', ['csrf', 'origin', 'confirmation', 'digest'])
def test_secure_confirmation_contract(client, db, completed_work, change):
    path, headers, _, _ = completed_work
    ready = reviewed(client, path, headers)
    payload = {'confirmed': True, 'snapshot_digest': ready['snapshot_digest']}
    if change == 'csrf':
        headers = {}
    elif change == 'origin':
        headers = {**headers, 'Origin': 'https://untrusted.invalid'}
    elif change == 'confirmation':
        payload['confirmed'] = False
    else:
        payload['snapshot_digest'] = '0' * 64
    result = client.post(path + '/testing/completion', headers=headers, json=payload)
    assert result.status_code == {'csrf': 403, 'origin': 403, 'confirmation': 422, 'digest': 409}[change]
    identifier = UUID(path.rsplit('/', 1)[1])
    assert db.get(Assessment, identifier).status == 'Testing'
    assert db.get(CompletionEvent, identifier) is None


def test_get_uses_one_assessment_snapshot_and_does_not_mutate(client, db, completed_work):
    path, _, owner, _ = completed_work
    models = (Assessment, BaselineExecutionRequest, ExecutionAttempt, ResultProcessingOutcome,
              SecurityObservation, Decision, CompletionEvent)
    before = [db.scalar(select(func.count()).select_from(model)) for model in models]
    statements = []
    def capture(conn, cursor, statement, parameters, context, many):
        if 'json_agg' in statement:
            statements.append(statement)
    event.listen(db.bind, 'before_cursor_execute', capture)
    try:
        first = client.get(path + '/testing/completion')
        second = client.get(path + '/testing/completion')
    finally:
        event.remove(db.bind, 'before_cursor_execute', capture)
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert first.headers['cache-control'] == 'no-store'
    assert len(statements) == 2
    assert all('testing_completion_events' in sql and 'testing_recommendation_decisions' in sql for sql in statements)
    assert before == [db.scalar(select(func.count()).select_from(model)) for model in models]
    assert not db.new and not db.dirty and not db.deleted


def test_attempt_heartbeat_does_not_change_digest(client, db, prepared):
    path, headers, _ = prepared
    result = confirm(client, path, headers, get_review(client, path)['start_review'])
    request_id = UUID(result.json()['queued_execution_ids'][0])
    attempt_id, *_ = claim(BorrowedFactory(db), request_id, 'heartbeat-fixture', 30)
    first = client.get(path + '/testing/completion').json()
    attempt = db.get(ExecutionAttempt, attempt_id)
    attempt.heartbeat_at += timedelta(seconds=1)
    attempt.lease_expires_at += timedelta(seconds=1)
    db.flush()
    second = client.get(path + '/testing/completion').json()
    assert second['snapshot_digest'] == first['snapshot_digest']
    assert second['summary']['active_execution_requests'] == second['summary']['active_attempts'] == 1


@pytest.mark.parametrize('write', ['receipt', 'lifecycle'])
def test_transaction_failure_rolls_back_receipt_and_lifecycle(client, db, completed_work, write):
    path, headers, _, _ = completed_work
    ready = reviewed(client, path, headers)
    def fail(conn, cursor, statement, parameters, context, many):
        if ((write == 'receipt' and statement.startswith('INSERT INTO testing_completion_events'))
                or (write == 'lifecycle' and statement.startswith('UPDATE assessments'))):
            raise SQLAlchemyError('synthetic transaction failure')
    event.listen(db.bind, 'before_cursor_execute', fail)
    try:
        response = client.post(path + '/testing/completion', headers=headers,
                               json={'confirmed': True, 'snapshot_digest': ready['snapshot_digest']})
        assert response.status_code == 503
    finally:
        event.remove(db.bind, 'before_cursor_execute', fail)
        db.rollback()
    identifier = UUID(path.rsplit('/', 1)[1])
    assert db.get(Assessment, identifier).status == 'Testing'
    assert db.get(CompletionEvent, identifier) is None


def test_persisted_legacy_receipt_is_returned_without_rewriting(client, db, completed_work):
    path, headers, owner, _ = completed_work
    ready = reviewed(client, path, headers)
    identifier = UUID(path.rsplit('/', 1)[1])
    legacy = {key: value for key, value in ready['summary'].items()
              if key not in ('active_execution_requests', 'recovery_required_requests', 'decision_counts')}
    db.add(CompletionEvent(assessment_id=identifier, actor_id=owner.id,
                           completed_at=datetime.now(timezone.utc), snapshot=legacy))
    db.get(Assessment, identifier).status = 'Finding Review'
    db.commit()
    result = client.get(path + '/testing/completion')
    assert result.status_code == 200, result.text
    receipt = result.json()['completion']
    assert receipt['snapshot_schema_version'] == 1 and receipt['snapshot_digest'] is None
    assert receipt['snapshot'] == legacy
    db.expire_all()
    assert db.get(CompletionEvent, identifier).snapshot == legacy
    assert not db.new and not db.dirty and not db.deleted


@pytest.mark.parametrize('restriction', ['expired_session', 'disabled', 'administrator'])
def test_authentication_and_role_restrictions_remain_enforced(client, db, completed_work, restriction):
    from app.models import AuthSession, Role
    path, headers, owner, _ = completed_work
    ready = reviewed(client, path, headers)
    if restriction == 'expired_session':
        session = db.scalar(select(AuthSession).where(AuthSession.user_id == owner.id))
        session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    elif restriction == 'disabled':
        owner.status = 'disabled'
    else:
        if db.get(Role, 'Technical Administrator') is None:
            db.add(Role(name='Technical Administrator'))
            db.flush()
        owner.role = 'Technical Administrator'
    db.commit()
    assert client.get(path + '/testing/completion').status_code == (403 if restriction == 'administrator' else 401)
    assert client.post(path + '/testing/completion', headers=headers,
                       json={'confirmed': True, 'snapshot_digest': ready['snapshot_digest']}).status_code == (
                           403 if restriction == 'administrator' else 401)
    assert db.get(Assessment, UUID(path.rsplit('/', 1)[1])).status == 'Testing'
    assert db.scalar(select(func.count()).select_from(CompletionEvent)) == 0


@pytest.mark.parametrize('decision', [None, 'Reviewed', 'Deferred'])
def test_shared_classification_preserves_completion_statistics(decision):
    from app.testing_completion_service import decision_statistics, recommendation_statistics
    from app.recommendation_planner import plan_recommendations
    observation = {'id': 'observation', 'target_id': 'target', 'evidence_id': 'evidence',
                   'observation_type': 'host_discovery', 'is_partial': False,
                   'data': {'address': '192.0.2.1', 'status': 'up'},
                   'collected_at': datetime.now(timezone.utc)}
    planned = plan_recommendations([SimpleNamespace(**observation)])
    decisions = [] if decision is None else [{'recommendation_id': planned[0]['id'], 'decision': decision}]
    full, pending, counts = decision_statistics(planned, decisions)
    minimal, completion_pending, completion_counts = recommendation_statistics([observation], decisions)
    assert completion_counts == counts and completion_pending == pending
    assert minimal == [{'id': full[0]['id'], 'title': full[0]['title'], 'decision': decision}]
    assert 'decision' not in planned[0]
    assert not full[0]['execution_available']
