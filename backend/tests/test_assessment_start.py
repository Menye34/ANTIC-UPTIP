from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select

from app import assessment_readiness, assessment_start
from app.baseline_catalog import PROFILES
from app.baseline_maintenance import record_tool_state
from app.config import get_settings
from app.execution_policy import PolicyDefinition, PolicyRule, select_policy
from app.models import Assessment, AssessmentAssignment, AssessmentStartAuthorization, AssessmentStartEvent
from test_assessments import API, add_analyst, sign_in


@pytest.fixture
def start_case(client, db, monkeypatch):
    user = add_analyst(db, 'start-creator')
    headers = sign_in(client, user.username)
    response = client.post(API, headers=headers, json={'name': 'Start test'})
    assert response.status_code == 201
    path = f"{API}/{response.json()['id']}"
    profile = PROFILES[0]
    record_tool_state(db, profile.tool, 'enabled', [profile.capability])
    db.commit()
    assert client.post(path + '/scope', headers=headers,
                       json={'revision': 0, 'value': '192.0.2.0/24'}).status_code == 201
    assert client.post(path + '/targets', headers=headers, json={'value': '192.0.2.1'}).status_code == 201
    definition = PolicyDefinition(policy_id='test-start', version=1, rules=(PolicyRule(
        rule_id='test-rule', activity=profile.activity, tool=profile.tool, capability=profile.capability,
        target_kind='IP address', profile_id=profile.key, profile_version=profile.version,
        disposition='preauthorized', parameter_digest='a' * 64, risk='low',
        prerequisites=('test-prerequisite',), max_units=1, stop_conditions=('test-stop',),
    ),))
    approval = {'policy_id': definition.policy_id, 'version': definition.version, 'digest': definition.digest,
                'reference': 'synthetic-start-approval', 'provenance': 'Test only'}
    evidence = assessment_readiness.StartEvidence(
        reference='test-evidence', expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        parameter_digest='a' * 64, risk='low', verified_prerequisites=frozenset({'test-prerequisite'}),
        requested_units=1, clear_stop_conditions=frozenset({'test-stop'}), mandatory_activities=frozenset(),
    )
    monkeypatch.setattr(assessment_readiness, 'effective_policy', lambda: select_policy(definition, approval))
    monkeypatch.setattr(assessment_readiness, 'trusted_start_evidence', lambda *_: evidence)
    from pydantic import SecretStr
    monkeypatch.setattr(get_settings(), 'start_review_key', SecretStr('synthetic-test-signing-key-' + 'x' * 32))
    return path, headers, user, evidence, approval


def review(client, path):
    response = client.get(path + '/readiness')
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    return response.json()['start_review']


def confirmation(review_data):
    return {'review_token': review_data['review_token'], 'mode': review_data['mode'], 'confirmed': True}


def test_full_start_and_replay(client, db, start_case, monkeypatch):
    path, headers, _, _, _ = start_case
    reviewed = review(client, path)
    assert reviewed['confirmation_possible'] and reviewed['mode'] == 'full'
    assert reviewed['policy']['approval_reference'] == 'synthetic-start-approval'
    body = confirmation(reviewed)
    import socket
    import subprocess

    def forbid_external_call(*args, **kwargs):
        pytest.fail('Start attempted a subprocess or network call')

    with monkeypatch.context() as guard:
        guard.setattr(socket, 'getaddrinfo', forbid_external_call)
        guard.setattr(socket.socket, 'connect', forbid_external_call)
        guard.setattr(subprocess, 'Popen', forbid_external_call)
        response = client.post(path + '/start', headers=headers, json=body)
    assert response.status_code == 201, response.text
    receipt = response.json()
    assert receipt['lifecycle_status'] == 'Ready' and receipt['execution_authorized'] is False
    assert receipt['authorized_activity_count'] == 1
    record = db.get(AssessmentStartAuthorization, UUID(receipt['authorization_id']))
    assert record.snapshot_digest == reviewed['snapshot_digest']
    assert record.snapshot['eligible_activities'] == reviewed['eligible_activities']
    assert db.get(AssessmentStartEvent, record.id).to_status == 'Ready'
    assert db.get(Assessment, record.assessment_id).status == 'Ready'
    monkeypatch.setattr('app.assessment_routes.verify_review_token', lambda *_: pytest.fail('Replay reverified token'))
    replay = client.post(path + '/start', headers=headers, json=body)
    assert replay.status_code == 200 and replay.json() == receipt
    assert client.post(path + '/start', headers=headers, json={**body, 'mode': 'partial'}).json() == {
        'detail': {'code': 'start_idempotency_conflict'}}
    assert db.scalar(select(func.count()).select_from(AssessmentStartEvent)) == 1


@pytest.mark.parametrize('dependent', [False, True])
def test_partial_start_and_blocked_dependency(client, start_case, monkeypatch, dependent):
    path, headers, _, evidence, _ = start_case
    response = client.post(path + '/targets', headers=headers, json={'value': '198.51.100.1'})
    assert response.status_code == 201
    outside = next(item for item in response.json()['targets'] if item['normalized_value'] == '198.51.100.1')
    if dependent:
        evidence = replace(evidence, mandatory_activities=frozenset({(outside['id'], PROFILES[0].key)}))
        monkeypatch.setattr(assessment_readiness, 'trusted_start_evidence', lambda *_: evidence)
    reviewed = review(client, path)
    if dependent:
        assert not reviewed['confirmation_possible']
        assert 'mandatory_activity_unavailable' in {item['exclusion_code'] for item in reviewed['excluded_activities']}
    else:
        assert reviewed['mode'] == 'partial'
        response = client.post(path + '/start', headers=headers, json=confirmation(reviewed))
        assert response.status_code == 201
        assert response.json()['excluded_target_count'] == 1


@pytest.mark.parametrize('change,code', [
    ('scope', 'start_review_stale'), ('target', 'start_review_stale'),
    ('baseline', 'start_no_eligible_activities'), ('profile', 'start_no_eligible_activities'),
    ('assessment', 'start_review_invalid'), ('tool', 'start_no_eligible_activities'),
    ('evidence', 'start_review_stale'), ('policy', 'start_no_eligible_activities'),
    ('tampered', 'start_review_invalid'), ('session', 'start_review_invalid'),
    ('expired', 'start_review_expired'),
])
def test_invalidated_review(client, db, start_case, monkeypatch, change, code):
    path, headers, user, evidence, approval = start_case
    if change == 'expired':
        monkeypatch.setattr(assessment_start, 'TOKEN_LIFETIME', timedelta(milliseconds=1))
    body = confirmation(review(client, path))
    if change == 'scope':
        assert client.post(path + '/scope', headers=headers,
                           json={'revision': 1, 'value': '203.0.113.0/24'}).status_code == 201
    elif change == 'target':
        target_id = review(client, path)['targets'][0]['target_id']
        assert client.patch(f'{path}/targets/{target_id}', headers=headers,
                            json={'revision': 1, 'value': '192.0.2.2'}).status_code == 200
    elif change == 'baseline':
        from app.models import BaselineAssignment
        db.delete(db.scalar(select(BaselineAssignment)))
        db.commit()
    elif change == 'profile':
        from app import baseline_catalog
        monkeypatch.setattr(baseline_catalog, 'PROFILES', (replace(PROFILES[0], version=2), *PROFILES[1:]))
    elif change == 'assessment':
        response = client.post(API, headers={**headers, 'Idempotency-Key': str(uuid4())},
                               json={'name': 'Different assessment'})
        assert response.status_code == 201
        path = f"{API}/{response.json()['id']}"
    elif change == 'tool':
        record_tool_state(db, PROFILES[0].tool, 'disabled', [])
        db.commit()
    elif change == 'evidence':
        monkeypatch.setattr(assessment_readiness, 'trusted_start_evidence',
                            lambda *_: replace(evidence, reference='new-revision'))
    elif change == 'policy':
        monkeypatch.setattr(assessment_readiness, 'effective_policy', lambda: select_policy(None, approval))
    elif change == 'tampered':
        body['review_token'] += '0'
    elif change == 'session':
        headers = sign_in(client, user.username)
    response = client.post(path + '/start', headers=headers, json=body)
    assert response.status_code == 409, response.text
    assert response.json()['detail']['code'] == code
    assert db.scalar(select(func.count()).select_from(AssessmentStartAuthorization)) == 0
    assert client.get(path).json()['status'] == 'Draft'


def test_confirmation_permissions(client, db, start_case):
    path, headers, _, _, _ = start_case
    body = confirmation(review(client, path))
    for overridden in ({'Origin': 'https://elsewhere.test'}, {'X-CSRF-Token': 'invalid'}):
        assert client.post(path + '/start', headers={**headers, **overridden}, json=body).status_code == 403
    assert client.post(path + '/start', headers=headers, json={**body, 'confirmed': False}).status_code == 422
    other = add_analyst(db, 'assigned-start-reader')
    db.add(AssessmentAssignment(assessment_id=UUID(path.rsplit('/', 1)[1]), analyst_id=other.id))
    db.commit()
    other_headers = sign_in(client, other.username)
    assert review(client, path)['review_token'] is None
    assert client.post(path + '/start', headers=other_headers, json=body).status_code == 403


def test_audit_failure_rolls_back_authorization_and_lifecycle(client, db, engine, start_case):
    from sqlalchemy import event
    from sqlalchemy.exc import SQLAlchemyError

    path, headers, _, _, _ = start_case
    body = confirmation(review(client, path))

    def fail_audit(conn, cursor, statement, *args):
        if statement.startswith('INSERT INTO assessment_start_events'):
            raise SQLAlchemyError('Synthetic audit write failure')

    event.listen(engine, 'before_cursor_execute', fail_audit)
    try:
        assert client.post(path + '/start', headers=headers, json=body).status_code == 503
    finally:
        event.remove(engine, 'before_cursor_execute', fail_audit)
    assert db.scalar(select(func.count()).select_from(AssessmentStartAuthorization)) == 0
    assert db.scalar(select(func.count()).select_from(AssessmentStartEvent)) == 0
    assert client.get(path).json()['status'] == 'Draft'


def test_concurrent_start_and_scope_edit(client, db, engine, start_case):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker

    from app.database import get_db
    from app.main import create_app

    path, headers, _, _, _ = start_case
    body = confirmation(review(client, path))
    cookies = dict(client.cookies)
    db.rollback()  # Release the review lock held by the shared test session.
    factory = sessionmaker(engine)

    def independent_db():
        with factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = independent_db
    barrier = Barrier(3)

    def send(endpoint, payload):
        with TestClient(app, base_url='https://testserver', cookies=cookies) as concurrent_client:
            barrier.wait(timeout=10)
            return concurrent_client.post(path + endpoint, json=payload,
                                          headers={**headers, 'Origin': 'https://testserver'})

    with ThreadPoolExecutor(max_workers=3) as pool:
        first = pool.submit(send, '/start', body)
        second = pool.submit(send, '/start', body)
        edit = pool.submit(send, '/scope', {'revision': 1, 'value': '203.0.113.0/24'})
        statuses = sorted([first.result(timeout=15).status_code, second.result(timeout=15).status_code])
        edit_status = edit.result(timeout=15).status_code
    if edit_status == 201:
        assert statuses == [409, 409]
        assert db.scalar(select(func.count()).select_from(AssessmentStartAuthorization)) == 0
    else:
        assert edit_status == 403
        assert statuses == [200, 201]
        assert db.scalar(select(func.count()).select_from(AssessmentStartEvent)) == 1


def test_review_fails_closed_without_policy_evidence_or_signing_key(client, start_case, monkeypatch):
    path, _, _, _, _ = start_case
    with monkeypatch.context() as guard:
        guard.setattr(assessment_readiness, 'effective_policy', lambda: select_policy(None, None))
        assert review(client, path)['review_token'] is None
    with monkeypatch.context() as guard:
        guard.setattr(assessment_readiness, 'trusted_start_evidence', lambda *_: None)
        assert review(client, path)['review_token'] is None
    monkeypatch.setattr(get_settings(), 'start_review_key', None)
    assert review(client, path)['review_token'] is None


def test_partial_start_with_independent_activities_on_same_target(client, db, start_case, monkeypatch):
    from app import baseline_catalog
    from app.baseline_resolution import reconcile

    path, headers, _, _, _ = start_case
    secondary = replace(PROFILES[0], key='test-excluded-profile')
    monkeypatch.setattr(baseline_catalog, 'PROFILES', (*PROFILES, secondary))
    assessment = db.scalar(select(Assessment).with_for_update())
    reconcile(db, assessment, 'test_catalog_change')
    db.commit()

    reviewed = review(client, path)
    assert reviewed['mode'] == 'partial'
    assert reviewed['excluded_targets'] == []
    assert [item['profile_id'] for item in reviewed['excluded_activities']] == [secondary.key]
    assert [item['profile_id'] for item in reviewed['eligible_activities']] == [PROFILES[0].key]
    response = client.post(path + '/start', headers=headers, json=confirmation(reviewed))
    assert response.status_code == 201
    assert response.json()['excluded_activity_count'] == 1


def test_migration_preserves_draft_and_refuses_downgrade_after_start(client, db, engine, start_case):
    from pathlib import Path

    from alembic import command
    from alembic.config import Config
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    path, headers, _, _, _ = start_case
    config = Config(str(Path(__file__).resolve().parents[1] / 'alembic.ini'))
    command.downgrade(config, '0008')
    command.upgrade(config, '0009')
    assert client.get(path).json()['status'] == 'Draft'
    response = client.post(path + '/start', headers=headers, json=confirmation(review(client, path)))
    assert response.status_code == 201
    with pytest.raises(DBAPIError, match='Cannot downgrade'):
        command.downgrade(config, '0008')
    with engine.connect() as connection:
        assert connection.scalar(text('SELECT version_num FROM alembic_version')) == '0009'
    with pytest.raises(DBAPIError, match='append-only'):
        with engine.begin() as connection:
            connection.execute(text('DELETE FROM assessment_start_authorizations'))


@pytest.mark.parametrize('case', [
    'eligible_only', 'completed', 'expired', 'stale', 'ordering_only', 'unknown',
    'missing', 'cyclic', 'contradictory', 'changed_after_review',
])
def test_prerequisite_semantics(client, db, start_case, monkeypatch, case):
    from app import baseline_catalog
    from app.baseline_resolution import current_assignments, reconcile
    from app.execution_policy import ActivityDependency
    from app.models import AssessmentTarget

    path, headers, _, evidence, approval = start_case
    assessment = db.scalar(select(Assessment).with_for_update())
    target = db.scalar(select(AssessmentTarget))
    first = PROFILES[0]
    second = replace(first, key='test-prerequisite-profile')
    monkeypatch.setattr(baseline_catalog, 'PROFILES', (*PROFILES, second))
    reconcile(db, assessment, 'test_prerequisite_catalog')
    db.commit()
    assignments = current_assignments(db, assessment.id)[target.id]
    first_eval, second_eval = (assignments[profile.key][1] for profile in (first, second))
    original = assessment_readiness.effective_policy().definition
    semantics = 'ordering_only' if case in {'ordering_only', 'cyclic', 'contradictory'} else 'completed'
    dependencies = () if case == 'unknown' else (ActivityDependency(profile_id=second.key, semantics=semantics),)
    first_rule = original.rules[0].model_copy(update={'activity_dependencies': dependencies})
    second_rule = original.rules[0].model_copy(update={
        'rule_id': 'test-prerequisite-rule', 'profile_id': second.key,
        'activity_dependencies': (ActivityDependency(profile_id=first.key, semantics='ordering_only'),)
        if case == 'cyclic' else (),
    })
    definition = original.model_copy(update={'rules': (first_rule, second_rule)})
    monkeypatch.setattr(assessment_readiness, 'effective_policy',
                        lambda: select_policy(definition, {**approval, 'digest': definition.digest}))
    now = datetime.now(timezone.utc)
    proof = assessment_readiness.PrerequisiteCompletion(
        target_id=str(target.id), profile_id=second.key, evaluation_id=str(second_eval.id),
        evaluation_fingerprint='b' * 64 if case == 'stale' else second_eval.fingerprint,
        policy_digest=definition.digest, reference='synthetic-completion', successful=True,
        completed_at=now - timedelta(hours=1),
        expires_at=now - timedelta(seconds=1) if case == 'expired' else now + timedelta(minutes=2),
    )
    first_evidence = replace(
        evidence, mandatory_activities=frozenset({(str(uuid4()) if case == 'missing' else str(target.id), second.key)}),
        prerequisite_completions=(proof,) if case in {
            'completed', 'stale', 'expired', 'contradictory', 'changed_after_review',
        } else (),
    )
    second_evidence = replace(evidence, mandatory_activities=frozenset({(str(target.id), first.key)})) if case == 'cyclic' else evidence
    evidence_by_fingerprint = {first_eval.fingerprint: first_evidence, second_eval.fingerprint: second_evidence}
    monkeypatch.setattr(assessment_readiness, 'trusted_start_evidence',
                        lambda _assessment, _target, digest, _policy: evidence_by_fingerprint[digest])

    response = client.get(path + '/readiness').json()
    reviewed = response['start_review']
    assert response['start_review_eligible'] == reviewed['confirmation_possible']
    activities = {item['profile_id']: item for item in response['targets'][0]['baseline_activities']}
    assert activities[first.key]['policy_eligible']
    expected = case in {'completed', 'ordering_only', 'changed_after_review'}
    assert activities[first.key]['start_review_eligible'] is expected
    if case == 'cyclic':
        assert reviewed['review_token'] is None
        assert client.get(path).json()['status'] == 'Draft'
        assert db.scalar(select(func.count()).select_from(AssessmentStartAuthorization)) == 0
        return

    assert reviewed['mode'] == ('full' if expected else 'partial')
    if case in {'completed', 'changed_after_review'}:
        assert datetime.fromisoformat(reviewed['expires_at']) == proof.expires_at
    if case == 'changed_after_review':
        evidence_by_fingerprint[first_eval.fingerprint] = replace(
            first_evidence, prerequisite_completions=(replace(proof, expires_at=now),),
        )
    response = client.post(path + '/start', headers=headers, json=confirmation(reviewed))
    if case == 'changed_after_review':
        assert response.status_code == 409
        assert db.scalar(select(func.count()).select_from(AssessmentStartAuthorization)) == 0
        assert client.get(path).json()['status'] == 'Draft'
    else:
        assert response.status_code == 201
        stored = db.scalar(select(AssessmentStartAuthorization)).snapshot
        assert {item['profile_id'] for item in stored['eligible_activities']} == (
            {first.key, second.key} if expected else {second.key}
        )
        if expected:
            dependent = next(item for item in stored['eligible_activities'] if item['profile_id'] == first.key)
            assert dependent['policy_dependencies'] == [{'profile_id': second.key, 'semantics': semantics}]
            assert dependent['safety_evidence']['mandatory_activities'] == [[str(target.id), second.key]]


@pytest.mark.parametrize('insert', [False, True])
def test_tool_writer_waits_for_start_commit(client, db, engine, start_case, insert):
    from concurrent.futures import ThreadPoolExecutor
    from queue import Queue
    from time import monotonic, sleep

    from sqlalchemy import event, text
    from sqlalchemy.orm import sessionmaker

    path, headers, _, _, _ = start_case
    body = confirmation(review(client, path))
    factory = sessionmaker(engine)
    pid = Queue()

    def write_tool():
        with factory.begin() as writer:
            pid.put(writer.scalar(text('SELECT pg_backend_pid()')))
            record_tool_state(writer, PROFILES[1 if insert else 0].tool, 'disabled', [])

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = None

        def check_tool_lock(conn, cursor, statement, *args):
            nonlocal future
            if not statement.startswith('INSERT INTO assessment_start_authorizations'):
                return
            future = pool.submit(write_tool)
            writer_pid = pid.get(timeout=5)
            with engine.connect() as observer:
                deadline = monotonic() + 5
                while monotonic() < deadline:
                    observer.execute(text('SELECT pg_stat_clear_snapshot()'))
                    waiting = observer.scalar(text(
                        "SELECT wait_event_type = 'Lock' FROM pg_stat_activity WHERE pid = :pid"
                    ), {'pid': writer_pid})
                    if waiting:
                        return
                    sleep(0.02)
            pytest.fail('Tool writer did not wait for Start to commit')

        event.listen(engine, 'before_cursor_execute', check_tool_lock)
        try:
            response = client.post(path + '/start', headers=headers, json=body)
        finally:
            event.remove(engine, 'before_cursor_execute', check_tool_lock)
            db.rollback()
        assert response.status_code == 201
        assert future is not None
        future.result(timeout=5)


def test_short_signing_key_disables_confirmation(client, start_case, monkeypatch):
    from pydantic import SecretStr

    path, headers, _, _, _ = start_case
    body = confirmation(review(client, path))
    monkeypatch.setattr(get_settings(), 'start_review_key', SecretStr('too-short'))
    data = client.get(path + '/readiness').json()
    assert data['start_review_eligible'] is data['start_review']['confirmation_possible'] is False
    assert data['start_review']['review_token'] is None
    response = client.post(path + '/start', headers=headers, json=body)
    assert response.json()['detail']['code'] == 'start_signing_unavailable'
    assert client.get(path).json()['status'] == 'Draft'
