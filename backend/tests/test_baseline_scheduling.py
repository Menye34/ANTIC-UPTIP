"""Scheduling tests use synthetic governed evidence, never scanner adapters."""
from uuid import UUID

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.exc import IntegrityError

from app.models import Assessment, AssessmentStartAuthorization, AssessmentStartEvent, BaselineExecutionRequest
from test_assessment_start import start_case, confirmation, review  # noqa: F401


@pytest.mark.parametrize('partial', [False, True])
def test_start_queues_exactly_authorized_work(client, db, start_case, monkeypatch, partial):
    import socket
    import subprocess

    path, headers, _, _, _ = start_case
    if partial:
        assert client.post(path + '/targets', headers=headers, json={'value': '198.51.100.1'}).status_code == 201
    empty = client.get(path + '/testing').json()
    assert empty['counts']['total'] == 0
    body = confirmation(review(client, path))

    def forbidden(*args, **kwargs):
        pytest.fail('Scheduling attempted scanner or network execution')

    with monkeypatch.context() as guard:
        guard.setattr(socket, 'getaddrinfo', forbidden)
        guard.setattr(socket.socket, 'connect', forbidden)
        guard.setattr(subprocess, 'Popen', forbidden)
        response = client.post(path + '/start', headers=headers, json=body)
    assert response.status_code == 201, response.text
    receipt = response.json()
    assert receipt['lifecycle_status'] == 'Testing'
    assert receipt['queued_execution_count'] == 1
    assert receipt['execution_authorized'] is False
    retry = client.post(path + '/start', headers=headers, json=body)
    assert retry.status_code == 200 and retry.json() == receipt
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest)) == 1
    assert db.scalar(select(AssessmentStartEvent)).to_status == 'Testing'
    overview = client.get(path + '/testing').json()
    assert overview['counts']['queued'] == 1
    assert overview['counts']['in_progress'] == overview['counts']['completed'] == 0
    assert overview['discovered_so_far'] == []
    executions = client.get(path + '/testing/executions').json()
    assert executions[0]['status'] == 'Queued'
    assert executions[0]['target'] == '192.0.2.1'
    details = client.get(path + '/testing/executions/' + executions[0]['id']).json()
    assert details['dispatch_status'] == 'requires_fresh_authorization'
    assert details['authorized_activity']['safety_evidence']['parameter_digest']
    assert len(overview['authorization_scope']['excluded_targets']) == int(partial)


def test_scheduling_failure_rolls_back_all_start_changes(client, db, engine, start_case):
    from sqlalchemy.exc import SQLAlchemyError

    path, headers, _, _, _ = start_case
    body = confirmation(review(client, path))

    def fail_insert(conn, cursor, statement, *args):
        if statement.startswith('INSERT INTO baseline_execution_requests'):
            raise SQLAlchemyError('Synthetic queue failure')

    event.listen(engine, 'before_cursor_execute', fail_insert)
    try:
        assert client.post(path + '/start', headers=headers, json=body).status_code == 503
    finally:
        event.remove(engine, 'before_cursor_execute', fail_insert)
    assert db.scalar(select(func.count()).select_from(AssessmentStartAuthorization)) == 0
    assert db.scalar(select(func.count()).select_from(AssessmentStartEvent)) == 0
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest)) == 0
    assert client.get(path).json()['status'] == 'Draft'


@pytest.mark.parametrize('failure', ['token', 'csrf', 'origin', 'confirmation', 'tool', 'scope'])
def test_rejected_start_never_schedules(client, db, start_case, failure):
    from app.baseline_maintenance import record_tool_state

    path, headers, _, _, _ = start_case
    body = confirmation(review(client, path))
    if failure == 'token':
        body['review_token'] += '0'
    elif failure == 'csrf':
        headers = {**headers, 'X-CSRF-Token': 'invalid'}
    elif failure == 'origin':
        headers = {**headers, 'Origin': 'https://other.test'}
    elif failure == 'confirmation':
        body['confirmed'] = False
    elif failure == 'tool':
        record_tool_state(db, 'Nmap', 'disabled', [])
        db.flush()
    elif failure == 'scope':
        assert client.post(path + '/scope', headers=headers,
                           json={'revision': 1, 'value': '203.0.113.0/24'}).status_code == 201
    assert client.post(path + '/start', headers=headers, json=body).status_code >= 400
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest)) == 0
    assert client.get(path).json()['status'] == 'Draft'


def test_testing_access_is_assessment_scoped(client, db, start_case):
    from test_assessments import add_analyst, sign_in

    path, headers, _, _, _ = start_case
    receipt = client.post(path + '/start', headers=headers, json=confirmation(review(client, path))).json()
    execution_id = receipt['queued_execution_ids'][0]
    outsider = add_analyst(db, 'queue-outsider')
    sign_in(client, outsider.username)
    for suffix in ('/testing', '/testing/executions', '/testing/executions/' + execution_id):
        assert client.get(path + suffix).status_code == 404
    client.cookies.clear()
    assert client.get(path + '/testing').status_code == 401


def test_database_prevents_duplicate_scheduling(client, db, start_case):
    path, headers, _, _, _ = start_case
    response = client.post(path + '/start', headers=headers, json=confirmation(review(client, path)))
    assert response.status_code == 201
    request = db.scalar(select(BaselineExecutionRequest))
    with pytest.raises(IntegrityError):
        with db.begin_nested():
            db.add(BaselineExecutionRequest(
                assessment_id=request.assessment_id, authorization_id=request.authorization_id,
                target_id=request.target_id, profile_id=request.profile_id,
                profile_version=request.profile_version, tool=request.tool, activity=request.activity,
                status='Queued', authorized_activity=request.authorized_activity,
            ))
            db.flush()


@pytest.mark.parametrize('same_key', [False, True])
def test_concurrent_start_has_one_authorization_and_queue(engine, monkeypatch, same_key):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from uuid import uuid4

    from fastapi.testclient import TestClient
    from sqlalchemy import text
    from sqlalchemy.orm import sessionmaker

    from app.database import get_db
    from app.main import create_app

    factory = sessionmaker(engine, expire_on_commit=False)

    def independent_db():
        with factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = independent_db
    try:
        with factory() as setup_db, TestClient(app, base_url='https://testserver') as setup_client:
            setup_client.headers['Origin'] = 'https://testserver'
            path, headers, _, _, _ = start_case.__wrapped__(setup_client, setup_db, monkeypatch)
            setup_db.commit()
            body = confirmation(review(setup_client, path))
            cookies = dict(setup_client.cookies)
        barrier = Barrier(2)

        def send(key):
            with TestClient(app, base_url='https://testserver', cookies=cookies) as parallel_client:
                barrier.wait(timeout=10)
                return parallel_client.post(path + '/start', json=body, headers={
                    **headers, 'Idempotency-Key': key, 'Origin': 'https://testserver',
                })

        key = headers['Idempotency-Key']
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(send, key)
            second = pool.submit(send, key if same_key else str(uuid4()))
            statuses = sorted([first.result(timeout=15).status_code, second.result(timeout=15).status_code])
        assert statuses == ([200, 201] if same_key else [201, 409])
        with factory() as check:
            assert check.scalar(select(func.count()).select_from(AssessmentStartAuthorization)) == 1
            assert check.scalar(select(func.count()).select_from(AssessmentStartEvent)) == 1
            assert check.scalar(select(func.count()).select_from(BaselineExecutionRequest)) == 1
    finally:
        # This engine is the positively verified disposable test database.
        with engine.begin() as connection:
            connection.execute(text('TRUNCATE users, roles, baseline_tool_states, execution_policy_versions CASCADE'))


def test_overview_keeps_one_snapshot_during_start(engine, monkeypatch):
    from fastapi.testclient import TestClient
    from sqlalchemy import text
    from sqlalchemy.orm import sessionmaker
    from app.database import get_db
    from app.main import create_app

    factory = sessionmaker(engine, expire_on_commit=False)

    def independent_db():
        with factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = independent_db
    try:
        with factory() as setup_db, TestClient(app, base_url='https://testserver') as writer:
            writer.headers['Origin'] = 'https://testserver'
            path, headers, _, _, _ = start_case.__wrapped__(writer, setup_db, monkeypatch)
            setup_db.commit()
            body = confirmation(review(writer, path))
            started = False

            def commit_after_overview_select(conn, cursor, statement, *args):
                nonlocal started
                if started or 'LEFT OUTER JOIN baseline_execution_requests' not in statement:
                    return
                started = True
                response = writer.post(path + '/start', headers=headers, json=body)
                assert response.status_code == 201

            event.listen(engine, 'after_cursor_execute', commit_after_overview_select)
            try:
                with TestClient(app, base_url='https://testserver', cookies=dict(writer.cookies)) as reader:
                    before = reader.get(path + '/testing').json()
            finally:
                event.remove(engine, 'after_cursor_execute', commit_after_overview_select)
            assert started
            assert before['lifecycle_status'] == 'Draft'
            assert before['counts']['total'] == 0
            assert before['authorization_scope']['authorization_id'] is None
            after = writer.get(path + '/testing').json()
            assert after['lifecycle_status'] == 'Testing'
            assert after['counts']['queued'] == 1
            assert after['authorization_scope']['authorization_id']
    finally:
        with engine.begin() as connection:
            connection.execute(text('TRUNCATE users, roles, baseline_tool_states, execution_policy_versions CASCADE'))


def test_configured_policy_reports_missing_safety_without_queue(client, db, start_case, monkeypatch):
    from app import assessment_readiness
    from app.execution_policy import PolicySelection
    from app.system_policy_catalog import configured_policy

    path, headers, _, _, _ = start_case
    monkeypatch.setattr(assessment_readiness, 'load_trusted_policy', lambda _: PolicySelection(
        'configured', 'system_policy_configured', 'Configured policy only', definition=configured_policy(),
    ))
    data = client.get(path + '/readiness').json()
    assert data['start_review']['confirmation_possible'] is False
    activity = data['targets'][0]['baseline_activities'][0]
    assert set(activity['system_safety_verification']['pending']) >= {
        'executor_parameter_binding', 'runtime_stop_condition_enforcement',
    }
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest)) == 0
    assert client.get(path).json()['status'] == 'Draft'
