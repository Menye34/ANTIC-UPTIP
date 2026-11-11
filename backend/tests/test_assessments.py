from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, select
from sqlalchemy.exc import SQLAlchemyError

from app.main import create_app
from app.models import Assessment, AssessmentAssignment, AssessmentCreationEvent, Role, User
from app.security import hasher

API = '/api/v1/assessments'


def add_analyst(db, username):
    if db.get(Role, 'Security Analyst') is None:
        db.add(Role(name='Security Analyst'))
        db.flush()
    user = User(username=username, role='Security Analyst', password_hash=hasher.hash('test-password'),
                password_change_required=False)
    db.add(user)
    db.commit()
    return user


def sign_in(client, username):
    result = client.post('/api/v1/auth/login', json={'username': username, 'password': 'test-password'})
    assert result.status_code == 200
    return {'X-CSRF-Token': result.json()['csrf_token'], 'Idempotency-Key': str(uuid4())}


def test_create_persists_draft_and_activity_and_unique_reference(client, db):
    user = add_analyst(db, 'draft-author')
    headers = sign_in(client, user.username)
    response = client.post(API, json={'name': '  Branch office  ', 'description': ' Network review ',
                                      'start_date': '2026-11-07'}, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data['name'] == 'Branch office'
    assert data['description'] == 'Network review'
    assert data['start_date'] == '2026-11-07' and data['end_date'] is None
    assert data['status'] == 'Draft'
    assert data['lead_analyst'] == data['created_by'] == user.username
    identifier = UUID(data['id'])
    assert db.get(Assessment, identifier).creator_id == user.id
    activity = db.get(AssessmentCreationEvent, identifier)
    assert activity.actor_id == user.id
    assert activity.occurred_at.isoformat().replace('+00:00', 'Z') == data['created_at']
    assert client.get(f'{API}/{identifier}').json() == data
    retry = client.post(API, json={'name': 'Branch office', 'description': 'Network review',
                                  'start_date': '2026-11-07'}, headers=headers)
    assert retry.status_code == 200 and retry.json() == data
    assert len(db.scalars(select(AssessmentCreationEvent)).all()) == 1
    assert client.post(API, json={'name': 'Different content'}, headers=headers).status_code == 409
    other = client.post(API, json={'name': 'Branch office', 'description': 'Network review',
                                  'start_date': '2026-11-07'},
                        headers={**headers, 'Idempotency-Key': str(uuid4())}).json()
    assert data['reference'].startswith('ASM-') and data['reference'] != other['reference']
    assert {row['id'] for row in client.get(API).json()} == {data['id'], other['id']}


@pytest.mark.parametrize('payload', [
    {}, {'name': '  '}, {'name': 'X', 'start_date': '2026-02-30'},
    {'name': 'X', 'start_date': 0},
    {'name': 'X', 'start_date': '2026-11-08', 'end_date': '2026-11-07'},
    {'name': 'X', 'creator_id': str(uuid4())}, {'name': 'X', 'status': 'Active'},
])
def test_rejects_invalid_fields_and_spoofing(client, db, payload):
    user = add_analyst(db, 'draft-validation')
    response = client.post(API, json=payload, headers=sign_in(client, user.username))
    assert response.status_code == 422
    assert db.scalars(select(Assessment)).all() == []


def test_auth_role_csrf_and_origin(client, db, user):
    assert client.get(API).status_code == 401
    assert client.get(f'{API}/{uuid4()}').status_code == 401
    assert client.post(API, json={'name': 'Draft'}).status_code == 401
    assert client.post(API, json={'name': 'Draft'}, headers=sign_in(client, user.username)).status_code == 403
    assert client.get(API).status_code == 403
    analyst = add_analyst(db, 'csrf-analyst')
    headers = sign_in(client, analyst.username)
    assert client.post(API, json={'name': 'Draft'}, headers={'Idempotency-Key': headers['Idempotency-Key']}).status_code == 403
    assert client.post(API, json={'name': 'Draft'}, headers={**headers, 'Origin': 'https://other.test'}).status_code == 403


def test_access_is_creator_or_assignment_not_lead_name(client, db):
    owner = add_analyst(db, 'draft-owner')
    assigned = add_analyst(db, 'draft-assignee')
    headers = sign_in(client, owner.username)
    identifier = client.post(API, json={'name': 'Private draft'}, headers=headers).json()['id']
    db.get(Assessment, UUID(identifier)).lead_analyst_id = assigned.id
    db.commit()

    sign_in(client, assigned.username)
    assert client.get(API).json() == []
    assert client.get(f'{API}/{identifier}').status_code == client.get(f'{API}/{uuid4()}').status_code == 404
    db.add(AssessmentAssignment(assessment_id=UUID(identifier), analyst_id=assigned.id))
    db.commit()
    assert client.get(f'{API}/{identifier}').status_code == 200
    assert [item['id'] for item in client.get(API).json()] == [identifier]


def test_creation_event_failure_rolls_back_assessment(client, db):
    user = add_analyst(db, 'rollback-analyst')
    headers = sign_in(client, user.username)

    def fail(*_):
        raise SQLAlchemyError('test failure')

    event.listen(AssessmentCreationEvent, 'before_insert', fail)
    try:
        response = client.post(API, json={'name': 'Should roll back'}, headers=headers)
    finally:
        event.remove(AssessmentCreationEvent, 'before_insert', fail)
    assert response.status_code == 503
    assert 'test failure' not in response.text
    assert db.scalars(select(Assessment)).all() == []
    assert db.scalars(select(AssessmentCreationEvent)).all() == []


def test_replay_key_is_scoped_to_creator_and_security_checks(client, db, user):
    owner = add_analyst(db, 'replay-owner')
    other = add_analyst(db, 'replay-other')
    headers = sign_in(client, owner.username)
    payload = {'name': 'Same draft payload'}
    original = client.post(API, json=payload, headers=headers)
    assert original.status_code == 201
    assert client.post(API, json=payload, headers={**headers, 'Origin': 'https://other.test'}).status_code == 403
    assert client.post(API, json=payload, headers={**headers, 'X-CSRF-Token': 'wrong'}).status_code == 403
    client.cookies.clear()
    assert client.post(API, json=payload, headers=headers).status_code == 401
    non_analyst = sign_in(client, user.username)
    assert client.post(API, json=payload, headers={**non_analyst, 'Idempotency-Key': headers['Idempotency-Key']}).status_code == 403
    other_headers = sign_in(client, other.username)
    duplicate_key = client.post(API, json=payload,
        headers={**other_headers, 'Idempotency-Key': headers['Idempotency-Key']})
    assert duplicate_key.status_code == 201
    assert duplicate_key.json()['id'] != original.json()['id']
    assert duplicate_key.json()['created_by'] == other.username


def test_concurrent_same_key_creates_one_draft_and_event(client, db):
    user = add_analyst(db, 'concurrent-analyst')
    headers = sign_in(client, user.username)
    cookies = dict(client.cookies)
    start = Barrier(2, timeout=10)

    def submit():
        # Each request uses a separate session and connection from the real app.
        with TestClient(create_app(), base_url='https://testserver', cookies=cookies) as worker:
            start.wait()
            return worker.post(API, json={'name': 'Concurrent draft'},
                               headers={**headers, 'Origin': 'https://testserver'})

    with ThreadPoolExecutor(max_workers=2) as workers:
        first, second = list(workers.map(lambda _: submit(), range(2)))
    assert sorted([first.status_code, second.status_code]) == [200, 201]
    assert first.json() == second.json()
    assert len(db.scalars(select(Assessment)).all()) == 1
    assert len(db.scalars(select(AssessmentCreationEvent)).all()) == 1
