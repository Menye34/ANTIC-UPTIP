from uuid import UUID, uuid4

import pytest
from sqlalchemy import event, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.models import AssessmentAssignment, ScopeEntry, ScopeEvent
from app.scope_validation import normalize
from test_assessments import API, add_analyst, sign_in


def draft(client, headers):
    response = client.post(API, json={'name': 'Scope draft'}, headers=headers)
    assert response.status_code == 201
    return response.json()['id']


@pytest.mark.parametrize(('raw', 'value', 'kind'), [
    (' 192.0.2.1 ', '192.0.2.1', 'IP address'),
    ('192.0.2.0/24', '192.0.2.0/24', 'Subnet'),
    ('Test.EXAMPLE', 'test.example', 'Hostname'),
    ('HTTPS://Test.EXAMPLE:8443/A?x=Y', 'https://test.example:8443/A?x=Y', 'Web URL'),
])
def test_scope_normalizes_without_broadening(raw, value, kind):
    assert normalize(raw) == (value, kind)


@pytest.mark.parametrize('raw', [
    '', '192.0.2.300', '127.1', '192.0.2.1/24', '192.0.2.0/33', '192.0.2.0/024',
    '-example.test', 'a..test', '::1', '*.example.test', 'https://user:secret@example.test/',
    'https://example.test:70000/', 'https://example.test/#fragment', 'http://0x7f000001/',
    'https://example.test/%xyz', 'ftp://example.test', 'https://example.test\\@other.test',
])
def test_scope_rejects_invalid_values(raw):
    with pytest.raises(ValueError):
        normalize(raw)


def test_scope_crud_revision_duplicates_and_audit(client, db):
    owner = add_analyst(db, 'scope-owner')
    headers = sign_in(client, owner.username)
    assessment = draft(client, headers)
    other = draft(client, {**headers, 'Idempotency-Key': str(uuid4())})
    path = f'{API}/{assessment}/scope'
    assert client.get(path).json()['entries'] == []
    assert client.post(path, json={'value': '192.0.2.1/24', 'revision': 0}, headers=headers).status_code == 422
    result = client.post(path, json={'value': ' Example.TEST ', 'revision': 0}, headers=headers)
    assert result.status_code == 201
    entry = result.json()['entries'][0]
    assert entry['value'] == 'example.test'
    assert client.get(path).json()['entries'] == [entry]
    assert client.get(f'{API}/{assessment}').json()['scope_entry_count'] == 1
    duplicate = client.post(path, json={'value': 'EXAMPLE.test', 'revision': 1}, headers=headers)
    assert duplicate.status_code == 409 and duplicate.json()['code'] == 'duplicate_entry'
    other_path = f'{API}/{other}/scope'
    assert client.post(other_path, json={'value': 'example.test', 'revision': 0}, headers=headers).status_code == 201
    entry_path = f"{path}/{entry['id']}"
    assert client.patch(f"{other_path}/{entry['id']}", json={'value': 'new.test', 'revision': 1},
                        headers=headers).status_code == 404
    unchanged = client.patch(entry_path, json={'value': ' EXAMPLE.TEST ', 'revision': 1}, headers=headers)
    assert unchanged.status_code == 200 and unchanged.json()['revision'] == 1
    stale = client.patch(entry_path, json={'value': 'new.test', 'revision': 0}, headers=headers)
    assert stale.status_code == 409 and stale.json()['code'] == 'stale_revision'
    assert client.patch(entry_path, json={'value': 'new.test', 'revision': 1}, headers=headers).status_code == 200
    assert client.request('DELETE', entry_path, json={'confirmed': False, 'revision': 2},
                          headers=headers).status_code == 422
    result = client.request('DELETE', entry_path, json={'confirmed': True, 'revision': 2}, headers=headers)
    assert result.status_code == 200 and result.json()['entries'] == []
    events = db.scalars(select(ScopeEvent).where(ScopeEvent.assessment_id == UUID(assessment))
                        .order_by(ScopeEvent.revision)).all()
    assert [record.action for record in events] == ['added', 'edited', 'removed']
    assert all(record.actor_id == owner.id and record.occurred_at for record in events)
    assert events[0].before is None
    assert events[1].before == events[0].after
    assert events[2].before == events[1].after and events[2].after is None


def test_scope_access_and_write_controls(client, db, user):
    assert client.get(f'{API}/{uuid4()}/scope').status_code == 401
    assert client.get(f'{API}/{uuid4()}/scope', headers=sign_in(client, user.username)).status_code == 403
    owner = add_analyst(db, 'scope-owner')
    assigned = add_analyst(db, 'scope-assigned')
    headers = sign_in(client, owner.username)
    assessment = draft(client, headers)
    path = f'{API}/{assessment}/scope'
    payload = {'value': 'example.test', 'revision': 0}
    assert client.post(path, json=payload).status_code == 403
    assert client.post(path, json=payload, headers={**headers, 'Origin': 'https://other.test'}).status_code == 403
    headers = sign_in(client, assigned.username)
    assert client.get(path).status_code == 404
    db.add(AssessmentAssignment(assessment_id=UUID(assessment), analyst_id=assigned.id))
    db.commit()
    assert client.get(path).json()['can_edit'] is False
    assert client.post(path, json=payload, headers=headers).status_code == 403
    # The current schema only permits Draft, so model a future state in a disposable transaction.
    headers = sign_in(client, owner.username)
    db.execute(text('ALTER TABLE assessments DROP CONSTRAINT ck_assessments_draft'))
    db.execute(text("UPDATE assessments SET status = 'Active' WHERE id = :id"), {'id': assessment})
    assert client.post(path, json=payload, headers=headers).status_code == 403
    db.rollback()


def test_scope_audit_failure_rolls_back_entry_and_revision(client, db):
    owner = add_analyst(db, 'scope-owner')
    headers = sign_in(client, owner.username)
    assessment = draft(client, headers)
    path = f'{API}/{assessment}/scope'

    def fail(*_):
        raise SQLAlchemyError('forced audit write failure')

    event.listen(ScopeEvent, 'before_insert', fail)
    try:
        assert client.post(path, json={'value': 'example.test', 'revision': 0}, headers=headers).status_code == 503
    finally:
        event.remove(ScopeEvent, 'before_insert', fail)
    result = client.get(path).json()
    assert result['revision'] == 0 and result['entries'] == []


def test_scope_database_constraints(client, db):
    owner = add_analyst(db, 'scope-owner')
    assessment = UUID(draft(client, sign_in(client, owner.username)))
    db.add(ScopeEntry(assessment_id=assessment, normalized_value='example.test', kind='Hostname'))
    db.commit()
    for parent_id, value, kind in [
        (assessment, 'example.test', 'Hostname'),
        (assessment, 'invalid-kind.test', 'Other'),
        (uuid4(), 'missing-parent.test', 'Hostname'),
    ]:
        db.add(ScopeEntry(assessment_id=parent_id, normalized_value=value, kind=kind))
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()
    assert not any('target' in name for name in db.scalars(text(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public'")))
