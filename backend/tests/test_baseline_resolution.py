from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import socket
import subprocess
from uuid import UUID

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import sessionmaker

from app import baseline_catalog
from app.baseline_maintenance import reconcile_all, record_tool_state
from app.models import BaselineAssignment, BaselineEvaluation
from test_assessments import API, add_analyst, sign_in


def test_resolution_lifecycle(client, db, engine, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Resolution attempted an external call')

    original = baseline_catalog.PROFILES
    factory = sessionmaker(engine)
    owner = add_analyst(db, 'baseline-owner')
    headers = sign_in(client, owner.username)
    assessment = client.post(API, headers=headers, json={'name': 'Baseline assessment'}).json()
    parent = f"{API}/{assessment['id']}"
    targets = parent + '/targets'
    scope = parent + '/scope'
    for revision, value in enumerate(['192.0.2.0/24', 'https://example.test/a', 'example.test']):
        assert client.post(scope, json={'revision': revision, 'value': value}, headers=headers).status_code == 201

    def add(value):
        response = client.post(targets, json={'value': value}, headers=headers)
        assert response.status_code == 201
        return next(target for target in response.json()['targets'] if target['normalized_value'] == value)

    ip = add('192.0.2.1')
    assert ip['baseline_assignments'][0]['reason_code'] == 'tool_unknown'
    assert add('192.0.2.0/25')['baseline_assignments'][0]['tool'] == 'Nmap'
    assert add('198.51.100.1')['baseline_summary'] == 'blocked'
    assert add('example.test')['baseline_summary'] == 'no_compatible_baseline'
    web = add('https://example.test/a')
    assert [assignment['tool'] for assignment in web['baseline_assignments']] == ['OWASP ZAP']

    # Test multi-assignment independently of the conservative initial catalog.
    secondary = replace(original[1], key='test-secondary', kinds=('IP address',))
    monkeypatch.setattr(baseline_catalog, 'PROFILES', (*original, secondary))
    with factory.begin() as tx:
        record_tool_state(tx, 'Nmap', 'enabled', ['ipv4-discovery'])
        record_tool_state(tx, 'OWASP ZAP', 'disabled', [])
    stale = client.get(targets).json()['targets']
    assert any(a['status'] == 'requires_revalidation' for t in stale for a in t['baseline_assignments'])
    db.rollback()  # The shared test session retains the assessment read lock.
    with monkeypatch.context() as guard:
        guard.setattr(socket, 'getaddrinfo', forbidden)
        guard.setattr(socket, 'create_connection', forbidden)
        guard.setattr(socket.socket, 'connect', forbidden)
        guard.setattr(subprocess, 'Popen', forbidden)
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda _: reconcile_all(factory, 'system_reconcile'), range(2)))

    view = next(t for t in client.get(targets).json()['targets'] if t['id'] == ip['id'])
    assert [(a['status'], a['reason_code']) for a in view['baseline_assignments']] == [
        ('resolved', 'prepared'), ('unavailable', 'tool_disabled')]
    assert view['eligibility'] == 'pending'
    history_count = len(db.scalars(select(BaselineEvaluation)).all())
    db.rollback()
    reconcile_all(factory, 'system_reconcile')
    assert len(db.scalars(select(BaselineEvaluation)).all()) == history_count
    db.rollback()

    with factory.begin() as tx:
        record_tool_state(tx, 'OWASP ZAP', 'unavailable', [])
    reconcile_all(factory, 'tool_state_changed')
    assert any(e.decision['reason_code'] == 'tool_unavailable' for e in db.scalars(select(BaselineEvaluation)))
    db.rollback()

    monkeypatch.setattr(baseline_catalog, 'PROFILES', (replace(original[0], version=2), original[1]))
    reconcile_all(factory, 'system_reconcile')
    view = next(t for t in client.get(targets).json()['targets'] if t['id'] == ip['id'])
    assert [a['version'] for a in view['baseline_assignments']] == [2]
    item_url = targets + '/' + ip['id']
    response = client.patch(item_url, json={'value': '198.51.100.2', 'revision': 1}, headers=headers)
    assert response.status_code == 200
    view = next(t for t in response.json()['targets'] if t['id'] == ip['id'])
    assert view['baseline_summary'] == 'blocked'
    scope_items = client.get(scope).json()['entries']
    subnet = next(item for item in scope_items if item['value'] == '192.0.2.0/24')
    assert client.request('DELETE', scope + '/' + subnet['id'], json={'revision': 3, 'confirmed': True},
                          headers=headers).status_code == 200
    assert next(t for t in client.get(targets).json()['targets'] if t['kind'] == 'Subnet')['baseline_summary'] == 'blocked'
    assert client.request('DELETE', item_url, json={'revision': 2, 'confirmed': True}, headers=headers).status_code == 200
    assert not db.scalars(select(BaselineAssignment).where(BaselineAssignment.target_id == UUID(ip['id']))).all()
    history = db.scalars(select(BaselineEvaluation).where(BaselineEvaluation.target_id == UUID(ip['id']))).all()
    assert {event.decision['profile']['version'] for event in history} == {1, 2}
    assert all(event.decision['profile']['digest'] for event in history)


def test_baseline_migration_round_trip_preserves_targets(client, db, engine):
    owner = add_analyst(db, 'baseline-migration-owner')
    headers = sign_in(client, owner.username)
    assessment = client.post(API, headers=headers, json={'name': 'Migration check'}).json()
    path = f"{API}/{assessment['id']}/targets"
    assert client.post(path, json={'value': '192.0.2.1'}, headers=headers).status_code == 201
    config = Config('backend/alembic.ini')
    command.downgrade(config, '0007')
    try:
        assert not inspect(engine).has_table('baseline_assignments')
        with engine.connect() as connection:
            assert connection.scalar(text('SELECT count(*) FROM assessment_targets')) == 1
    finally:
        command.upgrade(config, 'head')
    result = client.get(path).json()['targets'][0]
    assert result['normalized_value'] == '192.0.2.1'
    assert result['baseline_summary'] == 'pending'


def test_resolution_failure_rolls_back_target_and_history(client, db, engine, monkeypatch):
    from sqlalchemy.exc import SQLAlchemyError

    from app import target_routes
    from app.models import AssessmentTarget

    owner = add_analyst(db, 'baseline-rollback-owner')
    headers = sign_in(client, owner.username)
    assessment = client.post(API, headers=headers, json={'name': 'Rollback check'}).json()

    def fail_after_write(session, *args):
        original_reconcile(session, *args)
        session.flush()
        raise SQLAlchemyError('Simulated resolution failure')

    original_reconcile = target_routes.reconcile
    monkeypatch.setattr(target_routes, 'reconcile', fail_after_write)
    with engine.connect() as connection:
        before = connection.scalar(select(text('count(*)')).select_from(AssessmentTarget))
    response = client.post(f"{API}/{assessment['id']}/targets", headers=headers, json={'value': '192.0.2.1'})
    assert response.status_code == 503
    db.rollback()  # The test fixture supplies its own request session.
    with engine.connect() as connection:
        assert connection.scalar(select(text('count(*)')).select_from(AssessmentTarget)) == before
        assert not connection.execute(select(BaselineEvaluation.id)).all()
