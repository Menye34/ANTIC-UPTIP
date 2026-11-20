"""Start → scoped service queue → fake XML → real planner; no scanner execution."""
from uuid import UUID, uuid4
import pytest
from sqlalchemy import select, func, event
from sqlalchemy.exc import IntegrityError
from app.models import (Assessment, BaselineExecutionRequest, ServiceDiscoveryConsent,
                        AssessmentStartAuthorization, BaselineToolState, ScopeEntry)
from app.baseline_maintenance import record_tool_state
from app.baseline_resolution import reconcile
from app.dispatch_verification import verify, DispatchDenied
from test_scheduling_start import prepared, get_review, confirm, scheduling_concurrency  # noqa: F401
from test_service_discovery import ServiceAdapter
from test_execution_orchestration import BorrowedFactory
from app.execution_orchestration import ExecutionRunner
from app.execution_results import EvidenceStore


def authorize_ports(client, db, prepared, ports=None, capability=True):
    path, headers, _ = prepared
    if capability:
        record_tool_state(db, 'Nmap', 'enabled', ['ipv4-discovery', 'tcp-service-discovery'])
        reconcile(db, db.get(Assessment, UUID(path.rsplit('/', 1)[1])), 'tool_state_changed')
        db.commit()
    revision = client.get(path + '/scope').json()['revision']
    response = client.post(path + '/scope', headers=headers,
        json={'revision': revision, 'value': '192.0.2.1', 'tcp_ports': ports or [80, 443]})
    assert response.status_code == 201, response.text
    return path, headers


def test_scoped_start_queues_two_and_replays_without_dispatch(client, db, prepared):
    path, headers = authorize_ports(client, db, prepared)
    review = get_review(client, path)['start_review']
    assert review['mode'] == 'full' and review['confirmation_possible']
    assert [a['profile_id'] for a in review['eligible_activities']] == ['network-discovery', 'service-discovery']
    service = review['eligible_activities'][1]['scheduling_preparation']
    assert service['authorized_tcp_ports'] == [80, 443]
    assert service['plan']['arguments'][-2:] == ['-p', '80,443']
    key = str(uuid4())
    result = confirm(client, path, headers, review, key)
    assert result.status_code == 201, result.text
    assert result.json()['queued_execution_count'] == 2
    assert result.json()['execution_authorized'] is False
    assert confirm(client, path, headers, review, key).json() == result.json()
    assert confirm(client, path, headers, review).status_code == 409
    consent = db.scalar(select(ServiceDiscoveryConsent))
    row = db.get(BaselineExecutionRequest, consent.request_id)
    assert consent.snapshot['source'] == 'assessment_start'
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest)) == 2
    with pytest.raises(DispatchDenied, match='host_discovery_dependency_pending'):
        verify(db, row)
    from app.execution_orchestration import claim
    assert claim(BorrowedFactory(db), row.id, 'too-early', 30) is None
    assert row.status == 'Queued'
    assert client.get(path + '/testing').json()['counts']['queued'] == 2


def test_scoped_service_real_planner_from_fake_worker(client, db, prepared, tmp_path):
    path, headers = authorize_ports(client, db, prepared)
    result = confirm(client, path, headers, get_review(client, path)['start_review'])
    assert result.status_code == 201, result.text
    rows = db.scalars(select(BaselineExecutionRequest).order_by(BaselineExecutionRequest.profile_id)).all()
    host, service = rows
    # The existing fake host adapter exercises the real host authorization path.
    from test_execution_orchestration import FakeAdapter
    tmp_path.chmod(0o700)
    host_adapter = FakeAdapter()
    assert ExecutionRunner(BorrowedFactory(db), host_adapter, EvidenceStore(tmp_path), 'fake-host').run(host.id)
    assert host.status == 'Completed'
    adapter = ServiceAdapter()
    assert ExecutionRunner(BorrowedFactory(db), adapter, EvidenceStore(tmp_path), 'fake-service').run(service.id)
    assert service.status == 'Completed' and adapter.calls == 1
    assert not ExecutionRunner(BorrowedFactory(db), adapter, EvidenceStore(tmp_path), 'fake-service').run(service.id)
    recs = client.get(path + '/testing/recommendations').json()['recommendations']
    assert len(recs) == 2
    assert all(r['suggested_tool'] == 'Nikto' and not r['execution_available'] for r in recs)
    for rec in recs:
        assert rec['source_evidence_id'] and rec['source_observation_id']
        assert not client.get(path + f"/testing/recommendations/{rec['id']}/eligibility").json()['eligible']


@pytest.mark.parametrize('ports', [[0], [65536], [True], [80, 80], list(range(1, 18)), ['80']])
def test_invalid_ports_rejected(client, prepared, ports):
    path, headers, _ = prepared
    response = client.post(path + '/scope', headers=headers,
        json={'revision': 1, 'value': '192.0.2.1', 'tcp_ports': ports})
    assert response.status_code == 422


def test_subnet_never_authorizes_ports(client, prepared):
    path, headers, _ = prepared
    assert client.post(path + '/scope', headers=headers,
        json={'revision': 1, 'value': '192.0.2.0/28', 'tcp_ports': [80]}).status_code == 422


def test_missing_service_capability_excludes_only_service(client, db, prepared):
    path, headers = authorize_ports(client, db, prepared, capability=False)
    review = get_review(client, path)['start_review']
    assert review['mode'] == 'partial'
    assert [a['profile_id'] for a in review['eligible_activities']] == ['network-discovery']
    assert review['excluded_activities'][0]['profile_id'] == 'service-discovery'
    result = confirm(client, path, headers, review)
    assert result.status_code == 201 and result.json()['queued_execution_count'] == 1
    assert db.scalar(select(func.count()).select_from(ServiceDiscoveryConsent)) == 0


def test_port_change_invalidates_review(client, db, prepared):
    path, headers = authorize_ports(client, db, prepared)
    review = get_review(client, path)['start_review']
    scope = client.get(path + '/scope').json()
    entry = next(e for e in scope['entries'] if e['value'] == '192.0.2.1')
    assert client.patch(path + '/scope/' + entry['id'], headers=headers,
        json={'revision': scope['revision'], 'value': entry['value'], 'tcp_ports': [443]}).status_code == 200
    assert confirm(client, path, headers, review).status_code == 409
    assert db.scalar(select(func.count()).select_from(AssessmentStartAuthorization)) == 0
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest)) == 0


def test_consent_failure_rolls_back_entire_start(client, db, prepared):
    path, headers = authorize_ports(client, db, prepared)
    review = get_review(client, path)['start_review']
    def fail(*args):
        raise IntegrityError('synthetic consent failure', None, Exception('synthetic'))
    event.listen(ServiceDiscoveryConsent, 'before_insert', fail)
    try:
        assert confirm(client, path, headers, review).status_code == 503
    finally:
        event.remove(ServiceDiscoveryConsent, 'before_insert', fail)
    assert db.get(Assessment, UUID(path.rsplit('/', 1)[1])).status == 'Draft'
    for model in (AssessmentStartAuthorization, BaselineExecutionRequest, ServiceDiscoveryConsent):
        assert db.scalar(select(func.count()).select_from(model)) == 0


def test_scope_ports_readback_audit_and_clear(client, db, prepared):
    from app.models import ScopeEvent
    path, headers = authorize_ports(client, db, prepared, [443, 80])
    scope = client.get(path + '/scope').json()
    entry = next(e for e in scope['entries'] if e['value'] == '192.0.2.1')
    assert entry['tcp_ports'] == [80, 443]
    assert db.scalar(select(ScopeEvent).order_by(ScopeEvent.revision.desc())).after['tcp_ports'] == [80, 443]
    assert client.patch(path + '/scope/' + entry['id'], headers=headers,
        json={'revision': scope['revision'], 'value': entry['value'], 'tcp_ports': []}).status_code == 200
    review = get_review(client, path)['start_review']
    assert [a['profile_id'] for a in review['eligible_activities']] == ['network-discovery', 'service-discovery']
    assert review['eligible_activities'][1]['scheduling_preparation']['authorized_tcp_ports'] == [80, 443]


def test_scope_port_history_refuses_downgrade(scheduling_concurrency, monkeypatch):
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from fastapi.testclient import TestClient
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError
    app, factory, _, _, _ = scheduling_concurrency
    with factory() as db, TestClient(app, base_url='https://testserver') as client:
        client.headers['Origin'] = 'https://testserver'
        setup = prepared.__wrapped__(client, db, monkeypatch)
        authorize_ports(client, db, setup)
    config = Config(str(Path(__file__).resolve().parents[1] / 'alembic.ini'))
    config.set_main_option('script_location', str(Path(__file__).resolve().parents[1] / 'migrations'))
    with pytest.raises(DBAPIError, match='authorized TCP port history'):
        command.downgrade(config, '0024')
    with factory() as db:
        assert db.scalar(text('SELECT version_num FROM alembic_version')) == '0025'


def test_scoped_service_respects_runtime_tool_revocation(client, db, prepared, tmp_path):
    path, headers = authorize_ports(client, db, prepared)
    response = confirm(client, path, headers, get_review(client, path)['start_review'])
    assert response.status_code == 201
    host = db.scalar(select(BaselineExecutionRequest).where(BaselineExecutionRequest.profile_id == 'network-discovery'))
    service = db.scalar(select(BaselineExecutionRequest).where(BaselineExecutionRequest.profile_id == 'service-discovery'))
    from test_execution_orchestration import FakeAdapter
    tmp_path.chmod(0o700)
    assert ExecutionRunner(BorrowedFactory(db), FakeAdapter(), EvidenceStore(tmp_path), 'fake-host').run(host.id)
    assert host.status == 'Completed'
    record_tool_state(db, 'Nmap', 'disabled', [])
    db.flush()
    with pytest.raises(DispatchDenied):
        verify(db, service)


@pytest.mark.parametrize('same_key', [True, False])
@pytest.mark.parametrize('edit_ports', [False, True])
def test_concurrent_scoped_starts_never_duplicate(scheduling_concurrency, same_key, edit_ports):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from fastapi.testclient import TestClient
    app, factory, setup, _, cookies = scheduling_concurrency
    with factory() as db, TestClient(app, base_url='https://testserver', cookies=cookies) as client:
        client.headers['Origin'] = 'https://testserver'
        path, headers = authorize_ports(client, db, setup)
        review = get_review(client, path)['start_review']
        scope = client.get(path + '/scope').json()
        entry = next(e for e in scope['entries'] if e['value'] == '192.0.2.1')
    keys = [str(uuid4()), str(uuid4())]
    if same_key:
        keys[1] = keys[0]
    barrier = Barrier(3 if edit_ports else 2)
    def start(key):
        with TestClient(app, base_url='https://testserver', cookies=cookies) as client:
            client.headers['Origin'] = 'https://testserver'
            barrier.wait(timeout=10)
            return confirm(client, path, headers, review, key).status_code
    def edit():
        with TestClient(app, base_url='https://testserver', cookies=cookies) as client:
            client.headers['Origin'] = 'https://testserver'
            barrier.wait(timeout=10)
            return client.patch(path + '/scope/' + entry['id'], headers=headers,
                json={'revision': scope['revision'], 'value': entry['value'], 'tcp_ports': [443]}).status_code
    with ThreadPoolExecutor(max_workers=3) as pool:
        jobs = [pool.submit(start, key) for key in keys]
        edit_job = pool.submit(edit) if edit_ports else None
        statuses = sorted(job.result(timeout=20) for job in jobs)
        edit_status = edit_job.result(timeout=20) if edit_job else None
    edited = edit_status == 200
    assert edit_status in (None, 200, 403)
    assert statuses == ([409, 409] if edited else ([200, 201] if same_key else [201, 409]))
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest)) == (0 if edited else 2)
        assert db.scalar(select(func.count()).select_from(ServiceDiscoveryConsent)) == (0 if edited else 1)
        assert db.scalar(select(func.count()).select_from(AssessmentStartAuthorization)) == (0 if edited else 1)


def test_scoped_start_has_no_scanner_or_network_calls(client, db, prepared, monkeypatch):
    import socket
    import subprocess
    path, headers = authorize_ports(client, db, prepared)
    def forbidden(*args, **kwargs):
        pytest.fail('Start attempted to execute a scanner or network call')
    with monkeypatch.context() as guard:
        guard.setattr(socket, 'getaddrinfo', forbidden)
        guard.setattr(socket.socket, 'connect', forbidden)
        guard.setattr(subprocess, 'Popen', forbidden)
        review = get_review(client, path)['start_review']
        assert confirm(client, path, headers, review).status_code == 201
