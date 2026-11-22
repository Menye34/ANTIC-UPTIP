"""Real queued consent, fake adapters, disposable DB; no scanner invocation."""
from copy import deepcopy
from types import SimpleNamespace
import json

import pytest
from sqlalchemy import select, func

from app import service_start_preparation as policy
from app.baseline_catalog import fingerprint
from app.dispatch_verification import DispatchDenied, verify
from app.execution_orchestration import ExecutionRunner
from app.execution_results import EvidenceStore
from app.models import (AssessmentStartAuthorization, BaselineExecutionRequest,
                        ExecutionAttempt, ExecutionEvent, ServiceDiscoveryConsent)
from app.worker_diagnostics import diagnostics
from test_automatic_service_start import automatic  # noqa: F401
from test_scheduling_start import prepared, get_review, confirm  # noqa: F401
from test_execution_orchestration import BorrowedFactory, FakeAdapter
from test_service_discovery import ServiceAdapter


@pytest.fixture
def queued(client, db, automatic):
    path, headers = automatic
    response = confirm(client, path, headers, get_review(client, path)['start_review'])
    assert response.status_code == 201, response.text
    host, service = db.scalars(select(BaselineExecutionRequest).order_by(BaselineExecutionRequest.profile_id)).all()
    return path, host, service


@pytest.mark.parametrize('failure,code', [
    ('version', 'service_scheduling_policy_version_unsupported'),
    ('preparation', 'start_service_reviewed_preparation_invalid'),
    ('missing_activity', 'start_service_activity_match_invalid'),
    ('duplicate_activity', 'start_service_activity_match_invalid'),
    ('authorization', 'start_service_authorization_binding_invalid'),
    ('plan', 'start_service_plan_binding_invalid'),
    ('ports', 'start_service_scope_ports_changed'),
])
def test_each_binding_failure_is_distinct_and_read_only(db, queued, monkeypatch, failure, code):
    _, _, request = queued
    original_consent = db.get(ServiceDiscoveryConsent, request.id)
    original_auth = db.get(AssessmentStartAuthorization, request.authorization_id)
    before = deepcopy((original_consent.snapshot, original_consent.digest, original_auth.snapshot))
    # Isolate one verifier gate using detached copies; never rewrite immutable DB history.
    saved = deepcopy(original_consent.snapshot)
    auth = SimpleNamespace(snapshot=deepcopy(original_auth.snapshot))
    reviewed = saved['reviewed_preparation']
    activities = auth.snapshot['eligible_activities']
    if failure == 'version': reviewed['scheduling_policy']['version'] = 999
    elif failure == 'preparation': reviewed['fingerprint'] = '0' * 64
    elif failure == 'missing_activity': activities[:] = [a for a in activities if a['profile_id'] != 'service-discovery']
    elif failure == 'duplicate_activity': activities.append(deepcopy(activities[-1]))
    elif failure == 'authorization': activities[-1]['scheduling_preparation']['fingerprint'] = '0' * 64
    elif failure == 'plan': saved['preparation']['plan']['arguments'].append('--script=unsafe')
    elif failure == 'ports': monkeypatch.setattr(policy, 'ports_for', lambda *args: [443])
    consent = SimpleNamespace(**{key: getattr(original_consent, key) for key in
        ('assessment_id', 'target_id', 'actor_id', 'created_at', 'expires_at')},
        snapshot=saved, digest=fingerprint(saved))

    class DetachedRead:
        def get(self, model, key):
            if model is ServiceDiscoveryConsent: return consent
            if model is AssessmentStartAuthorization: return auth
            return db.get(model, key)
        def scalar(self, query): return db.scalar(query)

    with pytest.raises(DispatchDenied, match='^' + code + '$'):
        verify(DetachedRead(), request)
    assert (original_consent.snapshot, original_consent.digest, original_auth.snapshot) == before
    assert request.status == 'Queued'
    assert db.scalar(select(func.count()).select_from(ExecutionAttempt)) == 0


def test_older_worker_rejects_v3_once_with_precise_persisted_history(client, db, queued, monkeypatch, tmp_path):
    path, _, request = queued
    consent = db.get(ServiceDiscoveryConsent, request.id)
    original = deepcopy((consent.snapshot, consent.digest))
    monkeypatch.setattr(policy, 'SUPPORTED_VERSIONS', (1, 2))
    tmp_path.chmod(0o700)
    adapter = ServiceAdapter()
    runner = ExecutionRunner(BorrowedFactory(db), adapter, EvidenceStore(tmp_path), 'fake-old-worker')
    assert not runner.run(request.id)
    assert request.status == 'Blocked' and adapter.calls == 0
    events = db.scalars(select(ExecutionEvent).where(ExecutionEvent.request_id == request.id)).all()
    assert len(events) == 1 and events[0].event_type == 'dispatch_blocked'
    assert events[0].reason_code == 'service_scheduling_policy_version_unsupported'
    assert [p['version'] for p in events[0].details['worker']['service_scheduling_policies']] == [1, 2]
    # Even after worker support returns, a blocked request must not be relaunched.
    monkeypatch.setattr(policy, 'SUPPORTED_VERSIONS', (1, 2, 3))
    assert not runner.run(request.id) and adapter.calls == 0
    assert db.scalar(select(func.count()).select_from(ExecutionEvent).where(ExecutionEvent.request_id == request.id)) == 1
    assert db.scalar(select(func.count()).select_from(ExecutionAttempt)) == 0
    assert (consent.snapshot, consent.digest) == original
    details = client.get(path + f'/testing/executions/{request.id}')
    assert details.status_code == 200
    value = details.json()
    assert value['status'] == 'Blocked' and value['execution_authorized'] is False
    assert value['dispatch_status'] == 'dispatch_blocked'
    assert value['dispatch_history']['reason_code'] == events[0].reason_code
    assert value['dispatch_history']['attempt_id'] is None
    assert value['evidence'] == value['observations'] == []
    assert client.get(path + '/testing/recommendations').json()['count'] == 0


@pytest.mark.parametrize('version', [1, 2, 3])
def test_historical_policy_dispatch_and_receipts_are_preserved(client, db, automatic, monkeypatch, tmp_path, version):
    path, headers = automatic
    if version == 1:
        assert client.post(path + '/scope', headers=headers,
            json={'revision': 1, 'value': '192.0.2.1', 'tcp_ports': [443]}).status_code == 201
    with monkeypatch.context() as release:
        release.setattr(policy, 'VERSION', version)
        review = get_review(client, path)['start_review']
        assert confirm(client, path, headers, review).status_code == 201
    host, request = db.scalars(select(BaselineExecutionRequest).order_by(BaselineExecutionRequest.profile_id)).all()
    consent = db.get(ServiceDiscoveryConsent, request.id)
    before = deepcopy((consent.snapshot, consent.digest))
    tmp_path.chmod(0o700)
    assert ExecutionRunner(BorrowedFactory(db), FakeAdapter(), EvidenceStore(tmp_path), 'fake-host').run(host.id)
    assert verify(db, request)['plan']['ports'] == review['eligible_activities'][1]['scheduling_preparation']['plan']['ports']
    assert (consent.snapshot, consent.digest) == before


def test_diagnostics_command_needs_neither_database_nor_executable(monkeypatch, capsys):
    from app import execution_worker
    def forbidden(*args, **kwargs): raise AssertionError('Diagnostic attempted operational access')
    monkeypatch.setattr(execution_worker, 'get_settings', forbidden)
    monkeypatch.setattr(execution_worker, 'create_engine', forbidden)
    monkeypatch.setattr(execution_worker, 'resolve_adapter', forbidden)
    execution_worker.main(['--diagnostics'])
    value = json.loads(capsys.readouterr().out)
    assert value == diagnostics()
    assert [p['version'] for p in value['service_scheduling_policies']] == [1, 2, 3]
    assert set(value) == {'schema_version', 'worker_version', 'service_scheduling_current_version',
                          'service_scheduling_policies', 'dispatch_policies', 'policy_diagnostics_available'}


def test_unavailable_policy_diagnostics_cannot_suppress_denial_audit(db, queued, monkeypatch, tmp_path):
    import app.worker_diagnostics as metadata
    _, _, request = queued
    def unavailable(): raise ValueError('must-not-expose-internal-input')
    monkeypatch.setattr(metadata, 'service_authority', unavailable)
    monkeypatch.setattr(policy, 'SUPPORTED_VERSIONS', (1, 2))
    tmp_path.chmod(0o700)
    adapter = ServiceAdapter()
    assert not ExecutionRunner(BorrowedFactory(db), adapter, EvidenceStore(tmp_path), 'fake-worker').run(request.id)
    event = db.scalar(select(ExecutionEvent).where(ExecutionEvent.request_id == request.id))
    assert request.status == 'Blocked' and event.reason_code == 'service_scheduling_policy_version_unsupported'
    assert event.details['worker']['policy_diagnostics_available'] is False
    assert 'must-not-expose' not in json.dumps(event.details)
    assert adapter.calls == 0


def test_dispatch_projection_distinguishes_execution_state_from_launch_history():
    from app.testing_read_summary import dispatch_history
    assert dispatch_history([]) == {'dispatch_status': 'not_recorded', 'dispatch_history': None}
    def event(i, kind): return dict(id=str(i), event=kind, occurred_at=f'2026-11-21T01:00:0{i}+00:00',
                                   reason_code='recorded', attempt_id='a')
    claimed, started, finished = event(1, 'execution_claimed'), event(2, 'scanner_started'), event(3, 'execution_finished')
    assert dispatch_history([finished, claimed, started]) == {'dispatch_status': 'scanner_started', 'dispatch_history': started}
    # A later instant can have an earlier wall-clock label in another UTC offset.
    earlier = {**claimed, 'occurred_at': '2026-11-21T02:00:00+01:00'}
    later = {**started, 'occurred_at': '2026-11-21T01:30:00+00:00'}
    assert dispatch_history([later, earlier])['dispatch_history'] == later
