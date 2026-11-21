"""Automatic baseline → fake scanner → persisted evidence → real planner.

No analyst port input, external evidence provisioning or planner mocks.
"""
from copy import deepcopy
from uuid import UUID, uuid4
import pytest
from sqlalchemy import func, select
from app.baseline_catalog import fingerprint
from app.baseline_maintenance import record_tool_state
from app.baseline_resolution import reconcile
from app.dispatch_verification import verify
from app.execution_orchestration import ExecutionRunner
from app.execution_results import EvidenceStore
from app.models import (Assessment, AssessmentStartAuthorization, BaselineExecutionRequest,
                        ScopeEntry, ServiceDiscoveryConsent, SecurityObservation)
from app import service_start_preparation as service_policy
from test_scheduling_start import prepared, get_review, confirm, scheduling_concurrency  # noqa: F401
from test_execution_orchestration import BorrowedFactory, FakeAdapter
from test_service_discovery import ServiceAdapter, xml


def enable_services(db, path):
    record_tool_state(db, 'Nmap', 'enabled', ['ipv4-discovery', 'tcp-service-discovery'])
    reconcile(db, db.get(Assessment, UUID(path.rsplit('/', 1)[1])), 'tool_state_changed')
    db.commit()


@pytest.fixture
def automatic(db, prepared):
    path, headers, _ = prepared
    enable_services(db, path)
    # Subnet scope is enough; there is no explicit TCP-port provisioning.
    assert all(not entry.tcp_ports for entry in db.scalars(select(ScopeEntry)))
    return path, headers


def test_normal_start_prepares_fixed_ports_and_replay_without_port_input(client, db, automatic):
    path, headers = automatic
    first = get_review(client, path)
    second = get_review(client, path)
    review = first['start_review']
    assert review['snapshot_digest'] == second['start_review']['snapshot_digest']
    assert review['confirmation_possible'] and review['mode'] == 'full'
    assert len(review['eligible_activities']) == 2 and review['excluded_activities'] == []
    service = review['eligible_activities'][1]['scheduling_preparation']
    assert service['scheduling_policy']['version'] == 3
    assert service['scheduling_policy']['baseline_tcp_ports'] == [80, 443, 3000, 5000, 8000, 8080, 8443, 8888]
    assert service['plan']['ports'] == [80, 443, 3000, 5000, 8000, 8080, 8443, 8888]
    assert service['plan']['arguments'][-2:] == ['-p', '80,443,3000,5000,8000,8080,8443,8888']
    assert first['execution_authorized'] is False
    assert db.scalar(select(func.count()).select_from(ServiceDiscoveryConsent)) == 0
    key = str(uuid4())
    result = confirm(client, path, headers, review, key)
    assert result.status_code == 201, result.text
    assert result.json()['queued_execution_count'] == 2
    assert result.json()['lifecycle_status'] == 'Testing'
    assert result.json()['execution_authorized'] is False
    assert confirm(client, path, headers, review, key).json() == result.json()
    assert confirm(client, path, headers, review).status_code == 409
    assert client.get(path + '/testing').json()['counts']['queued'] == 2
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest)) == 2
    assert db.scalar(select(func.count()).select_from(ServiceDiscoveryConsent)) == 1
    assert all(not entry.tcp_ports for entry in db.scalars(select(ScopeEntry)))


def test_normal_start_real_evidence_and_reviewed_recommendations(client, db, automatic, tmp_path):
    path, headers = automatic
    receipt = confirm(client, path, headers, get_review(client, path)['start_review'])
    assert receipt.status_code == 201, receipt.text
    host, service = db.scalars(select(BaselineExecutionRequest).order_by(BaselineExecutionRequest.profile_id)).all()
    tmp_path.chmod(0o700)
    store = EvidenceStore(tmp_path)
    runner = ExecutionRunner(BorrowedFactory(db), FakeAdapter(), store, 'fake-host')
    assert runner.run(host.id) and host.status == 'Completed'
    assert client.get(path + '/testing/recommendations').json()['count'] == 0
    adapter = ServiceAdapter()
    service_runner = ExecutionRunner(BorrowedFactory(db), adapter, store, 'fake-service')
    assert service_runner.run(service.id) and service.status == 'Completed'
    assert not service_runner.run(service.id) and adapter.calls == 1
    response = client.get(path + '/testing/recommendations').json()
    assert response['count'] == 2 and response['decision_counts']['pending_review'] == 2
    recs = response['recommendations']
    for rec in recs:
        assert rec['suggested_tool'] == 'Nikto' and not rec['execution_available']
        assert rec['source_evidence_id'] and rec['source_observation_id']
        assert rec['source_test'] == {'test_name': 'Service Discovery', 'tool': 'Nmap',
                                      'status': 'Completed', 'execution_id': str(service.id)}
        assert not client.get(path + f"/testing/recommendations/{rec['id']}/eligibility").json()['eligible']
        review = client.get(path + f"/testing/recommendations/{rec['id']}/authorization-review").json()
        assert not review['authorization_available'] and not review['execution_available']
    observations = db.scalars(select(SecurityObservation)).all()
    assert not any(o.observation_type == 'web_application' for o in observations)
    assert client.post(path + '/testing/completion/decisions', headers=headers,
        json={'recommendation_id': recs[0]['id'], 'decision': 'Reviewed', 'review_outcome': 'Accepted'}).status_code == 200
    after = client.get(path + '/testing/recommendations').json()
    saved = next(r for r in after['recommendations'] if r['id'] == recs[0]['id'])
    assert saved['decision'] == 'Reviewed' and saved['review_outcome'] == 'Accepted'
    assert not saved['execution_available']
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest)) == 2


def test_completed_service_without_http_evidence_never_invents_recommendations(client, db, automatic, tmp_path):
    path, headers = automatic
    assert confirm(client, path, headers, get_review(client, path)['start_review']).status_code == 201
    host, service = db.scalars(select(BaselineExecutionRequest).order_by(BaselineExecutionRequest.profile_id)).all()
    tmp_path.chmod(0o700)
    store = EvidenceStore(tmp_path)
    assert ExecutionRunner(BorrowedFactory(db), FakeAdapter(), store, 'fake-host').run(host.id)
    class NoHttp(ServiceAdapter):
        def run(self, candidate, **kwargs):
            from dataclasses import replace
            outcome = super().run(candidate, **kwargs)
            return replace(outcome, stdout=xml([(80, 'closed', 'http', 'table', None),
                                               (443, 'filtered', 'http', 'table', None)]))
    assert ExecutionRunner(BorrowedFactory(db), NoHttp(), store, 'fake-no-http').run(service.id)
    assert service.status == 'Completed'
    assert client.get(path + '/testing/recommendations').json()['recommendations'] == []


def test_fixed_policy_rejects_other_ports_even_with_recomputed_fingerprint(client, automatic):
    path, _ = automatic
    value = get_review(client, path)['start_review']['eligible_activities'][1]['scheduling_preparation']
    for ports in ([22], [80, 443, 8081], [8081], [443, 443]):
        with pytest.raises(ValueError):
            service_policy.prepare(value['host_preparation'], ports)
    bad = deepcopy(value)
    from app.nmap_service_profile import plan
    bad['authorized_tcp_ports'] = [22]
    bad['plan'] = plan(bad['target_value'], [22])
    bad['parameter_digest'] = bad['plan']['parameter_digest']
    bad['fingerprint'] = fingerprint({k: v for k, v in bad.items() if k != 'fingerprint'})
    assert not service_policy.validate(bad)
    bad = deepcopy(value)
    bad['scheduling_policy']['version'] = 999
    assert not service_policy.validate(bad)


@pytest.mark.parametrize('ports,expected', [([443], [443]), ([80], [80]), ([22], [])])
def test_existing_narrow_scope_is_not_broadened(client, db, automatic, ports, expected):
    path, headers = automatic
    revision = client.get(path + '/scope').json()['revision']
    assert client.post(path + '/scope', headers=headers,
        json={'revision': revision, 'value': '192.0.2.1', 'tcp_ports': ports}).status_code == 201
    review = get_review(client, path)['start_review']
    services = [a for a in review['eligible_activities'] if a['profile_id'] == 'service-discovery']
    if expected:
        assert services[0]['scheduling_preparation']['plan']['ports'] == expected
    else:
        assert services == [] and review['mode'] == 'partial'
        assert review['excluded_activities'][0]['profile_id'] == 'service-discovery'


def test_existing_testing_assessment_is_not_retroactively_scheduled(client, db, prepared):
    path, headers, _ = prepared
    assert confirm(client, path, headers, get_review(client, path)['start_review']).status_code == 201
    enable_services(db, path)
    for _ in range(2):
        assert client.get(path + '/testing').json()['counts']['total'] == 1
        assert not get_review(client, path)['start_review']['confirmation_possible']
    assert db.scalar(select(func.count()).select_from(ServiceDiscoveryConsent)) == 0
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest)) == 1


def test_legacy_v1_start_consent_and_receipt_remain_valid(client, db, automatic, monkeypatch, tmp_path):
    path, headers = automatic
    assert client.post(path + '/scope', headers=headers,
        json={'revision': 1, 'value': '192.0.2.1', 'tcp_ports': [443]}).status_code == 201
    # Emulate the old release, not a client-selectable policy version.
    with monkeypatch.context() as old_release:
        old_release.setattr(service_policy, 'VERSION', 1)
        review = get_review(client, path)['start_review']
        assert review['eligible_activities'][1]['scheduling_preparation']['scheduling_policy']['version'] == 1
        key = str(uuid4())
        result = confirm(client, path, headers, review, key)
        assert result.status_code == 201, result.text
    auth = db.scalar(select(AssessmentStartAuthorization))
    consent = db.scalar(select(ServiceDiscoveryConsent))
    before = deepcopy((auth.snapshot, auth.snapshot_digest, consent.snapshot, consent.digest))
    assert confirm(client, path, headers, review, key).json() == result.json()
    host, service = db.scalars(select(BaselineExecutionRequest).order_by(BaselineExecutionRequest.profile_id)).all()
    tmp_path.chmod(0o700)
    assert ExecutionRunner(BorrowedFactory(db), FakeAdapter(), EvidenceStore(tmp_path), 'fake-host').run(host.id)
    assert verify(db, service)['plan']['ports'] == [443]
    assert (auth.snapshot, auth.snapshot_digest, consent.snapshot, consent.digest) == before


def test_v1_policy_definition_and_digest_are_preserved():
    from app.nmap_service_profile import authority
    old = {'id': 'uptip-scoped-service-scheduling', 'version': 1, 'purpose': 'schedule_only',
           'dispatch_policy_digest': authority()['digest'], 'scope': 'exact-ipv4-explicit-tcp-ports',
           'max_ports': 16, 'required_capability': 'tcp-service-discovery',
           'dependencies': ['network-discovery']}
    assert service_policy.policy(1) == {**old, 'digest': fingerprint(old)}
    assert service_policy.policy(2)['digest'] != service_policy.policy(1)['digest']
    assert service_policy.policy(3)['digest'] != service_policy.policy(2)['digest']


def test_old_review_is_stale_after_policy_version_change(client, db, automatic, monkeypatch):
    path, headers = automatic
    assert client.post(path + '/scope', headers=headers,
        json={'revision': 1, 'value': '192.0.2.1', 'tcp_ports': [80, 443]}).status_code == 201
    with monkeypatch.context() as old:
        old.setattr(service_policy, 'VERSION', 1)
        review = get_review(client, path)['start_review']
    assert confirm(client, path, headers, review).status_code == 409
    assert db.scalar(select(func.count()).select_from(AssessmentStartAuthorization)) == 0
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest)) == 0


@pytest.mark.parametrize('scheduling_concurrency', ['empty'], indirect=True)
def test_automatic_start_with_application_role_without_worker_privileges(scheduling_concurrency, monkeypatch):
    """Owner-backed fixtures must not conceal production-role permission errors."""
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker
    from app.database import get_db
    app, factory, _, _, _ = scheduling_concurrency
    with factory() as db, TestClient(app, base_url='https://testserver') as owner_client:
        owner_client.headers['Origin'] = 'https://testserver'
        path, headers, _ = prepared.__wrapped__(owner_client, db, monkeypatch)
        enable_services(db, path)
        cookies = dict(owner_client.cookies)
    with factory.begin() as db:
        # Dedicated disposable DB only; emulate core web-app privileges without
        # worker role membership, execution-event INSERT or worker lock EXECUTE.
        db.execute(text('GRANT USAGE ON SCHEMA public TO uptip_runtime'))
        db.execute(text('''GRANT SELECT ON users, auth_sessions, assessments, assessment_assignments,
            scope_entries, assessment_targets, baseline_tool_states, baseline_assignments,
            baseline_evaluations, assessment_start_authorizations, assessment_start_events,
            baseline_execution_requests, service_discovery_consents, service_discovery_revocations
            TO uptip_runtime'''))
        db.execute(text('GRANT UPDATE(status) ON users TO uptip_runtime'))
        db.execute(text('GRANT UPDATE(expires_at) ON auth_sessions TO uptip_runtime'))
        db.execute(text('GRANT UPDATE(status,updated_at) ON assessments TO uptip_runtime'))
        db.execute(text('''GRANT INSERT ON assessment_start_authorizations, assessment_start_events,
                           baseline_execution_requests TO uptip_runtime'''))
    engine = create_engine(factory.kw['bind'].url.set(username='uptip_runtime'), hide_parameters=True)
    runtime = sessionmaker(engine, expire_on_commit=False)
    original = app.dependency_overrides[get_db]
    def runtime_db():
        with runtime() as db:
            yield db
    app.dependency_overrides[get_db] = runtime_db
    try:
        with runtime() as db:
            assert not db.scalar(text("SELECT has_function_privilege(current_user,'public.lock_execution_dispatch_sources(uuid)','EXECUTE')"))
            assert not db.scalar(text("SELECT has_table_privilege(current_user,'execution_events','INSERT')"))
        with TestClient(app, base_url='https://testserver', cookies=cookies) as client:
            client.headers['Origin'] = 'https://testserver'
            review = get_review(client, path)['start_review']
            response = confirm(client, path, headers, review)
            assert response.status_code == 201, response.text
            assert response.json()['queued_execution_count'] == 2
            assert client.get(path + '/testing').json()['counts']['queued'] == 2
        with factory() as db:
            from app.models import AssessmentStartEvent, ExecutionEvent
            assert db.scalar(select(func.count()).select_from(AssessmentStartEvent)) == 1
            assert db.scalar(select(func.count()).select_from(ServiceDiscoveryConsent)) == 1
            assert db.scalar(select(func.count()).select_from(ExecutionEvent)) == 0
    finally:
        app.dependency_overrides[get_db] = original
        engine.dispose()


def test_v2_receipt_definition_preserved_and_v3_expands_only_new_starts():
    from app.nmap_service_profile import plan
    v2 = service_policy.policy(2)
    old = {'id': 'uptip-scoped-service-scheduling', 'version': 2, 'purpose': 'schedule_only',
           'dispatch_policy_digest': service_policy.authority()['digest'],
           'scope': 'authorized-ipv4-fixed-web-ports', 'max_ports': 2,
           'required_capability': 'tcp-service-discovery',
           'dependencies': ['network-discovery'], 'baseline_tcp_ports': [80, 443]}
    assert v2 == {**old, 'digest': fingerprint(old)}
    assert service_policy.policy(3)['max_ports'] == 8
    assert plan('192.0.2.1', list(service_policy.BASELINE_PORTS))['ports'] == list(service_policy.BASELINE_PORTS)
    with pytest.raises(ValueError):
        service_policy.prepare({'target_value': '192.0.2.1'}, [8080], version=2)


def test_http_on_nonstandard_port_is_normalized_and_recommended():
    from types import SimpleNamespace
    from app.execution_results import parse_services
    from app.recommendation_planner import plan_recommendations
    fact, = parse_services(xml([(8080, 'open', 'http', 'probed', None)]), '192.0.2.1', [8080])
    assert fact['port'] == 8080 and fact['service'] == 'http'
    source = SimpleNamespace(id=uuid4(), target_id=uuid4(), evidence_id=uuid4(),
                             observation_type='service_discovery', data=fact, is_partial=False)
    recommendations = plan_recommendations([source])
    assert len(recommendations) == 1
    assert recommendations[0]['suggested_tool'] == 'Nikto'
    assert recommendations[0]['port'] == 8080
    assert not recommendations[0]['execution_available']
