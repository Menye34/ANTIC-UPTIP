"""Synthetic adapters only. All database work uses the guarded pytest database."""
from contextlib import nullcontext
from datetime import timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy import select, text

from app.dispatch_policy import plan, validate_plan
from app.dispatch_verification import verify, DispatchDenied
from app.execution_orchestration import claim, recover_expired, ExecutionRunner, now
from app.execution_results import parse_discovery, EvidenceStore
from app.models import BaselineExecutionRequest, ExecutionAttempt, ExecutionEvent, User
from app.nmap_adapter import ScanOutcome, AdapterConfig, AdapterUnavailable
from test_scheduling_start import prepared, get_review, confirm  # noqa: F401
from test_scheduling_start import scheduling_concurrency  # noqa: F401


def xml(target='192.0.2.1'):
    return (f'<nmaprun scanner="nmap"><host><status state="up"/>'
            f'<address addr="{target}" addrtype="ipv4"/></host><runstats>'
            '<finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>').encode()


@pytest.fixture
def request_row(client, db, prepared):
    path, headers, _ = prepared
    result = confirm(client, path, headers, get_review(client, path)['start_review'])
    assert result.status_code == 201, result.text
    return db.get(BaselineExecutionRequest, UUID(result.json()['queued_execution_ids'][0]))


class BorrowedFactory:
    """Exercise transactions through the test's outer rollback boundary."""
    def __init__(self, db):
        self.db = db

    def __call__(self):
        return nullcontext(self.db)

    def begin(self):
        return self.db.begin_nested_context() if hasattr(self.db, 'begin_nested_context') else self._transaction()

    def _transaction(self):
        from contextlib import contextmanager
        @contextmanager
        def transaction():
            with self.db.begin_nested():
                yield self.db
        return transaction()


class FakeAdapter:
    config = SimpleNamespace(timeout=30, sha256='a'*64, version='7.95')
    calls = 0

    def verify(self):
        pass

    def run(self, candidate, *, safe, launched, launch_guard):
        assert validate_plan(candidate)
        with launch_guard():
            assert safe()
            launched('synthetic-boot:123:456')
        assert safe()
        self.calls += 1
        return ScanOutcome(xml(candidate['target']), b'', 0, 'scanner_exited', True, False)


def test_v2_claim_is_independent_authority_and_duplicate_safe(db, request_row):
    assert request_row.profile_version == 2
    decision = verify(db, request_row)
    assert decision['dispatch_policy']['purpose'] == 'dispatch'
    assert request_row.authorized_activity['scheduling_preparation']['purpose'] == 'schedule_only'
    factory = BorrowedFactory(db)
    result = claim(factory, request_row.id, 'synthetic', 30)
    assert result is not None
    assert claim(factory, request_row.id, 'other', 30) is None
    attempt = db.get(ExecutionAttempt, result[0])
    with pytest.raises(DispatchDenied, match='ownership'):
        verify(db, request_row, attempt=attempt, worker_id='other', claim_id=result[1])


def test_creator_revocation_blocks_dispatch(db, request_row):
    from app.models import Assessment
    owner = db.get(User, db.get(Assessment, request_row.assessment_id).creator_id)
    owner.status = 'disabled'
    db.flush()
    with pytest.raises(DispatchDenied, match='creator_permission'):
        verify(db, request_row)
    assert claim(BorrowedFactory(db), request_row.id, 'synthetic', 30) is None
    assert request_row.status == 'Blocked'


def test_expiry_enters_recovery_without_relaunch(db, request_row):
    factory = BorrowedFactory(db)
    aid, _, _ = claim(factory, request_row.id, 'synthetic', 30)
    attempt = db.get(ExecutionAttempt, aid)
    # Advance clock rather than illegally rewinding persisted lease timestamps.
    import app.execution_orchestration as orchestration
    future = now()+timedelta(minutes=2)
    from unittest.mock import patch
    with patch.object(orchestration, 'now', return_value=future):
        assert recover_expired(factory) == 1
    assert attempt.status == 'RecoveryRequired'
    assert claim(factory, request_row.id, 'replacement', 30) is None


def test_fake_end_to_end_evidence_completion_and_api(client, db, request_row, tmp_path):
    tmp_path.chmod(0o700)
    adapter = FakeAdapter()
    runner = ExecutionRunner(BorrowedFactory(db), adapter, EvidenceStore(tmp_path), 'synthetic')
    assert runner.run(request_row.id)
    assert request_row.status == 'Completed'
    assert runner.run(request_row.id) is False
    assert adapter.calls == 1
    response = client.get(f'/api/v1/assessments/{request_row.assessment_id}/testing/executions/{request_row.id}')
    assert response.status_code == 200
    body = response.json()
    assert body['status'] == 'Completed' and body['execution_authorized'] is False
    assert body['attempts'][0]['status'] == 'Succeeded'
    assert body['processing'][0]['status'] == 'Succeeded'
    assert body['observations'][0]['data'] == {'address':'192.0.2.1', 'status':'up'}
    assert 'content' not in str(body['evidence'])
    overview = client.get(f'/api/v1/assessments/{request_row.assessment_id}/testing').json()
    assert overview['counts']['completed'] == 1 and overview['counts']['queued'] == 0
    assert overview['discovered_so_far'][0]['data']['address'] == '192.0.2.1'


@pytest.mark.parametrize('value', ['example.test', '192.0.2.0/24', '::1', ' 192.0.2.1', '-iL'])
def test_plan_rejects_expansion(value):
    with pytest.raises(ValueError):
        plan(value)


@pytest.mark.parametrize('content', [b'', b'<!DOCTYPE nmaprun><nmaprun/>', b'<nmaprun>',
    b'<nmaprun scanner="nmap"><ports/></nmaprun>', xml('192.0.2.2'),
    b'\x00'+xml(), xml().replace(b'exit="success"', b'exit="error"')])
def test_parser_fails_closed(content):
    with pytest.raises(ValueError):
        parse_discovery(content, '192.0.2.1')


def test_exact_v2_plan_and_parser():
    assert plan('192.0.2.1')['arguments'] == ['-sn', '-n', '-oX', '-']
    assert parse_discovery(xml(), '192.0.2.1')['status'] == 'up'
    modified = {**plan('192.0.2.1'), 'arguments': ['-sV']}
    assert not validate_plan(modified)


@pytest.mark.parametrize('change', [{'timeout': 601}, {'output_limit': 10485761},
    {'safety_interval': 6}, {'sha256': 'invalid'}, {'version': 'unverified'}])
def test_adapter_limits_fail_closed(change):
    with pytest.raises(AdapterUnavailable):
        AdapterConfig(**({'executable':'/usr/bin/nmap', 'sha256':'a'*64, 'version':'7.95'} | change))


@pytest.mark.parametrize('changed', ['scope', 'target', 'tool', 'baseline', 'parameters'])
def test_changed_dispatch_facts_fail_closed(db, request_row, changed):
    from app.models import Assessment, AssessmentTarget, BaselineToolState, BaselineAssignment
    from copy import deepcopy
    if changed == 'scope':
        db.get(Assessment, request_row.assessment_id).scope_revision += 1
    elif changed == 'target':
        db.get(AssessmentTarget, request_row.target_id).revision += 1
    elif changed == 'tool':
        db.get(BaselineToolState, 'Nmap').revision += 1
    elif changed == 'baseline':
        db.delete(db.get(BaselineAssignment, (request_row.target_id, 'network-discovery')))
    else:
        # Detached synthetic corruption; do not weaken immutable database input.
        db.expunge(request_row)
        request_row.authorized_activity = deepcopy(request_row.authorized_activity)
        request_row.authorized_activity['scheduling_preparation']['plan']['arguments'] = ['-sV']
    db.flush()
    with pytest.raises(DispatchDenied):
        verify(db, request_row)


def test_unconfirmed_termination_preserves_recovery_and_evidence(db, request_row, tmp_path):
    class Uncertain(FakeAdapter):
        def run(self, candidate, *, safe, launched, launch_guard):
            with launch_guard():
                assert safe()
                launched('synthetic:123:456')
            return ScanOutcome(b'<partial', b'synthetic error', None, 'termination_unverified', False, True)
    tmp_path.chmod(0o700)
    assert not ExecutionRunner(BorrowedFactory(db), Uncertain(), EvidenceStore(tmp_path), 'synthetic').run(request_row.id)
    attempt = db.scalar(select(ExecutionAttempt))
    assert attempt.status == 'RecoveryRequired' and attempt.terminated_at is None
    assert request_row.status != 'Completed'
    assert claim(BorrowedFactory(db), request_row.id, 'restart', 30) is None


@pytest.mark.parametrize('scheduling_concurrency', ['empty'], indirect=True)
def test_concurrent_workers_claim_once(scheduling_concurrency, monkeypatch):
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from fastapi.testclient import TestClient
    app, factory, _, _, _ = scheduling_concurrency
    config = Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    config.set_main_option('script_location', str(Path(__file__).resolve().parents[1]/'migrations'))
    command.upgrade(config, '0019')
    with factory() as db, TestClient(app, base_url='https://testserver') as client:
        client.headers['Origin'] = 'https://testserver'
        path, headers, _ = prepared.__wrapped__(client, db, monkeypatch)
        result = confirm(client, path, headers, get_review(client, path)['start_review'])
        assert result.status_code == 201
        identifier = UUID(result.json()['queued_execution_ids'][0])
        db.rollback()
    barrier = Barrier(2)
    def send(worker):
        barrier.wait(timeout=10)
        return claim(factory, identifier, worker, 30)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(send, ['synthetic-a', 'synthetic-b']))
    assert sum(result is not None for result in results) == 1
    with factory() as db:
        assert len(db.scalars(select(ExecutionAttempt)).all()) == 1


def test_v1_contract_is_not_reinterpreted(db, request_row):
    # Detached v1 request: denial occurs before consulting scheduling preparation.
    db.expunge(request_row)
    request_row.profile_version = 1
    with pytest.raises(DispatchDenied, match='v1_output_contract'):
        verify(db, request_row)


def test_least_privilege_worker_can_finish_without_authentication_secrets(db, request_row, tmp_path):
    db.execute(text('CREATE ROLE uptip_phase2_test_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS'))
    db.execute(text('GRANT uptip_phase2_test_worker TO uptip WITH SET TRUE, INHERIT FALSE'))
    db.execute(text('GRANT USAGE ON SCHEMA public TO uptip_phase2_test_worker'))
    db.execute(text('GRANT SELECT(id,status,role,password_change_required) ON users TO uptip_phase2_test_worker'))
    db.execute(text('GRANT SELECT ON assessments, assessment_targets, scope_entries, assessment_start_authorizations, baseline_assignments, baseline_evaluations, baseline_tool_states, baseline_execution_requests TO uptip_phase2_test_worker'))
    db.execute(text('GRANT SELECT,INSERT ON execution_attempts,scanner_evidence,result_processing_outcomes,security_observations,execution_events TO uptip_phase2_test_worker'))
    db.execute(text('GRANT UPDATE ON execution_attempts,result_processing_outcomes TO uptip_phase2_test_worker'))
    db.execute(text('GRANT UPDATE(status,updated_at) ON baseline_execution_requests TO uptip_phase2_test_worker'))
    db.execute(text('GRANT EXECUTE ON FUNCTION public.lock_execution_dispatch_sources(uuid) TO uptip_phase2_test_worker'))
    db.execute(text('SET LOCAL ROLE uptip_phase2_test_worker'))
    assert not db.scalar(text("SELECT has_column_privilege(current_user,'users','password_hash','SELECT')"))
    assert not db.scalar(text("SELECT has_table_privilege(current_user,'execution_attempts','TRUNCATE')"))
    tmp_path.chmod(0o700)
    assert ExecutionRunner(BorrowedFactory(db), FakeAdapter(), EvidenceStore(tmp_path), 'synthetic').run(request_row.id)


def test_process_identity_cannot_be_rewritten(db, request_row):
    from sqlalchemy.exc import DBAPIError
    aid, _, _ = claim(BorrowedFactory(db), request_row.id, 'synthetic', 30)
    a = db.get(ExecutionAttempt, aid)
    a.process_reference = 'synthetic-boot:123:456'
    db.flush()
    with pytest.raises(DBAPIError, match='identity is immutable'):
        with db.begin_nested():
            a.process_reference = 'different:123:456'
            db.flush()


@pytest.mark.parametrize('scheduling_concurrency', ['empty'], indirect=True)
@pytest.mark.parametrize('insert', [False, True])
def test_dispatch_locks_tool_updates_and_insertions(scheduling_concurrency, monkeypatch, insert):
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from concurrent.futures import ThreadPoolExecutor, TimeoutError
    from threading import Event
    from fastapi.testclient import TestClient
    from app.execution_orchestration import locked
    from app.models import BaselineToolState
    app, factory, _, _, _ = scheduling_concurrency
    config = Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    config.set_main_option('script_location', str(Path(__file__).resolve().parents[1]/'migrations'))
    command.upgrade(config, '0019')
    with factory() as db, TestClient(app, base_url='https://testserver') as client:
        client.headers['Origin'] = 'https://testserver'
        path, headers, _ = prepared.__wrapped__(client, db, monkeypatch)
        result = confirm(client, path, headers, get_review(client, path)['start_review'])
        identifier = UUID(result.json()['queued_execution_ids'][0])
        db.rollback()
    entered = Event()
    def change_tool():
        with factory.begin() as db:
            entered.set()
            if insert:
                db.add(BaselineToolState(tool='synthetic-new-tool', state='unknown', capabilities=[], revision=1))
            else:
                db.execute(text("UPDATE baseline_tool_states SET state='disabled',revision=revision+1 WHERE tool='Nmap'"))
    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory.begin() as db:
            request = locked(db, identifier)
            verify(db, request)
            future = pool.submit(change_tool)
            assert entered.wait(timeout=5)
            with pytest.raises(TimeoutError):
                future.result(timeout=.2)
        future.result(timeout=5)
    if not insert:
        with factory.begin() as db:
            with pytest.raises(DispatchDenied, match='tool_unavailable'):
                verify(db, locked(db, identifier))


@pytest.mark.parametrize('scheduling_concurrency', ['empty'], indirect=True)
def test_worker_migration_roundtrip_and_public_denial(scheduling_concurrency):
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    app, factory, _, _, _ = scheduling_concurrency
    config = Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    config.set_main_option('script_location', str(Path(__file__).resolve().parents[1]/'migrations'))
    command.upgrade(config, '0019')
    with factory() as db:
        assert db.scalar(text("SELECT has_function_privilege('uptip_runtime','public.lock_execution_dispatch_sources(uuid)','EXECUTE')")) is False
        assert db.scalar(text("SELECT has_table_privilege('uptip_runtime','execution_events','TRUNCATE')")) is False
    command.downgrade(config, '0018')
    command.upgrade(config, '0019')
    with factory() as db:
        assert db.scalar(text('SELECT version_num FROM alembic_version')) == '0019'


def test_extended_testing_history_remains_assessment_isolated(client, db, request_row):
    from test_assessments import add_analyst, sign_in
    outsider = add_analyst(db, 'synthetic-outsider')
    sign_in(client, outsider.username)
    path = f'/api/v1/assessments/{request_row.assessment_id}/testing'
    for suffix in ('', '/executions', f'/executions/{request_row.id}'):
        assert client.get(path+suffix).status_code == 404


def test_modified_dispatch_authority_fails_closed(db, request_row, monkeypatch):
    from app.dispatch_policy import POLICY
    monkeypatch.setitem(POLICY, 'approval_source', 'unverified')
    with pytest.raises((DispatchDenied, ValueError)):
        verify(db, request_row)


def test_scanner_success_is_not_processing_success(db, request_row, tmp_path):
    class Malformed(FakeAdapter):
        def run(self, candidate, *, safe, launched, launch_guard):
            with launch_guard():
                assert safe()
                launched('synthetic:123:456')
            return ScanOutcome(b'<malformed', b'', 0, 'scanner_exited', True, False)
    tmp_path.chmod(0o700)
    assert ExecutionRunner(BorrowedFactory(db), Malformed(), EvidenceStore(tmp_path), 'synthetic').run(request_row.id)
    assert request_row.status == 'Failed'
    assert db.scalar(select(ExecutionAttempt.status)) == 'Succeeded'
    from app.models import ResultProcessingOutcome, ScannerEvidence
    assert db.scalar(select(ResultProcessingOutcome.status)) == 'Failed'
    assert db.scalar(select(ScannerEvidence.content).where(ScannerEvidence.format == 'nmap-xml')) == b'<malformed'


def test_claim_event_failure_rolls_back_claim(db, request_row):
    from sqlalchemy import event as orm_event
    def fail(mapper, connection, value):
        if value.event_type == 'execution_claimed':
            raise RuntimeError('synthetic-event-failure')
    orm_event.listen(ExecutionEvent, 'before_insert', fail)
    try:
        with pytest.raises(RuntimeError, match='synthetic-event'):
            claim(BorrowedFactory(db), request_row.id, 'synthetic', 30)
    finally:
        orm_event.remove(ExecutionEvent, 'before_insert', fail)
    assert db.scalar(select(ExecutionAttempt.id)) is None
    assert db.get(BaselineExecutionRequest, request_row.id).status == 'Queued'


@pytest.mark.parametrize('scheduling_concurrency', ['migration_0019_empty'], indirect=True)
def test_migration_refuses_removing_recorded_process_protection(scheduling_concurrency, monkeypatch):
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from sqlalchemy.exc import DBAPIError
    from fastapi.testclient import TestClient
    app, factory, _, _, _ = scheduling_concurrency
    config = Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    config.set_main_option('script_location', str(Path(__file__).resolve().parents[1]/'migrations'))
    command.upgrade(config, 'head')
    with factory() as db, TestClient(app, base_url='https://testserver') as client:
        client.headers['Origin'] = 'https://testserver'
        path, headers, _ = prepared.__wrapped__(client, db, monkeypatch)
        receipt = confirm(client, path, headers, get_review(client, path)['start_review'])
        identifier = UUID(receipt.json()['queued_execution_ids'][0])
        db.rollback()
    aid, _, _ = claim(factory, identifier, 'synthetic', 30)
    with factory.begin() as db:
        db.get(ExecutionAttempt, aid).process_reference = 'synthetic:123:456'
    with pytest.raises(DBAPIError, match='recorded history'):
        command.downgrade(config, '0018')
    with factory() as db:
        assert db.scalar(text('SELECT version_num FROM alembic_version')) == '0025'
        assert db.get(ExecutionAttempt, aid).process_reference == 'synthetic:123:456'


def test_testing_overview_uses_persisted_execution_events(client, db, request_row, tmp_path):
    """T-01 activity must reflect committed worker events, not a fabricated queue-only timeline."""
    tmp_path.chmod(0o700)
    runner = ExecutionRunner(BorrowedFactory(db), FakeAdapter(), EvidenceStore(tmp_path), 'synthetic')
    assert runner.run(request_row.id)
    url = f'/api/v1/assessments/{request_row.assessment_id}/testing'
    response = client.get(url)
    assert response.status_code == 200
    activity = response.json()['recent_activity']
    assert activity
    assert activity[0]['event'] == 'execution_finished'
    assert any(item['event'] == 'scanner_started' for item in activity)
    assert all(item['execution_id'] == str(request_row.id) for item in activity)
    assert all(set(item) == {'event', 'execution_id', 'occurred_at'} for item in activity)
    assert all('process_reference' not in str(item) for item in activity)
