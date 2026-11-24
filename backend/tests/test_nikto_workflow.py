"""Disposable PostgreSQL and fake tools only; never activate a deployment policy."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
import pytest
from sqlalchemy import select, func, text, create_engine
from sqlalchemy.exc import DBAPIError

from app import nikto_profile
from app.baseline_catalog import fingerprint
from app.baseline_maintenance import record_tool_state
from app.models import Assessment, User, BaselineExecutionRequest
from app.recommended_test_queue import RecommendedTestJob as Job, RecommendedTestEvent as Event
from app.recommended_test_runner import RecommendedTestRunner
from app.recommended_test_consumer import fresh_scope_check
from app.nmap_adapter import ScanOutcome
from test_testing_read_projection import completed  # noqa: F401
from test_automatic_service_start import automatic  # noqa: F401
from test_scheduling_start import prepared, get_review, confirm, scheduling_concurrency  # noqa: F401
from test_execution_orchestration import BorrowedFactory


@pytest.fixture
def accepted(client, db, completed):
    path, headers, _, _, _ = completed
    record_tool_state(db, 'Nikto', 'enabled', ['http-server-assessment'])
    rec = next(r for r in client.get(path+'/testing/recommendations').json()['recommendations'] if r['port'] == 80)
    assert client.post(path+'/testing/completion/decisions', headers=headers,
        json={'recommendation_id':rec['id'],'decision':'Reviewed','review_outcome':'Accepted'}).status_code == 200
    return path, headers, rec


@pytest.fixture
def test_release(monkeypatch):
    # Select the release-owned Version 2 policy in disposable tests.
    # Historical Version 1 remains disabled and unchanged.
    monkeypatch.setenv('UPTIP_NIKTO_POLICY_VERSION', '2')
    monkeypatch.setenv(
        'UPTIP_NIKTO_POLICY_DIGEST',
        nikto_profile.authority(2)['digest'],
    )
    assert nikto_profile.integration_available()


def queue(client, db, accepted):
    path, headers, rec = accepted
    ready = client.get(path+f"/testing/recommendations/{rec['id']}/start-readiness").json()
    assert ready['ready'], ready
    url = path+f"/testing/recommendations/{rec['id']}/start"
    response = client.post(url, headers=headers, json={'snapshot_digest':ready['snapshot_digest']})
    assert response.status_code == 202, response.text
    return db.get(Job, UUID(response.json()['id'])), ready, response.json()


class FakeBoundary:
    enforced = False
    @contextmanager
    def restrict(self, target, port):
        self.enforced = True
        try: yield self
        finally: self.enforced = False


class FakeNikto:
    calls = 0
    outcome = ScanOutcome(b'- Nikto v2.6.1\n+ controlled fixture\n',b'',0,'scanner_exited',True,False)
    def run(self, plan, *, safe, launched, launch_guard):
        with launch_guard():
            assert safe()
            launched('synthetic-nikto:123:456')
        assert safe()
        self.calls += 1
        return self.outcome


def test_release_remains_disabled_and_never_queues(client, db, accepted, monkeypatch):
    monkeypatch.delenv('UPTIP_NIKTO_POLICY_VERSION', raising=False)
    monkeypatch.delenv('UPTIP_NIKTO_POLICY_DIGEST', raising=False)
    assert not nikto_profile.integration_available()
    path, headers, rec = accepted
    assert nikto_profile.authority()['execution_enabled'] is False
    ready = client.get(path+f"/testing/recommendations/{rec['id']}/start-readiness").json()
    assert not ready['ready'] and ready['reason_code'] == 'execution_integration_pending'
    response = client.post(path+f"/testing/recommendations/{rec['id']}/start",headers=headers,
                           json={'snapshot_digest':ready['snapshot_digest']})
    assert response.status_code == 503
    assert db.scalar(select(func.count()).select_from(Job)) == 0


def test_atomic_queue_receipt_replay_and_all_testing_views(client, db, accepted, test_release):
    path, headers, rec = accepted
    job, ready, receipt = queue(client, db, accepted)
    replay = client.post(path+f"/testing/recommendations/{rec['id']}/start",headers=headers,
                        json={'snapshot_digest':ready['snapshot_digest']})
    assert replay.status_code == 202 and replay.json()['id'] == receipt['id']
    assert replay.json()['already_requested'] is True
    assert db.scalar(select(func.count()).select_from(Job)) == 1
    assert db.scalar(select(func.count()).select_from(Event)) == 1
    overview = client.get(path+'/testing').json()
    assert overview['counts']['total'] == 3 and overview['counts']['queued'] == 1
    assert len(client.get(path+'/testing/executions').json()) == 3
    readiness = client.get(path+'/testing/completion').json()
    assert readiness['summary']['total'] == 3 and readiness['summary']['active_execution_requests'] == 1
    assert not readiness['ready'] and 'active_tests' in readiness['summary']['blockers']
    assert client.get(path+f'/testing/executions/{job.id}').json()['execution_kind'] == 'recommended'
    assert client.get(path+f"/testing/recommendations/{rec['id']}/start-receipt").json()['id'] == receipt['id']


def test_worker_output_is_preserved_lazy_and_integrity_checked(client, db, accepted, test_release):
    path, _, _ = accepted
    job, _, _ = queue(client, db, accepted)
    before = deepcopy(job.authorization_snapshot)
    adapter = FakeNikto()
    runner = RecommendedTestRunner(BorrowedFactory(db), adapter, boundary=FakeBoundary())
    assert runner.run(job.id) and job.status == 'Completed'
    assert not runner.run(job.id) and adapter.calls == 1
    assert job.authorization_snapshot == before
    view = client.get(path+f'/testing/executions/{job.id}').json()
    assert view['status'] == 'Completed' and view['execution_authorized'] is False
    assert view['recommended_result']['integrity_verified'] and view['recommended_result']['termination_verified']
    assert view['observations'] == view['attempts'] == []
    assert len(view['processing']) == 1 and view['processing'][0]['status'] == 'Succeeded'
    assert 'controlled fixture' not in str(view)
    original = client.get(path+f'/testing/executions/{job.id}/evidence/{job.id}')
    assert original.status_code == 200 and original.json()['content'].encode() == adapter.outcome.stdout
    assert original.headers['cache-control'] == 'no-store'
    assert [r.event_type for r in db.scalars(select(Event).order_by(Event.occurred_at,Event.id))] == [
        'execution_queued','execution_claimed','scanner_started','execution_finished']
    # Capturing Nikto output is not normalized finding processing. Preserve the gate.
    summary = client.get(path+'/testing/completion').json()['summary']
    assert summary['missing_processing'] == 1 and 'processing_not_clear' in summary['blockers']


@pytest.mark.parametrize('reason,terminated', [('execution_timeout',True),('runtime_safety_lost',True),('termination_unverified',False)])
def test_failures_and_uncertainty_do_not_retry(client, db, accepted, test_release, reason, terminated):
    job, _, _ = queue(client, db, accepted)
    adapter = FakeNikto(); adapter.outcome = replace(adapter.outcome,exit_code=None,reason=reason,partial=True,terminated=terminated)
    runner = RecommendedTestRunner(BorrowedFactory(db),adapter,boundary=FakeBoundary())
    assert runner.run(job.id)
    assert job.status == ('Failed' if terminated else 'Running')
    assert job.termination_verified is terminated and job.output_partial
    assert not runner.run(job.id) and adapter.calls == 1


def test_expired_or_changed_acceptance_blocks_dispatch(client, db, accepted, test_release):
    path, headers, rec = accepted
    job, _, _ = queue(client, db, accepted)
    assert fresh_scope_check(db, job)
    assert client.post(path+'/testing/completion/decisions',headers=headers,json={
        'recommendation_id':rec['id'],'decision':'Deferred'}).status_code == 200
    assert not fresh_scope_check(db, job)
    adapter = FakeNikto()
    assert not RecommendedTestRunner(BorrowedFactory(db),adapter,boundary=FakeBoundary()).run(job.id)
    assert job.status == 'Blocked' and adapter.calls == 0


def test_expired_consent_and_legacy_unknown_provenance_are_not_accepted(client, db, accepted, test_release):
    from app.recommended_test_authorization import revalidate
    from types import SimpleNamespace
    job, _, _ = queue(client, db, accepted)
    saved = deepcopy(job.authorization_snapshot)
    saved['expires_at'] = (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
    assert not revalidate(db, SimpleNamespace(authorization_snapshot=saved))
    assert not revalidate(db, SimpleNamespace(authorization_snapshot=None))


def test_api_permissions_csrf_stale_digest_and_closed_lifecycle(client, db, accepted, test_release):
    path, headers, rec = accepted
    url = path+f"/testing/recommendations/{rec['id']}/start"
    ready = client.get(url+'-readiness').json()
    assert client.post(url,json={'snapshot_digest':ready['snapshot_digest']}).status_code == 403
    assert client.post(url,headers={**headers,'Origin':'https://untrusted.test'},json={'snapshot_digest':ready['snapshot_digest']}).status_code == 403
    assert client.post(url,headers=headers,json={'snapshot_digest':'0'*64}).status_code == 409
    assert client.post(url,headers=headers,json={'snapshot_digest':ready['snapshot_digest'],'port':443}).status_code == 422
    assert db.scalar(select(func.count()).select_from(Job)) == 0
    assessment = db.get(Assessment,UUID(path.rsplit('/',1)[1])); assessment.status = 'Ready'; db.flush()
    assert client.post(url,headers=headers,json={'snapshot_digest':ready['snapshot_digest']}).status_code == 409


def test_job_and_event_history_are_immutable(client, db, accepted, test_release):
    job, _, _ = queue(client, db, accepted)
    for statement in (
        "UPDATE recommended_test_jobs SET execution_plan='{}' WHERE id=:id",
        'DELETE FROM recommended_test_jobs WHERE id=:id',
        'TRUNCATE recommended_test_jobs CASCADE',
        "UPDATE recommended_test_events SET reason_code='tampered' WHERE job_id=:id",
    ):
        with pytest.raises(DBAPIError), db.begin_nested(): db.execute(text(statement),{'id':job.id})
    for privilege in ('UPDATE','DELETE','TRUNCATE','TRIGGER'):
        assert not db.scalar(text('SELECT has_table_privilege(\'uptip_runtime\',\'public.recommended_test_jobs\',:p)'),{'p':privilege})


def test_migration_matches_model_metadata(scheduling_concurrency, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from pathlib import Path
    from app.database import Base
    app, factory, _, _, _ = scheduling_concurrency
    with factory() as session:
        assert session.scalar(text('SELECT version_num FROM alembic_version')) == '0028'
        assert compare_metadata(MigrationContext.configure(session.connection()),Base.metadata) == []


def test_boundary_failure_never_launches_or_retries(client, db, accepted, test_release):
    from app.nmap_adapter import AdapterUnavailable
    class Unavailable:
        @contextmanager
        def restrict(self,*args):
            raise AdapterUnavailable('test-boundary-unavailable')
            yield
    job, _, _ = queue(client, db, accepted)
    adapter = FakeNikto()
    runner = RecommendedTestRunner(BorrowedFactory(db),adapter,boundary=Unavailable())
    assert not runner.run(job.id) and adapter.calls == 0
    assert job.status == 'Blocked' and job.failure_reason == 'network_boundary_unavailable'
    assert not runner.run(job.id)
    assert db.scalar(select(func.count()).select_from(Event).where(Event.job_id == job.id)) == 2


def test_scope_and_creator_loss_stop_revalidation(client, db, accepted, test_release):
    job, _, _ = queue(client, db, accepted)
    assert fresh_scope_check(db,job)
    user = db.get(User,job.actor_id); user.status='disabled'; db.flush()
    assert not fresh_scope_check(db,job)


def test_unaccepted_or_out_of_scope_recommendations_cannot_queue(client, db, accepted, test_release):
    path,headers,rec=accepted
    assert client.post(path+'/testing/completion/decisions',headers=headers,json={
        'recommendation_id':rec['id'],'decision':'Reviewed','review_outcome':'Rejected'}).status_code==200
    url=path+f"/testing/recommendations/{rec['id']}/start"
    assert not client.get(url+'-readiness').json()['ready']
    assert client.post(url,headers=headers,json={'snapshot_digest':'a'*64}).status_code==409
    assert db.scalar(select(func.count()).select_from(Job))==0


@pytest.fixture
def committed_case(scheduling_concurrency, monkeypatch, tmp_path, test_release):
    from fastapi.testclient import TestClient
    from test_automatic_service_start import enable_services
    from test_execution_orchestration import FakeAdapter, BorrowedFactory
    from test_service_discovery import ServiceAdapter
    from app.execution_orchestration import ExecutionRunner
    from app.execution_results import EvidenceStore
    app,factory,_,_,_=scheduling_concurrency
    with factory() as session,TestClient(app,base_url='https://testserver') as client:
        client.headers['Origin']='https://testserver'
        path,headers,_=prepared.__wrapped__(client,session,monkeypatch)
        enable_services(session,path)
        assert confirm(client,path,headers,get_review(client,path)['start_review']).status_code==201
        rows=session.scalars(select(BaselineExecutionRequest).order_by(BaselineExecutionRequest.profile_id)).all()
        tmp_path.chmod(0o700)
        store=EvidenceStore(tmp_path)
        assert ExecutionRunner(BorrowedFactory(session),FakeAdapter(),store,'fake-host').run(rows[0].id)
        assert ExecutionRunner(BorrowedFactory(session),ServiceAdapter(),store,'fake-service').run(rows[1].id)
        record_tool_state(session,'Nikto','enabled',['http-server-assessment']);session.commit()
        rec=client.get(path+'/testing/recommendations').json()['recommendations'][0]
        assert client.post(path+'/testing/completion/decisions',headers=headers,json={
            'recommendation_id':rec['id'],'decision':'Reviewed','review_outcome':'Accepted'}).status_code==200
        ready=client.get(path+f"/testing/recommendations/{rec['id']}/start-readiness").json()
        assert ready['ready']
        return app,factory,path,headers,dict(client.cookies),rec,ready


@pytest.mark.parametrize('scheduling_concurrency',['empty'],indirect=True)
def test_concurrent_start_requests_persist_one_job_and_event(committed_case):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from fastapi.testclient import TestClient
    app,factory,path,headers,cookies,rec,ready=committed_case
    barrier=Barrier(2)
    def submit():
        with TestClient(app,base_url='https://testserver') as client:
            client.cookies.update(cookies);client.headers['Origin']='https://testserver';barrier.wait(timeout=5)
            return client.post(path+f"/testing/recommendations/{rec['id']}/start",headers=headers,
                json={'snapshot_digest':ready['snapshot_digest']})
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses=list(pool.map(lambda _:submit(),range(2)))
    assert [r.status_code for r in responses]==[202,202]
    assert responses[0].json()['id']==responses[1].json()['id']
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Job))==1
        assert db.scalar(select(func.count()).select_from(Event))==1


@pytest.mark.parametrize('scheduling_concurrency',['empty'],indirect=True)
def test_history_downgrade_refused(committed_case):
    from fastapi.testclient import TestClient
    from alembic import command
    from alembic.config import Config
    from pathlib import Path
    app,factory,path,headers,cookies,rec,ready=committed_case
    with TestClient(app,base_url='https://testserver') as client:
        client.cookies.update(cookies);client.headers['Origin']='https://testserver'
        response=client.post(path+f"/testing/recommendations/{rec['id']}/start",headers=headers,json={'snapshot_digest':ready['snapshot_digest']})
        assert response.status_code==202
    config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    config.set_main_option('script_location',str(Path(__file__).resolve().parents[1]/'migrations'))
    with pytest.raises(DBAPIError,match='Cannot erase recommended test history'):
        command.downgrade(config,'0026')
    with factory() as db:
        assert db.scalar(text('SELECT version_num FROM alembic_version'))=='0028'
        assert db.scalar(select(func.count()).select_from(Job))==1


@pytest.mark.parametrize('scheduling_concurrency',['empty'],indirect=True)
def test_queue_and_audit_failure_roll_back_together(committed_case):
    from fastapi.testclient import TestClient
    from sqlalchemy import event
    from sqlalchemy.exc import SQLAlchemyError
    app,factory,path,headers,cookies,rec,ready=committed_case
    engine=factory.kw['bind']
    def fail(conn,cursor,statement,*args):
        if statement.startswith('INSERT INTO recommended_test_events'):
            raise SQLAlchemyError('synthetic audit failure')
    event.listen(engine,'before_cursor_execute',fail)
    try:
        with TestClient(app,base_url='https://testserver') as client:
            client.cookies.update(cookies);client.headers['Origin']='https://testserver'
            assert client.post(path+f"/testing/recommendations/{rec['id']}/start",headers=headers,json={'snapshot_digest':ready['snapshot_digest']}).status_code==503
    finally:event.remove(engine,'before_cursor_execute',fail)
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Job))==0
        assert db.scalar(select(func.count()).select_from(Event))==0


def test_worker_role_gets_only_required_column_privileges(migration_db):
    import os
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from app.config import get_settings
    url=migration_db.info['migration_test_migration_url']
    engine=create_engine(url)
    try:
        with engine.begin() as connection:
            exists=connection.scalar(text("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='uptip_worker')"))
            if not exists:
                if not os.environ.get('UPTIP_DISPOSABLE_ADMIN_URL'):
                    pytest.skip('Need an existing worker role or an explicitly marked disposable cluster')
                admin=create_engine(os.environ['UPTIP_DISPOSABLE_ADMIN_URL'])
                try:
                    with admin.connect() as conn:
                        assert conn.scalar(text("SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"))=='UPTIP disposable test cluster'
                finally:admin.dispose()
                connection.execute(text('CREATE ROLE uptip_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS'))
        config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
        config.set_main_option('script_location',str(Path(__file__).resolve().parents[1]/'migrations'))
        command.upgrade(config,'0027')
        with engine.connect() as connection:
            for p in ('DELETE','TRUNCATE','TRIGGER','INSERT'):
                assert not connection.scalar(text("SELECT has_table_privilege('uptip_worker','public.recommended_test_jobs',:p)"),{'p':p})
            assert connection.scalar(text("SELECT has_column_privilege('uptip_worker','public.recommended_test_jobs','status','UPDATE')"))
            for column in ('execution_plan','authorization_snapshot','actor_id','target_id'):
                assert not connection.scalar(text("SELECT has_column_privilege('uptip_worker','public.recommended_test_jobs',:column,'UPDATE')"),{'column':column})
            assert connection.scalar(text("SELECT has_function_privilege('uptip_worker','public.lock_recommended_job_sources(uuid)','EXECUTE')"))
            assert not connection.scalar(text("SELECT has_function_privilege('uptip_runtime','public.lock_recommended_job_sources(uuid)','EXECUTE')"))
    finally:engine.dispose()


@pytest.mark.parametrize('scheduling_concurrency',['empty'],indirect=True)
def test_concurrent_workers_cannot_duplicate_a_launch(committed_case):
    from fastapi.testclient import TestClient
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event as ThreadEvent
    app,factory,path,headers,cookies,rec,ready=committed_case
    with TestClient(app,base_url='https://testserver') as client:
        client.cookies.update(cookies);client.headers['Origin']='https://testserver'
        response=client.post(path+f"/testing/recommendations/{rec['id']}/start",headers=headers,json={'snapshot_digest':ready['snapshot_digest']})
        assert response.status_code==202
        job_id=UUID(response.json()['id'])
    entered,release=ThreadEvent(),ThreadEvent()
    class Waiting(FakeNikto):
        def run(self,*args,**kwargs):
            entered.set()
            assert release.wait(5)
            return super().run(*args,**kwargs)
    first,second=Waiting(),FakeNikto()
    a=RecommendedTestRunner(factory,first,boundary=FakeBoundary())
    b=RecommendedTestRunner(factory,second,boundary=FakeBoundary())
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending=pool.submit(a.run,job_id)
        assert entered.wait(5)
        try: assert not b.run(job_id)
        finally:release.set()
        assert pending.result(timeout=10)
    assert first.calls==1 and second.calls==0
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Event).where(Event.job_id==job_id,Event.event_type=='scanner_started'))==1



def test_recommended_worker_needs_no_password_or_administrative_privileges(client, db, accepted, test_release):
    job, _, _ = queue(client,db,accepted)
    db.execute(text('CREATE ROLE uptip_nikto_test_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS'))
    db.execute(text('GRANT uptip_nikto_test_worker TO uptip WITH SET TRUE, INHERIT FALSE'))
    db.execute(text('GRANT USAGE ON SCHEMA public TO uptip_nikto_test_worker'))
    db.execute(text('GRANT SELECT(id,status,role,password_change_required) ON users TO uptip_nikto_test_worker'))
    db.execute(text('GRANT SELECT ON assessments,assessment_targets,assessment_assignments,scope_entries,baseline_tool_states,baseline_execution_requests,execution_attempts,scanner_evidence,result_processing_outcomes,security_observations,testing_recommendation_decisions,recommendation_review_events,recommended_test_jobs,recommended_test_events TO uptip_nikto_test_worker'))
    db.execute(text('GRANT INSERT ON recommended_test_events TO uptip_nikto_test_worker'))
    db.execute(text('GRANT UPDATE(status,started_at,finished_at,exit_code,failure_reason,stdout,stderr,output_digest,termination_verified,output_partial,process_reference,updated_at) ON recommended_test_jobs TO uptip_nikto_test_worker'))
    db.execute(text('GRANT EXECUTE ON FUNCTION public.lock_recommended_job_sources(uuid) TO uptip_nikto_test_worker'))
    db.execute(text('SET LOCAL ROLE uptip_nikto_test_worker'))
    try:
        assert not db.scalar(text("SELECT has_column_privilege(current_user,'users','password_hash','SELECT')"))
        assert not db.scalar(text("SELECT has_column_privilege(current_user,'recommended_test_jobs','execution_plan','UPDATE')"))
        adapter=FakeNikto()
        assert RecommendedTestRunner(BorrowedFactory(db),adapter,boundary=FakeBoundary()).run(job.id)
        assert adapter.calls==1 and job.status=='Completed'
    finally:db.execute(text('RESET ROLE'))


def test_recommended_details_receipt_and_output_are_assessment_isolated(client, db, accepted, test_release):
    from test_assessments import add_analyst, sign_in
    job, _, _=queue(client,db,accepted)
    path,_,rec=accepted
    base=path+'/testing'
    for root in (base, f'/api/v1/assessments/{uuid4()}/testing'):
        if root != base:
            assert client.get(root+f'/executions/{job.id}').status_code==404
            assert client.get(root+f'/executions/{job.id}/evidence/{job.id}').status_code==404
    outsider=add_analyst(db,'nikto-outsider-'+uuid4().hex)
    headers=sign_in(client,outsider.username)
    for suffix in (f'/executions/{job.id}',f'/executions/{job.id}/evidence/{job.id}',
                   f"/recommendations/{rec['id']}/start-readiness",f"/recommendations/{rec['id']}/start-receipt"):
        assert client.get(base+suffix).status_code==404
    assert client.post(base+f"/recommendations/{rec['id']}/start",headers=headers,json={'snapshot_digest':'a'*64}).status_code==404
    client.cookies.clear()
    assert client.get(base+f'/executions/{job.id}').status_code==401
    assert client.get(base+f'/executions/{job.id}/evidence/{job.id}').status_code==401


def test_scope_loss_during_execution_is_observed_and_never_reported_complete(client,db,accepted,test_release):
    job,_,_=queue(client,db,accepted)
    class Revoked(FakeNikto):
        def run(self,plan,*,safe,launched,launch_guard):
            with launch_guard():
                assert safe();launched('synthetic-nikto:123:456')
            assessment=db.get(Assessment,job.assessment_id)
            assessment.scope_revision+=1;db.flush()
            assert not safe()
            self.calls+=1
            return replace(self.outcome,reason='runtime_safety_lost',partial=True)
    adapter=Revoked()
    assert RecommendedTestRunner(BorrowedFactory(db),adapter,boundary=FakeBoundary()).run(job.id)
    assert job.status=='Failed' and job.output_partial
    assert not RecommendedTestRunner(BorrowedFactory(db),adapter,boundary=FakeBoundary()).run(job.id)
    assert adapter.calls==1


def test_old_v1_queue_is_not_upgraded_or_dispatched_under_v2(client,db,accepted,test_release):
    path,headers,rec=accepted
    ready=client.get(path+f"/testing/recommendations/{rec['id']}/start-readiness").json()
    job=Job(assessment_id=UUID(path.rsplit('/',1)[1]),target_id=UUID(str(rec['target_id'])),
        actor_id=db.scalar(select(Assessment.creator_id)),recommendation_id=rec['id'],tool='Nikto',
        profile_id=nikto_profile.PROFILE_ID,profile_version=1,scope_revision=1,
        execution_plan=nikto_profile.plan(rec['target'],rec['port'],rec['service']),status='Queued')
    db.add(job);db.flush();original=deepcopy(job.execution_plan)
    url=path+f"/testing/recommendations/{rec['id']}/start"
    preview=client.get(url+'-readiness').json()
    assert not preview['ready'] and preview['reason_code']=='recommended_existing_policy_stale'
    response=client.post(url,headers=headers,json={'snapshot_digest':ready['snapshot_digest']})
    assert response.status_code==409
    adapter=FakeNikto()
    assert not RecommendedTestRunner(BorrowedFactory(db),adapter,boundary=FakeBoundary()).run(job.id)
    assert adapter.calls==0 and job.status=='Queued' and job.execution_plan==original
    assert client.get(url+'-receipt').json()['id']==str(job.id)


def test_system_policy_change_invalidates_review_and_queued_consent(client,db,accepted,test_release,monkeypatch):
    from app.config import get_settings
    job,_,_=queue(client,db,accepted)
    assert job.profile_version==2 and job.authorization_snapshot['dispatch_activation']['version']==2
    assert fresh_scope_check(db,job)
    monkeypatch.setattr(get_settings(),'nikto_policy_digest','0'*64)
    assert not fresh_scope_check(db,job)
    adapter=FakeNikto()
    assert not RecommendedTestRunner(BorrowedFactory(db),adapter,boundary=FakeBoundary()).run(job.id)
    assert job.status=='Blocked' and adapter.calls==0


def test_activated_policy_keeps_tool_port_and_consent_requirements(client,db,accepted,test_release,monkeypatch):
    path,headers,rec=accepted
    url=path+f"/testing/recommendations/{rec['id']}/start"
    ready=client.get(url+'-readiness').json()
    listing=client.get(path+'/testing/recommendations').json()['recommendations'][0]
    assert listing['tool_integration_status']=='integrated'
    assert listing['execution_status']=='requires_start_review' and not listing['execution_available']
    assert client.get(url.replace('/start','/eligibility')).json()['reason_code']=='explicit_start_required'
    from app import scope_ports
    with monkeypatch.context() as check:
        check.setattr(scope_ports,'authorized_ports',lambda *args:[443] if rec['port']==80 else [80])
        assert client.get(url+'-readiness').json()['reason_code']=='recommended_port_out_of_scope'
        assert client.post(url,headers=headers,json={'snapshot_digest':ready['snapshot_digest']}).status_code==409
    record_tool_state(db,'Nikto','disabled',[])
    assert client.get(url+'-readiness').json()['reason_code']=='nikto_tool_unavailable'
    assert client.post(url,headers=headers,json={'snapshot_digest':ready['snapshot_digest']}).status_code==409
    assert db.scalar(select(func.count()).select_from(Job))==0


def test_nikto_normalizer_only_extracts_explicit_path_observations():
    from app.nikto_normalizer import normalize
    content = (b'- Nikto v2.6.1\n'
               b'+ Server: example\n'
               b'+ /admin/: The X-Frame-Options header is missing.\n'
               b'+ /admin/: The X-Frame-Options header is missing.\n'
               b'+ OSVDB-123: informational text without a path\n')
    rows = normalize(content, target='192.0.2.10', port=80, scheme='http')
    assert len(rows) == 1
    assert rows[0]['type'] == 'http_server_test'
    assert rows[0]['data']['path'] == '/admin/'
    assert rows[0]['data']['verification'] == 'unverified'



def test_nikto_normalizer_accepts_six_digit_test_ids():
    from app.nikto_normalizer import normalize

    content = (
        b'- Nikto v2.6.1\n'
        b'+ [013587] /: The X-Content-Type-Options header is not set.\n'
        b'+ [013587] /: The X-Content-Type-Options header is not set.\n'
        b'+ [999999] /./: Directory indexing found.\n'
        b'+ Server: example\n'
    )

    rows = normalize(
        content,
        target='192.0.2.10',
        port=8080,
        scheme='http',
    )

    assert len(rows) == 2

    first, second = rows

    assert first['type'] == 'http_server_test'
    assert first['data']['test_id'] == '013587'
    assert first['data']['path'] == '/'
    assert first['data']['verification'] == 'unverified'
    assert 'X-Content-Type-Options' in first['data']['message']

    assert second['data']['test_id'] == '999999'
    assert second['data']['path'] == '/./'
    assert second['data']['verification'] == 'unverified'

def test_nikto_results_are_persisted_and_returned_without_raw_output(client, db, accepted, test_release):
    from app.recommended_normalization_models import RecommendedObservation, RecommendedProcessingOutcome
    path, _, _ = accepted
    job, _, _ = queue(client, db, accepted)
    adapter = FakeNikto()
    adapter.outcome = replace(adapter.outcome, stdout=(
        b'- Nikto v2.6.1\n+ /admin/: Missing security header.\n'))
    runner = RecommendedTestRunner(BorrowedFactory(db), adapter, boundary=FakeBoundary())
    assert runner.run(job.id)
    assert db.scalar(select(func.count()).select_from(RecommendedProcessingOutcome)) == 1
    assert db.scalar(select(func.count()).select_from(RecommendedObservation)) == 1
    view = client.get(path+f'/testing/executions/{job.id}').json()
    assert view['recommended_result']['integrity_verified']
    assert len(view['processing']) == 1 and view['processing'][0]['status'] == 'Succeeded'
    assert len(view['observations']) == 1
    assert view['observations'][0]['data']['path'] == '/admin/'
    assert 'Missing security header' in view['observations'][0]['data']['message']
    assert 'Nikto v2.6.1' not in str(view)
    from app.recommended_normalization import process_job
    process_job(db, job.id)
    assert db.scalar(select(func.count()).select_from(RecommendedObservation)) == 1


class TestNiktoFindingsConsolidation:
    @pytest.fixture
    def db(self, engine, nikto_owner_db):
        # Use the existing guarded, rollback-only owner session.
        return nikto_owner_db

    def test_nikto_findings_consolidation(
        self, client, db, accepted, test_release
    ):
        from app.findings_models import (
            ConsolidatedFinding,
            FindingRecommendedObservation,
        )
        from app.nikto_findings_processing import (
            candidate_keys,
            consolidate_nikto,
        )
        from app.recommended_normalization_models import (
            RecommendedObservation,
        )

        job, _, _ = queue(client, db, accepted)

        adapter = FakeNikto()

        adapter.outcome = replace(
            adapter.outcome,
            stdout=(
                b'- Nikto v2.6.1\n'
                b'+ /: Suggested security header missing: content-security-policy.\n'
                b'+ /: The X-Content-Type-Options header is not set.\n'
                b'+ /: Suggested security header missing: x-content-type-options.\n'
                b'+ /: Suggested security header missing: referrer-policy.\n'
                b'+ /: Suggested security header missing: permissions-policy.\n'
                b'+ /: Suggested security header missing: strict-transport-security.\n'
                b'+ /cgi-bin/: CGI directory found.\n'
            ),
        )

        runner = RecommendedTestRunner(
            BorrowedFactory(db),
            adapter,
            boundary=FakeBoundary(),
        )

        assert runner.run(job.id)
        assert job.status == 'Completed'

        assessment_id = job.assessment_id

        observations = db.scalars(
            select(RecommendedObservation).where(
                RecommendedObservation.assessment_id == assessment_id
            )
        ).all()

        assert len(observations) == 7

        # Four distinct findings from five eligible observations.
        keys = candidate_keys(db, assessment_id)

        assert len(keys) == 4

        # Candidate counting must not create database records.
        assert db.scalar(
            select(func.count())
            .select_from(ConsolidatedFinding)
            .where(
                ConsolidatedFinding.assessment_id == assessment_id
            )
        ) == 0

        # Acquire the assessment lock before consolidation.
        db.execute(
            select(Assessment.id)
            .where(Assessment.id == assessment_id)
            .with_for_update()
        ).one()

        assert consolidate_nikto(db, assessment_id) == 4

        findings = db.scalars(
            select(ConsolidatedFinding).where(
                ConsolidatedFinding.assessment_id == assessment_id
            )
        ).all()

        assert len(findings) == 4
        assert {f.identity_key for f in findings} == keys
        assert all(f.source == 'Nikto' for f in findings)

        assert sum(f.severity == 'Medium' for f in findings) == 1
        assert sum(f.severity == 'Low' for f in findings) == 3

        links = db.scalars(
            select(FindingRecommendedObservation).where(
                FindingRecommendedObservation.assessment_id
                == assessment_id
            )
        ).all()

        assert len(links) == 5

        duplicate_finding = next(
            f for f in findings
            if f.security_control == 'x-content-type-options'
        )

        assert sum(
            link.finding_id == duplicate_finding.id
            for link in links
        ) == 2

        # Repeated consolidation must not create duplicates.
        assert consolidate_nikto(db, assessment_id) == 0

        assert db.scalar(
            select(func.count())
            .select_from(FindingRecommendedObservation)
            .where(
                FindingRecommendedObservation.assessment_id
                == assessment_id
            )
        ) == 5

        # Unrelated assessment identifiers must not expose candidates.
        assert candidate_keys(db, uuid4()) == set()

        # Consolidation must not execute the scanner again.
        assert adapter.calls == 1


    def test_finding_ai_context_integration(
        self, client, db, accepted, test_release
    ):
        from types import SimpleNamespace
        from fastapi import HTTPException
        from app.finding_ai_context import retrieve_context
        from app.findings_models import (
            ConsolidatedFinding,
            FindingRecommendedObservation,
        )
        from app.nikto_findings_processing import consolidate_nikto

        job, _, _ = queue(client, db, accepted)

        adapter = FakeNikto()
        adapter.outcome = replace(
            adapter.outcome,
            stdout=(
                b'- Nikto v2.6.1\n'
                b'+ /: Suggested security header missing: content-security-policy.\n'
                b'+ /: The X-Content-Type-Options header is not set.\n'
                b'+ /: Suggested security header missing: x-content-type-options.\n'
                b'+ /cgi-bin/: CGI directory found.\n'
            ),
        )

        runner = RecommendedTestRunner(
            BorrowedFactory(db),
            adapter,
            boundary=FakeBoundary(),
        )

        assert runner.run(job.id)
        assert job.status == 'Completed'

        assessment_id = job.assessment_id

        assessment = db.scalar(
            select(Assessment)
            .where(Assessment.id == assessment_id)
            .with_for_update()
        )

        assert consolidate_nikto(db, assessment_id) == 2

        findings = db.scalars(
            select(ConsolidatedFinding).where(
                ConsolidatedFinding.assessment_id == assessment_id
            )
        ).all()

        assert len(findings) == 2

        owner = db.get(User, assessment.creator_id)
        assert owner is not None

        csp = next(f for f in findings if f.severity == 'Medium')
        xcto = next(f for f in findings if f.severity == 'Low')

        def snapshot():
            return (
                db.execute(
                    select(ConsolidatedFinding.__table__)
                    .where(
                        ConsolidatedFinding.assessment_id == assessment_id
                    )
                    .order_by(ConsolidatedFinding.id)
                ).all(),
                db.execute(
                    select(FindingRecommendedObservation.__table__)
                    .where(
                        FindingRecommendedObservation.assessment_id
                        == assessment_id
                    )
                    .order_by(
                        FindingRecommendedObservation.finding_id,
                        FindingRecommendedObservation.observation_id,
                    )
                ).all(),
            )

        before = snapshot()

        # Authorized retrieval using the real access-control predicate.
        csp_context = retrieve_context(
            db, assessment_id, csp.id, owner
        )

        assert csp_context['finding_id'] == str(csp.id)
        assert csp_context['assessment_id'] == str(assessment_id)
        assert csp_context['finding']['severity'] == 'Medium'
        assert csp_context['evidence_available'] is True
        assert csp_context['eligible_evidence_count'] == 1
        assert csp_context['evidence_included_count'] == 1
        assert csp_context['original_output_included'] is False

        # Evidence from the second finding must remain isolated.
        xcto_context = retrieve_context(
            db, assessment_id, xcto.id, owner
        )

        assert xcto_context['eligible_evidence_count'] == 2
        assert xcto_context['evidence_included_count'] == 2

        csp_ids = {
            e['observation_id'] for e in csp_context['evidence']
        }
        xcto_ids = {
            e['observation_id'] for e in xcto_context['evidence']
        }

        assert csp_ids.isdisjoint(xcto_ids)

        for finding, context in (
            (csp, csp_context),
            (xcto, xcto_context),
        ):
            linked_ids = {
                str(value) for value in db.scalars(
                    select(
                        FindingRecommendedObservation.observation_id
                    ).where(
                        FindingRecommendedObservation.assessment_id
                        == assessment_id,
                        FindingRecommendedObservation.finding_id
                        == finding.id,
                    )
                )
            }

            assert {
                e['observation_id'] for e in context['evidence']
            } == linked_ids

            assert all(
                e['source'] == 'Nikto'
                and e['exploitation_confirmed'] is False
                for e in context['evidence']
            )

        # An unrelated principal must not retrieve the finding.
        unrelated = SimpleNamespace(id=uuid4())

        with pytest.raises(HTTPException) as error:
            retrieve_context(
                db, assessment_id, csp.id, unrelated
            )

        assert error.value.status_code == 404

        # A mismatched assessment identifier must be rejected.
        with pytest.raises(HTTPException) as error:
            retrieve_context(db, uuid4(), csp.id, owner)

        assert error.value.status_code == 404

        # An unknown finding identifier must be rejected.
        with pytest.raises(HTTPException) as error:
            retrieve_context(db, assessment_id, uuid4(), owner)

        assert error.value.status_code == 404

        # Retrieval must preserve persisted findings and links.
        assert snapshot() == before

        # Repeated retrieval must produce the same context.
        assert retrieve_context(
            db, assessment_id, csp.id, owner
        ) == csp_context

        assert snapshot() == before
        assert adapter.calls == 1


    def test_finding_ai_history_integration(
        self, client, db, accepted, test_release, monkeypatch
    ):
        from unittest.mock import AsyncMock
        from app import finding_ai_routes as ai
        from app.config import get_settings
        from app.models import AssessmentAssignment, AuthSession
        from app.security import digest, session_csrf
        from app.findings_models import ConsolidatedFinding
        from app.finding_ai_history_models import FindingAIHistory
        from app.ollama_client import OllamaUnavailable

        # Use the existing disposable Nikto workflow.
        job, _, _ = queue(client, db, accepted)

        adapter = FakeNikto()
        adapter.outcome = replace(
            adapter.outcome,
            stdout=(
                b'- Nikto v2.6.1\n+ /: Suggested security header missing: content-security-policy.\n+ /: The X-Content-Type-Options header is not set.\n+ /: Suggested security header missing: x-content-type-options.\n+ /cgi-bin/: CGI directory found.\n'
            ),
        )

        runner = RecommendedTestRunner(
            BorrowedFactory(db),
            adapter,
            boundary=FakeBoundary(),
        )

        assert runner.run(job.id)
        assert job.status == "Completed"

        from app.nikto_findings_processing import consolidate_nikto

        assessment_id = job.assessment_id

        assessment = db.scalar(
            select(Assessment)
            .where(Assessment.id == assessment_id)
            .with_for_update()
        )

        assert consolidate_nikto(db, assessment_id) == 2

        findings = db.scalars(
            select(ConsolidatedFinding).where(
                ConsolidatedFinding.assessment_id == assessment_id
            )
        ).all()

        csp = next(f for f in findings if f.severity == "Medium")
        xcto = next(f for f in findings if f.severity == "Low")

        finding_id = csp.id
        other_finding_id = xcto.id
        owner_id = assessment.creator_id

        settings = get_settings()

        monkeypatch.setattr(settings, "ai_enabled", True)
        monkeypatch.setattr(settings, "ai_model", "qwen2.5:3b")
        monkeypatch.setattr(settings, "ai_context_tokens", 2048)
        monkeypatch.setattr(settings, "ai_max_output_tokens", 256)

        generate = AsyncMock(return_value={
            "answer": "Configure an appropriate CSP header.",
            "model": settings.ai_model,
            "output_tokens": 12,
        })

        monkeypatch.setattr(ai, "generate", generate)

        # Create an independent synthetic analyst.
        second = User(
            username="ai-history-" + uuid4().hex,
            role="Security Analyst",
            password_hash="synthetic-unused-password-hash",
            password_change_required=False,
            status="active",
        )

        db.add(second)
        db.flush()

        second_id = second.id

        db.add(AssessmentAssignment(
            assessment_id=assessment_id,
            analyst_id=second_id,
        ))

        owner_token = "history-owner-" + uuid4().hex
        second_token = "history-second-" + uuid4().hex

        for actor_id, token in (
            (owner_id, owner_token),
            (second_id, second_token),
        ):
            db.add(AuthSession(
                token_hash=digest(token),
                csrf_hash=digest(session_csrf(settings, token)),
                user_id=actor_id,
                expires_at=datetime.now(timezone.utc)
                + timedelta(minutes=30),
            ))

        # Release the fixture savepoint before the AI route rolls
        # back its initial read transaction.
        db.commit()

        def authenticate(token):
            client.cookies.clear()
            client.cookies.set(settings.cookie_name, token)
            client.headers["Origin"] = settings.public_origin
            client.headers["X-CSRF-Token"] = session_csrf(
                settings, token
            )

        base = (
            f"/api/v1/assessments/{assessment_id}"
            f"/findings/{finding_id}/ai"
        )

        def history(**params):
            response = client.get(
                base + "/history", params=params
            )
            assert response.status_code == 200, response.text
            return response.json()

        def count_records():
            return db.scalar(
                select(func.count())
                .select_from(FindingAIHistory)
                .where(
                    FindingAIHistory.assessment_id == assessment_id
                )
            )

        authenticate(owner_token)

        assert history()["entries"] == []
        assert count_records() == 0

        # Save three successful answers through the real API.
        saved_ids = []

        for question in (
            "What is the detected issue?",
            "What is the potential impact?",
            "How should this be remediated?",
        ):
            response = client.post(
                base + "/ask",
                json={"action": "custom", "question": question},
            )

            assert response.status_code == 200, response.text

            data = response.json()

            assert data["status"] == "answered", data
            assert data["history_id"]
            assert data["question"] == question
            assert data["advisory_only"] is True

            saved_ids.append(data["history_id"])

            record = db.get(
                FindingAIHistory, UUID(data["history_id"])
            )

            assert record is not None
            assert record.actor_id == owner_id
            assert record.assessment_id == assessment_id
            assert record.finding_id == finding_id
            assert record.question == question
            assert record.answer == data["answer"]
            assert record.evidence == data["evidence"]
            assert record.limitations == data["limitations"]
            assert record.prompt_version
            assert record.output_tokens == 12

        assert count_records() == 3

        # Verify ordering and pagination.
        all_entries = history()["entries"]

        assert len(all_entries) == 3

        expected_ids = [
            str(record.id)
            for record in db.scalars(
                select(FindingAIHistory)
                .where(
                    FindingAIHistory.assessment_id == assessment_id,
                    FindingAIHistory.finding_id == finding_id,
                    FindingAIHistory.actor_id == owner_id,
                )
                .order_by(
                    FindingAIHistory.created_at.desc(),
                    FindingAIHistory.id.desc(),
                )
            )
        ]

        assert [e["id"] for e in all_entries] == expected_ids
        assert set(expected_ids) == set(saved_ids)

        first = history(limit=2, offset=0)
        remaining = history(limit=2, offset=2)

        assert len(first["entries"]) == 2
        assert first["has_more"] is True
        assert len(remaining["entries"]) == 1
        assert remaining["has_more"] is False

        assert [
            e["id"]
            for e in first["entries"] + remaining["entries"]
        ] == expected_ids

        # A different finding must not expose these records.
        other = client.get(
            f"/api/v1/assessments/{assessment_id}"
            f"/findings/{other_finding_id}/ai/history"
        )

        assert other.status_code == 200
        assert other.json()["entries"] == []

        # Reject mismatched assessment and finding identifiers.
        assert client.get(
            f"/api/v1/assessments/{uuid4()}"
            f"/findings/{finding_id}/ai/history"
        ).status_code == 404

        assert client.get(
            f"/api/v1/assessments/{assessment_id}"
            f"/findings/{uuid4()}/ai/history"
        ).status_code == 404

        # An assigned analyst can access the same finding,
        # but cannot see the owner's private interactions.
        authenticate(second_token)

        assert history()["entries"] == []

        response = client.post(
            base + "/ask",
            json={"action": "explain_finding"},
        )

        assert response.status_code == 200, response.text
        assert response.json()["status"] == "answered"

        second_history_id = response.json()["history_id"]

        entries = history()["entries"]

        assert len(entries) == 1
        assert entries[0]["id"] == second_history_id
        assert second_history_id not in saved_ids
        assert count_records() == 4

        authenticate(owner_token)

        assert {
            e["id"] for e in history()["entries"]
        } == set(saved_ids)

        # Failed inference must never create a history record.
        generate.side_effect = OllamaUnavailable("ai_timeout")

        response = client.post(
            base + "/ask",
            json={"action": "suggest_fix"},
        )

        assert response.status_code == 200
        assert response.json()["code"] == "ai_timeout"
        assert count_records() == 4

        # Saved history remains available when AI is disabled.
        monkeypatch.setattr(settings, "ai_enabled", False)

        assert len(history()["entries"]) == 3

        response = client.post(
            base + "/ask",
            json={"action": "explain_finding"},
        )

        assert response.json()["code"] == "ai_disabled"
        assert count_records() == 4

        # Revoking an assignment must remove history access.
        assignment = db.get(
            AssessmentAssignment,
            (assessment_id, second_id),
        )

        assert assignment is not None

        db.delete(assignment)
        db.commit()

        authenticate(second_token)

        assert client.get(
            base + "/history"
        ).status_code == 404

        # Existing history remains intact.
        authenticate(owner_token)

        assert len(history()["entries"]) == 3
        assert count_records() == 4

        # An unauthenticated request cannot retrieve history.
        client.cookies.clear()

        assert client.get(
            base + "/history"
        ).status_code == 401

        # Verify effective runtime database permissions.
        for privilege in (
            "SELECT", "INSERT", "UPDATE",
            "DELETE", "TRUNCATE", "TRIGGER",
        ):
            allowed = db.scalar(text("""
                SELECT has_table_privilege(
                    'uptip_runtime',
                    'public.finding_ai_history',
                    :privilege
                )
            """), {"privilege": privilege})

            assert allowed == (
                privilege in {"SELECT", "INSERT"}
            )

        assert adapter.calls == 1
        assert generate.await_count == 5
