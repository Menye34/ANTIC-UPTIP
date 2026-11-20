"""Synthetic persistence fixtures only: never scanners or operational databases."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, inspect, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import DBAPIError

from app.models import (Assessment, BaselineExecutionRequest, ExecutionAttempt, ScannerEvidence,
                        ResultProcessingOutcome, SecurityObservation, ExecutionEvent)
from test_scheduling_start import prepared, get_review, confirm, scheduling_concurrency  # noqa: F401



@pytest.fixture
def db(engine):
    """Owner-role session for synthetic persistence tests only."""
    from dotenv import dotenv_values
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url
    from sqlalchemy.orm import sessionmaker

    import os
    values = dotenv_values(".env")
    runtime_raw = os.environ.get("UPTIP_DATABASE_URL") or values.get("UPTIP_DATABASE_URL")
    owner_raw = os.environ.get("UPTIP_MIGRATION_DATABASE_URL") or values.get("UPTIP_MIGRATION_DATABASE_URL")

    if not runtime_raw or not owner_raw:
        pytest.fail("Missing database configuration for persistence tests")

    runtime_url = make_url(runtime_raw)
    owner_url = make_url(owner_raw)

    if not (
        runtime_url.drivername == owner_url.drivername == "postgresql+psycopg"
        and runtime_url.username == "uptip_runtime"
        and owner_url.username == "uptip"
        and runtime_url.database == owner_url.database
        and runtime_url.database in ("uptip", "uptip_test_readiness_fix")
        and runtime_url.host == owner_url.host == "127.0.0.1"
        and runtime_url.port == owner_url.port
        and (runtime_url.port in (None, 5432) or os.environ.get('UPTIP_DISPOSABLE_ADMIN_URL'))
        and not runtime_url.query
        and not owner_url.query
    ):
        pytest.fail("Unsafe persistence-test database configuration")

    if os.environ.get('UPTIP_DISPOSABLE_ADMIN_URL'):
        from disposable_postgres import scheduling_database
        verify, _, _ = scheduling_database(
            'uptip_test_schedule_' + uuid4().hex, os.environ['UPTIP_DISPOSABLE_ADMIN_URL'],
            owner_raw, runtime_raw, engine.url)
        verify('verify')

    test_url = owner_url.set(database="uptip_test_readiness_fix")
    test_engine = create_engine(test_url, hide_parameters=True)

    try:
        with test_engine.connect() as connection:
            identity = connection.execute(text("""
                SELECT current_database(),
                       shobj_description(oid, 'pg_database')
                FROM pg_database
                WHERE datname = current_database()
            """)).one()

            if identity != (
                "uptip_test_readiness_fix",
                "UPTIP disposable integration test database",
            ):
                pytest.fail("Persistence-test database safety verification failed")

            connection.rollback()  # End the read-only identity-check transaction.
            transaction = connection.begin()

            try:
                factory = sessionmaker(
                    bind=connection,
                    expire_on_commit=False,
                    join_transaction_mode="create_savepoint",
                )
                with factory() as session:
                    yield session
            finally:
                if transaction.is_active:
                    transaction.rollback()
    finally:
        test_engine.dispose()

@pytest.fixture
def queued(client, db, prepared):
    path, headers, _ = prepared
    receipt = confirm(client,path,headers,get_review(client,path)['start_review'])
    assert receipt.status_code == 201
    return db.get(BaselineExecutionRequest,UUID(receipt.json()['queued_execution_ids'][0]))


def attempt_for(db,q,**changes):
    now=datetime.now(timezone.utc)
    prep=q.authorized_activity['scheduling_preparation']
    value=dict(request_id=q.id,assessment_id=q.assessment_id,target_id=q.target_id,
               attempt_number=1,claim_id=uuid4(),worker_id='synthetic-worker',
               claimed_at=now,heartbeat_at=now,lease_expires_at=now+timedelta(minutes=1),
               status='Claimed',tool=q.tool,profile_id=q.profile_id,profile_version=q.profile_version,
               parameters=prep['plan'],parameter_digest=prep['parameter_digest'],timeout_seconds=30)
    a=ExecutionAttempt(**{**value,**changes});db.add(a);db.flush();return a


def evidence_for(db,a,**changes):
    # Synthetic Nmap XML; never represented as genuine assessment output.
    content=b'<nmaprun><host><status state="up"/></host></nmaprun>'
    data=dict(attempt_id=a.id,request_id=a.request_id,assessment_id=a.assessment_id,target_id=a.target_id,
              tool='Nmap',format='nmap-xml',content=content,content_hash=sha256(content).hexdigest(),
              size_bytes=len(content),is_partial=False,collected_at=datetime.now(timezone.utc))
    e=ScannerEvidence(**{**data,**changes});db.add(e);db.flush();return e


def processing_for(db,e):
    p=ResultProcessingOutcome(evidence_id=e.id,attempt_id=e.attempt_id,request_id=e.request_id,
        assessment_id=e.assessment_id,target_id=e.target_id,processor='synthetic-host-parser',
        processor_version='1',run_number=1,operation_id=uuid4(),status='Pending',is_partial=e.is_partial)
    db.add(p);db.flush();p.status='Processing';p.started_at=datetime.now(timezone.utc);db.flush();return p


def observation_for(db,p,**changes):
    now=datetime.now(timezone.utc)
    data=dict(processing_id=p.id,evidence_id=p.evidence_id,attempt_id=p.attempt_id,request_id=p.request_id,
              assessment_id=p.assessment_id,target_id=p.target_id,observation_type='host_discovery',
              data={'address':'192.0.2.1','status':'up'},deduplication_key='a'*64,
              collected_at=now,processed_at=now,is_partial=p.is_partial)
    o=SecurityObservation(**{**data,**changes});db.add(o);db.flush();return o


def test_full_persistence_and_processing_completion(db,queued):
    a=attempt_for(db,queued);e=evidence_for(db,a);p=processing_for(db,e);o=observation_for(db,p)
    ev=ExecutionEvent(request_id=queued.id,assessment_id=queued.assessment_id,target_id=queued.target_id,
         attempt_id=a.id,operation_id=uuid4(),event_type='evidence_persisted',system_origin='synthetic-test',
         reason_code='test_only',details={'evidence_id':str(e.id)},occurred_at=datetime.now(timezone.utc))
    db.add(ev);db.flush()
    assert db.get(ScannerEvidence,e.id).content==e.content
    assert db.get(SecurityObservation,o.id).request_id==queued.id
    assert db.get(ExecutionEvent,ev.id).attempt_id==a.id
    a.status='Running';a.started_at=datetime.now(timezone.utc);a.reason_code='started';db.flush()
    a.status='Succeeded';a.exit_code=0;a.reason_code='scanner_succeeded'
    a.terminated_at=a.finished_at=datetime.now(timezone.utc);db.flush()
    with pytest.raises(DBAPIError):
        with db.begin_nested():
            queued.status='Completed';db.flush()
    p.status='Succeeded';p.observation_count=1;p.finished_at=datetime.now(timezone.utc);db.flush()
    queued.status='Completed';db.flush()
    assert db.get(BaselineExecutionRequest,queued.id).status=='Completed'
    with pytest.raises(DBAPIError,match='Completed execution processing is sealed'):
        with db.begin_nested():
            db.add(ResultProcessingOutcome(evidence_id=e.id,attempt_id=a.id,request_id=queued.id,
                assessment_id=queued.assessment_id,target_id=queued.target_id,processor=p.processor,
                processor_version=p.processor_version,run_number=2,operation_id=uuid4(),is_partial=False))
            db.flush()


@pytest.mark.parametrize('change',[{'status':'invented'},{'assessment_id':uuid4()},
    {'target_id':uuid4()},{'request_id':uuid4()},{'profile_version':3},
    {'parameters':{'target':'192.0.2.1','arguments':['-sV']}},{'parameter_digest':'b'*64},
    {'timeout_seconds':0},{'attempt_number':0}])
def test_invalid_attempts_fail_closed(db,queued,change):
    with pytest.raises(DBAPIError):
        with db.begin_nested():attempt_for(db,queued,**change)


def test_expired_lease_and_recovery_do_not_release_active_uniqueness(db,queued):
    old=datetime.now(timezone.utc)-timedelta(hours=1)
    a=attempt_for(db,queued,claimed_at=old,heartbeat_at=old,lease_expires_at=old+timedelta(minutes=1))
    for state in ('Claimed','RecoveryRequired'):
        a.status=state
        if state=='RecoveryRequired':a.reason_code='process_state_unknown'
        db.flush()
        with pytest.raises(DBAPIError):
            with db.begin_nested():attempt_for(db,queued,attempt_number=2)
    a.status='Failed';a.finished_at=datetime.now(timezone.utc);a.reason_code='verified_no_process';db.flush()
    assert attempt_for(db,queued,attempt_number=2).id != a.id


def test_started_attempt_requires_verified_termination_before_terminal(db,queued):
    a=attempt_for(db,queued);a.status='Running';a.started_at=datetime.now(timezone.utc);a.reason_code='started';db.flush()
    with pytest.raises(DBAPIError):
        with db.begin_nested():
            a.status='Failed';a.finished_at=datetime.now(timezone.utc);db.flush()


@pytest.mark.parametrize('change',[{'content_hash':'b'*64},{'size_bytes':2},
    {'format':'unstructured'},{'tool':'other'},{'assessment_id':uuid4()},
    {'content':None,'storage_key':'https://user:secret@example.test/file'},
    {'content':None,'storage_key':'evidence/../secret'},
    {'content':b'x'*1048577,'size_bytes':1048577,'content_hash':sha256(b'x'*1048577).hexdigest()}])
def test_evidence_integrity_and_safe_storage(db,queued,change):
    a=attempt_for(db,queued)
    with pytest.raises(DBAPIError):
        with db.begin_nested():evidence_for(db,a,**change)


def test_external_storage_reference_and_partial_failure_preserve_results(db,queued):
    a=attempt_for(db,queued)
    e=evidence_for(db,a,content=None,storage_key='evidence/test/opaque_object',size_bytes=2000000,is_partial=True)
    p=processing_for(db,e);o=observation_for(db,p)
    p.status='Failed';p.error_code='malformed_xml';p.safe_diagnostic='Synthetic bounded diagnostic.'
    p.observation_count=1;p.finished_at=datetime.now(timezone.utc);db.flush()
    assert db.get(SecurityObservation,o.id).is_partial
    assert db.get(ScannerEvidence,e.id).storage_key=='evidence/test/opaque_object'
    with pytest.raises(DBAPIError):
        with db.begin_nested():queued.status='Completed';db.flush()


@pytest.mark.parametrize('change',[{'observation_type':'open_port'},
    {'data':{'address':'192.0.2.1','status':'up','ports':[80]}},
    {'data':{'address':'192.0.2.2','status':'up'}},{'assessment_id':uuid4()},
    {'target_id':uuid4()},{'evidence_id':uuid4()},{'request_id':uuid4()}])
def test_observation_scope_and_discovery_semantics(db,queued,change):
    p=processing_for(db,evidence_for(db,attempt_for(db,queued)))
    with pytest.raises(DBAPIError):
        with db.begin_nested():observation_for(db,p,**change)


def test_observation_idempotency_and_processing_counts(db,queued):
    p=processing_for(db,evidence_for(db,attempt_for(db,queued)));o=observation_for(db,p)
    values={c.name:getattr(o,c.name) for c in SecurityObservation.__table__.columns};values['id']=uuid4()
    result=db.execute(insert(SecurityObservation).values(**values).on_conflict_do_nothing(
        constraint='uq_observation_deduplication').returning(SecurityObservation.id))
    assert result.scalar_one_or_none() is None
    with pytest.raises(DBAPIError):
        with db.begin_nested():
            p.status='Succeeded';p.observation_count=5;p.finished_at=datetime.now(timezone.utc);db.flush()
    assert db.scalar(select(func.count()).select_from(SecurityObservation))==1


@pytest.mark.parametrize('table',['scanner_evidence','security_observations','execution_events','execution_attempts','result_processing_outcomes'])
def test_history_cannot_be_truncated(db,queued,table):
    with pytest.raises(DBAPIError):
        with db.begin_nested():db.execute(text(f'TRUNCATE {table} CASCADE'))


def test_evidence_observation_and_events_are_append_only(db,queued):
    a=attempt_for(db,queued);e=evidence_for(db,a);p=processing_for(db,e);observation_for(db,p)
    db.add(ExecutionEvent(request_id=queued.id,assessment_id=queued.assessment_id,target_id=queued.target_id,
        operation_id=uuid4(),event_type='evidence_persisted',system_origin='synthetic',reason_code='test',details={},occurred_at=datetime.now(timezone.utc)))
    db.flush()
    for table in ('scanner_evidence','security_observations','execution_events'):
        for command in (f'DELETE FROM {table}',f'UPDATE {table} SET id=id'):
            with pytest.raises(DBAPIError):
                with db.begin_nested():db.execute(text(command))


def test_constraints_indexes_and_existing_authorization_immutability(db,queued):
    inspector=inspect(db.connection())
    assert 'uq_attempt_active' in {x['name'] for x in inspector.get_indexes('execution_attempts')}
    assert len(inspector.get_foreign_keys('security_observations'))==1
    for statement in ('UPDATE assessment_start_authorizations SET mode=mode','DELETE FROM assessment_start_events'):
        with pytest.raises(DBAPIError):
            with db.begin_nested():db.execute(text(statement))


@pytest.mark.parametrize('scheduling_concurrency', ['migration_0017'], indirect=True)
def test_0018_preserves_queued_requests_metadata_and_refuses_history_downgrade(scheduling_concurrency):
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from app.database import Base
    app,factory,(path,headers,_),review,cookies=scheduling_concurrency
    from fastapi.testclient import TestClient
    with TestClient(app,base_url='https://testserver',cookies=cookies) as c:
        c.headers['Origin']='https://testserver'
        receipt=confirm(c,path,headers,review)
        assert receipt.status_code==201
    engine=factory.kw['bind']
    config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    config.set_main_option('script_location',str(Path(__file__).resolve().parents[1]/'migrations'))
    with factory() as db:
        q=db.scalar(select(BaselineExecutionRequest))
        original=(q.id,q.status,q.authorized_activity,q.authorization_id)
        assert db.scalar(text('SELECT version_num FROM alembic_version'))=='0017'
    command.upgrade(config,'0018')
    with engine.connect() as conn:
        # Compare this historical revision only with its own models. The full
        # current metadata is checked after upgrade to head by Phase 3 tests.
        from sqlalchemy import MetaData
        historical = MetaData()
        later_tables = {'service_discovery_consents', 'service_discovery_revocations', 'recommendation_review_events', 'recommendation_authorization_records', 'recommendation_execution_requests',
                        'testing_recommendation_decisions', 'testing_completion_events'}
        for table in Base.metadata.sorted_tables:
            if table.name not in later_tables:
                table.to_metadata(historical)
        assert compare_metadata(MigrationContext.configure(conn),historical)==[]
        assert conn.scalar(text('SELECT version_num FROM alembic_version'))=='0018'
    # Empty persistence downgrade is safe even with a pre-existing queue.
    command.downgrade(config,'0017');command.upgrade(config,'0018')
    with factory() as db:
        q=db.scalar(select(BaselineExecutionRequest))
        assert (q.id,q.status,q.authorized_activity,q.authorization_id)==original
        a=attempt_for(db,q);db.commit()
        aid=a.id
    with pytest.raises(DBAPIError,match='Cannot downgrade with execution persistence history'):
        command.downgrade(config,'0017')
    with factory() as db:
        assert db.scalar(text('SELECT version_num FROM alembic_version'))=='0018'
        assert db.get(ExecutionAttempt,aid) is not None


def test_cancellation_and_terminal_records_preserve_history(db,queued):
    a=attempt_for(db,queued)
    now=datetime.now(timezone.utc)
    a.cancellation_requested_at=now;a.cancellation_source='system';a.cancellation_reason='scope_invalid'
    a.status='Cancelled';a.reason_code='cancelled_before_launch';a.finished_at=now;db.flush()
    for column,value in [('worker_id','different'),('status','Claimed')]:
        with pytest.raises(DBAPIError):
            with db.begin_nested():setattr(a,column,value);db.flush()
    e=evidence_for(db,a,is_partial=True);p=processing_for(db,e)
    p.status='Interrupted';p.error_code='interrupted';p.finished_at=datetime.now(timezone.utc);db.flush()
    with pytest.raises(DBAPIError):
        with db.begin_nested():p.status='Processing';db.flush()


def test_failed_persistence_transaction_keeps_no_partial_batch(db,queued):
    with pytest.raises(DBAPIError):
        with db.begin_nested():
            a=attempt_for(db,queued);e=evidence_for(db,a);p=processing_for(db,e)
            observation_for(db,p,request_id=uuid4())
    for model in (ExecutionAttempt,ScannerEvidence,ResultProcessingOutcome,SecurityObservation):
        assert db.scalar(select(func.count()).select_from(model))==0
    assert db.get(BaselineExecutionRequest,queued.id).status=='Queued'


def test_pending_reprocessing_does_not_allow_completed(db,queued):
    a=attempt_for(db,queued);e=evidence_for(db,a);p=processing_for(db,e)
    a.status='Running';a.started_at=datetime.now(timezone.utc);a.reason_code='started';db.flush()
    a.status='Succeeded';a.exit_code=0;a.reason_code='finished';a.terminated_at=a.finished_at=datetime.now(timezone.utc);db.flush()
    p.status='Succeeded';p.finished_at=datetime.now(timezone.utc);db.flush()
    newer=ResultProcessingOutcome(evidence_id=e.id,attempt_id=a.id,request_id=queued.id,
        assessment_id=queued.assessment_id,target_id=queued.target_id,processor=p.processor,
        processor_version=p.processor_version,run_number=2,operation_id=uuid4(),is_partial=False)
    db.add(newer);db.flush()
    with pytest.raises(DBAPIError):
        with db.begin_nested():queued.status='Completed';db.flush()


def test_concurrent_attempts_allow_one_active_owner(scheduling_concurrency):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from fastapi.testclient import TestClient
    app,factory,(path,headers,_),review,cookies=scheduling_concurrency
    with TestClient(app,base_url='https://testserver',cookies=cookies) as c:
        c.headers['Origin']='https://testserver'
        result=confirm(c,path,headers,review);assert result.status_code==201
    config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    config.set_main_option('script_location',str(Path(__file__).resolve().parents[1]/'migrations'))
    command.upgrade(config,'0018')
    barrier=Barrier(2)
    def claim(number):
        try:
            with factory.begin() as db:
                q=db.scalar(select(BaselineExecutionRequest));barrier.wait(timeout=10)
                attempt_for(db,q,attempt_number=number)
            return 'created'
        except DBAPIError:return 'conflict'
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(claim,[1,2]))==['conflict','created']
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(ExecutionAttempt))==1


def test_existing_runtime_role_cannot_destroy_execution_history(db):
    for table in ('execution_attempts','scanner_evidence','result_processing_outcomes','security_observations','execution_events'):
        assert db.scalar(text('SELECT has_table_privilege(:role,:table,:priv)'),
                         {'role':'uptip_runtime','table':table,'priv':'TRUNCATE'}) is False


@pytest.mark.parametrize('scheduling_concurrency',['empty'],indirect=True)
def test_existing_baseline_resolution_with_committed_isolated_sessions(scheduling_concurrency,monkeypatch):
    """Original regression needs committed targets visible to maintenance threads."""
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from fastapi.testclient import TestClient
    from test_baseline_resolution import test_resolution_lifecycle
    app,factory,_,_,_=scheduling_concurrency
    config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    config.set_main_option('script_location',str(Path(__file__).resolve().parents[1]/'migrations'))
    command.upgrade(config,'0018')
    with factory() as db,TestClient(app,base_url='https://testserver') as c:
        c.headers['Origin']='https://testserver'
        test_resolution_lifecycle(c,db,factory.kw['bind'],monkeypatch)


def test_persistence_does_not_enable_dispatch_or_runtime_authorization(db,queued,monkeypatch):
    import socket
    import subprocess
    from app.nmap_assessment_binding import BoundNmapPlan
    from app.nmap_execution_binding import NmapExecutionPlan
    from app.nmap_dispatch_authorization import verify_nmap_dispatch_authorization
    from app.nmap_runtime_state_provider import load_nmap_runtime_state
    attempt_for(db,queued)
    prep=queued.authorized_activity['scheduling_preparation']
    plan=NmapExecutionPlan(**{**prep['plan'],'arguments':tuple(prep['plan']['arguments'])})
    bound=BoundNmapPlan(assessment_id=queued.assessment_id,target_id=queued.target_id,
        assessment_scope_revision=prep['scope_revision'],target_revision=prep['target_revision'],
        evaluation_id=UUID(prep['evaluation_id']),evaluation_fingerprint=prep['evaluation_fingerprint'],
        policy_digest=prep['scheduling_policy']['digest'],plan=plan)
    def forbidden(*args,**kwargs):raise AssertionError('Persistence attempted an external execution')
    with monkeypatch.context() as guard:
        guard.setattr(socket,'getaddrinfo',forbidden)
        guard.setattr(socket.socket,'connect',forbidden)
        guard.setattr(subprocess,'Popen',forbidden)
        decision=verify_nmap_dispatch_authorization(db,execution_request_id=queued.id)
        state=load_nmap_runtime_state(db,bound_plan=bound,execution_request_id=queued.id)
    assert decision.authorized is False and decision.reason_code=='worker_ownership_required'
    assert state.authorization_valid is False
    assert db.scalar(select(Assessment.status).where(Assessment.id == queued.assessment_id)) == 'Testing'
    assert db.get(BaselineExecutionRequest,queued.id).status=='Queued'


def test_existing_cross_assessment_identifiers_cannot_be_mixed(client,db,queued,prepared):
    from test_assessments import API
    _,headers,_=prepared
    headers={**headers,'Idempotency-Key':str(uuid4())}
    created=client.post(API,headers=headers,json={'name':'Other assessment binding test'})
    assert created.status_code==201
    path=API+'/'+created.json()['id']
    assert client.post(path+'/scope',headers=headers,json={'revision':0,'value':'192.0.2.0/24'}).status_code==201
    assert client.post(path+'/targets',headers=headers,json={'value':'192.0.2.1'}).status_code==201
    result=confirm(client,path,headers,get_review(client,path)['start_review']);assert result.status_code==201
    other=db.get(BaselineExecutionRequest,UUID(result.json()['queued_execution_ids'][0]))
    first_attempt=attempt_for(db,queued);attempt_for(db,other)
    with pytest.raises(DBAPIError,match='fk_evidence_attempt_binding'):
        with db.begin_nested():
            evidence_for(db,first_attempt,request_id=other.id,assessment_id=other.assessment_id,target_id=other.target_id)
    p=processing_for(db,evidence_for(db,first_attempt))
    with pytest.raises(DBAPIError,match='fk_observation_processing_binding'):
        with db.begin_nested():
            observation_for(db,p,request_id=other.id,assessment_id=other.assessment_id,target_id=other.target_id)


@pytest.mark.parametrize('scheduling_concurrency',['empty'],indirect=True)
@pytest.mark.parametrize('scenario',['password-race','baseline-migration','start-scope','tool-update','tool-insert'])
def test_remaining_legacy_regressions_on_isolated_current_schema(scheduling_concurrency,monkeypatch,scenario):
    """Keep original assertions; replace only incompatible session plumbing."""
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from fastapi.testclient import TestClient
    app,factory,_,_,_=scheduling_concurrency
    engine=factory.kw['bind']
    config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    config.set_main_option('script_location',str(Path(__file__).resolve().parents[1]/'migrations'))
    command.upgrade(config,'0018')
    with factory() as db,TestClient(app,base_url='https://testserver') as c:
        c.headers['Origin']='https://testserver'
        if scenario=='password-race':
            from test_password_change import TEMPORARY,test_concurrent_changes_accept_only_one
            from test_assessments import add_analyst
            from app.security import hasher
            user=add_analyst(db,'analyst-01');user.password_hash=hasher.hash(TEMPORARY)
            user.password_change_required=True;db.commit()
            test_concurrent_changes_accept_only_one(c,user,engine)
        elif scenario=='baseline-migration':
            from test_baseline_resolution import test_baseline_migration_round_trip_preserves_targets
            test_baseline_migration_round_trip_preserves_targets(c,db,engine)
        else:
            from test_assessment_start import test_concurrent_start_and_scope_edit,test_tool_writer_waits_for_start_commit
            case=(*prepared.__wrapped__(c,db,monkeypatch),None,None)
            if scenario=='start-scope':test_concurrent_start_and_scope_edit(c,db,case)
            else:test_tool_writer_waits_for_start_commit(c,db,case,scenario=='tool-insert')
