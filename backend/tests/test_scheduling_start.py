"""Actual version-3 scheduling workflow, without execution approvals or evidence."""
from uuid import UUID, uuid4
import pytest
from pydantic import SecretStr
from sqlalchemy import select, func, text, event
from app import scheduling_policy
from app.config import get_settings
from app.models import (Assessment, AssessmentTarget, AssessmentAssignment,
                        AssessmentStartAuthorization, AssessmentStartEvent, BaselineExecutionRequest,
                        ExecutionPolicyVersion, SystemPolicyAuthorizationRecord, AssessmentStartEvidenceRecord)
from app.baseline_maintenance import record_tool_state
from test_assessments import API, add_analyst, sign_in


@pytest.fixture
def prepared(client, db, monkeypatch):
    user = add_analyst(db, 'schedule-owner')
    headers = sign_in(client, user.username)
    monkeypatch.setattr(get_settings(), 'start_review_key', SecretStr('synthetic-review-signing-key-' + 'x' * 40))
    result = client.post(API, headers=headers, json={'name': 'Scheduling assessment'})
    assert result.status_code == 201
    path = API + '/' + result.json()['id']
    record_tool_state(db, 'Nmap', 'enabled', ['ipv4-discovery'])
    db.commit()
    assert client.post(path+'/scope', headers=headers, json={'revision':0,'value':'192.0.2.0/24'}).status_code == 201
    assert client.post(path+'/targets', headers=headers, json={'value':'192.0.2.1'}).status_code == 201
    return path, headers, user


def get_review(client, path):
    r = client.get(path+'/readiness')
    assert r.status_code == 200
    assert r.headers['Cache-Control'] == 'no-store'
    return r.json()


def confirm(client, path, headers, review, key=None):
    return client.post(path+'/start', headers={**headers,'Idempotency-Key':key or str(uuid4())},
        json={'confirmed':True,'review_token':review['review_token'],'mode':review['mode']})


def test_full_start_and_replay_with_no_deployment_records(client, db, prepared):
    path, headers, _ = prepared
    data = get_review(client,path)
    review = data['start_review']
    assert review['confirmation_possible'] and review['mode']=='full'
    assert data['counts']=={'total':1,'eligible':1,'blocked_or_excluded':0}
    assert data['execution_authorized'] is False
    assert review['schema_version']==3 and review['purpose']=='schedule_only'
    activity=review['eligible_activities'][0]
    assert activity['safety_evidence'] is None
    prep=activity['scheduling_preparation']
    assert prep['plan']['arguments']==['-sn'] and prep['units']==1
    for model in (ExecutionPolicyVersion,SystemPolicyAuthorizationRecord,AssessmentStartEvidenceRecord):
        assert db.scalar(select(func.count()).select_from(model))==0
    key=str(uuid4())
    result=confirm(client,path,headers,review,key)
    assert result.status_code==201, result.text
    receipt=result.json()
    assert receipt['lifecycle_status']=='Testing' and receipt['queued_execution_count']==1
    assert receipt['execution_authorized'] is False
    retry=confirm(client,path,headers,review,key)
    assert retry.status_code==200 and retry.json()==receipt
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest))==1
    assert db.scalar(select(func.count()).select_from(AssessmentStartEvent))==1
    overview=client.get(path+'/testing').json()
    assert overview['counts']['queued']==1 and overview['counts']['completed']==0
    assert len(client.get(path+'/testing/executions').json())==1
    from app.nmap_dispatch_authorization import verify_nmap_dispatch_authorization
    decision=verify_nmap_dispatch_authorization(db,execution_request_id=UUID(receipt['queued_execution_ids'][0]))
    assert decision.authorized is False and decision.reason_code=='dispatch_safety_checks_pending'


def test_partial_excludes_outside_and_unsupported_targets(client, db, prepared):
    path,headers,_=prepared
    for value in ('198.51.100.1','192.0.2.0/28'):
        assert client.post(path+'/targets',headers=headers,json={'value':value}).status_code==201
    data=get_review(client,path)
    assert data['counts']=={'total':3,'eligible':1,'blocked_or_excluded':2}
    review=data['start_review']
    assert review['mode']=='partial' and len(review['eligible_activities'])==1
    assert len(review['excluded_targets'])==2
    assert confirm(client,path,headers,review).status_code==201
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest))==1


@pytest.mark.parametrize('change',['scope','target','tool','parameters','prerequisite','policy'])
def test_stale_review_cannot_start(client,db,prepared,monkeypatch,change):
    path,headers,_=prepared
    review=get_review(client,path)['start_review']
    if change=='scope':
        a=db.scalar(select(Assessment));a.scope_revision+=1;db.commit()
    elif change=='target':
        t=db.scalar(select(AssessmentTarget));t.revision+=1;db.commit()
    elif change=='tool':
        record_tool_state(db,'Nmap','disabled',[]);db.commit()
    elif change=='parameters':
        from app.nmap_discovery_profile import NMAP_DISCOVERY_PROFILE
        monkeypatch.setitem(NMAP_DISCOVERY_PROFILE,'arguments',['-sV'])
    elif change=='prerequisite':
        monkeypatch.setattr(scheduling_policy,'REQUIRED_CHECKS',(*scheduling_policy.REQUIRED_CHECKS,'unknown'))
    else:
        monkeypatch.setattr(scheduling_policy,'POLICY_VERSION',2)
    result=confirm(client,path,headers,review)
    assert result.status_code==409
    assert db.scalar(select(Assessment.status))=='Draft'
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest))==0
    assert db.scalar(select(func.count()).select_from(AssessmentStartAuthorization))==0


def test_creator_csrf_and_authentication_checks(client,db,prepared):
    path,headers,_=prepared
    review=get_review(client,path)['start_review']
    assert confirm(client,path,{},review).status_code==403
    other=add_analyst(db,'schedule-assigned')
    db.add(AssessmentAssignment(assessment_id=UUID(path.rsplit('/',1)[1]),analyst_id=other.id));db.commit()
    new_headers=sign_in(client,other.username)
    assert get_review(client,path)['start_review']['confirmation_possible'] is False
    assert confirm(client,path,new_headers,review).status_code==403
    client.cookies.clear()
    assert client.get(path+'/readiness').status_code==401
    assert confirm(client,path,headers,review).status_code==401


def test_audit_failure_rolls_back_queue_and_transition(client,db,engine,prepared):
    path,headers,_=prepared
    review=get_review(client,path)['start_review']
    from sqlalchemy.exc import IntegrityError
    def fail(mapper,connection,target):
        raise IntegrityError('synthetic',None,Exception('synthetic audit failure'))
    event.listen(AssessmentStartEvent,'before_insert',fail)
    try:
        assert confirm(client,path,headers,review).status_code == 503
    finally:
        event.remove(AssessmentStartEvent,'before_insert',fail)
    assert db.scalar(select(Assessment.status))=='Draft'
    assert db.scalar(select(func.count()).select_from(AssessmentStartAuthorization))==0
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest))==0


def test_readiness_is_read_only_and_deterministic(client,db,engine,prepared):
    path,_,_=prepared
    def read_only(conn,cursor,statement,*args):
        assert statement.lstrip().upper().startswith(('SELECT','SAVEPOINT','RELEASE SAVEPOINT','ROLLBACK TO SAVEPOINT'))
    event.listen(engine,'before_cursor_execute',read_only)
    try:
        first=get_review(client,path);second=get_review(client,path)
        assert first['start_review']['snapshot_digest']==second['start_review']['snapshot_digest']
    finally:
        event.remove(engine,'before_cursor_execute',read_only)


def test_expired_review_and_missing_key(client,db,prepared,monkeypatch):
    from app.assessment_start import signature
    import json
    from datetime import datetime,timedelta,timezone
    path,headers,_=prepared
    review=get_review(client,path)['start_review']
    payload=json.loads(bytes.fromhex(review['review_token'].split('.')[0]))
    payload['expires_at']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
    body=json.dumps(payload,sort_keys=True,separators=(',',':'))
    token=client.cookies[get_settings().cookie_name]
    review['review_token']=body.encode().hex()+'.'+signature(get_settings().start_review_key.get_secret_value(),token,body)
    assert confirm(client,path,headers,review).status_code==409
    monkeypatch.setattr(get_settings(),'start_review_key',None)
    assert get_review(client,path)['start_review']['confirmation_possible'] is False


def test_legacy_receipt_replays_but_legacy_review_cannot_create_new_start(client,db,monkeypatch):
    from test_assessment_start import prepare_start_case
    from app import assessment_routes, assessment_readiness
    path,headers,_,_,_=prepare_start_case(client,db,monkeypatch)
    with monkeypatch.context() as legacy:
        legacy.setattr(assessment_routes,'evaluate_readiness',assessment_readiness.evaluate_execution_readiness)
        old_review=get_review(client,path)['start_review']
    assert old_review['schema_version']==2
    # Recompute under the new scheduling policy rejects a formerly reviewed plan.
    assert confirm(client,path,headers,old_review).status_code==409
    key=str(uuid4())
    with monkeypatch.context() as legacy:
        legacy.setattr(assessment_routes,'evaluate_readiness',assessment_readiness.evaluate_execution_readiness)
        old_receipt=confirm(client,path,headers,old_review,key)
    assert old_receipt.status_code==201
    replay=confirm(client,path,headers,old_review,key)
    assert replay.status_code==200 and replay.json()==old_receipt.json()
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest))==1


@pytest.mark.parametrize('state',['unknown','disabled','unavailable'])
def test_unavailable_tool_has_no_confirmable_review(client,db,prepared,state):
    path,_,_=prepared
    record_tool_state(db,'Nmap',state,[]);db.commit()
    data=get_review(client,path)
    assert data['counts']=={'total':1,'eligible':0,'blocked_or_excluded':1}
    assert data['start_review']['confirmation_possible'] is False
    assert data['start_review']['review_token'] is None
    assert len(data['start_review']['excluded_activities'])==1


def test_preparation_tampering_fails_closed(client,db,prepared):
    from copy import deepcopy
    path,_,_=prepared
    prep=get_review(client,path)['start_review']['eligible_activities'][0]['scheduling_preparation']
    for field,value in [('parameter_digest','a'*64),('units',2),('dependencies',[{'unknown':True}]),
                        ('required_capability','untrusted'),('target_value','192.0.2.1 --script vuln')]:
        altered=deepcopy(prep);altered[field]=value
        altered['fingerprint']=scheduling_policy.fingerprint({k:v for k,v in altered.items() if k!='fingerprint'})
        assert not scheduling_policy.validate_preparation(altered),field


@pytest.fixture
def scheduling_concurrency(engine,monkeypatch,request):
    """Own a fresh marked database; never truncate protected application history."""
    from pathlib import Path
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from alembic import command
    from alembic.config import Config
    from fastapi.testclient import TestClient
    from app.database import get_db
    from app.main import create_app
    name='uptip_test_schedule_'+uuid4().hex
    admin=create_engine(engine.url.set(database='postgres'),isolation_level='AUTOCOMMIT')
    with admin.connect() as c:
        # The source engine has already passed the explicit disposable identity guard.
        c.execute(text(f'CREATE DATABASE "{name}"'))
        c.execute(text(f"COMMENT ON DATABASE \"{name}\" IS 'UPTIP disposable scheduling concurrency database'"))
    dedicated=create_engine(engine.url.set(database=name))
    settings=get_settings()
    try:
        with dedicated.connect() as c:
            identity=c.execute(text("SELECT current_database(), shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()")).one_or_none()
            if identity != (name,'UPTIP disposable scheduling concurrency database'):
                raise RuntimeError('Disposable scheduling database identity could not be verified')
        monkeypatch.setattr(settings,'migration_database_url',dedicated.url.render_as_string(hide_password=False))
        config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
        config.set_main_option('script_location',str(Path(__file__).resolve().parents[1]/'migrations'))
        command.upgrade(config,'0017')
        factory=sessionmaker(dedicated,expire_on_commit=False)
        app=create_app()
        def independent_db():
            with factory() as session:
                yield session
        app.dependency_overrides[get_db]=independent_db
        with factory() as db, TestClient(app,base_url='https://testserver') as c:
            c.headers['Origin']='https://testserver'
            if getattr(request,'param',None)=='empty':
                yield app,factory,None,None,{}
            else:
                result=prepared.__wrapped__(c,db,monkeypatch)
                reviewed=get_review(c,result[0])['start_review']
                db.rollback()
                yield app,factory,result,reviewed,dict(c.cookies)
    finally:
        dedicated.dispose()
        with admin.connect() as c:
            c.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.mark.parametrize('edit,same_key',[('none',True),('none',False),('scope',True),('target',True)])
def test_scheduling_concurrency(scheduling_concurrency,edit,same_key):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from fastapi.testclient import TestClient
    app,factory,(path,headers,_),review,cookies=scheduling_concurrency
    barrier=Barrier(2 if edit=='none' else 3)
    key=str(uuid4())
    def send(kind,request_key=None):
        with TestClient(app,base_url='https://testserver',cookies=cookies) as c:
            c.headers['Origin']='https://testserver'
            barrier.wait(timeout=10)
            if kind=='start':
                return confirm(c,path,headers,review,request_key).status_code
            if kind=='scope':
                return c.post(path+'/scope',headers=headers,json={'revision':1,'value':'198.51.100.0/24'}).status_code
            with factory() as db:
                target=db.scalar(select(AssessmentTarget))
                tid=str(target.id)
            return c.patch(path+'/targets/'+tid,headers=headers,json={'revision':1,'value':'192.0.2.2'}).status_code
    with ThreadPoolExecutor(max_workers=3) as pool:
        starts=[pool.submit(send,'start',key),
                pool.submit(send,'start',key if same_key else str(uuid4()))]
        edited=pool.submit(send,edit) if edit!='none' else None
        statuses=sorted(job.result(timeout=20) for job in starts)
        edit_status=edited.result(timeout=20) if edited else None
    with factory() as db:
        count=db.scalar(select(func.count()).select_from(BaselineExecutionRequest))
        if edit_status in (200,201):
            assert statuses==[409,409] and count==0
            assert db.scalar(select(Assessment.status))=='Draft'
        else:
            assert edit_status in (None,403)
            assert statuses==([200,201] if same_key else [201,409]) and count==1
            assert db.scalar(select(func.count()).select_from(AssessmentStartEvent))==1


def test_scheduling_does_not_call_scanners_dns_or_network(client,db,prepared,monkeypatch):
    import socket
    import subprocess
    path,headers,_=prepared
    def forbidden(*args,**kwargs):
        pytest.fail('Scheduling attempted a scanner, DNS, subprocess or network call')
    with monkeypatch.context() as guard:
        guard.setattr(socket,'getaddrinfo',forbidden)
        guard.setattr(socket.socket,'connect',forbidden)
        guard.setattr(subprocess,'Popen',forbidden)
        review=get_review(client,path)['start_review']
        assert confirm(client,path,headers,review).status_code==201


def test_queue_failure_rolls_back_all_records(client,db,engine,prepared):
    from sqlalchemy.exc import SQLAlchemyError
    path,headers,_=prepared
    review=get_review(client,path)['start_review']
    def fail(conn,cursor,statement,*args):
        if statement.startswith('INSERT INTO baseline_execution_requests'):
            raise SQLAlchemyError('Synthetic queue failure')
    event.listen(engine,'before_cursor_execute',fail)
    try:
        assert confirm(client,path,headers,review).status_code==503
    finally:
        event.remove(engine,'before_cursor_execute',fail)
    assert db.scalar(select(Assessment.status))=='Draft'
    for model in (AssessmentStartAuthorization,AssessmentStartEvent,BaselineExecutionRequest):
        assert db.scalar(select(func.count()).select_from(model))==0


@pytest.mark.parametrize('insert',[False,True])
def test_scheduling_tool_writer_waits_for_confirmation_commit(scheduling_concurrency,insert):
    from concurrent.futures import ThreadPoolExecutor
    from queue import Queue
    from threading import Event
    from time import monotonic
    from fastapi.testclient import TestClient
    app,factory,(path,headers,_),review,cookies=scheduling_concurrency
    engine=factory.kw['bind']
    pid=Queue()
    future=None
    tool='OWASP ZAP' if insert else 'Nmap'

    def write_tool():
        with factory.begin() as writer:
            pid.put(writer.scalar(text('SELECT pg_backend_pid()')))
            record_tool_state(writer,tool,'disabled',[])

    with ThreadPoolExecutor(max_workers=1) as pool:
        def check_lock(conn,cursor,statement,*args):
            nonlocal future
            if not statement.startswith('INSERT INTO assessment_start_authorizations'):
                return
            future=pool.submit(write_tool)
            writer_pid=pid.get(timeout=5)
            with engine.connect() as observer:
                deadline=monotonic()+5
                while monotonic()<deadline:
                    observer.execute(text('SELECT pg_stat_clear_snapshot()'))
                    waiting=observer.scalar(text(
                        "SELECT wait_event_type='Lock' FROM pg_stat_activity WHERE pid=:pid"
                    ),{'pid':writer_pid})
                    if waiting:
                        assert not future.done()
                        return
                    Event().wait(0.02)
            pytest.fail('Tool writer did not wait for scheduling confirmation commit')

        event.listen(engine,'before_cursor_execute',check_lock)
        try:
            with TestClient(app,base_url='https://testserver',cookies=cookies) as c:
                c.headers['Origin']='https://testserver'
                result=confirm(c,path,headers,review)
        finally:
            event.remove(engine,'before_cursor_execute',check_lock)
        assert result.status_code==201,result.text
        assert future is not None
        future.result(timeout=5)
    with factory() as db:
        from app.models import BaselineToolState
        state=db.get(BaselineToolState,tool)
        assert state.state=='disabled' and state.revision==(1 if insert else 2)
        stored=db.scalar(select(AssessmentStartAuthorization))
        assert stored.snapshot['eligible_activities'][0]['scheduling_preparation']['tool_revision']==1
        assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest))==1


def test_testing_overview_stays_on_one_snapshot_during_scheduling(scheduling_concurrency):
    from fastapi.testclient import TestClient
    app,factory,(path,headers,_),review,cookies=scheduling_concurrency
    engine=factory.kw['bind']
    started=False
    with TestClient(app,base_url='https://testserver',cookies=cookies) as writer:
        writer.headers['Origin']='https://testserver'
        def start_after_overview_select(conn,cursor,statement,*args):
            nonlocal started
            if started or 'LEFT OUTER JOIN baseline_execution_requests' not in statement:
                return
            started=True
            result=confirm(writer,path,headers,review)
            assert result.status_code==201,result.text
        event.listen(engine,'after_cursor_execute',start_after_overview_select)
        try:
            with TestClient(app,base_url='https://testserver',cookies=cookies) as reader:
                before=reader.get(path+'/testing').json()
        finally:
            event.remove(engine,'after_cursor_execute',start_after_overview_select)
        assert started
        assert before['lifecycle_status']=='Draft' and before['counts']['total']==0
        assert before['authorization_scope']['authorization_id'] is None
        after=writer.get(path+'/testing').json()
        assert after['lifecycle_status']=='Testing' and after['counts']['queued']==1
        assert after['authorization_scope']['authorization_id'] is not None


@pytest.mark.parametrize('scheduling_concurrency',['empty'],indirect=True)
@pytest.mark.parametrize('scenario',['creation','target'])
def test_existing_creation_and_target_duplicate_races(scheduling_concurrency,monkeypatch,scenario):
    """Execute original unchanged regressions on committed, isolated sessions."""
    from fastapi.testclient import TestClient
    from test_assessments import test_concurrent_same_key_creates_one_draft_and_event
    from test_targets import test_concurrent_normalized_duplicates_create_one_target
    app,factory,_,_,_=scheduling_concurrency
    # Original tests construct worker apps themselves. Keep every worker on
    # this fresh marked database, never the configured development database.
    monkeypatch.setattr('test_assessments.create_app',lambda:app)
    monkeypatch.setattr('test_targets.create_app',lambda:app)
    with factory() as db,TestClient(app,base_url='https://testserver') as c:
        c.headers['Origin']='https://testserver'
        if scenario=='creation':
            test_concurrent_same_key_creates_one_draft_and_event(c,db)
        else:
            test_concurrent_normalized_duplicates_create_one_target(c,db)


def test_draft_survives_migration_cycle_and_testing_prevents_downgrade(scheduling_concurrency):
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from sqlalchemy.exc import DBAPIError
    from fastapi.testclient import TestClient
    app,factory,(path,headers,_),_,cookies=scheduling_concurrency
    engine=factory.kw['bind']
    config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    config.set_main_option('script_location',str(Path(__file__).resolve().parents[1]/'migrations'))
    # No Start/approval/evidence history exists; keep Draft scope and targets.
    command.downgrade(config,'0008')
    command.upgrade(config,'0017')
    with factory() as db:
        assert db.scalar(text('SELECT version_num FROM alembic_version'))=='0017'
        assert db.scalar(select(Assessment.status))=='Draft'
        assert db.scalar(select(func.count()).select_from(AssessmentTarget))==1
    with TestClient(app,base_url='https://testserver',cookies=cookies) as c:
        c.headers['Origin']='https://testserver'
        review=get_review(c,path)['start_review']
        assert confirm(c,path,headers,review).status_code==201
    # Entire failed downgrade must roll back, retaining schema and history.
    with pytest.raises(DBAPIError,match='Cannot downgrade'):
        command.downgrade(config,'0011')
    with factory() as db:
        assert db.scalar(text('SELECT version_num FROM alembic_version'))=='0017'
        assert db.scalar(select(Assessment.status))=='Testing'
        for model in (AssessmentStartAuthorization,AssessmentStartEvent,BaselineExecutionRequest):
            assert db.scalar(select(func.count()).select_from(model))==1
