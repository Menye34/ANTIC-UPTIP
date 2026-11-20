"""Synthetic XML and fake scanner only; guarded disposable PostgreSQL."""
from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4
from contextlib import nullcontext
import pytest
from sqlalchemy import select, text, func
from sqlalchemy.exc import DBAPIError
from app.nmap_service_profile import plan, validate_plan
from app.execution_results import parse_services, EvidenceStore, process
from app.dispatch_verification import verify, DispatchDenied
from app.execution_orchestration import ExecutionRunner, claim
from app.nmap_adapter import ScanOutcome
from app.models import (BaselineExecutionRequest, ServiceDiscoveryConsent, ServiceDiscoveryRevocation,
                        ExecutionAttempt, SecurityObservation, BaselineToolState, Assessment, AssessmentTarget)
from app.baseline_maintenance import record_tool_state
from test_scheduling_start import prepared, get_review, confirm, scheduling_concurrency  # noqa: F401
from test_execution_orchestration import BorrowedFactory


def xml(ports=None, target='192.0.2.1'):
    ports = ports if ports is not None else [(80, 'open', 'http', 'probed', None), (443, 'open', 'http', 'probed', 'ssl')]
    nodes = ''.join(f'<port protocol="tcp" portid="{p}"><state state="{state}"/>'
        f'<service name="{name}" method="{method}" conf="10" version="1.2"'
        + (f' tunnel="{tunnel}"' if tunnel else '') + '/></port>' for p,state,name,method,tunnel in ports)
    return (f'<nmaprun scanner="nmap"><host><status state="up"/><address addr="{target}" addrtype="ipv4"/>'
            f'<ports>{nodes}</ports></host><runstats><finished exit="success"/>'
            '<hosts total="1" up="1" down="0"/></runstats></nmaprun>').encode()


@pytest.mark.parametrize('ports', [[], [0], [65536], [True], [80,80], list(range(1,18)), ['80'], [80.0]])
def test_restricted_ports(ports):
    with pytest.raises(ValueError): plan('192.0.2.1', ports)


def test_profile_is_exact_and_disallows_injection():
    candidate = plan('192.0.2.1', [443,80])
    assert candidate['ports'] == [80,443] and '-sT' in candidate['arguments'] and '-sV' in candidate['arguments']
    assert validate_plan(candidate)
    for args in (['--script','all'], ['-O'], ['-sU'], ['-sC'], ['--script-args','x=y']):
        changed=deepcopy(candidate);changed['arguments']+=args
        assert not validate_plan(changed)
    for target in ['example.com','192.0.2.0/24','192.0.2.1;id','192.000.2.1']:
        with pytest.raises(ValueError): plan(target,[80])


def test_actual_probed_http_https_only():
    facts=parse_services(xml(), '192.0.2.1', [80,443])
    assert [f['service'] for f in facts]==['http','https']
    assert all(f['version']=='1.2' for f in facts)
    for state,name,method in [('closed','http','probed'),('filtered','http','probed'),
                              ('open','unknown','probed'),('open','http','table')]:
        assert parse_services(xml([(80,state,name,method,None)]),'192.0.2.1',[80])==[]


def test_non_http_service_preserved_but_never_recommended():
    from app.recommendation_planner import plan_recommendations
    fact, = parse_services(xml([(22,'open','ssh','probed',None)]),'192.0.2.1',[22])
    assert fact['service'] == 'ssh' and fact['port'] == 22
    assert plan_recommendations([SimpleNamespace(id=uuid4(), target_id=uuid4(), evidence_id=uuid4(),
        observation_type='service_discovery', data=fact, is_partial=False)]) == []


@pytest.mark.parametrize('content', [b'', b'<broken>', b'<!DOCTYPE a [<!ENTITY x "evil">]><nmaprun/>',
    xml().replace(b'exit="success"',b'exit="error"'), xml(target='192.0.2.2'),
    xml([(81,'open','http','probed',None)]), xml([(80,'open','http','probed',None)]*2)])
def test_malformed_partial_wrong_target_or_port_fail_closed(content):
    with pytest.raises(ValueError):parse_services(content,'192.0.2.1',[80,443])


@pytest.fixture
def service_setup(client, db, prepared):
    path,headers,user=prepared
    # Capability is attested BEFORE Start, so immutable baseline fingerprints
    # bind the complete trusted tool-state revision without rewriting history.
    record_tool_state(db,'Nmap','enabled',['ipv4-discovery','tcp-service-discovery'])
    from app.baseline_resolution import reconcile
    assessment=db.get(Assessment,UUID(path.rsplit('/',1)[1]))
    reconcile(db,assessment,'tool_state_changed');db.commit()
    started=confirm(client,path,headers,get_review(client,path)['start_review'])
    assert started.status_code==201,started.text
    host=db.get(BaselineExecutionRequest,UUID(started.json()['queued_execution_ids'][0]))
    return path,headers,user,host


def schedule(client, setup, ports=None, key=None):
    path,headers,_,host=setup
    return client.post(path+'/testing/service-discovery',headers={**headers,'Idempotency-Key':key or str(uuid4())},
        json={'target_id':str(host.target_id),'ports':ports if ports is not None else [80,443],'confirmed':True})


@pytest.fixture
def service_row(client, db, service_setup):
    response=schedule(client,service_setup)
    assert response.status_code==201,response.text
    return db.get(BaselineExecutionRequest,UUID(response.json()['execution_id']))


def test_explicit_consent_idempotency_and_no_automatic_service(client,db,service_setup):
    host=service_setup[3]
    assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest))==1
    key=str(uuid4());one=schedule(client,service_setup,key=key);two=schedule(client,service_setup,key=key)
    assert one.status_code==201 and two.status_code==200 and one.json()==two.json()
    assert schedule(client,service_setup,ports=[22],key=key).status_code==409
    assert schedule(client,service_setup).status_code==409
    row=db.get(BaselineExecutionRequest,UUID(one.json()['execution_id']))
    assert row.authorization_id==host.authorization_id
    assert verify(db,row)['dispatch_policy']['id']=='uptip-tcp-service-discovery'
    assert one.json()['execution_authorized'] is False
    assert client.post(service_setup[0]+'/testing/service-discovery',headers={'Idempotency-Key':str(uuid4())},json={'target_id':str(host.target_id),'ports':[80],'confirmed':True}).status_code==403
    for sql in ['UPDATE service_discovery_consents SET digest=digest','DELETE FROM service_discovery_consents','TRUNCATE service_discovery_consents']:
        with pytest.raises(DBAPIError):
            with db.begin_nested(): db.execute(text(sql))


@pytest.mark.parametrize('change',['scope','target','tool','revoked','missing','expiry','parameters'])
def test_runtime_revalidation_rejects_changes(client,db,service_setup,service_row,monkeypatch,change):
    row=service_row
    original=db.get
    if change=='scope': db.get(Assessment,row.assessment_id).scope_revision+=1
    elif change=='target': db.get(AssessmentTarget,row.target_id).revision+=1
    elif change=='tool':record_tool_state(db,'Nmap','disabled',[])
    elif change=='revoked':
        assert client.post(service_setup[0]+f'/testing/service-discovery/{row.id}/revoke',headers=service_setup[1]).status_code==200
    elif change in ('missing','expiry'):
        # Characterize verifier input without bypassing immutable database guards.
        consent=db.get(ServiceDiscoveryConsent,row.id)
        if change=='missing':monkeypatch.setattr(db,'get',lambda model,key,*a,**kw: None if model is ServiceDiscoveryConsent else original(model,key,*a,**kw))
        else:
            from unittest.mock import patch
            import app.service_discovery as module
            fake=SimpleNamespace(now=lambda tz:consent.expires_at+timedelta(seconds=1))
            monkeypatch.setattr(module,'datetime',fake)
    else:
        from app.nmap_service_profile import POLICY
        monkeypatch.setitem(POLICY,'max_ports',100)
    if change=='missing': pass
    db.flush()
    with pytest.raises((DispatchDenied,ValueError)):verify(db,row)


class ServiceAdapter:
    config=SimpleNamespace(timeout=30,sha256='a'*64,version='7.95')
    calls=0
    def verify(self):pass
    def run(self,candidate,*,safe,launched,launch_guard):
        assert validate_plan(candidate)
        with launch_guard():
            assert safe();launched('synthetic-service:123:456')
        assert safe();self.calls+=1
        return ScanOutcome(xml(),b'',0,'scanner_exited',True,False)


def test_service_worker_evidence_planner_api_and_dedup(client,db,service_setup,service_row,tmp_path):
    tmp_path.chmod(0o700);adapter=ServiceAdapter()
    runner=ExecutionRunner(BorrowedFactory(db),adapter,EvidenceStore(tmp_path),'synthetic-service')
    assert runner.run(service_row.id)
    assert not runner.run(service_row.id) and adapter.calls==1
    assert service_row.status=='Completed'
    path=service_setup[0]
    details=client.get(path+f'/testing/executions/{service_row.id}').json()
    assert details['profile_id']=='service-discovery' and details['status']=='Completed'
    assert len(details['observations'])==2 and all(o['type']=='service_discovery' for o in details['observations'])
    assert details['processing'][0]['processor']=='nmap-service-discovery'
    from app.models import ScannerEvidence
    evidence=db.scalar(select(ScannerEvidence).where(ScannerEvidence.request_id==service_row.id,ScannerEvidence.format=='nmap-xml'))
    attempt=db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.request_id==service_row.id))
    assert evidence.content==xml() and not evidence.is_partial
    assert process(db,attempt,evidence,xml()).status=='Succeeded'
    assert len(db.scalars(select(SecurityObservation).where(SecurityObservation.request_id==service_row.id)).all())==2
    recs=client.get(path+'/testing/recommendations').json()['recommendations']
    assert len(recs)==2 and all(r['suggested_tool']=='Nikto' and not r['execution_available'] for r in recs)
    ids=[r['id'] for r in recs]
    assert ids==[r['id'] for r in client.get(path+'/testing/recommendations').json()['recommendations']]
    for rec in recs:
        assert rec['source_evidence_id']==str(evidence.id)
        assert client.get(path+f"/testing/recommendations/{rec['id']}/eligibility").json()['eligible'] is False
    # Persisted review is unchanged by fresh reads or idempotent reprocessing.
    assert client.post(path+'/testing/completion/decisions',headers=service_setup[1],json={
        'recommendation_id':ids[0],'decision':'Reviewed','review_outcome':'Accepted'}).status_code==200
    assert client.get(path+'/testing/recommendations').json()['recommendations'][0]['review_outcome']=='Accepted'


@pytest.mark.parametrize('outcome', [
    ScanOutcome(xml(),b'',1,'scanner_exited',True,True),
    ScanOutcome(xml(),b'',None,'timeout',True,True),
    ScanOutcome(xml(),b'',None,'runtime_safety_lost',True,True),
    ScanOutcome(xml(),b'',None,'termination_unverified',False,True),
    ScanOutcome(b'<broken>',b'',0,'scanner_exited',True,False),
])
def test_partial_failure_timeout_cancellation_and_uncertainty_never_recommend(client,db,service_setup,service_row,tmp_path,outcome):
    class Failed(ServiceAdapter):
        def run(self,candidate,*,safe,launched,launch_guard):
            with launch_guard():
                assert safe();launched('synthetic-failure:123:456')
            return outcome
    tmp_path.chmod(0o700)
    ExecutionRunner(BorrowedFactory(db),Failed(),EvidenceStore(tmp_path),'synthetic-failure').run(service_row.id)
    assert service_row.status != 'Completed'
    assert db.scalar(select(func.count()).select_from(SecurityObservation).where(SecurityObservation.request_id==service_row.id))==0
    assert client.get(service_setup[0]+'/testing/recommendations').json()['recommendations']==[]
    assert claim(BorrowedFactory(db),service_row.id,'replacement',30) is None


def test_creator_only_scope_port_and_csrf_enforcement(client,db,service_setup):
    path,headers,user,host=service_setup
    endpoint=path+'/testing/service-discovery'
    body={'target_id':str(host.target_id),'ports':[80],'confirmed':True}
    key={'Idempotency-Key':str(uuid4())}
    assert client.post(endpoint,headers=key,json=body).status_code==403
    assert client.post(endpoint,headers={**headers,**key},json={**body,'ports':[65536]}).status_code==422
    assert client.post(endpoint,headers={**headers,**key},json={**body,'confirmed':False}).status_code==422
    assert client.post(endpoint,headers={**headers,**key},json={**body,'arguments':['--script','all']}).status_code==422
    assert client.post(endpoint,headers={**headers,**key},json={**body,'target_id':str(uuid4())}).status_code==409
    from test_assessments import add_analyst, sign_in
    from app.models import AssessmentAssignment
    assigned=add_analyst(db,'assigned-service-'+uuid4().hex)
    db.add(AssessmentAssignment(assessment_id=host.assessment_id,analyst_id=assigned.id));db.commit()
    other_headers=sign_in(client,assigned.username)
    assert client.get(path+'/testing').status_code==200
    assert client.post(endpoint,headers={**other_headers,**key},json=body).status_code==404
    assert db.scalar(select(func.count()).select_from(ServiceDiscoveryConsent))==0


def test_revocation_denies_existing_live_claim(client,db,service_setup,service_row):
    factory=BorrowedFactory(db)
    aid,cid,_=claim(factory,service_row.id,'live-worker',30)
    a=db.get(ExecutionAttempt,aid)
    from app.nmap_dispatch_authorization import verify_nmap_dispatch_authorization
    assert verify_nmap_dispatch_authorization(db,execution_request_id=service_row.id,
        attempt_id=aid,worker_id='live-worker',claim_id=cid).authorized
    client.post(service_setup[0]+f'/testing/service-discovery/{service_row.id}/revoke',headers=service_setup[1])
    assert not verify_nmap_dispatch_authorization(db,execution_request_id=service_row.id,
        attempt_id=aid,worker_id='live-worker',claim_id=cid).authorized
    assert a.status=='Claimed'  # verifier itself never mutates worker state


def test_service_migration_metadata_and_empty_rollback(migration_db):
    from alembic import command
    from alembic.config import Config
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from pathlib import Path
    from app.database import Base
    from sqlalchemy import create_engine
    engine=create_engine(migration_db.info['migration_test_migration_url'])
    config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    config.set_main_option('script_location',str(Path(__file__).resolve().parents[1]/'migrations'))
    command.upgrade(config,'0023')
    command.upgrade(config,'0024')
    with engine.connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn),Base.metadata)==[]
        for table in ['service_discovery_consents','service_discovery_revocations']:
            for priv in ['UPDATE','DELETE','TRUNCATE']:
                assert not conn.scalar(text('SELECT has_table_privilege(\'uptip_runtime\',:table,:priv)'),{'table':table,'priv':priv})
            assert conn.scalar(text("SELECT count(*) FROM pg_trigger WHERE tgrelid=to_regclass(:table) AND NOT tgisinternal"),{'table':table})==3
    command.downgrade(config,'0023')
    command.upgrade(config,'0024')


def test_service_after_capability_update_preserves_original_start(client,db,prepared):
    path,headers,user=prepared
    started=confirm(client,path,headers,get_review(client,path)['start_review'])
    assert started.status_code==201
    host=db.get(BaselineExecutionRequest,UUID(started.json()['queued_execution_ids'][0]))
    from app.models import AssessmentStartAuthorization
    saved=deepcopy(db.get(AssessmentStartAuthorization,host.authorization_id).snapshot)
    record_tool_state(db,'Nmap','enabled',['ipv4-discovery','tcp-service-discovery'])
    from app.baseline_resolution import reconcile
    reconcile(db,db.get(Assessment,host.assessment_id),'tool_state_changed');db.commit()
    result=schedule(client,(path,headers,user,host))
    assert result.status_code==201,result.text
    row=db.get(BaselineExecutionRequest,UUID(result.json()['execution_id']))
    assert verify(db,row)['execution_authorized']
    assert db.get(AssessmentStartAuthorization,host.authorization_id).snapshot==saved


def test_invalid_consent_binding_fails_without_claim(client,db,service_setup,service_row,monkeypatch):
    consent=db.get(ServiceDiscoveryConsent,service_row.id)
    fake=SimpleNamespace(**{key:getattr(consent,key) for key in
        ['assessment_id','target_id','created_at','expires_at','actor_id','snapshot','digest']})
    fake.snapshot=deepcopy(fake.snapshot)
    fake.snapshot['preparation']['plan']['ports']=[22]
    original=db.get
    monkeypatch.setattr(db,'get',lambda model,key,*a,**kw:fake if model is ServiceDiscoveryConsent else original(model,key,*a,**kw))
    with pytest.raises(DispatchDenied,match='integrity'):verify(db,service_row)
    assert claim(BorrowedFactory(db),service_row.id,'tamper-test',30) is None
    assert service_row.status=='Blocked'


def test_service_adapter_exact_argv_and_timeout(tmp_path,monkeypatch):
    from test_nmap_adapter_v2 import fixture_adapter
    candidate=plan('192.0.2.1',[80])
    adapter=fixture_adapter(tmp_path,monkeypatch,
        'import sys\nassert sys.argv[1:]=='+repr([*candidate['arguments'],candidate['target']])+"\nprint('synthetic-service')\n")
    outcome=adapter.run(candidate,safe=lambda:True,launched=lambda _:None)
    assert outcome.exit_code==0 and not outcome.partial
    assert outcome.stdout==b'synthetic-service\n'
    adapter=fixture_adapter(tmp_path,monkeypatch,'import time\ntime.sleep(20)\n',timeout=1)
    outcome=adapter.run(candidate,safe=lambda:True,launched=lambda _:None)
    assert outcome.partial and outcome.terminated and outcome.reason=='execution_timeout'


@pytest.mark.parametrize('scheduling_concurrency',['empty'],indirect=True)
def test_service_consent_downgrade_refuses_history_and_concurrent_duplicate(scheduling_concurrency,monkeypatch):
    from fastapi.testclient import TestClient
    from concurrent.futures import ThreadPoolExecutor
    from alembic import command
    from alembic.config import Config
    from pathlib import Path
    app,factory,_,_,_=scheduling_concurrency
    with factory() as db, TestClient(app,base_url='https://testserver') as client:
        client.headers['Origin']='https://testserver'
        base=prepared.__wrapped__(client,db,monkeypatch)
        setup=service_setup.__wrapped__(client,db,base)
        cookies=dict(client.cookies)
    def submit():
        with TestClient(app,base_url='https://testserver',cookies=cookies) as client:
            client.headers['Origin']='https://testserver'
            return schedule(client,setup).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        codes=sorted(pool.map(lambda _:submit(),range(2)))
    assert codes==[201,409]
    config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    config.set_main_option('script_location',str(Path(__file__).resolve().parents[1]/'migrations'))
    with pytest.raises(DBAPIError,match='consent history'):command.downgrade(config,'0023')
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(ServiceDiscoveryConsent))==1
        assert db.scalar(text('SELECT version_num FROM alembic_version'))=='0024'


def test_no_capability_or_unauthenticated_session_cannot_grant_service(client,db,prepared):
    from fastapi.testclient import TestClient
    path,headers,_=prepared
    started=confirm(client,path,headers,get_review(client,path)['start_review'])
    host=db.get(BaselineExecutionRequest,UUID(started.json()['queued_execution_ids'][0]))
    body={'target_id':str(host.target_id),'ports':[80],'confirmed':True}
    assert client.post(path+'/testing/service-discovery',headers={**headers,'Idempotency-Key':str(uuid4())},json=body).status_code==409
    with TestClient(client.app,base_url='https://testserver') as anonymous:
        anonymous.headers['Origin']='https://testserver'
        assert anonymous.post(path+'/testing/service-discovery',headers={'Idempotency-Key':str(uuid4())},json=body).status_code==401
    assert db.scalar(select(func.count()).select_from(ServiceDiscoveryConsent))==0


def test_outside_scope_target_never_receives_service_consent(client,db,prepared):
    path,headers,user=prepared
    outside=client.post(path+'/targets',headers=headers,json={'value':'198.51.100.1'})
    assert outside.status_code==201
    outside_id=next(t['id'] for t in outside.json()['targets'] if t['normalized_value']=='198.51.100.1')
    started=confirm(client,path,headers,get_review(client,path)['start_review'])
    assert started.status_code==201
    result=client.post(path+'/testing/service-discovery',headers={**headers,'Idempotency-Key':str(uuid4())},
        json={'target_id':outside_id,'ports':[80],'confirmed':True})
    assert result.status_code==409
    assert db.scalar(select(func.count()).select_from(ServiceDiscoveryConsent))==0


def test_creator_capability_and_receipt_lookup_are_read_only(client,db,service_setup):
    path,headers,user,host=service_setup
    assert client.get(path+'/testing').json()['can_schedule_service_discovery'] is True
    key=str(uuid4())
    lookup=path+'/testing/service-discovery/receipts/'+key
    missing=client.get(lookup)
    assert missing.status_code==200 and missing.json()=={'assessment_id':str(host.assessment_id),'receipt':None}
    response=schedule(client,service_setup,key=key)
    assert response.status_code==201
    from app.models import ExecutionEvent
    before=db.scalar(select(func.count()).select_from(ExecutionEvent))
    for _ in range(2):
        read=client.get(lookup)
        assert read.status_code==200 and read.headers['Cache-Control']=='no-store'
        assert read.json()['receipt']==response.json()
        assert read.json()['receipt']['ports']==[80,443]
    assert db.scalar(select(func.count()).select_from(ExecutionEvent))==before
    assert db.scalar(select(func.count()).select_from(ServiceDiscoveryConsent))==1
    # A receipt establishes historical scheduling, not fresh dispatch authority.
    row=db.get(BaselineExecutionRequest,UUID(response.json()['execution_id']))
    assert client.post(path+f'/testing/service-discovery/{row.id}/revoke',headers=headers).status_code==200
    assert client.get(lookup).json()['receipt']==response.json()


def test_assigned_and_unrelated_analysts_cannot_read_creator_receipts(client,db,service_setup):
    from test_assessments import add_analyst,sign_in
    from app.models import AssessmentAssignment
    from fastapi.testclient import TestClient
    path,headers,user,host=service_setup
    key=str(uuid4());assert schedule(client,service_setup,key=key).status_code==201
    lookup=path+'/testing/service-discovery/receipts/'+key
    for assigned in (True,False):
        other=add_analyst(db,'receipt-other-'+uuid4().hex)
        if assigned:db.add(AssessmentAssignment(assessment_id=host.assessment_id,analyst_id=other.id))
        db.commit();sign_in(client,other.username)
        assert client.get(path+'/testing').status_code==(200 if assigned else 404)
        if assigned:assert client.get(path+'/testing').json()['can_schedule_service_discovery'] is False
        assert client.get(lookup).status_code==404
    with TestClient(client.app,base_url='https://testserver') as anonymous:
        assert anonymous.get(lookup).status_code==401
