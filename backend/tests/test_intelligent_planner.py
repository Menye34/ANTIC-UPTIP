"""Planner-only facts are synthetic; no real tool execution or integration."""
from copy import deepcopy
from types import SimpleNamespace
from uuid import UUID, uuid4
import pytest
from sqlalchemy import select, func, text
from sqlalchemy.exc import DBAPIError
from app.models import RecommendationReviewEvent, BaselineExecutionRequest
from app.recommendation_planner import plan_recommendations, normalized_fact
from app.recommendation_eligibility import evaluate_recommendation
from app.baseline_catalog import fingerprint
from test_testing_completion_contract import completed_work  # noqa: F401
from test_testing_completion_concurrency import committed_completion  # noqa: F401
from test_scheduling_start import prepared, scheduling_concurrency  # noqa: F401


def observed(kind='service_discovery', **updates):
    data={'address':'192.0.2.1','state':'open','port':443,'transport':'tcp','service':'https'}
    if kind=='web_application':data.update(url='https://192.0.2.1/app',application_verified=True)
    data.update(updates)
    return SimpleNamespace(id=uuid4(),target_id=uuid4(),evidence_id=uuid4(),is_partial=False,observation_type=kind,data=data)


def test_host_and_port_only_do_not_invent_followups():
    for kind in ('host_discovery','open_port','unknown'):
        assert plan_recommendations([observed(kind)])==[]
    assert plan_recommendations([observed(service=None)])==[]


@pytest.mark.parametrize('data', [{'port':True},{'port':0},{'port':65536},{'service':'ssh'},
    {'service':'smtp'},{'transport':'udp'},{'state':'closed'},{'address':'192.168.001.1'},
    {'version':'bad\nversion'},{'service':''}])
def test_invalid_or_unsupported_facts_do_not_generate(data):
    assert plan_recommendations([observed(**data)])==[]


def test_distinct_server_and_application_objectives_not_fixed_http_mapping():
    server=observed();app=observed('web_application');app.target_id=server.target_id
    values=plan_recommendations([server,app])
    assert {v['suggested_tool'] for v in values}=={'Nikto','OWASP ZAP'}
    for item in values:
        assert len(item['explanation']) == 1
        assert item['reason'] == item['explanation'][0]
        assert item['proposed_test']['profile_id'] is None
        if item['suggested_tool'] == 'Nikto':
            assert item['reason'] == (
                'HTTPS service detected on 192.0.2.1:443. '
                'Nikto is recommended to check for server '
                'misconfigurations and exposed resources.'
            )
        else:
            assert item['reason'] == (
                'Web application identified at https://192.0.2.1/app. '
                'OWASP ZAP is recommended to assess application security weaknesses.'
            )
        assert item['source_observation_id'] in (server.id,app.id)
        assert item['execution_status']=='pending_integration' and not item['execution_available']
        assert not evaluate_recommendation(item['id'],[server,app])['eligible']
    app.data['application_verified']=False
    assert plan_recommendations([app])==[]


@pytest.mark.parametrize('change', [{'url':'https://other.example/app'},{'url':'https://user:password@192.0.2.1/app'},
    {'url':'https://192.0.2.1:8443/app'},{'url':'file:///etc/passwd'},{'application_verified':False}])
def test_web_application_requires_explicit_valid_evidence(change):
    assert plan_recommendations([observed('web_application',**change)])==[]


def test_identity_deduplication_material_changes_and_completed_objective():
    source=observed();same=deepcopy(source);same.id=uuid4();same.evidence_id=uuid4()
    one,=plan_recommendations([source,same]);assert plan_recommendations([same,source])==[one]
    source.data['version']='1.2'
    assert plan_recommendations([source])[0]['id']!=one['id']
    assert plan_recommendations([source],completed_capabilities=[(str(source.target_id),'http-server-assessment',fingerprint(normalized_fact(source)))])==[]
    source.is_partial=True;assert plan_recommendations([source])==[]


def test_planning_makes_no_dns_network_or_scanner_calls(monkeypatch):
    import socket,subprocess
    def forbidden(*args,**kwargs):pytest.fail('Planner attempted I/O')
    monkeypatch.setattr(socket,'getaddrinfo',forbidden);monkeypatch.setattr(socket,'socket',forbidden)
    monkeypatch.setattr(subprocess,'Popen',forbidden)
    assert plan_recommendations([observed()])


def test_reject_accept_history_is_idempotent_and_never_dispatches(client,db,completed_work):
    path,headers,_,_=completed_work
    listing=client.get(path+'/testing/recommendations').json();item=listing['recommendations'][0]
    count=db.scalar(select(func.count()).select_from(BaselineExecutionRequest))
    endpoint=path+'/testing/completion/decisions'
    previous_digest = None
    for outcome,revision in [('Rejected',1),('Rejected',1),('Accepted',2)]:
        payload={'recommendation_id':item['id'],'decision':'Reviewed','review_outcome':outcome}
        assert client.post(endpoint,json=payload).status_code==403
        response=client.post(endpoint,headers=headers,json=payload)
        assert response.status_code==200,response.text
        current=client.get(path+'/testing/recommendations').json()['recommendations'][0]
        assert current['review_outcome']==outcome and current['decision']=='Reviewed'
        assert not current['execution_available']
        records=db.scalars(select(RecommendationReviewEvent).order_by(RecommendationReviewEvent.revision)).all()
        assert len(records)==revision and records[-1].snapshot['source_evidence_id']==item['source_evidence_id']
        assert db.scalar(select(func.count()).select_from(BaselineExecutionRequest))==count
        digest=client.get(path+'/testing/completion').json()['snapshot_digest']
        if previous_digest is not None:
            assert (digest != previous_digest) == (outcome == 'Accepted')
        previous_digest=digest
    for sql in ('UPDATE recommendation_review_events SET outcome=outcome', 'DELETE FROM recommendation_review_events','TRUNCATE recommendation_review_events'):
        with pytest.raises(DBAPIError):
            with db.begin_nested():db.execute(text(sql))
    assert client.post(endpoint,headers=headers,json={'recommendation_id':item['id'],'decision':'Deferred','review_outcome':'Accepted'}).status_code==422


@pytest.mark.parametrize('scheduling_concurrency',['empty'],indirect=True)
def test_review_migration_refuses_history_downgrade_and_retains_runtime_restrictions(committed_completion):
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from fastapi.testclient import TestClient
    app,factory,path,headers,cookies,_=committed_completion
    with TestClient(app,base_url='https://testserver',cookies=cookies) as client:
        client.headers['Origin']='https://testserver'
        item=client.get(path+'/testing/recommendations').json()['recommendations'][0]
        body={'recommendation_id':item['id'],'decision':'Reviewed','review_outcome':'Rejected'}
        assert client.post(path+'/testing/completion/decisions',headers=headers,json=body).status_code==200
    config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    config.set_main_option('script_location',str(Path(__file__).resolve().parents[1]/'migrations'))
    command.downgrade(config,'0023')  # Empty new service-consent tables are safely reversible.
    with pytest.raises(DBAPIError,match='recommendation review history'):
        command.downgrade(config,'0022')
    with factory() as db:
        assert db.scalar(text('SELECT version_num FROM alembic_version'))=='0023'
        assert db.scalar(select(func.count()).select_from(RecommendationReviewEvent))==1
        for privilege in ('UPDATE','DELETE','TRUNCATE'):
            assert not db.scalar(text("SELECT has_table_privilege('uptip_runtime','recommendation_review_events',:privilege)"),{'privilege':privilege})


def test_invalid_review_snapshot_and_cross_assessment_binding_fail_closed(client,db,completed_work):
    path,_,owner,_=completed_work
    item=client.get(path+'/testing/recommendations').json()['recommendations'][0]
    with pytest.raises(DBAPIError,match='provenance mismatch'):
        with db.begin_nested():
            db.add(RecommendationReviewEvent(assessment_id=UUID(path.rsplit('/',1)[1]),actor_id=owner.id,
                recommendation_id=item['id'],context_digest=item['id'],outcome='Rejected',revision=1,
                snapshot={**item,'source_observation_id':str(uuid4())}))
            db.flush()


def test_actual_nmap_host_discovery_api_does_not_invent_web_recommendations(client,db,prepared,tmp_path):
    from test_scheduling_start import confirm,get_review
    from test_execution_orchestration import FakeAdapter,BorrowedFactory
    from app.execution_orchestration import ExecutionRunner
    from app.execution_results import EvidenceStore
    path,headers,_=prepared
    receipt=confirm(client,path,headers,get_review(client,path)['start_review'])
    assert receipt.status_code==201
    tmp_path.chmod(0o700)
    assert ExecutionRunner(BorrowedFactory(db),FakeAdapter(),EvidenceStore(tmp_path),'synthetic-host-only').run(UUID(receipt.json()['queued_execution_ids'][0]))
    response=client.get(path+'/testing/recommendations')
    assert response.status_code==200,response.text
    assert response.json()['count']==0 and response.json()['recommendations']==[]
    overview=client.get(path+'/testing').json()
    assert overview['counts']['completed']==1
    assert all(item['type']=='host_discovery' and 'port' not in item['data'] for item in overview['discovered_so_far'])


def test_deferred_legacy_host_review_is_not_silently_cleared():
    from hashlib import sha256
    from app.recommendation_planner import carry_deferred_legacy
    from app.testing_completion_service import recommendation_statistics
    from datetime import datetime,timezone
    source=observed('host_discovery');source.data={'address':'192.0.2.1','status':'up'}
    source.collected_at=datetime.now(timezone.utc)
    identity=sha256(f'host-review-v1:{source.target_id}:192.0.2.1'.encode()).hexdigest()
    decision={'recommendation_id':identity,'decision':'Deferred'}
    assert plan_recommendations([source])==[]
    carried=carry_deferred_legacy([source],[decision],[])
    assert len(carried)==1 and not carried[0]['execution_available']
    _,pending,counts=recommendation_statistics([vars(source)],[decision])
    assert pending==[identity] and counts['deferred']==counts['pending_completion']==1
    assert carry_deferred_legacy([source],[{**decision,'decision':'Reviewed'}],[])==[]


def test_latest_complete_service_context_replaces_old_fact_not_its_history():
    old=observed(version='1');new=deepcopy(old);new.id=uuid4();new.data['version']='2'
    old.collected_at='2026-11-01T00:00:00Z';new.collected_at='2026-11-02T00:00:00Z'
    item,=plan_recommendations([new,old])
    assert item['id']==plan_recommendations([new])[0]['id']
    assert old.data['version']=='1'


def test_unsuccessful_processing_never_supplies_recommendations():
    from test_testing_completion_contract import synthetic
    from app.testing_completion_service import build_review
    from datetime import datetime,timezone
    source=observed();record={**vars(source),'id':str(source.id),'target_id':str(source.target_id),
        'evidence_id':str(source.evidence_id),'request_id':'request','processing_id':'failed',
        'collected_at':datetime.now(timezone.utc)}
    state,actor=synthetic(executions=[{'id':'request','status':'Completed'}],
        observations=[record],processing=[{'id':'failed','request_id':'request','evidence_id':record['evidence_id'],'status':'Failed'}])
    result=build_review(state,actor)
    assert result['summary']['recommendation_count']==0
    assert 'processing_not_clear' in result['summary']['blockers'] and not result['ready']
