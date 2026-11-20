"""Disposable PostgreSQL + fake scanner; read-only Figma projections and evidence."""
from hashlib import sha256
from types import SimpleNamespace
from uuid import UUID, uuid4
import os
import pytest
from sqlalchemy import select, event, func
from app.models import (AssessmentAssignment, BaselineExecutionRequest, ScannerEvidence,
                        AssessmentStartAuthorization, Assessment)
from app.evidence_reading import EvidenceUnavailable, MAX_BYTES, read_original
from app.execution_results import EvidenceStore
from app.execution_orchestration import ExecutionRunner
from app.testing_read_summary import discovery_totals
from test_automatic_service_start import automatic  # noqa: F401
from test_scheduling_start import prepared, get_review, confirm, scheduling_concurrency  # noqa: F401
from test_execution_orchestration import FakeAdapter, BorrowedFactory
from test_service_discovery import ServiceAdapter


def source(content=b'<nmaprun/>', **changes):
    raw = content if content is not None else b''
    return SimpleNamespace(**{**dict(content=content, storage_key=None, size_bytes=len(raw),
        content_hash=sha256(raw).hexdigest()), **changes})


def test_inline_original_is_exact_and_hash_checked():
    assert read_original(source(b'<nmaprun>&lt;script&gt;</nmaprun>')) == '<nmaprun>&lt;script&gt;</nmaprun>'
    for row in (source(content_hash='0'*64), source(size_bytes=4), source(size_bytes=MAX_BYTES+1),
                source(content=b'\xff'), source(storage_key='evidence/'+'a'*32)):
        with pytest.raises(EvidenceUnavailable): read_original(row)


def test_file_original_bounded_private_and_no_paths(tmp_path):
    tmp_path.chmod(0o700)
    content=b'<nmaprun/>'
    key=EvidenceStore(tmp_path).write(content)
    row=source(content=None, storage_key=key, size_bytes=len(content), content_hash=sha256(content).hexdigest())
    assert read_original(row,str(tmp_path)) == content.decode()
    (tmp_path/key.split('/')[1]).write_bytes(b'x'*len(content))
    with pytest.raises(EvidenceUnavailable): read_original(row,str(tmp_path))
    for key in ('../../etc/passwd', 'evidence/../file', '/etc/passwd', 'evidence/'+'z'*32):
        with pytest.raises(EvidenceUnavailable): read_original(source(content=None, storage_key=key),str(tmp_path))
    with pytest.raises(EvidenceUnavailable): read_original(row)
    with pytest.raises(EvidenceUnavailable): read_original(row, str(tmp_path/'missing'))
    tmp_path.chmod(0o755)
    with pytest.raises(EvidenceUnavailable): read_original(row,str(tmp_path))


@pytest.mark.parametrize('kind',['symlink','hardlink','fifo','directory'])
def test_nonregular_and_linked_evidence_never_read(tmp_path,kind):
    tmp_path.chmod(0o700)
    name='a'*32
    outside=tmp_path/'private'
    outside.write_bytes(b'secret');outside.chmod(0o600)
    path=tmp_path/name
    if kind=='symlink': path.symlink_to(outside)
    elif kind=='hardlink': os.link(outside,path)
    elif kind=='fifo': os.mkfifo(path,0o600)
    else: path.mkdir(mode=0o700)
    row=source(content=None,storage_key='evidence/'+name,size_bytes=6,content_hash=sha256(b'secret').hexdigest())
    with pytest.raises(EvidenceUnavailable):read_original(row,str(tmp_path))


def test_discovery_totals_never_infer_web_apps_or_double_count():
    row={'target_id':'t','type':'service_discovery','data':{'address':'192.0.2.1','port':443,
        'service':'https','transport':'tcp','state':'open'}}
    assert discovery_totals([row,row],True)=={'open_ports':1,'services':1,'web_targets':None}
    assert discovery_totals([],False)=={'open_ports':None,'services':None,'web_targets':None}
    assert discovery_totals([],True)=={'open_ports':0,'services':0,'web_targets':None}
    assert discovery_totals([{**row,'data':{**row['data'],'state':'closed'}}],False)['open_ports'] is None


@pytest.fixture
def completed(client,db,automatic,tmp_path):
    path,headers=automatic
    assert confirm(client,path,headers,get_review(client,path)['start_review']).status_code==201
    host,service=db.scalars(select(BaselineExecutionRequest).order_by(BaselineExecutionRequest.profile_id)).all()
    tmp_path.chmod(0o700)
    assert ExecutionRunner(BorrowedFactory(db),FakeAdapter(),EvidenceStore(tmp_path),'fake-host').run(host.id)
    # Host reachability is insufficient to count open services or web targets.
    data=client.get(path+'/testing').json()
    assert data['discovery_totals']=={'open_ports':None,'services':None,'web_targets':None}
    assert ExecutionRunner(BorrowedFactory(db),ServiceAdapter(),EvidenceStore(tmp_path),'fake-service').run(service.id)
    evidence=db.scalar(select(ScannerEvidence).where(ScannerEvidence.request_id==service.id,
        ScannerEvidence.format=='nmap-xml'))
    return path,headers,host,service,evidence


def test_overview_and_details_are_coherent_read_only(client,db,engine,completed):
    path,_,_,service,evidence=completed
    statements=[]
    def check(conn,cursor,statement,*args):
        assert statement.lstrip().upper().startswith(('SELECT','SAVEPOINT','RELEASE SAVEPOINT','ROLLBACK TO SAVEPOINT'))
        if statement.startswith('SELECT'):statements.append(statement)
    event.listen(engine,'before_cursor_execute',check)
    try:
        overview=client.get(path+'/testing')
        response=client.get(path+f'/testing/executions/{service.id}')
    finally:event.remove(engine,'before_cursor_execute',check)
    assert overview.status_code==response.status_code==200
    data=overview.json()
    assert data['discovery_totals']=={'open_ports':2,'services':2,'web_targets':None}
    assert data['authorization_scope']['scope_current'] is True
    assert data['authorization_scope']['boundaries']==[{'value':'192.0.2.0/24','kind':'Subnet'}]
    assert data['authorization_scope']['authorized_by']['username']
    assert data['authorization_scope']['authorized_by']['confirmed_at']
    details=response.json()
    assert details['status']=='Completed' and details['attempts'][0]['status']=='Succeeded'
    assert details['processing'][0]['status']=='Succeeded' and len(details['observations'])==2
    assert any(e['id']==str(evidence.id) for e in details['evidence'])
    # One data projection per endpoint in addition to session/user auth reads.
    assert len([s for s in statements if 'json_agg' in s])==2
    assert 'storage_key' not in response.text and 'process_reference' not in response.text


def test_original_endpoint_exact_bound_and_authorized(client,db,completed):
    from test_assessments import add_analyst,sign_in
    path,_,host,service,evidence=completed
    url=path+f'/testing/executions/{service.id}/evidence/{evidence.id}'
    result=client.get(url)
    assert result.status_code==200 and result.headers['Cache-Control']=='no-store'
    data=result.json()
    assert data['content'].encode()==evidence.content
    assert data['sha256']==sha256(evidence.content).hexdigest()
    assert 'storage_key' not in data and 'path' not in data
    assert client.get(path+f'/testing/executions/{host.id}/evidence/{evidence.id}').status_code==404
    assert client.get(path+f'/testing/executions/{service.id}/evidence/{uuid4()}').status_code==404
    other=add_analyst(db,'evidence-other-'+uuid4().hex)
    sign_in(client,other.username)
    assert client.get(url).status_code==404
    db.add(AssessmentAssignment(assessment_id=UUID(path.rsplit('/',1)[1]),analyst_id=other.id));db.commit()
    assert client.get(url).status_code==200
    client.cookies.clear()
    assert client.get(url).status_code==401


def test_invalid_original_never_discloses_content_or_path(client,db,completed,monkeypatch):
    path,_,_,service,evidence=completed
    # Mock a storage/read failure, not authorization or the relationship query.
    import app.evidence_reading as reader
    def fail(*args):raise EvidenceUnavailable('/sensitive/worker/path')
    monkeypatch.setattr(reader,'read_original',fail)
    response=client.get(path+f'/testing/executions/{service.id}/evidence/{evidence.id}')
    assert response.status_code==503
    assert '/sensitive' not in response.text and '<nmaprun' not in response.text


def test_file_backed_original_endpoint_requires_trusted_directory(client,db,automatic,tmp_path,monkeypatch):
    from dataclasses import replace
    from test_service_discovery import xml
    from app.config import get_settings
    path,headers=automatic
    assert confirm(client,path,headers,get_review(client,path)['start_review']).status_code==201
    host,service=db.scalars(select(BaselineExecutionRequest).order_by(BaselineExecutionRequest.profile_id)).all()
    tmp_path.chmod(0o700);store=EvidenceStore(tmp_path)
    assert ExecutionRunner(BorrowedFactory(db),FakeAdapter(),store,'fake-host').run(host.id)
    content=b'<!--'+b'x'*1048577+b'-->'+xml()
    class Large(ServiceAdapter):
        def run(self,candidate,**kwargs):return replace(super().run(candidate,**kwargs),stdout=content)
    assert ExecutionRunner(BorrowedFactory(db),Large(),store,'fake-service').run(service.id)
    row=db.scalar(select(ScannerEvidence).where(ScannerEvidence.request_id==service.id,
        ScannerEvidence.format=='nmap-xml'))
    assert row.content is None and row.storage_key.startswith('evidence/')
    url=path+f'/testing/executions/{service.id}/evidence/{row.id}'
    monkeypatch.setattr(get_settings(),'evidence_read_directory',None)
    assert client.get(url).status_code==503
    monkeypatch.setattr(get_settings(),'evidence_read_directory',str(tmp_path))
    response=client.get(url)
    assert response.status_code==200 and response.json()['content'].encode()==content
    assert row.storage_key not in response.text


def test_execution_details_snapshot_during_worker_commit(scheduling_concurrency,tmp_path):
    from threading import Event
    from concurrent.futures import ThreadPoolExecutor
    from fastapi.testclient import TestClient
    app,factory,(path,headers,_),review,cookies=scheduling_concurrency
    with TestClient(app,base_url='https://testserver',cookies=cookies) as c:
        c.headers['Origin']='https://testserver'
        receipt=confirm(c,path,headers,review)
        assert receipt.status_code==201
        identifier=UUID(receipt.json()['queued_execution_ids'][0])
    captured,release=Event(),Event()
    def pause(conn,cursor,statement,*args):
        if 'json_agg' in statement and 'execution_attempts' in statement and not captured.is_set():
            captured.set()
            assert release.wait(10),'Worker did not finish'
    def read():
        with TestClient(app,base_url='https://testserver',cookies=cookies) as c:
            return c.get(path+f'/testing/executions/{identifier}')
    engine=factory.kw['bind'];event.listen(engine,'after_cursor_execute',pause)
    tmp_path.chmod(0o700)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(read)
            try:
                assert captured.wait(10)
                assert ExecutionRunner(factory,FakeAdapter(),EvidenceStore(tmp_path),'fake-worker').run(identifier)
            finally:release.set()
            response=future.result(timeout=10)
    finally:event.remove(engine,'after_cursor_execute',pause)
    data=response.json()
    assert response.status_code==200
    assert data['status']=='Queued' and data['attempts']==[] and data['processing']==[]
    current=read().json()
    assert current['status']=='Completed' and current['attempts'][0]['status']=='Succeeded'
    assert current['processing'][0]['status']=='Succeeded'
