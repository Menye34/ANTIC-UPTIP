"""Assessment-isolated read projections of real recommended-job persistence."""
from hashlib import sha256
from uuid import UUID, uuid5
from fastapi import HTTPException
from sqlalchemy import select, func, literal, LargeBinary
from .models import Assessment
from .assessment_routes import accessible
from .recommended_test_queue import RecommendedTestJob as Job, RecommendedTestEvent as Event


def output_verified():
    content = Job.stdout.op('||')(literal(b'\x00', type_=LargeBinary)).op('||')(Job.stderr)
    return func.encode(func.sha256(content), 'hex') == Job.output_digest


def fields():
    return {name: getattr(Job, name) for name in ('id','assessment_id','target_id','recommendation_id',
        'tool','profile_id','profile_version','execution_plan','status','created_at','updated_at',
        'started_at','finished_at','failure_reason','exit_code','output_partial','termination_verified')} | {
        'output_verified': output_verified(),
        'stdout_size': func.octet_length(Job.stdout), 'stderr_size': func.octet_length(Job.stderr),
        'stdout_sha256': func.encode(func.sha256(Job.stdout), 'hex'),
        'stderr_sha256': func.encode(func.sha256(Job.stderr), 'hex')}


def json_job():
    return func.json_build_object(*[v for key, value in fields().items() for v in (key, value)])


def overview_jobs():
    return select(func.json_agg(json_job())).where(Job.assessment_id == Assessment.id).correlate(Assessment).scalar_subquery()


def overview_events():
    recent = select(Event.job_id.label('execution_id'), Event.event_type.label('event'), Event.occurred_at).where(
        Event.assessment_id == Assessment.id).order_by(Event.occurred_at.desc(), Event.id.desc()).limit(20).correlate(Assessment).lateral()
    return select(func.json_agg(func.json_build_object('execution_id', recent.c.execution_id,
        'event', recent.c.event, 'occurred_at', recent.c.occurred_at))).select_from(recent).scalar_subquery()


def execution_view(row):
    return {'id': row['id'], 'target_id': row['target_id'], 'profile_id': row['profile_id'],
        'profile_version': row['profile_version'], 'test_name': 'HTTP Server Assessment',
        'tool': row['tool'], 'target': row['execution_plan']['target'], 'status': row['status'],
        'authorization_id': None, 'execution_kind': 'recommended',
        'created_at': row['created_at'], 'updated_at': row['updated_at'], 'execution_authorized': False}


def details(db, assessment_id, execution_id, user):
    events = select(func.json_agg(func.json_build_object('id',Event.id,'event',Event.event_type,
        'reason_code',Event.reason_code,'occurred_at',Event.occurred_at,'attempt_id',None))).where(
        Event.job_id == Job.id, Event.assessment_id == Job.assessment_id,
        Event.target_id == Job.target_id).correlate(Job).scalar_subquery()
    found = db.execute(select(json_job(), events).join(Assessment, Assessment.id == Job.assessment_id)
        .where(Job.id == execution_id, Assessment.id == assessment_id, accessible(user))).one_or_none()
    if found is None: raise HTTPException(404)
    row, events = found
    events = sorted(events or [], key=lambda e: (e['occurred_at'],e['id']))
    from .testing_read_summary import dispatch_history
    evidence = []
    for stream in ('stdout','stderr'):
        if row[stream+'_sha256'] is not None:
            evidence.append({'id': str(execution_id if stream == 'stdout' else uuid5(execution_id, 'stderr')),
                'format': 'nikto-'+stream, 'size_bytes': row[stream+'_size'], 'sha256': row[stream+'_sha256'],
                'partial': row['output_partial'] is not False, 'collected_at': row['finished_at'] or row['updated_at']})
    return {**execution_view(row), **dispatch_history(events), 'authorized_activity': row['execution_plan'],
            'attempts': [], 'processing': [], 'observations': [], 'events': events, 'evidence': evidence,
            'recommended_result': {'termination_verified': row['termination_verified'] is True,
                'partial': row['output_partial'] is not False, 'integrity_verified': row['output_verified'] is True,
                'failure_reason': row['failure_reason']}}


def original(db, assessment_id, execution_id, evidence_id, user):
    if evidence_id not in (execution_id, uuid5(execution_id, 'stderr')): raise HTTPException(404)
    row = db.scalar(select(Job).join(Assessment, Assessment.id == Job.assessment_id).where(
        Job.id == execution_id, Assessment.id == assessment_id, accessible(user)))
    if row is None: raise HTTPException(404)
    stdout, stderr = row.stdout, row.stderr
    if (not isinstance(stdout, bytes) or not isinstance(stderr, bytes) or len(stdout)+len(stderr)>5*1024*1024
            or sha256(stdout+b'\x00'+stderr).hexdigest() != row.output_digest):
        raise HTTPException(503, detail={'code':'original_evidence_unavailable'})
    stream = 'stdout' if evidence_id == execution_id else 'stderr'
    content = stdout if stream == 'stdout' else stderr
    try: text = content.decode('utf-8')
    except UnicodeDecodeError: raise HTTPException(503, detail={'code':'original_evidence_unavailable'}) from None
    return {'assessment_id': assessment_id, 'execution_id': execution_id, 'evidence_id': evidence_id,
            'sha256':sha256(content).hexdigest(),'size_bytes':len(content),'format':'nikto-'+stream,
            'partial':row.output_partial is not False,'content':text}
