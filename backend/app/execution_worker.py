"""Explicit operator-launched worker; never started by FastAPI or migrations."""
import argparse
import signal
import socket
import time
from uuid import uuid4

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from .config import get_settings
from .execution_orchestration import ExecutionRunner, recover_expired
from .execution_results import EvidenceStore
from .models import BaselineExecutionRequest
from .nmap_adapter import AdapterConfig, NmapAdapter


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--evidence-directory', required=True)
    parser.add_argument('--timeout', type=int, default=600)
    parser.add_argument('--output-limit', type=int, default=10*1024*1024)
    parser.add_argument('--safety-interval', type=float, default=5)
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--enable-dispatch', action='store_true', help='Explicit operator opt-in; never grants authorization')
    args = parser.parse_args()
    if not args.enable_dispatch:
        parser.error('Dispatch requires explicit operator opt-in and independent runtime authorization.')
    adapter = NmapAdapter(AdapterConfig(args.executable, args.sha256, args.version,
        args.timeout, args.output_limit, args.safety_interval))
    store = EvidenceStore(args.evidence_directory)
    adapter.verify()  # Version only; no target or scan.
    stopped = False

    def stop(*_):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    engine = create_engine(get_settings().database_url, pool_pre_ping=True, hide_parameters=True, poolclass=NullPool,
        connect_args={'connect_timeout': 3, 'options': '-c statement_timeout=3000 -c lock_timeout=2000'})
    factory = sessionmaker(engine, expire_on_commit=False)
    worker_id = f'{socket.gethostname()}:{uuid4()}'
    # One dedicated connection holds a session advisory lock: at most one live
    # worker per database. If its connection is lost, this process fails closed.
    with engine.connect().execution_options(isolation_level='AUTOCOMMIT') as ownership:
        safe_role = ownership.scalar(text("""
            SELECT NOT (rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls)
            FROM pg_roles WHERE rolname=current_user
        """))
        if not safe_role:
            raise RuntimeError('A non-administrative dedicated worker database role is required.')
        if ownership.scalar(text("SELECT has_schema_privilege(current_user,'public','CREATE') OR has_database_privilege(current_user,current_database(),'CREATE')")):
            raise RuntimeError('Worker role must not have schema or database creation privileges.')
        for table in ('assessments', 'users', 'assessment_start_authorizations', 'execution_attempts',
                      'scanner_evidence', 'execution_events', 'security_observations', 'result_processing_outcomes',
                      'service_discovery_consents', 'service_discovery_revocations'):
            unsafe = ownership.scalar(text("""
                SELECT pg_has_role(current_user, c.relowner, 'MEMBER')
                    OR has_table_privilege(current_user, c.oid, 'DELETE,TRUNCATE,TRIGGER')
                FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND c.relname=:table
            """), {'table': table})
            if unsafe is not False:
                raise RuntimeError('Worker role has destructive or unverifiable database privileges.')
        if not ownership.scalar(text('SELECT pg_try_advisory_lock(873248901)')):
            raise RuntimeError('An execution worker already holds the database worker lock.')
        def unhealthy():
            if stopped:
                return True
            try:
                ownership.execute(text('SELECT 1'))
                return False
            except Exception:
                return True
        runner = ExecutionRunner(factory, adapter, store, worker_id, unhealthy)
        while not stopped:
            ownership.execute(text('SELECT 1'))
            recover_expired(factory)
            with factory() as db:
                ids = db.scalars(select(BaselineExecutionRequest.id)
                    .where(BaselineExecutionRequest.status == 'Queued')
                    .order_by(BaselineExecutionRequest.created_at, BaselineExecutionRequest.id).limit(100)).all()
            for request_id in ids:
                if stopped:
                    break
                runner.run(request_id)
            if args.once:
                break
            for _ in range(20):
                if stopped:
                    break
                time.sleep(.25)


if __name__ == '__main__':
    main()
