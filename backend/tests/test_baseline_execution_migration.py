"""Real migration verification, restricted to a dedicated disposable PostgreSQL DB."""
from datetime import datetime, timezone
import os
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
import pytest
from sqlalchemy import create_engine, insert, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from app.config import get_settings
from app.database import Base
from app.models import Assessment, AssessmentStartAuthorization, AssessmentTarget, BaselineExecutionRequest, Role, User


def test_0012_upgrade_constraints_triggers_privileges_and_downgrade(monkeypatch):
    migration_url = os.environ.get('UPTIP_MIGRATION_TEST_URL')
    runtime_url = os.environ.get('UPTIP_MIGRATION_TEST_RUNTIME_URL')
    if not migration_url or not runtime_url:
        pytest.skip('Set dedicated disposable migration-test URLs')
    source, runtime = make_url(migration_url), make_url(runtime_url)
    if (source.host != '127.0.0.1' or source.database != 'uptip_test_migration_0012'
            or source.drivername != 'postgresql+psycopg' or source.query or runtime.query
            or runtime.set(username=source.username, password=source.password) != source
            or runtime.username != 'uptip_test_runtime' or source.username == runtime.username):
        pytest.fail('Migration test requires distinct local roles on uptip_test_migration_0012')
    engine = create_engine(source, hide_parameters=True)
    runtime_engine = create_engine(runtime, hide_parameters=True)
    config = Config(str(Path(__file__).resolve().parents[1] / 'alembic.ini'))
    try:
        with engine.connect() as connection:
            identity = connection.execute(text("""
                SELECT current_database(), shobj_description(oid, 'pg_database')
                FROM pg_database WHERE datname = current_database()
            """)).one()
            if identity != ('uptip_test_migration_0012', 'UPTIP disposable migration test database'):
                pytest.fail('Disposable migration database marker is missing')
            if inspect(connection).has_table('alembic_version'):
                pytest.fail('Migration test requires an unused disposable database')
        monkeypatch.setenv('UPTIP_DATABASE_URL', runtime_url)
        monkeypatch.setenv('UPTIP_MIGRATION_DATABASE_URL', migration_url)
        monkeypatch.setenv('UPTIP_ENVIRONMENT', 'test')
        monkeypatch.setenv('UPTIP_RATE_KEY', 'test-only-not-a-deployment-secret-123456')
        get_settings.cache_clear()
        command.upgrade(config, '0011')
        with engine.connect() as connection:
            assert connection.scalar(text('SELECT version_num FROM alembic_version')) == '0011'
        command.upgrade(config, '0012')
        with engine.connect() as connection:
            assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
            triggers = set(connection.scalars(text("""
                SELECT tgname FROM pg_trigger WHERE tgrelid = 'baseline_execution_requests'::regclass
                AND NOT tgisinternal
            """)))
            assert triggers == {'protect_baseline_execution_input', 'reject_baseline_execution_truncate'}
        command.downgrade(config, '0011')
        assert not inspect(engine).has_table('baseline_execution_requests')
        command.upgrade(config, '0012')

        actor, first, second, target, other_target, authorization, other_authorization, queued = [uuid4() for _ in range(8)]
        with engine.begin() as connection:
            connection.execute(insert(Role).values(name='migration-fixture'))
            connection.execute(insert(User).values(id=actor, username='migration-fixture',
                password_hash='invalid-test-only-hash', status='active', role='migration-fixture',
                password_change_required=False))
            for identifier in (first, second):
                connection.execute(insert(Assessment).values(id=identifier, reference=str(identifier), name='Migration fixture',
                    idempotency_key=uuid4(), request_fingerprint='a' * 64, creator_id=actor, lead_analyst_id=actor, status='Draft'))
            connection.execute(insert(AssessmentTarget).values(id=target, assessment_id=first, original_value='192.0.2.1',
                normalized_value='192.0.2.1', kind='IP address', scope_status='in_scope',
                classification_reason='Migration fixture only', scope_revision=0))
            connection.execute(insert(AssessmentStartAuthorization).values(id=authorization, assessment_id=first,
                actor_id=actor, idempotency_key=uuid4(), request_fingerprint='a' * 64, mode='full',
                snapshot_version=2, snapshot_digest='b' * 64, snapshot={}, confirmed_at=datetime.now(timezone.utc)))
            connection.execute(insert(AssessmentTarget).values(id=other_target, assessment_id=second,
                original_value='192.0.2.2', normalized_value='192.0.2.2', kind='IP address',
                scope_status='in_scope', classification_reason='Migration fixture only', scope_revision=0))
            connection.execute(insert(AssessmentStartAuthorization).values(id=other_authorization, assessment_id=second,
                actor_id=actor, idempotency_key=uuid4(), request_fingerprint='c' * 64, mode='full',
                snapshot_version=2, snapshot_digest='d' * 64, snapshot={}, confirmed_at=datetime.now(timezone.utc)))
        values = dict(id=queued, assessment_id=first, authorization_id=authorization, target_id=target,
                      profile_id='migration-fixture', profile_version=1, tool='test', activity='test',
                      status='Queued', authorized_activity={})
        with engine.begin() as connection:
            connection.execute(insert(BaselineExecutionRequest).values(**values))
        for changed in (
            {'id': uuid4()}, {'id': uuid4(), 'assessment_id': second},
            {'id': uuid4(), 'target_id': other_target}, {'id': uuid4(), 'authorization_id': other_authorization},
        ):
            with pytest.raises(DBAPIError):
                with engine.begin() as connection:
                    connection.execute(insert(BaselineExecutionRequest).values(**{**values, **changed}))
        for statement in (
            "UPDATE baseline_execution_requests SET tool = 'changed'",
            "UPDATE baseline_execution_requests SET authorized_activity = json_build_object('changed', true)",
            'DELETE FROM baseline_execution_requests',
            'TRUNCATE baseline_execution_requests',
        ):
            with pytest.raises(DBAPIError):
                with engine.begin() as connection:
                    connection.execute(text(statement))
        with engine.begin() as connection:
            connection.execute(text("UPDATE baseline_execution_requests SET status = 'Running'"))
            connection.execute(text('GRANT SELECT, INSERT ON baseline_execution_requests TO uptip_test_runtime'))
            connection.execute(text('REVOKE CREATE ON SCHEMA public FROM PUBLIC'))
        with runtime_engine.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM baseline_execution_requests")) == 1
            assert connection.scalar(text("""
                SELECT NOT rolsuper AND NOT rolcreaterole FROM pg_roles WHERE rolname = current_user
            """))
            assert not connection.scalar(text("""
                SELECT has_table_privilege(current_user, 'baseline_execution_requests', 'TRUNCATE')
            """))
            assert not connection.scalar(text("""
                SELECT pg_has_role(current_user, relowner, 'USAGE')
                FROM pg_class WHERE oid = 'baseline_execution_requests'::regclass
            """))
        for statement in ('TRUNCATE baseline_execution_requests',
                          'ALTER TABLE baseline_execution_requests DISABLE TRIGGER ALL'):
            with pytest.raises(DBAPIError):
                with runtime_engine.begin() as connection:
                    connection.execute(text(statement))
        with pytest.raises(DBAPIError, match='Cannot downgrade'):
            command.downgrade(config, '0011')
        with engine.connect() as connection:
            assert connection.scalar(text('SELECT version_num FROM alembic_version')) == '0012'
            assert connection.scalar(text('SELECT count(*) FROM baseline_execution_requests')) == 1
    finally:
        runtime_engine.dispose()
        engine.dispose()
        get_settings.cache_clear()
