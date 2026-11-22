import os
import sys
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(scope='session')
def database_url():
    url = os.environ.get('UPTIP_TEST_DATABASE_URL')
    if not url:
        pytest.skip('Set UPTIP_TEST_DATABASE_URL to a disposable PostgreSQL database')
    return url


@pytest.fixture(scope='session')
def engine(database_url):
    # Require both an exact local destination and explicit opt-in on the database itself.
    try:
        url = make_url(database_url)
    except (SQLAlchemyError, ValueError):
        pytest.fail('Invalid UPTIP_TEST_DATABASE_URL.', pytrace=False)
    allowed_databases = {
        'uptip_test_readiness_fix',
        'uptip_test_nikto_normalization',
    }
    if (url.drivername != 'postgresql+psycopg' or url.database not in allowed_databases
            or url.host not in {'127.0.0.1', '::1'} or url.query):
        pytest.fail('Use an explicitly allowed local disposable PostgreSQL test database with no URL query options.',
                    pytrace=False)

    engine = create_engine(url, hide_parameters=True)
    try:
        try:
            with engine.connect() as connection:
                identity = connection.execute(text("""
                    SELECT current_database(), shobj_description(oid, 'pg_database')
                    FROM pg_database
                    WHERE datname = current_database()
                """)).one_or_none()
        except SQLAlchemyError:
            pytest.fail('Could not verify the disposable PostgreSQL test database.', pytrace=False)
        if identity != (url.database, 'UPTIP disposable integration test database'):
            pytest.fail(
                'The selected disposable test database must carry the exact '
                "'UPTIP disposable integration test database' marker.",
                pytrace=False,
            )

        os.environ.update(UPTIP_ENVIRONMENT='test',
                          UPTIP_PUBLIC_ORIGIN='https://testserver', UPTIP_COOKIE_SECURE='true',
                          UPTIP_RATE_KEY='test-only-not-a-deployment-secret-123456')
        from app.config import get_settings
        get_settings.cache_clear()
        config = Config(str(Path(__file__).resolve().parents[1] / 'alembic.ini'))
        # The dedicated integration-test database is migrated separately.
        # Never reset its schema automatically during pytest execution.
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def db(engine):
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            factory = sessionmaker(
                bind=connection,
                expire_on_commit=False,
                join_transaction_mode='create_savepoint',
            )
            with factory() as session:
                yield session
        finally:
            if transaction.is_active:
                transaction.rollback()




@pytest.fixture
def migration_db(monkeypatch):
    """Fresh, marked database per invocation; never reuse committed history."""
    import subprocess
    from uuid import uuid4
    from app.config import get_settings

    os.environ.update(
        UPTIP_ENVIRONMENT="test",
        UPTIP_PUBLIC_ORIGIN="https://testserver",
        UPTIP_COOKIE_SECURE="true",
        UPTIP_RATE_KEY="test-only-not-a-deployment-secret-123456",
    )
    get_settings.cache_clear()
    settings = get_settings()
    runtime_url = make_url(settings.database_url)
    migration_url = make_url(settings.migration_database_url)
    direct_admin = os.environ.get('UPTIP_DISPOSABLE_ADMIN_URL')
    if not direct_admin and not (
        runtime_url.drivername == migration_url.drivername == 'postgresql+psycopg'
        and runtime_url.username == 'uptip_runtime'
        and migration_url.username == 'uptip'
        and runtime_url.database == migration_url.database == 'uptip'
        and runtime_url.host == migration_url.host == '127.0.0.1'
        and runtime_url.port in (None, 5432)
        and migration_url.port in (None, 5432)
        and not runtime_url.query and not migration_url.query
    ):
        pytest.fail('Unsafe migration fixture configuration')

    name = 'uptip_test_migration_' + uuid4().hex
    helper = Path('/usr/local/lib/uptip-test/migration_db_admin.py')
    if not direct_admin and not helper.is_file():
        pytest.fail('Install the restricted migration DB admin helper before testing')

    def administer(action):
        subprocess.run(
            ['sudo', '-n', '-u', 'postgres', '/usr/bin/python3', str(helper), action, name],
            check=True, timeout=30,
        )

    if direct_admin:
        from disposable_postgres import scheduling_database
        administer, migration_url, runtime_url = scheduling_database(
            name, direct_admin, settings.migration_database_url, settings.database_url,
            os.environ.get('UPTIP_TEST_DATABASE_URL', ''), kind='migration')
    administer('create')
    dedicated = None
    migration_engine = None
    try:
        test_runtime_url = runtime_url.set(database=name)
        test_migration_url = migration_url.set(database=name)
        migration_engine = create_engine(test_migration_url, hide_parameters=True)
        with migration_engine.connect() as connection:
            identity = connection.execute(text('''
                SELECT current_database(), r.rolname,
                       shobj_description(d.oid, 'pg_database')
                FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba
                WHERE d.datname=current_database()
            ''')).one()
            assert identity == (name, 'uptip', 'UPTIP disposable isolated migration test database')

        monkeypatch.setattr(settings, 'migration_database_url',
                            test_migration_url.render_as_string(hide_password=False))
        config = Config(str(Path(__file__).resolve().parents[1] / 'alembic.ini'))
        command.upgrade(config, '0016')
        # Bootstrap only this marked test DB's pre-Start runtime grants.
        # No owner membership, DDL, TRUNCATE or protected-history UPDATE.
        with migration_engine.begin() as connection:
            connection.execute(text('GRANT USAGE, SELECT ON SEQUENCE assessment_reference_sequence TO uptip_runtime'))
            connection.execute(text('GRANT SELECT ON roles TO uptip_runtime'))
            connection.execute(text('GRANT SELECT, UPDATE ON users TO uptip_runtime'))
            connection.execute(text('GRANT SELECT, INSERT, UPDATE, DELETE ON auth_sessions, login_buckets, password_change_challenges TO uptip_runtime'))
            connection.execute(text('GRANT SELECT, INSERT ON auth_events TO uptip_runtime'))
            connection.execute(text('GRANT SELECT, INSERT, UPDATE ON assessments, assessment_assignments, scope_entries, assessment_targets, baseline_tool_states, baseline_assignments TO uptip_runtime'))
            connection.execute(text('GRANT SELECT, INSERT ON assessment_creation_events, scope_events, baseline_evaluations TO uptip_runtime'))
        dedicated = create_engine(test_runtime_url, hide_parameters=True)
        with migration_engine.connect() as connection:
            assert connection.scalar(text('SELECT version_num FROM alembic_version')) == '0016'
        monkeypatch.setattr(settings, 'database_url',
                            test_runtime_url.render_as_string(hide_password=False))
        factory = sessionmaker(bind=dedicated, expire_on_commit=False)
        with factory() as session:
            session.info['migration_test_name'] = name
            session.info['migration_test_runtime_url'] = test_runtime_url
            session.info['migration_test_migration_url'] = test_migration_url
            yield session
            session.rollback()
    finally:
        from app.database import session_factory

        if session_factory.cache_info().currsize:
            cached_factory = session_factory()
            cached_factory.kw['bind'].dispose()
            session_factory.cache_clear()

        if dedicated is not None:
            dedicated.dispose()
        if migration_engine is not None:
            migration_engine.dispose()
        try:
            administer('drop')
        except Exception as exc:
            raise RuntimeError(
                f'Isolated migration test database {name} could not be safely deleted; '
                'inspect its connections and marker before manual recovery'
            ) from exc


@pytest.fixture
def migration_client(migration_db):
    """Test client connected to the isolated migration-test database."""
    from app.database import get_db
    from app.main import create_app

    app = create_app()
    app.dependency_overrides[get_db] = lambda: migration_db

    with TestClient(app, base_url="https://testserver") as test_client:
        test_client.headers["Origin"] = "https://testserver"
        yield test_client

    app.dependency_overrides.clear()

@pytest.fixture
def committed_db(engine, monkeypatch):
    """Committed database session for isolated concurrency tests."""
    from sqlalchemy.engine import make_url

    raw_url = os.environ.get("UPTIP_TEST_DATABASE_URL")
    if not raw_url:
        pytest.fail("UPTIP_TEST_DATABASE_URL is required")

    source_url = make_url(raw_url)

    if (
        source_url.drivername != "postgresql+psycopg"
        or source_url.database not in {"uptip_test_readiness_fix", "uptip_test_nikto_normalization"}
        or source_url.host not in {"127.0.0.1", "::1"}
        or source_url.query
    ):
        pytest.fail("Unsafe concurrency database configuration")

    direct_admin = os.environ.get('UPTIP_DISPOSABLE_ADMIN_URL')
    if direct_admin:
        from uuid import uuid4
        from disposable_postgres import scheduling_database
        from app.config import get_settings
        settings = get_settings()
        administer, owner, _ = scheduling_database(
            'uptip_test_schedule_' + uuid4().hex, direct_admin,
            os.environ.get('UPTIP_MIGRATION_DATABASE_URL', ''),
            os.environ.get('UPTIP_DATABASE_URL', ''), source_url)
        administer('create')
        isolated = create_engine(owner, hide_parameters=True)
        try:
            monkeypatch.setattr(settings, 'migration_database_url', owner.render_as_string(hide_password=False))
            config = Config(str(Path(__file__).resolve().parents[1] / 'alembic.ini'))
            config.set_main_option('script_location', str(Path(__file__).resolve().parents[1] / 'migrations'))
            command.upgrade(config, 'head')
            with sessionmaker(isolated, expire_on_commit=False)() as session:
                yield session
                session.rollback()
        finally:
            isolated.dispose()
            administer('drop')
        return

    url = source_url.set(database="uptip_test_concurrency")
    dedicated_engine = create_engine(url, hide_parameters=True)

    try:
        with dedicated_engine.connect() as connection:
            identity = connection.execute(text("""
                SELECT current_database(),
                       shobj_description(oid, 'pg_database')
                FROM pg_database
                WHERE datname = current_database()
            """)).one()

        assert identity == (
            "uptip_test_concurrency",
            "UPTIP disposable concurrency test database",
        ), "Concurrency database safety verification failed"

        factory = sessionmaker(
            bind=dedicated_engine,
            expire_on_commit=False,
        )


        # The database is recreated before each concurrency test.
        # Never TRUNCATE protected execution-history tables.
        try:
            with factory() as session:
                yield session
                session.rollback()
        finally:
            pass

    finally:
        dedicated_engine.dispose()


@pytest.fixture
def committed_client(committed_db):
    """Test client connected to the isolated concurrency database."""
    from app.database import get_db
    from app.main import create_app

    app = create_app()
    app.dependency_overrides[get_db] = lambda: committed_db

    with TestClient(app, base_url="https://testserver") as test_client:
        test_client.headers["Origin"] = "https://testserver"
        yield test_client

    app.dependency_overrides.clear()

@pytest.fixture
def client(db):
    from app.database import get_db
    from app.main import create_app
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, base_url='https://testserver') as client:
        client.headers['Origin'] = 'https://testserver'
        yield client


@pytest.fixture
def user(db):
    from app.models import Role, User
    from app.security import hasher
    db.add(Role(name='test-fixture-role'))
    db.flush()
    user = User(username='analyst-01', role='test-fixture-role', password_hash=hasher.hash('test-password'),
                password_change_required=False)
    db.add(user)
    db.commit()
    return user
