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
    if (url.drivername != 'postgresql+psycopg' or url.database != 'uptip_test_readiness_fix'
            or url.host not in {'127.0.0.1', '::1'} or url.query):
        pytest.fail('Use the dedicated local PostgreSQL database uptip_test_readiness_fix with no URL query options.',
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
        if identity != ('uptip_test_readiness_fix', 'UPTIP disposable integration test database'):
            pytest.fail(
                "After creating a dedicated disposable database, run "
                "COMMENT ON DATABASE uptip_test_readiness_fix IS 'UPTIP disposable integration test database';",
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
def migration_db():
    """Committed runtime session on the isolated migration-test database."""
    import os

    os.environ.update(
        UPTIP_ENVIRONMENT="test",
        UPTIP_PUBLIC_ORIGIN="https://testserver",
        UPTIP_COOKIE_SECURE="true",
        UPTIP_RATE_KEY="test-only-not-a-deployment-secret-123456",
    )

    from app.config import get_settings
    get_settings.cache_clear()

    yield from _migration_db_session()


def _migration_db_session():
    """Committed runtime session on the dedicated migration-test database."""
    from app.config import get_settings

    settings = get_settings()
    runtime_url = make_url(settings.database_url)
    migration_url = make_url(settings.migration_database_url)

    if not (
        runtime_url.username == "uptip_runtime"
        and migration_url.username == "uptip"
        and runtime_url.database == migration_url.database == "uptip"
        and runtime_url.host == migration_url.host == "127.0.0.1"
    ):
        pytest.fail("Unsafe migration fixture configuration")

    test_url = runtime_url.set(database="uptip_test_migration_0016")
    dedicated_engine = create_engine(test_url, hide_parameters=True)

    try:
        with dedicated_engine.connect() as connection:
            identity = connection.execute(text("""
                SELECT current_database(),
                       shobj_description(oid, 'pg_database')
                FROM pg_database
                WHERE datname = current_database()
            """)).one()

            revision = connection.scalar(
                text("SELECT version_num FROM alembic_version")
            )

        if identity != (
            "uptip_test_migration_0016",
            "UPTIP disposable migration integration test database",
        ) or revision != "0016":
            pytest.fail("Migration database identity or revision mismatch")

        factory = sessionmaker(
            bind=dedicated_engine,
            expire_on_commit=False,
        )

        with factory() as session:
            yield session
            session.rollback()

    finally:
        dedicated_engine.dispose()


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
def committed_db(engine):
    """Committed database session for isolated concurrency tests."""
    from sqlalchemy.engine import make_url

    raw_url = os.environ.get("UPTIP_TEST_DATABASE_URL")
    if not raw_url:
        pytest.fail("UPTIP_TEST_DATABASE_URL is required")

    source_url = make_url(raw_url)

    if (
        source_url.drivername != "postgresql+psycopg"
        or source_url.database != "uptip_test_readiness_fix"
        or source_url.host not in {"127.0.0.1", "::1"}
        or source_url.query
    ):
        pytest.fail("Unsafe concurrency database configuration")

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
