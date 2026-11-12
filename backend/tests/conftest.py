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
