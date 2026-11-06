import os
import sys
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
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
    # Refuse destructive test reset against a database without an explicit test name.
    from sqlalchemy.engine import make_url
    assert 'test' in (make_url(database_url).database or '')
    os.environ.update(UPTIP_DATABASE_URL=database_url, UPTIP_ENVIRONMENT='test',
                      UPTIP_PUBLIC_ORIGIN='https://testserver', UPTIP_COOKIE_SECURE='true',
                      UPTIP_RATE_KEY='test-only-not-a-deployment-secret-123456')
    from app.config import get_settings
    get_settings.cache_clear()
    config = Config(str(Path(__file__).resolve().parents[1] / 'alembic.ini'))
    command.downgrade(config, 'base')
    command.upgrade(config, 'head')
    engine = create_engine(database_url)
    yield engine
    engine.dispose()


@pytest.fixture
def db(engine):
    with engine.begin() as conn:
        conn.execute(text('TRUNCATE auth_events, auth_sessions, login_buckets, users, roles CASCADE'))
    with sessionmaker(engine, expire_on_commit=False)() as session:
        yield session


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
