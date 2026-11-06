from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select
from app.models import AuthEvent, AuthSession, User
from app.security import digest

LOGIN = '/api/v1/auth/login'


def login(client, password='test-password', username='analyst-01'):
    return client.post(LOGIN, json={'username': username, 'password': password})


def test_valid_session_cookie_and_protected_resource(client, user, db):
    response = login(client)
    assert response.status_code == 200
    assert response.json()['state'] == 'authenticated'
    cookie = response.headers['set-cookie']
    assert 'HttpOnly' in cookie and 'Secure' in cookie and 'SameSite=strict' in cookie
    assert 'Path=/' in cookie and 'Max-Age=1800' in cookie
    token = client.cookies.get('__Host-uptip_session')
    session = db.get(AuthSession, digest(token))
    assert session and session.token_hash != token
    assert session.csrf_hash != response.json()['csrf_token']
    assert client.get('/api/v1/auth/session').status_code == 200
    assert 'password_hash' not in response.text and user.password_hash not in response.text


@pytest.mark.parametrize('status', ['disabled', 'locked'])
def test_unknown_and_wrong_password_do_not_disclose_account_state(client, user, db, status):
    wrong = login(client, password='wrong')
    unknown = login(client, username='unknown')
    user.status = status
    db.commit()
    disabled_wrong = login(client, password='wrong')
    unavailable = login(client)
    assert wrong.status_code == unknown.status_code == disabled_wrong.status_code == 401
    assert wrong.json() == unknown.json() == disabled_wrong.json()
    assert unavailable.status_code == 403
    assert unavailable.json()['state'] == 'account_unavailable'
    assert not client.cookies
    assert db.scalar(select(func.count()).select_from(AuthSession)) == 0
    assert 'account_unavailable' in db.scalars(select(AuthEvent.reason)).all()


def test_pending_never_issues_session(client, user, db):
    user.password_change_required = True
    db.commit()
    response = login(client)
    assert response.json()['state'] == 'password_change_required'
    assert response.json()['next_step_available'] is True
    assert response.json()['csrf_token']
    assert '__Host-uptip_session' not in client.cookies
    assert client.get('/api/v1/auth/session').status_code == 401
    assert db.scalar(select(func.count()).select_from(AuthSession)) == 0


def test_csrf_logout_and_session_revocation(client, user):
    csrf = login(client).json()['csrf_token']
    assert client.post('/api/v1/auth/logout').status_code == 403
    assert client.post('/api/v1/auth/logout', headers={'X-CSRF-Token': csrf, 'Origin': 'https://evil.test'}).status_code == 403
    assert client.post('/api/v1/auth/logout', headers={'X-CSRF-Token': csrf}).status_code == 200
    assert client.get('/api/v1/auth/session').status_code == 401


def test_expiration_and_policy_changes_reject_sessions(client, user, db):
    login(client)
    session = db.scalar(select(AuthSession))
    session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    expired = client.get('/api/v1/auth/session')
    assert expired.status_code == 401 and expired.json()['state'] == 'session_expired'
    assert 'Max-Age=0' in expired.headers['set-cookie']
    assert client.get('/api/v1/auth/session').json()['state'] == 'unauthenticated'
    login(client)
    user.password_change_required = True
    db.commit()
    assert client.get('/api/v1/auth/session').status_code == 401


def test_rotation(client, user, db):
    login(client)
    old = client.cookies.get('__Host-uptip_session')
    login(client)
    assert old != client.cookies.get('__Host-uptip_session')
    assert db.get(AuthSession, digest(old)) is None


def test_throttle_is_database_backed_and_does_not_leak(client, user, db):
    from app.config import get_settings
    settings = get_settings()
    original = settings.username_limit
    settings.username_limit = 2
    try:
        assert login(client, password='wrong').status_code == 401
        assert login(client, password='wrong').status_code == 401
        response = login(client)
        assert response.status_code == 429 and response.headers['retry-after'] == '900'
        assert 'test-password' not in response.text
        assert db.scalar(select(func.count()).select_from(AuthSession)) == 0
    finally:
        settings.username_limit = original


def test_validation_never_echoes_password_or_input(client):
    secret = 'never-echo-this-secret'
    response = client.post(LOGIN, json={'username': '', 'password': secret, 'extra': secret})
    assert response.status_code == 422 and secret not in response.text
    assert client.post(LOGIN, content='{invalid-secret', headers={'Content-Type': 'application/json'}).status_code == 422
    assert client.get('/api/v1/auth/session').status_code == 401


def test_origin_protection(client, user):
    assert login_without_origin(client).status_code == 403
    assert client.post(LOGIN, json={'username': user.username, 'password': 'test-password'},
                       headers={'Origin': 'https://evil.test'}).status_code == 403


def login_without_origin(client):
    del client.headers['Origin']
    return login(client)


def test_audit_does_not_contain_credentials(client, user, db):
    login(client, password='secret-invalid-password')
    events = db.scalars(select(AuthEvent)).all()
    assert len(events) == 1
    assert events[0].reason == 'invalid_credentials'
    assert len(events[0].client_key) == 64
    assert user.password_hash.startswith('$argon2id$')


def test_migration_schema_matches_models(engine):
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from app.database import Base
    with engine.connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []


def test_oversized_and_chunked_bodies_rejected(client):
    assert client.post(LOGIN, content=b'x' * 9000).status_code == 413
    response = client.post(LOGIN, content=iter([b'x' * 4096, b'x' * 4096, b'x']))
    assert response.status_code == 413
    assert response.headers['cache-control'] == 'no-store'


def test_server_database_errors_are_generic(client, user, monkeypatch):
    from sqlalchemy.exc import SQLAlchemyError
    from app import routes
    def unavailable(*args, **kwargs):
        raise SQLAlchemyError('sensitive-database-details')
    monkeypatch.setattr(routes, 'authenticate', unavailable)
    response = login(client)
    assert response.status_code == 503
    assert 'sensitive-database-details' not in response.text


def test_rate_window_expires(client, user, db, monkeypatch):
    from app import service
    from app.config import get_settings
    settings = get_settings()
    original = settings.username_limit
    settings.username_limit = 1
    try:
        monkeypatch.setattr(service.time, 'time', lambda: 1800)
        assert login(client, password='wrong').status_code == 401
        assert login(client).status_code == 429
        monkeypatch.setattr(service.time, 'time', lambda: 2700)
        assert login(client).status_code == 200
    finally:
        settings.username_limit = original


def test_atomic_throttle_across_connections(engine):
    from concurrent.futures import ThreadPoolExecutor
    from sqlalchemy.orm import Session
    from app.config import get_settings
    from app.service import throttled
    settings = get_settings()
    original = settings.username_limit
    settings.username_limit = 3
    def attempt(_):
        with Session(engine) as session:
            denied = throttled(session, settings, 'concurrency-fixture', 'concurrency-fixture')
            session.commit()
            return denied
    try:
        with ThreadPoolExecutor(max_workers=6) as pool:
            assert list(pool.map(attempt, range(6))).count(False) == 3
    finally:
        settings.username_limit = original


@pytest.mark.parametrize('status', ['disabled', 'locked'])
def test_account_status_change_rejects_existing_session(client, user, db, status):
    assert login(client).json()['state'] == 'authenticated'
    user.status = status
    db.commit()
    assert client.get('/api/v1/auth/session').status_code == 401


def test_authenticated_session_keeps_server_assigned_role(client, user, db):
    from starlette.requests import Request
    from app.routes import current_session
    from app.models import Role
    db.add(Role(name='other-test-role'))
    db.commit()
    # Client cannot select or override a role on login.
    rejected = client.post(LOGIN, json={'username': user.username, 'password': 'test-password', 'role': 'other-test-role'})
    assert rejected.status_code == 422
    login(client)
    token = client.cookies.get('__Host-uptip_session')
    request = Request({'type': 'http', 'headers': [(b'cookie', f'__Host-uptip_session={token}'.encode())]})
    session, principal = current_session(request, db)
    assert session and principal.id == user.id
    assert principal.role == 'test-fixture-role'


def test_removed_endpoints_are_not_registered(client):
    assert client.post('/api/v1/auth/mfa/verify', json={'code': '123456'}).status_code == 404
    assert client.get('/api/v1/auth/mfa/challenge').status_code == 404
