from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import secrets

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import password_service
from app.config import get_settings
from app.models import AuthEvent, AuthSession, MfaChallenge, MfaCredential, PasswordChangeChallenge
from app.security import digest, hasher, verify_password

# Test-fixture credentials only; nothing is seeded in the application database.
TEMPORARY = 'InitialPassword123!'
REPLACEMENT = 'ReplacementPassword456!'


@pytest.fixture
def temporary_user(user, db):
    user.password_hash = hasher.hash(TEMPORARY)
    user.password_change_required = True
    db.commit()
    return user


def begin(client):
    response = client.post('/api/v1/auth/login', json={'username': 'analyst-01', 'password': TEMPORARY})
    assert response.status_code == 200 and response.json()['state'] == 'password_change_required'
    assert response.json()['next_step_available'] is True
    return response.json()['csrf_token']


def change(client, csrf, password=REPLACEMENT, confirmation=None):
    return client.post('/api/v1/auth/password/change', json={'new_password': password,
        'confirmation': password if confirmation is None else confirmation}, headers={'X-CSRF-Token': csrf})


def test_temporary_password_required_for_restricted_challenge(client, temporary_user, db):
    wrong = client.post('/api/v1/auth/login', json={'username': temporary_user.username, 'password': 'wrong'})
    assert wrong.status_code == 401 and not client.cookies
    csrf = begin(client)
    raw = client.cookies.get('__Host-uptip_password_change')
    challenge = db.scalar(select(PasswordChangeChallenge))
    assert challenge.token_hash == digest(raw) and challenge.token_hash != raw
    assert challenge.password_fingerprint == digest(temporary_user.password_hash)
    assert challenge.expires_at > password_service.now()
    assert client.get('/api/v1/auth/password/challenge').json()['csrf_token'] == csrf
    assert client.get('/api/v1/auth/session').status_code == 401
    assert db.scalar(select(func.count()).select_from(AuthSession)) == 0


def test_password_replacement_is_single_use_and_requires_fresh_login(client, temporary_user, db):
    csrf = begin(client)
    raw = client.cookies.get('__Host-uptip_password_change')
    response = change(client, csrf)
    assert response.status_code == 200 and response.json()['state'] == 'password_changed'
    assert response.json()['csrf_token'] is None
    assert not temporary_user.password_change_required
    assert verify_password(REPLACEMENT, temporary_user.password_hash)
    assert not verify_password(TEMPORARY, temporary_user.password_hash)
    assert db.get(PasswordChangeChallenge, digest(raw)).consumed
    assert db.scalar(select(func.count()).select_from(AuthSession)) == 0
    assert client.get('/api/v1/auth/session').status_code == 401
    assert client.post('/api/v1/auth/login', json={'username': 'analyst-01', 'password': TEMPORARY}).status_code == 401
    response = client.post('/api/v1/auth/login', json={'username': 'analyst-01', 'password': REPLACEMENT})
    assert response.json()['state'] == 'authenticated'
    assert client.get('/api/v1/auth/session').status_code == 200
    assert 'password_changed' in db.scalars(select(AuthEvent.reason)).all()


def test_confirmation_and_complexity_are_server_enforced(client, temporary_user, db):
    csrf = begin(client)
    before = temporary_user.password_hash
    response = change(client, csrf, confirmation='DifferentPassword789!')
    assert response.status_code == 422 and response.json()['state'] == 'password_mismatch'
    assert response.json()['message'] == 'Passwords do not match. Re-enter your new password.'
    assert temporary_user.password_hash == before and temporary_user.password_change_required
    for invalid in ['Short1!', 'lowercaseonly123!', 'UPPERCASEONLY123!', 'NoNumbersHere!!', 'NoSymbolsHere123', ' ' * 20]:
        response = change(client, csrf, invalid)
        assert response.status_code == 422 and response.json()['state'] == 'password_rejected'
        assert invalid not in response.text
    assert temporary_user.password_hash == before
    assert change(client, csrf).json()['state'] == 'password_changed'


def test_rejects_temporary_password_reuse(client, temporary_user):
    csrf = begin(client)
    response = change(client, csrf, TEMPORARY)
    assert response.json()['state'] == 'password_rejected'
    assert response.json()['message'] == 'Choose a password different from your temporary password.'
    assert temporary_user.password_change_required


def test_missing_invalid_expired_and_consumed_challenges(client, temporary_user, db):
    assert change(client, 'missing').status_code == 401
    client.cookies.set('__Host-uptip_password_change', secrets.token_urlsafe(32))
    assert change(client, 'wrong').status_code == 401
    client.cookies.clear()
    csrf = begin(client)
    raw = client.cookies.get('__Host-uptip_password_change')
    challenge = db.get(PasswordChangeChallenge, digest(raw))
    challenge.expires_at = password_service.now() - timedelta(seconds=1)
    db.commit()
    assert change(client, csrf).json()['state'] == 'challenge_expired'
    assert client.get('/api/v1/auth/password/challenge').status_code == 401
    client.cookies.clear()
    csrf = begin(client)
    raw = client.cookies.get('__Host-uptip_password_change')
    assert change(client, csrf).status_code == 200
    client.cookies.set('__Host-uptip_password_change', raw)
    assert change(client, csrf).json()['state'] == 'challenge_expired'


def test_origin_and_csrf_cannot_be_bypassed(client, temporary_user):
    csrf = begin(client)
    assert change(client, 'wrong').status_code == 403
    response = client.post('/api/v1/auth/password/change', json={'new_password': REPLACEMENT, 'confirmation': REPLACEMENT},
                           headers={'X-CSRF-Token': csrf, 'Origin': 'https://evil.test'})
    assert response.status_code == 403
    assert temporary_user.password_change_required


def test_replacement_revokes_sessions_and_all_pending_challenges(client, temporary_user, db):
    csrf = begin(client)
    credential = MfaCredential(user_id=temporary_user.id, secret_ciphertext='unusable-test-fixture-ciphertext')
    db.add(credential)
    db.flush()
    db.add(AuthSession(token_hash='a' * 64, csrf_hash='b' * 64, user_id=temporary_user.id,
        expires_at=password_service.now() + timedelta(minutes=20)))
    db.add(MfaChallenge(token_hash='c' * 64, user_id=temporary_user.id, credential_id=credential.id,
        password_fingerprint=digest(temporary_user.password_hash), expires_at=password_service.now() + timedelta(minutes=5), environment='test'))
    db.commit()
    assert change(client, csrf).json()['state'] == 'password_changed'
    assert db.scalar(select(func.count()).select_from(AuthSession)) == 0
    assert all(c.consumed for c in db.scalars(select(MfaChallenge)))
    assert all(c.consumed for c in db.scalars(select(PasswordChangeChallenge)))


def test_concurrent_changes_accept_only_one(client, temporary_user, engine):
    csrf = begin(client)
    raw = client.cookies.get('__Host-uptip_password_change')
    def attempt(_):
        with Session(engine) as db:
            status, result = password_service.change(db, get_settings(), raw, csrf, REPLACEMENT, REPLACEMENT, 'concurrency-fixture')
            return result['state']
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, range(2)))
    assert outcomes.count('password_changed') == 1
    assert outcomes.count('challenge_expired') == 1


def test_mfa_requirement_is_not_bypassed_after_replacement(client, temporary_user, db):
    temporary_user.mfa_required = True
    db.commit()
    csrf = begin(client)
    assert change(client, csrf).json()['state'] == 'password_changed'
    response = client.post('/api/v1/auth/login', json={'username': 'analyst-01', 'password': REPLACEMENT})
    assert response.json()['state'] == 'mfa_enrollment_required'
    assert client.get('/api/v1/auth/session').status_code == 401


def test_password_fingerprint_and_status_are_rechecked(client, temporary_user, db):
    csrf = begin(client)
    temporary_user.password_hash = hasher.hash('AnotherTemporaryPassword123!')
    db.commit()
    assert change(client, csrf).json()['state'] == 'challenge_expired'


def test_rate_limits_are_shared_and_no_secrets_in_validation(client, temporary_user, monkeypatch):
    csrf = begin(client)
    settings = get_settings()
    monkeypatch.setattr(settings, 'username_limit', 1)
    assert change(client, csrf, confirmation='wrong').status_code == 422
    assert change(client, csrf).status_code == 429
    response = client.post('/api/v1/auth/password/change', json={'new_password': '', 'confirmation': REPLACEMENT, 'extra': TEMPORARY})
    assert response.status_code == 422 and REPLACEMENT not in response.text and TEMPORARY not in response.text
