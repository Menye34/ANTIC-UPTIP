from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
import pyotp
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import mfa_service
from app.config import Settings, get_settings
from app.main import create_app
from app.database import get_db
from app.models import AuthSession, MfaChallenge, MfaCredential


@pytest.fixture
def enrolled(user, db, monkeypatch):
    settings = get_settings()
    key = Fernet.generate_key()
    monkeypatch.setattr(settings, 'environment', 'development')
    monkeypatch.setattr(settings, 'dev_mfa_username', user.username)
    monkeypatch.setattr(settings, 'dev_mfa_max_attempts', 3)  # Test fixture choice, not production policy.
    monkeypatch.setattr(settings, 'mfa_encryption_key', key.decode())
    secret = pyotp.random_base32()
    credential = MfaCredential(user_id=user.id, secret_ciphertext=Fernet(key).encrypt(secret.encode()).decode())
    user.mfa_required = True
    user.mfa_enrolled = True
    db.add(credential)
    db.commit()
    return user, credential, pyotp.TOTP(secret)


def begin(client):
    response = client.post('/api/v1/auth/login', json={'username': 'analyst-01', 'password': 'test-password'})
    assert response.status_code == 200 and response.json()['next_step_available']
    assert response.json()['state'] == 'mfa_verification_required'
    assert '__Host-uptip_session' not in client.cookies
    return response.json()['csrf_token']


def verify(client, csrf, code):
    return client.post('/api/v1/auth/mfa/verify', json={'code': code}, headers={'X-CSRF-Token': csrf})


def test_real_totp_promotes_only_after_verification(client, enrolled, db):
    user, credential, totp = enrolled
    csrf = begin(client)
    assert client.get('/api/v1/auth/session').status_code == 401
    response = verify(client, csrf, totp.now())
    assert response.status_code == 200 and response.json()['state'] == 'authenticated'
    assert 'HttpOnly' in response.headers['set-cookie'] and 'Secure' in response.headers['set-cookie']
    assert client.get('/api/v1/auth/session').status_code == 200
    assert db.scalar(select(AuthSession)).mfa_credential_id == credential.id
    assert db.scalar(select(MfaChallenge)).consumed
    assert totp.secret not in response.text and credential.secret_ciphertext not in response.text
    assert verify(client, csrf, totp.now()).status_code == 401


def test_invalid_replay_and_old_codes_do_not_authenticate(client, enrolled, db):
    _, credential, totp = enrolled
    csrf = begin(client)
    wrong = next(f'{n:06}' for n in range(100) if not totp.verify(f'{n:06}', valid_window=1))
    assert verify(client, csrf, wrong).json()['state'] == 'invalid_code'
    old_code = totp.at(mfa_service.now().timestamp() - 120)
    assert verify(client, csrf, old_code).json()['state'] == 'invalid_code'
    assert db.scalar(select(func.count()).select_from(AuthSession)) == 0
    assert verify(client, csrf, totp.now()).json()['state'] == 'authenticated'
    # Fresh username/password challenge must not make an accepted time step reusable.
    client.cookies.clear()
    csrf = begin(client)
    response = verify(client, csrf, totp.now())
    assert response.json()['state'] == 'invalid_code'
    assert credential.last_accepted_step is not None


def test_lockout_persists_across_login_and_cancel_without_extension(client, enrolled, db, monkeypatch):
    _, credential, totp = enrolled
    fixed = mfa_service.now()
    monkeypatch.setattr(mfa_service, 'now', lambda: fixed)
    wrong = next(f'{n:06}' for n in range(100) if not totp.verify(f'{n:06}', for_time=fixed, valid_window=1))
    csrf = begin(client)
    for _ in range(2):
        assert verify(client, csrf, wrong).json()['state'] == 'invalid_code'
    locked = verify(client, csrf, wrong)
    assert locked.status_code == 429 and locked.json()['retry_after_seconds'] == 900
    end = credential.locked_until
    assert end == fixed + timedelta(minutes=15)
    for _ in range(2):
        assert verify(client, csrf, totp.at(fixed)).json()['state'] == 'too_many_attempts'
        assert credential.locked_until == end and credential.failed_attempts == 3
    assert client.post('/api/v1/auth/mfa/cancel', headers={'X-CSRF-Token': csrf}).status_code == 200
    client.cookies.clear()
    csrf = begin(client)
    assert client.get('/api/v1/auth/mfa/challenge').json()['state'] == 'too_many_attempts'
    assert verify(client, csrf, totp.at(fixed)).json()['state'] == 'too_many_attempts'
    monkeypatch.setattr(mfa_service, 'now', lambda: fixed + timedelta(minutes=15, seconds=1))
    client.cookies.clear()
    csrf = begin(client)
    assert verify(client, csrf, totp.at(mfa_service.now())).json()['state'] == 'authenticated'


def test_challenge_expiry_missing_csrf_and_origin(client, enrolled, db):
    _, _, totp = enrolled
    assert client.get('/api/v1/auth/mfa/challenge').status_code == 401
    assert verify(client, 'missing', totp.now()).status_code == 401
    csrf = begin(client)
    assert verify(client, 'wrong', totp.now()).status_code == 403
    assert client.post('/api/v1/auth/mfa/verify', json={'code': totp.now()}, headers={
        'X-CSRF-Token': csrf, 'Origin': 'https://evil.test'}).status_code == 403
    challenge = db.scalar(select(MfaChallenge))
    challenge.expires_at = mfa_service.now() - timedelta(seconds=1)
    db.commit()
    assert verify(client, csrf, totp.now()).json()['state'] == 'challenge_expired'
    assert client.get('/api/v1/auth/session').status_code == 401
    assert client.post('/api/v1/auth/mfa/cancel', headers={'X-CSRF-Token': csrf}).json()['state'] == 'mfa_cancelled'
    assert challenge.consumed


def test_cancellation_does_not_invalidate_other_sessions(client, enrolled, db):
    user, _, totp = enrolled
    # An unrelated previously authenticated browser session is not touched by cancellation.
    db.add(AuthSession(token_hash='a' * 64, csrf_hash='b' * 64, user_id=user.id,
                       expires_at=mfa_service.now() + timedelta(minutes=20)))
    db.commit()
    csrf = begin(client)
    assert client.post('/api/v1/auth/mfa/cancel', headers={'X-CSRF-Token': 'wrong'}).status_code == 403
    assert client.post('/api/v1/auth/mfa/cancel', headers={'X-CSRF-Token': csrf}).json()['state'] == 'mfa_cancelled'
    assert verify(client, csrf, totp.now()).json()['state'] == 'challenge_expired'
    assert db.get(AuthSession, 'a' * 64) is not None
    assert not client.cookies.get('__Host-uptip_session')


def test_password_status_and_configuration_changes_fail_closed(client, enrolled, db, monkeypatch):
    user, _, totp = enrolled
    csrf = begin(client)
    user.password_change_required = True
    db.commit()
    assert verify(client, csrf, totp.now()).json()['state'] == 'challenge_expired'
    user.password_change_required = False
    db.commit()
    csrf = begin(client)
    monkeypatch.setattr(get_settings(), 'environment', 'production')
    assert verify(client, csrf, totp.now()).json()['state'] == 'challenge_expired'
    assert client.get('/api/v1/auth/session').status_code == 401


def test_production_has_no_development_mfa_decision(client, enrolled, monkeypatch):
    monkeypatch.setattr(get_settings(), 'environment', 'production')
    response = client.post('/api/v1/auth/login', json={'username': 'analyst-01', 'password': 'test-password'})
    assert response.json()['state'] == 'mfa_verification_required'
    assert response.json()['next_step_available'] is False
    assert response.json()['csrf_token'] is None and not client.cookies
    with pytest.raises(ValueError):
        Settings(database_url='postgresql+psycopg://unused', rate_key='x' * 32,
                 dev_mfa_username='development-fixture', dev_mfa_max_attempts=3,
                 mfa_encryption_key=Fernet.generate_key().decode())


def test_validation_and_secret_errors_do_not_leak(client, enrolled, db):
    _, credential, totp = enrolled
    csrf = begin(client)
    for code in ['12345', '1234567', 'abcdef', '１２３４５６', 123456]:
        response = verify(client, csrf, code)
        assert response.status_code == 422
        assert str(code) not in response.text
    credential.secret_ciphertext = 'corrupt-private-secret'
    db.commit()
    response = verify(client, csrf, totp.now())
    assert response.status_code == 503 and 'corrupt-private-secret' not in response.text


def test_leading_zero_and_clock_skew(client, enrolled, monkeypatch):
    _, _, totp = enrolled
    base = int(mfa_service.now().timestamp()) // 30
    step = next(n for n in range(base, base + 300) if totp.at(n * 30).startswith('0'))
    from datetime import datetime, timezone
    monkeypatch.setattr(mfa_service, 'now', lambda: datetime.fromtimestamp(step * 30, timezone.utc))
    csrf = begin(client)
    code = totp.at(step * 30)
    assert code.startswith('0') and verify(client, csrf, code).json()['state'] == 'authenticated'


def test_concurrent_requests_accept_code_only_once(client, enrolled, engine):
    _, _, totp = enrolled
    csrf = begin(client)
    raw = client.cookies.get('__Host-uptip_mfa')
    code = totp.now()
    def request(_):
        with Session(engine) as session:
            status, result, token = mfa_service.verify(session, get_settings(), raw, csrf, code, 'test-peer')
            return result['state']
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(request, range(2)))
    assert outcomes.count('authenticated') == 1
    assert outcomes.count('challenge_expired') == 1


def test_password_replacement_precedes_mfa_and_unenrolled_stays_pending(client, enrolled, db):
    user, _, _ = enrolled
    user.password_change_required = True
    db.commit()
    response = client.post('/api/v1/auth/login', json={'username': user.username, 'password': 'test-password'})
    assert response.json()['state'] == 'password_change_required'
    assert response.json()['next_step_available'] is True
    assert '__Host-uptip_session' not in client.cookies
    user.password_change_required = False
    user.mfa_enrolled = False
    db.commit()
    response = client.post('/api/v1/auth/login', json={'username': user.username, 'password': 'test-password'})
    assert response.json()['state'] == 'mfa_enrollment_required'
    assert response.json()['next_step_available'] is False
    assert db.scalar(select(func.count()).select_from(MfaChallenge)) == 0


def test_development_session_proof_is_not_accepted_in_production(client, enrolled, monkeypatch):
    _, _, totp = enrolled
    csrf = begin(client)
    assert verify(client, csrf, totp.now()).json()['state'] == 'authenticated'
    assert client.get('/api/v1/auth/session').status_code == 200
    monkeypatch.setattr(get_settings(), 'environment', 'production')
    assert client.get('/api/v1/auth/session').status_code == 401


def test_development_config_requires_explicit_threshold():
    with pytest.raises(ValueError):
        Settings(database_url='postgresql+psycopg://unused', rate_key='x' * 32,
                 environment='development', dev_mfa_username='dedicated-fixture',
                 mfa_encryption_key=Fernet.generate_key().decode())


def test_interactive_development_provisioning_encrypts_and_verifies_secret(client, enrolled, db, monkeypatch, capsys):
    from app import mfa_provision
    user, credential, _ = enrolled
    db.delete(credential)
    user.mfa_enrolled = False
    db.commit()
    captured_secret = []
    def enrollment_code(prompt):
        output = capsys.readouterr().out
        uri = next(line for line in output.splitlines() if line.startswith('otpauth://'))
        authenticator = pyotp.parse_uri(uri)
        captured_secret.append(authenticator.secret)
        return authenticator.now()
    monkeypatch.setattr(mfa_provision, 'session_factory', lambda: lambda: db)
    monkeypatch.setattr(mfa_provision, 'getpass', enrollment_code)
    mfa_provision.main()
    # CLI owns/closes its session; inspect committed records with a fresh session.
    with Session(db.bind) as check:
        stored = check.scalar(select(MfaCredential))
        assert stored and stored.last_accepted_step is not None
        assert captured_secret[0] not in stored.secret_ciphertext
        assert Fernet(get_settings().mfa_encryption_key.encode()).decrypt(stored.secret_ciphertext.encode()).decode() == captured_secret[0]
