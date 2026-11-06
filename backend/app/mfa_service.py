"""Real TOTP verification. Production issuance awaits an approved policy decision source."""
from datetime import datetime, timedelta, timezone
import hmac
import math
import secrets

from cryptography.fernet import Fernet, InvalidToken
import pyotp
from sqlalchemy import select, update

from .models import AuthEvent, AuthSession, MfaChallenge, MfaCredential, User
from .security import client_key, digest
from .service import audit

INVALID_CODE = 'That code is incorrect. Check your authenticator app and try again.'
LOCKED = 'Too many attempts. Try again in 15 minutes or contact your administrator.'
CHALLENGE_EXPIRED = 'Your verification session has ended. Sign in again to continue.'


def now():
    return datetime.now(timezone.utc)


def development_enabled(settings, user):
    return settings.environment == 'development' and settings.dev_mfa_username == user.username and bool(
        settings.dev_mfa_max_attempts and settings.mfa_encryption_key)


def csrf_for(settings, raw):
    return client_key(settings.rate_key, 'mfa-csrf:' + raw)


def begin(db, settings, user):
    if not development_enabled(settings, user):
        return None
    credential = db.scalar(select(MfaCredential).where(MfaCredential.user_id == user.id).with_for_update())
    if not credential or not user.mfa_enrolled:
        return None
    db.execute(update(MfaChallenge).where(MfaChallenge.user_id == user.id).values(consumed=True))
    raw = secrets.token_urlsafe(32)
    db.add(MfaChallenge(token_hash=digest(raw), user_id=user.id, credential_id=credential.id,
                        password_fingerprint=digest(user.password_hash), expires_at=now() + timedelta(minutes=5),
                        environment=settings.environment))
    return {'state': 'mfa_verification_required', 'message': 'MFA verification required.',
            'next_step_available': True, 'csrf_token': csrf_for(settings, raw), '_pending_token': raw}


def challenge_context(db, settings, raw):
    if not raw or len(raw) > 128:
        return None
    challenge = db.get(MfaChallenge, digest(raw))
    if not challenge:
        return None
    # Shared order with password login: user -> credential -> challenge. Serializes promotion/cancellation.
    user = db.scalar(select(User).where(User.id == challenge.user_id).with_for_update().execution_options(populate_existing=True))
    credential = db.scalar(select(MfaCredential).where(MfaCredential.id == challenge.credential_id).with_for_update().execution_options(populate_existing=True))
    db.refresh(challenge, with_for_update=True)
    if (not user or not credential or challenge.consumed or challenge.environment != settings.environment
        or not development_enabled(settings, user) or user.status != 'active' or user.password_change_required
        or not user.mfa_enrolled or challenge.password_fingerprint != digest(user.password_hash)):
        return None
    return challenge, user, credential


def lock_result(credential):
    if credential.locked_until and credential.locked_until > now():
        return {'state': 'too_many_attempts', 'message': LOCKED,
                'retry_after_seconds': max(1, math.ceil((credential.locked_until - now()).total_seconds()))}
    return None


def inspect(db, settings, raw):
    context = challenge_context(db, settings, raw)
    if not context:
        return 401, {'state': 'challenge_expired', 'message': CHALLENGE_EXPIRED}
    challenge, user, credential = context
    # A lockout outlives its challenge and remains attached to the account credential.
    if locked := lock_result(credential):
        return 429, locked
    if challenge.expires_at <= now():
        return 401, {'state': 'challenge_expired', 'message': CHALLENGE_EXPIRED}
    return 200, {'state': 'mfa_verification_required', 'message': 'MFA verification required.',
                 'next_step_available': True, 'csrf_token': csrf_for(settings, raw)}


def verify(db, settings, raw, csrf, code, ip):
    context = challenge_context(db, settings, raw)
    if not context:
        return 401, {'state': 'challenge_expired', 'message': CHALLENGE_EXPIRED}, None
    challenge, user, credential = context
    if not hmac.compare_digest(csrf_for(settings, raw), csrf):
        return 403, {'state': 'forbidden', 'message': 'Request could not be verified.'}, None
    ip_key = client_key(settings.rate_key, 'ip:' + ip)
    if locked := lock_result(credential):
        return 429, locked, None  # Never extend lockout or increase the counter for blocked requests.
    if challenge.expires_at <= now():
        return 401, {'state': 'challenge_expired', 'message': CHALLENGE_EXPIRED}, None
    if credential.locked_until:
        credential.failed_attempts = 0
        credential.locked_until = None
    try:
        secret = Fernet(settings.mfa_encryption_key.encode()).decrypt(credential.secret_ciphertext.encode()).decode()
    except (InvalidToken, ValueError):
        audit(db, 'mfa_unavailable', ip_key, user)
        db.commit()
        return 503, {'state': 'unavailable', 'message': 'Verification is temporarily unavailable. Please try again.'}, None
    totp = pyotp.TOTP(secret, digits=6, interval=30)
    step = int(now().timestamp()) // 30
    # Accept only +/- one 30-second time step. Record a monotonic high-water mark.
    matches = [candidate for candidate in (step - 1, step, step + 1)
               if totp.verify(code, for_time=candidate * 30, valid_window=0)]
    accepted = max(matches) if matches else None
    if accepted is None or (credential.last_accepted_step is not None and accepted <= credential.last_accepted_step):
        credential.failed_attempts += 1
        if credential.failed_attempts >= settings.dev_mfa_max_attempts:
            credential.locked_until = now() + timedelta(minutes=15)
            audit(db, 'mfa_locked', ip_key, user)
            result = lock_result(credential)
            db.commit()
            return 429, result, None
        audit(db, 'mfa_invalid_code', ip_key, user)
        db.commit()
        # TOTP cannot reliably prove which historic interval an arbitrary incorrect code belongs to.
        return 401, {'state': 'invalid_code', 'message': INVALID_CODE}, None
    credential.last_accepted_step = accepted
    credential.failed_attempts = 0
    credential.locked_until = None
    user.mfa_verified_at = now()
    challenge.consumed = True
    token, session_csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    db.add(AuthSession(token_hash=digest(token), csrf_hash=digest(session_csrf), user_id=user.id,
                       mfa_credential_id=credential.id, expires_at=now() + timedelta(seconds=settings.session_seconds)))
    audit(db, 'mfa_verified', ip_key, user)
    db.commit()
    return 200, {'state': 'authenticated', 'message': 'Authentication complete.', 'csrf_token': session_csrf}, token


def cancel(db, settings, raw, csrf, ip):
    if not raw:
        return 200, {'state': 'mfa_cancelled', 'message': 'Verification cancelled.'}
    if len(raw) > 128 or not hmac.compare_digest(csrf_for(settings, raw), csrf):
        return 403, {'state': 'forbidden', 'message': 'Request could not be verified.'}
    challenge = db.get(MfaChallenge, digest(raw))
    if challenge:
        db.scalar(select(User).where(User.id == challenge.user_id).with_for_update())
        db.refresh(challenge, with_for_update=True)
    if challenge and not challenge.consumed:
        challenge.consumed = True
        db.add(AuthEvent(
            reason='mfa_cancelled', user_id=challenge.user_id, client_key=client_key(settings.rate_key, 'ip:' + ip)))
        db.commit()
    return 200, {'state': 'mfa_cancelled', 'message': 'Verification cancelled.'}
