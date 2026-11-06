from datetime import datetime, timedelta, timezone
import hmac
import secrets
import unicodedata

from sqlalchemy import delete, select, update

from .models import AuthSession, PasswordChangeChallenge, User
from .security import client_key, digest, hasher, verify_password
from .service import audit, throttled

MISMATCH = 'Passwords do not match. Re-enter your new password.'
ENDED = 'Your password-change session has ended. Sign in again to continue.'


def now():
    return datetime.now(timezone.utc)


def meets_requirements(password):
    categories = {unicodedata.category(char) for char in password}
    return (12 <= len(password) <= 1024 and {'Lu', 'Ll', 'Nd'} <= categories
            and any(category.startswith(('P', 'S')) for category in categories))


def csrf_for(settings, raw):
    return client_key(settings.rate_key, 'password-change-csrf:' + raw)


def begin(db, settings, user):
    # Called only after password verification and account eligibility checks, with the user locked.
    db.execute(update(PasswordChangeChallenge).where(PasswordChangeChallenge.user_id == user.id).values(consumed=True))
    raw = secrets.token_urlsafe(32)
    db.add(PasswordChangeChallenge(token_hash=digest(raw), user_id=user.id,
        password_fingerprint=digest(user.password_hash), expires_at=now() + timedelta(minutes=5), environment=settings.environment))
    return {'state': 'password_change_required', 'message': 'Password replacement required.',
            'next_step_available': True, 'csrf_token': csrf_for(settings, raw), '_password_token': raw}


def valid(settings, challenge, user):
    return bool(user and user.status == 'active' and user.password_change_required
        and not challenge.consumed and challenge.expires_at > now()
        and challenge.environment == settings.environment and challenge.password_fingerprint == digest(user.password_hash))


def inspect(db, settings, raw):
    challenge = db.get(PasswordChangeChallenge, digest(raw)) if raw and len(raw) <= 128 else None
    if not challenge or not valid(settings, challenge, db.get(User, challenge.user_id)):
        return 401, {'state': 'challenge_expired', 'message': ENDED}
    return 200, {'state': 'password_change_required', 'message': 'Password replacement required.',
                 'next_step_available': True, 'csrf_token': csrf_for(settings, raw)}


def change(db, settings, raw, csrf, new_password, confirmation, ip):
    challenge = db.get(PasswordChangeChallenge, digest(raw)) if raw and len(raw) <= 128 else None
    if not challenge:
        return 401, {'state': 'challenge_expired', 'message': ENDED}
    if not hmac.compare_digest(csrf_for(settings, raw), csrf):
        return 403, {'state': 'forbidden', 'message': 'Request could not be verified.'}
    ip_key = client_key(settings.rate_key, 'ip:' + ip)
    # Reuse the existing shared IP and per-subject limits, before taking user locks.
    if throttled(db, settings, 'password-change:' + str(challenge.user_id), ip):
        audit(db, 'password_change_throttled', ip_key)
        db.commit()
        return 429, {'state': 'rate_limited', 'message': 'Too many attempts. Please try again later.',
                     'retry_after_seconds': settings.rate_window_seconds}
    user = db.scalar(select(User).where(User.id == challenge.user_id).with_for_update().execution_options(populate_existing=True))
    db.refresh(challenge, with_for_update=True)
    if not valid(settings, challenge, user):
        audit(db, 'password_challenge_rejected', ip_key, user)
        db.commit()
        return 401, {'state': 'challenge_expired', 'message': ENDED}
    if not hmac.compare_digest(new_password.encode(), confirmation.encode()):
        audit(db, 'password_change_mismatch', ip_key, user)
        db.commit()
        return 422, {'state': 'password_mismatch', 'message': MISMATCH}
    if not meets_requirements(new_password):
        audit(db, 'password_policy_rejected', ip_key, user)
        db.commit()
        return 422, {'state': 'password_rejected', 'message': 'Your new password must meet all password requirements.'}
    if verify_password(new_password, user.password_hash):
        audit(db, 'temporary_password_reused', ip_key, user)
        db.commit()
        return 422, {'state': 'password_rejected', 'message': 'Choose a password different from your temporary password.'}
    user.password_hash = hasher.hash(new_password)
    user.password_change_required = False
    # All updates and revocations commit together; no authentication session is granted here.
    db.execute(delete(AuthSession).where(AuthSession.user_id == user.id))
    db.execute(update(PasswordChangeChallenge).where(PasswordChangeChallenge.user_id == user.id).values(consumed=True))
    audit(db, 'password_changed', ip_key, user)
    db.commit()
    return 200, {'state': 'password_changed', 'message': 'Password updated. Sign in with your new password.'}
