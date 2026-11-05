import time
from datetime import datetime, timedelta, timezone
import secrets

from sqlalchemy import case, select
from sqlalchemy.dialects.postgresql import insert

from .models import AuthEvent, AuthSession, LoginBucket, User
from .security import DUMMY_HASH, can_activate, client_key, digest, hasher, verify_password

INVALID = 'Unable to sign in. Check your credentials and try again.'


def audit(db, reason, ip_key, user=None):
    db.add(AuthEvent(reason=reason, client_key=ip_key, user_id=user.id if user else None))


def throttled(db, settings, username, ip):
    window = int(time.time()) // settings.rate_window_seconds
    denied = False
    # Atomic PostgreSQL upserts share counters across workers. Stable order avoids deadlocks.
    for value, limit in [('ip:' + ip, settings.ip_limit), ('user:' + username, settings.username_limit)]:
        key = client_key(settings.rate_key, value)
        stmt = insert(LoginBucket).values(key=key, window=window, count=1)
        stmt = stmt.on_conflict_do_update(index_elements=['key'], set_={
            'window': window,
            'count': case((LoginBucket.window == window, LoginBucket.count + 1), else_=1),
        }).returning(LoginBucket.count)
        denied = db.scalar(stmt) > limit or denied
    return denied


def authenticate(db, settings, username, password, ip, old_token=None):
    ip_key = client_key(settings.rate_key, 'ip:' + ip)
    if throttled(db, settings, username, ip):
        audit(db, 'rate_limited', ip_key)
        db.commit()
        return 429, {'state': 'rate_limited', 'message': 'Too many sign-in attempts. Please try again later.'}, None
    user = db.scalar(select(User).where(User.username == username).with_for_update())
    valid = verify_password(password, user.password_hash if user else DUMMY_HASH)
    if not valid or user is None or user.status != 'active':
        audit(db, 'account_unavailable' if valid and user else 'invalid_credentials', ip_key, user)
        db.commit()
        # Disabled and unknown accounts deliberately have identical public errors.
        return 401, {'state': 'invalid_credentials', 'message': INVALID}, None
    if hasher.check_needs_rehash(user.password_hash):
        user.password_hash = hasher.hash(password)
    if user.password_change_required:
        state = 'password_change_required'
    elif user.mfa_required or user.mfa_enrolled:
        state = 'mfa_verification_required' if user.mfa_enrolled else 'mfa_enrollment_required'
    else:
        state = 'authenticated'
    audit(db, state, ip_key, user)
    if state != 'authenticated':
        db.commit()
        return 200, {'state': state, 'message': 'Additional authentication is required. This step is not yet available.'}, None
    assert can_activate(user)
    if old_token:
        previous = db.get(AuthSession, digest(old_token))
        if previous:
            db.delete(previous)
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    db.add(AuthSession(token_hash=digest(token), csrf_hash=digest(csrf), user_id=user.id,
                       expires_at=datetime.now(timezone.utc) + timedelta(seconds=settings.session_seconds)))
    db.commit()
    return 200, {'state': state, 'message': 'Authentication complete.', 'csrf_token': csrf}, token
