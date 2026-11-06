import hashlib
import hmac
import secrets

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

hasher = PasswordHasher(type=Type.ID)
DUMMY_HASH = hasher.hash(secrets.token_urlsafe(32))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def client_key(secret: str, value: str) -> str:
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()


def verify_password(password: str, encoded: str) -> bool:
    try:
        return hasher.verify(encoded, password)
    except (VerificationError, InvalidHashError):
        return False


def can_activate(user, mfa_verified=False) -> bool:
    # A historic MFA verification timestamp never satisfies a new login challenge.
    return user.status == 'active' and not user.password_change_required and (
        not (user.mfa_required or user.mfa_enrolled) or (mfa_verified and user.mfa_enrolled)
    )
