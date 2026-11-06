"""Interactive, dedicated-account, development-only authenticator provisioning."""
from getpass import getpass
import time

from cryptography.fernet import Fernet
import pyotp
from sqlalchemy import select

from .config import get_settings
from .database import session_factory
from .models import MfaCredential, User


def main():
    settings = get_settings()
    if settings.environment != 'development' or not settings.dev_mfa_username:
        raise SystemExit('Configure the dedicated development MFA account first.')
    with session_factory()() as db:
        user = db.scalar(select(User).where(User.username == settings.dev_mfa_username).with_for_update())
        if not user or user.status != 'active' or user.password_change_required:
            raise SystemExit('An active development account with its password already replaced is required.')
        if db.scalar(select(MfaCredential).where(MfaCredential.user_id == user.id)):
            raise SystemExit('Authenticator already provisioned; no reset is performed.')
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret, digits=6, interval=30)
        print('Private enrollment URI (contains a secret; do not save, log, or share):')
        print(totp.provisioning_uri(name=user.username, issuer_name='UPTIP Development'))
        code = getpass('Enter the current six-digit code from the authenticator: ')
        if not (code.isascii() and code.isdigit() and len(code) == 6 and totp.verify(code, valid_window=1)):
            raise SystemExit('Enrollment verification failed; nothing saved.')
        # Account is MFA-enrolled only after actual possession verification.
        step = int(time.time()) // 30
        last_step = max(n for n in (step - 1, step, step + 1) if totp.verify(code, for_time=n * 30))
        db.add(MfaCredential(user_id=user.id, last_accepted_step=last_step, secret_ciphertext=Fernet(settings.mfa_encryption_key.encode()).encrypt(secret.encode()).decode()))
        user.mfa_enrolled = True
        user.mfa_required = True
        db.commit()
    print('Dedicated development authenticator configured. Sign in with the account password.')


if __name__ == '__main__':
    main()
