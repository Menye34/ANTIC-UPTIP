"""Explicit development-only provisioning. No seeded credentials or invented role catalogue."""
import argparse
from getpass import getpass

from .config import get_settings
from .database import session_factory
from .models import Role, User
from .schemas import LoginRequest
from .security import hasher


def main():
    if get_settings().environment != 'development':
        raise SystemExit('Provisioning is restricted to development.')
    parser = argparse.ArgumentParser()
    parser.add_argument('--username', required=True)
    parser.add_argument('--role', required=True, help='An approved UPTIP role name; no default is assumed')
    parser.add_argument('--password-already-replaced', action='store_true')
    parser.add_argument('--mfa-not-required', action='store_true', help='Development policy only')
    args = parser.parse_args()
    password = getpass('Password (at least 12 characters): ')
    if len(password) < 12 or password != getpass('Confirm password: '):
        raise SystemExit('Password requirements or confirmation failed.')
    LoginRequest(username=args.username, password=password)
    with session_factory()() as db:
        if db.get(Role, args.role) is None:
            db.add(Role(name=args.role))
            db.flush()
        db.add(User(username=args.username, role=args.role, password_hash=hasher.hash(password),
                    password_change_required=not args.password_already_replaced,
                    mfa_required=not args.mfa_not_required))
        db.commit()
    print('Development account created. No credentials are printed.')


if __name__ == '__main__':
    main()
