import pytest
from pydantic import ValidationError
from app.config import Settings
from app.security import hasher, verify_password


def test_argon2id():
    encoded = hasher.hash('unit-test-secret')
    assert encoded.startswith('$argon2id$')
    assert verify_password('unit-test-secret', encoded)
    assert not verify_password('wrong', encoded)
    assert not verify_password('wrong', 'invalid-hash')


def test_production_cannot_use_insecure_cookie():
    with pytest.raises(ValidationError):
        Settings(database_url='postgresql+psycopg://unused', rate_key='x' * 32,
                 environment='production', cookie_secure=False, public_origin='http://localhost')
