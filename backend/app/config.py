from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore', env_prefix='UPTIP_', hide_input_in_errors=True)
    database_url: str
    environment: str = 'production'
    public_origin: str = 'https://localhost'
    cookie_secure: bool = True
    session_seconds: int = Field(default=1800, ge=60, le=86400)
    rate_window_seconds: int = Field(default=900, ge=1)
    ip_limit: int = Field(default=30, ge=1)
    username_limit: int = Field(default=10, ge=1)
    rate_key: str = Field(min_length=32, repr=False)

    # Explicit isolated development harness, not a production MFA policy.
    dev_mfa_username: str | None = None
    dev_mfa_max_attempts: int | None = Field(default=None, ge=1, le=100)
    mfa_encryption_key: str | None = Field(default=None, repr=False)

    @model_validator(mode='after')
    def secure_configuration(self):
        if not self.database_url.startswith('postgresql+psycopg://'):
            raise ValueError('PostgreSQL with psycopg is required')
        if self.environment not in ('development', 'test', 'production'):
            raise ValueError('Unknown environment')
        if self.environment == 'production' and (
            not self.cookie_secure or not self.public_origin.startswith('https://')
        ):
            raise ValueError('Production requires HTTPS and Secure cookies')
        if self.public_origin.endswith('/'):
            raise ValueError('Origin must not have a trailing slash')
        if self.dev_mfa_username is not None:
            if self.environment != 'development' or self.dev_mfa_max_attempts is None or not self.mfa_encryption_key:
                raise ValueError('Development MFA requires development environment, explicit limit and encryption key')
        if self.mfa_encryption_key:
            from cryptography.fernet import Fernet
            Fernet(self.mfa_encryption_key.encode())
        return self

    @property
    def password_cookie_name(self):
        return '__Host-uptip_password_change' if self.cookie_secure else 'uptip_dev_password_change'

    @property
    def challenge_cookie_name(self):
        return '__Host-uptip_mfa' if self.cookie_secure else 'uptip_dev_mfa'

    @property
    def cookie_name(self):
        return '__Host-uptip_session' if self.cookie_secure else 'uptip_dev_session'


@lru_cache
def get_settings():
    return Settings()
