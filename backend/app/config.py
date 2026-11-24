from functools import lru_cache

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore', env_prefix='UPTIP_', hide_input_in_errors=True)
    database_url: str
    worker_database_url: str | None = None
    migration_database_url: str | None = None
    environment: str = 'production'
    public_origin: str = 'https://localhost'
    cookie_secure: bool = True
    session_seconds: int = Field(default=1800, ge=60, le=86400)
    rate_window_seconds: int = Field(default=900, ge=1)
    ip_limit: int = Field(default=30, ge=1)
    username_limit: int = Field(default=10, ge=1)
    # None leaves Nikto disabled; Version 2 requires an exact system policy digest.
    nikto_policy_version: int | None = None
    nikto_policy_digest: str | None = None
    evidence_read_directory: str | None = None

    # Local finding AI assistance: disabled until explicitly activated.
    ai_enabled: bool = False
    ai_base_url: str = 'http://127.0.0.1:11434'
    ai_model: str = Field(
        default='qwen2.5:3b',
        min_length=1,
        max_length=100,
    )
    ai_timeout_seconds: int = Field(default=180, ge=10, le=300)
    ai_context_tokens: int = Field(default=2048, ge=1024, le=4096)
    ai_max_output_tokens: int = Field(default=256, ge=64, le=512)
    ai_threads: int = Field(default=2, ge=1, le=4)
    ai_keep_alive: str = '2m'
    ai_max_concurrent_requests: int = Field(default=1, ge=1, le=1)

    start_review_key: SecretStr | None = None
    rate_key: str = Field(min_length=32, repr=False)

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
        if self.ai_base_url != 'http://127.0.0.1:11434':
            raise ValueError('AI service must use the local Ollama endpoint')
        if self.ai_model not in ('qwen2.5:3b', 'qwen2.5:7b'):
            raise ValueError('Unsupported local AI model')
        if self.ai_keep_alive not in ('0', '1m', '2m'):
            raise ValueError('Unsupported AI model retention duration')
        if self.ai_max_output_tokens >= self.ai_context_tokens:
            raise ValueError('AI output must fit within the context window')
        return self

    @property
    def password_cookie_name(self):
        return '__Host-uptip_password_change' if self.cookie_secure else 'uptip_dev_password_change'

    @property
    def cookie_name(self):
        return '__Host-uptip_session' if self.cookie_secure else 'uptip_dev_session'


@lru_cache
def get_settings():
    return Settings()
