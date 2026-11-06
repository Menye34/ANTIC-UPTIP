from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

State = Literal['invalid_credentials', 'account_unavailable', 'password_change_required',
                'mfa_verification_required', 'mfa_enrollment_required', 'authenticated',
                'rate_limited', 'unavailable', 'invalid_request', 'forbidden', 'unauthenticated', 'session_expired', 'invalid_code', 'code_expired', 'too_many_attempts',
                'challenge_expired', 'mfa_cancelled']


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=False)
    username: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9][A-Za-z0-9._@-]*$')
    password: SecretStr = Field(min_length=1, max_length=1024)


class AuthResponse(BaseModel):
    state: State
    message: str
    next_step_available: bool = False
    csrf_token: str | None = None
    retry_after_seconds: int | None = None


class MfaVerifyRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: SecretStr = Field(min_length=6, max_length=6)

    @classmethod
    def valid_code(cls, value):
        return len(value) == 6 and value.isascii() and value.isdigit()

    @field_validator('code')
    @classmethod
    def six_digits(cls, value):
        if not cls.valid_code(value.get_secret_value()):
            raise ValueError('Six digits required')
        return value
