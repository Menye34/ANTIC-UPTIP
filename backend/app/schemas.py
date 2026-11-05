from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, SecretStr

State = Literal['invalid_credentials', 'account_unavailable', 'password_change_required',
                'mfa_verification_required', 'mfa_enrollment_required', 'authenticated',
                'rate_limited', 'unavailable', 'invalid_request', 'forbidden', 'unauthenticated', 'session_expired']


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=False)
    username: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9][A-Za-z0-9._@-]*$')
    password: SecretStr = Field(min_length=1, max_length=1024)


class AuthResponse(BaseModel):
    state: State
    message: str
    next_step_available: bool = False
    csrf_token: str | None = None
