from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, SecretStr

WorkspaceRole = Literal['Security Analyst', 'Technical Administrator']

State = Literal['invalid_credentials', 'account_unavailable', 'password_change_required',
                'authenticated',
                'rate_limited', 'unavailable', 'invalid_request', 'forbidden', 'unauthenticated', 'session_expired',
                'challenge_expired', 'password_mismatch', 'password_rejected', 'password_changed']


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=False)
    username: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9][A-Za-z0-9._@-]*$')
    password: SecretStr = Field(min_length=1, max_length=1024)


class AuthResponse(BaseModel):
    state: State
    message: str
    next_step_available: bool = False
    csrf_token: str | None = None
    role: str | None = None
    username: str | None = None
    user_id: UUID | None = None
    retry_after_seconds: int | None = None


class PasswordChangeRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    new_password: SecretStr = Field(min_length=1, max_length=1024)
    confirmation: SecretStr = Field(min_length=1, max_length=1024)
