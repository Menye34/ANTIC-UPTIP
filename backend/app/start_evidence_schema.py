"""Strict schema for persisted assessment-start safety evidence."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator


class PrerequisiteCompletionDocument(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', strict=True)

    target_id: str = Field(min_length=1)
    profile_id: str = Field(min_length=1)
    evaluation_id: str = Field(min_length=1)
    evaluation_fingerprint: str = Field(pattern=r'^[0-9a-f]{64}$')
    policy_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    reference: str = Field(min_length=1)
    successful: bool
    completed_at: datetime
    expires_at: datetime

    @model_validator(mode='after')
    def validate_times(self):
        if (
            self.completed_at.utcoffset() is None
            or self.expires_at.utcoffset() is None
            or self.expires_at <= self.completed_at
        ):
            raise ValueError('Prerequisite completion timestamps are invalid.')
        return self


class StartEvidenceDocument(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', strict=True)

    parameter_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    risk: str = Field(pattern=r'^(low|elevated|high)$')
    verified_prerequisites: frozenset[str]
    requested_units: int = Field(gt=0)
    clear_stop_conditions: frozenset[str]
    mandatory_activities: frozenset[tuple[str, str]]
    prerequisite_completions: tuple[PrerequisiteCompletionDocument, ...] = ()

    @model_validator(mode='after')
    def validate_evidence(self):
        if any(not item.strip() for item in self.verified_prerequisites):
            raise ValueError('Prerequisite identifiers must not be blank.')

        if any(not item.strip() for item in self.clear_stop_conditions):
            raise ValueError('Stop-condition identifiers must not be blank.')

        if any(
            not target.strip() or not profile.strip()
            for target, profile in self.mandatory_activities
        ):
            raise ValueError('Mandatory activity identifiers must not be blank.')

        return self
