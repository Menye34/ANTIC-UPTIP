"""Validated request and response contracts for finding AI assistance."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


AIAction = Literal[
    "explain_finding",
    "explain_impact",
    "suggest_fix",
    "write_description",
    "explain_tool_output",
    "custom",
]


class FindingAIRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    action: AIAction
    question: str | None = Field(default=None, max_length=500)

    @field_validator("question")
    @classmethod
    def validate_question(cls, value):
        if value is None:
            return None

        value = value.strip()

        if not value:
            raise ValueError("Question must not be empty")

        if any(
            not char.isprintable() and char not in ("\n", "\t")
            for char in value
        ):
            raise ValueError("Question contains invalid characters")

        return value

    @model_validator(mode="after")
    def validate_action(self):
        if self.action == "custom" and self.question is None:
            raise ValueError("Custom action requires a question")

        if self.action != "custom" and self.question is not None:
            raise ValueError("Quick actions do not accept custom questions")

        return self


class AIEvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observation_id: UUID
    evidence_id: UUID
    source: str = Field(min_length=1, max_length=100)


class FindingAIAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["answered"] = "answered"
    history_id: UUID | None = None
    assessment_id: UUID
    finding_id: UUID
    action: AIAction
    question: str = Field(min_length=1, max_length=500)
    answer: str = Field(min_length=1, max_length=6000)
    model: str = Field(min_length=1, max_length=100)
    output_tokens: int = Field(ge=1, le=512)
    evidence: list[AIEvidenceReference] = Field(
        min_length=1,
        max_length=3,
    )
    limitations: list[str] = Field(max_length=8)
    advisory_only: Literal[True] = True


class FindingAIInsufficientEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["insufficient_evidence"] = "insufficient_evidence"
    assessment_id: UUID
    finding_id: UUID
    action: AIAction
    message: str = Field(min_length=1, max_length=500)


class FindingAIUnavailable(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["unavailable"] = "unavailable"
    code: str = Field(min_length=1, max_length=80)
    message: str = Field(min_length=1, max_length=500)
    retryable: bool = False


FindingAIResponse = (
    FindingAIAnswer
    | FindingAIInsufficientEvidence
    | FindingAIUnavailable
)


class FindingAIHistoryEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    action: AIAction
    question: str = Field(min_length=1, max_length=500)
    answer: str = Field(min_length=1, max_length=6000)
    model: str = Field(min_length=1, max_length=100)
    prompt_version: str = Field(min_length=1, max_length=80)
    output_tokens: int = Field(ge=1, le=512)
    evidence: list[AIEvidenceReference] = Field(
        min_length=1, max_length=3
    )
    limitations: list[str] = Field(max_length=8)
    created_at: datetime
    advisory_only: Literal[True] = True


class FindingAIHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment_id: UUID
    finding_id: UUID
    entries: list[FindingAIHistoryEntry] = Field(max_length=50)
    limit: int = Field(ge=1, le=50)
    offset: int = Field(ge=0, le=10000)
    has_more: bool
