"""Validated completion contracts; legacy receipt snapshots remain opaque history."""
from typing import Annotated, Literal
from datetime import datetime

from pydantic import BaseModel, ConfigDict, BeforeValidator, Field, JsonValue, model_validator

Count = Annotated[int, Field(strict=True, ge=0)]
Digest = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Code = Literal['no_tests', 'missing_completion_receipt', 'active_tests',
               'unsuccessful_tests', 'processing_not_clear', 'pending_recommendations',
               'incorrect_lifecycle']


class Contract(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class ExecutionCounts(Contract):
    Queued: Count
    Running: Count
    Completed: Count
    Failed: Count
    Stopped: Count
    Blocked: Count
    Cancelled: Count


class DecisionCounts(Contract):
    total: Count
    pending_review: Count
    reviewed: Count
    deferred: Count
    pending_completion: Count

    @model_validator(mode='after')
    def consistent(self):
        if (self.total != self.pending_review + self.reviewed + self.deferred
                or self.pending_completion != self.pending_review + self.deferred):
            raise ValueError('Inconsistent recommendation counters')
        return self


class Summary(Contract):
    total: Count
    counts: ExecutionCounts
    active_attempts: Count
    active_execution_requests: Count
    recovery_required_requests: Count
    processing_errors: Count
    processing_pending: Count
    missing_processing: Count
    recommendation_count: Count
    pending_recommendation_ids: list[Digest]
    reviewed_recommendations: Count
    deferred_recommendations: Count
    decision_counts: DecisionCounts
    candidate_findings: Count | None
    blockers: list[Code]

    @model_validator(mode='after')
    def consistent(self):
        stats = self.decision_counts
        if (sum(self.counts.model_dump().values()) != self.total
                or self.active_execution_requests > self.total
                or self.recovery_required_requests > self.active_execution_requests
                or stats.total != self.recommendation_count
                or stats.reviewed != self.reviewed_recommendations
                or stats.deferred != self.deferred_recommendations
                or stats.pending_completion != len(self.pending_recommendation_ids)
                or len(set(self.pending_recommendation_ids)) != len(self.pending_recommendation_ids)
                or len(set(self.blockers)) != len(self.blockers)):
            raise ValueError('Inconsistent completion summary')
        return self


class Recommendation(Contract):
    id: Digest
    title: str
    decision: Literal['Reviewed', 'Deferred'] | None


class Blocker(Contract):
    code: Code
    message: str
    count: Count | None
    action: Literal['view_tests', 'review_recommendations'] | None


def receipt_timestamp(value):
    # Database JSON timestamps and serialized API responses share this input.
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return value


class CompletionReceipt(Contract):
    completed_at: Annotated[datetime, BeforeValidator(receipt_timestamp)]
    actor_id: str
    snapshot: dict[str, JsonValue]
    snapshot_schema_version: Literal[1, 2]
    snapshot_digest: Digest | None

    @model_validator(mode='after')
    def verified(self):
        if self.completed_at.tzinfo is None or self.completed_at.utcoffset() is None:
            raise ValueError('Receipt timestamp must be timezone aware')
        metadata = self.snapshot.get('_completion_contract')
        if self.snapshot_schema_version == 1:
            if metadata is not None or self.snapshot_digest is not None:
                raise ValueError('Legacy receipt cannot invent digest metadata')
        else:
            from .testing_completion_service import canonical_digest
            if not isinstance(metadata, dict) or set(metadata) != {'schema_version', 'snapshot_digest', 'inputs'}:
                raise ValueError('Invalid receipt metadata')
            inputs = metadata['inputs']
            summary = {key: value for key, value in self.snapshot.items() if key != '_completion_contract'}
            Summary.model_validate(summary)
            if (metadata['schema_version'] != 2 or not isinstance(inputs, dict)
                    or inputs.get('schema_version') != 2 or inputs.get('lifecycle_status') != 'Testing'
                    or metadata['snapshot_digest'] != self.snapshot_digest
                    or canonical_digest({'inputs': inputs, 'summary': summary}) != self.snapshot_digest):
                raise ValueError('Receipt digest mismatch')
        return self


class CompletionReview(Contract):
    assessment_id: str
    assessment_name: str
    lifecycle_status: Literal['Draft', 'Ready', 'Testing', 'Finding Review']
    ready: bool = Field(strict=True)
    can_complete: bool = Field(strict=True)
    snapshot_schema_version: Literal[2]
    snapshot_digest: Digest
    summary: Summary
    blocker_details: list[Blocker]
    recommendations: list[Recommendation]
    completion: CompletionReceipt | None

    @model_validator(mode='after')
    def consistent(self):
        if [item.code for item in self.blocker_details] != self.summary.blockers:
            raise ValueError('Blocker details disagree with blocker codes')
        if self.ready != (self.lifecycle_status == 'Testing' and not self.summary.blockers):
            raise ValueError('Invalid readiness state')
        if self.can_complete and self.lifecycle_status != 'Testing':
            raise ValueError('Completion capability requires Testing')
        ids = [item.id for item in self.recommendations]
        pending = [item.id for item in self.recommendations if item.decision != 'Reviewed']
        if (len(ids) != len(set(ids)) or len(ids) != self.summary.recommendation_count
                or pending != self.summary.pending_recommendation_ids
                or sum(item.decision == 'Reviewed' for item in self.recommendations) != self.summary.reviewed_recommendations
                or sum(item.decision == 'Deferred' for item in self.recommendations) != self.summary.deferred_recommendations):
            raise ValueError('Recommendation details disagree with summary')
        if self.completion is not None:
            if self.lifecycle_status != 'Finding Review':
                raise ValueError('Receipt requires Finding Review')
            if (self.completion.snapshot_schema_version == 2
                    and self.completion.snapshot['_completion_contract']['inputs']['assessment_id'] != self.assessment_id):
                raise ValueError('Receipt assessment mismatch')
        elif self.lifecycle_status == 'Finding Review' and 'missing_completion_receipt' not in self.summary.blockers:
            raise ValueError('Missing receipt must fail closed')
        return self


class DecisionResponse(Contract):
    assessment_id: str
    recommendation_id: Digest
    decision: Literal['Reviewed', 'Deferred']
