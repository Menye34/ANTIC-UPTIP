"""Persistence only. No claiming loop, scanner dispatch, parsing or execution."""
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint,
                        Index, Integer, LargeBinary, String, Text, UniqueConstraint, func, text)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base


class ExecutionAttempt(Base):
    __tablename__ = 'execution_attempts'
    __table_args__ = (
        ForeignKeyConstraint(['request_id', 'assessment_id', 'target_id'],
                             ['baseline_execution_requests.id', 'baseline_execution_requests.assessment_id',
                              'baseline_execution_requests.target_id'], name='fk_attempt_request_binding'),
        UniqueConstraint('id', 'request_id', 'assessment_id', 'target_id', name='uq_attempt_binding'),
        UniqueConstraint('request_id', 'attempt_number', name='uq_attempt_number'),
        CheckConstraint('attempt_number > 0 AND profile_version > 0 AND timeout_seconds > 0', name='ck_attempt_positive'),
        CheckConstraint("status IN ('Claimed','Running','RecoveryRequired','Succeeded','Failed','Stopped','Blocked','Cancelled')", name='ck_attempt_status'),
        CheckConstraint("parameter_digest ~ '^[0-9a-f]{64}$' AND jsonb_typeof(parameters)='object' AND octet_length(parameters::text)<=65536", name='ck_attempt_parameters'),
        CheckConstraint("btrim(worker_id)<>'' AND btrim(profile_id)<>'' AND btrim(tool)<>''", name='ck_attempt_identity'),
        CheckConstraint('lease_expires_at > claimed_at AND heartbeat_at >= claimed_at', name='ck_attempt_lease'),
        CheckConstraint('started_at IS NULL OR started_at >= claimed_at', name='ck_attempt_start'),
        CheckConstraint('finished_at IS NULL OR finished_at >= coalesce(started_at,claimed_at)', name='ck_attempt_finish'),
        CheckConstraint('terminated_at IS NULL OR (started_at IS NOT NULL AND terminated_at >= started_at)', name='ck_attempt_termination'),
        CheckConstraint("(status IN ('Claimed','Running','RecoveryRequired') AND finished_at IS NULL) OR (status IN ('Succeeded','Failed','Stopped','Blocked','Cancelled') AND finished_at IS NOT NULL AND (started_at IS NULL OR terminated_at IS NOT NULL))", name='ck_attempt_terminal'),
        CheckConstraint("status NOT IN ('Running','Succeeded') OR started_at IS NOT NULL", name='ck_attempt_running'),
        CheckConstraint("status<>'Succeeded' OR (exit_code IS NOT NULL AND exit_code=0)", name='ck_attempt_success'),
        CheckConstraint("status='Claimed' OR (reason_code IS NOT NULL AND btrim(reason_code)<>'')", name='ck_attempt_reason'),
        CheckConstraint("cancellation_requested_at IS NULL OR (cancellation_source IS NOT NULL AND cancellation_source IN ('analyst','system') AND cancellation_reason IS NOT NULL AND btrim(cancellation_reason)<>'' AND (cancellation_source<>'analyst' OR cancellation_actor_id IS NOT NULL))", name='ck_attempt_cancellation'),
        Index('uq_attempt_active', 'request_id', unique=True,
              postgresql_where=text("status IN ('Claimed','Running','RecoveryRequired')")),
        Index('ix_attempt_recovery', 'status', 'lease_expires_at'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    request_id: Mapped[UUID]
    assessment_id: Mapped[UUID]
    target_id: Mapped[UUID]
    attempt_number: Mapped[int]
    claim_id: Mapped[UUID] = mapped_column(unique=True)
    worker_id: Mapped[str] = mapped_column(String(160))
    claimed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24), default='Claimed')
    reason_code: Mapped[str | None] = mapped_column(String(80))
    exit_code: Mapped[int | None]
    tool: Mapped[str] = mapped_column(String(80))
    profile_id: Mapped[str] = mapped_column(String(80))
    profile_version: Mapped[int]
    parameters: Mapped[dict] = mapped_column(JSONB)
    parameter_digest: Mapped[str] = mapped_column(String(64))
    timeout_seconds: Mapped[int]
    process_reference: Mapped[str | None] = mapped_column(String(160))
    recovery_reason: Mapped[str | None] = mapped_column(String(80))
    cancellation_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancellation_actor_id: Mapped[UUID | None] = mapped_column(ForeignKey('users.id'))
    cancellation_source: Mapped[str | None] = mapped_column(String(16))
    cancellation_reason: Mapped[str | None] = mapped_column(String(80))
    terminated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    termination_outcome: Mapped[str | None] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ScannerEvidence(Base):
    __tablename__ = 'scanner_evidence'
    __table_args__ = (
        ForeignKeyConstraint(['attempt_id','request_id','assessment_id','target_id'],
            ['execution_attempts.id','execution_attempts.request_id','execution_attempts.assessment_id','execution_attempts.target_id'], name='fk_evidence_attempt_binding'),
        UniqueConstraint('id','attempt_id','request_id','assessment_id','target_id', name='uq_evidence_binding'),
        UniqueConstraint('attempt_id','format','content_hash','is_partial', name='uq_evidence_content'),
        CheckConstraint("content_hash ~ '^[0-9a-f]{64}$' AND btrim(tool)<>'' AND btrim(format)<>''", name='ck_evidence_identity'),
        CheckConstraint('(content IS NULL) <> (storage_key IS NULL)', name='ck_evidence_storage'),
        CheckConstraint('size_bytes >= 0 AND size_bytes <= 67108864', name='ck_evidence_size'),
        CheckConstraint("content IS NULL OR (octet_length(content)<=1048576 AND octet_length(content)=size_bytes AND encode(sha256(content),'hex')=content_hash)", name='ck_evidence_inline_integrity'),
        CheckConstraint("storage_key IS NULL OR (storage_key ~ '^evidence/[A-Za-z0-9_/-]+$' AND storage_key NOT LIKE '%//%')", name='ck_evidence_storage_key'),
        Index('ix_evidence_request', 'request_id', 'collected_at'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    attempt_id: Mapped[UUID]
    request_id: Mapped[UUID]
    assessment_id: Mapped[UUID]
    target_id: Mapped[UUID]
    tool: Mapped[str] = mapped_column(String(80))
    format: Mapped[str] = mapped_column(String(32))
    content: Mapped[bytes | None] = mapped_column(LargeBinary)
    storage_key: Mapped[str | None] = mapped_column(String(512))
    content_hash: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int]
    is_partial: Mapped[bool]
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ResultProcessingOutcome(Base):
    __tablename__ = 'result_processing_outcomes'
    __table_args__ = (
        ForeignKeyConstraint(['evidence_id','attempt_id','request_id','assessment_id','target_id'],
            ['scanner_evidence.id','scanner_evidence.attempt_id','scanner_evidence.request_id','scanner_evidence.assessment_id','scanner_evidence.target_id'], name='fk_processing_evidence_binding'),
        UniqueConstraint('id','evidence_id','attempt_id','request_id','assessment_id','target_id', name='uq_processing_binding'),
        UniqueConstraint('evidence_id','processor','processor_version','run_number', name='uq_processing_run'),
        CheckConstraint("status IN ('Pending','Processing','Succeeded','Failed','Interrupted')", name='ck_processing_status'),
        CheckConstraint("run_number>0 AND observation_count>=0 AND btrim(processor)<>'' AND btrim(processor_version)<>''", name='ck_processing_identity'),
        CheckConstraint("status='Pending' OR started_at IS NOT NULL", name='ck_processing_start'),
        CheckConstraint("(status IN ('Pending','Processing') AND finished_at IS NULL) OR (status IN ('Succeeded','Failed','Interrupted') AND finished_at IS NOT NULL AND finished_at >= started_at)", name='ck_processing_finish'),
        CheckConstraint("status NOT IN ('Failed','Interrupted') OR (error_code IS NOT NULL AND btrim(error_code)<>'')", name='ck_processing_error'),
        CheckConstraint('safe_diagnostic IS NULL OR octet_length(safe_diagnostic)<=2048', name='ck_processing_diagnostic_size'),
        Index('ix_processing_attempt', 'attempt_id', 'created_at'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    evidence_id: Mapped[UUID]
    attempt_id: Mapped[UUID]
    request_id: Mapped[UUID]
    assessment_id: Mapped[UUID]
    target_id: Mapped[UUID]
    processor: Mapped[str] = mapped_column(String(80))
    processor_version: Mapped[str] = mapped_column(String(40))
    run_number: Mapped[int]
    operation_id: Mapped[UUID] = mapped_column(unique=True)
    status: Mapped[str] = mapped_column(String(16), default='Pending')
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(80))
    safe_diagnostic: Mapped[str | None] = mapped_column(Text)
    observation_count: Mapped[int] = mapped_column(default=0)
    is_partial: Mapped[bool]
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class SecurityObservation(Base):
    __tablename__ = 'security_observations'
    __table_args__ = (
        ForeignKeyConstraint(['processing_id','evidence_id','attempt_id','request_id','assessment_id','target_id'],
            ['result_processing_outcomes.id','result_processing_outcomes.evidence_id','result_processing_outcomes.attempt_id',
             'result_processing_outcomes.request_id','result_processing_outcomes.assessment_id','result_processing_outcomes.target_id'], name='fk_observation_processing_binding'),
        UniqueConstraint('evidence_id','deduplication_key', name='uq_observation_deduplication'),
        CheckConstraint("deduplication_key ~ '^[0-9a-f]{64}$' AND btrim(observation_type)<>''", name='ck_observation_identity'),
        CheckConstraint("jsonb_typeof(data)='object' AND octet_length(data::text)<=16384", name='ck_observation_data'),
        CheckConstraint('processed_at >= collected_at', name='ck_observation_time'),
        Index('ix_observation_assessment_target', 'assessment_id', 'target_id', 'collected_at'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    processing_id: Mapped[UUID]
    evidence_id: Mapped[UUID]
    attempt_id: Mapped[UUID]
    request_id: Mapped[UUID]
    assessment_id: Mapped[UUID]
    target_id: Mapped[UUID]
    observation_type: Mapped[str] = mapped_column(String(80))
    data: Mapped[dict] = mapped_column(JSONB)
    deduplication_key: Mapped[str] = mapped_column(String(64))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_partial: Mapped[bool]


class ExecutionEvent(Base):
    __tablename__ = 'execution_events'
    __table_args__ = (
        ForeignKeyConstraint(['request_id','assessment_id','target_id'],
            ['baseline_execution_requests.id','baseline_execution_requests.assessment_id','baseline_execution_requests.target_id'], name='fk_event_request_binding'),
        ForeignKeyConstraint(['attempt_id','request_id','assessment_id','target_id'],
            ['execution_attempts.id','execution_attempts.request_id','execution_attempts.assessment_id','execution_attempts.target_id'], name='fk_event_attempt_binding'),
        UniqueConstraint('request_id','operation_id', name='uq_execution_event_operation'),
        CheckConstraint('(actor_id IS NULL) <> (system_origin IS NULL)', name='ck_execution_event_origin'),
        CheckConstraint("btrim(event_type)<>'' AND btrim(reason_code)<>'' AND (system_origin IS NULL OR btrim(system_origin)<>'')", name='ck_execution_event_identity'),
        CheckConstraint("jsonb_typeof(details)='object' AND octet_length(details::text)<=4096", name='ck_execution_event_details'),
        Index('ix_execution_event_timeline', 'request_id', 'occurred_at', 'id'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    request_id: Mapped[UUID]
    assessment_id: Mapped[UUID]
    target_id: Mapped[UUID]
    attempt_id: Mapped[UUID | None]
    operation_id: Mapped[UUID]
    event_type: Mapped[str] = mapped_column(String(80))
    actor_id: Mapped[UUID | None] = mapped_column(ForeignKey('users.id'))
    system_origin: Mapped[str | None] = mapped_column(String(80))
    reason_code: Mapped[str] = mapped_column(String(80))
    details: Mapped[dict] = mapped_column(JSONB)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
