from datetime import date, datetime
import json
from uuid import UUID, uuid4

from sqlalchemy import JSON, Boolean, CheckConstraint, Date, DateTime, ForeignKey, ForeignKeyConstraint, Index, Integer, Sequence, String, Text, UniqueConstraint, event, func
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class Role(Base):
    __tablename__ = 'roles'
    # No roles are seeded: names must come from the approved UPTIP role catalogue.
    name: Mapped[str] = mapped_column(String(80), primary_key=True)


class User(Base):
    __tablename__ = 'users'
    __table_args__ = (CheckConstraint("status IN ('active', 'disabled', 'locked')"),)
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    username: Mapped[str] = mapped_column(String(128), unique=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(16), default='active')
    role: Mapped[str] = mapped_column(ForeignKey('roles.name'))
    password_change_required: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AuthSession(Base):
    __tablename__ = 'auth_sessions'
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class LoginBucket(Base):
    __tablename__ = 'login_buckets'
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    window: Mapped[int] = mapped_column(Integer)
    count: Mapped[int] = mapped_column(Integer)


class AuthEvent(Base):
    __tablename__ = 'auth_events'
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID | None] = mapped_column(ForeignKey('users.id', ondelete='SET NULL'))
    reason: Mapped[str] = mapped_column(String(40))
    client_key: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class PasswordChangeChallenge(Base):
    __tablename__ = 'password_change_challenges'
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
    password_fingerprint: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    environment: Mapped[str] = mapped_column(String(16))


assessment_reference_sequence = Sequence('assessment_reference_sequence', metadata=Base.metadata)


class Assessment(Base):
    __tablename__ = 'assessments'
    __table_args__ = (
        UniqueConstraint('creator_id', 'idempotency_key', name='uq_assessments_creator_idempotency'),
        CheckConstraint("status IN ('Draft', 'Ready')", name='ck_assessments_start_state'),
        CheckConstraint('end_date >= start_date', name='ck_assessments_window'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    reference: Mapped[str] = mapped_column(String(48), unique=True)
    idempotency_key: Mapped[UUID]
    request_fingerprint: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    start_date: Mapped[date | None] = mapped_column(Date)
    end_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(16), default='Draft')
    scope_revision: Mapped[int] = mapped_column(Integer, server_default='0')
    creator_id: Mapped[UUID] = mapped_column(ForeignKey('users.id'), index=True)
    lead_analyst_id: Mapped[UUID] = mapped_column(ForeignKey('users.id'))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AssessmentAssignment(Base):
    __tablename__ = 'assessment_assignments'
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey('assessments.id', ondelete='CASCADE'), primary_key=True)
    analyst_id: Mapped[UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), primary_key=True, index=True)


class AssessmentCreationEvent(Base):
    __tablename__ = 'assessment_creation_events'
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey('assessments.id'), primary_key=True)
    actor_id: Mapped[UUID] = mapped_column(ForeignKey('users.id'))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScopeEntry(Base):
    __tablename__ = 'scope_entries'
    __table_args__ = (
        UniqueConstraint('assessment_id', 'normalized_value', name='uq_scope_entry_value'),
        CheckConstraint("kind IN ('IP address', 'Subnet', 'Hostname', 'Web URL')", name='ck_scope_entry_kind'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey('assessments.id', ondelete='CASCADE'))
    normalized_value: Mapped[str] = mapped_column(String(1024))
    kind: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScopeEvent(Base):
    __tablename__ = 'scope_events'
    __table_args__ = (CheckConstraint("action IN ('added', 'edited', 'removed')", name='ck_scope_event_action'),)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey('assessments.id'), primary_key=True)
    revision: Mapped[int] = mapped_column(primary_key=True)
    entry_id: Mapped[UUID]
    actor_id: Mapped[UUID] = mapped_column(ForeignKey('users.id'))
    action: Mapped[str] = mapped_column(String(16))
    before: Mapped[dict | None] = mapped_column(JSON(none_as_null=True))
    after: Mapped[dict | None] = mapped_column(JSON(none_as_null=True))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AssessmentTarget(Base):
    __tablename__ = 'assessment_targets'
    __table_args__ = (
        UniqueConstraint('assessment_id', 'normalized_value', name='uq_assessment_target_value'),
        CheckConstraint("kind IN ('IP address', 'Subnet', 'Hostname', 'Web URL')", name='ck_target_kind'),
        CheckConstraint("scope_status IN ('in_scope', 'out_of_scope', 'requires_revalidation')", name='ck_target_scope'),
        CheckConstraint('scope_revision >= 0 AND revision > 0', name='ck_target_revisions'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey('assessments.id', ondelete='CASCADE'))
    original_value: Mapped[str] = mapped_column(String(1024))
    normalized_value: Mapped[str] = mapped_column(String(1024))
    kind: Mapped[str] = mapped_column(String(16))
    scope_status: Mapped[str] = mapped_column(String(24))
    classification_reason: Mapped[str] = mapped_column(String(80))
    scope_revision: Mapped[int] = mapped_column(Integer)
    revision: Mapped[int] = mapped_column(Integer, server_default='1')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class BaselineToolState(Base):
    __tablename__ = 'baseline_tool_states'
    __table_args__ = (
        CheckConstraint("state IN ('enabled', 'disabled', 'unavailable', 'unknown')", name='ck_baseline_tool_state'),
        CheckConstraint('revision > 0', name='ck_baseline_tool_revision'),
    )
    tool: Mapped[str] = mapped_column(String(32), primary_key=True)
    state: Mapped[str] = mapped_column(String(16))
    capabilities: Mapped[list] = mapped_column(JSON)
    revision: Mapped[int] = mapped_column(Integer)


class BaselineEvaluation(Base):
    __tablename__ = 'baseline_evaluations'
    __table_args__ = (UniqueConstraint('id', 'assessment_id', 'target_id', 'fingerprint',
                                       name='uq_baseline_evaluation_binding'),)
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    # Historical identifiers survive target and assessment removal.
    assessment_id: Mapped[UUID] = mapped_column(index=True)
    target_id: Mapped[UUID] = mapped_column(index=True)
    profile_key: Mapped[str] = mapped_column(String(80))
    fingerprint: Mapped[str] = mapped_column(String(64))
    decision: Mapped[dict] = mapped_column(JSON)
    trigger: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class BaselineAssignment(Base):
    __tablename__ = 'baseline_assignments'
    target_id: Mapped[UUID] = mapped_column(ForeignKey('assessment_targets.id', ondelete='CASCADE'), primary_key=True)
    profile_key: Mapped[str] = mapped_column(String(80), primary_key=True)
    evaluation_id: Mapped[UUID] = mapped_column(ForeignKey('baseline_evaluations.id'), unique=True)


class AssessmentStartAuthorization(Base):
    __tablename__ = 'assessment_start_authorizations'
    __table_args__ = (
        UniqueConstraint('assessment_id', 'actor_id', 'idempotency_key', name='uq_start_actor_key'),
        CheckConstraint("mode IN ('full', 'partial')", name='ck_start_mode'),
        CheckConstraint('snapshot_version > 0', name='ck_start_snapshot_version'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey('assessments.id'), unique=True)
    actor_id: Mapped[UUID] = mapped_column(ForeignKey('users.id'))
    idempotency_key: Mapped[UUID]
    request_fingerprint: Mapped[str] = mapped_column(String(64))
    mode: Mapped[str] = mapped_column(String(7))
    snapshot_version: Mapped[int]
    snapshot_digest: Mapped[str] = mapped_column(String(64))
    snapshot: Mapped[dict] = mapped_column(JSON)
    confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AssessmentStartEvent(Base):
    __tablename__ = 'assessment_start_events'
    authorization_id: Mapped[UUID] = mapped_column(ForeignKey('assessment_start_authorizations.id'), primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    from_status: Mapped[str] = mapped_column(String(16))
    to_status: Mapped[str] = mapped_column(String(16))


class ExecutionPolicyVersion(Base):
    __tablename__ = 'execution_policy_versions'
    __table_args__ = (
        CheckConstraint('version > 0', name='ck_policy_version_positive'),
        CheckConstraint("digest ~ '^[0-9a-f]{64}$'", name='ck_policy_digest'),
        CheckConstraint("json_typeof(definition) = 'object'", name='ck_policy_definition_object'),
        CheckConstraint("btrim(policy_id) <> ''", name='ck_policy_id_present'),
    )
    policy_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    version: Mapped[int] = mapped_column(primary_key=True)
    digest: Mapped[str] = mapped_column(String(64), unique=True)
    definition: Mapped[dict] = mapped_column(JSON)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ExecutionPolicyApprovalRecord(Base):
    __tablename__ = 'execution_policy_approvals'
    __table_args__ = (
        UniqueConstraint('reference', 'policy_digest', name='uq_policy_approval_binding'),
        CheckConstraint('valid_until > valid_from', name='ck_policy_approval_window'),
        CheckConstraint("btrim(reference) <> '' AND btrim(provenance) <> ''", name='ck_policy_approval_identity'),
    )
    reference: Mapped[str] = mapped_column(String(160), primary_key=True)
    policy_digest: Mapped[str] = mapped_column(ForeignKey('execution_policy_versions.digest'), index=True)
    provenance: Mapped[str] = mapped_column(Text)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AssessmentStartEvidenceRecord(Base):
    __tablename__ = 'assessment_start_evidence'
    __table_args__ = (
        ForeignKeyConstraint(
            ['evaluation_id', 'assessment_id', 'target_id', 'evaluation_fingerprint'],
            ['baseline_evaluations.id', 'baseline_evaluations.assessment_id',
             'baseline_evaluations.target_id', 'baseline_evaluations.fingerprint'],
            name='fk_start_evidence_evaluation_binding',
        ),
        ForeignKeyConstraint(
            ['approval_reference', 'policy_digest'],
            ['execution_policy_approvals.reference', 'execution_policy_approvals.policy_digest'],
            name='fk_start_evidence_approval_binding',
        ),
        CheckConstraint('valid_until > valid_from', name='ck_start_evidence_window'),
        CheckConstraint("json_typeof(evidence) = 'object'", name='ck_start_evidence_object'),
        CheckConstraint("btrim(reference) <> '' AND btrim(provenance) <> ''", name='ck_start_evidence_identity'),
        Index('ix_start_evidence_binding', 'assessment_id', 'target_id', 'evaluation_fingerprint', 'policy_digest'),
        Index('ix_start_evidence_approval', 'approval_reference', 'policy_digest'),
    )
    reference: Mapped[str] = mapped_column(String(160), primary_key=True)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey('assessments.id'))
    target_id: Mapped[UUID]
    evaluation_id: Mapped[UUID] = mapped_column(index=True)
    evaluation_fingerprint: Mapped[str] = mapped_column(String(64))
    approval_reference: Mapped[str] = mapped_column(String(160))
    policy_digest: Mapped[str] = mapped_column(String(64))
    provenance: Mapped[str] = mapped_column(Text)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    evidence: Mapped[dict] = mapped_column(JSON)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuthorizationRecordRevocation(Base):
    __tablename__ = 'authorization_record_revocations'
    __table_args__ = (
        CheckConstraint('(approval_reference IS NULL) <> (evidence_reference IS NULL)',
                        name='ck_authorization_revocation_subject'),
        CheckConstraint("btrim(reason) <> '' AND btrim(provenance) <> ''", name='ck_authorization_revocation_reason'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    approval_reference: Mapped[str | None] = mapped_column(ForeignKey('execution_policy_approvals.reference'), unique=True)
    evidence_reference: Mapped[str | None] = mapped_column(ForeignKey('assessment_start_evidence.reference'), unique=True)
    reason: Mapped[str] = mapped_column(Text)
    provenance: Mapped[str] = mapped_column(Text)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

@event.listens_for(ExecutionPolicyVersion, 'before_insert')
def validate_policy_version(mapper, connection, record):
    from .execution_policy import PolicyDefinition

    policy = PolicyDefinition.model_validate_json(json.dumps(record.definition))
    if (record.policy_id, record.version, record.digest) != (policy.policy_id, policy.version, policy.digest):
        raise ValueError('Policy identity or digest does not match its definition.')

# Register system-managed authorization models.
from .system_authorization_models import (
    SystemPolicyAuthorizationRecord,
    SystemPolicyAuthorizationRevocation,
)
