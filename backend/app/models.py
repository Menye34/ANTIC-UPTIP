from datetime import date, datetime
from uuid import UUID, uuid4

from sqlalchemy import JSON, Boolean, CheckConstraint, Date, DateTime, ForeignKey, Integer, Sequence, String, Text, UniqueConstraint, func
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
        CheckConstraint("status = 'Draft'", name='ck_assessments_draft'),
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
