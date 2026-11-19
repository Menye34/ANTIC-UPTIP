"""Dedicated recommendation review records; never interchangeable with Start authorization."""
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Index, JSON, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class RecommendationAuthorizationRecord(Base):
    __tablename__ = 'recommendation_authorization_records'
    __table_args__ = (
        UniqueConstraint('id', 'assessment_id', 'target_id', name='uq_rec_auth_binding'),
        UniqueConstraint('assessment_id', 'actor_id', 'idempotency_key', name='uq_rec_auth_actor_key'),
        ForeignKeyConstraint(['target_id', 'assessment_id'],
                             ['assessment_targets.id', 'assessment_targets.assessment_id'],
                             name='fk_rec_auth_target_assessment'),
        CheckConstraint("status IN ('Pending', 'Denied', 'Approved', 'Revoked')", name='ck_rec_auth_status'),
        CheckConstraint("length(recommendation_id) = 64", name='ck_rec_auth_rec_id'),
        Index('ix_rec_auth_assessment_created', 'assessment_id', 'created_at'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey('assessments.id'))
    target_id: Mapped[UUID]
    actor_id: Mapped[UUID] = mapped_column(ForeignKey('users.id'))
    recommendation_id: Mapped[str] = mapped_column(String(64))
    source_observation_id: Mapped[UUID]
    source_evidence_id: Mapped[UUID]
    profile_id: Mapped[str] = mapped_column(String(80))
    profile_version: Mapped[int]
    scope_revision: Mapped[int]
    authorization_snapshot: Mapped[dict] = mapped_column(JSON)
    snapshot_digest: Mapped[str] = mapped_column(String(64))
    idempotency_key: Mapped[str] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(16), default='Pending')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RecommendationExecutionRequest(Base):
    __tablename__ = 'recommendation_execution_requests'
    __table_args__ = (
        UniqueConstraint('authorization_id', name='uq_rec_execution_auth'),
        ForeignKeyConstraint(['authorization_id', 'assessment_id', 'target_id'],
                             ['recommendation_authorization_records.id',
                              'recommendation_authorization_records.assessment_id',
                              'recommendation_authorization_records.target_id'],
                             name='fk_rec_execution_auth_binding'),
        CheckConstraint("status IN ('PendingVerification', 'Blocked', 'Cancelled')",
                        name='ck_rec_execution_non_dispatchable'),
        Index('ix_rec_execution_assessment', 'assessment_id', 'created_at'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    assessment_id: Mapped[UUID]
    target_id: Mapped[UUID]
    authorization_id: Mapped[UUID]
    status: Mapped[str] = mapped_column(String(32), default='PendingVerification')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
