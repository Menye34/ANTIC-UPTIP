"""Dedicated durable queue for recommendation-driven tests.

This queue is independent of assessment-start execution requests. A queued
record is not permission for an arbitrary worker to launch a process: the
consumer must revalidate its immutable plan and the current scope.
"""
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Index, JSON, String, UniqueConstraint, func, Integer, LargeBinary, Boolean
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class RecommendedTestJob(Base):
    __tablename__ = 'recommended_test_jobs'
    __table_args__ = (
        UniqueConstraint('assessment_id', 'recommendation_id', name='uq_recommended_job_recommendation'),
        UniqueConstraint('id', 'assessment_id', 'target_id', name='uq_recommended_job_binding'),
        ForeignKeyConstraint(['target_id', 'assessment_id'], ['assessment_targets.id', 'assessment_targets.assessment_id'], name='fk_recommended_target_assessment'),
        CheckConstraint("status IN ('Queued','Running','Completed','Failed','Stopped','Blocked','Cancelled')",
                        name='ck_recommended_job_status'),
        Index('ix_recommended_job_queue', 'status', 'created_at'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey('assessments.id'), nullable=False)
    target_id: Mapped[UUID] = mapped_column(ForeignKey('assessment_targets.id'), nullable=False)
    actor_id: Mapped[UUID] = mapped_column(ForeignKey('users.id'), nullable=False)
    recommendation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tool: Mapped[str] = mapped_column(String(40), nullable=False)
    profile_id: Mapped[str] = mapped_column(String(80), nullable=False)
    profile_version: Mapped[int] = mapped_column(nullable=False)
    scope_revision: Mapped[int] = mapped_column(nullable=False)
    execution_plan: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default='Queued')
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(String(120), nullable=True)
    stdout: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    stderr: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    output_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    authorization_snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    termination_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    output_partial: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    process_reference: Mapped[str | None] = mapped_column(String(160), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class RecommendedTestEvent(Base):
    __tablename__ = 'recommended_test_events'
    __table_args__ = (ForeignKeyConstraint(['job_id', 'assessment_id', 'target_id'],
        ['recommended_test_jobs.id', 'recommended_test_jobs.assessment_id', 'recommended_test_jobs.target_id'],
        name='fk_recommended_event_job'), Index('ix_recommended_event_job', 'job_id', 'occurred_at', 'id'))
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(nullable=False)
    assessment_id: Mapped[UUID] = mapped_column(nullable=False)
    target_id: Mapped[UUID] = mapped_column(nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(120), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
