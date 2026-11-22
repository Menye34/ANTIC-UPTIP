"""Dedicated durable queue for recommendation-driven tests.

This queue is independent of assessment-start execution requests. A queued
record is not permission for an arbitrary worker to launch a process: the
consumer must revalidate its immutable plan and the current scope.
"""
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, JSON, String, UniqueConstraint, func, Integer, LargeBinary
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class RecommendedTestJob(Base):
    __tablename__ = 'recommended_test_jobs'
    __table_args__ = (
        UniqueConstraint('assessment_id', 'recommendation_id', name='uq_recommended_job_recommendation'),
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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
