"""Persist processing and observations for independent recommended-test jobs."""
from datetime import datetime
from uuid import UUID, uuid4
from sqlalchemy import CheckConstraint, DateTime, ForeignKeyConstraint, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base


class RecommendedProcessingOutcome(Base):
    __tablename__ = 'recommended_processing_outcomes'
    __table_args__ = (
        ForeignKeyConstraint(['job_id', 'assessment_id', 'target_id'],
                             ['recommended_test_jobs.id', 'recommended_test_jobs.assessment_id', 'recommended_test_jobs.target_id'],
                             name='fk_recommended_processing_job'),
        UniqueConstraint('id', 'job_id', 'assessment_id', 'target_id', name='uq_recommended_processing_binding'),
        UniqueConstraint('job_id', 'processor', 'processor_version', 'output_digest', name='uq_recommended_processing_source'),
        CheckConstraint("status IN ('Succeeded','Failed')", name='ck_recommended_processing_status'),
        CheckConstraint("output_digest ~ '^[0-9a-f]{64}$'", name='ck_recommended_processing_digest'),
        CheckConstraint('observation_count >= 0', name='ck_recommended_processing_count'),
        Index('ix_recommended_processing_assessment', 'assessment_id', 'job_id'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(nullable=False)
    assessment_id: Mapped[UUID] = mapped_column(nullable=False)
    target_id: Mapped[UUID] = mapped_column(nullable=False)
    processor: Mapped[str] = mapped_column(String(80), nullable=False)
    processor_version: Mapped[str] = mapped_column(String(40), nullable=False)
    output_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(80))
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RecommendedObservation(Base):
    __tablename__ = 'recommended_observations'
    __table_args__ = (
        ForeignKeyConstraint(['processing_id', 'job_id', 'assessment_id', 'target_id'],
                             ['recommended_processing_outcomes.id', 'recommended_processing_outcomes.job_id',
                              'recommended_processing_outcomes.assessment_id', 'recommended_processing_outcomes.target_id'],
                             name='fk_recommended_observation_processing'),
        UniqueConstraint('job_id', 'deduplication_key', name='uq_recommended_observation_key'),
        CheckConstraint("deduplication_key ~ '^[0-9a-f]{64}$'", name='ck_recommended_observation_key'),
        CheckConstraint("jsonb_typeof(data)='object' AND octet_length(data::text)<=16384", name='ck_recommended_observation_data'),
        Index('ix_recommended_observation_assessment', 'assessment_id', 'target_id'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    processing_id: Mapped[UUID] = mapped_column(nullable=False)
    job_id: Mapped[UUID] = mapped_column(nullable=False)
    assessment_id: Mapped[UUID] = mapped_column(nullable=False)
    target_id: Mapped[UUID] = mapped_column(nullable=False)
    observation_type: Mapped[str] = mapped_column(String(80), nullable=False)
    data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    deduplication_key: Mapped[str] = mapped_column(String(64), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_partial: Mapped[bool] = mapped_column(nullable=False, default=False)
