"""Analyst review outcomes are not execution authorization."""
from datetime import datetime
from uuid import UUID, uuid4
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, JSON, Integer, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base

class RecommendationReviewEvent(Base):
    __tablename__ = 'recommendation_review_events'
    __table_args__ = (
        UniqueConstraint('assessment_id','recommendation_id','revision',name='uq_recommendation_review_revision'),
        CheckConstraint('revision>0',name='ck_recommendation_review_revision'),
        CheckConstraint("outcome IN ('Accepted','Rejected')", name='ck_recommendation_review_outcome'),
        CheckConstraint("json_typeof(snapshot)='object' AND (snapshot->>'id') IS NOT DISTINCT FROM recommendation_id", name='ck_recommendation_review_snapshot'),
        CheckConstraint("recommendation_id ~ '^[0-9a-f]{64}$' AND context_digest=recommendation_id", name='ck_recommendation_review_context'),
        Index('ix_recommendation_review_latest', 'assessment_id', 'recommendation_id', 'revision'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey('assessments.id'))
    recommendation_id: Mapped[str] = mapped_column(String(64))
    actor_id: Mapped[UUID] = mapped_column(ForeignKey('users.id'))
    context_digest: Mapped[str] = mapped_column(String(64))
    revision: Mapped[int] = mapped_column(Integer)
    snapshot: Mapped[dict] = mapped_column(JSON)
    outcome: Mapped[str] = mapped_column(String(16))
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
