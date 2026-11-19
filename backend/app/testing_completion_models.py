"""Testing completion records, separate from scanner execution authorizations."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base

class TestingRecommendationDecision(Base):
    __tablename__ = 'testing_recommendation_decisions'
    __table_args__ = (CheckConstraint("decision IN ('Reviewed', 'Deferred')",
                                     name='ck_testing_recommendation_decision'),)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey('assessments.id'), primary_key=True)
    recommendation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    actor_id: Mapped[UUID] = mapped_column(ForeignKey('users.id'))
    decision: Mapped[str] = mapped_column(String(16))
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

class TestingCompletionEvent(Base):
    __tablename__ = 'testing_completion_events'
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey('assessments.id'), primary_key=True)
    actor_id: Mapped[UUID] = mapped_column(ForeignKey('users.id'))
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    snapshot: Mapped[dict] = mapped_column(JSON)
