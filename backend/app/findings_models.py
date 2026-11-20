"""Consolidated finding records and immutable observation provenance."""
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Index, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base


class ConsolidatedFinding(Base):
    __tablename__ = 'consolidated_findings'
    __table_args__ = (
        UniqueConstraint('assessment_id', 'identity_key', name='uq_finding_assessment_identity'),
        UniqueConstraint('id', 'assessment_id', name='uq_finding_assessment'),
        CheckConstraint("severity IN ('Critical','High','Medium','Low')", name='ck_finding_severity'),
        CheckConstraint("btrim(title)<>'' AND btrim(identity_key)<>'' AND btrim(rule_version)<>''", name='ck_finding_identity'),
        Index('ix_findings_assessment_severity', 'assessment_id', 'severity'),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey('assessments.id'), nullable=False)
    identity_key: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    affected_target: Mapped[str] = mapped_column(String(1024), nullable=False)
    source: Mapped[str] = mapped_column(String(160), nullable=False)
    source_test: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    security_control: Mapped[str] = mapped_column(String(240), nullable=False)
    observed_condition: Mapped[str] = mapped_column(Text, nullable=False)
    detected_issue: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class FindingObservation(Base):
    __tablename__ = 'finding_observations'
    __table_args__ = (
        ForeignKeyConstraint(['finding_id', 'assessment_id'], ['consolidated_findings.id', 'consolidated_findings.assessment_id'], name='fk_finding_link_assessment'),
        UniqueConstraint('observation_id', name='uq_finding_observation_once'),
        Index('ix_finding_observations_assessment', 'assessment_id', 'finding_id'),
    )
    finding_id: Mapped[UUID] = mapped_column(primary_key=True)
    observation_id: Mapped[UUID] = mapped_column(ForeignKey('security_observations.id'), primary_key=True)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey('assessments.id'), nullable=False)
    match_reason: Mapped[str] = mapped_column(String(80), nullable=False)
