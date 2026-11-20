"""Immutable explicit creator consent; scheduling history is not dispatch authority."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import (CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint,
                        String, UniqueConstraint, func)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base


class ServiceDiscoveryConsent(Base):
    __tablename__ = 'service_discovery_consents'
    __table_args__ = (
        ForeignKeyConstraint(['request_id', 'assessment_id', 'target_id'],
            ['baseline_execution_requests.id', 'baseline_execution_requests.assessment_id',
             'baseline_execution_requests.target_id'], name='fk_service_consent_request'),
        UniqueConstraint('assessment_id', 'idempotency_key', name='uq_service_consent_key'),
        CheckConstraint("expires_at > created_at AND expires_at <= created_at + interval '1 hour'", name='ck_service_consent_expiry'),
        CheckConstraint("digest ~ '^[0-9a-f]{64}$' AND jsonb_typeof(snapshot)='object'",
                        name='ck_service_consent_snapshot'),
    )
    request_id: Mapped[UUID] = mapped_column(primary_key=True)
    assessment_id: Mapped[UUID]
    target_id: Mapped[UUID]
    actor_id: Mapped[UUID] = mapped_column(ForeignKey('users.id'))
    idempotency_key: Mapped[UUID]
    snapshot: Mapped[dict] = mapped_column(JSONB)
    digest: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ServiceDiscoveryRevocation(Base):
    __tablename__ = 'service_discovery_revocations'
    request_id: Mapped[UUID] = mapped_column(ForeignKey('service_discovery_consents.request_id'), primary_key=True)
    actor_id: Mapped[UUID] = mapped_column(ForeignKey('users.id'))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
