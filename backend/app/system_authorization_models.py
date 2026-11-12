"""Persistent identity for system-managed policy authorizations."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class SystemPolicyAuthorizationRecord(Base):
    __tablename__ = "system_policy_authorizations"

    __table_args__ = (
        UniqueConstraint(
            "reference",
            "policy_digest",
            name="uq_system_authorization_binding",
        ),
        CheckConstraint(
            "valid_until > valid_from",
            name="ck_system_authorization_window",
        ),
        CheckConstraint(
            "btrim(reference) <> '' AND btrim(provenance) <> ''",
            name="ck_system_authorization_identity",
        ),
    )

    reference: Mapped[str] = mapped_column(String(160), primary_key=True)

    policy_digest: Mapped[str] = mapped_column(
        ForeignKey("execution_policy_versions.digest"),
        nullable=False,
    )

    provenance: Mapped[str] = mapped_column(Text, nullable=False)

    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    valid_until: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class SystemPolicyAuthorizationRevocation(Base):
    __tablename__ = "system_policy_authorization_revocations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)

    authorization_reference: Mapped[str] = mapped_column(
        ForeignKey("system_policy_authorizations.reference"),
        unique=True,
        nullable=False,
    )

    reason: Mapped[str] = mapped_column(Text, nullable=False)

    provenance: Mapped[str] = mapped_column(Text, nullable=False)

    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
