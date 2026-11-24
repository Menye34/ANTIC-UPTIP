"""Persistent advisory AI interactions scoped to findings."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class FindingAIHistory(Base):
    __tablename__ = "finding_ai_history"

    __table_args__ = (
        ForeignKeyConstraint(
            ["finding_id", "assessment_id"],
            [
                "consolidated_findings.id",
                "consolidated_findings.assessment_id",
            ],
            name="fk_ai_history_finding_assessment",
        ),
        CheckConstraint(
            "action IN ('explain_finding', 'explain_impact', "
            "'suggest_fix', 'write_description', "
            "'explain_tool_output', 'custom')",
            name="ck_ai_history_action",
        ),
        CheckConstraint(
            "char_length(question) BETWEEN 1 AND 500 "
            "AND btrim(question) <> ''",
            name="ck_ai_history_question",
        ),
        CheckConstraint(
            "char_length(answer) BETWEEN 1 AND 6000 "
            "AND btrim(answer) <> ''",
            name="ck_ai_history_answer",
        ),
        CheckConstraint(
            "output_tokens BETWEEN 1 AND 512",
            name="ck_ai_history_output_tokens",
        ),
        CheckConstraint(
            "CASE WHEN jsonb_typeof(evidence) = 'array' "
            "THEN jsonb_array_length(evidence) BETWEEN 1 AND 3 "
            "ELSE false END",
            name="ck_ai_history_evidence",
        ),
        CheckConstraint(
            "CASE WHEN jsonb_typeof(limitations) = 'array' "
            "THEN jsonb_array_length(limitations) <= 8 "
            "ELSE false END",
            name="ck_ai_history_limitations",
        ),
        Index(
            "ix_ai_history_scope_created",
            "assessment_id",
            "finding_id",
            "actor_id",
            "created_at",
            "id",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4
    )

    assessment_id: Mapped[UUID] = mapped_column(
        ForeignKey("assessments.id"), nullable=False
    )

    finding_id: Mapped[UUID] = mapped_column(nullable=False)

    actor_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id"), nullable=False
    )

    action: Mapped[str] = mapped_column(
        String(40), nullable=False
    )

    question: Mapped[str] = mapped_column(
        String(500), nullable=False
    )

    answer: Mapped[str] = mapped_column(
        Text, nullable=False
    )

    model: Mapped[str] = mapped_column(
        String(100), nullable=False
    )

    prompt_version: Mapped[str] = mapped_column(
        String(80), nullable=False
    )

    output_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False
    )

    evidence: Mapped[list] = mapped_column(
        JSONB, nullable=False
    )

    limitations: Mapped[list] = mapped_column(
        JSONB, nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
