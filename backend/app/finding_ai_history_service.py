"""Persistence and authorized retrieval of finding AI history."""

from uuid import UUID, uuid4

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .assessment_routes import accessible
from .models import Assessment, User
from .findings_models import ConsolidatedFinding
from .finding_ai_history_models import FindingAIHistory
from .finding_ai_schemas import (
    FindingAIAnswer,
    FindingAIHistoryEntry,
    FindingAIHistoryResponse,
)


def save_interaction(
    db: Session,
    actor_id: UUID,
    answer: FindingAIAnswer,
    prompt_version: str,
) -> UUID:
    """Persist only a successfully validated advisory answer."""

    identifier = uuid4()

    record = FindingAIHistory(
        id=identifier,
        assessment_id=answer.assessment_id,
        finding_id=answer.finding_id,
        actor_id=actor_id,
        action=answer.action,
        question=answer.question,
        answer=answer.answer,
        model=answer.model,
        prompt_version=prompt_version,
        output_tokens=answer.output_tokens,
        evidence=[
            item.model_dump(mode="json")
            for item in answer.evidence
        ],
        limitations=list(answer.limitations),
    )

    db.add(record)
    db.commit()

    return identifier


def retrieve_history(
    db: Session,
    assessment_id: UUID,
    finding_id: UUID,
    user: User,
    limit: int = 20,
    offset: int = 0,
) -> FindingAIHistoryResponse:
    """Retrieve only the current analyst's authorized interactions."""

    if user.role != "Security Analyst":
        raise HTTPException(403)

    if not 1 <= limit <= 50 or not 0 <= offset <= 10000:
        raise HTTPException(422)

    authorized = db.scalar(
        select(ConsolidatedFinding.id)
        .join(
            Assessment,
            Assessment.id == ConsolidatedFinding.assessment_id,
        )
        .where(
            ConsolidatedFinding.id == finding_id,
            ConsolidatedFinding.assessment_id == assessment_id,
            accessible(user),
        )
    )

    if authorized is None:
        raise HTTPException(404)

    records = db.scalars(
        select(FindingAIHistory)
        .join(
            Assessment,
            Assessment.id == FindingAIHistory.assessment_id,
        )
        .where(
            FindingAIHistory.assessment_id == assessment_id,
            FindingAIHistory.finding_id == finding_id,
            FindingAIHistory.actor_id == user.id,
            accessible(user),
        )
        .order_by(
            FindingAIHistory.created_at.desc(),
            FindingAIHistory.id.desc(),
        )
        .offset(offset)
        .limit(limit + 1)
    ).all()

    entries = [
        FindingAIHistoryEntry.model_validate(record)
        for record in records[:limit]
    ]

    return FindingAIHistoryResponse(
        assessment_id=assessment_id,
        finding_id=finding_id,
        entries=entries,
        limit=limit,
        offset=offset,
        has_more=len(records) > limit,
    )
