"""Authenticated, read-only local AI assistance for security findings."""

import asyncio
import hmac
from threading import Lock
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.exc import SQLAlchemyError
from pydantic import ValidationError
from sqlalchemy.orm import Session

from .assessment_routes import analyst
from .config import get_settings
from .database import get_db
from .models import User
from .routes import trusted_origin, current_session
from .security import session_csrf
from .finding_ai_context import retrieve_context
from .finding_ai_prompt import build_prompt, PromptUnavailable
from .finding_ai_schemas import (
    FindingAIRequest,
    FindingAIResponse,
    FindingAIAnswer,
    FindingAIInsufficientEvidence,
    FindingAIUnavailable,
    FindingAIHistoryResponse,
)
from .ollama_client import generate, OllamaUnavailable
from .finding_ai_history_service import (
    save_interaction, retrieve_history,
)


router = APIRouter(
    prefix="/api/v1/assessments/{assessment_id}/findings"
)

# Single active inference per backend process.
inference_lock = Lock()


UNAVAILABLE_MESSAGES = {
    "ai_history_unavailable": (
        "The AI answer could not be saved. Please try again.",
        True,
    ),
    "ai_disabled": (
        "The AI Assistant is currently disabled.",
        False,
    ),
    "ai_busy": (
        "The AI Assistant is processing another request. "
        "Please try again shortly.",
        True,
    ),
    "ai_timeout": (
        "The AI Assistant took too long to respond. "
        "Please try again.",
        True,
    ),
    "ai_context_too_large": (
        "The available information or question is too large "
        "for the configured AI model.",
        False,
    ),
    "ai_context_invalid": (
        "The finding context could not be verified.",
        False,
    ),
    "ai_service_unavailable": (
        "The local AI service is unavailable. "
        "Please try again later.",
        True,
    ),
    "ai_response_invalid": (
        "The AI Assistant could not provide a valid response.",
        True,
    ),
    "ai_response_incomplete": (
        "The AI Assistant returned an incomplete answer.",
        True,
    ),
    "ai_response_empty": (
        "The AI Assistant did not return an answer.",
        True,
    ),
    "ai_response_too_large": (
        "The AI response exceeded the permitted size.",
        True,
    ),
    "ai_model_mismatch": (
        "The configured AI model could not be verified.",
        False,
    ),
    "ai_context_changed": (
        "The finding information changed during processing. "
        "Please submit your question again.",
        True,
    ),
}


def unavailable(code: str) -> FindingAIUnavailable:
    """Return fixed messages without exposing internal exceptions."""

    if code not in UNAVAILABLE_MESSAGES:
        code = "ai_service_unavailable"

    message, retryable = UNAVAILABLE_MESSAGES[code]

    return FindingAIUnavailable(
        code=code,
        message=message,
        retryable=retryable,
    )


@router.post(
    "/{finding_id}/ai/ask",
    response_model=FindingAIResponse,
)
def ask_finding_ai(
    assessment_id: UUID,
    finding_id: UUID,
    body: FindingAIRequest,
    request: Request,
    user: User = Depends(analyst),
    db: Session = Depends(get_db),
):
    """Answer a question without changing findings or executing tools."""

    settings = get_settings()

    # Reuse UPTIP's existing session-bound CSRF protection.
    token = request.cookies.get(settings.cookie_name)

    if not token or not trusted_origin(request):
        raise HTTPException(403)

    supplied = request.headers.get(
        "x-csrf-token", ""
    ).encode()

    expected = session_csrf(settings, token).encode()

    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(403)

    actor_id = user.id

    # Authorization is checked even when AI is disabled or busy.
    context = retrieve_context(
        db,
        assessment_id,
        finding_id,
        user,
    )

    # End the read transaction before potentially lengthy inference.
    db.rollback()

    if not settings.ai_enabled:
        return unavailable("ai_disabled")

    try:
        prepared = build_prompt(
            context,
            body,
            settings,
        )
    except PromptUnavailable as exc:
        if exc.code == "ai_insufficient_evidence":
            return FindingAIInsufficientEvidence(
                assessment_id=assessment_id,
                finding_id=finding_id,
                action=body.action,
                message=(
                    "There is not enough eligible supporting "
                    "evidence to answer this question reliably."
                ),
            )

        return unavailable(exc.code)

    # Reject concurrent requests rather than queueing them.
    if not inference_lock.acquire(blocking=False):
        return unavailable("ai_busy")

    try:
        try:
            result = asyncio.run(
                generate(
                    system=prepared["system"],
                    prompt=prepared["prompt"],
                    settings=settings,
                )
            )
        except OllamaUnavailable as exc:
            return unavailable(exc.code)

        # Recheck session and assessment access after inference.
        _, refreshed_user = current_session(request, db)

        if refreshed_user is None:
            raise HTTPException(401)

        if (
            refreshed_user.id != actor_id
            or refreshed_user.role != "Security Analyst"
        ):
            raise HTTPException(403)

        refreshed_context = retrieve_context(
            db,
            assessment_id,
            finding_id,
            refreshed_user,
        )

        if refreshed_context != context:
            return unavailable("ai_context_changed")

        try:
            answer = FindingAIAnswer(
                assessment_id=assessment_id,
                finding_id=finding_id,
                action=body.action,
                question=prepared["question"],
                answer=result["answer"],
                model=result["model"],
                output_tokens=result["output_tokens"],
                evidence=prepared["evidence"],
                limitations=[
                    "AI-generated advice requires analyst review.",
                    "Supporting observations do not establish "
                    "successful exploitation.",
                    "Individual observations are represented by metadata only.",
                    "Full original scanner output was not "
                    "provided to the AI model.",
                    "Evidence references identify the supplied "
                    "context, not independently verified AI claims.",
                ],
                advisory_only=True,
            )
        except (ValidationError, KeyError, TypeError):
            return unavailable("ai_response_invalid")

        try:
            identifier = save_interaction(
                db, actor_id, answer, prepared["prompt_version"]
            )
        except SQLAlchemyError:
            db.rollback()
            return unavailable("ai_history_unavailable")

        return answer.model_copy(
            update={"history_id": identifier}
        )

    finally:
        inference_lock.release()


@router.get(
    "/{finding_id}/ai/history",
    response_model=FindingAIHistoryResponse,
)
def finding_ai_history(
    assessment_id: UUID,
    finding_id: UUID,
    limit: int = Query(default=20, ge=1, le=50),
    offset: int = Query(default=0, ge=0, le=10000),
    user: User = Depends(analyst),
    db: Session = Depends(get_db),
):
    """Return the current analyst's earlier finding interactions."""

    return retrieve_history(
        db,
        assessment_id,
        finding_id,
        user,
        limit=limit,
        offset=offset,
    )
