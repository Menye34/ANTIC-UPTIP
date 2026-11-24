"""Read-only, assessment-scoped context for finding AI assistance."""

from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .assessment_routes import accessible
from .models import Assessment, User
from .findings_models import ConsolidatedFinding
from .findings_processing import candidates as baseline_candidates
from .nikto_findings_processing import candidates as nikto_candidates


MAX_EVIDENCE_ITEMS = 3
MAX_FIELD_LENGTH = 400
MAX_EVIDENCE_LENGTH = 600

FINDING_FIELDS = (
    "title",
    "severity",
    "affected_target",
    "source",
    "source_test",
    "description",
    "impact",
    "security_control",
    "observed_condition",
    "detected_issue",
    "remediation",
)


def bounded_text(value, limit=MAX_FIELD_LENGTH):
    """Limit text without interpreting it as instructions."""
    if not isinstance(value, str):
        return ""

    value = "".join(
        char for char in value
        if char.isprintable() or char in "\\n\\t"
    ).strip()

    if len(value) > limit:
        return value[:limit] + " [truncated]"

    return value


def matches_finding(finding, key, fields):
    """Reject evidence that does not match the stored finding."""
    return (
        key == finding.identity_key
        and fields.get("title") == finding.title
        and fields.get("severity") == finding.severity
        and fields.get("affected_target") == finding.affected_target
    )


def retrieve_context(
    db: Session,
    assessment_id: UUID,
    finding_id: UUID,
    user: User,
) -> dict:
    """Retrieve authorized finding context without modifying records."""

    finding = db.scalar(
        select(ConsolidatedFinding)
        .join(
            Assessment,
            Assessment.id == ConsolidatedFinding.assessment_id,
        )
        .where(
            Assessment.id == assessment_id,
            ConsolidatedFinding.assessment_id == assessment_id,
            ConsolidatedFinding.id == finding_id,
            accessible(user),
        )
    )

    if finding is None:
        raise HTTPException(404)

    evidence = []
    eligible_count = 0

    for observation, original, request, key, fields in baseline_candidates(
        db, assessment_id, finding_id=finding_id
    ):
        if not matches_finding(finding, key, fields):
            continue

        eligible_count += 1

        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            continue

        evidence.append({
            "observation_id": str(observation.id),
            "evidence_id": str(original.id),
            "source": bounded_text(original.tool, 80),
            "observation_type": observation.observation_type,
            "content": bounded_text(
                fields.get("observed_condition"),
                MAX_EVIDENCE_LENGTH,
            ),
            "evidence_kind": "normalized_observation",
            "exploitation_confirmed": False,
        })

    for observation, key, fields in nikto_candidates(
        db, assessment_id, finding_id=finding_id
    ):
        if not matches_finding(finding, key, fields):
            continue

        eligible_count += 1

        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            continue

        evidence.append({
            "observation_id": str(observation.id),
            "evidence_id": str(observation.job_id),
            "source": "Nikto",
            "observation_type": observation.observation_type,
            "content": bounded_text(
                observation.data.get("message"),
                MAX_EVIDENCE_LENGTH,
            ),
            "evidence_kind": "normalized_observation",
            "exploitation_confirmed": False,
        })

    limitations = [
        "Scanner observations do not establish successful exploitation.",
        "Full original scanner output is not included in this context.",
        "Finding descriptions and remediation are existing system assessments.",
    ]

    if not evidence:
        limitations.append(
            "No eligible linked supporting observations are available."
        )

    if eligible_count > len(evidence):
        limitations.append(
            "Additional eligible observations were omitted "
            "to limit AI context size."
        )

    return {
        "assessment_id": str(assessment_id),
        "finding_id": str(finding_id),
        "finding": {
            field: bounded_text(getattr(finding, field))
            for field in FINDING_FIELDS
        },
        "evidence": evidence,
        "evidence_available": bool(evidence),
        "eligible_evidence_count": eligible_count,
        "evidence_included_count": len(evidence),
        "original_output_included": False,
        "limitations": limitations,
    }
